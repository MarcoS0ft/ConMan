//! Versioned JSON import/export for the full connection tree.
//!
//! ## Envelope schema (version 2, P1.2)
//!
//! ```json
//! {
//!   "conman_export_version": 2,
//!   "exported_at": <epoch-seconds>,
//!   "credential_folders": [...],
//!   "credentials":         [...],
//!   "groups":              [...],
//!   "connections":         [...],
//!   "credential_secrets":  [...],  // omitted when empty
//!   "settings":            [["ui.theme_mode","1"], ...]  // v2; omitted when empty
//! }
//! ```
//!
//! Version 1 (pinned 2026-06-28) is identical minus the `settings` field.
//! [`import`] accepts both v1 and v2; a v1 envelope simply carries no settings.
//! Volatile/machine-specific settings keys ([`EXPORT_EXCLUDED_SETTING_KEYS`])
//! are never exported.
//!
//! ## Import semantics (additive, pinned)
//!
//! Every imported record receives a **fresh** database ID; the IDs embedded in
//! the envelope are used only as intra-envelope link keys.  Parent and
//! credential links are rewritten to the newly assigned IDs.  Links to IDs not
//! present in the envelope are silently set to `None` (never a panic or hard
//! failure).  Cyclic parent references in untrusted input are broken by
//! treating the offending node as a root — no abort, no loop.
//!
//! ## Secrets
//!
//! Secrets are **excluded by default**.  They are embedded only when
//! [`ExportOptions::include_secrets`] is `true` *and* a
//! [`cm_core::CredentialStore`] is supplied.  Encoding: lower-case hex
//! (`secret_hex`); no additional dependency beyond `serde_json`.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use cm_core::{
    Connection, ConnectionId, ConnectionRepository, Credential, CredentialFolder,
    CredentialFolderId, CredentialId, CredentialKind, CredentialPurpose, CredentialRef,
    CredentialStore, Group, GroupId, KEY_FIRST_RUN_SEEDED, KEY_RENDERER_BACKEND, KEY_SESSION_TABS,
    Secret,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Envelope schema version produced by this build.
///
/// - v1 (P1.2): tree + optional gated secrets.
/// - v2 (P1.2 cont.): adds an optional `settings` list carrying app settings.
///
/// [`export`] always emits [`ENVELOPE_VERSION`]; [`import`] accepts both v1 and
/// v2 (see [`MIN_SUPPORTED_VERSION`]) and rejects anything else with
/// [`ImportExportError::UnsupportedVersion`].
pub const ENVELOPE_VERSION: u32 = 2;

/// Oldest envelope version [`import`] still accepts. v1 envelopes simply carry
/// no `settings` (the field defaults to empty), so no migration is needed.
pub const MIN_SUPPORTED_VERSION: u32 = 1;

/// Settings keys deliberately EXCLUDED from an export: machine-specific /
/// volatile state that must not travel with a shared or backed-up envelope.
/// References `cm-core`'s canonical key constants (rather than duplicating
/// the literal strings here) so a key rename can't silently desync this list
/// from the settings it's meant to catch.
/// - [`KEY_SESSION_TABS`]: the last-session tab snapshot — references local
///   connection IDs and is per-machine session state.
/// - [`KEY_FIRST_RUN_SEEDED`]: the demo-seed guard — importing it would
///   suppress first-run seeding on a fresh target DB.
/// - [`KEY_RENDERER_BACKEND`]: cached hardware-capability probe result
///   (P7.1). A pinned "accelerated" cache carried to a GPU-less machine
///   would crash on launch, defeating the renderer probe/fallback entirely —
///   the importing machine must always re-probe (its absence collapses to
///   "auto", see [`cm_core::SettingsService::load_renderer_backend`]).
const EXPORT_EXCLUDED_SETTING_KEYS: &[&str] =
    &[KEY_SESSION_TABS, KEY_FIRST_RUN_SEEDED, KEY_RENDERER_BACKEND];

/// Upper bound on topological-sort passes to guard against cyclic or otherwise
/// malformed input from untrusted JSON.
const MAX_TOPO_PASSES: usize = 1_024;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Options controlling what is included in an [`export`] / [`export_to_json`] call.
#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    /// When `true`, resolved secrets are fetched from the keychain and embedded
    /// in [`ExportEnvelope::credential_secrets`].
    ///
    /// # WARNING
    /// This option embeds **plain-text secret material** into the JSON output.
    /// Only set it when the operator has explicitly requested a
    /// secrets-inclusive export.  Treat the resulting file with the same care
    /// as a private-key or password database.
    pub include_secrets: bool,
}

/// Versioned JSON export envelope.
///
/// Serialised with `serde_json`; the schema is pinned at version
/// [`ENVELOPE_VERSION`].  Deserialising an envelope with a different version
/// succeeds at the JSON level but [`import`] will reject it with
/// [`ImportExportError::UnsupportedVersion`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEnvelope {
    pub conman_export_version: u32,
    /// UTC epoch-seconds at export time.
    pub exported_at: i64,
    pub credential_folders: Vec<CredentialFolder>,
    pub credentials: Vec<Credential>,
    pub groups: Vec<Group>,
    pub connections: Vec<Connection>,
    /// Present only when [`ExportOptions::include_secrets`] is `true` and
    /// secrets were available.  Omitted from serialisation when empty so a
    /// default export carries no hint of the field.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub credential_secrets: Vec<ExportedSecret>,
    /// App settings (v2) as ordered `[key, value]` string pairs. Volatile /
    /// machine-specific keys ([`EXPORT_EXCLUDED_SETTING_KEYS`]) are omitted.
    /// Empty for v1 envelopes (the field is absent there and defaults empty),
    /// and suppressed from serialisation when empty.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub settings: Vec<(String, String)>,
}

/// One secret entry in a gated export.
///
/// `secret_hex` is the raw secret bytes encoded as lower-case hex.  For
/// password credentials this is the UTF-8 bytes of the password; for SSH
/// credentials it is the bytes of the PEM-encoded private key.
///
/// `purpose` is one of the stable [`CredentialPurpose`] string forms:
/// `"password"`, `"ssh-key"`, or `"ssh-passphrase"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedSecret {
    /// The **exported** (pre-remap) credential ID.  During import this is
    /// looked up in the remap table to find the freshly assigned ID.
    pub credential_id: CredentialId,
    /// Stable purpose tag from [`CredentialPurpose::as_str`].
    pub purpose: String,
    /// Raw secret bytes encoded as lower-case hex (no `base64` dep needed).
    pub secret_hex: String,
}

/// Typed errors returned by the import/export functions.
#[derive(Debug, thiserror::Error)]
pub enum ImportExportError {
    /// The envelope's `conman_export_version` is not supported by this build.
    #[error("unsupported envelope version {found} (supported: {supported})")]
    UnsupportedVersion { found: u32, supported: u32 },
    /// Structural or domain-validation failure in the input data.
    #[error("malformed import data: {0}")]
    Malformed(String),
    /// JSON serialisation or deserialisation error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// A repository operation failed during import.
    #[error("repository error during import: {0}")]
    Repository(#[from] cm_core::RepositoryError),
    /// A keychain operation failed during a secrets-inclusive export.
    #[error("keychain error during export: {0}")]
    SecretStore(String),
}

/// Statistics returned by a successful [`import`] / [`import_from_json`] call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportStats {
    pub credential_folders_imported: usize,
    pub credentials_imported: usize,
    pub groups_imported: usize,
    pub connections_imported: usize,
    /// Number of individual secrets successfully written to the keychain.
    pub secrets_imported: usize,
    /// Number of app-settings key/value pairs applied (v2 envelopes).
    pub settings_imported: usize,
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// Export the full tree from `repo` into a versioned [`ExportEnvelope`].
///
/// Secrets are excluded unless `options.include_secrets == true` *and* a
/// `store` is supplied.  When `include_secrets` is `true` but `store` is
/// `None` the export succeeds with an empty `credential_secrets` list.
pub fn export(
    repo: &dyn ConnectionRepository,
    options: &ExportOptions,
    store: Option<&dyn CredentialStore>,
) -> Result<ExportEnvelope, ImportExportError> {
    let credential_folders = repo.list_credential_folders()?;
    let credentials = repo.list_credentials()?;
    let groups = repo.list_groups()?;
    let connections = repo.list_connections()?;

    let credential_secrets = if options.include_secrets {
        match store {
            Some(s) => collect_secrets(&credentials, s),
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };

    // v2: carry app settings, minus the volatile/machine-specific keys.
    let settings: Vec<(String, String)> = repo
        .list_settings()?
        .into_iter()
        .filter(|(k, _)| !EXPORT_EXCLUDED_SETTING_KEYS.contains(&k.as_str()))
        .collect();

    Ok(ExportEnvelope {
        conman_export_version: ENVELOPE_VERSION,
        exported_at: current_epoch_secs(),
        credential_folders,
        credentials,
        groups,
        connections,
        credential_secrets,
        settings,
    })
}

/// Serialise the export to a pretty-printed JSON string.
///
/// Convenience wrapper around [`export`] + `serde_json::to_string_pretty`.
pub fn export_to_json(
    repo: &dyn ConnectionRepository,
    options: &ExportOptions,
    store: Option<&dyn CredentialStore>,
) -> Result<String, ImportExportError> {
    let envelope = export(repo, options, store)?;
    serde_json::to_string_pretty(&envelope).map_err(ImportExportError::Json)
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/// Import an [`ExportEnvelope`] into `repo` (additive; every record gets a
/// fresh ID).
///
/// See the [module-level documentation][self] for full semantics.
///
/// If `store` is provided and the envelope contains secrets they are written
/// to the keychain under the **new** credential IDs.  Per-entry secret
/// failures are non-fatal; [`ImportStats::secrets_imported`] counts successes
/// only.
pub fn import(
    envelope: &ExportEnvelope,
    repo: &dyn ConnectionRepository,
    store: Option<&dyn CredentialStore>,
) -> Result<ImportStats, ImportExportError> {
    let found = envelope.conman_export_version;
    if !(MIN_SUPPORTED_VERSION..=ENVELOPE_VERSION).contains(&found) {
        return Err(ImportExportError::UnsupportedVersion {
            found,
            supported: ENVELOPE_VERSION,
        });
    }

    let mut stats = ImportStats::default();

    // Insertion order matters: each step depends on the maps built by the
    // previous steps.

    // 1. Credential folders (topologically sorted — parents first).
    let folder_id_map = import_credential_folders(&envelope.credential_folders, repo, &mut stats)?;

    // 2. Credentials (reference folders).
    let cred_id_map = import_credentials(&envelope.credentials, &folder_id_map, repo, &mut stats)?;

    // 3. Groups (topologically sorted; may reference credentials via
    //    default_credential).
    let group_id_map = import_groups(&envelope.groups, &cred_id_map, repo, &mut stats)?;

    // 4. Connections (reference groups and credentials).
    import_connections(
        &envelope.connections,
        &group_id_map,
        &cred_id_map,
        repo,
        &mut stats,
    )?;

    // 5. Secrets — non-fatal per-entry, guarded by store availability.
    if let Some(s) = store
        && !envelope.credential_secrets.is_empty()
    {
        import_secrets(&envelope.credential_secrets, &cred_id_map, s, &mut stats);
    }

    // 6. App settings (v2) — applied verbatim via set_setting. Absent in v1
    //    envelopes (empty). Excluded keys were already dropped at export; be
    //    defensive and skip them here too in case of hand-edited input.
    for (key, value) in &envelope.settings {
        if EXPORT_EXCLUDED_SETTING_KEYS.contains(&key.as_str()) {
            continue;
        }
        repo.set_setting(key, value)?;
        stats.settings_imported += 1;
    }

    Ok(stats)
}

/// Parse a JSON string and import it (convenience wrapper).
///
/// Returns [`ImportExportError::Malformed`] on empty input and
/// [`ImportExportError::Json`] on JSON parse failure — both without panicking.
pub fn import_from_json(
    json: &str,
    repo: &dyn ConnectionRepository,
    store: Option<&dyn CredentialStore>,
) -> Result<ImportStats, ImportExportError> {
    if json.trim().is_empty() {
        return Err(ImportExportError::Malformed("empty input".into()));
    }
    let envelope: ExportEnvelope = serde_json::from_str(json)?;
    import(&envelope, repo, store)
}

// ---------------------------------------------------------------------------
// Import helpers
// ---------------------------------------------------------------------------

fn import_credential_folders(
    folders: &[CredentialFolder],
    repo: &dyn ConnectionRepository,
    stats: &mut ImportStats,
) -> Result<HashMap<CredentialFolderId, CredentialFolderId>, ImportExportError> {
    let mut id_map: HashMap<CredentialFolderId, CredentialFolderId> = HashMap::new();

    for folder in topo_sort_folders(folders) {
        let new_parent = folder.parent_id.and_then(|old| id_map.get(&old).copied());
        let new_id = repo.upsert_credential_folder(&CredentialFolder {
            id: CredentialFolderId::UNSAVED,
            parent_id: new_parent,
            name: folder.name.clone(),
            sort: folder.sort,
        })?;
        id_map.insert(folder.id, new_id);
        stats.credential_folders_imported += 1;
    }

    Ok(id_map)
}

fn import_credentials(
    credentials: &[Credential],
    folder_id_map: &HashMap<CredentialFolderId, CredentialFolderId>,
    repo: &dyn ConnectionRepository,
    stats: &mut ImportStats,
) -> Result<HashMap<CredentialId, CredentialId>, ImportExportError> {
    let mut id_map: HashMap<CredentialId, CredentialId> = HashMap::new();

    for cred in credentials {
        let new_folder = cred
            .folder_id
            .and_then(|old| folder_id_map.get(&old).copied());
        let new_id = repo.upsert_credential(&Credential {
            id: CredentialId::UNSAVED,
            folder_id: new_folder,
            name: cred.name.clone(),
            kind: cred.kind,
            username: cred.username.clone(),
        })?;
        id_map.insert(cred.id, new_id);
        stats.credentials_imported += 1;
    }

    Ok(id_map)
}

fn import_groups(
    groups: &[Group],
    cred_id_map: &HashMap<CredentialId, CredentialId>,
    repo: &dyn ConnectionRepository,
    stats: &mut ImportStats,
) -> Result<HashMap<GroupId, GroupId>, ImportExportError> {
    let mut id_map: HashMap<GroupId, GroupId> = HashMap::new();

    for group in topo_sort_groups(groups) {
        let new_parent = group.parent_id.and_then(|old| id_map.get(&old).copied());
        let new_default_cred = group
            .default_credential
            .and_then(|old| cred_id_map.get(&old).copied());
        let new_id = repo.upsert_group(&Group {
            id: GroupId::UNSAVED,
            parent_id: new_parent,
            name: group.name.clone(),
            sort: group.sort,
            default_credential: new_default_cred,
        })?;
        id_map.insert(group.id, new_id);
        stats.groups_imported += 1;
    }

    Ok(id_map)
}

fn import_connections(
    connections: &[Connection],
    group_id_map: &HashMap<GroupId, GroupId>,
    cred_id_map: &HashMap<CredentialId, CredentialId>,
    repo: &dyn ConnectionRepository,
    stats: &mut ImportStats,
) -> Result<(), ImportExportError> {
    for conn in connections {
        let new_group = conn
            .group_id
            .and_then(|old| group_id_map.get(&old).copied());
        let new_cred = conn
            .credential
            .and_then(|old| cred_id_map.get(&old).copied());

        // Use Connection::new to re-validate the kind/settings invariant against
        // untrusted data.
        let to_insert = Connection::new(
            ConnectionId::UNSAVED,
            new_group,
            conn.name.clone(),
            conn.kind,
            conn.settings.clone(),
            new_cred,
            conn.sort,
            conn.created_at,
            conn.updated_at,
        )
        .map_err(|e| {
            ImportExportError::Malformed(format!(
                "connection '{}' failed domain validation: {e}",
                conn.name
            ))
        })?;

        repo.upsert_connection(&to_insert)?;
        stats.connections_imported += 1;
    }
    Ok(())
}

/// Write imported secrets to the keychain under the *new* credential IDs.
///
/// Errors on individual entries are non-fatal (skipped silently) to keep the
/// importer defensive against partial or malformed secret data.
fn import_secrets(
    secrets: &[ExportedSecret],
    cred_id_map: &HashMap<CredentialId, CredentialId>,
    store: &dyn CredentialStore,
    stats: &mut ImportStats,
) {
    for entry in secrets {
        // Remap old → new credential ID.
        let Some(&new_cred_id) = cred_id_map.get(&entry.credential_id) else {
            continue; // Credential not in this import batch.
        };

        let Some(purpose) = parse_purpose(&entry.purpose) else {
            continue; // Unknown purpose string in untrusted input.
        };

        let Ok(raw) = from_hex(&entry.secret_hex) else {
            continue; // Malformed hex.
        };

        let key = CredentialRef::new(new_cred_id, purpose);
        let secret = Secret::new(raw);
        match store.store(&key, &secret) {
            Ok(()) => stats.secrets_imported += 1,
            Err(e) => tracing::warn!(
                credential_id = new_cred_id.get(),
                purpose = purpose.as_str(),
                error = %e,
                "keychain store failed for imported secret"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Secret collection for export
// ---------------------------------------------------------------------------

fn collect_secrets(credentials: &[Credential], store: &dyn CredentialStore) -> Vec<ExportedSecret> {
    let mut out = Vec::new();
    for cred in credentials {
        let purposes: &[CredentialPurpose] = match cred.kind {
            CredentialKind::Password => &[CredentialPurpose::Password],
            CredentialKind::SshKey => &[CredentialPurpose::SshKey],
            CredentialKind::SshKeyWithPassphrase => {
                &[CredentialPurpose::SshKey, CredentialPurpose::SshPassphrase]
            }
        };
        for &purpose in purposes {
            let key = CredentialRef::new(cred.id, purpose);
            // Absent or error → skip; export continues (never fatal).
            match store.get(&key) {
                Ok(Some(secret)) => out.push(ExportedSecret {
                    credential_id: cred.id,
                    purpose: purpose.as_str().to_string(),
                    secret_hex: to_hex(secret.expose()),
                }),
                Ok(None) => tracing::debug!(
                    credential_id = cred.id.get(),
                    purpose = purpose.as_str(),
                    "secret absent during export"
                ),
                Err(e) => tracing::debug!(
                    credential_id = cred.id.get(),
                    purpose = purpose.as_str(),
                    error = %e,
                    "secret unreadable during export"
                ),
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Topological sort
// ---------------------------------------------------------------------------

fn topo_sort_folders(folders: &[CredentialFolder]) -> Vec<&CredentialFolder> {
    topo_sort(folders, |f| f.id, |f| f.parent_id)
}

fn topo_sort_groups(groups: &[Group]) -> Vec<&Group> {
    topo_sort(groups, |g| g.id, |g| g.parent_id)
}

/// Sort `items` so every parent is emitted before its children.
///
/// - Nodes whose `parent_id` is absent from the list are treated as roots.
/// - Cycles are detected by observing "no progress" over a full pass; the
///   remaining (cyclic) nodes are then flushed as roots rather than looping
///   forever.  Total passes are bounded by [`MAX_TOPO_PASSES`].
fn topo_sort<T, Id, FId, FPid>(items: &[T], id_fn: FId, parent_id_fn: FPid) -> Vec<&T>
where
    Id: std::hash::Hash + Eq + Copy,
    FId: Fn(&T) -> Id,
    FPid: Fn(&T) -> Option<Id>,
{
    let all_ids: HashSet<Id> = items.iter().map(&id_fn).collect();
    let mut emitted: HashSet<Id> = HashSet::new();
    let mut result: Vec<&T> = Vec::with_capacity(items.len());
    let mut remaining: Vec<&T> = items.iter().collect();

    for _ in 0..MAX_TOPO_PASSES {
        if remaining.is_empty() {
            break;
        }
        let before = remaining.len();
        remaining.retain(|item| {
            let parent_ready = match parent_id_fn(item) {
                None => true,                             // root node
                Some(p) if !all_ids.contains(&p) => true, // dangling ref → root
                Some(p) => emitted.contains(&p),          // parent already emitted
            };
            if parent_ready {
                emitted.insert(id_fn(item));
                result.push(item);
                false // remove from `remaining`
            } else {
                true // keep for next pass
            }
        });
        if remaining.len() == before {
            // No progress → cycle detected; append remaining as roots.
            for item in remaining.drain(..) {
                result.push(item);
            }
            break;
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

/// Current UTC time as epoch seconds; returns 0 on a pre-epoch system clock.
fn current_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

fn parse_purpose(s: &str) -> Option<CredentialPurpose> {
    match s {
        "password" => Some(CredentialPurpose::Password),
        "ssh-key" => Some(CredentialPurpose::SshKey),
        "ssh-passphrase" => Some(CredentialPurpose::SshPassphrase),
        _ => None,
    }
}

/// Encode raw bytes as a lower-case hex string.
///
/// `pub(crate)`: also reused by [`crate::import`]'s foreign-format importers
/// (e.g. RoyalTS, P9.2) to encode a plaintext secret into an
/// [`ExportedSecret`] without duplicating the encoder.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

/// Decode a hex string (upper- or lower-case) into bytes.
/// Returns `Err(())` on odd length or a non-hex character.
fn from_hex(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    // Safety: len is even and we step by 2, so bytes[i + 1] is always in bounds.
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]).ok_or(())?;
        let lo = hex_nibble(bytes[i + 1]).ok_or(())?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

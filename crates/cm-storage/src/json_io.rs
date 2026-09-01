//! Versioned JSON import/export for the full connection tree.
//!
//! ## Envelope schema (version 1)
//!
//! ```json
//! {
//! "conman_export_version": 1,
//! "exported_at": <epoch-seconds>,
//! "credential_folders": [...],
//! "credentials": [...],
//! "groups": [...],
//! "connections": [...],
//! "credential_secrets": [...] // omitted when empty
//! }
//! ```
//!
//! ## Import semantics (additive, pinned)
//!
//! Every imported record receives a **fresh** database ID; the IDs embedded in
//! the envelope are used only as intra-envelope link keys. Parent and
//! credential links are rewritten to the newly assigned IDs. Links to IDs not
//! present in the envelope are silently set to `None` (never a panic or hard
//! failure). Cyclic parent references in untrusted input are broken by
//! treating the offending node as a root — no abort, no loop. All database
//! writes are one transaction; keychain writes begin only after it commits.
//!
//! ## Secrets
//!
//! Secrets are **excluded by default**. When explicitly requested, every
//! expected secret must be readable or export fails without producing a
//! backup document. Encoding: lower-case hex (`secret_hex`).

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionRepository, Credential, CredentialFolder,
    CredentialFolderId, CredentialId, CredentialKind, CredentialPurpose, CredentialRef,
    CredentialSource, CredentialStore, Group, GroupId, Secret,
};
use serde::{Deserialize, Serialize};

use crate::repository::{AtomicImportRepository, ImportTransaction};

// Constants

/// Envelope schema version produced by this build.
///
/// [`export`] always emits this version and [`import`] accepts only this exact
/// schema. ConMan is greenfield, so import does not carry compatibility readers
/// for superseded envelope shapes.
pub const ENVELOPE_VERSION: u32 = 1;

/// Upper bound on topological-sort passes to guard against cyclic or otherwise
/// malformed input from untrusted JSON.
const MAX_TOPO_PASSES: usize = 1_024;

// Public types

/// Options controlling what is included in an [`export`] / [`export_to_json`] call.
#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    /// When `true`, resolved secrets are fetched from the keychain and embedded
    /// in [`ExportEnvelope::credential_secrets`].
    ///
    /// # WARNING
    /// This option embeds **plain-text secret material** into the JSON output.
    /// Only set it when the operator has explicitly requested a
    /// secrets-inclusive export. Treat the resulting file with the same care
    /// as a private-key or password database.
    pub include_secrets: bool,
}

/// Completeness accounting for a secret-inclusive backup.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SecretExportReport {
    pub attempted: usize,
    pub included: usize,
    pub failures: usize,
}

impl SecretExportReport {
    fn merge(&mut self, other: Self) {
        self.attempted += other.attempted;
        self.included += other.included;
        self.failures += other.failures;
    }
}

/// Structured result of exporting the connection tree.
#[derive(Debug, Clone)]
pub struct ExportOutcome {
    pub envelope: ExportEnvelope,
    pub secret_report: SecretExportReport,
}

impl std::ops::Deref for ExportOutcome {
    type Target = ExportEnvelope;

    fn deref(&self) -> &Self::Target {
        &self.envelope
    }
}

/// JSON serialization plus the same completeness report as [`ExportOutcome`].
#[derive(Debug, Clone)]
pub struct ExportJsonOutcome {
    pub json: String,
    pub secret_report: SecretExportReport,
}

impl std::ops::Deref for ExportJsonOutcome {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.json
    }
}

impl AsRef<[u8]> for ExportJsonOutcome {
    fn as_ref(&self) -> &[u8] {
        self.json.as_bytes()
    }
}

/// Versioned JSON export envelope.
///
/// Serialised with `serde_json`; the schema is pinned at version
/// [`ENVELOPE_VERSION`]. Deserialising an envelope with a different version
/// succeeds at the JSON level but [`import`] will reject it with
/// [`ImportExportError::UnsupportedVersion`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportEnvelope {
    pub conman_export_version: u32,
    /// UTC epoch-seconds at export time.
    pub exported_at: i64,
    pub credential_folders: Vec<CredentialFolder>,
    pub credentials: Vec<Credential>,
    pub groups: Vec<Group>,
    pub connections: Vec<Connection>,
    /// Present only when [`ExportOptions::include_secrets`] is `true` and
    /// secrets were available. Omitted from serialisation when empty so a
    /// default export carries no hint of the field.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub credential_secrets: Vec<ExportedSecret>,
    /// Inline (`CredentialSource::Inline`) per-connection secrets, the
    /// connection-scoped counterpart to `credential_secrets`. Populated only
    /// when [`ExportOptions::include_secrets`] is `true`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub connection_secrets: Vec<ExportedConnectionSecret>,
}

/// One secret entry in a gated export, tied to a credential **object**.
///
/// `secret_hex` is the raw secret bytes encoded as lower-case hex. For
/// password credentials this is the UTF-8 bytes of the password; for SSH
/// credentials it is the bytes of the PEM-encoded private key.
///
/// `purpose` is one of the stable [`CredentialPurpose`] string forms:
/// `"password"`, `"ssh-key"`, or `"ssh-passphrase"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedSecret {
    /// The **exported** (pre-remap) credential ID. During import this is
    /// looked up in the remap table to find the freshly assigned ID.
    pub credential_id: CredentialId,
    /// Stable purpose tag from [`CredentialPurpose::as_str`].
    pub purpose: String,
    /// Raw secret bytes encoded as lower-case hex (no `base64` dep needed).
    pub secret_hex: String,
}

/// One inline (`CredentialSource::Inline`) secret entry, tied to a
/// **connection** rather than a credential object — the counterpart to
/// [`ExportedSecret`]. Always `purpose == "password"` in practice today
/// because inline authentication is password-only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedConnectionSecret {
    /// The **exported** (pre-remap) connection ID. During import this is
    /// looked up in the connection-id remap table built while importing
    /// connections, mirroring how `ExportedSecret::credential_id` is remapped.
    pub connection_id: ConnectionId,
    /// Stable purpose tag from [`CredentialPurpose::as_str`].
    pub purpose: String,
    /// Raw secret bytes encoded as lower-case hex.
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
    /// A requested secret-inclusive backup could not retrieve every expected
    /// secret. No envelope or JSON document is returned in this case.
    #[error(
        "secret-inclusive export incomplete: attempted {attempted}, included {included}, failures {failures}"
    )]
    IncompleteSecretExport {
        attempted: usize,
        included: usize,
        failures: usize,
    },
    /// the attempted password did not decrypt an mRemoteNG file's
    /// encrypted fields (wrong password, or a custom one was never
    /// supplied). The caller should prompt for the correct password and
    /// retry via `import::import_from_path_with_password`. Never raised for
    /// any other import format.
    #[error("a password is required to decrypt this file's secrets")]
    PasswordRequired,
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
}

// Export

/// Export the full tree from `repo` into a versioned [`ExportEnvelope`].
///
/// Secrets are excluded unless `options.include_secrets == true`. A requested
/// secret-inclusive export succeeds only when every expected secret can be
/// retrieved; otherwise it fails before returning an envelope.
pub fn export(
    repo: &dyn ConnectionRepository,
    options: &ExportOptions,
    store: Option<&dyn CredentialStore>,
) -> Result<ExportOutcome, ImportExportError> {
    let credential_folders = repo.list_credential_folders()?;
    let credentials = repo.list_credentials()?;
    let groups = repo.list_groups()?;
    let connections = repo.list_connections()?;

    let (credential_secrets, connection_secrets, secret_report) = if options.include_secrets {
        let (credential_secrets, mut report) = collect_secrets(&credentials, store);
        let (connection_secrets, connection_report) =
            collect_connection_secrets(&connections, store);
        report.merge(connection_report);
        (credential_secrets, connection_secrets, report)
    } else {
        (Vec::new(), Vec::new(), SecretExportReport::default())
    };

    if secret_report.failures > 0 {
        return Err(ImportExportError::IncompleteSecretExport {
            attempted: secret_report.attempted,
            included: secret_report.included,
            failures: secret_report.failures,
        });
    }

    tracing::info!(
        credentials = credentials.len(),
        groups = groups.len(),
        connections = connections.len(),
        secrets = credential_secrets.len(),
        connection_secrets = connection_secrets.len(),
        include_secrets = options.include_secrets,
        "exporting envelope"
    );

    Ok(ExportOutcome {
        envelope: ExportEnvelope {
            conman_export_version: ENVELOPE_VERSION,
            exported_at: current_epoch_secs(),
            credential_folders,
            credentials,
            groups,
            connections,
            credential_secrets,
            connection_secrets,
        },
        secret_report,
    })
}

/// Serialise the export to a pretty-printed JSON string.
///
/// Convenience wrapper around [`export`] + `serde_json::to_string_pretty`.
pub fn export_to_json(
    repo: &dyn ConnectionRepository,
    options: &ExportOptions,
    store: Option<&dyn CredentialStore>,
) -> Result<ExportJsonOutcome, ImportExportError> {
    let outcome = export(repo, options, store)?;
    let json = serde_json::to_string_pretty(&outcome.envelope)?;
    Ok(ExportJsonOutcome {
        json,
        secret_report: outcome.secret_report,
    })
}

// Import

/// Import an [`ExportEnvelope`] into `repo` (additive; every record gets a
/// fresh ID).
///
/// See the [module-level documentation][self] for full semantics.
///
/// Database changes commit atomically before any keychain mutation. If `store`
/// is provided, envelope secrets are then written under the **new** IDs;
/// per-entry keychain failures remain non-fatal and
/// [`ImportStats::secrets_imported`] counts successes only.
pub fn import(
    envelope: &ExportEnvelope,
    repo: &dyn AtomicImportRepository,
    store: Option<&dyn CredentialStore>,
) -> Result<ImportStats, ImportExportError> {
    let found = envelope.conman_export_version;
    if found != ENVELOPE_VERSION {
        tracing::warn!(
            found,
            supported = ENVELOPE_VERSION,
            "rejecting import: unsupported envelope version"
        );
        return Err(ImportExportError::UnsupportedVersion {
            found,
            supported: ENVELOPE_VERSION,
        });
    }

    // Validate all untrusted connections before performing any repository
    // mutation. In particular, malformed Telnet profiles must be rejected,
    // not normalized into the interactive-login contract during import.
    for conn in &envelope.connections {
        conn.validate().map_err(|e| {
            ImportExportError::Malformed(format!(
                "connection '{}' failed domain validation: {e}",
                conn.name
            ))
        })?;
    }

    let mut stats = ImportStats::default();
    let mut transaction = repo.begin_import()?;

    // Insertion order matters: each step depends on the maps built by the
    // previous steps.

    // 1. Credential folders (topologically sorted — parents first).
    let folder_id_map = import_credential_folders(
        &envelope.credential_folders,
        transaction.as_mut(),
        &mut stats,
    )?;

    // 2. Credentials (reference folders).
    let cred_id_map = import_credentials(
        &envelope.credentials,
        &folder_id_map,
        transaction.as_mut(),
        &mut stats,
    )?;

    // 3. Groups (topologically sorted; may reference credentials via
    // default_credential).
    let group_id_map = import_groups(
        &envelope.groups,
        &cred_id_map,
        transaction.as_mut(),
        &mut stats,
    )?;

    // 4. Connections (reference groups and credentials).
    let (conn_id_map, connection_secret_ids) = import_connections(
        &envelope.connections,
        &group_id_map,
        &cred_id_map,
        transaction.as_mut(),
        &mut stats,
    )?;

    // Commit all database records before adopting any secret into the
    // keychain. A write or commit failure therefore rolls the whole batch back
    // and cannot leave secrets referring to records that were never imported.
    transaction.commit()?;

    // 5. Secrets — non-fatal per-entry, guarded by store availability.
    if let Some(s) = store {
        if !envelope.credential_secrets.is_empty() {
            import_secrets(&envelope.credential_secrets, &cred_id_map, s, &mut stats);
        }
        if !envelope.connection_secrets.is_empty() {
            import_connection_secrets(
                &envelope.connection_secrets,
                &conn_id_map,
                &connection_secret_ids,
                s,
                &mut stats,
            );
        }
    }

    tracing::info!(
        folders = stats.credential_folders_imported,
        credentials = stats.credentials_imported,
        groups = stats.groups_imported,
        connections = stats.connections_imported,
        secrets = stats.secrets_imported,
        "import complete"
    );

    Ok(stats)
}

/// Parse a JSON string and import it (convenience wrapper).
///
/// Returns [`ImportExportError::Malformed`] on empty input and
/// [`ImportExportError::Json`] on JSON parse failure — both without panicking.
pub fn import_from_json(
    json: &str,
    repo: &dyn AtomicImportRepository,
    store: Option<&dyn CredentialStore>,
) -> Result<ImportStats, ImportExportError> {
    if json.trim().is_empty() {
        return Err(ImportExportError::Malformed("empty input".into()));
    }
    let envelope: ExportEnvelope = serde_json::from_str(json)?;
    import(&envelope, repo, store)
}

// Import helpers

fn import_credential_folders(
    folders: &[CredentialFolder],
    transaction: &mut dyn ImportTransaction,
    stats: &mut ImportStats,
) -> Result<HashMap<CredentialFolderId, CredentialFolderId>, ImportExportError> {
    let mut id_map: HashMap<CredentialFolderId, CredentialFolderId> = HashMap::new();

    for folder in topo_sort_folders(folders) {
        let new_parent = folder.parent_id.and_then(|old| id_map.get(&old).copied());
        let new_id = transaction.insert_credential_folder(&CredentialFolder {
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
    transaction: &mut dyn ImportTransaction,
    stats: &mut ImportStats,
) -> Result<HashMap<CredentialId, CredentialId>, ImportExportError> {
    let mut id_map: HashMap<CredentialId, CredentialId> = HashMap::new();

    for cred in credentials {
        let new_folder = cred
            .folder_id
            .and_then(|old| folder_id_map.get(&old).copied());
        let new_id = transaction.insert_credential(&Credential {
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
    transaction: &mut dyn ImportTransaction,
    stats: &mut ImportStats,
) -> Result<HashMap<GroupId, GroupId>, ImportExportError> {
    let mut id_map: HashMap<GroupId, GroupId> = HashMap::new();

    for group in topo_sort_groups(groups) {
        let new_parent = group.parent_id.and_then(|old| id_map.get(&old).copied());
        let new_default_cred = group
            .default_credential
            .and_then(|old| cred_id_map.get(&old).copied());
        let new_id = transaction.insert_group(&Group {
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

/// Remaps a [`CredentialSource`]'s `Object` id through
/// `cred_id_map`, exactly like every other cross-reference in this file — a
/// reference to a credential outside this import batch silently collapses to
/// `None` (inherit), never a hard failure. `Inline`/`Prompt` pass through
/// unchanged (nothing to remap; an `Inline` secret is remapped separately, by
/// connection id, in [`import_connection_secrets`]).
fn remap_credential_source(
    source: Option<CredentialSource>,
    cred_id_map: &HashMap<CredentialId, CredentialId>,
) -> Option<CredentialSource> {
    match source {
        Some(CredentialSource::Object(old_id)) => cred_id_map
            .get(&old_id)
            .copied()
            .map(CredentialSource::Object),
        other => other,
    }
}

fn import_connections(
    connections: &[Connection],
    group_id_map: &HashMap<GroupId, GroupId>,
    cred_id_map: &HashMap<CredentialId, CredentialId>,
    transaction: &mut dyn ImportTransaction,
    stats: &mut ImportStats,
) -> Result<(HashMap<ConnectionId, ConnectionId>, HashSet<ConnectionId>), ImportExportError> {
    let mut id_map: HashMap<ConnectionId, ConnectionId> = HashMap::new();
    let mut connection_secret_ids = HashSet::new();

    for conn in connections {
        let new_group = conn
            .group_id
            .and_then(|old| group_id_map.get(&old).copied());
        let new_source = remap_credential_source(conn.credential_source.clone(), cred_id_map);

        // Use Connection::new to re-validate the kind/settings invariant against
        // untrusted data.
        let to_insert = Connection::new(
            ConnectionId::UNSAVED,
            new_group,
            conn.name.clone(),
            conn.kind,
            conn.settings.clone(),
            new_source,
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

        let new_id = transaction.insert_connection(&to_insert)?;
        if matches!(
            to_insert.credential_source,
            Some(CredentialSource::Inline {
                has_secret: true,
                ..
            })
        ) {
            connection_secret_ids.insert(new_id);
        }
        id_map.insert(conn.id, new_id);
        stats.connections_imported += 1;
    }
    Ok((id_map, connection_secret_ids))
}

/// Write imported secrets to the keychain under the *new* credential IDs.
///
/// Errors on individual entries are non-fatal — logged (never silently) and
/// skipped, to keep the importer defensive against partial or malformed
/// secret data without aborting the whole batch.
fn import_secrets(
    secrets: &[ExportedSecret],
    cred_id_map: &HashMap<CredentialId, CredentialId>,
    store: &dyn CredentialStore,
    stats: &mut ImportStats,
) {
    for entry in secrets {
        // Remap old → new credential ID.
        let Some(&new_cred_id) = cred_id_map.get(&entry.credential_id) else {
            tracing::warn!(
                credential_id = entry.credential_id.get(),
                "skipping imported secret: credential not in this import batch"
            );
            continue;
        };

        let Some(purpose) = parse_purpose(&entry.purpose) else {
            tracing::warn!(
                credential_id = new_cred_id.get(),
                purpose = %entry.purpose,
                "skipping imported secret: unrecognized purpose"
            );
            continue;
        };

        let Ok(raw) = from_hex(&entry.secret_hex) else {
            tracing::warn!(
                credential_id = new_cred_id.get(),
                purpose = purpose.as_str(),
                "skipping imported secret: malformed hex"
            );
            continue;
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

/// write imported *inline* (connection-scoped) secrets to the
/// keychain under the *new* connection IDs — the `CredentialRef::for_connection`
/// counterpart to [`import_secrets`]. Same defensive, non-fatal-per-entry
/// posture.
fn import_connection_secrets(
    secrets: &[ExportedConnectionSecret],
    conn_id_map: &HashMap<ConnectionId, ConnectionId>,
    eligible_connection_ids: &HashSet<ConnectionId>,
    store: &dyn CredentialStore,
    stats: &mut ImportStats,
) {
    for entry in secrets {
        let Some(&new_conn_id) = conn_id_map.get(&entry.connection_id) else {
            tracing::warn!(
                connection_id = entry.connection_id.get(),
                "skipping imported connection secret: connection not in this import batch"
            );
            continue;
        };
        if !eligible_connection_ids.contains(&new_conn_id) {
            tracing::warn!(
                connection_id = new_conn_id.get(),
                "skipping imported connection secret: connection does not use inline credentials"
            );
            continue;
        }

        let Some(purpose) = parse_purpose(&entry.purpose) else {
            tracing::warn!(
                connection_id = new_conn_id.get(),
                purpose = %entry.purpose,
                "skipping imported connection secret: unrecognized purpose"
            );
            continue;
        };

        let Ok(raw) = from_hex(&entry.secret_hex) else {
            tracing::warn!(
                connection_id = new_conn_id.get(),
                purpose = purpose.as_str(),
                "skipping imported connection secret: malformed hex"
            );
            continue;
        };

        let key = CredentialRef::for_connection(new_conn_id, purpose);
        let secret = Secret::new(raw);
        match store.store(&key, &secret) {
            Ok(()) => stats.secrets_imported += 1,
            Err(e) => tracing::warn!(
                connection_id = new_conn_id.get(),
                purpose = purpose.as_str(),
                error = %e,
                "keychain store failed for imported connection secret"
            ),
        }
    }
}

// Secret collection for export

fn collect_secrets(
    credentials: &[Credential],
    store: Option<&dyn CredentialStore>,
) -> (Vec<ExportedSecret>, SecretExportReport) {
    let mut out = Vec::new();
    let mut report = SecretExportReport::default();
    for cred in credentials {
        let purposes: &[CredentialPurpose] = match cred.kind {
            CredentialKind::Password => &[CredentialPurpose::Password],
            CredentialKind::SshKey => &[CredentialPurpose::SshKey],
            CredentialKind::SshKeyWithPassphrase => {
                &[CredentialPurpose::SshKey, CredentialPurpose::SshPassphrase]
            }
        };
        for &purpose in purposes {
            report.attempted += 1;
            let key = CredentialRef::new(cred.id, purpose);
            match store.map(|store| store.get(&key)) {
                Some(Ok(Some(secret))) => {
                    report.included += 1;
                    out.push(ExportedSecret {
                        credential_id: cred.id,
                        purpose: purpose.as_str().to_string(),
                        secret_hex: to_hex(secret.expose()),
                    });
                }
                Some(Ok(None)) | None => {
                    report.failures += 1;
                    tracing::warn!(
                        credential_id = cred.id.get(),
                        purpose = purpose.as_str(),
                        "required secret absent during secret-inclusive export"
                    );
                }
                Some(Err(error)) => {
                    report.failures += 1;
                    tracing::warn!(
                        credential_id = cred.id.get(),
                        purpose = purpose.as_str(),
                        %error,
                        "required secret unreadable during secret-inclusive export"
                    );
                }
            }
        }
    }
    (out, report)
}

/// the `CredentialSource::Inline` counterpart to [`collect_secrets`] —
/// reads `conn:<id>:password` for every connection whose source is `Inline`
/// with `has_secret: true`. Password-only (inline never stores any other
/// purpose, per the non-goals), same absent/error-is-never-fatal posture.
fn collect_connection_secrets(
    connections: &[Connection],
    store: Option<&dyn CredentialStore>,
) -> (Vec<ExportedConnectionSecret>, SecretExportReport) {
    let mut out = Vec::new();
    let mut report = SecretExportReport::default();
    for conn in connections {
        // A valid Telnet profile can only use Prompt. Keep this explicit so
        // even a malformed repository row cannot make a Telnet secret leave
        // the machine during a secrets-inclusive export.
        if conn.kind == ConnectionKind::Telnet {
            continue;
        }
        let Some(CredentialSource::Inline {
            has_secret: true, ..
        }) = &conn.credential_source
        else {
            continue;
        };
        report.attempted += 1;
        let key = CredentialRef::for_connection(conn.id, CredentialPurpose::Password);
        match store.map(|store| store.get(&key)) {
            Some(Ok(Some(secret))) => {
                report.included += 1;
                out.push(ExportedConnectionSecret {
                    connection_id: conn.id,
                    purpose: CredentialPurpose::Password.as_str().to_string(),
                    secret_hex: to_hex(secret.expose()),
                });
            }
            Some(Ok(None)) | None => {
                report.failures += 1;
                tracing::warn!(
                    connection_id = conn.id.get(),
                    "required inline secret absent during secret-inclusive export"
                );
            }
            Some(Err(error)) => {
                report.failures += 1;
                tracing::warn!(
                    connection_id = conn.id.get(),
                    %error,
                    "required inline secret unreadable during secret-inclusive export"
                );
            }
        }
    }
    (out, report)
}

// Topological sort

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
///   forever. Total passes are bounded by [`MAX_TOPO_PASSES`].
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

// Misc helpers

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
/// (e.g. RoyalTS) to encode a plaintext secret into an
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
/// Returns `Err` on odd length or a non-hex character.
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

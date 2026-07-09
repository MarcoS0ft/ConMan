//! ConMan's own CSV interchange-format importer (P9.3).
//!
//! Unlike RoyalTS/mRemoteNG, this is not a foreign product's export format —
//! it's an interchange schema ConMan owns, designed for hand-authored or
//! spreadsheet-exported connection lists. Same architecture as every other
//! importer in this module: parse into an in-memory [`ExportEnvelope`], then
//! hand it to the existing, unmodified [`crate::json_io::import`] seam.
//!
//! Uses the `csv` crate (memos/P9.3-csv-dep.md) rather than a hand-rolled
//! splitter: RFC 4180 quoting/escaping is needed for `ssh_private_key_pem`,
//! which is expected to carry a multi-line PEM block, and
//! [`::csv::StringRecord::position`] gives an exact source line number for
//! free — used verbatim as the "row N" in every [`ImportWarning`].
//!
//! ## Schema
//! Header row required; columns are matched **case-insensitively and by
//! name**, so column order doesn't matter and unrecognized extra columns are
//! logged once (DEBUG) and otherwise ignored:
//!
//! `name, kind, group_path, host, port, username, domain, auth_method,
//! password, ssh_private_key_pem, ssh_passphrase, width, height,
//! color_depth, cred_name`
//!
//! - `kind` = `ssh` | `rdp` | `local` (case-insensitive). Anything else, or a
//!   missing `name`/`kind`, or a missing `host` on an ssh/rdp row, skips the
//!   row with a counted [`ImportWarning`] naming the row number and reason —
//!   never silent.
//! - `group_path` is `/`-separated (e.g. `Prod/Web`), creating nested groups
//!   deduped by full path string (mirrors [`super::royalts`]'s per-document
//!   dedupe philosophy, just keyed by path instead of a foreign object ID).
//!   Blank → root level.
//! - `port` blank or unparsable → the kind's default (22 ssh / 3389 rdp).
//!   `width`/`height`/`color_depth` (rdp only) blank or unparsable →
//!   [`RdpSettings`]'s own defaults — these are never fatal to the row (a
//!   malformed number just falls back rather than aborting an otherwise-good
//!   connection).
//! - `auth_method` (ssh: `password` | `key` | `agent` | `prompt`; rdp has no
//!   settings-level auth method, so the column there only gates whether a
//!   `password` is treated as secret material — see below) — blank defaults
//!   to `password`; an unrecognized value defaults to `password` too, with a
//!   counted warning (never silently reinterpreted).
//! - **Secrets — this is the only import format that can carry SSH keys.**
//!   `password` → [`ExportedSecret`] (purpose `password`).
//!   `ssh_private_key_pem` (+ optional `ssh_passphrase`) → `ExportedSecret`(s)
//!   (purpose `ssh-key` / `ssh-passphrase`). `agent` and `prompt` rows never
//!   store secret material even if those columns are non-empty (explicit
//!   "don't store" intent). `local` rows never get a credential attached
//!   (no auth concept in [`LocalSettings`]).
//! - **Credential handling:** if `cred_name` is set, **dedupe** — one
//!   [`Credential`] per unique `cred_name`, referenced by every row sharing
//!   it. Two passes over the parsed rows ([`collect_credentials`] then
//!   [`walk_rows`]) mirror [`super::royalts`]'s dedupe-by-construction
//!   architecture: the *first* row (by file order) carrying both a given
//!   `cred_name` **and** actual secret material registers the credential;
//!   earlier/later rows that only reference the name by find it already
//!   there. A `cred_name` mentioned but never backed by secret material on
//!   any row simply resolves to no credential (never a hard error — the
//!   connection still imports, just without one). Without `cred_name`, each
//!   row gets its own private credential (only created when the row itself
//!   carries secret material).
//! - `username`/`domain` land on the **connection's** settings (consistent
//!   with the current model — the P9.6 `CredentialSource` model change lands
//!   separately and this stays compatible); the credential created for a
//!   `cred_name`/per-row secret also carries `username` so it's still
//!   authoritative post-assignment (mirrors [`super::royalts::register_credential`]).

use std::collections::HashMap;

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionSettings, Credential, CredentialId,
    CredentialKind, CredentialPurpose, CredentialRef, Group, GroupId, LocalSettings, RdpSettings,
    SshAuthMethod, SshSettings,
};

use crate::json_io::{self, ExportEnvelope, ExportedSecret, ImportExportError};

use super::ImportWarning;

/// Header names this importer understands (case-insensitive). Anything else
/// in the header row is ignored (logged once, DEBUG) rather than rejected —
/// tolerates hand-authored files with extra bookkeeping columns.
const KNOWN_COLUMNS: &[&str] = &[
    "name",
    "kind",
    "group_path",
    "host",
    "port",
    "username",
    "domain",
    "auth_method",
    "password",
    "ssh_private_key_pem",
    "ssh_passphrase",
    "width",
    "height",
    "color_depth",
    "cred_name",
];

/// Header name (lower-cased) → column index.
type HeaderIndex = HashMap<String, usize>;

/// Parse a ConMan-schema CSV document into a v1 [`ExportEnvelope`] plus any
/// counted [`ImportWarning`]s. IDs assigned here are synthetic, file-scoped
/// link keys only — [`crate::json_io::import`] remaps every record to a
/// fresh database ID, exactly as it does for a native `.json` export.
pub fn parse(contents: &str) -> Result<(ExportEnvelope, Vec<ImportWarning>), ImportExportError> {
    let mut reader = ::csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true) // tolerate rows with fewer/extra trailing columns than the header
        .from_reader(contents.as_bytes());

    let headers = reader.headers().map_err(|e| {
        ImportExportError::Malformed(format!("csv: failed to read header row: {e}"))
    })?;
    if headers.is_empty() {
        return Err(ImportExportError::Malformed(
            "csv: missing header row".into(),
        ));
    }
    let mut idx = HashMap::new();
    let mut unknown = Vec::new();
    for (i, h) in headers.iter().enumerate() {
        let lower = h.trim().to_ascii_lowercase();
        if !KNOWN_COLUMNS.contains(&lower.as_str()) {
            unknown.push(lower.clone());
        }
        idx.insert(lower, i);
    }
    if !unknown.is_empty() {
        tracing::debug!(columns = ?unknown, "csv: unrecognized columns ignored");
    }

    let records: Vec<::csv::StringRecord> = reader
        .records()
        .collect::<Result<_, _>>()
        .map_err(|e| ImportExportError::Malformed(format!("csv: {e}")))?;

    let mut ctx = ParseCtx::default();
    collect_credentials(&records, &idx, &mut ctx);
    walk_rows(&records, &idx, &mut ctx);

    let envelope = ExportEnvelope {
        conman_export_version: json_io::MIN_SUPPORTED_VERSION,
        exported_at: 0, // foreign/own-format import: no meaningful export timestamp
        credential_folders: Vec::new(),
        credentials: ctx.credentials,
        groups: ctx.groups,
        connections: ctx.connections,
        credential_secrets: ctx.credential_secrets,
        settings: Vec::new(),
    };

    Ok((envelope, ctx.warnings))
}

// ---------------------------------------------------------------------------
// Parse state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ParseCtx {
    groups: Vec<Group>,
    credentials: Vec<Credential>,
    credential_secrets: Vec<ExportedSecret>,
    connections: Vec<Connection>,
    warnings: Vec<ImportWarning>,
    /// Full `group_path` string (e.g. `"Prod/Web"`) → the synthetic
    /// [`GroupId`] minted for it — this map *is* the path-dedupe.
    group_path_to_id: HashMap<String, GroupId>,
    /// `cred_name` → the synthetic [`CredentialId`] minted for it — this map
    /// *is* the name-dedupe (built in [`collect_credentials`], consulted in
    /// [`walk_rows`]).
    cred_name_to_id: HashMap<String, CredentialId>,
    next_group_id: i64,
    next_cred_id: i64,
    next_conn_id: i64,
}

impl ParseCtx {
    fn fresh_group_id(&mut self) -> GroupId {
        self.next_group_id += 1;
        GroupId::new(self.next_group_id)
    }

    fn fresh_cred_id(&mut self) -> CredentialId {
        self.next_cred_id += 1;
        CredentialId::new(self.next_cred_id)
    }

    fn fresh_conn_id(&mut self) -> ConnectionId {
        self.next_conn_id += 1;
        ConnectionId::new(self.next_conn_id)
    }
}

// ---------------------------------------------------------------------------
// Field access
// ---------------------------------------------------------------------------

/// Looks up `name` (case-insensitive) in `rec` via the header index; a
/// missing column, a missing cell, or a blank (whitespace-only) value are all
/// treated the same — `None`.
fn field(idx: &HeaderIndex, rec: &::csv::StringRecord, name: &str) -> Option<String> {
    let i = *idx.get(name)?;
    let v = rec.get(i)?.trim();
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

/// The 1-based source line number for `rec`, used in every "row N" warning.
/// `csv::Reader` tracks this even across a multi-line quoted field (e.g. a
/// PEM block spanning several physical lines still reports the record's
/// *starting* line) — falls back to the record index (data rows start after
/// the header) only if the reader somehow didn't track a position.
fn row_number(rec: &::csv::StringRecord, index: usize) -> u64 {
    rec.position().map(|p| p.line()).unwrap_or(index as u64 + 2)
}

/// Parses `raw` as `T`, falling back to `default` on `None` or a parse
/// failure — used for port/width/height/color_depth, none of which are
/// fatal to the row when malformed (unlike `name`/`kind`/`host`).
fn parse_or<T: std::str::FromStr>(raw: Option<&str>, default: T) -> T {
    raw.and_then(|s| s.trim().parse::<T>().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Secret-material classification (shared by both passes)
// ---------------------------------------------------------------------------

/// Determines what (if any) secret material a row supplies, from its own
/// `auth_method`/`password`/`ssh_private_key_pem`/`ssh_passphrase` columns.
/// `None` means the row carries no secret to store — including the explicit
/// `agent`/`prompt` cases, where any populated secret columns are
/// deliberately ignored (the user asked for no stored secret).
fn secret_material_for_row(
    auth_method: &str,
    password: Option<&str>,
    ssh_key: Option<&str>,
    ssh_passphrase: Option<&str>,
) -> Option<(CredentialKind, Vec<(CredentialPurpose, String)>)> {
    match auth_method.trim().to_ascii_lowercase().as_str() {
        "agent" | "prompt" => None,
        "key" => {
            let key_pem = ssh_key?;
            let kind = if ssh_passphrase.is_some() {
                CredentialKind::SshKeyWithPassphrase
            } else {
                CredentialKind::SshKey
            };
            let mut secrets = vec![(CredentialPurpose::SshKey, key_pem.to_string())];
            if let Some(p) = ssh_passphrase {
                secrets.push((CredentialPurpose::SshPassphrase, p.to_string()));
            }
            Some((kind, secrets))
        }
        // "" (blank defaults to password) | "password" | any unrecognized
        // value (defaulted to password by `ssh_auth_method`, warned there).
        _ => {
            let pw = password?;
            Some((
                CredentialKind::Password,
                vec![(CredentialPurpose::Password, pw.to_string())],
            ))
        }
    }
}

fn push_secrets(
    ctx: &mut ParseCtx,
    cred_id: CredentialId,
    secrets: Vec<(CredentialPurpose, String)>,
) {
    for (purpose, secret) in secrets {
        ctx.credential_secrets.push(ExportedSecret {
            credential_id: cred_id,
            purpose: purpose.as_str().to_string(),
            secret_hex: json_io::to_hex(secret.as_bytes()),
        });
    }
}

// ---------------------------------------------------------------------------
// Pass 1: `cred_name` credential dedupe
// ---------------------------------------------------------------------------

fn collect_credentials(records: &[::csv::StringRecord], idx: &HeaderIndex, ctx: &mut ParseCtx) {
    for rec in records {
        let Some(cred_name) = field(idx, rec, "cred_name") else {
            continue;
        };
        if ctx.cred_name_to_id.contains_key(&cred_name) {
            continue; // already registered — first row supplying secret material wins.
        }
        let auth_method = field(idx, rec, "auth_method").unwrap_or_default();
        let username = field(idx, rec, "username");
        let password = field(idx, rec, "password");
        let ssh_key = field(idx, rec, "ssh_private_key_pem");
        let ssh_passphrase = field(idx, rec, "ssh_passphrase");

        let Some((cred_kind, secrets)) = secret_material_for_row(
            &auth_method,
            password.as_deref(),
            ssh_key.as_deref(),
            ssh_passphrase.as_deref(),
        ) else {
            // No secret material on *this* row — a later row sharing the
            // same cred_name may still supply it.
            continue;
        };

        let cred_id = ctx.fresh_cred_id();
        ctx.credentials.push(Credential {
            id: cred_id,
            name: cred_name.clone(),
            kind: cred_kind,
            folder_id: None,
            username,
        });
        push_secrets(ctx, cred_id, secrets);
        ctx.cred_name_to_id.insert(cred_name, cred_id);
    }
}

// ---------------------------------------------------------------------------
// Pass 2: group tree + connections
// ---------------------------------------------------------------------------

fn walk_rows(records: &[::csv::StringRecord], idx: &HeaderIndex, ctx: &mut ParseCtx) {
    for (i, rec) in records.iter().enumerate() {
        let row_num = row_number(rec, i);
        process_row(row_num, rec, idx, ctx);
    }
}

/// Resolves (or creates) the group chain for a `/`-separated `group_path`,
/// deduped by full path string. Blank → root (`None`).
fn ensure_group_path(ctx: &mut ParseCtx, path: &str) -> Option<GroupId> {
    let mut parent: Option<GroupId> = None;
    let mut acc = String::new();
    for segment in path.split('/') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue; // tolerate leading/trailing/doubled '/'
        }
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(segment);
        if let Some(&id) = ctx.group_path_to_id.get(&acc) {
            parent = Some(id);
            continue;
        }
        let id = ctx.fresh_group_id();
        ctx.groups.push(Group {
            id,
            parent_id: parent,
            name: segment.to_string(),
            sort: 0,
            default_credential: None,
        });
        ctx.group_path_to_id.insert(acc.clone(), id);
        parent = Some(id);
    }
    parent
}

/// Resolves the [`CredentialId`] (if any) a row's connection should carry:
/// the shared `cred_name` credential (pass 1), or a fresh per-row credential
/// built from this row's own secret material, or `None`. `local` rows never
/// get a credential — [`LocalSettings`] has no auth concept.
#[allow(clippy::too_many_arguments)]
fn resolve_row_credential(
    ctx: &mut ParseCtx,
    kind: ConnectionKind,
    auth_method: &str,
    username: Option<&str>,
    password: Option<&str>,
    ssh_key: Option<&str>,
    ssh_passphrase: Option<&str>,
    cred_name: Option<&str>,
    conn_name: &str,
) -> Option<CredentialId> {
    if kind == ConnectionKind::LocalTerminal {
        return None;
    }
    if let Some(name) = cred_name {
        return ctx.cred_name_to_id.get(name).copied();
    }
    let (cred_kind, secrets) =
        secret_material_for_row(auth_method, password, ssh_key, ssh_passphrase)?;
    let cred_id = ctx.fresh_cred_id();
    ctx.credentials.push(Credential {
        id: cred_id,
        name: format!("{conn_name} credential"),
        kind: cred_kind,
        folder_id: None,
        username: username.map(str::to_string),
    });
    push_secrets(ctx, cred_id, secrets);
    Some(cred_id)
}

/// Maps the `auth_method` column to [`SshAuthMethod`]; unrecognized values
/// default to `Password` with a counted warning (never silently
/// reinterpreted). `key_ref`'s embedded [`CredentialId`] is a placeholder —
/// `cm_ui::controller::sessions::resolve_ssh_auth` resolves the secret via
/// the connection's own assigned credential, not via `key_ref` (mirrors the
/// same placeholder pattern the tree-editor form uses,
/// `cm-ui/src/controller/tree_ctl.rs`).
fn ssh_auth_method(auth_method: &str, row_num: u64, ctx: &mut ParseCtx) -> SshAuthMethod {
    match auth_method.trim().to_ascii_lowercase().as_str() {
        "" | "password" | "prompt" => SshAuthMethod::Password,
        "key" => SshAuthMethod::PublicKey {
            key_ref: CredentialRef::new(CredentialId::UNSAVED, CredentialPurpose::SshKey),
        },
        "agent" => SshAuthMethod::Agent,
        other => {
            tracing::warn!(
                row = row_num,
                auth_method = %other,
                "csv: unrecognized auth_method, defaulted to password"
            );
            ctx.warnings.push(ImportWarning::new(format!(
                "row {row_num}: unrecognized auth_method '{other}', defaulted to password"
            )));
            SshAuthMethod::Password
        }
    }
}

fn process_row(row_num: u64, rec: &::csv::StringRecord, idx: &HeaderIndex, ctx: &mut ParseCtx) {
    let Some(name) = field(idx, rec, "name") else {
        tracing::warn!(row = row_num, "csv: row skipped, missing name");
        ctx.warnings.push(ImportWarning::new(format!(
            "row {row_num}: missing 'name' — skipped"
        )));
        return;
    };
    let Some(kind_str) = field(idx, rec, "kind") else {
        tracing::warn!(row = row_num, "csv: row skipped, missing kind");
        ctx.warnings.push(ImportWarning::new(format!(
            "row {row_num}: missing 'kind' — skipped"
        )));
        return;
    };
    let kind = match kind_str.to_ascii_lowercase().as_str() {
        "ssh" => ConnectionKind::Ssh,
        "rdp" => ConnectionKind::Rdp,
        "local" => ConnectionKind::LocalTerminal,
        other => {
            tracing::warn!(row = row_num, kind = %other, "csv: row skipped, unrecognized kind");
            ctx.warnings.push(ImportWarning::new(format!(
                "row {row_num}: unrecognized kind '{other}' — skipped"
            )));
            return;
        }
    };

    let host = field(idx, rec, "host");
    if kind != ConnectionKind::LocalTerminal && host.is_none() {
        tracing::warn!(row = row_num, "csv: row skipped, missing host");
        ctx.warnings.push(ImportWarning::new(format!(
            "row {row_num}: missing 'host' for a {kind_str} connection — skipped"
        )));
        return;
    }

    let group_id = field(idx, rec, "group_path").and_then(|p| ensure_group_path(ctx, &p));
    let username = field(idx, rec, "username");
    let domain = field(idx, rec, "domain");
    let auth_method_str = field(idx, rec, "auth_method").unwrap_or_default();
    let password = field(idx, rec, "password");
    let ssh_key = field(idx, rec, "ssh_private_key_pem");
    let ssh_passphrase = field(idx, rec, "ssh_passphrase");
    let cred_name = field(idx, rec, "cred_name");

    let credential = resolve_row_credential(
        ctx,
        kind,
        &auth_method_str,
        username.as_deref(),
        password.as_deref(),
        ssh_key.as_deref(),
        ssh_passphrase.as_deref(),
        cred_name.as_deref(),
        &name,
    );

    let settings = match kind {
        ConnectionKind::Ssh => ConnectionSettings::Ssh(SshSettings {
            host: host.unwrap_or_default(),
            port: parse_or(
                field(idx, rec, "port").as_deref(),
                SshSettings::DEFAULT_PORT,
            ),
            username: username.clone().unwrap_or_default(),
            auth_method: ssh_auth_method(&auth_method_str, row_num, ctx),
        }),
        ConnectionKind::Rdp => ConnectionSettings::Rdp(RdpSettings {
            host: host.unwrap_or_default(),
            port: parse_or(
                field(idx, rec, "port").as_deref(),
                RdpSettings::DEFAULT_PORT,
            ),
            domain,
            username: username.clone(),
            width: parse_or(
                field(idx, rec, "width").as_deref(),
                RdpSettings::DEFAULT_WIDTH,
            ),
            height: parse_or(
                field(idx, rec, "height").as_deref(),
                RdpSettings::DEFAULT_HEIGHT,
            ),
            color_depth: parse_or(field(idx, rec, "color_depth").as_deref(), 32),
        }),
        ConnectionKind::LocalTerminal => ConnectionSettings::Local(LocalSettings::default()),
    };

    let conn_id = ctx.fresh_conn_id();
    match Connection::new(
        conn_id,
        group_id,
        name.clone(),
        kind,
        settings,
        credential,
        0,
        0,
        0,
    ) {
        Ok(conn) => ctx.connections.push(conn),
        Err(e) => {
            tracing::warn!(
                row = row_num,
                connection = %name,
                error = %e,
                "csv: connection skipped (validation)"
            );
            ctx.warnings.push(ImportWarning::new(format!(
                "row {row_num}: connection '{name}' skipped: {e}"
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/csv_sample.csv");

    #[test]
    fn parses_group_path_nesting_into_group_tree() {
        let (envelope, _warnings) = parse(FIXTURE).expect("fixture should parse");
        // Four rows share the "Prod/Web" group_path — the point of the dedupe
        // is that this still produces exactly one "Prod" and one "Web" group.
        assert_eq!(
            envelope.groups.iter().filter(|g| g.name == "Prod").count(),
            1,
            "Prod must dedupe to one group despite multiple rows sharing it"
        );
        assert_eq!(
            envelope.groups.iter().filter(|g| g.name == "Web").count(),
            1,
            "Web must dedupe to one group despite multiple rows sharing it"
        );
        let by_name: HashMap<&str, &Group> = envelope
            .groups
            .iter()
            .map(|g| (g.name.as_str(), g))
            .collect();
        let prod = by_name.get("Prod").expect("Prod group present");
        let web = by_name.get("Web").expect("Web group present");
        assert_eq!(web.parent_id, Some(prod.id));
    }

    #[test]
    fn parses_ssh_rdp_and_local_rows() {
        let (envelope, _warnings) = parse(FIXTURE).expect("fixture should parse");

        let ssh = envelope
            .connections
            .iter()
            .find(|c| c.name == "web-01-ssh")
            .expect("ssh connection present");
        assert_eq!(ssh.kind, ConnectionKind::Ssh);
        match &ssh.settings {
            ConnectionSettings::Ssh(s) => assert_eq!(s.host, "web01.example.test"),
            other => panic!("expected Ssh settings, got {other:?}"),
        }

        let rdp = envelope
            .connections
            .iter()
            .find(|c| c.name == "win-01-rdp")
            .expect("rdp connection present");
        assert_eq!(rdp.kind, ConnectionKind::Rdp);
        match &rdp.settings {
            ConnectionSettings::Rdp(s) => assert_eq!(s.host, "win01.example.test"),
            other => panic!("expected Rdp settings, got {other:?}"),
        }

        let local = envelope
            .connections
            .iter()
            .find(|c| c.name == "scratch-shell")
            .expect("local connection present");
        assert_eq!(local.kind, ConnectionKind::LocalTerminal);
        assert_eq!(local.credential, None, "local rows never get a credential");
    }

    #[test]
    fn ssh_key_row_lands_as_an_ssh_key_exported_secret() {
        let (envelope, _warnings) = parse(FIXTURE).expect("fixture should parse");
        let keyed = envelope
            .connections
            .iter()
            .find(|c| c.name == "build-box-key")
            .expect("key-auth connection present");
        match &keyed.settings {
            ConnectionSettings::Ssh(s) => {
                assert!(matches!(s.auth_method, SshAuthMethod::PublicKey { .. }))
            }
            other => panic!("expected Ssh settings, got {other:?}"),
        }
        let cred_id = keyed.credential.expect("key row should carry a credential");
        let cred = envelope
            .credentials
            .iter()
            .find(|c| c.id == cred_id)
            .expect("credential present");
        assert_eq!(cred.kind, CredentialKind::SshKey);

        let secret = envelope
            .credential_secrets
            .iter()
            .find(|s| s.credential_id == cred_id && s.purpose == "ssh-key")
            .expect("ssh-key secret present");
        let decoded = (0..secret.secret_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&secret.secret_hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();
        assert!(
            String::from_utf8(decoded)
                .unwrap()
                .contains("BEGIN OPENSSH PRIVATE KEY")
        );
    }

    #[test]
    fn shared_cred_name_dedupes_to_one_credential() {
        let (envelope, _warnings) = parse(FIXTURE).expect("fixture should parse");
        let sharing: Vec<_> = envelope
            .connections
            .iter()
            .filter(|c| c.name == "svc-a" || c.name == "svc-b")
            .collect();
        assert_eq!(sharing.len(), 2, "both shared-credential rows present");
        let cred_ids: std::collections::HashSet<_> =
            sharing.iter().filter_map(|c| c.credential).collect();
        assert_eq!(
            cred_ids.len(),
            1,
            "svc-a and svc-b must dedupe to exactly one credential"
        );
        assert_eq!(
            envelope
                .credentials
                .iter()
                .filter(|c| c.name == "shared-svc")
                .count(),
            1,
            "exactly one Credential object named after the shared cred_name"
        );
    }

    #[test]
    fn malformed_row_missing_host_is_skipped_with_a_counted_warning() {
        let (envelope, warnings) = parse(FIXTURE).expect("fixture should parse");
        assert!(
            !envelope.connections.iter().any(|c| c.name == "no-host-ssh"),
            "the row missing 'host' must not produce a connection"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.message.contains("missing 'host'")),
            "skipping must be counted as a warning, not silent: {warnings:?}"
        );
    }

    #[test]
    fn empty_input_is_a_malformed_error_not_a_panic() {
        let err = parse("").unwrap_err();
        assert!(matches!(err, ImportExportError::Malformed(_)));
    }
}

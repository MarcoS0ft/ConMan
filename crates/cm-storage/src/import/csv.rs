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
//! - `kind` = `ssh` | `rdp` | `telnet` | `local` (case-insensitive). Anything
//!   else, or a missing `name`/`kind`, or a missing `host` on a remote row, skips the
//!   row with a counted [`ImportWarning`] naming the row number and reason —
//!   never silent.
//! - `group_path` is `/`-separated (e.g. `Prod/Web`), creating nested groups
//!   deduped by full path string (mirrors [`super::royalts`]'s per-document
//!   dedupe philosophy, just keyed by path instead of a foreign object ID).
//!   Blank → root level.
//! - `port` blank or unparsable → the kind's default (22 ssh / 3389 rdp /
//!   23 telnet).
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
//!   (no auth concept in [`LocalSettings`]). Telnet rows always use
//!   [`CredentialSource::Prompt`]; populated username/password/key fields are
//!   ignored with one counted warning because login is interactive.
//! - **Credential handling:** if `cred_name` is set, **dedupe** — one
//!   [`Credential`] per unique `cred_name`, referenced by every row sharing
//!   it, as a [`CredentialSource::Object`]. Two passes over the parsed rows
//!   ([`collect_credentials`] then [`walk_rows`]) mirror [`super::royalts`]'s
//!   dedupe-by-construction architecture: the *first* row (by file order)
//!   carrying both a given `cred_name` **and** actual secret material
//!   registers the credential; earlier/later rows that only reference the
//!   name by find it already there. A `cred_name` mentioned but never backed
//!   by secret material on any row simply resolves to no credential (never a
//!   hard error — the connection still imports, just without one).
//!
//!   Without `cred_name`, a row's own secret material (P9.6 decision 5)
//!   becomes: **`CredentialSource::Inline`** when the row is password-auth
//!   (genuinely per-row, unshared — the whole point of Inline), carrying
//!   `username`/`domain` on the source itself and the secret as a
//!   connection-scoped [`crate::json_io::ExportedConnectionSecret`]; or
//!   **still `CredentialSource::Object`** when the row is key-auth — Inline
//!   is password-only (no key-material field), so an SSH key must stay a
//!   `Credential{SshKey}` + `ExportedSecret(ssh-key)` regardless of sharing.
//! - `username`/`domain` land on the **connection's** settings (unchanged);
//!   an `Object` credential (shared `cred_name` or a per-row key) also
//!   carries `username` so it's still authoritative post-assignment (mirrors
//!   [`super::royalts::register_credential`]); an `Inline` source carries its
//!   own `username`/`domain` copy instead (see
//!   [`cm_core::resolve_connection_auth`]).

use std::collections::HashMap;

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionSettings, Credential, CredentialId,
    CredentialKind, CredentialPurpose, CredentialRef, CredentialSource, Group, GroupId,
    LocalSettings, RdpSettings, SshAuthMethod, SshSettings, TelnetSettings,
};

use crate::json_io::{
    self, ExportEnvelope, ExportedConnectionSecret, ExportedSecret, ImportExportError,
};

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
        conman_export_version: json_io::ENVELOPE_VERSION,
        exported_at: 0, // foreign/own-format import: no meaningful export timestamp
        credential_folders: Vec::new(),
        credentials: ctx.credentials,
        groups: ctx.groups,
        connections: ctx.connections,
        credential_secrets: ctx.credential_secrets,
        connection_secrets: ctx.connection_secrets,
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
    /// P9.6 decision 5: a no-`cred_name`, password-auth row's secret lands
    /// here (Inline, connection-scoped) instead of in `credential_secrets` —
    /// see [`resolve_row_credential`].
    connection_secrets: Vec<ExportedConnectionSecret>,
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
        // Telnet's authentication is remote-prompt driven. In particular, a
        // Telnet row carrying `cred_name` must not manufacture a credential
        // object during this first pass before the row itself is translated.
        if field(idx, rec, "kind").is_some_and(|kind| kind.eq_ignore_ascii_case("telnet")) {
            continue;
        }
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

/// What a row's own credential resolution produced: an already-registered
/// (shared or per-row) credential **object**, or — P9.6 decision 5 — a
/// genuinely per-row password whose plaintext is pushed as an Inline
/// connection-secret once the connection's synthetic id is known (mirrors
/// `mremoteng.rs`'s `push_connection`).
enum RowCredential {
    Object(CredentialId),
    InlinePassword(String),
}

/// Resolves what (if any) credential a row's connection should carry: the
/// shared `cred_name` credential (pass 1) is always [`RowCredential::Object`];
/// without `cred_name`, the row's own secret material decides — a key-bearing
/// row still becomes a fresh `Object` (Inline is password-only, so a
/// `Credential{SshKey}` is the only place a key can live), a password-only
/// row becomes [`RowCredential::InlinePassword`] (genuinely per-row, unshared
/// — no dedupe concept applies). `None` when the row has no secret material
/// at all. `local` rows never get a credential — [`LocalSettings`] has no
/// auth concept; Telnet always explicitly prompts and must not retain any
/// imported secret material.
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
) -> Option<RowCredential> {
    if matches!(kind, ConnectionKind::LocalTerminal | ConnectionKind::Telnet) {
        return None;
    }
    if let Some(name) = cred_name {
        return ctx
            .cred_name_to_id
            .get(name)
            .copied()
            .map(RowCredential::Object);
    }
    let (cred_kind, secrets) =
        secret_material_for_row(auth_method, password, ssh_key, ssh_passphrase)?;

    if cred_kind == CredentialKind::Password {
        let (_, pw) = secrets
            .into_iter()
            .next()
            .expect("secret_material_for_row's password branch always yields exactly one entry");
        return Some(RowCredential::InlinePassword(pw));
    }

    let cred_id = ctx.fresh_cred_id();
    ctx.credentials.push(Credential {
        id: cred_id,
        name: format!("{conn_name} credential"),
        kind: cred_kind,
        folder_id: None,
        username: username.map(str::to_string),
    });
    push_secrets(ctx, cred_id, secrets);
    Some(RowCredential::Object(cred_id))
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
        "telnet" => ConnectionKind::Telnet,
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

    if kind == ConnectionKind::Telnet
        && (username.is_some()
            || password.is_some()
            || ssh_key.is_some()
            || ssh_passphrase.is_some())
    {
        tracing::warn!(
            row = row_num,
            "csv: Telnet credential fields ignored; login is interactive"
        );
        ctx.warnings.push(ImportWarning::new(format!(
            "row {row_num}: Telnet credentials were ignored because Telnet login is interactive"
        )));
    }

    let credential_resolution = resolve_row_credential(
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
    // P9.6 decision 5: a shared cred_name / key-bearing row stays an Object
    // reference; a genuinely per-row password (no cred_name) becomes Inline,
    // carrying username/domain on the source itself (authoritative, per
    // `resolve_connection_auth`'s Inline arm).
    let credential = match kind {
        ConnectionKind::Telnet => Some(CredentialSource::Prompt),
        _ => match &credential_resolution {
            Some(RowCredential::Object(id)) => Some(CredentialSource::Object(*id)),
            Some(RowCredential::InlinePassword(_)) => Some(CredentialSource::Inline {
                username: username.clone().unwrap_or_default(),
                domain: domain.clone(),
                has_secret: true,
            }),
            None => None,
        },
    };

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
        ConnectionKind::Telnet => ConnectionSettings::Telnet(TelnetSettings {
            host: host.unwrap_or_default(),
            port: parse_or(
                field(idx, rec, "port").as_deref(),
                TelnetSettings::DEFAULT_PORT,
            ),
        }),
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
        Ok(conn) => {
            // The Inline secret is only pushed once the connection actually
            // validates — a rejected connection carries no keychain entry to
            // orphan.
            if let Some(RowCredential::InlinePassword(secret)) = credential_resolution {
                ctx.connection_secrets.push(ExportedConnectionSecret {
                    connection_id: conn_id,
                    purpose: CredentialPurpose::Password.as_str().to_string(),
                    secret_hex: json_io::to_hex(secret.as_bytes()),
                });
            }
            ctx.connections.push(conn);
        }
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
        assert_eq!(
            local.credential_source, None,
            "local rows never get a credential"
        );
    }

    /// P9.6 decision 5: `web-01-ssh` has no `cred_name` and password auth —
    /// the genuinely-per-row, unshared case that must become
    /// `CredentialSource::Inline` (not a synthesized `Credential` object).
    #[test]
    fn no_cred_name_password_row_becomes_an_inline_credential_and_connection_secret() {
        let (envelope, _warnings) = parse(FIXTURE).expect("fixture should parse");
        let ssh = envelope
            .connections
            .iter()
            .find(|c| c.name == "web-01-ssh")
            .expect("ssh connection present");
        match &ssh.credential_source {
            Some(CredentialSource::Inline {
                username,
                has_secret,
                ..
            }) => {
                assert_eq!(username, "deploy");
                assert!(*has_secret);
            }
            other => panic!("expected an Inline credential source, got {other:?}"),
        }
        let secret = envelope
            .connection_secrets
            .iter()
            .find(|s| s.connection_id == ssh.id && s.purpose == "password")
            .expect("password connection-secret present");
        let decoded = (0..secret.secret_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&secret.secret_hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();
        assert_eq!(decoded, b"dummy-pw-1");
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
        let cred_id = match &keyed.credential_source {
            Some(CredentialSource::Object(id)) => *id,
            other => panic!("expected an Object credential source, got {other:?}"),
        };
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
        let cred_ids: std::collections::HashSet<_> = sharing
            .iter()
            .filter_map(|c| match c.credential_source {
                Some(CredentialSource::Object(id)) => Some(id),
                _ => None,
            })
            .collect();
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
        // "row 10", not some off-by-N count — the fixture's preceding
        // build-box-key row spans a multi-line quoted PEM field (physical
        // lines 5-7), so this also proves `csv::StringRecord::position`
        // tracks the real source line across a multi-line record rather than
        // just counting data rows.
        assert!(
            warnings
                .iter()
                .any(|w| w.message.contains("row 10: missing 'host'")),
            "skipping must cite the real source line (row 10), not just be a counted warning: {warnings:?}"
        );
    }

    #[test]
    fn empty_input_is_a_malformed_error_not_a_panic() {
        let err = parse("").unwrap_err();
        assert!(matches!(err, ImportExportError::Malformed(_)));
    }

    #[test]
    fn telnet_rows_use_interactive_login_and_never_create_secret_artifacts() {
        let csv = r#"name,kind,host,port,username,cred_name,auth_method,password,ssh_private_key_pem,ssh_passphrase
legacy-console,telnet,legacy.example.test,2323,legacy-user,legacy-cred,key,legacy-password,legacy-private-key,legacy-passphrase
default-port,TeLnEt,default.example.test,,,,,,,
"#;

        let (envelope, warnings) = parse(csv).expect("Telnet rows should parse");
        assert_eq!(envelope.connections.len(), 2);

        let legacy = envelope
            .connections
            .iter()
            .find(|connection| connection.name == "legacy-console")
            .expect("custom-port Telnet connection present");
        assert_eq!(legacy.kind, ConnectionKind::Telnet);
        assert_eq!(legacy.credential_source, Some(CredentialSource::Prompt));
        match &legacy.settings {
            ConnectionSettings::Telnet(settings) => {
                assert_eq!(settings.host, "legacy.example.test");
                assert_eq!(settings.port, 2323);
            }
            other => panic!("expected Telnet settings, got {other:?}"),
        }

        let default_port = envelope
            .connections
            .iter()
            .find(|connection| connection.name == "default-port")
            .expect("default-port Telnet connection present");
        match &default_port.settings {
            ConnectionSettings::Telnet(settings) => {
                assert_eq!(settings.host, "default.example.test");
                assert_eq!(settings.port, TelnetSettings::DEFAULT_PORT);
            }
            other => panic!("expected Telnet settings, got {other:?}"),
        }
        assert_eq!(
            default_port.credential_source,
            Some(CredentialSource::Prompt)
        );

        assert!(envelope.credentials.is_empty());
        assert!(envelope.credential_secrets.is_empty());
        assert!(envelope.connection_secrets.is_empty());
        let serialized = serde_json::to_string(&envelope).expect("serialize envelope");
        for ignored in [
            "legacy-user",
            "legacy-cred",
            "legacy-password",
            "legacy-private-key",
            "legacy-passphrase",
        ] {
            assert!(
                !serialized.contains(ignored),
                "ignored Telnet field leaked into the envelope: {ignored}"
            );
        }

        let ignored_warnings = warnings
            .iter()
            .filter(|warning| warning.message.contains("Telnet credentials were ignored"))
            .collect::<Vec<_>>();
        assert_eq!(
            ignored_warnings.len(),
            1,
            "all populated credential/key fields on one row produce one warning: {warnings:?}"
        );
        assert!(ignored_warnings[0].message.starts_with("row 2:"));
    }
}

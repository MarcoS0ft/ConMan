//! RoyalTS `.rjson` importer (P9.2).
//!
//! Parses the plaintext RoyalTS JSON export format — a document shaped like
//! `{"Objects": [...]}`, a nested tree of folder / connection / credential
//! nodes (children of a folder live in that folder's own `"Objects"` array)
//! — into an in-memory [`ExportEnvelope`]. This module never touches a
//! repository or keychain; [`parse`]'s caller ([`super::import_from_path`])
//! hands the envelope to the existing, unmodified
//! [`crate::json_io::import`] seam.
//!
//! Scope note: this handles the plaintext `.rjson` export only. RoyalTS's
//! encrypted vault format (`.rtsz`, password-protected) is out of scope for
//! this task (see the P9.2 task spec's "Out" list).
//!
//! ## Node-kind detection
//! RoyalTS has shipped (at least) two type-name families across versions:
//! the modern short names (`Folder`, `RemoteDesktopConnection`,
//! `TerminalConnection`, `Credential`) and older, more verbose names
//! carrying a `RoyalRDS...`-style prefix (e.g. `RoyalRDSConnection`,
//! `RoyalRDSFolder`, `RoyalRDSCredential`). Rather than enumerate every
//! historical/exact type string — undocumented and version-dependent — node
//! kind is inferred with a case-insensitive substring match against the
//! `"Type"` field, checked in this order (most-specific first): `credential`
//! → Credential, `folder` → Folder, `web`/`vnc` → unsupported, `terminal` /
//! `ssh` → SSH, `remotedesktop` or (`rds` and `connection`) → RDP, anything
//! else → unsupported. This is robust to both families without hard-failing
//! on the legacy names.
//!
//! ## Credential dedupe
//! Credentials are separate objects, referenced by connections via
//! `"CredentialID"`, and may be shared by many connections. [`parse`] makes
//! two passes over the tree: pass 1 ([`collect_credentials`]) walks the
//! *entire* document (regardless of nesting) and registers exactly one
//! ConMan [`Credential`] per unique RoyalTS `ID` — a second `Credential` node
//! reusing an already-seen `ID` is a no-op (dedupe by construction, not by
//! attribute comparison). Pass 2 ([`walk_nodes`]) then builds the group tree
//! and connections, resolving `CredentialID` references against the map pass
//! 1 built, so N connections sharing one RoyalTS credential all resolve to
//! that single ConMan `Credential`.
//!
//! ## Field mapping (see the P9.2 task report for the full table)
//! - `Folder` → [`Group`] (nested `"Objects"` → child groups, recursively;
//!   `parent_id` set from the enclosing folder, `None` at the document root).
//! - `RemoteDesktopConnection` (+ legacy) → an RDP [`Connection`]. Host from
//!   `URI`/`ComputerName`/`Host`/`HostName` (first present); `Domain`,
//!   `UserName`/`Username` copied; port defaults to
//!   [`RdpSettings::DEFAULT_PORT`] (RoyalTS only emits `Port` when
//!   non-default). The many RoyalTS RDP tuning attributes (color profile,
//!   gateway, redirection flags, etc.) have no home in [`RdpSettings`] and
//!   are dropped — expected, per the task spec.
//! - `TerminalConnection` (+ legacy) → an SSH [`Connection`]; same host/port
//!   handling, port defaults to [`SshSettings::DEFAULT_PORT`].
//!   `auth_method` is [`SshAuthMethod::Password`] when a `CredentialID`
//!   resolves, else [`SshAuthMethod::Agent`] (no credential to attach).
//! - `Credential` → a ConMan [`Credential`] (kind
//!   [`CredentialKind::Password`]) plus an [`ExportedSecret`]
//!   (`purpose = "password"`) carrying the **plaintext** password RoyalTS
//!   stores in the clear in this export format — this is the intended
//!   plaintext → keychain path `crate::json_io`'s docs call out (import
//!   legitimately writes secrets; export stays secret-excluded by default).
//! - `WebConnection`/`VNCConnection`/anything unrecognized → skipped with a
//!   counted [`ImportWarning`] (never silent).

use std::collections::HashMap;

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionSettings, Credential, CredentialId,
    CredentialKind, CredentialPurpose, CredentialSource, Group, GroupId, RdpSettings,
    SshAuthMethod, SshSettings,
};
use serde::Deserialize;
use serde_json::Value;

use crate::json_io::{self, ExportEnvelope, ExportedSecret, ImportExportError};

use super::ImportWarning;

/// Top-level RoyalTS document shape: `{"Objects": [...]}`.
#[derive(Debug, Deserialize)]
struct RoyalTsDocument {
    #[serde(rename = "Objects", default)]
    objects: Vec<Value>,
}

/// Parse a RoyalTS `.rjson` document into a v1 [`ExportEnvelope`] plus any
/// counted [`ImportWarning`]s. IDs assigned here are synthetic, file-scoped
/// link keys only — [`crate::json_io::import`] remaps every record to a
/// fresh database ID, exactly as it does for a native `.json` export.
pub fn parse(contents: &str) -> Result<(ExportEnvelope, Vec<ImportWarning>), ImportExportError> {
    let doc: RoyalTsDocument = serde_json::from_str(contents)?;

    let mut ctx = ParseCtx::default();
    collect_credentials(&doc.objects, &mut ctx);
    walk_nodes(&doc.objects, None, &mut ctx);

    let envelope = ExportEnvelope {
        conman_export_version: json_io::MIN_SUPPORTED_VERSION,
        exported_at: 0, // foreign import: no meaningful export timestamp
        credential_folders: Vec::new(),
        credentials: ctx.credentials,
        groups: ctx.groups,
        connections: ctx.connections,
        credential_secrets: ctx.credential_secrets,
        connection_secrets: Vec::new(),
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
    /// RoyalTS `ID` (string, typically a GUID) → the synthetic
    /// [`CredentialId`] minted for it. Built in pass 1, consulted in pass 2 —
    /// this map *is* the dedupe: one entry per unique RoyalTS credential ID.
    cred_guid_to_id: HashMap<String, CredentialId>,
    /// Running count of credential nodes skipped because their GUID was
    /// already registered (P9.8 G8) — logged as a count only, never the GUID
    /// itself.
    credential_dedup_count: usize,
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
// Node classification
// ---------------------------------------------------------------------------

enum NodeKind {
    Folder,
    Rdp,
    Ssh,
    Credential,
    /// Carries the raw `Type` string for the warning message.
    Unsupported,
}

/// Classify a RoyalTS node by a case-insensitive substring match against its
/// `"Type"` field — see the module doc for why (both type-name families,
/// undocumented/version-dependent exact strings).
fn classify(type_str: &str) -> NodeKind {
    let t = type_str.to_ascii_lowercase();
    if t.contains("credential") {
        NodeKind::Credential
    } else if t.contains("folder") {
        NodeKind::Folder
    } else if t.contains("web") || t.contains("vnc") {
        NodeKind::Unsupported
    } else if t.contains("terminal") || t.contains("ssh") {
        NodeKind::Ssh
    } else if t.contains("remotedesktop") || (t.contains("rds") && t.contains("connection")) {
        NodeKind::Rdp
    } else {
        NodeKind::Unsupported
    }
}

// ---------------------------------------------------------------------------
// Field access helpers
// ---------------------------------------------------------------------------

fn get_str(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| v.get(k).and_then(Value::as_str))
        .map(str::to_string)
}

fn get_u16(v: &Value, keys: &[&str]) -> Option<u16> {
    keys.iter()
        .find_map(|k| v.get(k).and_then(Value::as_u64))
        .and_then(|n| u16::try_from(n).ok())
}

fn children(v: &Value) -> &[Value] {
    v.get("Objects")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

// ---------------------------------------------------------------------------
// Pass 1: credential discovery (dedupe by construction)
// ---------------------------------------------------------------------------

fn collect_credentials(nodes: &[Value], ctx: &mut ParseCtx) {
    for node in nodes {
        if let Some(type_str) = node.get("Type").and_then(Value::as_str)
            && matches!(classify(type_str), NodeKind::Credential)
        {
            register_credential(node, ctx);
        }
        collect_credentials(children(node), ctx);
    }
}

fn register_credential(node: &Value, ctx: &mut ParseCtx) {
    let Some(guid) = get_str(node, &["ID", "Id"]) else {
        tracing::warn!("royalts: node skipped, missing ID");
        ctx.warnings
            .push(ImportWarning::new("credential node missing 'ID' — skipped"));
        return;
    };
    if ctx.cred_guid_to_id.contains_key(&guid) {
        ctx.credential_dedup_count += 1;
        tracing::debug!(
            count = ctx.credential_dedup_count,
            "royalts: credential deduped"
        );
        return; // Already registered — defensive dedupe guard.
    }

    let name = get_str(node, &["Name"]).unwrap_or_else(|| "Imported credential".to_string());
    let username = get_str(node, &["UserName", "Username"]);
    let password = get_str(node, &["Password"]);

    let cred_id = ctx.fresh_cred_id();
    ctx.credentials.push(Credential {
        id: cred_id,
        name,
        kind: CredentialKind::Password,
        folder_id: None,
        username,
    });

    if let Some(pw) = password {
        ctx.credential_secrets.push(ExportedSecret {
            credential_id: cred_id,
            purpose: CredentialPurpose::Password.as_str().to_string(),
            secret_hex: json_io::to_hex(pw.as_bytes()),
        });
    }

    ctx.cred_guid_to_id.insert(guid, cred_id);
}

// ---------------------------------------------------------------------------
// Pass 2: group tree + connections
// ---------------------------------------------------------------------------

fn walk_nodes(nodes: &[Value], parent_group: Option<GroupId>, ctx: &mut ParseCtx) {
    for node in nodes {
        let Some(type_str) = node.get("Type").and_then(Value::as_str) else {
            tracing::warn!(name = ?get_str(node, &["Name"]), "royalts: node skipped, missing Type");
            ctx.warnings
                .push(ImportWarning::new("node missing 'Type' field — skipped"));
            continue;
        };

        match classify(type_str) {
            NodeKind::Credential => {} // Handled entirely in pass 1.
            NodeKind::Folder => {
                let name =
                    get_str(node, &["Name"]).unwrap_or_else(|| "Imported folder".to_string());
                let group_id = ctx.fresh_group_id();
                ctx.groups.push(Group {
                    id: group_id,
                    parent_id: parent_group,
                    name,
                    sort: 0,
                    default_credential: None,
                });
                walk_nodes(children(node), Some(group_id), ctx);
            }
            NodeKind::Rdp => build_rdp_connection(node, parent_group, ctx),
            NodeKind::Ssh => build_ssh_connection(node, parent_group, ctx),
            NodeKind::Unsupported => {
                tracing::warn!(node_type = %type_str, "royalts: unsupported node kind skipped");
                ctx.warnings.push(ImportWarning::new(format!(
                    "skipped unsupported node kind '{type_str}' (Web/VNC/other unmapped RoyalTS type)"
                )));
            }
        }
    }
}

fn resolve_credential(node: &Value, ctx: &ParseCtx) -> Option<CredentialId> {
    get_str(node, &["CredentialID", "CredentialId"])
        .and_then(|guid| ctx.cred_guid_to_id.get(&guid).copied())
}

fn build_rdp_connection(node: &Value, group: Option<GroupId>, ctx: &mut ParseCtx) {
    let name = get_str(node, &["Name"]).unwrap_or_else(|| "Imported connection".to_string());
    let host = get_str(node, &["URI", "ComputerName", "Host", "HostName"]).unwrap_or_default();
    let port = get_u16(node, &["Port"]).unwrap_or(RdpSettings::DEFAULT_PORT);
    let domain = get_str(node, &["Domain"]);
    let username = get_str(node, &["UserName", "Username"]);
    let credential = resolve_credential(node, ctx);

    let settings = ConnectionSettings::Rdp(RdpSettings {
        host,
        port,
        domain,
        username,
        ..RdpSettings::default()
    });

    push_connection(
        node,
        name,
        group,
        ConnectionKind::Rdp,
        settings,
        credential,
        ctx,
    );
}

fn build_ssh_connection(node: &Value, group: Option<GroupId>, ctx: &mut ParseCtx) {
    let name = get_str(node, &["Name"]).unwrap_or_else(|| "Imported connection".to_string());
    let host = get_str(node, &["URI", "ComputerName", "Host", "HostName"]).unwrap_or_default();
    let port = get_u16(node, &["Port"]).unwrap_or(SshSettings::DEFAULT_PORT);
    let username = get_str(node, &["UserName", "Username"]).unwrap_or_default();
    let credential = resolve_credential(node, ctx);

    let auth_method = if credential.is_some() {
        SshAuthMethod::Password
    } else {
        SshAuthMethod::Agent
    };

    let settings = ConnectionSettings::Ssh(SshSettings {
        host,
        port,
        username,
        auth_method,
    });

    push_connection(
        node,
        name,
        group,
        ConnectionKind::Ssh,
        settings,
        credential,
        ctx,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_connection(
    node: &Value,
    name: String,
    group: Option<GroupId>,
    kind: ConnectionKind,
    settings: ConnectionSettings,
    credential: Option<CredentialId>,
    ctx: &mut ParseCtx,
) {
    let _ = node; // reserved: node kept for future field mapping/diagnostics.
    let conn_id = ctx.fresh_conn_id();
    // RoyalTS always dedupes to a shared credential OBJECT, never Inline —
    // P9.6 decision 5's Inline mapping only applies to a genuinely per-row/
    // per-node *unshared* password (mRemoteNG, CSV without cred_name);
    // RoyalTS's CredentialID is shared-by-reference by construction (see the
    // module doc's "Credential dedupe" section), so it stays Object here.
    let credential_source = credential.map(CredentialSource::Object);
    match Connection::new(
        conn_id,
        group,
        name.clone(),
        kind,
        settings,
        credential_source,
        0,
        0,
        0,
    ) {
        Ok(conn) => ctx.connections.push(conn),
        Err(e) => {
            tracing::warn!(
                connection = %name,
                error = %e,
                "royalts: connection skipped (validation)"
            );
            ctx.warnings.push(ImportWarning::new(format!(
                "connection '{name}' skipped: {e}"
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/royalts_sample.rjson");

    #[test]
    fn parses_folder_nesting_into_group_tree() {
        let (envelope, _warnings) = parse(FIXTURE).expect("fixture should parse");
        let by_name: HashMap<&str, &Group> = envelope
            .groups
            .iter()
            .map(|g| (g.name.as_str(), g))
            .collect();

        let prod = by_name.get("Production").expect("Production group present");
        let web = by_name.get("Web Tier").expect("Web Tier group present");
        assert_eq!(web.parent_id, Some(prod.id));
    }

    #[test]
    fn parses_both_rdp_and_ssh_connections() {
        let (envelope, _warnings) = parse(FIXTURE).expect("fixture should parse");
        let rdp = envelope
            .connections
            .iter()
            .find(|c| c.name == "app-server-rdp")
            .expect("rdp connection present");
        assert_eq!(rdp.kind, ConnectionKind::Rdp);
        match &rdp.settings {
            ConnectionSettings::Rdp(s) => assert_eq!(s.host, "app01.internal.example"),
            other => panic!("expected Rdp settings, got {other:?}"),
        }

        let ssh = envelope
            .connections
            .iter()
            .find(|c| c.name == "app-server-ssh")
            .expect("ssh connection present");
        assert_eq!(ssh.kind, ConnectionKind::Ssh);
    }

    #[test]
    fn shared_credential_dedupes_to_one_credential_with_plaintext_secret() {
        let (envelope, _warnings) = parse(FIXTURE).expect("fixture should parse");
        assert_eq!(
            envelope.credentials.len(),
            1,
            "the shared credential must dedupe to exactly one ConMan credential"
        );
        let cred = &envelope.credentials[0];
        assert_eq!(cred.name, "shared-app-login");

        // Both connections referencing it resolve to the same credential id.
        let referencing: Vec<_> = envelope
            .connections
            .iter()
            .filter(|c| c.credential_source == Some(CredentialSource::Object(cred.id)))
            .collect();
        assert_eq!(
            referencing.len(),
            2,
            "both connections should reference the one credential"
        );

        assert_eq!(envelope.credential_secrets.len(), 1);
        let secret = &envelope.credential_secrets[0];
        assert_eq!(secret.credential_id, cred.id);
        assert_eq!(secret.purpose, "password");
        // "hunter2-plaintext" hex-encoded, sanity-checked byte-for-byte below
        // rather than hardcoding the hex string.
        let decoded = (0..secret.secret_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&secret.secret_hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();
        assert_eq!(decoded, b"hunter2-plaintext");
    }

    #[test]
    fn port_defaults_apply_when_absent() {
        let (envelope, _warnings) = parse(FIXTURE).expect("fixture should parse");
        let ssh_no_port = envelope
            .connections
            .iter()
            .find(|c| c.name == "no-port-ssh")
            .expect("ssh connection without an explicit port present");
        match &ssh_no_port.settings {
            ConnectionSettings::Ssh(s) => assert_eq!(s.port, SshSettings::DEFAULT_PORT),
            other => panic!("expected Ssh settings, got {other:?}"),
        }

        let rdp_no_port = envelope
            .connections
            .iter()
            .find(|c| c.name == "no-port-rdp")
            .expect("rdp connection without an explicit port present");
        match &rdp_no_port.settings {
            ConnectionSettings::Rdp(s) => assert_eq!(s.port, RdpSettings::DEFAULT_PORT),
            other => panic!("expected Rdp settings, got {other:?}"),
        }
    }

    #[test]
    fn web_and_vnc_nodes_are_skipped_with_a_counted_warning() {
        let (envelope, warnings) = parse(FIXTURE).expect("fixture should parse");
        assert!(
            !envelope
                .connections
                .iter()
                .any(|c| c.name == "legacy-vnc-console"),
            "the VNC node must not produce a connection"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.message.contains("unsupported node kind")),
            "skipping must be counted as a warning, not silent: {warnings:?}"
        );
    }

    #[test]
    fn legacy_royalrds_type_names_parse_the_same_as_modern_names() {
        let (envelope, _warnings) = parse(FIXTURE).expect("fixture should parse");
        let legacy_rdp = envelope
            .connections
            .iter()
            .find(|c| c.name == "legacy-family-rdp")
            .expect("legacy RoyalRDS-family RDP connection present");
        assert_eq!(legacy_rdp.kind, ConnectionKind::Rdp);

        let legacy_folder = envelope
            .groups
            .iter()
            .find(|g| g.name == "Legacy Family Folder")
            .expect("legacy RoyalRDS-family folder present");
        assert!(
            envelope
                .connections
                .iter()
                .any(|c| c.group_id == Some(legacy_folder.id) && c.name == "legacy-family-rdp"),
            "the legacy folder should contain the legacy connection"
        );
    }
}

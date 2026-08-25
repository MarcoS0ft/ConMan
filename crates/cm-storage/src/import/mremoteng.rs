//! mRemoteNG `confCons.xml` importer (P9.4).
//!
//! Same architecture as every other importer in this module: parse into an
//! in-memory [`ExportEnvelope`], then hand it to the existing, unmodified
//! [`crate::json_io::import`] seam. The one structural difference from
//! RoyalTS/CSV: `Password` values are **encrypted** (see
//! [`super::mremoteng_crypto`]) and must be decrypted with a password before
//! use — [`parse`] takes one as a parameter.
//!
//! ## Document shape (attribute-based XML)
//! ```xml
//! <mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections"
//!     EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000"
//!     FullFileEncryption="false" Protected="<base64 canary>" ConfVersion="2.6">
//!   <Node Name="Prod" Type="Container">
//!     <Node Name="app01" Type="Connection" Protocol="RDP"
//!         Hostname="app01.example.test" Port="3389" Username="admin"
//!         Domain="CORP" Password="<base64 AES-GCM ciphertext>"
//!         InheritHostname="false" .../>
//!   </Node>
//! </mrng:Connections>
//! ```
//! The root element may or may not carry the `mrng:` prefix (older exports
//! omit it) — matched tolerantly by **local name** (`Connections`), same for
//! `Node`, so both families parse identically. Values are attributes, not
//! child text, so the parser only ever reads `Event::Start`/`Event::Empty`
//! attribute maps plus `Event::End` for nesting — no text-node handling
//! needed at all.
//!
//! ## MVP boundary (clean errors, not half-built support)
//! - `FullFileEncryption="true"` (whole-file-encrypted body, a different
//!   scheme entirely) → a clear [`ImportExportError::Malformed`] naming it
//!   unsupported. Fast-follow, not built here.
//! - Anything other than `EncryptionEngine="AES"` +
//!   `BlockCipherMode="GCM"` (i.e. legacy pre-2.6 AES-CBC/MD5-key, or the
//!   CCM/EAX block modes) → same, a clear named error. Fast-follow.
//!
//! ## Password handling
//! [`parse`] pre-validates `password` against the root `Protected` canary
//! (if present) before touching any node — a failed GCM auth tag there means
//! the file uses a **custom** password, surfaced as
//! [`ImportExportError::PasswordRequired`] so the caller
//! (`import_from_path_with_password`) can re-prompt. Documents that omit
//! `Protected` (rare) instead treat the *first* encrypted `Password` field
//! encountered during the walk as the de-facto canary — see
//! [`ParseCtx::decrypt`]. Once the password has been confirmed correct once,
//! any *later* individual field failing to decrypt is treated as that one
//! field being unusual/corrupt (a counted warning, connection still imports
//! without a credential) rather than re-triggering `PasswordRequired`.
//!
//! ## Inheritance (auth-critical fields only)
//! mRemoteNG lets a `Connection` inherit `Hostname`/`Port`/`Username`/
//! `Domain`/`Password`/`Protocol` from its nearest ancestor `Container` via
//! `Inherit<Field>="true"` (ConMan resolves only these six — other inherited
//! tuning attributes have no home in [`RdpSettings`]/[`SshSettings`] and are
//! dropped regardless, exactly like RoyalTS's tuning attrs). See
//! [`Inherited`]/[`resolve_inheritable`]. This prevents the empty-password
//! class of bug: a connection that inherits its password from an enclosing
//! container would otherwise import with no credential at all.
//!
//! ## Field + protocol mapping
//! `Type="Container"` → [`Group`] (nested). `Protocol="RDP"` →
//! [`ConnectionKind::Rdp`]; `"SSH1"`/`"SSH2"` → [`ConnectionKind::Ssh`];
//! `"Telnet"` → [`ConnectionKind::Telnet`] with interactive login;
//! anything else → skipped with a counted [`ImportWarning`]. A blank/absent
//! effective `Hostname` also skips the connection (counted), mirroring CSV's
//! missing-host handling. `Port` blank/unparsable → the kind's default.
//! mRemoteNG has **no separate credential objects** (creds are inline per
//! node, never shared) — a decrypted password becomes a
//! [`CredentialSource::Inline`] (P9.6 decision 5) carrying `username`/`domain`
//! on the source itself, with the plaintext pushed as an
//! [`crate::json_io::ExportedConnectionSecret`] once the connection's
//! synthetic id is known; `username`/`domain` also still land on the
//! connection's settings as before. SSH `auth_method` is
//! [`SshAuthMethod::Password`] when a password resolved, else
//! [`SshAuthMethod::Agent`] (mirrors `royalts.rs`'s `build_ssh_connection`).

use std::collections::HashMap;

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionSettings, CredentialPurpose,
    CredentialSource, Group, GroupId, RdpSettings, SshAuthMethod, SshSettings, TelnetSettings,
};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use crate::json_io::{self, ExportEnvelope, ExportedConnectionSecret, ImportExportError};

use super::ImportWarning;
use super::mremoteng_crypto;

/// Parses a `confCons.xml` document into a v1 [`ExportEnvelope`] plus any
/// counted [`ImportWarning`]s, decrypting `Password` fields with `password`
/// (mRemoteNG's default is [`mremoteng_crypto::DEFAULT_PASSWORD`]). IDs
/// assigned here are synthetic, file-scoped link keys only —
/// [`crate::json_io::import`] remaps every record to a fresh database ID.
///
/// Returns [`ImportExportError::PasswordRequired`] if `password` doesn't
/// authenticate against the document (see the module doc's "Password
/// handling" section) — never a panic or garbage plaintext, the GCM tag
/// guarantees a wrong password is detected.
pub fn parse(
    contents: &str,
    password: &str,
) -> Result<(ExportEnvelope, Vec<ImportWarning>), ImportExportError> {
    let (root_attrs, roots) = parse_xml_tree(contents)?;

    let full_file_encryption = root_attrs
        .get("FullFileEncryption")
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
    if full_file_encryption {
        return Err(ImportExportError::Malformed(
            "mRemoteNG Full File Encryption is not supported — re-export with it disabled \
             (fast-follow)"
                .into(),
        ));
    }

    let engine = root_attrs
        .get("EncryptionEngine")
        .map(String::as_str)
        .unwrap_or("AES");
    let mode = root_attrs
        .get("BlockCipherMode")
        .map(String::as_str)
        .unwrap_or("GCM");
    if !engine.eq_ignore_ascii_case("AES") || !mode.eq_ignore_ascii_case("GCM") {
        return Err(ImportExportError::Malformed(format!(
            "unsupported mRemoteNG encryption scheme (EncryptionEngine={engine}, \
             BlockCipherMode={mode}); only AES/GCM (ConfVersion 2.6+) is supported (fast-follow)"
        )));
    }

    let kdf_iterations = root_attrs
        .get("KdfIterations")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(mremoteng_crypto::DEFAULT_KDF_ITERATIONS);

    let mut ctx = ParseCtx {
        password: password.to_string(),
        kdf_iterations,
        ..Default::default()
    };

    // Pre-validate the password against the `Protected` canary before
    // touching any node, when the document carries one (the common case).
    if let Some(protected) = root_attrs.get("Protected") {
        ctx.decrypt(protected)?;
    }

    walk_nodes(&roots, None, &Inherited::default(), &mut ctx)?;

    let envelope = ExportEnvelope {
        conman_export_version: json_io::MIN_SUPPORTED_VERSION,
        exported_at: 0, // foreign import: no meaningful export timestamp
        credential_folders: Vec::new(),
        // mRemoteNG never produces a shared credential object (P9.6 decision
        // 5 — every per-node password is Inline, never Object); these two
        // stay permanently empty.
        credentials: Vec::new(),
        groups: ctx.groups,
        connections: ctx.connections,
        credential_secrets: Vec::new(),
        connection_secrets: ctx.connection_secrets,
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
    connections: Vec<Connection>,
    /// P9.6 decision 5: every decrypted per-node password becomes an
    /// Inline connection-secret (never a shared credential object) — see
    /// [`push_connection`].
    connection_secrets: Vec<ExportedConnectionSecret>,
    warnings: Vec<ImportWarning>,
    password: String,
    kdf_iterations: u32,
    /// Set once any field has successfully decrypted with `password` — see
    /// [`ParseCtx::decrypt`].
    password_confirmed: bool,
    next_group_id: i64,
    next_conn_id: i64,
}

impl ParseCtx {
    fn fresh_group_id(&mut self) -> GroupId {
        self.next_group_id += 1;
        GroupId::new(self.next_group_id)
    }

    fn fresh_conn_id(&mut self) -> ConnectionId {
        self.next_conn_id += 1;
        ConnectionId::new(self.next_conn_id)
    }

    /// Attempts to decrypt one mRemoteNG-encrypted field.
    ///
    /// Before the password has ever been confirmed correct, a failure here
    /// means the *password itself* is wrong — propagated as
    /// [`ImportExportError::PasswordRequired`] (this is what makes the first
    /// encrypted field act as a de-facto `Protected`-canary substitute for
    /// documents that omit one). Once confirmed, a later failure is assumed
    /// to be that one field being corrupt/unusual and is reported to the
    /// caller as `Ok(None)` instead, so the caller can turn it into a normal
    /// per-connection warning rather than aborting the whole import.
    fn decrypt(&mut self, value_b64: &str) -> Result<Option<Vec<u8>>, ImportExportError> {
        match mremoteng_crypto::decrypt_field(value_b64, &self.password, self.kdf_iterations) {
            Ok(plaintext) => {
                self.password_confirmed = true;
                Ok(Some(plaintext))
            }
            Err(_) if !self.password_confirmed => Err(ImportExportError::PasswordRequired),
            Err(_) => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// XML → generic attribute tree
// ---------------------------------------------------------------------------

/// A `<Node>` element: its attributes plus nested child `<Node>`s (a
/// `Container`'s contents). Built once by [`parse_xml_tree`] so the rest of
/// this module walks a plain in-memory tree, mirroring how `royalts.rs`
/// walks a `serde_json::Value` tree.
struct XmlNode {
    attrs: HashMap<String, String>,
    children: Vec<XmlNode>,
}

/// Pull-parses `contents` into the root `<Connections>` element's attributes
/// plus the top-level `<Node>` tree. Matches `Connections`/`Node` by *local*
/// name only (ignores any `mrng:` namespace prefix), tolerating both the
/// modern prefixed root and older unprefixed exports.
fn parse_xml_tree(
    contents: &str,
) -> Result<(HashMap<String, String>, Vec<XmlNode>), ImportExportError> {
    let mut reader = Reader::from_str(contents);

    let mut root_attrs: Option<HashMap<String, String>> = None;
    let mut stack: Vec<XmlNode> = Vec::new();
    let mut roots: Vec<XmlNode> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                if is_local_name(&e, b"Connections") {
                    if root_attrs.is_none() {
                        root_attrs = Some(collect_attrs(&e)?);
                    }
                } else if is_local_name(&e, b"Node") {
                    stack.push(XmlNode {
                        attrs: collect_attrs(&e)?,
                        children: Vec::new(),
                    });
                }
            }
            Ok(Event::Empty(e)) => {
                if is_local_name(&e, b"Connections") {
                    if root_attrs.is_none() {
                        root_attrs = Some(collect_attrs(&e)?);
                    }
                } else if is_local_name(&e, b"Node") {
                    let node = XmlNode {
                        attrs: collect_attrs(&e)?,
                        children: Vec::new(),
                    };
                    attach(&mut stack, &mut roots, node);
                }
            }
            Ok(Event::End(e)) => {
                if e.local_name().as_ref() == b"Node" {
                    let node = stack.pop().ok_or_else(|| {
                        ImportExportError::Malformed(
                            "mremoteng: unbalanced closing </Node> tag".into(),
                        )
                    })?;
                    attach(&mut stack, &mut roots, node);
                }
            }
            Ok(_) => {} // Text/Comment/Decl/PI/CData — irrelevant, values are all attributes.
            Err(e) => {
                return Err(ImportExportError::Malformed(format!(
                    "mremoteng: xml parse error: {e}"
                )));
            }
        }
    }

    let root_attrs = root_attrs.ok_or_else(|| {
        ImportExportError::Malformed("mremoteng: missing root <Connections> element".into())
    })?;
    Ok((root_attrs, roots))
}

fn attach(stack: &mut [XmlNode], roots: &mut Vec<XmlNode>, node: XmlNode) {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(node);
    } else {
        roots.push(node);
    }
}

fn is_local_name(e: &BytesStart<'_>, name: &[u8]) -> bool {
    e.local_name().as_ref() == name
}

fn collect_attrs(e: &BytesStart<'_>) -> Result<HashMap<String, String>, ImportExportError> {
    let mut map = HashMap::new();
    for attr in e.attributes().with_checks(false) {
        let attr = attr.map_err(|err| {
            ImportExportError::Malformed(format!("mremoteng: attribute parse error: {err}"))
        })?;
        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
        let value = attr
            .unescape_value()
            .map_err(|err| {
                ImportExportError::Malformed(format!("mremoteng: attribute value error: {err}"))
            })?
            .into_owned();
        map.insert(key, value);
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Inheritance
// ---------------------------------------------------------------------------

/// The resolved (post-inheritance) value of each auth-critical field at some
/// point in the container chain — threaded down the walk like `royalts.rs`'s
/// `parent_group`, but carrying values instead of just an ID.
#[derive(Default, Clone)]
struct Inherited {
    hostname: Option<String>,
    port: Option<String>,
    username: Option<String>,
    domain: Option<String>,
    /// Still the **encrypted** base64 value — decrypted only where actually
    /// used (a connection that never resolves a password never attempts a
    /// decrypt, e.g. inside a container whose descendants don't inherit it).
    password: Option<String>,
    protocol: Option<String>,
}

/// Resolves one field for `node`: its own attribute wins when
/// `Inherit<Field>` is explicitly `"false"` (or absent) and `node` actually
/// has its own value; an explicit `"true"` prefers the ancestor's resolved
/// value. Either way, if the preferred source is empty the other is used as
/// a fallback, so a node's effective value is never *lost* — only mRemoteNG's
/// own author's stated intent (own vs. inherited) is honored when both are
/// available.
fn resolve_field(
    own: Option<&str>,
    inherit_attr: Option<&str>,
    ancestor: Option<&str>,
) -> Option<String> {
    let inherits = inherit_attr.is_some_and(|v| v.eq_ignore_ascii_case("true"));
    if inherits {
        ancestor.or(own).map(str::to_string)
    } else {
        own.or(ancestor).map(str::to_string)
    }
}

/// Computes `node`'s own effective values given `ancestor`'s (its parent
/// container's) already-resolved chain. Used both when descending into a
/// `Container` (to build the context its children inherit) and when building
/// a `Connection` (to get its final field values).
fn resolve_inheritable(node: &XmlNode, ancestor: &Inherited) -> Inherited {
    let attr = |name: &str| node.attrs.get(name).map(String::as_str);
    Inherited {
        hostname: resolve_field(
            attr("Hostname"),
            attr("InheritHostname"),
            ancestor.hostname.as_deref(),
        ),
        port: resolve_field(attr("Port"), attr("InheritPort"), ancestor.port.as_deref()),
        username: resolve_field(
            attr("Username"),
            attr("InheritUsername"),
            ancestor.username.as_deref(),
        ),
        domain: resolve_field(
            attr("Domain"),
            attr("InheritDomain"),
            ancestor.domain.as_deref(),
        ),
        password: resolve_field(
            attr("Password"),
            attr("InheritPassword"),
            ancestor.password.as_deref(),
        ),
        protocol: resolve_field(
            attr("Protocol"),
            attr("InheritProtocol"),
            ancestor.protocol.as_deref(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Tree walk: groups + connections
// ---------------------------------------------------------------------------

fn walk_nodes(
    nodes: &[XmlNode],
    parent_group: Option<GroupId>,
    inherited: &Inherited,
    ctx: &mut ParseCtx,
) -> Result<(), ImportExportError> {
    for node in nodes {
        match node.attrs.get("Type").map(String::as_str) {
            Some("Container") => {
                let name = node
                    .attrs
                    .get("Name")
                    .cloned()
                    .unwrap_or_else(|| "Imported folder".to_string());
                let group_id = ctx.fresh_group_id();
                ctx.groups.push(Group {
                    id: group_id,
                    parent_id: parent_group,
                    name,
                    sort: 0,
                    default_credential: None,
                });
                let child_context = resolve_inheritable(node, inherited);
                walk_nodes(&node.children, Some(group_id), &child_context, ctx)?;
            }
            Some("Connection") => build_connection(node, parent_group, inherited, ctx)?,
            Some(other) => {
                tracing::warn!(node_type = %other, "mremoteng: node with unrecognized Type skipped");
                ctx.warnings.push(ImportWarning::new(format!(
                    "node with unrecognized Type '{other}' skipped"
                )));
            }
            None => {
                tracing::warn!("mremoteng: node skipped, missing Type");
                ctx.warnings
                    .push(ImportWarning::new("node missing 'Type' — skipped"));
            }
        }
    }
    Ok(())
}

fn build_connection(
    node: &XmlNode,
    group: Option<GroupId>,
    inherited: &Inherited,
    ctx: &mut ParseCtx,
) -> Result<(), ImportExportError> {
    let effective = resolve_inheritable(node, inherited);
    let name = node
        .attrs
        .get("Name")
        .cloned()
        .unwrap_or_else(|| "Imported connection".to_string());

    let protocol = effective.protocol.unwrap_or_default();
    let kind = match protocol.to_ascii_uppercase().as_str() {
        "RDP" => ConnectionKind::Rdp,
        "SSH1" | "SSH2" => ConnectionKind::Ssh,
        "TELNET" => ConnectionKind::Telnet,
        other => {
            tracing::warn!(connection = %name, protocol = %other, "mremoteng: unsupported protocol skipped");
            ctx.warnings.push(ImportWarning::new(format!(
                "connection '{name}' skipped: unsupported protocol '{other}'"
            )));
            return Ok(());
        }
    };

    let host = effective.hostname.filter(|h| !h.trim().is_empty());
    let Some(host) = host else {
        tracing::warn!(connection = %name, "mremoteng: connection skipped, missing host");
        ctx.warnings.push(ImportWarning::new(format!(
            "connection '{name}' skipped: missing host"
        )));
        return Ok(());
    };

    let username = effective.username.filter(|u| !u.trim().is_empty());
    let domain = effective.domain.filter(|d| !d.trim().is_empty());

    // `decrypted_password` is `None` for two different reasons: no password
    // field at all (perfectly normal, no warning), or a password field that
    // existed but failed to decrypt post password-confirmation (that one
    // field being unusual/corrupt — see `ParseCtx::decrypt`) — only the
    // latter is worth a counted warning, so `password_present` distinguishes
    // them.
    let password_present = effective
        .password
        .as_deref()
        .is_some_and(|p| !p.trim().is_empty());
    let decrypted_password = if kind == ConnectionKind::Telnet {
        // P10.1 Telnet login is driven entirely by the remote terminal. Do
        // not even attempt to decrypt the node's password: aside from being
        // unnecessary, doing so would make ignored credential material
        // observable through password/decryption failures.
        None
    } else if password_present {
        ctx.decrypt(
            effective
                .password
                .as_deref()
                .expect("checked by password_present"),
        )?
    } else {
        None
    };
    if kind == ConnectionKind::Telnet && (username.is_some() || password_present) {
        tracing::warn!(
            connection = %name,
            "mremoteng: Telnet credential fields ignored; login is interactive"
        );
        ctx.warnings.push(ImportWarning::new(format!(
            "connection '{name}': Telnet credentials were ignored because Telnet login is interactive"
        )));
    } else if password_present && decrypted_password.is_none() {
        tracing::warn!(
            connection = %name,
            "mremoteng: password present but undecryptable, connection imported without a credential"
        );
        ctx.warnings.push(ImportWarning::new(format!(
            "connection '{name}': password present but could not be decrypted (imported without a credential)"
        )));
    }

    // P9.6 decision 5: a decrypted password becomes an Inline source —
    // mRemoteNG's per-node password is never shared, so there's no dedupe
    // concept the way RoyalTS's CredentialID has. `username`/`domain` are
    // carried on the source itself (authoritative, per
    // `resolve_connection_auth`'s Inline arm) in addition to still landing on
    // the connection's settings below.
    let credential_source = if kind == ConnectionKind::Telnet {
        Some(CredentialSource::Prompt)
    } else {
        decrypted_password
            .is_some()
            .then(|| CredentialSource::Inline {
                username: username.clone().unwrap_or_default(),
                domain: domain.clone(),
                has_secret: true,
            })
    };

    let port_raw = effective.port;
    let settings = match kind {
        ConnectionKind::Rdp => ConnectionSettings::Rdp(RdpSettings {
            host,
            port: port_raw
                .as_deref()
                .and_then(|p| p.parse().ok())
                .unwrap_or(RdpSettings::DEFAULT_PORT),
            domain,
            username,
            ..RdpSettings::default()
        }),
        ConnectionKind::Ssh => ConnectionSettings::Ssh(SshSettings {
            host,
            port: port_raw
                .as_deref()
                .and_then(|p| p.parse().ok())
                .unwrap_or(SshSettings::DEFAULT_PORT),
            username: username.unwrap_or_default(),
            auth_method: if decrypted_password.is_some() {
                SshAuthMethod::Password
            } else {
                SshAuthMethod::Agent
            },
        }),
        ConnectionKind::LocalTerminal => {
            unreachable!("mremoteng does not classify local terminal nodes")
        }
        ConnectionKind::Telnet => ConnectionSettings::Telnet(TelnetSettings {
            host,
            port: port_raw
                .as_deref()
                .and_then(|p| p.parse().ok())
                .unwrap_or(TelnetSettings::DEFAULT_PORT),
        }),
    };

    push_connection(
        name,
        group,
        kind,
        settings,
        credential_source,
        decrypted_password,
        ctx,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_connection(
    name: String,
    group: Option<GroupId>,
    kind: ConnectionKind,
    settings: ConnectionSettings,
    credential_source: Option<CredentialSource>,
    decrypted_password: Option<Vec<u8>>,
    ctx: &mut ParseCtx,
) {
    let conn_id = ctx.fresh_conn_id();
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
        Ok(conn) => {
            // The Inline secret is only pushed once the connection actually
            // validates — a rejected connection carries no keychain entry to
            // orphan.
            if let Some(pw_bytes) = decrypted_password {
                ctx.connection_secrets.push(ExportedConnectionSecret {
                    connection_id: conn_id,
                    purpose: CredentialPurpose::Password.as_str().to_string(),
                    secret_hex: json_io::to_hex(&pw_bytes),
                });
            }
            ctx.connections.push(conn);
        }
        Err(e) => {
            tracing::warn!(connection = %name, error = %e, "mremoteng: connection skipped (validation)");
            ctx.warnings.push(ImportWarning::new(format!(
                "connection '{name}' skipped: {e}"
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/mremoteng_confCons.xml");

    #[test]
    fn parses_container_nesting_into_group_tree() {
        let (envelope, _warnings) = parse(FIXTURE, "mR3m").expect("fixture should parse");
        let by_name: HashMap<&str, &Group> = envelope
            .groups
            .iter()
            .map(|g| (g.name.as_str(), g))
            .collect();
        let prod = by_name.get("Prod").expect("Prod group present");
        let web = by_name.get("Web").expect("Web group present");
        let shared = by_name.get("Shared").expect("Shared group present");
        assert_eq!(web.parent_id, Some(prod.id));
        assert_eq!(shared.parent_id, Some(prod.id));
    }

    #[test]
    fn parses_rdp_and_ssh2_connections() {
        let (envelope, _warnings) = parse(FIXTURE, "mR3m").expect("fixture should parse");

        let rdp = envelope
            .connections
            .iter()
            .find(|c| c.name == "app01-rdp")
            .expect("rdp connection present");
        assert_eq!(rdp.kind, ConnectionKind::Rdp);
        match &rdp.settings {
            ConnectionSettings::Rdp(s) => {
                assert_eq!(s.host, "app01.example.test");
                assert_eq!(s.domain.as_deref(), Some("CORP"));
            }
            other => panic!("expected Rdp settings, got {other:?}"),
        }

        let ssh = envelope
            .connections
            .iter()
            .find(|c| c.name == "app01-ssh")
            .expect("ssh connection present");
        assert_eq!(ssh.kind, ConnectionKind::Ssh);
        match &ssh.settings {
            ConnectionSettings::Ssh(s) => {
                assert_eq!(s.host, "app01.example.test");
                assert_eq!(s.username, "deploy");
                assert_eq!(s.auth_method, SshAuthMethod::Password);
            }
            other => panic!("expected Ssh settings, got {other:?}"),
        }
    }

    #[test]
    fn decrypted_password_becomes_an_inline_credential_and_connection_secret() {
        let (envelope, _warnings) = parse(FIXTURE, "mR3m").expect("fixture should parse");
        let rdp = envelope
            .connections
            .iter()
            .find(|c| c.name == "app01-rdp")
            .expect("rdp connection present");
        match &rdp.credential_source {
            Some(CredentialSource::Inline {
                username,
                has_secret,
                ..
            }) => {
                assert_eq!(username, "admin");
                assert!(*has_secret);
            }
            other => panic!("expected an Inline credential source, got {other:?}"),
        }
        let secret = envelope
            .connection_secrets
            .iter()
            .find(|s| s.connection_id == rdp.id && s.purpose == "password")
            .expect("password connection-secret present");
        let decoded = (0..secret.secret_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&secret.secret_hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();
        assert_eq!(decoded, b"dummy-pw-1");
        assert!(
            envelope.credentials.is_empty(),
            "mRemoteNG never produces a shared credential object — only Inline sources"
        );
    }

    /// The fixture's "Shared" container carries its own encrypted `Password`
    /// — but a `Container` never becomes a `Connection`/credential itself
    /// (only `Type="Connection"` nodes do), so there is no direct test of
    /// "Shared"'s own secret in isolation. This test *is* that coverage: it
    /// proves the container's password is real, reachable, decryptable
    /// ciphertext by resolving it through the one child that inherits it. If
    /// this test ever seems to have "gone missing" from a search for
    /// "Shared" + "password", it hasn't — this is it.
    #[test]
    fn inherited_password_resolves_from_the_enclosing_container() {
        let (envelope, _warnings) = parse(FIXTURE, "mR3m").expect("fixture should parse");
        let inherited = envelope
            .connections
            .iter()
            .find(|c| c.name == "inherited-conn")
            .expect("inherited-conn present");
        assert!(
            matches!(
                &inherited.credential_source,
                Some(CredentialSource::Inline {
                    has_secret: true,
                    ..
                })
            ),
            "expected an Inline credential source with a secret, got {:?}",
            inherited.credential_source
        );
        let secret = envelope
            .connection_secrets
            .iter()
            .find(|s| s.connection_id == inherited.id && s.purpose == "password")
            .expect("password connection-secret present");
        let decoded = (0..secret.secret_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&secret.secret_hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();
        assert_eq!(
            decoded, b"dummy-shared-pw",
            "InheritPassword=\"true\" must resolve the Shared container's own Password"
        );
    }

    #[test]
    fn unsupported_protocol_is_skipped_with_a_counted_warning() {
        let (envelope, warnings) = parse(FIXTURE, "mR3m").expect("fixture should parse");
        assert!(!envelope.connections.iter().any(|c| c.name == "legacy-vnc"));
        assert!(
            warnings
                .iter()
                .any(|w| w.message.contains("unsupported protocol 'VNC'")),
            "the VNC node must be a counted warning: {warnings:?}"
        );
    }

    #[test]
    fn blank_host_is_skipped_with_a_counted_warning() {
        let (envelope, warnings) = parse(FIXTURE, "mR3m").expect("fixture should parse");
        assert!(
            !envelope
                .connections
                .iter()
                .any(|c| c.name == "no-host-conn")
        );
        assert!(
            warnings.iter().any(|w| w.message.contains("missing host")),
            "the hostless node must be a counted warning: {warnings:?}"
        );
    }

    #[test]
    fn wrong_password_returns_password_required_not_a_panic() {
        let err = parse(FIXTURE, "definitely-wrong").expect_err("wrong password must fail");
        assert!(matches!(err, ImportExportError::PasswordRequired));
    }

    #[test]
    fn full_file_encryption_is_a_clean_unsupported_error() {
        let xml = r#"<?xml version="1.0"?>
<Connections Name="Connections" EncryptionEngine="AES" BlockCipherMode="GCM"
    KdfIterations="1000" FullFileEncryption="true" ConfVersion="2.6">
</Connections>"#;
        let err = parse(xml, "mR3m").expect_err("FullFileEncryption must be rejected cleanly");
        assert!(matches!(err, ImportExportError::Malformed(_)));
    }

    #[test]
    fn legacy_non_gcm_scheme_is_a_clean_unsupported_error() {
        let xml = r#"<?xml version="1.0"?>
<Connections Name="Connections" EncryptionEngine="AES" BlockCipherMode="CBC"
    ConfVersion="1.75">
</Connections>"#;
        let err = parse(xml, "mR3m").expect_err("non-GCM mode must be rejected cleanly");
        assert!(matches!(err, ImportExportError::Malformed(_)));
    }

    /// `full_file_encryption_is_a_clean_unsupported_error` and
    /// `legacy_non_gcm_scheme_is_a_clean_unsupported_error` (above) both use
    /// an unprefixed `<Connections>` root too, but neither ever reaches node
    /// parsing (they error out on the root attrs first). This is the actual
    /// happy-path coverage: an unprefixed legacy root whose child `<Node>`
    /// really does parse into a connection, proving `is_local_name`'s
    /// prefix-agnostic match works end to end, not just "doesn't crash
    /// before erroring."
    #[test]
    fn unprefixed_legacy_root_parses_a_real_connection() {
        let xml = r#"<?xml version="1.0"?>
<Connections Name="Connections" EncryptionEngine="AES" BlockCipherMode="GCM"
    KdfIterations="1000" FullFileEncryption="false"
    Protected="A5nqyoRWQqkL2KxoR2BJSxOSeEozs1oQ1i9qvQjnlolWAGtXVY1lGBiHshF19wcFpkRF7QvACHLq1yjSeBOp"
    ConfVersion="2.6">
  <Node Name="legacy-root-conn" Type="Connection" Protocol="SSH2"
      Hostname="legacy.example.test" Username="root" />
</Connections>"#;
        let (envelope, _warnings) =
            parse(xml, "mR3m").expect("unprefixed root should parse just like the mrng: one");
        assert!(
            envelope
                .connections
                .iter()
                .any(|c| c.name == "legacy-root-conn"),
            "the connection under the unprefixed root must still parse"
        );
    }

    #[test]
    fn node_missing_type_is_skipped_with_a_counted_warning() {
        let xml = r#"<?xml version="1.0"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections"
    EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000"
    FullFileEncryption="false" ConfVersion="2.6">
  <Node Name="no-type-node" Hostname="notype.example.test" />
  <Node Name="good-conn" Type="Connection" Protocol="SSH2"
      Hostname="good.example.test" Username="root" />
</mrng:Connections>"#;
        let (envelope, warnings) =
            parse(xml, "mR3m").expect("a missing-Type node must not fail the whole parse");
        assert!(
            !envelope
                .connections
                .iter()
                .any(|c| c.name == "no-type-node"),
            "a node with no Type must not produce a connection"
        );
        assert!(
            envelope.connections.iter().any(|c| c.name == "good-conn"),
            "the sibling node must still parse"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.message.contains("missing 'Type'")),
            "the missing-Type node must be a counted warning: {warnings:?}"
        );
    }

    /// The subtlest branch in `ParseCtx::decrypt`: once the password has been
    /// confirmed correct (via the root's `Protected` canary here), a LATER
    /// field that still fails to decrypt is that one field being
    /// corrupt/unusual — not a wrong password for the whole file. This
    /// connection's `Password` is real ciphertext, but encrypted under a
    /// different password entirely (reused from
    /// `tests/import_mremoteng.rs`'s custom-password fixture) — decrypting it
    /// with the confirmed "mR3m" must fail the GCM tag, hit the `Ok(None)`
    /// path, and become a counted warning + a credential-less connection,
    /// never a re-triggered `PasswordRequired` for the whole file.
    #[test]
    fn a_single_corrupt_field_after_password_confirmation_is_a_warning_not_a_hard_failure() {
        let xml = r#"<?xml version="1.0"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections"
    EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000"
    FullFileEncryption="false"
    Protected="A5nqyoRWQqkL2KxoR2BJSxOSeEozs1oQ1i9qvQjnlolWAGtXVY1lGBiHshF19wcFpkRF7QvACHLq1yjSeBOp"
    ConfVersion="2.6">
  <Node Name="corrupt-pw-conn" Type="Connection" Protocol="SSH2"
      Hostname="corrupt.example.test" Username="svc"
      Password="Mgr1rTSfK8KlOpiVc0tDB8WUnd5dNg33VZDo7BmMoNkIR+nkTFAQZnuBU+NE42prNvsZCQGYM3dqHFiTug==" />
</mrng:Connections>"#;
        let (envelope, warnings) =
            parse(xml, "mR3m").expect("one corrupt field must not fail the whole parse");
        let conn = envelope
            .connections
            .iter()
            .find(|c| c.name == "corrupt-pw-conn")
            .expect("the connection must still import");
        assert_eq!(
            conn.credential_source, None,
            "no credential -- the field couldn't be decrypted"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.message.contains("could not be decrypted")),
            "the corrupt field must be a counted warning: {warnings:?}"
        );
    }

    #[test]
    fn telnet_inherits_transport_fields_but_never_decrypts_or_imports_credentials() {
        let xml = r#"<?xml version="1.0"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections"
    EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000"
    FullFileEncryption="false" ConfVersion="2.6">
  <Node Name="Inherited Telnet" Type="Container" Protocol="Telnet"
      Hostname="inherited.example.test" Port="2323" Username="legacy-user"
      Password="deliberately-not-valid-ciphertext">
    <Node Name="inherited-console" Type="Connection"
        InheritProtocol="true" InheritHostname="true" InheritPort="true"
        InheritUsername="true" InheritPassword="true" />
  </Node>
  <Node Name="default-port-console" Type="Connection" Protocol="tELnEt"
      Hostname="default.example.test" />
</mrng:Connections>"#;

        // There is no Protected canary and the inherited Password is invalid
        // ciphertext. Success proves the Telnet node's ignored password was
        // never passed to the decryptor.
        let (envelope, warnings) =
            parse(xml, "wrong-and-irrelevant").expect("Telnet password must not be decrypted");
        assert_eq!(envelope.connections.len(), 2);

        let inherited = envelope
            .connections
            .iter()
            .find(|connection| connection.name == "inherited-console")
            .expect("inherited Telnet connection present");
        assert_eq!(inherited.kind, ConnectionKind::Telnet);
        assert_eq!(inherited.credential_source, Some(CredentialSource::Prompt));
        match &inherited.settings {
            ConnectionSettings::Telnet(settings) => {
                assert_eq!(settings.host, "inherited.example.test");
                assert_eq!(settings.port, 2323);
            }
            other => panic!("expected Telnet settings, got {other:?}"),
        }

        let default_port = envelope
            .connections
            .iter()
            .find(|connection| connection.name == "default-port-console")
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
        assert!(!serialized.contains("legacy-user"));
        assert!(!serialized.contains("deliberately-not-valid-ciphertext"));

        let ignored_warnings = warnings
            .iter()
            .filter(|warning| warning.message.contains("Telnet credentials were ignored"))
            .collect::<Vec<_>>();
        assert_eq!(
            ignored_warnings.len(),
            1,
            "inherited username plus password produce one warning for their connection: {warnings:?}"
        );
        assert!(ignored_warnings[0].message.contains("inherited-console"));
    }
}

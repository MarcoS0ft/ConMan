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
//! anything else → skipped with a counted [`ImportWarning`]. A blank/absent
//! effective `Hostname` also skips the connection (counted), mirroring CSV's
//! missing-host handling. `Port` blank/unparsable → the kind's default.
//! mRemoteNG has **no separate credential objects** (creds are inline per
//! node) — like CSV without `cred_name`, a per-connection [`Credential`] is
//! created only when a password actually decrypts; `username`/`domain` land
//! on the connection's settings; SSH `auth_method` is
//! [`SshAuthMethod::Password`] when a password resolved, else
//! [`SshAuthMethod::Agent`] (mirrors `royalts.rs`'s `build_ssh_connection`).

use std::collections::HashMap;

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionSettings, Credential, CredentialId,
    CredentialKind, CredentialPurpose, Group, GroupId, RdpSettings, SshAuthMethod, SshSettings,
};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use crate::json_io::{self, ExportEnvelope, ExportedSecret, ImportExportError};

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
    password: String,
    kdf_iterations: u32,
    /// Set once any field has successfully decrypted with `password` — see
    /// [`ParseCtx::decrypt`].
    password_confirmed: bool,
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
    let decrypted_password = if password_present {
        ctx.decrypt(
            effective
                .password
                .as_deref()
                .expect("checked by password_present"),
        )?
    } else {
        None
    };
    if password_present && decrypted_password.is_none() {
        tracing::warn!(
            connection = %name,
            "mremoteng: password present but undecryptable, connection imported without a credential"
        );
        ctx.warnings.push(ImportWarning::new(format!(
            "connection '{name}': password present but could not be decrypted (imported without a credential)"
        )));
    }

    let credential = decrypted_password.as_ref().map(|pw_bytes| {
        let cred_id = ctx.fresh_cred_id();
        ctx.credentials.push(Credential {
            id: cred_id,
            name: format!("{name} credential"),
            kind: CredentialKind::Password,
            folder_id: None,
            username: username.clone(),
        });
        ctx.credential_secrets.push(ExportedSecret {
            credential_id: cred_id,
            purpose: CredentialPurpose::Password.as_str().to_string(),
            secret_hex: json_io::to_hex(pw_bytes),
        });
        cred_id
    });

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
            auth_method: if credential.is_some() {
                SshAuthMethod::Password
            } else {
                SshAuthMethod::Agent
            },
        }),
        ConnectionKind::LocalTerminal => {
            unreachable!("mremoteng only ever classifies RDP/SSH1/SSH2 into this arm")
        }
    };

    push_connection(name, group, kind, settings, credential, ctx);
    Ok(())
}

fn push_connection(
    name: String,
    group: Option<GroupId>,
    kind: ConnectionKind,
    settings: ConnectionSettings,
    credential: Option<CredentialId>,
    ctx: &mut ParseCtx,
) {
    let conn_id = ctx.fresh_conn_id();
    match Connection::new(
        conn_id,
        group,
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
    fn decrypted_password_becomes_a_per_connection_credential_and_secret() {
        let (envelope, _warnings) = parse(FIXTURE, "mR3m").expect("fixture should parse");
        let rdp = envelope
            .connections
            .iter()
            .find(|c| c.name == "app01-rdp")
            .expect("rdp connection present");
        let cred_id = rdp
            .credential
            .expect("rdp connection should carry a credential");
        let secret = envelope
            .credential_secrets
            .iter()
            .find(|s| s.credential_id == cred_id && s.purpose == "password")
            .expect("password secret present");
        let decoded = (0..secret.secret_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&secret.secret_hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();
        assert_eq!(decoded, b"dummy-pw-1");
    }

    #[test]
    fn inherited_password_resolves_from_the_enclosing_container() {
        let (envelope, _warnings) = parse(FIXTURE, "mR3m").expect("fixture should parse");
        let inherited = envelope
            .connections
            .iter()
            .find(|c| c.name == "inherited-conn")
            .expect("inherited-conn present");
        let cred_id = inherited
            .credential
            .expect("inherited-conn should carry the container's credential");
        let secret = envelope
            .credential_secrets
            .iter()
            .find(|s| s.credential_id == cred_id && s.purpose == "password")
            .expect("password secret present");
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
}

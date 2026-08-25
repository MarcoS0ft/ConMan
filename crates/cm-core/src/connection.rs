use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::ids::{ConnectionId, CredentialId, GroupId};
use crate::kind::ConnectionKind;
use crate::settings::ConnectionSettings;

// ---------------------------------------------------------------------------
// CredentialSource (P9.6-A)
// ---------------------------------------------------------------------------

/// How a [`Connection`] obtains its authentication credential.
///
/// Lives on [`Connection::credential_source`] as `Option<CredentialSource>` —
/// **`None` means "inherit from the ancestor group chain"** (today's
/// behavior, preserved: see [`resolve_effective_credential`]), which is
/// meaningfully different from `Some(Prompt)` (explicitly ignore inheritance
/// and always prompt). The three `Some(_)` variants are the user-approved
/// explicit modes.
///
/// Adjacently tagged (`{"kind": "...", "value": ...}`) rather than the
/// internally-tagged style [`crate::SshAuthMethod`] uses, because `Object`'s
/// payload (a bare [`CredentialId`], itself `#[serde(transparent)]`) can't be
/// flattened into an internally-tagged map the way `SshAuthMethod::PublicKey`'s
/// struct payload can.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CredentialSource {
    /// Reference a shared [`crate::Credential`] object (today's explicit
    /// credential link, renamed from `Connection::credential`).
    Object(CredentialId),
    /// Username/domain entered directly on the connection. The secret (if
    /// any) lives in the keychain keyed to the **connection**, not a
    /// credential object — see [`crate::CredentialRef::for_connection`].
    /// Password only; inline SSH keys/passphrases stay credential-objects
    /// (non-goal, per the P9.6 design brief).
    Inline {
        username: String,
        domain: Option<String>,
        /// Whether a keychain entry exists for this connection's inline
        /// secret. Lets a caller skip the keychain round-trip when `false`
        /// (nothing to fetch) and the UI show "set"/"unset" without a
        /// keychain read.
        has_secret: bool,
    },
    /// Explicitly no stored secret — prompt at connect time.
    Prompt,
}

/// A node in the connection tree that holds connections and/or other groups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    /// Parent group; `None` means root level.
    pub parent_id: Option<GroupId>,
    pub name: String,
    /// Ordering among siblings.
    pub sort: i64,
    /// The credential inherited by connections in this group and its
    /// descendants unless overridden. `None` means no default (inherit from
    /// the parent group or leave unset).
    pub default_credential: Option<CredentialId>,
}

/// A saved connection profile. Carries kind-specific [`ConnectionSettings`]
/// and, optionally, a [`CredentialSource`] (never the secret itself). The
/// effective credential is resolved by [`resolve_effective_credential`]
/// (object id only) or, for the full username/domain/secret picture,
/// [`resolve_connection_auth`].
///
/// Timestamps are `i64` epoch seconds (no `chrono` dependency).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    pub id: ConnectionId,
    /// Owning group; `None` means root level.
    pub group_id: Option<GroupId>,
    pub name: String,
    pub kind: ConnectionKind,
    pub settings: ConnectionSettings,
    /// How this connection obtains its credential. `None` means inherit from
    /// the ancestor group chain (see [`resolve_effective_credential`]) —
    /// preserves today's behavior. `Some(_)` is one of the three explicit,
    /// user-facing modes (P9.6-A): reference a shared object, inline
    /// creds, or explicitly prompt.
    #[serde(default)]
    pub credential_source: Option<CredentialSource>,
    /// **Deserialize-only legacy shim** (P9.6-A): pre-P9.6 exports/envelopes
    /// serialized the credential link as a bare `"credential": <id|null>`
    /// field (no `credential_source`). Reading that old shape populates this
    /// field via serde; `cm_storage::json_io::import`'s normalization step
    /// maps it into `credential_source` (`Some(id) → Object(id)`, `None` →
    /// inherit) and clears it. Never populated by new code, never
    /// serialized out — `credential_source` is the only wire shape new
    /// exports produce.
    #[serde(rename = "credential", default, skip_serializing)]
    pub legacy_credential: Option<CredentialId>,
    /// Ordering among siblings.
    pub sort: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Connection {
    /// Builds a connection, rejecting a `settings` variant that disagrees with
    /// `kind` ([`DomainError::SettingsKindMismatch`]).
    // The entity genuinely has this many independent fields; grouping them into
    // a sub-struct purely to satisfy the lint would obscure the data model.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ConnectionId,
        group_id: Option<GroupId>,
        name: String,
        kind: ConnectionKind,
        settings: ConnectionSettings,
        credential_source: Option<CredentialSource>,
        sort: i64,
        created_at: i64,
        updated_at: i64,
    ) -> Result<Self, DomainError> {
        let conn = Self {
            id,
            group_id,
            name,
            kind,
            settings,
            credential_source,
            legacy_credential: None,
            sort,
            created_at,
            updated_at,
        };
        conn.validate()?;
        Ok(conn)
    }

    /// Checks kind/settings and protocol-specific invariants. Use this to
    /// defensively validate connections rehydrated from untrusted input (for
    /// example, imported JSON).
    pub fn validate(&self) -> Result<(), DomainError> {
        let found = self.settings.kind();
        if found != self.kind {
            return Err(DomainError::SettingsKindMismatch {
                expected: self.kind,
                found,
            });
        }
        if let ConnectionSettings::Telnet(settings) = &self.settings {
            if settings.host.trim().is_empty() {
                return Err(DomainError::TelnetHostEmpty);
            }
            if self.credential_source != Some(CredentialSource::Prompt) {
                return Err(DomainError::TelnetCredentialSourceMustPrompt);
            }
        }
        Ok(())
    }
}

/// Returns the effective credential-**object** id for a connection, i.e. the
/// id that applies when the connection's [`CredentialSource`] is (or resolves
/// through inheritance to) [`CredentialSource::Object`]:
///
/// 1. `Some(CredentialSource::Object(id))` on the connection itself, or
/// 2. `None` (inherit) → the `default_credential` of the nearest ancestor
///    group that has one (walking `parent_id` up the chain), or
/// 3. `None` if neither the connection nor any ancestor group specifies one,
///    or the connection's own source is `Inline`/`Prompt` (an explicit,
///    non-object choice — never falls back to the group chain).
///
/// The walk is bounded by `groups.len()` to be cycle-safe: a valid (acyclic)
/// group tree of N nodes has paths of at most N steps, so any longer walk
/// would imply a cycle and is terminated. Used by [`resolve_connection_auth`]
/// for the `Object`/inherit cases; kept as its own function because callers
/// that only care about "which shared credential object applies" (e.g. tree
/// UI display) don't need the full username/domain/secret resolution.
pub fn resolve_effective_credential(conn: &Connection, groups: &[Group]) -> Option<CredentialId> {
    match &conn.credential_source {
        Some(CredentialSource::Object(id)) => return Some(*id),
        Some(_) => return None, // Inline/Prompt: explicit non-object source, no group fallback
        None => {}              // inherit: fall through to the group walk
    }

    // Walk ancestor groups; bounded by group count for cycle safety.
    let max_depth = groups.len();
    let mut current_group_id = conn.group_id;
    for _ in 0..max_depth {
        let gid = current_group_id?;
        let group = groups.iter().find(|g| g.id == gid)?;
        if let Some(cred) = group.default_credential {
            return Some(cred);
        }
        current_group_id = group.parent_id;
    }
    None
}

// ---------------------------------------------------------------------------
// resolve_connection_auth (P9.6-A Decision 3)
// ---------------------------------------------------------------------------

/// Effective, resolved authentication material for a [`Connection`] — the
/// pure counterpart to `cm_ui::controller::sessions::resolve_ssh_auth` /
/// `resolve_rdp_auth` (Phase C makes those thin adapters over this).
#[derive(Debug, Clone)]
pub struct ResolvedAuth {
    /// Never `None` for callers that need a bare string (matches the
    /// existing `effective_auth_username` contract) — empty string means "no
    /// username resolved from any source," the same as today.
    pub username: String,
    /// `Some` only when [`CredentialSource::Inline`] provides an authoritative
    /// override; `None` means "no override — use the connection's own
    /// [`crate::RdpSettings::domain`]/[`crate::SshSettings`] as before" (a
    /// credential object never carries a domain).
    pub domain: Option<String>,
    /// `None` when there's nothing to fetch (`Prompt`, no credential resolved
    /// at all, or an `Inline` source with `has_secret: false`) or the
    /// keychain has no entry for `purpose` (a miss, not an error — callers
    /// already treat "no secret" as "prompt/fail to connect", not a crash).
    pub secret: Option<crate::Secret>,
}

/// Resolves the effective `{username, domain, secret}` for `conn`, extending
/// the existing most-specific-wins precedence
/// (`cm_ui::controller::sessions::effective_auth_username`) rather than
/// reinventing it:
///
/// - `None` (inherit) → walk groups via [`resolve_effective_credential`]; a
///   resolved object id is handled exactly like `Some(Object(id))` below; no
///   credential anywhere in the chain → `username` falls back to the
///   connection's own settings username, `secret` is `None`.
/// - `Some(Object(id))` → `username` = the object's own non-empty `username`,
///   else the connection's settings username; `secret` =
///   `store.get(cred:<id>:<purpose>)`.
/// - `Some(Inline { username, domain, has_secret })` → `username`/`domain`
///   are authoritative (override settings + group; `username` still falls
///   back to the settings username if the inline value is empty, mirroring
///   the object case's defensiveness); `secret` = `has_secret &&
///   purpose == Password` ? `store.get(conn:<id>:password)` : `None` (inline
///   never stores any other purpose — password-only, per the non-goals).
/// - `Some(Prompt)` → `username` = the connection's settings username (may be
///   empty), `domain` = `None`, `secret` = `None` (the caller prompts).
///
/// `purpose` lets one connection's SSH `PublicKey` auth call this twice (once
/// for `SshKey`, required; once for `SshPassphrase`, optional) the same way
/// `resolve_ssh_auth` already does with `require_secret`/`fetch_secret` — this
/// function stays protocol-agnostic (RDP is always `Password`; SSH picks the
/// purpose(s) its `auth_method` needs).
///
/// A pure function over the [`crate::CredentialStore`] port — unit-testable
/// with a mock store, and the one place cm-ui/cm-session-facing adapters both
/// call into. Only a genuine backend failure (not a miss) is `Err`.
pub fn resolve_connection_auth(
    conn: &Connection,
    groups: &[Group],
    credentials: &[crate::Credential],
    store: &dyn crate::CredentialStore,
    purpose: crate::CredentialPurpose,
) -> Result<ResolvedAuth, crate::CredentialError> {
    let settings_username = settings_username(conn);

    match &conn.credential_source {
        None => match resolve_effective_credential(conn, groups) {
            Some(object_id) => {
                resolve_object(object_id, credentials, store, purpose, settings_username)
            }
            None => Ok(ResolvedAuth {
                username: settings_username.to_owned(),
                domain: None,
                secret: None,
            }),
        },
        Some(CredentialSource::Object(id)) => {
            resolve_object(*id, credentials, store, purpose, settings_username)
        }
        Some(CredentialSource::Inline {
            username,
            domain,
            has_secret,
        }) => {
            let secret = if *has_secret && purpose == crate::CredentialPurpose::Password {
                store.get(&crate::CredentialRef::for_connection(conn.id, purpose))?
            } else {
                None
            };
            let username = if username.is_empty() {
                settings_username.to_owned()
            } else {
                username.clone()
            };
            Ok(ResolvedAuth {
                username,
                domain: domain.clone(),
                secret,
            })
        }
        Some(CredentialSource::Prompt) => Ok(ResolvedAuth {
            username: settings_username.to_owned(),
            domain: None,
            secret: None,
        }),
    }
}

/// The kind-specific username already on `conn.settings` — the fallback
/// every [`CredentialSource`] arm defers to when it has nothing more specific
/// (mirrors `effective_auth_username`'s `inline_username` parameter, just
/// read directly off `conn` instead of threaded in by the caller).
fn settings_username(conn: &Connection) -> &str {
    match &conn.settings {
        ConnectionSettings::Ssh(s) => s.username.as_str(),
        ConnectionSettings::Rdp(s) => s.username.as_deref().unwrap_or(""),
        ConnectionSettings::Telnet(_) => "",
        ConnectionSettings::Local(_) => "",
    }
}

fn resolve_object(
    id: CredentialId,
    credentials: &[crate::Credential],
    store: &dyn crate::CredentialStore,
    purpose: crate::CredentialPurpose,
    settings_username: &str,
) -> Result<ResolvedAuth, crate::CredentialError> {
    let cred_username = credentials
        .iter()
        .find(|c| c.id == id)
        .and_then(|c| c.username.clone())
        .filter(|u| !u.is_empty());
    let username = cred_username.unwrap_or_else(|| settings_username.to_owned());
    let secret = store.get(&crate::CredentialRef::new(id, purpose))?;
    Ok(ResolvedAuth {
        username,
        domain: None,
        secret,
    })
}

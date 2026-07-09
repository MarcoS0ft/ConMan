use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::ids::{CredentialFolderId, CredentialId};

// ---------------------------------------------------------------------------
// CredentialKind
// ---------------------------------------------------------------------------

/// The kind of secret material stored for a [`Credential`].
///
/// Serde tags are a wire/format contract — pin them, do not churn them.
/// `SshKeyWithPassphrase` indicates that both an SSH private key and its
/// passphrase are stored in the keychain under the same [`CredentialId`] keyed
/// by [`CredentialPurpose::SshKey`] and [`CredentialPurpose::SshPassphrase`]
/// respectively ("passphrase-as-purpose" model).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CredentialKind {
    #[serde(rename = "password")]
    Password,
    #[serde(rename = "ssh-key")]
    SshKey,
    #[serde(rename = "ssh-key-with-passphrase")]
    SshKeyWithPassphrase,
}

// ---------------------------------------------------------------------------
// Credential and CredentialFolder entities
// ---------------------------------------------------------------------------

/// A first-class, shareable credential object. Carries only non-secret
/// metadata; the actual secret lives in the OS keychain keyed by
/// [`CredentialRef`] (service=`"conman"`, account=`"cred:<id>:<purpose>"`).
///
/// Many connections may reference the same `Credential` via
/// [`crate::Connection::credential`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub id: CredentialId,
    pub name: String,
    pub kind: CredentialKind,
    /// The credential folder this credential belongs to; `None` means root.
    pub folder_id: Option<CredentialFolderId>,
    /// The login username stored alongside the credential (not a secret --
    /// the password/key material lives in the keychain, keyed separately).
    /// BUG-cred-username-auth: this is now the *authoritative* auth username
    /// once a credential is assigned to a connection (own, or inherited via
    /// [`crate::resolve_effective_credential`]) -- see
    /// `cm_ui::controller::sessions::effective_auth_username`. A connection's
    /// inline `settings.username` is only the fallback for connections with
    /// no credential assigned (e.g. Quick Connect with a typed username).
    pub username: Option<String>,
}

/// A node in the credential folder tree. Folders nest arbitrarily via
/// `parent_id`; a `None` parent is a root-level folder. The storage layer
/// (P1.1) enforces the no-cycle constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialFolder {
    pub id: CredentialFolderId,
    /// Parent folder; `None` means root level.
    pub parent_id: Option<CredentialFolderId>,
    pub name: String,
    /// Ordering among siblings.
    pub sort: i64,
}

// ---------------------------------------------------------------------------
// CredentialPurpose
// ---------------------------------------------------------------------------

/// What a stored secret is used for. The string forms (`"password"`,
/// `"ssh-key"`, `"ssh-passphrase"`) are part of the [`CredentialRef`] account
/// format (`"cred:<id>:<purpose>"`) and are a contract the keychain adapter
/// (P1.3) relies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialPurpose {
    Password,
    SshKey,
    SshPassphrase,
}

impl CredentialPurpose {
    /// The stable string form used inside a [`CredentialRef`] account.
    pub const fn as_str(self) -> &'static str {
        match self {
            CredentialPurpose::Password => "password",
            CredentialPurpose::SshKey => "ssh-key",
            CredentialPurpose::SshPassphrase => "ssh-passphrase",
        }
    }
}

// ---------------------------------------------------------------------------
// CredentialRef
// ---------------------------------------------------------------------------

/// An opaque, stable key identifying a secret in the OS keychain. It is a
/// `service` + `account` pair; the secret itself is **never** stored here.
///
/// The format is a contract the keychain adapter (P1.3) relies on: the service
/// is fixed ([`CredentialRef::SERVICE`]) and the account is
/// `"cred:<credential-id>:<purpose>"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialRef {
    service: String,
    account: String,
}

impl CredentialRef {
    /// The fixed keychain service name for all ConMan credentials.
    pub const SERVICE: &'static str = "conman";

    /// Builds the reference for a given credential **object** and purpose.
    pub fn new(credential: CredentialId, purpose: CredentialPurpose) -> Self {
        Self {
            service: Self::SERVICE.to_string(),
            account: format!("cred:{}:{}", credential.get(), purpose.as_str()),
        }
    }

    /// Builds the reference for a **connection-scoped** inline secret
    /// (P9.6-A `CredentialSource::Inline`) — account
    /// `"conn:<connection-id>:<purpose>"`, distinct from [`Self::new`]'s
    /// `"cred:<credential-id>:<purpose>"` so inline secrets never collide
    /// with a credential object's keychain slot even if the numeric ids
    /// happen to coincide.
    pub fn for_connection(connection: crate::ConnectionId, purpose: CredentialPurpose) -> Self {
        Self {
            service: Self::SERVICE.to_string(),
            account: format!("conn:{}:{}", connection.get(), purpose.as_str()),
        }
    }

    /// The keychain service name.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The keychain account name (`"cred:<credential-id>:<purpose>"`).
    pub fn account(&self) -> &str {
        &self.account
    }
}

// ---------------------------------------------------------------------------
// Secret
// ---------------------------------------------------------------------------

/// A secret value (e.g. a password or key) held only transiently at the
/// boundary between a [`crate::CredentialStore`] and its consumers.
///
/// The backing bytes are zeroized on drop, and `Debug`/`Display` redact the
/// contents — `Debug` is **never** derived, to avoid leaking the secret into
/// logs or error messages.
#[derive(Clone)]
pub struct Secret {
    bytes: Vec<u8>,
}

impl Secret {
    /// Wraps raw secret bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Wraps a secret string, zeroizing the source `String`.
    pub fn from_string(mut value: String) -> Self {
        let secret = Self {
            bytes: value.as_bytes().to_vec(),
        };
        value.zeroize();
        secret
    }

    /// Borrows the raw secret bytes. Use sparingly and never log the result.
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

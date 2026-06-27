use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::ids::ConnectionId;

/// What a stored secret is used for. The string forms (`"password"`,
/// `"ssh-key"`, `"ssh-passphrase"`) are part of the [`CredentialRef`] account
/// format and are a contract the keychain adapter (P1.3) relies on.
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

/// An opaque, stable key identifying a secret in the OS keychain. It is a
/// `service` + `account` pair; the secret itself is **never** stored here.
///
/// The format is a contract the keychain adapter (P1.3) relies on: the service
/// is fixed ([`CredentialRef::SERVICE`]) and the account is
/// `"<connection-id>:<purpose>"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialRef {
    service: String,
    account: String,
}

impl CredentialRef {
    /// The fixed keychain service name for all ConMan credentials.
    pub const SERVICE: &'static str = "conman";

    /// Builds the reference for a given connection and purpose.
    pub fn new(connection: ConnectionId, purpose: CredentialPurpose) -> Self {
        Self {
            service: Self::SERVICE.to_string(),
            account: format!("{}:{}", connection.get(), purpose.as_str()),
        }
    }

    /// The keychain service name.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The keychain account name (`"<connection-id>:<purpose>"`).
    pub fn account(&self) -> &str {
        &self.account
    }
}

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

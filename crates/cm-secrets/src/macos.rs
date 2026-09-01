//! macOS data-protection Keychain adapter.
//!
//! ConMan deliberately does not query the legacy file-based Keychain. Every
//! operation targets the data-protection Keychain and the shared access group
//! granted to the signed GUI and `conmanctl` bundles. Consequently, an old
//! legacy item is neither migrated nor silently adopted.

use std::fmt;

use cm_core::{CredentialError, CredentialRef, CredentialStore, Secret};
use security_framework::passwords::{
    PasswordOptions, delete_generic_password_options, generic_password,
    set_generic_password_options,
};
use security_framework_sys::base::{
    errSecAuthFailed as ERR_SEC_AUTH_FAILED, errSecItemNotFound as ERR_SEC_ITEM_NOT_FOUND,
};

/// Keychain access group shared by the GUI and the bundled command-line tool.
///
/// This value must match both executables' signed entitlements. Apple's data-
/// protection Keychain rejects access when the entitlement or its authorizing
/// provisioning profile is absent; there is intentionally no insecure or
/// legacy fallback.
pub(crate) const ACCESS_GROUP: &str = "2NZRF4HQT7.com.marcos0ft.conman.shared";

/// Credential store backed by the per-user macOS data-protection Keychain.
#[derive(Default)]
pub struct KeyringStore;

impl KeyringStore {
    /// Creates a data-protection Keychain store.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn options(key: &CredentialRef) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(key.service(), key.account());
        options.use_protected_keychain();
        options.set_access_group(ACCESS_GROUP);
        options
    }

    fn backend_error(operation: &str, code: i32) -> CredentialError {
        tracing::error!(
            operation,
            code,
            "macOS data-protection Keychain operation failed"
        );
        let guidance = match code {
            // errSecMissingEntitlement (not currently exported by
            // security-framework-sys).
            -34_018 => "this ConMan build is not signed with its authorized Keychain Access Group",
            // errSecInteractionNotAllowed.
            -25_308 => "the user Keychain is locked or interaction is unavailable",
            // errSecUserCanceled and errSecAuthFailed.
            -128 | ERR_SEC_AUTH_FAILED => "Keychain access was denied or cancelled",
            _ => "the operating system rejected the request",
        };
        CredentialError::Backend(format!(
            "macOS data-protection Keychain {operation} failed: {guidance} (OSStatus {code})"
        ))
    }
}

impl fmt::Debug for KeyringStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyringStore")
            .field("backend", &"macOS data-protection Keychain")
            .finish_non_exhaustive()
    }
}

impl CredentialStore for KeyringStore {
    fn store(&self, key: &CredentialRef, secret: &Secret) -> Result<(), CredentialError> {
        set_generic_password_options(secret.expose(), Self::options(key))
            .map_err(|error| Self::backend_error("store", error.code()))
    }

    fn get(&self, key: &CredentialRef) -> Result<Option<Secret>, CredentialError> {
        match generic_password(Self::options(key)) {
            Ok(secret) => Ok(Some(Secret::new(secret))),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(Self::backend_error("get", error.code())),
        }
    }

    fn delete(&self, key: &CredentialRef) -> Result<(), CredentialError> {
        match delete_generic_password_options(Self::options(key)) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(error) => Err(Self::backend_error("delete", error.code())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_group_is_team_scoped_and_stable() {
        assert_eq!(ACCESS_GROUP, "2NZRF4HQT7.com.marcos0ft.conman.shared");
    }

    #[test]
    fn debug_does_not_disclose_item_identifiers() {
        let debug = format!("{:?}", KeyringStore::new());
        assert!(debug.contains("data-protection Keychain"));
        assert!(!debug.contains("cred:"));
    }

    #[test]
    fn entitlement_and_denial_errors_are_actionable() {
        let entitlement = KeyringStore::backend_error("get", -34_018).to_string();
        assert!(entitlement.contains("not signed"));
        assert!(entitlement.contains("Keychain Access Group"));

        let denied = KeyringStore::backend_error("get", ERR_SEC_AUTH_FAILED).to_string();
        assert!(denied.contains("denied or cancelled"));
    }
}

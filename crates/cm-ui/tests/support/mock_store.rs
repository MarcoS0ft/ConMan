//! A `CredentialStore` double for the element-test harness. It avoids OS
//! keychain access so [`cm_ui::build_for_test`] can construct a real
//! [`CredentialStore`] port and exercise UI behavior.
//! `AppWindow` + controller without touching the OS keychain from a test
//! process.

use cm_core::{CredentialError, CredentialRef, CredentialStore, Secret};

/// Stores nothing, resolves nothing. Every call succeeds trivially -- there
/// is nothing for a suite to assert about credential persistence here (that
/// would need `cm-secrets`), only that the port is satisfied.
#[derive(Debug, Default)]
pub(crate) struct NullCredentialStore;

impl CredentialStore for NullCredentialStore {
    fn store(&self, _key: &CredentialRef, _secret: &Secret) -> Result<(), CredentialError> {
        Ok(())
    }

    fn get(&self, _key: &CredentialRef) -> Result<Option<Secret>, CredentialError> {
        Ok(None)
    }

    fn delete(&self, _key: &CredentialRef) -> Result<(), CredentialError> {
        Ok(())
    }
}

//! A `CredentialStore` double for the P8.2 element-test harness.
//!
//! None of the P8.2 suites drive a real secret round-trip through the OS
//! keychain -- that is `cm-secrets`'s own concern (and out of scope per the
//! task spec: "real protocol sessions... out"). This just satisfies the
//! [`CredentialStore`] port so [`cm_ui::build_for_test`] can construct a real
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

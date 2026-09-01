//! Linux credential storage backed by the freedesktop Secret Service.
//!
//! A Secret Service provider such as GNOME Keyring or KWallet owns persistence,
//! locking, and user prompts. ConMan deliberately does not fall back to the
//! process/session-scoped kernel keyring: a saved credential must either be
//! durably stored or fail with an actionable error.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use cm_core::{CredentialError, CredentialRef, CredentialStore, Secret};

/// Select the persistent freedesktop Secret Service backend.
pub(crate) fn initialize_native_keyring() {
    keyring::set_default_credential_builder(keyring::secret_service::default_credential_builder());
    tracing::info!(backend = "secret-service", "keychain backend initialized");
}

/// Persistent Linux implementation of [`CredentialStore`].
pub struct KeyringStore {
    entries: Mutex<HashMap<(String, String), Arc<keyring::Entry>>>,
    // keyring's synchronous Secret Service backend cautions against concurrent
    // or rapidly overlapping D-Bus calls. One process-wide store is shared by
    // ConMan, so a small operation lock is sufficient.
    io: Mutex<()>,
}

impl KeyringStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            io: Mutex::new(()),
        }
    }

    fn entry_for(&self, key: &CredentialRef) -> Result<Arc<keyring::Entry>, CredentialError> {
        let cache_key = (key.service().to_owned(), key.account().to_owned());
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(entry) = entries.get(&cache_key) {
            return Ok(Arc::clone(entry));
        }

        let entry = keyring::Entry::new(key.service(), key.account()).map_err(map_error)?;
        let entry = Arc::new(entry);
        entries.insert(cache_key, Arc::clone(&entry));
        Ok(entry)
    }

    fn with_io<T>(
        &self,
        operation: impl FnOnce() -> Result<T, keyring::Error>,
    ) -> Result<T, CredentialError> {
        let _guard = self
            .io
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        operation().map_err(map_error)
    }
}

impl Default for KeyringStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for KeyringStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyringStore").finish_non_exhaustive()
    }
}

impl CredentialStore for KeyringStore {
    fn store(&self, key: &CredentialRef, secret: &Secret) -> Result<(), CredentialError> {
        let entry = self.entry_for(key)?;
        self.with_io(|| entry.set_secret(secret.expose()))
            .inspect_err(|error| {
                tracing::error!(
                    purpose = key.purpose_str().unwrap_or("unknown"),
                    error = %error,
                    "Secret Service store failed"
                );
            })
    }

    fn get(&self, key: &CredentialRef) -> Result<Option<Secret>, CredentialError> {
        let entry = self.entry_for(key)?;
        let result = {
            let _guard = self
                .io
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            entry.get_secret()
        };

        match result {
            Ok(bytes) => {
                tracing::debug!(
                    purpose = key.purpose_str().unwrap_or("unknown"),
                    hit = true,
                    "Secret Service get"
                );
                Ok(Some(Secret::new(bytes)))
            }
            Err(keyring::Error::NoEntry) => {
                tracing::debug!(
                    purpose = key.purpose_str().unwrap_or("unknown"),
                    hit = false,
                    "Secret Service get"
                );
                Ok(None)
            }
            Err(error) => {
                let error = map_error(error);
                tracing::error!(
                    purpose = key.purpose_str().unwrap_or("unknown"),
                    error = %error,
                    "Secret Service get failed"
                );
                Err(error)
            }
        }
    }

    fn delete(&self, key: &CredentialRef) -> Result<(), CredentialError> {
        let entry = self.entry_for(key)?;
        let result = {
            let _guard = self
                .io
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            entry.delete_credential()
        };

        match result {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => {
                let error = map_error(error);
                tracing::error!(
                    purpose = key.purpose_str().unwrap_or("unknown"),
                    error = %error,
                    "Secret Service delete failed"
                );
                Err(error)
            }
        }
    }
}

fn map_error(error: keyring::Error) -> CredentialError {
    let message = match error {
        keyring::Error::NoStorageAccess(cause) => format!(
            "Linux Secret Service is locked or access was denied or cancelled; unlock the desktop credential wallet or keyring and try again ({cause})"
        ),
        keyring::Error::PlatformFailure(cause) => format!(
            "Linux Secret Service is unavailable; start a Secret Service provider in this desktop session and try again ({cause})"
        ),
        other => format!("Linux Secret Service operation failed: {other}"),
    };
    CredentialError::Backend(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cm_core::{CredentialId, CredentialPurpose};
    use std::io;
    use std::sync::Once;

    static MOCK_INIT: Once = Once::new();

    fn use_mock_backend() {
        MOCK_INIT.call_once(|| {
            keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        });
    }

    fn key(id: i64) -> CredentialRef {
        CredentialRef::new(CredentialId::new(id), CredentialPurpose::Password)
    }

    #[test]
    fn selected_backend_persists_until_explicit_deletion() {
        use keyring::credential::CredentialPersistence;

        assert!(matches!(
            keyring::secret_service::default_credential_builder().persistence(),
            CredentialPersistence::UntilDelete
        ));
    }

    #[test]
    fn round_trip_overwrite_and_delete() {
        use_mock_backend();
        let store = KeyringStore::new();
        let key = key(91_001);

        store
            .store(&key, &Secret::new(b"first".to_vec()))
            .expect("store");
        store
            .store(&key, &Secret::new(b"second".to_vec()))
            .expect("overwrite");
        assert_eq!(
            store.get(&key).expect("get").expect("present").expose(),
            b"second"
        );
        store.delete(&key).expect("delete");
        assert!(store.get(&key).expect("get after delete").is_none());
        store.delete(&key).expect("idempotent delete");
    }

    #[test]
    fn unavailable_service_error_is_actionable() {
        let error = map_error(keyring::Error::PlatformFailure(Box::new(io::Error::other(
            "D-Bus session unavailable",
        ))));
        let message = error.to_string();
        assert!(message.contains("Linux Secret Service is unavailable"));
        assert!(message.contains("Secret Service provider"));
    }

    #[test]
    fn locked_or_cancelled_error_is_actionable() {
        let error = map_error(keyring::Error::NoStorageAccess(Box::new(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "prompt dismissed",
        ))));
        let message = error.to_string();
        assert!(message.contains("locked or access was denied or cancelled"));
        assert!(message.contains("unlock the desktop credential wallet or keyring"));
    }
}

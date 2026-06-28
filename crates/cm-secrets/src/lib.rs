//! `cm-secrets` — the OS keychain adapter for ConMan.
//!
//! Implements the [`cm_core::CredentialStore`] port over the operating-system
//! keychain via the [`keyring`] crate (Windows Credential Manager / DPAPI,
//! macOS Keychain, Linux Secret Service / `keyutils`).
//!
//! # Key design points
//!
//! * **Account format.** Every keychain entry uses the fixed service name
//!   `"conman"` ([`cm_core::CredentialRef::SERVICE`]) and an account of the
//!   form `"cred:<credential-id>:<purpose>"` (built by
//!   [`cm_core::CredentialRef::new`]).  The format is a contract shared by
//!   this crate and `cm-core`; do not change it without updating both.
//!
//! * **Secrets are never logged.** [`cm_core::Secret`] has a custom
//!   `Debug` / `Display` that emits `"<redacted>"`.  This crate never
//!   formats, prints, or clones the raw bytes for any purpose other than
//!   passing them directly to the OS keychain API.
//!
//! * **Entry cache.** `keyring` 3.x creates a fresh in-memory
//!   [`keyring::mock`] credential on each [`keyring::Entry::new`] call.  To
//!   make deterministic CI tests possible — and to avoid redundant OS
//!   round-trips in the real-backend path — [`KeyringStore`] keeps one
//!   `Arc<keyring::Entry>` per `(service, account)` pair.  All three
//!   operations (`store`, `get`, `delete`) obtain the cached entry before
//!   releasing the internal lock, then execute the keychain I/O lock-free.
//!
//! # Backend selection
//!
//! `keyring` 3.x selects the backend at compile time based on enabled
//! features.  With **no platform features** — which is what this crate's
//! `Cargo.toml` specifies — keyring falls back to its built-in mock backend
//! on every platform.  The `conman` binary (or an integration-test harness)
//! can override this at runtime by calling
//! [`keyring::set_default_credential_builder`] with a platform-specific
//! builder before constructing any [`KeyringStore`] instances.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use cm_core::{CredentialError, CredentialRef, CredentialStore, Secret};

// ---------------------------------------------------------------------------
// KeyringStore
// ---------------------------------------------------------------------------

/// OS-keychain adapter implementing [`CredentialStore`].
///
/// Wraps the [`keyring`] crate, keying secrets by
/// [`CredentialRef`] → `(service, account)`.  An internal entry cache
/// ensures deterministic behaviour under the mock backend and avoids
/// redundant entry construction with real OS backends.
///
/// ## Example
///
/// ```no_run
/// use cm_secrets::KeyringStore;
/// use cm_core::CredentialStore;
///
/// let _store: Box<dyn CredentialStore> = Box::new(KeyringStore::new());
/// ```
pub struct KeyringStore {
    /// Maps `(service, account)` pairs to their [`keyring::Entry`] objects.
    ///
    /// Using `Arc<Entry>` lets us clone a cheap reference out of the cache,
    /// release the mutex, and perform keychain I/O without holding the lock.
    /// This keeps the critical section short and avoids blocking other threads
    /// on potentially slow OS round-trips.
    entries: Mutex<HashMap<(String, String), Arc<keyring::Entry>>>,
}

impl KeyringStore {
    /// Creates a new `KeyringStore` with an empty entry cache.
    ///
    /// Construction never touches the OS keychain; I/O only happens on the
    /// first `store`, `get`, or `delete` call for each key.
    pub fn new() -> Self {
        KeyringStore {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the cached [`Arc<keyring::Entry>`] for `key`, creating and
    /// caching a fresh entry if one does not yet exist.
    ///
    /// The mutex is held only for the HashMap lookup/insert.  Keychain I/O
    /// is performed after releasing the lock.
    fn entry_for(&self, key: &CredentialRef) -> Result<Arc<keyring::Entry>, CredentialError> {
        let cache_key = (key.service().to_owned(), key.account().to_owned());

        let mut guard = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(entry) = guard.get(&cache_key) {
            return Ok(Arc::clone(entry));
        }

        let entry = keyring::Entry::new(key.service(), key.account())
            .map_err(|e| CredentialError::Backend(e.to_string()))?;
        let arc = Arc::new(entry);
        guard.insert(cache_key, Arc::clone(&arc));
        Ok(arc)
    }
}

impl Default for KeyringStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for KeyringStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not expose the entry cache contents; service/account strings are
        // considered sensitive metadata (they encode credential IDs).
        f.debug_struct("KeyringStore").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// CredentialStore impl
// ---------------------------------------------------------------------------

impl CredentialStore for KeyringStore {
    /// Stores `secret` in the OS keychain at the slot identified by `key`.
    ///
    /// Overwrites any existing entry for the same key.  The raw bytes are
    /// passed directly via [`keyring::Entry::set_secret`] and are never
    /// copied into a log, error message, or any auxiliary buffer.
    fn store(&self, key: &CredentialRef, secret: &Secret) -> Result<(), CredentialError> {
        self.entry_for(key)?
            .set_secret(secret.expose())
            .map_err(|e| CredentialError::Backend(e.to_string()))
    }

    /// Returns the secret stored under `key`, or `None` if no entry exists.
    ///
    /// [`keyring::Error::NoEntry`] is normalised to `Ok(None)`.  Every other
    /// keychain error is propagated as [`CredentialError::Backend`].
    fn get(&self, key: &CredentialRef) -> Result<Option<Secret>, CredentialError> {
        match self.entry_for(key)?.get_secret() {
            Ok(bytes) => Ok(Some(Secret::new(bytes))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(CredentialError::Backend(e.to_string())),
        }
    }

    /// Removes the keychain entry for `key`.
    ///
    /// If the entry does not exist this is a no-op (idempotent).  Any other
    /// keychain error is propagated as [`CredentialError::Backend`].
    fn delete(&self, key: &CredentialRef) -> Result<(), CredentialError> {
        match self.entry_for(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(CredentialError::Backend(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cm_core::{CredentialId, CredentialPurpose, CredentialRef, Secret};
    use std::sync::Once;

    /// Switch the process-wide keyring backend to the built-in in-memory mock.
    ///
    /// [`std::sync::Once`] guarantees this runs exactly once even when tests
    /// execute in parallel.  The mock backend is already the compile-time
    /// default on Linux when no platform features are enabled, but we install
    /// it explicitly here for clarity and cross-platform determinism.
    static MOCK_INIT: Once = Once::new();

    fn use_mock_backend() {
        MOCK_INIT.call_once(|| {
            keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        });
    }

    /// Convenience constructor for [`CredentialRef`] in tests.
    fn cred_ref(id: i64, purpose: CredentialPurpose) -> CredentialRef {
        CredentialRef::new(CredentialId::new(id), purpose)
    }

    // -----------------------------------------------------------------------
    // Round-trip tests (mock backend — deterministic in CI)
    // -----------------------------------------------------------------------

    #[test]
    fn round_trip_password() {
        use_mock_backend();
        let store = KeyringStore::new();
        let key = cred_ref(1, CredentialPurpose::Password);
        let secret = Secret::new(b"hunter2".to_vec());

        store.store(&key, &secret).expect("store must succeed");

        let got = store.get(&key).expect("get must succeed");
        assert!(got.is_some(), "secret should be present after store");
        assert_eq!(got.unwrap().expose(), b"hunter2");

        store.delete(&key).expect("delete must succeed");

        let after = store.get(&key).expect("get after delete must succeed");
        assert!(after.is_none(), "secret must be absent after delete");
    }

    #[test]
    fn round_trip_binary_secret() {
        use_mock_backend();
        let store = KeyringStore::new();
        let key = cred_ref(2, CredentialPurpose::SshKey);

        // All 256 byte values — verifies that arbitrary binary material
        // (e.g. raw SSH private-key bytes) survives the round-trip intact.
        let bytes: Vec<u8> = (0u8..=255).collect();
        let secret = Secret::new(bytes.clone());

        store.store(&key, &secret).expect("store must succeed");
        let got = store.get(&key).expect("get must succeed");
        assert_eq!(
            got.expect("must be Some").expose(),
            &bytes[..],
            "binary secret round-trip must be lossless"
        );

        store.delete(&key).expect("cleanup delete");
    }

    #[test]
    fn get_nonexistent_returns_none() {
        use_mock_backend();
        let store = KeyringStore::new();
        // Use a large credential id unlikely to collide with other tests.
        let key = cred_ref(1_000, CredentialPurpose::Password);

        let result = store.get(&key).expect("get on absent key must not error");
        assert!(
            result.is_none(),
            "get on an absent key must return None, not an error"
        );
    }

    #[test]
    fn delete_nonexistent_is_idempotent() {
        use_mock_backend();
        let store = KeyringStore::new();
        let key = cred_ref(2_000, CredentialPurpose::SshPassphrase);

        store
            .delete(&key)
            .expect("delete of nonexistent key must succeed (idempotent)");
    }

    #[test]
    fn overwrite_updates_stored_secret() {
        use_mock_backend();
        let store = KeyringStore::new();
        let key = cred_ref(3, CredentialPurpose::Password);

        store
            .store(&key, &Secret::new(b"first".to_vec()))
            .expect("first store");
        store
            .store(&key, &Secret::new(b"second".to_vec()))
            .expect("second store (overwrite)");

        let got = store.get(&key).expect("get must succeed");
        assert_eq!(
            got.expect("must be Some").expose(),
            b"second",
            "overwrite must replace the previous secret"
        );
        store.delete(&key).expect("cleanup delete");
    }

    #[test]
    fn different_purposes_are_independent_slots() {
        use_mock_backend();
        let store = KeyringStore::new();
        let pw_key = cred_ref(4, CredentialPurpose::Password);
        let sk_key = cred_ref(4, CredentialPurpose::SshKey);

        store
            .store(&pw_key, &Secret::new(b"pass".to_vec()))
            .expect("store password");
        store
            .store(&sk_key, &Secret::new(b"key-bytes".to_vec()))
            .expect("store ssh key");

        assert_eq!(
            store
                .get(&pw_key)
                .expect("get password")
                .expect("must be Some")
                .expose(),
            b"pass"
        );
        assert_eq!(
            store
                .get(&sk_key)
                .expect("get ssh key")
                .expect("must be Some")
                .expose(),
            b"key-bytes"
        );

        store.delete(&pw_key).expect("cleanup");
        store.delete(&sk_key).expect("cleanup");
    }

    // -----------------------------------------------------------------------
    // Secret hygiene — Debug / Display must never expose raw bytes
    // -----------------------------------------------------------------------

    #[test]
    fn secret_debug_is_redacted() {
        let secret = Secret::new(b"super-secret-material".to_vec());
        let dbg = format!("{secret:?}");
        assert!(
            !dbg.contains("super-secret-material"),
            "Secret::fmt(Debug) must not expose bytes; got: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "Secret::fmt(Debug) should print '<redacted>'; got: {dbg}"
        );
    }

    #[test]
    fn secret_display_is_redacted() {
        let secret = Secret::new(b"super-secret-material".to_vec());
        let display = format!("{secret}");
        assert!(
            !display.contains("super-secret-material"),
            "Secret::fmt(Display) must not expose bytes; got: {display}"
        );
        assert!(
            display.contains("<redacted>"),
            "Secret::fmt(Display) should print '<redacted>'; got: {display}"
        );
    }

    #[test]
    fn keyring_store_debug_names_type_only() {
        let store = KeyringStore::new();
        let dbg = format!("{store:?}");
        assert!(
            dbg.contains("KeyringStore"),
            "Debug output must name the type; got: {dbg}"
        );
    }

    // -----------------------------------------------------------------------
    // Trait-object usability
    // -----------------------------------------------------------------------

    #[test]
    fn can_be_used_as_dyn_credential_store() {
        use_mock_backend();
        // Compile-time check: if CredentialStore is not object-safe or
        // KeyringStore does not implement it, this will not compile.
        let store: Box<dyn CredentialStore> = Box::new(KeyringStore::new());
        let key = cred_ref(5, CredentialPurpose::Password);
        let _ = store.get(&key).expect("get via dyn trait must succeed");
    }
}

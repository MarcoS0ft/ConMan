//! `cm-secrets` — the OS keychain adapter for ConMan.
//!
//! Implements the `CredentialStore` port over the operating system keychain
//! (Windows Credential Manager first; macOS Keychain and Linux Secret Service
//! later). Stores, retrieves, and deletes secrets keyed by `CredentialRef`.
//! Secrets are never logged, exported, or written to the store.

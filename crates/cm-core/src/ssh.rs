//! SSH auth-input and host-key-verification contract types.
//!
//! Moved here from `cm-session/src/ssh.rs` — these are pure data/trait
//! definitions with no I/O, needed by the [`crate::session_ports::
//! SessionProvider`] port (which must be nameable from `cm-core`) and
//! implemented by `cm-ui` (`UiHostKeyVerifier`/`UiKbdInteractiveHandler` in
//! `controller/sessions.rs`). `KnownHosts` — the file-backed known-hosts
//! policy engine — is *not* moved: it does real file I/O
//! (`russh::keys::known_hosts::*`), which has no place in `cm-core`'s
//! charter (ARCHITECTURE §1: "no I/O"). It stays in `cm-session::ssh`; the
//! `SessionProvider` adapter constructs it internally so callers never need
//! to know it exists.

use std::sync::Arc;

use crate::credential::Secret;

/// MVP inline authentication input (until `cm-secrets`/profile storage lands in).
/// Secrets are [`Secret`] (zeroizing) and never logged.
///
/// `Clone` is derived so the controller can store a copy for reconnect.
/// `Secret::clone` produces a fresh zeroized-on-drop copy — no hygiene regression.
///
/// `Debug` is hand-written (not derived) because [`Self::KeyboardInteractive`]
/// carries a handler trait object that cannot derive `Debug`; the manual impl
/// also gives every variant the same "never print secret material" guarantee
/// [`Secret`] itself provides.
#[derive(Clone)]
pub enum SshAuthInput {
    /// Password authentication.
    Password(Secret),
    /// Public-key authentication from a key file on disk, with an optional
    /// passphrase (quick-connect: the user types/picks a local path).
    Key {
        path: std::path::PathBuf,
        passphrase: Option<Secret>,
    },
    /// Public-key authentication from key material held in memory (a
    /// stored `Credential`'s private-key text fetched from the keychain —
    /// there is no file on disk to point `Key` at). `key_pem` is the
    /// OpenSSH/PEM-encoded private key text, decoded via
    /// `russh::keys::decode_secret_key` instead of `load_secret_key`
    /// (`cm-session::ssh`).
    KeyMaterial {
        key_pem: Secret,
        passphrase: Option<Secret>,
    },
    /// ssh-agent authentication. Unix: `SSH_AUTH_SOCK`. Windows: the
    /// OpenSSH agent named pipe `\\.\pipe\openssh-ssh-agent`.
    Agent,
    /// Keyboard-interactive authentication: the server drives one or
    /// more challenge/response rounds (e.g. a password prompt, then a TOTP
    /// code); `handler` collects the user's answers for each round. Modeled
    /// on [`HostKeyVerifier`] — a UI prompt flow round-tripped synchronously
    /// from the session's driver thread.
    KeyboardInteractive {
        handler: Arc<dyn KbdInteractiveHandler>,
    },
}

impl std::fmt::Debug for SshAuthInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => f.write_str("Password(<redacted>)"),
            Self::Key { path, .. } => f
                .debug_struct("Key")
                .field("path", path)
                .finish_non_exhaustive(),
            Self::KeyMaterial { .. } => f.write_str("KeyMaterial(<redacted>)"),
            Self::Agent => f.write_str("Agent"),
            Self::KeyboardInteractive { .. } => f.write_str("KeyboardInteractive(<handler>)"),
        }
    }
}

// Keyboard-interactive auth

/// A single keyboard-interactive prompt from the server: the text to show and
/// whether the terminal should echo the typed characters.
#[derive(Debug, Clone)]
pub struct KbdInteractivePrompt {
    pub text: String,
    pub echo: bool,
}

/// One keyboard-interactive challenge round: optional name/instructions text
/// plus the prompts to answer. A server may issue several rounds in sequence
/// (e.g. a password prompt, then a one-time code) before it reports success
/// or failure.
#[derive(Debug, Clone)]
pub struct KbdInteractiveChallenge {
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<KbdInteractivePrompt>,
}

/// Collects the user's answers for one keyboard-interactive challenge round.
///
/// The UI prompt flow is modeled on [`HostKeyVerifier`]: implementations
/// block the calling (session driver) thread while they round-trip through
/// the host UI event loop. Return `None` to abort authentication (e.g. the
/// user dismissed the prompt) or `Some(answers)` with exactly
/// `challenge.prompts.len` entries, in order. Answers are [`Secret`] and
/// must never be logged, `Debug`-formatted, or otherwise stringified outside
/// the auth exchange itself (CONVENTIONS §2).
pub trait KbdInteractiveHandler: Send + Sync {
    fn respond(&self, challenge: &KbdInteractiveChallenge) -> Option<Vec<Secret>>;
}

// Host-key verification

/// Which store a previously-recorded host key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownHostSource {
    /// ConMan's own known-hosts file (writable).
    ConManStore,
    /// The user's OpenSSH `~/.ssh/known_hosts` (consulted read-only).
    UserKnownHosts,
}

/// The situation presented to the verifier for a host key needing a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeySituation {
    /// The host is in neither store.
    Unknown,
    /// The host is known but the presented key differs (possible MITM).
    Mismatch {
        stored_fingerprint: String,
        source: KnownHostSource,
    },
}

/// Details of a host key awaiting a user decision (the prompt UI is).
#[derive(Debug, Clone)]
pub struct HostKeyInfo {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    /// SHA256 fingerprint of the presented key (`SHA256:...`).
    pub fingerprint: String,
    pub situation: HostKeySituation,
}

/// The user's decision for an unknown or mismatched host key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyDecision {
    /// Accept: on `Unknown` store the key in ConMan's store; on `Mismatch`
    /// replace the ConMan store entry. Never touches `~/.ssh/known_hosts`.
    Accept,
    /// Reject and abort the connection.
    Reject,
}

/// Decides whether to trust an unknown/mismatched host key. In this is the
/// prompt UI; in tests it is programmatic (auto-accept / auto-reject).
pub trait HostKeyVerifier: Send + Sync {
    fn decide(&self, info: &HostKeyInfo) -> HostKeyDecision;
}

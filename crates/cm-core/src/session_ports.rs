//! `SessionProvider` port (P6.15, gap 27).
//!
//! Establishes live sessions for the three connection kinds ConMan supports,
//! hiding the concrete adapter types (`LocalTerminalSession`,
//! `SshTerminalSession`, `RdpSession` — all in `cm-session`) behind one
//! object-safe port. `cm-ui` depends on this trait only (never the concrete
//! adapters); the `conman` composition root constructs `cm_session::
//! SessionProviderImpl` and injects it as `Arc<dyn SessionProvider>` —
//! mirrors how `ConnectionRepository`/`CredentialStore` are already injected.
//!
//! Per-transport trust-store persistence the caller previously had to
//! construct itself (SSH's `KnownHosts`, RDP's `CertStore` — both real file
//! I/O, so they stay in `cm-session`, never in `cm-core`) is now the
//! provider's concern: callers no longer need to know either file exists.
//!
//! Reserved-decision writeup (the trait shape, and why the supporting types
//! in [`crate::session`]/[`crate::ssh`]/[`crate::rdp`] had to move here too):
//! `docs/devel/memos/P6.15-sessionprovider-port.md`.

use std::sync::Arc;

use crate::rdp::{CertVerifier, RdpAuthInput};
use crate::session::Session;
use crate::settings::{LocalSettings, RdpSettings, SshSettings, TelnetSettings};
use crate::ssh::{HostKeyVerifier, SshAuthInput};
use crate::terminal::TerminalSize;

/// Uniform, string-only failure returned when a [`SessionProvider`] cannot
/// establish a session synchronously (thread/spawn/connect setup failure —
/// e.g. the PTY couldn't be opened, or an OS thread couldn't be started).
///
/// Protocol/auth/cert failures still surface later via `Session::status()`
/// (`SessionStatus::Failed`), unchanged. Every existing call site only ever
/// called `.to_string()` on the three transport-specific error enums this
/// replaces at the port boundary (`cm_session::{SshError, RdpError,
/// local::SessionError}`), so collapsing them to one `Display`-only type
/// here loses no information any caller used.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SessionSetupError(String);

impl SessionSetupError {
    /// Wrap any error's `Display` output (typically `err.to_string()` on the
    /// adapter's own typed error).
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

/// Establishes a live [`Session`] for a resolved connection config
/// (ARCHITECTURE §3). Object-safe so it can be held as `Arc<dyn
/// SessionProvider>`.
///
/// Keeps the thread-per-session model unchanged: each method returns
/// immediately with a handle in `SessionStatus::Connecting` (SSH/RDP) or
/// `Connected` (local, spawned synchronously) exactly as the concrete
/// constructors did before P6.15 — only the *construction* boundary moved,
/// not the runtime shape.
pub trait SessionProvider: Send + Sync {
    /// Spawn a local shell session.
    fn spawn_local(
        &self,
        settings: &LocalSettings,
        size: TerminalSize,
    ) -> Result<Box<dyn Session>, SessionSetupError>;

    /// Connect an SSH session. `verifier` decides unknown/mismatched host
    /// keys; the provider consults its own known-hosts store internally
    /// (unchanged defaults — see the memo).
    fn connect_ssh(
        &self,
        settings: &SshSettings,
        auth: SshAuthInput,
        verifier: Arc<dyn HostKeyVerifier>,
        size: TerminalSize,
    ) -> Result<Box<dyn Session>, SessionSetupError>;

    /// Connect a Telnet session. Login is performed interactively through
    /// the terminal; there is no authentication or verifier parameter.
    fn connect_telnet(
        &self,
        settings: &TelnetSettings,
        size: TerminalSize,
    ) -> Result<Box<dyn Session>, SessionSetupError>;

    /// Connect an RDP session. `verifier` decides unknown/changed server
    /// certificates; the provider consults its own persistent cert-trust
    /// store internally (unchanged defaults — see the memo).
    fn connect_rdp(
        &self,
        settings: &RdpSettings,
        auth: RdpAuthInput,
        verifier: Arc<dyn CertVerifier>,
    ) -> Result<Box<dyn Session>, SessionSetupError>;
}

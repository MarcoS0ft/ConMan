//! `SessionProvider` port.
//!
//! Establishes live sessions for ConMan's supported connection kinds, hiding
//! the concrete adapter types (`LocalTerminalSession`, `SshTerminalSession`,
//! `TelnetTerminalSession`, `RdpSession` — all in `cm-session`) behind one
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
use std::sync::Arc;

use crate::rdp::{CertVerifier, RdpAuthInput};
use crate::session::{Session, SessionEndpointId};
use crate::settings::{LocalSettings, RdpSettings, SshSettings, TelnetSettings};
use crate::ssh::{HostKeyVerifier, SshAuthInput};
use crate::terminal::TerminalSize;

/// Per-session options shared by terminal-backed transports.
///
/// The options are captured when a Local, SSH, or Telnet session is created,
/// so changing application preferences affects only subsequently-created
/// sessions. RDP does not use a terminal buffer and is intentionally
/// unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalOptions {
    /// Maximum number of history lines exposed above the active screen. Zero
    /// disables retained scrollback. Implementations may additionally impose
    /// a documented memory ceiling, so dense rows can yield fewer lines.
    pub max_scrollback: usize,
}

impl Default for TerminalOptions {
    fn default() -> Self {
        Self {
            max_scrollback: crate::app_settings::DEFAULT_SCROLLBACK_LIMIT,
        }
    }
}

/// Uniform, string-only failure returned when a [`SessionProvider`] cannot
/// establish a session synchronously (thread/spawn/connect setup failure —
/// e.g. the PTY couldn't be opened, or an OS thread couldn't be started).
///
/// Protocol/auth/cert failures still surface later via `Session::status`
/// (`SessionStatus::Failed`), unchanged. Every existing call site only ever
/// called `.to_string` on the three transport-specific error enums this
/// replaces at the port boundary (`cm_session::{SshError, RdpError,
/// local::SessionError}`), so collapsing them to one `Display`-only type
/// here loses no information any caller used.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SessionSetupError(String);

impl SessionSetupError {
    /// Wrap any error's `Display` output (typically `err.to_string` on the
    /// adapter's own typed error).
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

/// Establishes a live [`Session`] for a resolved connection config
/// (ARCHITECTURE §3). Object-safe so it can be held as `Arc<dyn
/// SessionProvider>`.
///
/// Each method returns immediately with a handle in
/// `SessionStatus::Connecting` (SSH/RDP) or `Connected` (local, spawned
/// synchronously), while the thread-per-session model remains unchanged.
pub trait SessionProvider: Send + Sync {
    /// Spawn a local shell session.
    fn spawn_local(
        &self,
        settings: &LocalSettings,
        size: TerminalSize,
        options: TerminalOptions,
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
        options: TerminalOptions,
    ) -> Result<Box<dyn Session>, SessionSetupError>;

    /// Connect a Telnet session. Login is performed interactively through
    /// the terminal; there is no authentication or verifier parameter.
    fn connect_telnet(
        &self,
        settings: &TelnetSettings,
        size: TerminalSize,
        options: TerminalOptions,
    ) -> Result<Box<dyn Session>, SessionSetupError>;

    /// Connect an RDP session. `verifier` decides unknown/changed server
    /// certificates; the provider consults its own persistent cert-trust
    /// store internally (unchanged defaults — see the memo).
    fn connect_rdp(
        &self,
        settings: &RdpSettings,
        auth: RdpAuthInput,
        verifier: Arc<dyn CertVerifier>,
        endpoint_id: SessionEndpointId,
    ) -> Result<Box<dyn Session>, SessionSetupError>;
}

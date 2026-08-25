//! `cm-session` — session orchestration for ConMan.
//!
//! Provides two session families:
//!
//! 1. **Terminal sessions** — local PTY shell ([`LocalTerminalSession`]) and
//!    SSH/TELNET remote terminals ([`SshTerminalSession`],
//!    [`TelnetTerminalSession`]). All implement [`TerminalSession`]
//!    and [`Session`] (ARCHITECTURE §4, P3.x / P4.1). Gated on
//!    `engine-libghostty`.
//!
//! 2. **RDP session** — [`RdpSession`] driven by IronRDP over tokio. Implements
//!    [`Session`] (Framebuffer surface, P4.1). Always available.
//!
//! The libghostty engine requires the zig 0.15.2 toolchain; see
//! `docs/devel/AI_GUIDANCE.md`.

mod pane;
pub use pane::{FocusDir, MAX_PANES, PaneGroup, PaneLayout, PaneRect};

mod session;
pub use session::{
    ExitStatus, FailedSession, FrameUpdate, RdpInputEvent, RdpMouseButton, Session, SessionInput,
    SessionStatus, Surface, TerminalSession,
};

mod rdp;
pub use rdp::{
    CertDecision, CertInfo, CertSituation, CertStore, CertVerifier, FixedCertVerifier,
    KnownCertSource, RdpAuthInput, RdpError, RdpSession,
};

#[cfg(feature = "engine-libghostty")]
mod engine_owner;
#[cfg(feature = "engine-libghostty")]
mod libghostty;
#[cfg(feature = "engine-libghostty")]
mod local;
#[cfg(feature = "engine-libghostty")]
mod ssh;
#[cfg(feature = "engine-libghostty")]
mod telnet;

#[cfg(feature = "engine-libghostty")]
pub use libghostty::{EngineError, LibghosttyEngine};
#[cfg(feature = "engine-libghostty")]
pub use local::{LocalTerminalSession, SessionError};
#[cfg(feature = "engine-libghostty")]
pub use ssh::{
    HostKeyDecision, HostKeyInfo, HostKeySituation, HostKeyVerifier, KbdInteractiveChallenge,
    KbdInteractiveHandler, KbdInteractivePrompt, KnownHostSource, KnownHosts, SshAuthInput,
    SshError, SshTerminalSession,
};
#[cfg(feature = "engine-libghostty")]
pub use telnet::{TelnetError, TelnetTerminalSession};

// P6.15: the `SessionProvider` port adapter needs `LocalTerminalSession`
// (local.rs) and `SshTerminalSession` (ssh.rs), both gated on
// `engine-libghostty` — so the adapter is gated the same way (mirrors the
// existing "zig-free build has no complete session story yet" shape; see
// AI_GUIDANCE.md's `--no-default-features` note).
#[cfg(feature = "engine-libghostty")]
mod provider;
#[cfg(feature = "engine-libghostty")]
pub use provider::SessionProviderImpl;

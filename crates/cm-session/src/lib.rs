//! `cm-session` — session orchestration for ConMan.
//!
//! Provides two session families:
//!
//! 1. **Terminal sessions** — local PTY shell ([`LocalTerminalSession`]) and
//!    SSH shell ([`SshTerminalSession`]). Both implement [`TerminalSession`]
//!    and [`Session`] (ARCHITECTURE §4, P3.x). Gated on `engine-libghostty`.
//!
//! 2. **RDP session** — [`RdpSession`] driven by IronRDP over tokio. Implements
//!    [`Session`] only (Framebuffer surface, P4.1). Always available.
//!
//! The libghostty engine requires the zig 0.15.2 toolchain; see
//! `docs/devel/AI_GUIDANCE.md`.

mod session;
pub use session::{ExitStatus, FrameUpdate, Session, SessionStatus, Surface, TerminalSession};

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
pub use libghostty::{EngineError, LibghosttyEngine};
#[cfg(feature = "engine-libghostty")]
pub use local::{LocalTerminalSession, SessionError};
#[cfg(feature = "engine-libghostty")]
pub use ssh::{
    HostKeyDecision, HostKeyInfo, HostKeySituation, HostKeyVerifier, KnownHostSource, KnownHosts,
    SshAuthInput, SshError, SshTerminalSession,
};

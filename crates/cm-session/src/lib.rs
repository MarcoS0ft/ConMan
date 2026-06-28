//! `cm-session` — session orchestration for ConMan.
//!
//! Provides terminal sessions behind the shared [`TerminalSession`] abstraction:
//! a local PTY shell ([`LocalTerminalSession`]) and an SSH shell
//! ([`SshTerminalSession`]). Both drive the **same** `!Send` VT engine from a
//! dedicated owner thread; only bytes and owned snapshots cross channels
//! (ARCHITECTURE §4).
//!
//! The engine + sessions are behind the `engine-libghostty` feature (default
//! on). Building it requires the zig 0.15.2 toolchain; see
//! `docs/devel/AI_GUIDANCE.md`.

mod session;
pub use session::{ExitStatus, SessionStatus, TerminalSession};

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

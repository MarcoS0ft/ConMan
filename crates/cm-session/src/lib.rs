//! `cm-session` — session orchestration for ConMan.
//!
//! Owns live connections (which outlive tabs) via the `SessionManager` and
//! implements the `SessionProvider` adapters for RDP, SSH, and local shell, the
//! `TerminalEngine` port and its adapters, and the PTY plumbing. Bytes cross
//! channels; protocol state stays on its owning thread.
//!
//! The libghostty-vt VT-engine adapter is behind the `engine-libghostty`
//! feature (default on). Building it requires the zig 0.15.2 toolchain; see
//! `docs/devel/AI_GUIDANCE.md`.

#[cfg(feature = "engine-libghostty")]
mod libghostty;
#[cfg(feature = "engine-libghostty")]
pub use libghostty::{EngineError, LibghosttyEngine};

#[cfg(feature = "engine-libghostty")]
mod local;
#[cfg(feature = "engine-libghostty")]
pub use local::{ExitStatus, LocalTerminalSession, SessionError};

pub const NAME: &str = "cm-session";

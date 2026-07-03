//! Session abstractions for ConMan.
//!
//! **P6.15:** the unified [`Session`] trait and its supporting neutral types
//! (`Surface`, `SessionInput`, `SessionStatus`, `FrameUpdate`, `ExitStatus`,
//! `RdpInputEvent`, `RdpMouseButton`, `FailedSession`) moved to
//! `cm_core::session` — the [`crate::SessionProvider`] port (`cm-core`)
//! returns `Box<dyn Session>`, so the trait has to be nameable from `cm-core`
//! without `cm-core` depending on this crate. Re-exported here so every
//! existing `use crate::session::{...}` import in `ssh.rs`/`rdp.rs`/
//! `local.rs` keeps resolving unchanged. See
//! `docs/devel/memos/P6.15-sessionprovider-port.md`.
//!
//! [`TerminalSession`] (below) is the original terminal-specific trait used
//! by the P3.x UI controller. It stays here — unlike `Session`, it is never
//! named outside `cm-session` (the controller no longer holds it directly
//! after the P4.2 migration), so it has no reason to cross the port
//! boundary.

pub use cm_core::session::{
    ExitStatus, FailedSession, FrameUpdate, RdpInputEvent, RdpMouseButton, Session, SessionInput,
    SessionStatus, Surface,
};

use std::sync::mpsc::Receiver;

use cm_core::terminal::{GridSnapshot, KeyEvent, MouseEvent, TerminalSize};

/// A live terminal session over some byte-stream transport.
///
/// The handle is `Send` (it holds only channels + state); the `!Send` VT engine
/// stays confined to its owner thread — only bytes (in) and owned
/// [`GridSnapshot`]s (out) cross threads (ARCHITECTURE §4). Object-safe so the
/// UI can hold `Box<dyn TerminalSession>` per tab.
///
/// Implementors also implement [`Session`] (unified lifecycle + surface).
pub trait TerminalSession {
    /// Stream of viewport snapshots; drain with `recv`/`try_recv`/`recv_timeout`.
    fn snapshots(&self) -> &Receiver<GridSnapshot>;
    /// Encode a key event and send it to the transport.
    fn send_key(&self, ev: KeyEvent);
    /// Encode a mouse event and send it (subject to the active mouse mode).
    fn send_mouse(&self, ev: MouseEvent);
    /// Write raw pasted bytes to the transport.
    fn paste(&self, bytes: Vec<u8>);
    /// Resize the grid (engine + transport).
    fn resize(&self, size: TerminalSize);
    /// P6.7: set the viewport's scroll offset (lines above the live tail;
    /// `0` = tail/follow — see `cm_session::engine_owner::ScrollState`).
    fn set_scroll(&self, offset: u32);
    /// Current lifecycle state.
    fn status(&self) -> SessionStatus;
    /// Signal shutdown and release the session's resources.
    fn shutdown(&self);
}

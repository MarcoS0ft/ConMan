//! Session abstractions for ConMan.
//!
//! The unified [`Session`] trait and its supporting neutral types live in
//! `cm_core::session` because [`crate::SessionProvider`] returns
//! `Box<dyn Session>` and `cm-core` cannot depend on this crate. They are
//! re-exported here for the transport implementations.
//!
//! [`TerminalSession`] (below) is the terminal-specific trait used by the
//! terminal transports.

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
/// [`GridSnapshot`]s (out) cross threads. Object-safe so the
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
    /// Set the viewport's scroll offset (lines above the live tail;
    /// `0` = tail/follow — see `cm_session::engine_owner::ScrollState`).
    fn set_scroll(&self, offset: u32);
    /// Current lifecycle state.
    fn status(&self) -> SessionStatus;
    /// Signal shutdown and release the session's resources.
    fn shutdown(&self);
}

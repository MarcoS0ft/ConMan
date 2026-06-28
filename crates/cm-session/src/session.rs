//! The shared [`TerminalSession`] abstraction (generalized from the P2.2
//! deferral) that the UI uses uniformly for local and SSH terminals.

use std::sync::mpsc::Receiver;

use cm_core::terminal::{GridSnapshot, KeyEvent, MouseEvent, TerminalSize};

/// The exit status of a session's process (local shell child / remote shell).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    pub success: bool,
    pub code: u32,
}

/// Lifecycle state of a [`TerminalSession`].
///
/// Local sessions start `Connected` (the shell is spawned synchronously); SSH
/// sessions start `Connecting` and transition to `Connected` or
/// `Failed(reason)` as the async handshake/auth completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    /// Establishing the transport (SSH connect/handshake/auth in progress).
    Connecting,
    /// The shell is live; snapshots are flowing.
    Connected,
    /// The transport closed without a reported process exit.
    Disconnected,
    /// The remote/local shell process exited.
    Exited(ExitStatus),
    /// Setup failed; the string is a user-facing reason (never contains secrets).
    Failed(String),
}

/// A live terminal session over some byte-stream transport.
///
/// The handle is `Send` (it holds only channels + state); the `!Send` VT engine
/// stays confined to its owner thread — only bytes (in) and owned
/// [`GridSnapshot`]s (out) cross threads (ARCHITECTURE §4). Object-safe so the
/// UI can hold `Box<dyn TerminalSession>` per tab.
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
    /// Current lifecycle state.
    fn status(&self) -> SessionStatus;
    /// Signal shutdown and release the session's resources.
    fn shutdown(&self);
}

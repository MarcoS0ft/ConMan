//! Session abstractions for ConMan.
//!
//! Provides two related trait families:
//!
//! - **[`TerminalSession`]** — the original terminal-specific trait used by the
//!   P3.x UI controller. Unchanged; `LocalTerminalSession` and
//!   `SshTerminalSession` implement it. The controller continues to hold
//!   `Box<dyn TerminalSession>` until the P4.2 migration.
//!
//! - **[`Session`]** — the unified trait introduced in P4.1. Both terminal and
//!   RDP sessions implement it. The UI controller will migrate to
//!   `Box<dyn Session>` in P4.2.  The surface accessor returns a [`Surface`]
//!   enum that distinguishes a terminal grid channel from an RGBA framebuffer
//!   channel — the pattern established in ARCHITECTURE §4/§5.

use std::sync::mpsc::Receiver;

use cm_core::terminal::{GridSnapshot, KeyEvent, MouseEvent, TerminalSize};

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// The exit status of a session's process (local shell child / remote shell).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    pub success: bool,
    pub code: u32,
}

/// Lifecycle state of a session.
///
/// Local sessions start `Connected` (the shell is spawned synchronously); SSH
/// and RDP sessions start `Connecting` and transition to `Connected` or
/// `Failed(reason)` as the async handshake/auth completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    /// Establishing the transport (connect/handshake/auth in progress).
    Connecting,
    /// The session is live.
    Connected,
    /// The transport closed without a reported process exit.
    Disconnected,
    /// The remote/local shell process exited.
    Exited(ExitStatus),
    /// Setup failed; the string is a user-facing reason (never contains secrets).
    Failed(String),
}

// ---------------------------------------------------------------------------
// Unified Session trait (P4.1)
// ---------------------------------------------------------------------------

/// A decoded RGBA framebuffer frame published by [`crate::RdpSession`].
///
/// Contains the full RGBA buffer at the negotiated resolution; the UI blits
/// the entire buffer into a `slint::Image` (full-frame replacement is fast —
/// ARCHITECTURE §5). Dirty-rect coalescing happens inside the session driver;
/// a single [`FrameUpdate`] per timer tick is the norm.
#[derive(Debug, Clone)]
pub struct FrameUpdate {
    /// Desktop width in pixels.
    pub width: u16,
    /// Desktop height in pixels.
    pub height: u16,
    /// RGBA bytes, row-major, `width × height × 4` bytes total.
    pub rgba: Vec<u8>,
}

/// The rendering surface exposed by a [`Session`].
///
/// - `TerminalGrid` — a channel of terminal cell snapshots (terminal sessions).
/// - `Framebuffer`  — a channel of decoded RGBA frames (RDP sessions).
///
/// The UI inspects this once on session construction and holds the appropriate
/// receiver for the tab's lifetime (ARCHITECTURE §4).
#[allow(clippy::large_enum_variant)]
pub enum Surface {
    /// Terminal sessions: receive [`GridSnapshot`]s for glyph-atlas rendering.
    TerminalGrid(Receiver<GridSnapshot>),
    /// RDP sessions: receive [`FrameUpdate`]s for `slint::Image` blit.
    Framebuffer(Receiver<FrameUpdate>),
}

impl std::fmt::Debug for Surface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TerminalGrid(_) => write!(f, "Surface::TerminalGrid(..)"),
            Self::Framebuffer(_) => write!(f, "Surface::Framebuffer(..)"),
        }
    }
}

/// Unified live-session handle (introduced in P4.1).
///
/// Both terminal and RDP sessions implement this trait. The `cm-ui` controller
/// currently holds `Box<dyn TerminalSession>`; it will migrate to
/// `Box<dyn Session>` in P4.2 (`TerminalSession` is kept intact for that
/// transition). Object-safe.
pub trait Session: Send {
    /// The surface channel for this session — inspect once, keep the receiver.
    fn surface(&self) -> &Surface;
    /// Current lifecycle state.
    fn status(&self) -> SessionStatus;
    /// Signal graceful shutdown and release resources.
    fn shutdown(&self);
    /// Request a desktop resize (pixels for RDP; the terminal adapter converts
    /// to cells via its current font metrics).
    fn resize_px(&self, width: u32, height: u32);
}

// ---------------------------------------------------------------------------
// Terminal-specific trait (P3.x; kept for backward-compat with cm-ui P3.2)
// ---------------------------------------------------------------------------

/// A live terminal session over some byte-stream transport.
///
/// The handle is `Send` (it holds only channels + state); the `!Send` VT engine
/// stays confined to its owner thread — only bytes (in) and owned
/// [`GridSnapshot`]s (out) cross threads (ARCHITECTURE §4). Object-safe so the
/// UI can hold `Box<dyn TerminalSession>` per tab.
///
/// Terminal sessions **also** implement [`Session`]; P4.2 migrates the
/// controller to `Box<dyn Session>`.
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

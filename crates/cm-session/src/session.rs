//! Session abstractions for ConMan.
//!
//! Provides two related trait families:
//!
//! - **[`TerminalSession`]** — the original terminal-specific trait used by
//!   the P3.x UI controller. Kept intact for backward-compat; the controller
//!   no longer holds it directly after the P4.2 migration.
//!
//! - **[`Session`]** — the unified trait (P4.1+). `RdpSession`,
//!   `LocalTerminalSession`, and `SshTerminalSession` all implement it.
//!   The surface accessor returns a [`Surface`] enum distinguishing a terminal
//!   grid channel from an RGBA framebuffer channel (ARCHITECTURE §4/§5).
//!   P4.2 adds `resize_cells` and `send_input` so the controller can drive all
//!   session kinds through `Box<dyn Session>` alone.
//!
//! Neutral input types ([`RdpInputEvent`], [`RdpMouseButton`], [`SessionInput`])
//! live here because they must be shared between the `Session` trait definition
//! and the `rdp` module (which imports them) without creating a circular dep.

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
// Neutral RDP input types (P4.2 — moved here from rdp.rs so SessionInput can
// reference them without a circular dep rdp→session→rdp).
// ---------------------------------------------------------------------------

/// Mouse button identifier for [`RdpInputEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpMouseButton {
    Left,
    Middle,
    Right,
    /// Typically Browser Back.
    X1,
    /// Typically Browser Forward.
    X2,
}

/// Transport-neutral RDP input event.
///
/// Used by [`SessionInput::Rdp`] to send keyboard, mouse, and scroll events to
/// an RDP session via [`Session::send_input`].  The driver converts these to
/// `FastPathInputEvent`s inside `cm-session::rdp` using `ironrdp-input`.
#[derive(Debug, Clone)]
pub enum RdpInputEvent {
    /// Keyboard scancode key-press.
    KeyDown {
        /// PS/2 scancode (0x00–0xFF).
        scancode: u8,
        /// True for extended keys (e.g. right-Ctrl, cursor keys, numpad-/).
        extended: bool,
    },
    /// Keyboard scancode key-release.
    KeyUp { scancode: u8, extended: bool },
    /// Mouse cursor moved to absolute position.
    MouseMove { x: u16, y: u16 },
    /// Mouse button pressed.
    MouseDown {
        button: RdpMouseButton,
        x: u16,
        y: u16,
    },
    /// Mouse button released.
    MouseUp {
        button: RdpMouseButton,
        x: u16,
        y: u16,
    },
    /// Mouse wheel rotation.
    Scroll {
        /// Positive = scroll up / away from user; negative = scroll down.
        delta: i16,
        /// True for vertical scroll (the common case), false for horizontal.
        vertical: bool,
        x: u16,
        y: u16,
    },
}

// ---------------------------------------------------------------------------
// Transport-neutral session input (P4.2)
// ---------------------------------------------------------------------------

/// Transport-neutral input event sent to any session via [`Session::send_input`].
///
/// Each session implementation handles the variants it understands and silently
/// ignores the rest (terminal sessions ignore `Rdp*`; RDP sessions ignore
/// `Key`/`Mouse`/`Paste`).
#[derive(Debug, Clone)]
pub enum SessionInput {
    /// Terminal key event.
    Key(KeyEvent),
    /// Terminal mouse event.
    Mouse(MouseEvent),
    /// Paste raw bytes into the terminal (e.g. clipboard paste via bracketed-paste).
    Paste(Vec<u8>),
    /// RDP input events (keyboard / mouse / scroll).
    Rdp(Vec<RdpInputEvent>),
    /// Paste text into the RDP session via the CLIPRDR channel.
    RdpPaste(String),
}

// ---------------------------------------------------------------------------
// Unified Session trait (P4.1+P4.2)
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

impl Surface {
    /// Return the terminal grid receiver if this is `TerminalGrid`.
    pub fn as_terminal_grid(&self) -> Option<&Receiver<GridSnapshot>> {
        match self {
            Self::TerminalGrid(rx) => Some(rx),
            Self::Framebuffer(_) => None,
        }
    }

    /// Return the framebuffer receiver if this is `Framebuffer`.
    pub fn as_framebuffer(&self) -> Option<&Receiver<FrameUpdate>> {
        match self {
            Self::Framebuffer(rx) => Some(rx),
            Self::TerminalGrid(_) => None,
        }
    }
}

impl std::fmt::Debug for Surface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TerminalGrid(_) => write!(f, "Surface::TerminalGrid(..)"),
            Self::Framebuffer(_) => write!(f, "Surface::Framebuffer(..)"),
        }
    }
}

/// Unified live-session handle (P4.1+P4.2).
///
/// `RdpSession`, `LocalTerminalSession`, and `SshTerminalSession` all implement
/// this trait. The `cm-ui` controller holds `Box<dyn Session>` per tab after
/// the P4.2 migration.  Object-safe.
pub trait Session: Send {
    /// The surface channel for this session — inspect once, keep the receiver.
    fn surface(&self) -> &Surface;
    /// Current lifecycle state.
    fn status(&self) -> SessionStatus;
    /// Signal graceful shutdown and release resources.
    fn shutdown(&self);
    /// Request a desktop resize in pixels.
    ///
    /// For RDP sessions this sends a Display Control PDU. Terminal session
    /// impls convert to cell dimensions (approximate or exact). See also
    /// `resize_cells` for cell-level precision.
    fn resize_px(&self, width: u32, height: u32);

    // ── P4.2 additions ────────────────────────────────────────────────────────

    /// Resize by cell grid dimensions (terminal sessions; no-op for RDP).
    ///
    /// Preferred for terminal sessions where the UI has precise font metrics.
    /// RDP sessions use [`resize_px`] instead.
    fn resize_cells(&self, _cols: u16, _rows: u16) {}

    /// Send transport-neutral input to the session.
    ///
    /// Each implementor handles the variants it supports and silently ignores
    /// the rest. Default: no-op.
    fn send_input(&self, _input: SessionInput) {}
}

// ---------------------------------------------------------------------------
// Terminal-specific trait (P3.x; kept for backward-compat)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// FailedSession (P5.3 carry-over fix b)
// ---------------------------------------------------------------------------

/// A sentinel [`Session`] that immediately reports `Failed`.
///
/// Used when a synchronous connection error prevents spawning a real session
/// thread — the UI receives a proper tab with an error overlay rather than
/// a silent `eprintln!` (carry-over fix b).
///
/// The surface channel is a permanently-closed `Receiver<GridSnapshot>`:
/// the tick loop will drain nothing and the tab is auto-closed after the
/// user dismisses the error overlay.
#[derive(Debug)]
pub struct FailedSession {
    reason: String,
    surface: Surface,
}

impl FailedSession {
    /// Create a session that always reports `Failed(reason)`.
    pub fn new(reason: impl Into<String>) -> Self {
        let (_tx, rx) = std::sync::mpsc::channel::<GridSnapshot>();
        // `_tx` is dropped immediately — the receiver will return `Err` on any
        // recv call, which is exactly what a permanently-closed channel does.
        Self {
            reason: reason.into(),
            surface: Surface::TerminalGrid(rx),
        }
    }
}

impl Session for FailedSession {
    fn surface(&self) -> &Surface {
        &self.surface
    }

    fn status(&self) -> SessionStatus {
        SessionStatus::Failed(self.reason.clone())
    }

    fn shutdown(&self) {}
    fn resize_px(&self, _width: u32, _height: u32) {}
    fn resize_cells(&self, _cols: u16, _rows: u16) {}
    fn send_input(&self, _input: SessionInput) {}
}

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
    /// Current lifecycle state.
    fn status(&self) -> SessionStatus;
    /// Signal shutdown and release the session's resources.
    fn shutdown(&self);
}

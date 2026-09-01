//! Session lifecycle port types.
//!
//! Moved here from `cm-session/src/session.rs` so the [`SessionProvider`]
//! port (`cm_core::session_ports`) can return a value `cm-ui` uses
//! polymorphically without depending on the concrete `cm-session` adapter
//! crate.
//!
//! `cm-session`'s `RdpSession`/`LocalTerminalSession`/`SshTerminalSession`
//! all implement [`Session`]; `cm-session::session` re-exports everything in
//! this module so existing `use crate::session::{...}` imports there keep
//! resolving unchanged. The `TerminalSession` trait (the older, terminal-only
//! trait predating the unified `Session`) is *not* moved — it is
//! `cm-session`-internal only (never named by `cm-ui`).
//!
//! [`SessionProvider`]: crate::session_ports::SessionProvider

use std::sync::mpsc::{Receiver, Sender};

use std::path::PathBuf;

use crate::terminal::{GridSnapshot, KeyEvent, MouseEvent};

// Shared types

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

// Neutral RDP input types live here so SessionInput can
// reference them without a circular dep rdp→session→rdp; — moved again,
// cm-session → cm-core, so the SessionProvider port can return a Session
// trait object without cm-core depending on cm-session).

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
/// an RDP session via [`Session::send_input`]. The driver converts these to
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

// Transport-neutral session input

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
    /// set the terminal viewport's scroll offset (lines above the live
    /// tail; `0` = tail/follow). Terminal sessions only — RDP ignores it.
    Scroll(u32),
    /// RDP input events (keyboard / mouse / scroll).
    Rdp(Vec<RdpInputEvent>),
    /// Drive the RDP clipboard channel independently from keyboard input.
    RdpClipboard(RdpClipboardCommand),
}

/// Process-local identity assigned by the UI before a session is constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionEndpointId(pub u64);

/// Monotonic revision of clipboard content observed on the ConMan host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalClipboardRevision(pub u64);

/// Monotonic revision of clipboard content announced by one live RDP backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemoteClipboardRevision(pub u64);

/// Clipboard content supported by the RDP bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardSnapshot {
    Empty,
    Text(String),
    Files(Vec<PathBuf>),
}

/// Commands sent to an RDP session's CLIPRDR driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdpClipboardCommand {
    SetActive(bool),
    PublishLocal {
        revision: LocalClipboardRevision,
        snapshot: ClipboardSnapshot,
    },
}

/// Result of advertising one local clipboard revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardPublishResult {
    Advertised,
    Rejected,
}

/// Remote clipboard content materialized by an RDP backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteClipboardContent {
    Text(String),
    Files {
        staging_root: PathBuf,
        paths: Vec<PathBuf>,
    },
}

/// Events drained by the UI from an RDP session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdpClipboardEvent {
    LocalAdvertiseResult {
        revision: LocalClipboardRevision,
        result: ClipboardPublishResult,
    },
    RemoteContent {
        revision: RemoteClipboardRevision,
        content: RemoteClipboardContent,
    },
}

// Unified Session trait (+)

/// A decoded RGBA framebuffer frame published by `cm_session::RdpSession`.
///
/// Contains the full RGBA buffer at the negotiated resolution; the UI blits
/// the entire buffer into a `slint::Image` (full-frame replacement is fast —
/// Dirty-rect coalescing happens inside the session driver;
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
/// - `Framebuffer` — a channel of decoded RGBA frames (RDP sessions).
///
/// The UI inspects this once on session construction and holds the appropriate
/// receiver for the tab's lifetime.
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

/// Unified live-session handle (+; port-ified in).
///
/// `cm_session::{RdpSession, LocalTerminalSession, SshTerminalSession}` all
/// implement this trait. The `cm-ui` controller holds `Box<dyn Session>` per
/// tab, obtained from a [`crate::session_ports::SessionProvider`] rather than
/// naming the concrete adapters directly. Object-safe.
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

    // ── additions ────────────────────────────────────────────────────────

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

    // ── addition ────────────────────────────────────────────────────────

    /// Request the full retained buffer as plain-text lines (search) be sent
    /// to `reply`, asynchronously — the caller polls `reply` rather than
    /// blocking on it (the read can be expensive for large scrollback; see
    /// `cm_core::terminal::TerminalEngine::buffer_text`). Terminal sessions
    /// forward this to their engine-owner thread; RDP and other non-terminal
    /// sessions inherit this default no-op (the reply sender is simply
    /// dropped, so the caller's receiver just never resolves).
    fn request_search_text(&self, _reply: Sender<Vec<String>>) {}

    /// Drain clipboard events. Non-RDP sessions have no clipboard channel.
    fn drain_rdp_clipboard_events(&self) -> Vec<RdpClipboardEvent> {
        Vec::new()
    }
}

// FailedSession

/// A sentinel [`Session`] that immediately reports `Failed`.
///
/// Used when a synchronous connection error prevents spawning a real session
/// thread — the UI receives a proper tab with an error overlay rather than
/// a silent `eprintln!` .
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

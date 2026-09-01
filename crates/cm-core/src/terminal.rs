//! Terminal-engine port and the runtime value types it exchanges.
//!
//! These types are **runtime-only** (never persisted), so — unlike the domain
//! entities — they carry no `serde` derives. They are the contract between
//! three layers: the session layer drives [`TerminalEngine::feed`] /
//! [`TerminalEngine::resize`], the engine adapter (libghostty-vt, in
//! `cm-session`) maintains VT state, and the renderer (`cm-ui`) consumes
//! the [`GridSnapshot`].
//!
//! `cm-core` stays free of any engine dependency: only the trait and the value
//! types live here.
//!
//! The snapshot is the **visible viewport**, including scrollback, selection,
//! and search through the caller-supplied offset.

use std::ops::{BitOr, BitOrAssign};

/// Terminal grid dimensions, in character cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    pub rows: u16,
    pub cols: u16,
}

impl TerminalSize {
    /// Total cell count (`rows * cols`) as `usize`.
    #[must_use]
    pub fn cell_count(self) -> usize {
        usize::from(self.rows) * usize::from(self.cols)
    }
}

/// A cell color. `Default` means "use the theme's default fg/bg"; the concrete
/// RGB for `Default`/`Palette` is resolved by the renderer against the active
/// palette/theme, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    /// The themed default foreground/background.
    Default,
    /// An index into the 256-color palette.
    Palette(u8),
    /// A direct truecolor value.
    Rgb { r: u8, g: u8, b: u8 },
}

/// Visual attributes of a cell, as a compact bitfield.
///
/// A plain `u16` bitfield (rather than a `bitflags` dependency) keeps `cm-core`
/// dependency-free. `overline` and the various non-single underline styles
/// (double/curly/dotted/dashed) that some VT engines expose are intentionally
/// **not** represented — our surface is minimal; underline collapses to a
/// single boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CellAttrs(u16);

impl CellAttrs {
    pub const BOLD: Self = Self(1 << 0);
    pub const DIM: Self = Self(1 << 1);
    pub const ITALIC: Self = Self(1 << 2);
    pub const UNDERLINE: Self = Self(1 << 3);
    pub const BLINK: Self = Self(1 << 4);
    pub const REVERSE: Self = Self(1 << 5);
    pub const HIDDEN: Self = Self(1 << 6);
    pub const STRIKETHROUGH: Self = Self(1 << 7);

    /// No attributes set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Raw bits (for renderers that prefer a mask).
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether every bit in `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Set the bits in `other`.
    pub const fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    #[must_use]
    pub const fn bold(self) -> bool {
        self.contains(Self::BOLD)
    }
    #[must_use]
    pub const fn dim(self) -> bool {
        self.contains(Self::DIM)
    }
    #[must_use]
    pub const fn italic(self) -> bool {
        self.contains(Self::ITALIC)
    }
    #[must_use]
    pub const fn underline(self) -> bool {
        self.contains(Self::UNDERLINE)
    }
    #[must_use]
    pub const fn blink(self) -> bool {
        self.contains(Self::BLINK)
    }
    #[must_use]
    pub const fn reverse(self) -> bool {
        self.contains(Self::REVERSE)
    }
    #[must_use]
    pub const fn hidden(self) -> bool {
        self.contains(Self::HIDDEN)
    }
    #[must_use]
    pub const fn strikethrough(self) -> bool {
        self.contains(Self::STRIKETHROUGH)
    }
}

impl BitOr for CellAttrs {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for CellAttrs {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// A single grid cell.
///
/// `grapheme` is a [`String`] for simplicity and zero `cm-core` dependencies;
/// most cells hold a single character. If per-cell allocation ever shows up in
/// renderer profiles, this is a localized swap to an inline/compact string type
/// behind the same field — callers read it as `&str`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    /// The cell's grapheme cluster. Empty string for a blank cell, and for the
    /// spacer cell that follows a wide cell (see `width`).
    pub grapheme: String,
    pub fg: Color,
    pub bg: Color,
    pub attrs: CellAttrs,
    /// Display width in cells: `1` = normal, `2` = wide (e.g. CJK). The cell
    /// immediately after a width-2 cell is a spacer (empty grapheme, width 1)
    /// and must not be drawn.
    pub width: u8,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            grapheme: String::new(),
            fg: Color::Default,
            bg: Color::Default,
            attrs: CellAttrs::empty(),
            width: 1,
        }
    }
}

/// Cursor shape (DECSCUSR). Defaults to [`CursorShape::Block`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CursorShape {
    #[default]
    Block,
    Underline,
    Bar,
}

/// The cursor's position and presentation within the viewport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorState {
    pub row: u16,
    pub col: u16,
    pub visible: bool,
    pub shape: CursorShape,
}

/// An owned snapshot of a **viewport window** into the engine's grid, for
/// rendering.
///
/// Row-major: `cells[row * size.cols + col]`, with `cells.len == size.rows *
/// size.cols`. This type is deliberately `Send` (it owns only plain data and
/// `String`s): it crosses from the engine-owner thread to the renderer/UI
/// bridge, while the engine itself — being `!Send` — never moves.
///
/// The window need not be the live tail. [`TerminalEngine::snapshot`] takes a
/// `scroll_offset` (lines above the tail) and echoes back the resolved
/// position via `scroll_offset`/`scrollback_len`, so callers can render a
/// scroll-position indicator and address absolute buffer lines
/// (`scrollback_len - scroll_offset + row`) without a second round trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GridSnapshot {
    pub size: TerminalSize,
    pub cells: Vec<Cell>,
    pub cursor: CursorState,
    /// Lines of scrollback currently retained above the live tail, independent
    /// of `scroll_offset` (i.e. how far back the user *could* scroll right now).
    pub scrollback_len: u32,
    /// The scroll offset actually used to produce this snapshot (lines above
    /// the tail; `0` = the live/tail view). Always `<= scrollback_len` —
    /// implementations clamp rather than erroring on an out-of-range request.
    pub scroll_offset: u32,
    /// Whether the application has enabled a mouse-tracking mode (DECSET
    /// 1000/1002/1003 and friends). `cm-ui`'s wheel handler uses this to
    /// decide whether a wheel notch should scroll *our* scrollback viewport
    /// (tracking off — the common case) or be forwarded to the app as a
    /// wheel-button mouse event (tracking on — e.g. `less`/`vim`/`htop`).
    pub mouse_tracking: bool,
}

/// Keyboard modifier state accompanying a [`KeyEvent`]/[`MouseEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyModifiers {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    /// The platform "super" key (Windows / Command).
    pub sup: bool,
}

/// A logical key. `Char` carries the layout-resolved character; the named
/// variants are the non-text keys the engine encodes specially.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Enter,
    Tab,
    Backspace,
    Escape,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    Delete,
    /// A function key, `1`-based (`F(1)` = F1).
    F(u8),
}

/// A key press to be encoded into a terminal byte sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    pub key: Key,
    pub mods: KeyModifiers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
    ScrollUp,
    ScrollDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseAction {
    Press,
    Release,
    Move,
}

/// A mouse event in **cell coordinates** (not pixels). The engine converts to
/// whatever wire format the application has enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseEvent {
    pub button: MouseButton,
    pub action: MouseAction,
    pub row: u16,
    pub col: u16,
    pub mods: KeyModifiers,
}

/// A VT engine: consumes a byte stream, maintains grid/cursor state, emits an
/// owned renderable [`GridSnapshot`], and encodes input events to bytes.
///
/// Object-safe — held as `Box<dyn TerminalEngine>`.
///
/// **Not `Send`/`Sync` by contract.** The primary implementation
/// (libghostty-vt) is `!Send + !Sync`, so an engine is owned by a single thread
/// for its whole life. Only bytes (in) and [`GridSnapshot`]/encoded bytes (out)
/// cross threads — never the engine itself. Do not add a `: Send` bound.
pub trait TerminalEngine {
    /// Feed raw VT bytes (from a PTY/SSH stream). Never panics on malformed
    /// input — the engine parses defensively and fails soft.
    fn feed(&mut self, bytes: &[u8]);

    /// Resize the grid to `size`.
    fn resize(&mut self, size: TerminalSize);

    /// Produce an owned snapshot of the viewport starting `scroll_offset`
    /// lines above the live tail (`0` = the tail — the earlier sole
    /// behavior). Implementations **clamp** `scroll_offset` to the available
    /// scrollback (never error on an out-of-range request;
    /// untrusted/derived input fails soft); the clamped value actually used
    /// is echoed back via [`GridSnapshot::scroll_offset`].
    fn snapshot(&self, scroll_offset: u32) -> GridSnapshot;

    /// Lines of scrollback currently retained above the live tail. Cheap —
    /// does not build a snapshot — so callers (the engine-owner loop) can
    /// clamp/derive scroll positions without paying for a full grid read on
    /// every byte chunk. Default `0` for an engine with no scrollback.
    fn scrollback_len(&self) -> u32 {
        0
    }

    /// Plain-text rows spanning the full retained buffer (scrollback +
    /// active screen), oldest first, for whole-buffer search. Row `i`
    /// is `i` lines above the buffer's origin — the same address space as
    /// `GridSnapshot::scrollback_len`/`scroll_offset` (`scrollback_len -
    /// scroll_offset` is the absolute row of the snapshot's first visible
    /// row). Trailing blank cells per line are trimmed. Reading the full
    /// buffer can be expensive for a large scrollback, so callers should call
    /// this only on an explicit search action, not on every keystroke.
    /// Default: empty (no scrollback / not implemented).
    fn buffer_text(&self) -> Vec<String> {
        Vec::new()
    }

    /// Encode a key event into bytes, honoring active terminal modes (e.g.
    /// application-cursor mode).
    fn encode_key(&self, ev: &KeyEvent) -> Vec<u8>;

    /// Encode a mouse event into bytes per the active mouse-tracking mode and
    /// format. Returns empty when no mouse mode is enabled.
    fn encode_mouse(&self, ev: &MouseEvent) -> Vec<u8>;

    /// Whether the application has enabled bracketed paste (DECSET 2004).
    /// `cm_session::engine_owner`'s `Msg::Paste` handler consults this to
    /// decide whether to wrap pasted bytes in the `ESC[200~`/`ESC[201~`
    /// markers or send them raw. Defaults to `false` (raw paste), so
    /// adding this method is non-breaking for any engine that doesn't track
    /// the mode — see.
    fn bracketed_paste_enabled(&self) -> bool {
        false
    }

    /// Drain any bytes the engine needs to write *back* to the PTY in reply to
    /// host queries it processed during [`feed`](Self::feed) — e.g. a DSR
    /// cursor-position report (`CSI 6 n`) or device attributes (`CSI c`). The
    /// caller must forward these to the PTY. On Windows this is essential: the
    /// ConPTY/conhost host issues `CSI 6 n` at startup and **stalls ~3 s**
    /// waiting for the reply before emitting the shell prompt (/B7). The
    /// default returns empty for engines that never produce replies.
    fn take_responses(&mut self) -> Vec<u8> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn assert_send<T: Send>() {}

    #[test]
    fn grid_snapshot_is_send() {
        // The renderer bridge requires this; the engine itself is not Send.
        assert_send::<GridSnapshot>();
    }

    #[test]
    fn cell_attrs_bitfield() {
        let mut a = CellAttrs::BOLD | CellAttrs::ITALIC;
        assert!(a.bold() && a.italic());
        assert!(!a.underline());
        a |= CellAttrs::UNDERLINE;
        assert!(a.contains(CellAttrs::UNDERLINE));
        assert!(a.contains(CellAttrs::BOLD | CellAttrs::ITALIC | CellAttrs::UNDERLINE));
        assert_eq!(CellAttrs::empty().bits(), 0);
    }

    #[test]
    fn default_cell_is_blank() {
        let c = Cell::default();
        assert!(c.grapheme.is_empty());
        assert_eq!(c.width, 1);
        assert_eq!(c.fg, Color::Default);
    }
}

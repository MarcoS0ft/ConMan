//! libghostty-vt adapter for the [`cm_core::TerminalEngine`] port.
//!
//! Wraps libghostty-vt's `Terminal` plus its key/mouse encoders, mapping
//! between our minimal [`cm_core::terminal`] value types and libghostty's FFI
//! types. No `unsafe` here — the safe `libghostty-vt` wrapper is used
//! throughout.
//!
//! Threading: like the underlying `Terminal`, [`LibghosttyEngine`] is
//! `!Send + !Sync` (it holds an FFI pointer). It is owned by a single thread;
//! only bytes and [`GridSnapshot`]s cross thread boundaries (ARCHITECTURE §4,
//! validated in P0.2).
//!
//! Build note: this adapter is compiled from Ghostty source via zig **0.15.2**
//! (not 0.16.0). On Windows debug builds set
//! `LIBGHOSTTY_VT_SYS_OPTIMIZE=ReleaseSafe` to avoid a Debug-mode crash. See
//! `docs/devel/AI_GUIDANCE.md` and the P0.2 verdict memo.

use std::cell::RefCell;
use std::rc::Rc;

use cm_core::terminal::{
    Cell, CellAttrs, Color, CursorShape, CursorState, GridSnapshot, Key, KeyEvent, KeyModifiers,
    MouseAction, MouseButton, MouseEvent, TerminalEngine, TerminalSize,
};
use libghostty_vt::screen::CellWide;
use libghostty_vt::style::{Style as VtStyle, StyleColor, Underline};
use libghostty_vt::terminal::{Mode, Options, Point, PointCoordinate, Terminal};
use libghostty_vt::{key, mouse};

/// Scrollback retained by the engine, in lines. Exposed for viewport-offset
/// rendering and whole-buffer search since P6.7 (`TerminalEngine::snapshot`'s
/// `scroll_offset` param, `scrollback_len`, `buffer_text`).
const DEFAULT_MAX_SCROLLBACK: usize = 10_000;

/// Nominal cell pixel size used for `resize` (libghostty wants pixel metrics
/// for in-band size reports). The renderer supplies real metrics in P2.3; until
/// then these placeholders only affect pixel-coordinate reporting.
const NOMINAL_CELL_PX_W: u32 = 8;
const NOMINAL_CELL_PX_H: u32 = 16;

/// Grapheme-cluster scratch buffer length. 16 codepoints comfortably covers a
/// base char plus combining marks / ZWJ emoji sequences.
const GRAPHEME_BUF_LEN: usize = 16;

/// Errors constructing a [`LibghosttyEngine`].
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// libghostty-vt failed to allocate/initialize the terminal.
    #[error("libghostty-vt terminal init failed: {0}")]
    Init(String),
}

/// A [`TerminalEngine`] backed by libghostty-vt.
#[derive(Debug)]
pub struct LibghosttyEngine {
    term: Terminal<'static, 'static>,
    size: TerminalSize,
    /// Bytes the terminal wants written back to the PTY (replies to host
    /// queries such as DSR/`CSI 6 n`). Filled by the `on_pty_write` callback
    /// during `feed`; drained by [`take_responses`](TerminalEngine::take_responses).
    /// Shared (`Rc`) because the callback and the engine both reference it; both
    /// stay on the single owner thread, so `!Send` is fine.
    responses: Rc<RefCell<Vec<u8>>>,
}

impl LibghosttyEngine {
    /// Create an engine with the given initial grid size.
    ///
    /// # Errors
    /// Returns [`EngineError::Init`] if libghostty-vt cannot allocate the
    /// terminal (e.g. zero-sized grid or out of memory).
    pub fn new(size: TerminalSize) -> Result<Self, EngineError> {
        let mut term = Terminal::new(Options {
            cols: size.cols,
            rows: size.rows,
            max_scrollback: DEFAULT_MAX_SCROLLBACK,
        })
        .map_err(|e| EngineError::Init(format!("{e:?}")))?;

        // Capture the terminal's PTY-write replies (e.g. the DSR cursor-position
        // report) so the session can forward them to the PTY. Required on Windows:
        // ConPTY queries `CSI 6 n` at startup and stalls ~3 s if unanswered (B7).
        let responses = Rc::new(RefCell::new(Vec::new()));
        let sink = responses.clone();
        term.on_pty_write(move |_term, data: &[u8]| {
            sink.borrow_mut().extend_from_slice(data);
        })
        .map_err(|e| EngineError::Init(format!("on_pty_write: {e:?}")))?;

        Ok(Self {
            term,
            size,
            responses,
        })
    }

    /// Read one cell at `point` (P6.7: generalized from the P2.1
    /// `Point::Active`-only form so [`snapshot`](TerminalEngine::snapshot) can
    /// address `Point::Screen` rows for a scrolled-back view too).
    fn read_cell(&self, point: Point) -> Cell {
        let Ok(grid) = self.term.grid_ref(point) else {
            return Cell::default();
        };

        let mut buf = ['\0'; GRAPHEME_BUF_LEN];
        let grapheme = match grid.graphemes(&mut buf) {
            Ok(n) => buf[..n].iter().collect::<String>(),
            Err(_) => String::new(),
        };

        let width = match grid.cell().and_then(libghostty_vt::screen::Cell::wide) {
            Ok(CellWide::Wide) => 2,
            // Narrow + both spacer kinds render as a single (often empty) cell.
            _ => 1,
        };

        let (fg, bg, attrs) = grid.style().map(map_style).unwrap_or((
            Color::Default,
            Color::Default,
            CellAttrs::empty(),
        ));

        Cell {
            grapheme,
            fg,
            bg,
            attrs,
            width,
        }
    }

    fn try_encode_key(&self, ev: &KeyEvent) -> Result<Vec<u8>, libghostty_vt::Error> {
        let mut encoder = key::Encoder::new()?;
        // Honor active terminal modes (application-cursor, keypad, etc.).
        encoder.set_options_from_terminal(&self.term);

        let mut event = key::Event::new()?;
        event.set_action(key::Action::Press);

        let (gkey, text, unshifted) = map_key(ev.key, ev.mods);
        event.set_key(gkey);
        if let Some(cp) = unshifted {
            event.set_unshifted_codepoint(cp);
        }
        event.set_mods(map_mods(ev.mods));
        if let Some(t) = text {
            event.set_utf8(Some(t));
        }

        let mut out = Vec::new();
        encoder.encode_to_vec(&event, &mut out)?;
        Ok(out)
    }

    fn try_encode_mouse(&self, ev: &MouseEvent) -> Result<Vec<u8>, libghostty_vt::Error> {
        let mut encoder = mouse::Encoder::new()?;
        // Inherit the active tracking mode + wire format from the terminal.
        encoder.set_options_from_terminal(&self.term);
        // 1x1 px cells make surface-space positions equal to cell indices, so
        // cell-based formats (X10/normal/SGR) encode the right column/row.
        encoder.set_size(mouse::EncoderSize {
            screen_width: u32::from(self.size.cols),
            screen_height: u32::from(self.size.rows),
            cell_width: 1,
            cell_height: 1,
            padding_top: 0,
            padding_bottom: 0,
            padding_right: 0,
            padding_left: 0,
        });

        let mut event = mouse::Event::new()?;
        event.set_action(map_mouse_action(ev.action));
        event.set_button(Some(map_mouse_button(ev.button)));
        event.set_mods(map_mods(ev.mods));
        event.set_position(mouse::Position {
            x: f32::from(ev.col) + 0.5,
            y: f32::from(ev.row) + 0.5,
        });

        let mut out = Vec::new();
        encoder.encode_to_vec(&event, &mut out)?;
        Ok(out)
    }
}

impl TerminalEngine for LibghosttyEngine {
    fn feed(&mut self, bytes: &[u8]) {
        // vt_write never fails and never panics on malformed input.
        self.term.vt_write(bytes);
    }

    fn resize(&mut self, size: TerminalSize) {
        if self
            .term
            .resize(size.cols, size.rows, NOMINAL_CELL_PX_W, NOMINAL_CELL_PX_H)
            .is_ok()
        {
            self.size = size;
        }
    }

    fn snapshot(&self, scroll_offset: u32) -> GridSnapshot {
        let scrollback_len = self.scrollback_len();
        let offset = scroll_offset.min(scrollback_len);

        let mut cells = Vec::with_capacity(self.size.cell_count());
        if offset == 0 {
            // Live tail: identical to the pre-P6.7 `Point::Active` reads, kept
            // as its own branch so the well-exercised P2.1 behavior/tests are
            // untouched when nobody has scrolled.
            for y in 0..self.size.rows {
                for x in 0..self.size.cols {
                    cells.push(
                        self.read_cell(Point::Active(PointCoordinate { x, y: u32::from(y) })),
                    );
                }
            }
        } else {
            // Scrolled back: address the full screen (scrollback + active).
            // `top` is the absolute row (oldest-first) of the viewport's first
            // visible row; `total_rows` already accounts for scrollback +
            // the active region, so this is exactly `scrollback_len - offset`.
            let total_rows = u32::try_from(self.term.total_rows().unwrap_or(0)).unwrap_or(0);
            let top = total_rows
                .saturating_sub(u32::from(self.size.rows))
                .saturating_sub(offset);
            for y in 0..self.size.rows {
                for x in 0..self.size.cols {
                    cells.push(self.read_cell(Point::Screen(PointCoordinate {
                        x,
                        y: top + u32::from(y),
                    })));
                }
            }
        }

        let cursor = CursorState {
            row: self.term.cursor_y().unwrap_or(0),
            col: self.term.cursor_x().unwrap_or(0),
            // The active-area cursor is off-screen whenever the viewport is
            // scrolled back; DECTCEM visibility only matters at the tail.
            visible: offset == 0 && self.term.is_cursor_visible().unwrap_or(true),
            // DECSCUSR cursor shape is exposed via libghostty's render-state
            // API, wired with the renderer in P2.3; default to Block for now.
            shape: CursorShape::Block,
        };

        GridSnapshot {
            size: self.size,
            cells,
            cursor,
            scrollback_len,
            scroll_offset: offset,
            mouse_tracking: self.term.is_mouse_tracking().unwrap_or(false),
        }
    }

    fn scrollback_len(&self) -> u32 {
        u32::try_from(self.term.scrollback_rows().unwrap_or(0)).unwrap_or(u32::MAX)
    }

    fn buffer_text(&self) -> Vec<String> {
        let total_rows = u32::try_from(self.term.total_rows().unwrap_or(0)).unwrap_or(0);
        let mut lines = Vec::with_capacity(total_rows as usize);
        for y in 0..total_rows {
            let mut line = String::new();
            for x in 0..self.size.cols {
                let cell = self.read_cell(Point::Screen(PointCoordinate { x, y }));
                line.push_str(&cell.grapheme);
            }
            lines.push(line.trim_end().to_string());
        }
        lines
    }

    fn encode_key(&self, ev: &KeyEvent) -> Vec<u8> {
        self.try_encode_key(ev).unwrap_or_default()
    }

    fn encode_mouse(&self, ev: &MouseEvent) -> Vec<u8> {
        self.try_encode_mouse(ev).unwrap_or_default()
    }

    fn bracketed_paste_enabled(&self) -> bool {
        self.term.mode(Mode::BRACKETED_PASTE).unwrap_or(false)
    }

    fn take_responses(&mut self) -> Vec<u8> {
        std::mem::take(&mut *self.responses.borrow_mut())
    }
}

fn map_color(c: StyleColor) -> Color {
    match c {
        StyleColor::None => Color::Default,
        StyleColor::Palette(p) => Color::Palette(p.0),
        StyleColor::Rgb(rgb) => Color::Rgb {
            r: rgb.r,
            g: rgb.g,
            b: rgb.b,
        },
    }
}

fn map_style(style: VtStyle) -> (Color, Color, CellAttrs) {
    let mut attrs = CellAttrs::empty();
    if style.bold {
        attrs |= CellAttrs::BOLD;
    }
    if style.faint {
        attrs |= CellAttrs::DIM;
    }
    if style.italic {
        attrs |= CellAttrs::ITALIC;
    }
    if !matches!(style.underline, Underline::None) {
        // Non-single underline styles collapse to a single underline flag.
        attrs |= CellAttrs::UNDERLINE;
    }
    if style.blink {
        attrs |= CellAttrs::BLINK;
    }
    if style.inverse {
        attrs |= CellAttrs::REVERSE;
    }
    if style.invisible {
        attrs |= CellAttrs::HIDDEN;
    }
    if style.strikethrough {
        attrs |= CellAttrs::STRIKETHROUGH;
    }
    // `overline` has no representation in our minimal CellAttrs surface.
    (map_color(style.fg_color), map_color(style.bg_color), attrs)
}

fn map_mods(mods: KeyModifiers) -> key::Mods {
    let mut m = key::Mods::empty();
    if mods.ctrl {
        m |= key::Mods::CTRL;
    }
    if mods.alt {
        m |= key::Mods::ALT;
    }
    if mods.shift {
        m |= key::Mods::SHIFT;
    }
    if mods.sup {
        m |= key::Mods::SUPER;
    }
    m
}

/// Map an ASCII letter/digit to its physical [`key::Key`] so the encoder can
/// derive control sequences (e.g. Ctrl-C). Returns `Unidentified` otherwise —
/// the printable text still flows through `utf8`.
fn char_to_key(c: char) -> key::Key {
    match c.to_ascii_lowercase() {
        'a' => key::Key::A,
        'b' => key::Key::B,
        'c' => key::Key::C,
        'd' => key::Key::D,
        'e' => key::Key::E,
        'f' => key::Key::F,
        'g' => key::Key::G,
        'h' => key::Key::H,
        'i' => key::Key::I,
        'j' => key::Key::J,
        'k' => key::Key::K,
        'l' => key::Key::L,
        'm' => key::Key::M,
        'n' => key::Key::N,
        'o' => key::Key::O,
        'p' => key::Key::P,
        'q' => key::Key::Q,
        'r' => key::Key::R,
        's' => key::Key::S,
        't' => key::Key::T,
        'u' => key::Key::U,
        'v' => key::Key::V,
        'w' => key::Key::W,
        'x' => key::Key::X,
        'y' => key::Key::Y,
        'z' => key::Key::Z,
        '0' => key::Key::Digit0,
        '1' => key::Key::Digit1,
        '2' => key::Key::Digit2,
        '3' => key::Key::Digit3,
        '4' => key::Key::Digit4,
        '5' => key::Key::Digit5,
        '6' => key::Key::Digit6,
        '7' => key::Key::Digit7,
        '8' => key::Key::Digit8,
        '9' => key::Key::Digit9,
        _ => key::Key::Unidentified,
    }
}

fn function_key(n: u8) -> key::Key {
    match n {
        1 => key::Key::F1,
        2 => key::Key::F2,
        3 => key::Key::F3,
        4 => key::Key::F4,
        5 => key::Key::F5,
        6 => key::Key::F6,
        7 => key::Key::F7,
        8 => key::Key::F8,
        9 => key::Key::F9,
        10 => key::Key::F10,
        11 => key::Key::F11,
        12 => key::Key::F12,
        _ => key::Key::Unidentified,
    }
}

/// Map a logical key + mods to `(physical key, optional utf8 text, optional
/// unshifted codepoint)`. For printable characters without Ctrl/Alt we pass the
/// text through; with Ctrl/Alt we pass `None` and let the encoder derive the
/// control sequence from the logical key (matching the P0.2-validated vectors).
fn map_key(key: Key, mods: KeyModifiers) -> (key::Key, Option<String>, Option<char>) {
    match key {
        Key::Char(c) => {
            let unshifted = Some(c.to_ascii_lowercase());
            let text = if mods.ctrl || mods.alt {
                None
            } else {
                Some(c.to_string())
            };
            (char_to_key(c), text, unshifted)
        }
        Key::Enter => (key::Key::Enter, None, None),
        Key::Tab => (key::Key::Tab, None, None),
        Key::Backspace => (key::Key::Backspace, None, None),
        Key::Escape => (key::Key::Escape, None, None),
        Key::Up => (key::Key::ArrowUp, None, None),
        Key::Down => (key::Key::ArrowDown, None, None),
        Key::Left => (key::Key::ArrowLeft, None, None),
        Key::Right => (key::Key::ArrowRight, None, None),
        Key::Home => (key::Key::Home, None, None),
        Key::End => (key::Key::End, None, None),
        Key::PageUp => (key::Key::PageUp, None, None),
        Key::PageDown => (key::Key::PageDown, None, None),
        Key::Insert => (key::Key::Insert, None, None),
        Key::Delete => (key::Key::Delete, None, None),
        Key::F(n) => (function_key(n), None, None),
    }
}

fn map_mouse_action(action: MouseAction) -> mouse::Action {
    match action {
        MouseAction::Press => mouse::Action::Press,
        MouseAction::Release => mouse::Action::Release,
        MouseAction::Move => mouse::Action::Motion,
    }
}

fn map_mouse_button(button: MouseButton) -> mouse::Button {
    match button {
        MouseButton::Left => mouse::Button::Left,
        MouseButton::Middle => mouse::Button::Middle,
        MouseButton::Right => mouse::Button::Right,
        // Wheel up/down are reported as buttons 4/5 in the X11/SGR protocols.
        MouseButton::ScrollUp => mouse::Button::Four,
        MouseButton::ScrollDown => mouse::Button::Five,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(rows: u16, cols: u16) -> LibghosttyEngine {
        LibghosttyEngine::new(TerminalSize { rows, cols }).expect("engine init")
    }

    fn cell_at(snap: &GridSnapshot, row: u16, col: u16) -> &Cell {
        &snap.cells[usize::from(row) * usize::from(snap.size.cols) + usize::from(col)]
    }

    #[test]
    fn dsr_cursor_position_report_is_answered() {
        // B7: ConPTY/conhost sends `CSI 6 n` at startup and stalls ~3 s until the
        // terminal replies with a cursor-position report. The engine must surface
        // that reply via `take_responses` so the session can write it to the PTY.
        let mut e = engine(24, 80);
        assert!(e.take_responses().is_empty(), "no reply before any query");
        // Move the cursor to row 3, col 5 (1-based CSI), then request CPR.
        e.feed(b"\x1b[3;5H\x1b[6n");
        let reply = e.take_responses();
        assert_eq!(
            reply, b"\x1b[3;5R",
            "expected a CPR for the current cursor cell"
        );
        // Draining is one-shot.
        assert!(e.take_responses().is_empty());
    }

    #[test]
    fn plain_text_and_cursor() {
        let mut e = engine(6, 20);
        e.feed(b"Hello");
        let snap = e.snapshot(0);
        assert_eq!(cell_at(&snap, 0, 0).grapheme, "H");
        assert_eq!(cell_at(&snap, 0, 4).grapheme, "o");
        assert_eq!(snap.cursor.row, 0);
        assert_eq!(snap.cursor.col, 5);
        assert!(snap.cursor.visible);
    }

    #[test]
    fn sgr_attrs_and_truecolor() {
        let mut e = engine(4, 20);
        // bold + italic + underline + reverse + truecolor fg, one char.
        e.feed(b"\x1b[1;3;4;7m\x1b[38;2;10;20;30mX\x1b[0m");
        let c = e.snapshot(0);
        let cell = cell_at(&c, 0, 0);
        assert_eq!(cell.grapheme, "X");
        assert!(cell.attrs.bold());
        assert!(cell.attrs.italic());
        assert!(cell.attrs.underline());
        assert!(cell.attrs.reverse());
        assert_eq!(
            cell.fg,
            Color::Rgb {
                r: 10,
                g: 20,
                b: 30
            }
        );
    }

    #[test]
    fn clears_ed_el() {
        let mut e = engine(4, 10);
        e.feed(b"abc\x1b[1;1H\x1b[K"); // write, home, erase-to-EOL
        assert_eq!(cell_at(&e.snapshot(0), 0, 0).grapheme, "");
        e.feed(b"xyz\x1b[2J"); // write, erase display
        assert_eq!(cell_at(&e.snapshot(0), 0, 0).grapheme, "");
    }

    #[test]
    fn line_wrap() {
        let mut e = engine(4, 8);
        e.feed(b"ABCDEFGHIJKL"); // 12 chars into 8 cols
        let s = e.snapshot(0);
        assert_eq!(cell_at(&s, 0, 7).grapheme, "H");
        assert_eq!(cell_at(&s, 1, 0).grapheme, "I");
        assert_eq!(cell_at(&s, 1, 3).grapheme, "L");
    }

    #[test]
    fn cjk_wide_and_emoji() {
        let mut e = engine(4, 20);
        e.feed("中a😀".as_bytes());
        let s = e.snapshot(0);
        let wide = cell_at(&s, 0, 0);
        assert_eq!(wide.grapheme, "中");
        assert_eq!(wide.width, 2);
        // The cell after a wide cell is a spacer: empty grapheme, width 1.
        let spacer = cell_at(&s, 0, 1);
        assert!(spacer.grapheme.is_empty());
        assert_eq!(spacer.width, 1);
        assert_eq!(cell_at(&s, 0, 2).grapheme, "a");
        assert_eq!(cell_at(&s, 0, 3).grapheme, "😀");
    }

    #[test]
    fn resize_reflow_lossless() {
        let mut e = engine(6, 20);
        e.feed(b"0123456789ABCDEFGHIJ"); // exactly 20 cols
        assert_eq!(cell_at(&e.snapshot(0), 0, 19).grapheme, "J");

        e.resize(TerminalSize { rows: 6, cols: 10 });
        let s = e.snapshot(0);
        assert_eq!(s.size.cols, 10);
        assert_eq!(cell_at(&s, 0, 0).grapheme, "0");
        assert_eq!(cell_at(&s, 0, 9).grapheme, "9");
        assert_eq!(cell_at(&s, 1, 0).grapheme, "A");
        assert_eq!(cell_at(&s, 1, 9).grapheme, "J");

        e.resize(TerminalSize { rows: 6, cols: 20 });
        let s = e.snapshot(0);
        assert_eq!(cell_at(&s, 0, 0).grapheme, "0");
        assert_eq!(cell_at(&s, 0, 19).grapheme, "J");
    }

    #[test]
    fn encode_keys() {
        let e = engine(4, 10);
        // Plain letter -> the character.
        assert_eq!(
            e.encode_key(&KeyEvent {
                key: Key::Char('a'),
                mods: KeyModifiers::default(),
            }),
            b"a"
        );
        // Ctrl-C -> ETX (0x03).
        assert_eq!(
            e.encode_key(&KeyEvent {
                key: Key::Char('c'),
                mods: KeyModifiers {
                    ctrl: true,
                    ..Default::default()
                },
            }),
            vec![0x03]
        );
        // Up arrow -> CSI A.
        assert_eq!(
            e.encode_key(&KeyEvent {
                key: Key::Up,
                mods: KeyModifiers::default(),
            }),
            b"\x1b[A"
        );
        // Enter -> CR.
        assert_eq!(
            e.encode_key(&KeyEvent {
                key: Key::Enter,
                mods: KeyModifiers::default(),
            }),
            b"\r"
        );
    }

    #[test]
    fn encode_mouse_sgr() {
        let mut e = engine(10, 40);
        // Enable normal mouse tracking (?1000) + SGR extended mode (?1006).
        e.feed(b"\x1b[?1000h\x1b[?1006h");
        let bytes = e.encode_mouse(&MouseEvent {
            button: MouseButton::Left,
            action: MouseAction::Press,
            row: 2,
            col: 3,
            mods: KeyModifiers::default(),
        });
        // SGR press at 1-based col;row = 4;3.
        assert_eq!(bytes, b"\x1b[<0;4;3M");
    }

    #[test]
    fn bracketed_paste_enabled_tracks_decset_2004() {
        let mut e = engine(10, 40);
        assert!(!e.bracketed_paste_enabled(), "off by default");
        e.feed(b"\x1b[?2004h");
        assert!(e.bracketed_paste_enabled());
        e.feed(b"\x1b[?2004l");
        assert!(!e.bracketed_paste_enabled());
    }

    // ── P6.7: scrollback offset / follow-tail / search text ────────────────

    /// Feed `n` numbered lines ("L0".."L{n-1}"), each on its own row.
    fn feed_numbered_lines(e: &mut LibghosttyEngine, n: usize) {
        for i in 0..n {
            e.feed(format!("L{i}\r\n").as_bytes());
        }
    }

    #[test]
    fn snapshot_zero_offset_matches_tail_and_reports_no_scrollback_yet() {
        let mut e = engine(4, 10);
        e.feed(b"hi");
        let s = e.snapshot(0);
        assert_eq!(s.scrollback_len, 0);
        assert_eq!(s.scroll_offset, 0);
        assert_eq!(cell_at(&s, 0, 0).grapheme, "h");
        assert!(s.cursor.visible);
    }

    #[test]
    fn snapshot_at_offset_shows_scrolled_history() {
        // 4 rows: enough lines scroll old content into history.
        let mut e = engine(4, 10);
        feed_numbered_lines(&mut e, 10);

        let tail = e.snapshot(0);
        assert!(
            tail.scrollback_len > 0,
            "10 lines into a 4-row grid must scroll"
        );
        assert_eq!(tail.scroll_offset, 0);

        // Scroll all the way back: the oldest retained line ("L0") is visible.
        let max = tail.scrollback_len;
        let scrolled = e.snapshot(max);
        assert_eq!(scrolled.scroll_offset, max);
        assert_eq!(cell_at(&scrolled, 0, 0).grapheme, "L");
        assert_eq!(cell_at(&scrolled, 0, 1).grapheme, "0");
    }

    #[test]
    fn snapshot_offset_clamps_beyond_available_scrollback() {
        let mut e = engine(4, 10);
        feed_numbered_lines(&mut e, 10);
        let scrollback_len = e.snapshot(0).scrollback_len;
        // A wildly out-of-range request clamps rather than erroring/panicking.
        let far = e.snapshot(9_999);
        assert_eq!(far.scroll_offset, scrollback_len);
    }

    #[test]
    fn cursor_hidden_while_scrolled_back_visible_at_tail() {
        let mut e = engine(4, 10);
        feed_numbered_lines(&mut e, 10);
        let tail = e.snapshot(0);
        assert!(tail.cursor.visible);
        let scrolled = e.snapshot(tail.scrollback_len);
        assert!(
            !scrolled.cursor.visible,
            "the active-area cursor is off-screen once scrolled back"
        );
    }

    #[test]
    fn mouse_tracking_flag_tracks_decset_1000() {
        let mut e = engine(10, 40);
        assert!(!e.snapshot(0).mouse_tracking, "off by default");
        e.feed(b"\x1b[?1000h");
        assert!(e.snapshot(0).mouse_tracking);
        e.feed(b"\x1b[?1000l");
        assert!(!e.snapshot(0).mouse_tracking);
    }

    #[test]
    fn buffer_text_covers_scrollback_and_active_oldest_first() {
        let mut e = engine(4, 10);
        feed_numbered_lines(&mut e, 10);
        let lines = e.buffer_text();
        assert!(lines.len() >= 10, "expected at least the 10 fed lines");
        assert_eq!(lines[0], "L0", "oldest retained line comes first");
        assert!(
            lines.iter().any(|l| l == "L9"),
            "the newest line is included"
        );
    }

    #[test]
    fn buffer_text_on_empty_terminal_is_all_blank_lines() {
        // Maximal/empty-input edge case (CONVENTIONS §2): no scrollback yet,
        // buffer_text degrades to just the blank active rows, never panics.
        let e = engine(4, 10);
        let lines = e.buffer_text();
        assert_eq!(lines.len(), 4);
        assert!(lines.iter().all(String::is_empty));
    }
}

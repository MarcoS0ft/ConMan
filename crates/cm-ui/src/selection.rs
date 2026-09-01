//! Terminal text-selection semantics: click counting (single/double/
//! triple), word/line-boundary expansion over a [`GridSnapshot`], copy-text
//! extraction, and the per-pane lifecycle state machine the controller drives
//! from pointer events.
//!
//! [`terminal_renderer::Selection`] is pure cell-range geometry consumed by the
//! draw pass; everything here is the layer *above* it that decides when a
//! selection exists, how big it is, and when it goes stale. See
//! `terminal_renderer::SelectionPoint`'s doc comment for the scrollback
//! coordinate seam this module inherits.
use std::time::{Duration, Instant};

use cm_core::{Cell, GridSnapshot};

use crate::terminal_renderer::{Selection, SelectionPoint};

/// Consecutive clicks at the same cell within this window count toward a
/// double/triple click; anything slower (or at a different cell) restarts the
/// count at 1. 450ms is a common desktop-OS double-click threshold.
const MULTI_CLICK_WINDOW: Duration = Duration::from_millis(450);

/// Tracks consecutive same-cell clicks to classify a click as single (1),
/// double (2), or triple (3+, capped/cycled at 3). Pure and deterministic —
/// the caller supplies `now` rather than this reading the clock, so it is
/// fully unit-testable without real timers.
#[derive(Debug, Default)]
pub(crate) struct ClickTracker {
    last_cell: Option<(u16, u16)>,
    last_time: Option<Instant>,
    count: u8,
}

impl ClickTracker {
    /// Register a left-button press at `cell` and return the click count in
    /// its run: 1 for a fresh click, 2 for a double, 3 for a triple. A 4th
    /// consecutive click restarts the cycle at 1 (so click-click-click-click
    /// is double, not a meaningless "quadruple").
    pub(crate) fn register(&mut self, cell: (u16, u16), now: Instant) -> u8 {
        let continues = self.last_cell == Some(cell)
            && self
                .last_time
                .is_some_and(|t| now.saturating_duration_since(t) <= MULTI_CLICK_WINDOW);
        self.count = if continues { self.count % 3 + 1 } else { 1 };
        self.last_cell = Some(cell);
        self.last_time = Some(now);
        self.count
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

/// A character that participates in "word" selection (double-click). Matches
/// common terminal-emulator behavior: alphanumerics and underscore are word
/// characters; everything else (including all punctuation and whitespace) is
/// a boundary.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The `(start_col, end_col)` word-boundary span containing `col` on `row`,
/// per [`is_word_char`]. If the clicked cell is not itself a word character,
/// the "word" is just that one cell (so double-clicking whitespace or
/// punctuation selects exactly the character clicked, not the whole run of
/// separators — matches common terminal behavior).
pub(crate) fn word_bounds(snap: &GridSnapshot, row: u16, col: u16) -> (u16, u16) {
    let cols = snap.size.cols;
    if cols == 0 {
        return (col, col);
    }
    let row_start = usize::from(row) * usize::from(cols);
    let char_at = |c: u16| -> Option<char> {
        snap.cells
            .get(row_start + usize::from(c))
            .and_then(|cell| cell.grapheme.chars().next())
    };
    if !char_at(col).is_some_and(is_word_char) {
        return (col, col);
    }
    let mut start = col;
    while start > 0 && char_at(start - 1).is_some_and(is_word_char) {
        start -= 1;
    }
    let mut end = col;
    while end + 1 < cols && char_at(end + 1).is_some_and(is_word_char) {
        end += 1;
    }
    (start, end)
}

/// The whole-row span for a triple-click line selection.
pub(crate) fn line_bounds(cols: u16) -> (u16, u16) {
    (0, cols.saturating_sub(1))
}

/// The absolute buffer row of `snap`'s viewport row 0. See
/// `terminal_renderer::SelectionPoint`'s doc comment for the address space —
/// `0` for a snapshot with no scrollback fields set (earlier test
/// fixtures), which is also the correct value for a live tail view.
fn viewport_top(snap: &GridSnapshot) -> u32 {
    snap.scrollback_len.saturating_sub(snap.scroll_offset)
}

/// Convert an absolute buffer row to a viewport-relative row into
/// `snap.cells`, or `None` if that row is not part of the currently
/// displayed window (scrolled elsewhere — the selection/match is simply not
/// visible right now, not an error).
fn viewport_row(snap: &GridSnapshot, abs_row: u16) -> Option<u16> {
    let rel = u32::from(abs_row).checked_sub(viewport_top(snap))?;
    (rel < u32::from(snap.size.rows)).then_some(rel as u16)
}

/// The cells covered by `sel` against `snap`, in row-major reading order —
/// shared by [`extract_text`] and the staleness check in
/// [`PaneSelectionState::invalidate_if_stale`] so both agree on exactly what
/// "the content currently under the selection" means. `sel`'s rows are
/// absolute buffer lines; rows outside `snap`'s current viewport
/// window contribute nothing (the selection has scrolled out of view).
fn selected_cells(snap: &GridSnapshot, sel: &Selection) -> Vec<Cell> {
    let cols = snap.size.cols;
    let (start, end) = sel.normalized();
    let mut out = Vec::new();
    for abs_row in start.row..=end.row {
        let Some((from, to)) = sel.row_span(abs_row, cols) else {
            continue;
        };
        let Some(row) = viewport_row(snap, abs_row) else {
            continue;
        };
        let row_start = usize::from(row) * usize::from(cols);
        for col in from..=to {
            if let Some(cell) = snap.cells.get(row_start + usize::from(col)) {
                out.push(cell.clone());
            }
        }
    }
    out
}

/// Extract the selected text from `snap`, one line per selected row (trailing
/// blanks trimmed per line, matching the usual "copy from a terminal" feel),
/// joined with `\n`. `sel`'s rows are absolute buffer lines; a row
/// outside `snap`'s current viewport window contributes an empty line (rather
/// than being skipped) so a selection spanning partly off-screen content
/// still copies with the right line count — the common case is the whole
/// selection being visible, since it clears once scrolled fully out of view
/// (see [`PaneSelectionState::invalidate_if_stale`]).
pub(crate) fn extract_text(snap: &GridSnapshot, sel: &Selection) -> String {
    let cols = snap.size.cols;
    let (start, end) = sel.normalized();
    let mut lines = Vec::with_capacity(usize::from(end.row.saturating_sub(start.row)) + 1);
    for abs_row in start.row..=end.row {
        let Some((from, to)) = sel.row_span(abs_row, cols) else {
            continue;
        };
        let mut line = String::new();
        if let Some(row) = viewport_row(snap, abs_row) {
            let row_start = usize::from(row) * usize::from(cols);
            for col in from..=to {
                if let Some(cell) = snap.cells.get(row_start + usize::from(col)) {
                    line.push_str(&cell.grapheme);
                }
            }
        }
        lines.push(line.trim_end().to_string());
    }
    lines.join("\n")
}

/// Per-pane mouse-selection state the controller updates from pointer events
/// and drains on tick: the live [`Selection`] (if any), the multi-click
/// tracker, a pending drag anchor, and the lifecycle bookkeeping used
/// to implement the pinned rule "selection clears on new output that scrolls
/// the region [or] on resize" — see [`invalidate_if_stale`].
///
/// "Clears on focus change" is implemented by the controller calling
/// [`clear`](Self::clear) directly when it detects the active tab or the
/// focused pane within a tab has changed (`sessions.rs`'s `tick`/`tick_tab`).
#[derive(Debug, Default)]
pub(crate) struct PaneSelectionState {
    selection: Option<Selection>,
    /// Monotonic identity for the currently selected content. Clipboard
    /// writes capture this value so an asynchronous completion can clear the
    /// selection it copied without clearing a newer selection that happens
    /// to belong to the same pane.
    generation: u64,
    /// The selected cells' content as of the last time `selection` was set —
    /// compared against fresh snapshots to detect "the thing I selected
    /// changed under me" (scrolled away, overwritten, or a resize altered
    /// which cells even exist at that row/col).
    baseline: Vec<Cell>,
    click: ClickTracker,
    /// Mouse-down position before the first drag motion. Keeping this separate
    /// from `selection` prevents a plain click from becoming a visible,
    /// copyable one-cell selection.
    pending_anchor: Option<SelectionPoint>,
    /// Owner and concrete button of the pointer gesture currently captured
    /// by Slint. Ownership is decided at press time and remains pinned until
    /// release/cancel so changing Shift or DEC mouse mode mid-drag cannot
    /// deliver an unmatched tail to either side.
    pointer_capture: Option<PointerCapture>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PointerOwner {
    Local,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PointerCapture {
    owner: PointerOwner,
    button: i32,
}

/// Routing decision for one terminal-surface pointer event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PointerRoute {
    /// ConMan owns the gesture (selection or local paste behavior).
    Local,
    /// The terminal application owns the gesture through DEC mouse tracking.
    Terminal(i32, i32),
    /// No owner has meaningful work for this event.
    Ignore,
}

/// Pointer button/kind discriminants shared with `crate::input`'s Slint
/// wire format (`0`=no button/cancel, `1`=left, `1`=press, `2`=release,
/// `3`=move) — duplicated here as named constants rather than importing
/// `crate::input` (which is a leaf module with no reason to depend back on
/// `selection`). Slint reports `PointerEventButton.other` (mapped to zero)
/// for move events even while a `TouchArea` owns a left-button grab.
const BTN_NONE: i32 = 0;
const BTN_LEFT: i32 = 1;
#[cfg(test)]
const BTN_RIGHT: i32 = 2;
#[cfg(test)]
const BTN_MIDDLE: i32 = 3;
const KIND_CANCEL: i32 = 0;
const KIND_PRESS: i32 = 1;
const KIND_RELEASE: i32 = 2;
const KIND_MOVE: i32 = 3;

impl PaneSelectionState {
    /// The live selection, if any (e.g. to pass into the renderer or to copy).
    pub(crate) fn selection(&self) -> Option<&Selection> {
        self.selection.as_ref()
    }

    /// Identity of the live selection, if any.
    pub(crate) fn selection_generation(&self) -> Option<u64> {
        self.selection.as_ref().map(|_| self.generation)
    }

    /// Decide whether ConMan or the terminal application owns this pointer
    /// event. DEC mouse tracking claims every button by default; Shift on the
    /// initial press is the conventional terminal-emulator override for a
    /// local gesture. The press-time decision is retained across captured
    /// moves and release/cancel events.
    pub(crate) fn route_pointer(
        &mut self,
        mouse_tracking: bool,
        shift: bool,
        button: i32,
        kind: i32,
    ) -> PointerRoute {
        if kind == KIND_CANCEL {
            return match self.pointer_capture.take() {
                Some(PointerCapture {
                    owner: PointerOwner::Terminal,
                    button,
                }) => PointerRoute::Terminal(button, KIND_RELEASE),
                Some(PointerCapture {
                    owner: PointerOwner::Local,
                    ..
                }) => PointerRoute::Local,
                None => PointerRoute::Ignore,
            };
        }

        if kind == KIND_PRESS {
            if button == BTN_NONE {
                return PointerRoute::Ignore;
            }
            let owner = if mouse_tracking && !shift {
                PointerOwner::Terminal
            } else {
                PointerOwner::Local
            };
            self.pointer_capture = Some(PointerCapture { owner, button });
            return match owner {
                PointerOwner::Local => PointerRoute::Local,
                PointerOwner::Terminal => PointerRoute::Terminal(button, kind),
            };
        }

        if let Some(capture) = self.pointer_capture {
            let route = match capture.owner {
                PointerOwner::Local => PointerRoute::Local,
                PointerOwner::Terminal => PointerRoute::Terminal(capture.button, kind),
            };
            if kind == KIND_RELEASE {
                self.pointer_capture = None;
            }
            return route;
        }

        // Hover motion is useful only to tracking modes that requested it;
        // `input::map_mouse` decides whether the active protocol encodes a
        // buttonless move. Stray releases are ignored to avoid fabricating an
        // unmatched terminal gesture.
        if kind == KIND_MOVE && mouse_tracking && !shift {
            PointerRoute::Terminal(button, kind)
        } else {
            PointerRoute::Ignore
        }
    }

    /// Drop the current selection (lifecycle: resize / new-output-scroll /
    /// focus-change per the module doc).
    pub(crate) fn clear(&mut self) {
        if self.selection.take().is_some() {
            self.advance_generation();
        }
        self.baseline.clear();
        self.pending_anchor = None;
    }

    /// Clear only the selection represented by an asynchronous request.
    /// Returns whether a live selection was cleared.
    pub(crate) fn clear_if_generation(&mut self, generation: u64) -> bool {
        if self.selection.is_some() && self.generation == generation {
            self.clear();
            true
        } else {
            false
        }
    }

    /// Handle a terminal-surface pointer event for selection purposes:
    /// left-press classifies as single/double/triple click (char/word/line
    /// selection); a move while a left-press anchor is pending extends the
    /// character selection; any release or cancellation ends the drag.
    /// `snap`/`cols` are the pane's most recent grid snapshot (used to expand
    /// word/line bounds and to capture the staleness baseline) — `None`
    /// degrades to a bare drag with no word/line expansion (the pane has not
    /// produced a snapshot yet).
    ///
    /// Returns `true` iff the visible [`Selection`] geometry actually changed
    /// (created, extended, or — implicitly, via [`clear`](Self::clear), which
    /// callers invoke separately — removed). bundled fix (F-perf,
    /// finding R1): the controller uses this to gate the forced
    /// selection-highlight re-render in `sessions.rs`'s `wire_pointer` so a
    /// plain button-less hover move (no selection, [`crate::input::map_mouse`]
    /// returns `None`) no longer forces a full-grid raster on every motion
    /// event — only an actual selection change does.
    pub(crate) fn on_pointer(
        &mut self,
        button: i32,
        kind: i32,
        cell: (u16, u16),
        snap: Option<&GridSnapshot>,
        now: Instant,
    ) -> bool {
        // `cell.0` from `renderer.cell_at` is viewport-relative; a
        // `Selection`'s stored rows are absolute buffer lines, so translate
        // once here via the snapshot's current scroll position. No `snap` ->
        // no scrollback context -> the row is used as-is (matches the
        // earlier degenerate "no snapshot yet" behavior).
        let abs_row = snap.map_or(cell.0, |s| {
            u16::try_from(viewport_top(s) + u32::from(cell.0)).unwrap_or(u16::MAX)
        });
        match (button, kind) {
            (BTN_LEFT, KIND_PRESS) => {
                let n = self.click.register(cell, now);
                match (n, snap) {
                    (2, Some(snap)) => {
                        let (from, to) = word_bounds(snap, cell.0, cell.1);
                        self.pending_anchor = None;
                        self.selection = Some(Selection::new(
                            SelectionPoint {
                                row: abs_row,
                                col: from,
                            },
                            SelectionPoint {
                                row: abs_row,
                                col: to,
                            },
                        ));
                        self.advance_generation();
                        self.rebaseline(snap);
                        true
                    }
                    (n, Some(snap)) if n >= 3 => {
                        let (from, to) = line_bounds(snap.size.cols);
                        self.pending_anchor = None;
                        self.selection = Some(Selection::new(
                            SelectionPoint {
                                row: abs_row,
                                col: from,
                            },
                            SelectionPoint {
                                row: abs_row,
                                col: to,
                            },
                        ));
                        self.advance_generation();
                        self.rebaseline(snap);
                        true
                    }
                    _ => {
                        let changed = self.selection.take().is_some();
                        if changed {
                            self.advance_generation();
                        }
                        self.baseline.clear();
                        self.pending_anchor = Some(SelectionPoint {
                            row: abs_row,
                            col: cell.1,
                        });
                        changed
                    }
                }
            }
            // Slint move events do not carry the held button. The pending
            // anchor, which only a left press can create, is the drag proof.
            (_, KIND_MOVE) if self.pending_anchor.is_some() => {
                let anchor = self.pending_anchor.expect("checked above");
                let new_cursor = SelectionPoint {
                    row: abs_row,
                    col: cell.1,
                };
                let next = Selection::new(anchor, new_cursor);
                let changed = self.selection.as_ref() != Some(&next);
                self.selection = Some(next);
                if changed {
                    self.advance_generation();
                }
                // A drag is not the first half of a later double-click.
                self.click.reset();
                if changed && let Some(snap) = snap {
                    self.rebaseline(snap);
                }
                changed
            }
            (_, KIND_CANCEL) => {
                self.pending_anchor = None;
                false
            }
            (_, KIND_RELEASE) => {
                self.pending_anchor = None;
                false
            }
            _ => false,
        }
    }

    fn rebaseline(&mut self, snap: &GridSnapshot) {
        if let Some(sel) = &self.selection {
            self.baseline = selected_cells(snap, sel);
        }
    }

    fn advance_generation(&mut self) {
        // Reuse would require 2^64 visible selection changes in one process.
        // Wrapping keeps pointer handling fail-soft instead of making an
        // impossible exhaustion case capable of panicking the UI thread.
        self.generation = self.generation.wrapping_add(1);
    }

    /// Clear the selection if the content it covers no longer matches what
    /// was selected — either the grid was resized (a `row_span` computed
    /// against the old width would be meaningless) or the covered cells'
    /// content changed (new output scrolled the region, or overwrote it in
    /// place). Call once per pane whenever a fresh [`GridSnapshot`] is
    /// drained (`sessions::tick_tab`). A no-op when there is no selection.
    pub(crate) fn invalidate_if_stale(&mut self, new_snap: &GridSnapshot) {
        let Some(sel) = &self.selection else {
            return;
        };
        let current = selected_cells(new_snap, sel);
        if current != self.baseline {
            self.clear();
        }
    }

    /// Copy the selected text out, if any (does not clear the selection —
    /// pinned in the lifecycle rule: "copying does not clear").
    pub(crate) fn copy_text(&self, snap: &GridSnapshot) -> Option<String> {
        let sel = self.selection.as_ref()?;
        let text = extract_text(snap, sel);
        if text.is_empty() { None } else { Some(text) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cm_core::{CellAttrs, Color, CursorShape, CursorState, TerminalSize};

    fn cell(g: &str) -> Cell {
        Cell {
            grapheme: g.to_string(),
            fg: Color::Default,
            bg: Color::Default,
            attrs: CellAttrs::empty(),
            width: 1,
        }
    }

    fn row_snap(rows: &[&str], cols: u16) -> GridSnapshot {
        row_snap_at(rows, cols, 0, 0)
    }

    /// Like `row_snap`, but at a given scrollback position: `rows` is
    /// the *visible viewport* content, and `scrollback_len`/`scroll_offset`
    /// place it within a larger absolute-row address space, matching what a
    /// real scrolled-back `GridSnapshot` reports.
    fn row_snap_at(
        rows: &[&str],
        cols: u16,
        scrollback_len: u32,
        scroll_offset: u32,
    ) -> GridSnapshot {
        let mut cells = Vec::new();
        for row in rows {
            let chars: Vec<char> = row.chars().collect();
            for i in 0..usize::from(cols) {
                let g = chars.get(i).map(char::to_string).unwrap_or_default();
                cells.push(cell(&g));
            }
        }
        GridSnapshot {
            size: TerminalSize {
                rows: rows.len() as u16,
                cols,
            },
            cells,
            cursor: CursorState {
                row: 0,
                col: 0,
                visible: false,
                shape: CursorShape::Block,
            },
            scrollback_len,
            scroll_offset,
            mouse_tracking: false,
        }
    }

    // ── ClickTracker ─────────────────────────────────────────────────────

    #[test]
    fn click_tracker_single_click_is_one() {
        let mut t = ClickTracker::default();
        assert_eq!(t.register((0, 0), Instant::now()), 1);
    }

    #[test]
    fn click_tracker_counts_double_and_triple_at_same_cell() {
        let mut t = ClickTracker::default();
        let t0 = Instant::now();
        assert_eq!(t.register((3, 4), t0), 1);
        assert_eq!(t.register((3, 4), t0 + Duration::from_millis(100)), 2);
        assert_eq!(t.register((3, 4), t0 + Duration::from_millis(200)), 3);
        // A 4th click within the window restarts the cycle.
        assert_eq!(t.register((3, 4), t0 + Duration::from_millis(300)), 1);
    }

    #[test]
    fn click_tracker_resets_on_different_cell() {
        let mut t = ClickTracker::default();
        let t0 = Instant::now();
        assert_eq!(t.register((0, 0), t0), 1);
        assert_eq!(t.register((0, 1), t0 + Duration::from_millis(50)), 1);
    }

    #[test]
    fn click_tracker_resets_after_window_expires() {
        let mut t = ClickTracker::default();
        let t0 = Instant::now();
        assert_eq!(t.register((0, 0), t0), 1);
        assert_eq!(
            t.register((0, 0), t0 + MULTI_CLICK_WINDOW + Duration::from_millis(1)),
            1
        );
    }

    // ── word_bounds / line_bounds ────────────────────────────────────────

    #[test]
    fn word_bounds_expands_to_full_word() {
        let snap = row_snap(&["  hello_world  "], 15);
        assert_eq!(word_bounds(&snap, 0, 7), (2, 12));
    }

    #[test]
    fn word_bounds_on_punctuation_selects_single_char() {
        let snap = row_snap(&["a.b"], 3);
        assert_eq!(word_bounds(&snap, 0, 1), (1, 1));
    }

    #[test]
    fn word_bounds_at_row_start_and_end_clamp() {
        let snap = row_snap(&["hello"], 5);
        assert_eq!(word_bounds(&snap, 0, 0), (0, 4));
        assert_eq!(word_bounds(&snap, 0, 4), (0, 4));
    }

    #[test]
    fn line_bounds_spans_whole_row() {
        assert_eq!(line_bounds(80), (0, 79));
        assert_eq!(line_bounds(0), (0, 0));
    }

    // ── extract_text ─────────────────────────────────────────────────────

    #[test]
    fn extract_text_single_row_trims_trailing_blanks() {
        let snap = row_snap(&["hello     "], 10);
        let sel = Selection::new(
            SelectionPoint { row: 0, col: 0 },
            SelectionPoint { row: 0, col: 9 },
        );
        assert_eq!(extract_text(&snap, &sel), "hello");
    }

    #[test]
    fn extract_text_multi_row_joins_with_newline() {
        let snap = row_snap(&["abc", "def"], 3);
        let sel = Selection::new(
            SelectionPoint { row: 0, col: 0 },
            SelectionPoint { row: 1, col: 2 },
        );
        assert_eq!(extract_text(&snap, &sel), "abc\ndef");
    }

    // ── PaneSelectionState ───────────────────────────────────────────────

    #[test]
    fn slint_buttonless_drag_move_creates_char_selection() {
        let snap = row_snap(&["hello world"], 11);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0);
        // A real Slint TouchArea move reports PointerEventButton.other even
        // while its left-button grab is active.
        s.on_pointer(BTN_NONE, KIND_MOVE, (0, 4), Some(&snap), t0);
        s.on_pointer(BTN_LEFT, KIND_RELEASE, (0, 4), Some(&snap), t0);
        let sel = s.selection().expect("selection after drag");
        assert_eq!(sel.normalized().0, SelectionPoint { row: 0, col: 0 });
        assert_eq!(sel.normalized().1, SelectionPoint { row: 0, col: 4 });
    }

    #[test]
    fn drag_extends_backward_past_anchor() {
        let snap = row_snap(&["hello world"], 11);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 6), Some(&snap), t0);
        s.on_pointer(BTN_NONE, KIND_MOVE, (0, 2), Some(&snap), t0);
        let (start, end) = s.selection().unwrap().normalized();
        assert_eq!((start.col, end.col), (2, 6));
    }

    #[test]
    fn double_click_selects_word_without_starting_a_drag() {
        let snap = row_snap(&["hello world"], 11);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 7), Some(&snap), t0);
        s.on_pointer(
            BTN_LEFT,
            KIND_PRESS,
            (0, 7),
            Some(&snap),
            t0 + Duration::from_millis(50),
        );
        let (start, end) = s.selection().unwrap().normalized();
        assert_eq!((start.col, end.col), (6, 10)); // "world"
        // A stray move after a word-click must not extend it because there is
        // no pending drag anchor.
        s.on_pointer(
            BTN_LEFT,
            KIND_MOVE,
            (0, 0),
            Some(&snap),
            t0 + Duration::from_millis(60),
        );
        let (start2, end2) = s.selection().unwrap().normalized();
        assert_eq!((start2.col, end2.col), (6, 10));
    }

    #[test]
    fn triple_click_selects_whole_line() {
        let snap = row_snap(&["hi"], 2);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        for i in 0..3 {
            s.on_pointer(
                BTN_LEFT,
                KIND_PRESS,
                (0, 0),
                Some(&snap),
                t0 + Duration::from_millis(i * 10),
            );
        }
        let (start, end) = s.selection().unwrap().normalized();
        assert_eq!((start.col, end.col), (0, 1));
    }

    #[test]
    fn release_without_drag_leaves_no_selection() {
        let snap = row_snap(&["x"], 1);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0);
        s.on_pointer(BTN_LEFT, KIND_RELEASE, (0, 0), Some(&snap), t0);
        assert!(s.selection().is_none());
    }

    #[test]
    fn invalidate_if_stale_clears_when_selected_content_changes() {
        let snap1 = row_snap(&["hello"], 5);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap1), t0);
        s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 4), Some(&snap1), t0);
        assert!(s.selection().is_some());

        // Same size, different content at the selected cells -> stale.
        let snap2 = row_snap(&["world"], 5);
        s.invalidate_if_stale(&snap2);
        assert!(s.selection().is_none());
    }

    #[test]
    fn invalidate_if_stale_keeps_selection_when_content_is_unchanged() {
        let snap = row_snap(&["hello"], 5);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0);
        s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 4), Some(&snap), t0);
        // A snapshot identical in the selected region -> still valid.
        let snap_same = row_snap(&["hello"], 5);
        s.invalidate_if_stale(&snap_same);
        assert!(s.selection().is_some());
    }

    #[test]
    fn invalidate_if_stale_clears_on_resize() {
        // Select the whole 5-col row.
        let snap = row_snap(&["hello"], 5);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0);
        s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 4), Some(&snap), t0);
        // A shrink-resize clamps the same selection's `row_span` to fewer
        // cells (`row_span` re-clamps against the new width), so the
        // covered-cell count itself differs from the baseline even though
        // the surviving prefix happens to match.
        let resized = row_snap(&["hel"], 3);
        s.invalidate_if_stale(&resized);
        assert!(s.selection().is_none());
    }

    #[test]
    fn copy_text_does_not_clear_selection() {
        let snap = row_snap(&["abc"], 3);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0);
        s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 2), Some(&snap), t0);
        assert_eq!(s.copy_text(&snap).as_deref(), Some("abc"));
        assert!(s.selection().is_some(), "copy must not clear the selection");
    }

    #[test]
    fn copy_text_none_when_nothing_selected() {
        let snap = row_snap(&["abc"], 3);
        let s = PaneSelectionState::default();
        assert_eq!(s.copy_text(&snap), None);
    }

    #[test]
    fn asynchronous_clear_targets_exact_selection_generation() {
        let snap = row_snap(&["abc"], 3);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0);
        s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 1), Some(&snap), t0);
        let copied_generation = s.selection_generation().expect("first selection");

        assert!(!s.clear_if_generation(copied_generation.wrapping_add(1)));
        assert!(
            s.selection().is_some(),
            "mismatched completion preserves selection"
        );

        // A new gesture may recreate overlapping geometry, but it must have a
        // different identity so the older clipboard result cannot clear it.
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0);
        s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 2), Some(&snap), t0);
        let newer_generation = s.selection_generation().expect("new selection");
        assert_ne!(newer_generation, copied_generation);
        assert!(!s.clear_if_generation(copied_generation));
        assert!(
            s.selection().is_some(),
            "stale success preserves newer selection"
        );

        assert!(s.clear_if_generation(newer_generation));
        assert!(s.selection().is_none());
    }

    // ── bundled fix (F-perf, finding R1): on_pointer's "changed" ──
    // return value is exactly the render-gating signal `sessions.rs`'s
    // `wire_pointer` uses to skip the forced re-render on events that didn't
    // touch the selection - these assert that signal is correct.

    #[test]
    fn press_without_an_existing_selection_reports_unchanged() {
        let snap = row_snap(&["abc"], 3);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        assert!(!s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0));
        assert!(s.selection().is_none());
    }

    #[test]
    fn dragging_move_to_a_new_cell_reports_changed() {
        let snap = row_snap(&["abcdef"], 6);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0);
        assert!(s.on_pointer(BTN_NONE, KIND_MOVE, (0, 3), Some(&snap), t0));
    }

    #[test]
    fn first_same_cell_drag_move_creates_a_one_cell_selection() {
        let snap = row_snap(&["abcdef"], 6);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 2), Some(&snap), t0);
        assert!(s.on_pointer(BTN_NONE, KIND_MOVE, (0, 2), Some(&snap), t0));
        let sel = s.selection().expect("selection after same-cell drag");
        assert_eq!(sel.anchor, SelectionPoint { row: 0, col: 2 });
        assert_eq!(sel.cursor, SelectionPoint { row: 0, col: 2 });
        assert!(!s.on_pointer(BTN_NONE, KIND_MOVE, (0, 2), Some(&snap), t0));
    }

    #[test]
    fn button_less_hover_move_reports_unchanged() {
        // The exact case finding R1 flagged: a plain move with no
        // button held (not dragging) must never report a selection change -
        // this is the "hover-only move" the F-perf gate exists to skip.
        let snap = row_snap(&["abcdef"], 6);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        assert!(!s.on_pointer(BTN_NONE, KIND_MOVE, (0, 3), Some(&snap), t0));
        assert!(s.selection().is_none());
    }

    #[test]
    fn cancel_discards_pending_anchor_before_later_hover_move() {
        let snap = row_snap(&["abcdef"], 6);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();

        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 1), Some(&snap), t0);
        assert!(!s.on_pointer(BTN_NONE, KIND_CANCEL, (0, 1), Some(&snap), t0));
        assert!(!s.on_pointer(BTN_NONE, KIND_MOVE, (0, 4), Some(&snap), t0));
        assert!(s.selection().is_none());
    }

    #[test]
    fn release_reports_unchanged() {
        let snap = row_snap(&["abc"], 3);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0);
        assert!(!s.on_pointer(BTN_LEFT, KIND_RELEASE, (0, 0), Some(&snap), t0));
    }

    #[test]
    fn mouse_tracking_owns_every_button_without_shift() {
        let mut s = PaneSelectionState::default();

        assert_eq!(
            s.route_pointer(true, false, BTN_LEFT, KIND_PRESS),
            PointerRoute::Terminal(BTN_LEFT, KIND_PRESS)
        );
        assert_eq!(
            s.route_pointer(true, false, BTN_NONE, KIND_MOVE),
            PointerRoute::Terminal(BTN_LEFT, KIND_MOVE)
        );
        assert_eq!(
            s.route_pointer(true, false, BTN_LEFT, KIND_RELEASE),
            PointerRoute::Terminal(BTN_LEFT, KIND_RELEASE)
        );

        assert_eq!(
            s.route_pointer(true, false, BTN_RIGHT, KIND_PRESS),
            PointerRoute::Terminal(BTN_RIGHT, KIND_PRESS)
        );
        assert_eq!(
            s.route_pointer(true, false, BTN_RIGHT, KIND_RELEASE),
            PointerRoute::Terminal(BTN_RIGHT, KIND_RELEASE)
        );
        assert_eq!(
            s.route_pointer(true, false, BTN_MIDDLE, KIND_PRESS),
            PointerRoute::Terminal(BTN_MIDDLE, KIND_PRESS)
        );
    }

    #[test]
    fn shift_at_press_pins_gesture_to_local_selection() {
        let mut s = PaneSelectionState::default();

        assert_eq!(
            s.route_pointer(true, true, BTN_LEFT, KIND_PRESS),
            PointerRoute::Local
        );
        // Releasing Shift during the drag must not leak a move/release tail to
        // the TUI, which never received the matching press.
        assert_eq!(
            s.route_pointer(true, false, BTN_NONE, KIND_MOVE),
            PointerRoute::Local
        );
        assert_eq!(
            s.route_pointer(true, false, BTN_LEFT, KIND_RELEASE),
            PointerRoute::Local
        );
    }

    #[test]
    fn local_mode_owns_right_and_middle_paste_gestures() {
        let mut s = PaneSelectionState::default();
        assert_eq!(
            s.route_pointer(false, false, BTN_RIGHT, KIND_PRESS),
            PointerRoute::Local
        );
        assert_eq!(
            s.route_pointer(false, false, BTN_RIGHT, KIND_RELEASE),
            PointerRoute::Local
        );
        assert_eq!(
            s.route_pointer(true, true, BTN_MIDDLE, KIND_PRESS),
            PointerRoute::Local,
            "Shift overrides tracking for every locally-owned gesture"
        );
    }

    #[test]
    fn terminal_owned_gesture_stays_terminal_if_shift_changes_mid_drag() {
        let mut s = PaneSelectionState::default();

        assert_eq!(
            s.route_pointer(true, false, BTN_LEFT, KIND_PRESS),
            PointerRoute::Terminal(BTN_LEFT, KIND_PRESS)
        );
        assert_eq!(
            s.route_pointer(true, true, BTN_NONE, KIND_MOVE),
            PointerRoute::Terminal(BTN_LEFT, KIND_MOVE)
        );
        assert_eq!(
            s.route_pointer(true, true, BTN_LEFT, KIND_RELEASE),
            PointerRoute::Terminal(BTN_LEFT, KIND_RELEASE)
        );
    }

    #[test]
    fn cancel_releases_only_a_terminal_owned_capture() {
        let mut s = PaneSelectionState::default();
        s.route_pointer(true, false, BTN_RIGHT, KIND_PRESS);
        assert_eq!(
            s.route_pointer(true, false, BTN_NONE, KIND_CANCEL),
            PointerRoute::Terminal(BTN_RIGHT, KIND_RELEASE)
        );
        assert_eq!(
            s.route_pointer(true, false, BTN_NONE, KIND_CANCEL),
            PointerRoute::Ignore
        );

        s.route_pointer(true, true, BTN_LEFT, KIND_PRESS);
        assert_eq!(
            s.route_pointer(true, false, BTN_NONE, KIND_CANCEL),
            PointerRoute::Local
        );
    }

    #[test]
    fn click_after_drag_clears_selection_and_starts_a_fresh_click_run() {
        let snap = row_snap(&["hello world"], 11);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();

        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0);
        s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 4), Some(&snap), t0);
        s.on_pointer(BTN_LEFT, KIND_RELEASE, (0, 4), Some(&snap), t0);
        assert!(s.selection().is_some());

        assert!(s.on_pointer(
            BTN_LEFT,
            KIND_PRESS,
            (0, 0),
            Some(&snap),
            t0 + Duration::from_millis(50),
        ));
        assert!(s.selection().is_none());
    }

    // ──: selection survives scrollback (offset-aware) ──────────────────

    #[test]
    fn selection_made_while_scrolled_back_stores_absolute_row() {
        // 100 lines of scrollback, scrolled 40 lines back from the tail: the
        // viewport's row 0 is absolute line 60.
        let snap = row_snap_at(&["hello world"], 11, 100, 40);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0);
        s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 4), Some(&snap), t0);
        let sel = s.selection().unwrap();
        assert_eq!(sel.anchor.row, 60);
        assert_eq!(sel.cursor.row, 60);
    }

    #[test]
    fn copy_text_at_offset_k_returns_the_right_text() {
        // Spec wording ( verification): "a selection made at offset K
        // copies the right text."
        let snap = row_snap_at(&["hello world"], 11, 100, 40);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 6), Some(&snap), t0);
        s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 10), Some(&snap), t0);
        assert_eq!(s.copy_text(&snap).as_deref(), Some("world"));
    }

    #[test]
    fn selection_survives_when_still_within_the_scrolled_viewport() {
        // Selection made at absolute row 60 (offset 40, 1-row viewport).
        let snap1 = row_snap_at(&["hello"], 5, 100, 40);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap1), t0);
        s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 4), Some(&snap1), t0);
        assert!(s.selection().is_some());

        // Scroll slightly further back (offset 41, 2-row viewport): absolute
        // top is now 59, so the window covers rows 59-60 — row 60 ("hello",
        // unchanged content) is still visible, just no longer at row 0.
        let snap2 = row_snap_at(&["prev", "hello"], 5, 100, 41);
        s.invalidate_if_stale(&snap2);
        assert!(
            s.selection().is_some(),
            "selection should survive a scroll that keeps it in view"
        );
    }

    #[test]
    fn selection_clears_on_tail_follow_jump_scrolling_it_out_of_view() {
        // Made 40 lines back (absolute row 60); then the view snaps to the
        // tail (offset 0) - the selection's absolute row is no longer part
        // of the displayed window at all, so it must clear.
        let snap1 = row_snap_at(&["hello"], 5, 100, 40);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap1), t0);
        s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 4), Some(&snap1), t0);
        assert!(s.selection().is_some());

        let tail_snap = row_snap_at(&["prompt$ "], 8, 100, 0);
        s.invalidate_if_stale(&tail_snap);
        assert!(
            s.selection().is_none(),
            "a tail-follow jump must clear a selection scrolled out of view"
        );
    }
}

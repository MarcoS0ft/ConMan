//! Terminal text-selection semantics (P6.5): click counting (single/double/
//! triple), word/line-boundary expansion over a [`GridSnapshot`], copy-text
//! extraction, and the per-pane lifecycle state machine the controller drives
//! from pointer events.
//!
//! [`terminal_renderer::Selection`] is pure cell-range geometry consumed by the
//! draw pass; everything here is the layer *above* it that decides when a
//! selection exists, how big it is, and when it goes stale. See
//! `terminal_renderer::SelectionPoint`'s doc comment for the P6.7
//! (scrollback) coordinate seam this module inherits.
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

/// The cells covered by `sel` against `snap`, in row-major reading order —
/// shared by [`extract_text`] and the staleness check in
/// [`PaneSelectionState::invalidate_if_stale`] so both agree on exactly what
/// "the content currently under the selection" means.
fn selected_cells(snap: &GridSnapshot, sel: &Selection) -> Vec<Cell> {
    let cols = snap.size.cols;
    let (start, end) = sel.normalized();
    let mut out = Vec::new();
    for row in start.row..=end.row {
        let Some((from, to)) = sel.row_span(row, cols) else {
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
/// joined with `\n`.
///
/// P6.7 seam: this walks `sel`'s viewport-relative rows against the live
/// snapshot only — there is no scrollback to read from yet (see
/// `terminal_renderer::SelectionPoint`'s doc comment).
pub(crate) fn extract_text(snap: &GridSnapshot, sel: &Selection) -> String {
    let cols = snap.size.cols;
    let (start, end) = sel.normalized();
    let mut lines = Vec::with_capacity(usize::from(end.row.saturating_sub(start.row)) + 1);
    for row in start.row..=end.row {
        let Some((from, to)) = sel.row_span(row, cols) else {
            continue;
        };
        let row_start = usize::from(row) * usize::from(cols);
        let mut line = String::new();
        for col in from..=to {
            if let Some(cell) = snap.cells.get(row_start + usize::from(col)) {
                line.push_str(&cell.grapheme);
            }
        }
        lines.push(line.trim_end().to_string());
    }
    lines.join("\n")
}

/// Per-pane mouse-selection state the controller updates from pointer events
/// and drains on tick: the live [`Selection`] (if any), the multi-click
/// tracker, whether a drag is in progress, and the lifecycle bookkeeping used
/// to implement the pinned rule "selection clears on new output that scrolls
/// the region [or] on resize" (`docs/devel/tasks/
/// P6.5-terminal-selection-copy-paste.md`) — see [`invalidate_if_stale`].
///
/// "Clears on focus change" is implemented by the controller calling
/// [`clear`](Self::clear) directly when it detects the active tab or the
/// focused pane within a tab has changed (`sessions.rs`'s `tick`/`tick_tab`).
#[derive(Debug, Default)]
pub(crate) struct PaneSelectionState {
    selection: Option<Selection>,
    /// The selected cells' content as of the last time `selection` was set —
    /// compared against fresh snapshots to detect "the thing I selected
    /// changed under me" (scrolled away, overwritten, or a resize altered
    /// which cells even exist at that row/col).
    baseline: Vec<Cell>,
    click: ClickTracker,
    dragging: bool,
}

/// Pointer button/kind discriminants shared with `crate::input`'s Slint
/// wire format (`1`=left, `1`=press, `2`=release, `3`=move) — duplicated here
/// as named constants rather than importing `crate::input` (which is a
/// leaf module with no reason to depend back on `selection`).
const BTN_LEFT: i32 = 1;
const KIND_PRESS: i32 = 1;
const KIND_RELEASE: i32 = 2;
const KIND_MOVE: i32 = 3;

impl PaneSelectionState {
    /// The live selection, if any (e.g. to pass into the renderer or to copy).
    pub(crate) fn selection(&self) -> Option<&Selection> {
        self.selection.as_ref()
    }

    /// Drop the current selection (lifecycle: resize / new-output-scroll /
    /// focus-change per the module doc).
    pub(crate) fn clear(&mut self) {
        self.selection = None;
        self.baseline.clear();
    }

    /// Handle a terminal-surface pointer event for selection purposes:
    /// left-press classifies as single/double/triple click (char/word/line
    /// selection); left-move while dragging extends the char selection;
    /// any release ends the drag. `snap`/`cols` are the pane's most recent
    /// grid snapshot (used to expand word/line bounds and to capture the
    /// staleness baseline) — `None` degrades to a bare drag with no
    /// word/line expansion (the pane has not produced a snapshot yet).
    ///
    /// Returns `true` iff the visible [`Selection`] geometry actually changed
    /// (created, extended, or — implicitly, via [`clear`](Self::clear), which
    /// callers invoke separately — removed). P6.8 bundled fix (F-perf,
    /// P6.17 finding R1): the controller uses this to gate the forced
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
        match (button, kind) {
            (BTN_LEFT, KIND_PRESS) => {
                let n = self.click.register(cell, now);
                let sel = match (n, snap) {
                    (2, Some(snap)) => {
                        let (from, to) = word_bounds(snap, cell.0, cell.1);
                        self.dragging = false;
                        Selection::new(
                            SelectionPoint {
                                row: cell.0,
                                col: from,
                            },
                            SelectionPoint {
                                row: cell.0,
                                col: to,
                            },
                        )
                    }
                    (n, Some(snap)) if n >= 3 => {
                        let (from, to) = line_bounds(snap.size.cols);
                        self.dragging = false;
                        Selection::new(
                            SelectionPoint {
                                row: cell.0,
                                col: from,
                            },
                            SelectionPoint {
                                row: cell.0,
                                col: to,
                            },
                        )
                    }
                    _ => {
                        self.dragging = true;
                        Selection::new(
                            SelectionPoint {
                                row: cell.0,
                                col: cell.1,
                            },
                            SelectionPoint {
                                row: cell.0,
                                col: cell.1,
                            },
                        )
                    }
                };
                self.selection = Some(sel);
                if let Some(snap) = snap {
                    self.rebaseline(snap);
                }
                true
            }
            (BTN_LEFT, KIND_MOVE) if self.dragging => {
                let new_cursor = SelectionPoint {
                    row: cell.0,
                    col: cell.1,
                };
                let changed = match &mut self.selection {
                    Some(sel) if sel.cursor != new_cursor => {
                        sel.cursor = new_cursor;
                        true
                    }
                    _ => false,
                };
                if changed && let Some(snap) = snap {
                    self.rebaseline(snap);
                }
                changed
            }
            (_, KIND_RELEASE) => {
                self.dragging = false;
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
    fn plain_click_then_drag_creates_char_selection() {
        let snap = row_snap(&["hello world"], 11);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0);
        s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 4), Some(&snap), t0);
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
        s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 2), Some(&snap), t0);
        let (start, end) = s.selection().unwrap().normalized();
        assert_eq!((start.col, end.col), (2, 6));
    }

    #[test]
    fn double_click_selects_word_and_stops_dragging() {
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
        // A stray move after a word-click must not extend it (dragging=false).
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
    fn release_without_drag_leaves_a_single_cell_selection_but_stops_dragging() {
        // Matches the pinned model: creating the Selection happens on press;
        // whether a *visible/copyable* highlight is desirable for a pure
        // click-no-drag is a product nicety left to the renderer/UX, but the
        // state machine itself must not keep "dragging" true after release.
        let snap = row_snap(&["x"], 1);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0);
        s.on_pointer(BTN_LEFT, KIND_RELEASE, (0, 0), Some(&snap), t0);
        assert!(!s.dragging);
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

    // ── P6.8 bundled fix (F-perf, P6.17 finding R1): on_pointer's "changed" ──
    // return value is exactly the render-gating signal `sessions.rs`'s
    // `wire_pointer` uses to skip the forced re-render on events that didn't
    // touch the selection -- these assert that signal is correct.

    #[test]
    fn press_reports_changed() {
        let snap = row_snap(&["abc"], 3);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        assert!(s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0));
    }

    #[test]
    fn dragging_move_to_a_new_cell_reports_changed() {
        let snap = row_snap(&["abcdef"], 6);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0);
        assert!(s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 3), Some(&snap), t0));
    }

    #[test]
    fn dragging_move_to_the_same_cell_reports_unchanged() {
        // The drag cursor didn't actually move to a new cell -- e.g. two
        // motion events land in the same cell -- there is nothing new to
        // paint, so this must report `false` (a real-world analogue of a
        // hover-only move, at the drag layer).
        let snap = row_snap(&["abcdef"], 6);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 2), Some(&snap), t0);
        assert!(!s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 2), Some(&snap), t0));
    }

    #[test]
    fn button_less_hover_move_reports_unchanged() {
        // The exact case P6.17 finding R1 flagged: a plain move with no
        // button held (not dragging) must never report a selection change --
        // this is the "hover-only move" the F-perf gate exists to skip.
        let snap = row_snap(&["abcdef"], 6);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        assert!(!s.on_pointer(BTN_LEFT, KIND_MOVE, (0, 3), Some(&snap), t0));
    }

    #[test]
    fn release_reports_unchanged() {
        let snap = row_snap(&["abc"], 3);
        let mut s = PaneSelectionState::default();
        let t0 = Instant::now();
        s.on_pointer(BTN_LEFT, KIND_PRESS, (0, 0), Some(&snap), t0);
        assert!(!s.on_pointer(BTN_LEFT, KIND_RELEASE, (0, 0), Some(&snap), t0));
    }
}

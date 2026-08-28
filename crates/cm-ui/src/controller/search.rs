//! Whole-buffer terminal search (P6.7, `Ctrl⇧F`): pure match-finding logic,
//! the per-tab [`SearchState`] lifecycle, and the wiring for the search
//! overlay's callbacks + the `Ctrl⇧F` / in-overlay keyboard shortcuts.
//!
//! Scoping decisions (see the task report):
//! - Search targets the pane that was focused when the overlay opened. The
//!   stable pane index keeps split-pane Find aligned with the same contextual
//!   action target as Copy/Paste and RDP send-key commands.
//! - Matching is always case-insensitive; the spec calls a case-fold toggle
//!   optional and no UI control for it is exposed (`find_matches` still
//!   takes a `case_sensitive` param — it's independently useful/tested — but
//!   [`SearchState`] always passes `false`).

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc::Receiver;

use cm_session::{Session, SessionInput};
use slint::{ComponentHandle, SharedString};

use crate::AppWindow;
use crate::input;
use crate::terminal_renderer::SearchMatch;

use super::*;

/// Hard cap on the number of matches kept (CONVENTIONS §2: bound every
/// loop/allocation driven by derived/untrusted-shaped input) — a common
/// single-character query across a full 10k-line buffer could otherwise
/// produce an unusably large match list.
const MAX_SEARCH_MATCHES: usize = 5000;

pub(super) fn wire_search(ctx: &Ctx) {
    wire_search_edited(ctx);
    wire_search_next(ctx);
    wire_search_prev(ctx);
    wire_search_close(ctx);
}

fn wire_search_edited(ctx: &Ctx) {
    ctx.ui.on_search_edited({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |query| {
            if let Some(ui) = weak.upgrade() {
                edit_search_query(&ui, &state, query.to_string());
            }
        }
    });
}

fn wire_search_next(ctx: &Ctx) {
    ctx.ui.on_search_next({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                advance_search(&ui, &state, true);
            }
        }
    });
}

fn wire_search_prev(ctx: &Ctx) {
    ctx.ui.on_search_prev({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                advance_search(&ui, &state, false);
            }
        }
    });
}

fn wire_search_close(ctx: &Ctx) {
    ctx.ui.on_search_close({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                close_search(&ui, &state);
            }
        }
    });
}

/// Open the search overlay for the active tab (idempotent) and kick off a
/// buffer-text request so a previously-typed query (if any) has something to
/// search against immediately.
pub(super) fn open_search(ui: &AppWindow, state: &Rc<RefCell<State>>) {
    ui.set_terminal_search_open(true);
    {
        let mut st = state.borrow_mut();
        let active = st.active;
        if let Some(tab) = st.tabs.get_mut(active) {
            let target = tab.pane_group.focused();
            if target == 0 {
                if matches!(tab.session.surface(), cm_session::Surface::TerminalGrid(_)) {
                    let session: &dyn Session = tab.session.as_ref();
                    tab.search.open(target, session);
                }
            } else if let Some(pane) = tab.extra_panes.get(target - 1)
                && matches!(pane.session.surface(), cm_session::Surface::TerminalGrid(_))
            {
                let session: &dyn Session = pane.session.as_ref();
                tab.search.open(target, session);
            }
        }
    }
    refresh_search_ui(ui, state);
}

fn close_search(ui: &AppWindow, state: &Rc<RefCell<State>>) {
    ui.set_terminal_search_open(false);
    let mut st = state.borrow_mut();
    let active = st.active;
    if let Some(tab) = st.tabs.get_mut(active) {
        tab.search.close();
    }
}

fn edit_search_query(ui: &AppWindow, state: &Rc<RefCell<State>>, query: String) {
    ui.set_terminal_search_query(SharedString::from(query.as_str()));
    {
        let mut st = state.borrow_mut();
        let active = st.active;
        if let Some(tab) = st.tabs.get_mut(active) {
            let target = tab.search.target_pane();
            if target == 0 {
                let session: &dyn Session = tab.session.as_ref();
                tab.search.set_query(query, session);
            } else if let Some(pane) = tab.extra_panes.get(target - 1) {
                let session: &dyn Session = pane.session.as_ref();
                tab.search.set_query(query, session);
            }
        }
    }
    refresh_search_ui(ui, state);
}

fn advance_search(ui: &AppWindow, state: &Rc<RefCell<State>>, forward: bool) {
    let mut st = state.borrow_mut();
    let active = st.active;
    let Some(tab) = st.tabs.get_mut(active) else {
        return;
    };
    let Some(target_row) = tab.search.advance(forward) else {
        return;
    };
    let target = tab.search.target_pane();
    if target == 0 {
        let Some(last) = tab.last.as_ref() else {
            return;
        };
        let offset = offset_to_show_row(last.scrollback_len, target_row);
        tab.session.send_input(SessionInput::Scroll(offset));
    } else {
        let Some(pane) = tab.extra_panes.get(target - 1) else {
            return;
        };
        let Some(last) = pane.last.as_ref() else {
            return;
        };
        let offset = offset_to_show_row(last.scrollback_len, target_row);
        pane.session.send_input(SessionInput::Scroll(offset));
    }
    drop(st);
    refresh_search_ui(ui, state);
}

fn refresh_search_ui(ui: &AppWindow, state: &Rc<RefCell<State>>) {
    let st = state.borrow();
    refresh_search_ui_from(ui, &st);
}

/// Push the active tab's current match count / current-match index to the UI
/// (the overlay's "N/M" readout). Takes `&State` directly (rather than
/// `&Rc<RefCell<State>>`) so `sessions::tick_tab` — which already holds a
/// `&mut State` borrow — can call it without a second, conflicting borrow.
pub(super) fn refresh_search_ui_from(ui: &AppWindow, st: &State) {
    let Some(tab) = st.tabs.get(st.active) else {
        return;
    };
    ui.set_terminal_search_match_count(tab.search.matches().len() as i32);
    ui.set_terminal_search_current_index(tab.search.current().map_or(-1, |i| i as i32));
}

/// Route to the search overlay's editing keys when it is open — mirrors
/// `palette::handle_palette_key`'s "the terminal FocusScope still forwards
/// keys here" pattern (`sessions.rs`'s `wire_key_input` checks
/// `ui.get_terminal_search_open()` first, exactly like `palette_open`).
/// `Ctrl⇧F` here closes the overlay (opening it is handled by the ordinary
/// Ctrl⇧ dispatch table when *not* already open).
pub(super) fn handle_search_key(
    ui: &AppWindow,
    state: &Rc<RefCell<State>>,
    text: &str,
    special: i32,
    mods: i32,
) {
    let ctrl_shift =
        mods & (input::MOD_CTRL | input::MOD_SHIFT) == (input::MOD_CTRL | input::MOD_SHIFT);
    if ctrl_shift && matches!(text, "f" | "F") {
        close_search(ui, state);
        return;
    }
    match special {
        4 => close_search(ui, state), // Escape
        1 if mods & input::MOD_SHIFT != 0 => advance_search(ui, state, false), // Shift+Enter -> prev
        1 => advance_search(ui, state, true),                                  // Enter -> next
        3 if mods & (input::MOD_CTRL | input::MOD_ALT) == 0 => {
            // Backspace.
            let mut q = ui.get_terminal_search_query().to_string();
            q.pop();
            edit_search_query(ui, state, q);
        }
        0 if mods & (input::MOD_CTRL | input::MOD_ALT) == 0 && !text.is_empty() => {
            let q = format!("{}{}", ui.get_terminal_search_query(), text);
            edit_search_query(ui, state, q);
        }
        _ => {}
    }
}

/// Find every occurrence of `query` in `lines` (oldest-first, one entry per
/// buffer row — the shape `TerminalEngine::buffer_text` returns). Case-folds
/// unless `case_sensitive`. Empty query -> no matches (never "everything
/// matches" — CONVENTIONS §2 empty-input case). Matching is by Unicode
/// scalar, not byte offset, so match columns line up with terminal cells for
/// the common single-scalar-per-cell case; combining-mark grapheme clusters
/// share the same simplification `terminal_renderer`'s glyph draw already
/// has (first scalar only).
pub(crate) fn find_matches(
    lines: &[String],
    query: &str,
    case_sensitive: bool,
) -> Vec<SearchMatch> {
    if query.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    'lines: for (i, line) in lines.iter().enumerate() {
        let Ok(row) = u16::try_from(i) else { break };
        let (hay, needle): (Vec<char>, Vec<char>) = if case_sensitive {
            (line.chars().collect(), query.chars().collect())
        } else {
            (
                line.to_lowercase().chars().collect(),
                query.to_lowercase().chars().collect(),
            )
        };
        let n = needle.len();
        if n == 0 || hay.len() < n {
            continue;
        }
        for start in 0..=(hay.len() - n) {
            if hay[start..start + n] == needle[..] {
                let col_start = u16::try_from(start).unwrap_or(u16::MAX);
                let col_end = u16::try_from(start + n - 1).unwrap_or(u16::MAX);
                out.push(SearchMatch {
                    row,
                    col_start,
                    col_end,
                });
                if out.len() >= MAX_SEARCH_MATCHES {
                    break 'lines;
                }
            }
        }
    }
    out
}

/// The scroll offset (lines above the tail) that brings absolute buffer row
/// `target_row` into view, given the pane's current `scrollback_len`. Places
/// the match at the top of the viewport when it is within scrollback;
/// saturates to `0` (tail) when `target_row` is in the live active region,
/// where it is already visible without scrolling.
pub(crate) fn offset_to_show_row(scrollback_len: u32, target_row: u16) -> u32 {
    scrollback_len.saturating_sub(u32::from(target_row))
}

/// Per-tab search-overlay state (P6.7): open/query/matches/current index,
/// plus the pending [`Receiver`] awaiting a `Session::request_search_text`
/// reply. Lives on [`Tab`] (mirrors [`crate::selection::PaneSelectionState`]'s
/// per-tab home).
#[derive(Default)]
pub(crate) struct SearchState {
    open: bool,
    target_pane: usize,
    query: String,
    matches: Vec<SearchMatch>,
    current: Option<usize>,
    pending: Option<Receiver<Vec<String>>>,
}

impl SearchState {
    pub(crate) fn is_open(&self) -> bool {
        self.open
    }

    pub(crate) fn matches(&self) -> &[SearchMatch] {
        &self.matches
    }

    pub(crate) fn current(&self) -> Option<usize> {
        self.current
    }

    pub(crate) fn target_pane(&self) -> usize {
        self.target_pane
    }

    pub(crate) fn applies_to(&self, pane: usize) -> bool {
        self.open && self.target_pane == pane
    }

    fn current_match(&self) -> Option<SearchMatch> {
        self.current.and_then(|i| self.matches.get(i)).copied()
    }

    /// Open the overlay (idempotent) and (re-)request the buffer text.
    pub(crate) fn open(&mut self, target_pane: usize, session: &dyn Session) {
        self.open = true;
        self.target_pane = target_pane;
        self.request_text(session);
    }

    /// Close the overlay. Deliberately keeps `query`/`matches` (reopening
    /// resumes the last search rather than starting blank — common find-bar
    /// UX); only `open` and the in-flight request are reset.
    pub(crate) fn close(&mut self) {
        self.open = false;
        self.pending = None;
    }

    fn set_query(&mut self, query: String, session: &dyn Session) {
        self.query = query;
        self.matches.clear();
        self.current = None;
        self.request_text(session);
    }

    fn request_text(&mut self, session: &dyn Session) {
        let (tx, rx) = std::sync::mpsc::channel();
        session.request_search_text(tx);
        self.pending = Some(rx);
    }

    /// Drain a pending buffer-text reply, if one has arrived, and recompute
    /// matches. Call once per tick while `is_open()` (mirrors how
    /// `sessions::tick_tab` polls snapshot channels). Returns `true` if the
    /// match list was (re)computed, so the caller knows to force a render and
    /// refresh the overlay's match-count UI.
    pub(crate) fn poll(&mut self) -> bool {
        let Some(rx) = &self.pending else {
            return false;
        };
        let Ok(lines) = rx.try_recv() else {
            return false;
        };
        self.pending = None;
        // Case-fold toggle is optional per spec and not exposed in the UI —
        // always case-insensitive (see the module doc).
        self.matches = find_matches(&lines, &self.query, false);
        self.current = if self.matches.is_empty() {
            None
        } else {
            Some(0)
        };
        true
    }

    /// Move to the next/previous match (wrapping). Returns the absolute
    /// buffer row to scroll into view, if there is a match to go to.
    fn advance(&mut self, forward: bool) -> Option<u16> {
        if self.matches.is_empty() {
            return None;
        }
        let n = self.matches.len();
        self.current = Some(match self.current {
            None => 0,
            Some(i) if forward => (i + 1) % n,
            Some(i) => (i + n - 1) % n,
        });
        self.current_match().map(|m| m.row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(rows: &[&str]) -> Vec<String> {
        rows.iter().map(|s| (*s).to_owned()).collect()
    }

    // ── find_matches ─────────────────────────────────────────────────────

    #[test]
    fn empty_query_matches_nothing() {
        assert!(find_matches(&lines(&["hello", "world"]), "", false).is_empty());
    }

    #[test]
    fn finds_a_single_hit() {
        let m = find_matches(&lines(&["hello world"]), "world", true);
        assert_eq!(
            m,
            vec![SearchMatch {
                row: 0,
                col_start: 6,
                col_end: 10
            }]
        );
    }

    #[test]
    fn finds_hits_across_multiple_lines_oldest_first() {
        let m = find_matches(&lines(&["foo", "bar foo", "foo"]), "foo", true);
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].row, 0);
        assert_eq!(m[1].row, 1);
        assert_eq!(m[1].col_start, 4);
        assert_eq!(m[2].row, 2);
    }

    #[test]
    fn finds_overlapping_or_adjacent_hits_on_the_same_line() {
        let m = find_matches(&lines(&["aaaa"]), "aa", true);
        // "aaaa" contains "aa" at offsets 0,1,2 (overlap-permitting scan).
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn case_insensitive_by_request() {
        let m = find_matches(&lines(&["Hello World"]), "world", false);
        assert_eq!(m.len(), 1);
        assert!(find_matches(&lines(&["Hello World"]), "world", true).is_empty());
    }

    #[test]
    fn no_match_returns_empty() {
        assert!(find_matches(&lines(&["hello", "world"]), "xyz", true).is_empty());
    }

    #[test]
    fn maximal_input_is_capped_not_hung() {
        // A common single-character query across a large buffer must not
        // produce an unbounded match list (CONVENTIONS §2 bounded-loop rule).
        let big: Vec<String> = (0..2000).map(|_| "aaaaaaaaaa".to_owned()).collect();
        let m = find_matches(&big, "a", true);
        assert_eq!(m.len(), MAX_SEARCH_MATCHES);
    }

    #[test]
    fn query_longer_than_line_does_not_panic() {
        assert!(find_matches(&lines(&["ab"]), "abcdef", true).is_empty());
    }

    // ── offset_to_show_row ───────────────────────────────────────────────

    #[test]
    fn offset_to_show_row_in_scrollback() {
        assert_eq!(offset_to_show_row(100, 40), 60);
    }

    #[test]
    fn offset_to_show_row_in_active_region_saturates_to_tail() {
        // A row at/after the tail needs no scrolling.
        assert_eq!(offset_to_show_row(50, 80), 0);
    }

    // ── SearchState ───────────────────────────────────────────────────────

    /// A no-op `Session` stub, just enough to exercise `SearchState` without
    /// spinning up a real engine/session thread.
    struct NoopSession {
        surface: cm_session::Surface,
    }
    impl NoopSession {
        fn new() -> Self {
            let (_tx, rx) = std::sync::mpsc::channel();
            Self {
                surface: cm_session::Surface::TerminalGrid(rx),
            }
        }
    }
    impl Session for NoopSession {
        fn surface(&self) -> &cm_session::Surface {
            &self.surface
        }
        fn status(&self) -> cm_session::SessionStatus {
            cm_session::SessionStatus::Connected
        }
        fn shutdown(&self) {}
        fn resize_px(&self, _w: u32, _h: u32) {}
        fn request_search_text(&self, reply: std::sync::mpsc::Sender<Vec<String>>) {
            let _ = reply.send(vec!["hello world".to_owned(), "another line".to_owned()]);
        }
    }

    #[test]
    fn search_state_open_query_poll_finds_matches() {
        let session = NoopSession::new();
        let mut s = SearchState::default();
        assert!(!s.is_open());
        s.open(0, &session);
        assert!(s.is_open());
        s.set_query("line".to_owned(), &session);
        assert!(s.poll(), "poll should pick up the queued reply");
        assert_eq!(s.matches().len(), 1);
        assert_eq!(s.current(), Some(0));
    }

    #[test]
    fn search_state_advance_wraps_and_reports_none_with_no_matches() {
        let session = NoopSession::new();
        let mut s = SearchState::default();
        // No query yet -> no matches -> advance is a no-op.
        assert_eq!(s.advance(true), None);

        s.open(0, &session);
        s.set_query("l".to_owned(), &session);
        s.poll();
        assert!(s.matches().len() >= 2, "'l' should hit both fixture lines");
        let first = s.advance(true).unwrap();
        // Cycling forward through every remaining match, plus one more, must
        // wrap back around to the first match (regardless of whether any two
        // matches happen to share the same row).
        for _ in 1..s.matches().len() {
            s.advance(true);
        }
        assert_eq!(s.advance(true), Some(first));
    }

    #[test]
    fn search_state_close_keeps_query_but_drops_pending() {
        let session = NoopSession::new();
        let mut s = SearchState::default();
        s.open(0, &session);
        s.set_query("hello".to_owned(), &session);
        s.close();
        assert!(!s.is_open());
        assert!(s.pending.is_none());
        assert_eq!(s.query, "hello");
    }
}

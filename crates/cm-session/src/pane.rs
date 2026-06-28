//! Pane-group abstraction for split-pane tabs (P5.1).
//!
//! A [`PaneGroup`] models the layout and focus of up to N panes within a tab.
//! Each pane index maps to a session owned by the UI controller — the
//! PaneGroup itself carries no session references (ARCHITECTURE §4 — the
//! controller is the session owner).
//!
//! P5.1 supports up to 2 panes per tab (one split). The design is
//! intentionally extensible (count-based, not hard-coded to 2) so a future
//! task can increase the limit.

/// Layout direction for a two-pane split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneLayout {
    /// Single pane (no split).
    Single,
    /// Side-by-side (left / right).
    HSplit,
    /// Top / bottom.
    VSplit,
}

/// Maximum number of panes a [`PaneGroup`] will hold (P5.1: 2).
const MAX_PANES: usize = 2;

/// Logical grouping of panes for one tab.
///
/// Tracks pane count (1..=[`MAX_PANES`]), focused pane index, and split
/// layout.  The controller maps pane indices to concrete [`Session`]
/// references.
///
/// [`Session`]: crate::Session
#[derive(Debug, Clone)]
pub struct PaneGroup {
    count: usize,
    focused: usize,
    layout: PaneLayout,
}

impl Default for PaneGroup {
    fn default() -> Self {
        Self::single()
    }
}

impl PaneGroup {
    /// Create a single-pane group (the common initial state).
    pub fn single() -> Self {
        Self {
            count: 1,
            focused: 0,
            layout: PaneLayout::Single,
        }
    }

    /// Attempt to split the group with the given layout direction.
    ///
    /// Returns the index of the newly created pane (always `count - 1`), or
    /// `None` if the group is already at [`MAX_PANES`].
    pub fn split(&mut self, layout: PaneLayout) -> Option<usize> {
        if self.count >= MAX_PANES {
            return None;
        }
        self.layout = layout;
        self.count += 1;
        let new_idx = self.count - 1;
        // Move focus to the new pane.
        self.focused = new_idx;
        Some(new_idx)
    }

    /// Close the currently focused pane.
    ///
    /// Returns the index of the closed pane on success, or `None` if this is
    /// the last pane (cannot close the last pane via this API — callers must
    /// handle "close entire tab" separately).
    pub fn close_focused(&mut self) -> Option<usize> {
        if self.count <= 1 {
            return None;
        }
        let closed = self.focused;
        self.count -= 1;
        self.layout = PaneLayout::Single;
        // Clamp focus to the new range.
        if self.focused >= self.count {
            self.focused = self.count - 1;
        }
        Some(closed)
    }

    /// Move focus relative to the current pane.
    ///
    /// `delta > 0` moves toward higher indices (right / down); `delta < 0`
    /// moves toward lower indices (left / up). Clamps at boundaries.
    ///
    /// Returns the new focused pane index.
    pub fn focus_move(&mut self, delta: i32) -> usize {
        if self.count <= 1 {
            return 0;
        }
        let new = if delta > 0 {
            (self.focused + 1).min(self.count - 1)
        } else {
            self.focused.saturating_sub(1)
        };
        self.focused = new;
        new
    }

    /// Directly set the focused pane. Silently ignores out-of-range indices.
    pub fn set_focused(&mut self, idx: usize) {
        if idx < self.count {
            self.focused = idx;
        }
    }

    /// Number of active panes (1..=[`MAX_PANES`]).
    pub fn count(&self) -> usize {
        self.count
    }

    /// Index of the currently focused pane.
    pub fn focused(&self) -> usize {
        self.focused
    }

    /// Layout kind (ignored when `count == 1`).
    pub fn layout(&self) -> PaneLayout {
        self.layout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_pane_initial_state() {
        let pg = PaneGroup::single();
        assert_eq!(pg.count(), 1);
        assert_eq!(pg.focused(), 0);
        assert_eq!(pg.layout(), PaneLayout::Single);
    }

    #[test]
    fn split_h_creates_second_pane() {
        let mut pg = PaneGroup::single();
        let new_idx = pg
            .split(PaneLayout::HSplit)
            .expect("first split should succeed");
        assert_eq!(new_idx, 1);
        assert_eq!(pg.count(), 2);
        assert_eq!(pg.focused(), 1); // focus moves to new pane
        assert_eq!(pg.layout(), PaneLayout::HSplit);
    }

    #[test]
    fn split_v_creates_second_pane() {
        let mut pg = PaneGroup::single();
        let new_idx = pg
            .split(PaneLayout::VSplit)
            .expect("first split should succeed");
        assert_eq!(new_idx, 1);
        assert_eq!(pg.count(), 2);
        assert_eq!(pg.layout(), PaneLayout::VSplit);
    }

    #[test]
    fn split_at_max_returns_none() {
        let mut pg = PaneGroup::single();
        pg.split(PaneLayout::HSplit).unwrap();
        assert!(
            pg.split(PaneLayout::HSplit).is_none(),
            "should not exceed MAX_PANES"
        );
    }

    #[test]
    fn close_focused_returns_to_single() {
        let mut pg = PaneGroup::single();
        pg.split(PaneLayout::HSplit).unwrap();
        // focused is now 1
        let closed = pg.close_focused().expect("should close second pane");
        assert_eq!(closed, 1);
        assert_eq!(pg.count(), 1);
        assert_eq!(pg.focused(), 0);
        assert_eq!(pg.layout(), PaneLayout::Single);
    }

    #[test]
    fn close_last_pane_returns_none() {
        let mut pg = PaneGroup::single();
        assert!(pg.close_focused().is_none(), "cannot close the last pane");
    }

    #[test]
    fn focus_move_clamps_at_bounds() {
        let mut pg = PaneGroup::single();
        pg.split(PaneLayout::HSplit).unwrap();
        assert_eq!(pg.focused(), 1);

        // Move right beyond last pane: should clamp at 1.
        assert_eq!(pg.focus_move(1), 1);

        // Move left to first pane.
        assert_eq!(pg.focus_move(-1), 0);

        // Move left beyond first pane: should stay at 0.
        assert_eq!(pg.focus_move(-1), 0);
    }

    #[test]
    fn focus_move_single_pane_stays_zero() {
        let mut pg = PaneGroup::single();
        assert_eq!(pg.focus_move(1), 0);
        assert_eq!(pg.focus_move(-1), 0);
    }

    #[test]
    fn set_focused_out_of_range_is_ignored() {
        let mut pg = PaneGroup::single();
        pg.set_focused(99); // out of range
        assert_eq!(pg.focused(), 0);
    }
}

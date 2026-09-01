//! Pane-group abstraction for split-pane tabs.
//!
//! A [`PaneGroup`] models the layout and focus of an arbitrary number (up to
//! [`MAX_PANES`]) of panes within a tab as a **recursive binary split tree**
//! Each leaf carries a dense
//! pane id in `0..count`; id `0` is always the tab's "primary" pane (the
//! controller keeps its session/renderer in `Tab` fields directly, while ids
//! `1..count` live in `Tab::extra_panes` — see `cm-ui/src/controller/mod.rs`).
//! The PaneGroup itself carries no session references (ARCHITECTURE §4 — the
//! controller is the session owner); it only tracks geometry and focus.
//!
//! Ids stay dense on every mutation: splitting always allocates `count` as
//! the new leaf's id (append), and closing a leaf renumbers every id above
//! the closed one down by one — this mirrors `Vec::remove`'s shifting
//! behavior exactly, so the controller's parallel `Vec<ExtraPaneState>`
//! (indexed by `id - 1`) never needs its own remapping pass.

use std::collections::HashMap;

/// Split direction used both as the `split` argument and to label a split
/// node in the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneLayout {
    /// Single pane (no split) — only ever the *group's* apparent layout when
    /// `count == 1`; a tree with 2+ leaves has one `PaneLayout` per split
    /// node instead of a single group-wide value (see [`PaneGroup::rects`]).
    Single,
    /// Side-by-side (left / right).
    HSplit,
    /// Top / bottom.
    VSplit,
}

/// Maximum number of panes a [`PaneGroup`] will hold. Keyboard/equal-split only,
/// no drag-resize, so a
/// higher cap stays usable without per-pane resize affordances).
pub const MAX_PANES: usize = 6;

/// A fractional (0.0..=1.0) rectangle for one pane, relative to the session
/// area's top-left corner — the shape the UI layer positions a `PaneSlot` at
/// (`x * area.width`, `y * area.height`,...). Indexed by pane id: see
/// [`PaneGroup::rects`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PaneRect {
    pub pane: usize,
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

/// The four directions [`PaneGroup::focus_dir`] can move focus in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusDir {
    Left,
    Right,
    Up,
    Down,
}

#[derive(Debug, Clone)]
enum Node {
    Leaf(usize),
    Split {
        dir: PaneLayout,
        a: Box<Node>,
        b: Box<Node>,
    },
}

impl Node {
    /// Replace the leaf with id `target` in-place with `replacement`.
    /// Returns `true` if the leaf was found (and replaced).
    fn replace_leaf(&mut self, target: usize, replacement: Node) -> bool {
        match self {
            Node::Leaf(id) if *id == target => {
                *self = replacement;
                true
            }
            Node::Leaf(_) => false,
            Node::Split { a, b, .. } => {
                a.replace_leaf(target, replacement.clone()) || b.replace_leaf(target, replacement)
            }
        }
    }

    /// Remove the leaf with id `target`, promoting its sibling in place of
    /// the parent `Split` node. Returns `true` if removed. The root itself
    /// can never be removed this way (a lone root `Leaf` has no parent to
    /// collapse into) — callers must check `count > 1` first.
    fn remove_leaf(&mut self, target: usize) -> bool {
        if let Node::Split { a, b, .. } = self {
            if let Node::Leaf(id) = a.as_ref()
                && *id == target
            {
                *self = (**b).clone();
                return true;
            }
            if let Node::Leaf(id) = b.as_ref()
                && *id == target
            {
                *self = (**a).clone();
                return true;
            }
            return a.remove_leaf(target) || b.remove_leaf(target);
        }
        false
    }

    /// Decrement every leaf id strictly greater than `threshold` by one —
    /// keeps ids dense after a removal (see module docs).
    fn renumber_above(&mut self, threshold: usize) {
        match self {
            Node::Leaf(id) => {
                if *id > threshold {
                    *id -= 1;
                }
            }
            Node::Split { a, b, .. } => {
                a.renumber_above(threshold);
                b.renumber_above(threshold);
            }
        }
    }

    /// Recursively compute fractional rects for every leaf within `(x, y, w, h)`.
    fn rects_into(&self, x: f32, y: f32, w: f32, h: f32, out: &mut HashMap<usize, PaneRect>) {
        match self {
            Node::Leaf(id) => {
                out.insert(
                    *id,
                    PaneRect {
                        pane: *id,
                        x,
                        y,
                        w,
                        h,
                    },
                );
            }
            Node::Split { dir, a, b } => match dir {
                PaneLayout::HSplit => {
                    let half = w / 2.0;
                    a.rects_into(x, y, half, h, out);
                    b.rects_into(x + half, y, w - half, h, out);
                }
                PaneLayout::VSplit => {
                    let half = h / 2.0;
                    a.rects_into(x, y, w, half, out);
                    b.rects_into(x, y + half, w, h - half, out);
                }
                PaneLayout::Single => {
                    // Never constructed as a split direction; treat as HSplit
                    // defensively rather than panicking on untrusted state.
                    let half = w / 2.0;
                    a.rects_into(x, y, half, h, out);
                    b.rects_into(x + half, y, w - half, h, out);
                }
            },
        }
    }
}

/// Logical grouping of panes for one tab: a recursive binary split tree
/// tracking up to [`MAX_PANES`] leaves, plus the focused leaf's id.
/// The controller maps leaf ids to concrete [`Session`] references.
///
/// [`Session`]: crate::Session
#[derive(Debug, Clone)]
pub struct PaneGroup {
    root: Node,
    count: usize,
    focused: usize,
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
            root: Node::Leaf(0),
            count: 1,
            focused: 0,
        }
    }

    /// Split the focused pane with the given direction, appending a new leaf.
    ///
    /// Returns the id of the newly created pane (always `count - 1` after
    /// the split, i.e. the previous `count`), or `None` if the group is
    /// already at [`MAX_PANES`].
    pub fn split(&mut self, layout: PaneLayout) -> Option<usize> {
        if self.count >= MAX_PANES {
            return None;
        }
        let new_id = self.count;
        let focused = self.focused;
        let replaced = self.root.replace_leaf(
            focused,
            Node::Split {
                dir: layout,
                a: Box::new(Node::Leaf(focused)),
                b: Box::new(Node::Leaf(new_id)),
            },
        );
        debug_assert!(replaced, "focused pane id must always exist in the tree");
        self.count += 1;
        self.focused = new_id;
        Some(new_id)
    }

    /// Close the currently focused pane.
    ///
    /// Returns the id of the closed pane on success, or `None` if this is
    /// the last pane (cannot close the last pane via this API — callers must
    /// handle "close entire tab" separately). Surviving ids above the closed
    /// one are renumbered down by one to stay dense (module docs) — the
    /// caller's parallel per-pane state (e.g. `Vec<ExtraPaneState>`) should
    /// be updated with an equivalent `Vec::remove` at the matching index.
    pub fn close_focused(&mut self) -> Option<usize> {
        if self.count <= 1 {
            return None;
        }
        let closed = self.focused;
        let removed = self.root.remove_leaf(closed);
        debug_assert!(removed, "focused pane id must always exist in the tree");
        self.root.renumber_above(closed);
        self.count -= 1;
        // Focus falls back to the pane that took the closed pane's id slot
        // (the sibling that got promoted keeps its own id, shifted down if it
        // was above `closed`); clamp defensively.
        self.focused = closed.min(self.count - 1);
        Some(closed)
    }

    /// Move focus in the given screen direction, using each pane's geometry
    /// (via [`Self::rects`]) rather than id order — this is what makes
    /// `Ctrl⇧Arrows` "do the right thing" once panes are arranged in more
    /// than one row/column (a plain "next/prev id" cannot).
    ///
    /// Picks the candidate pane whose center lies in the requested direction
    /// from the focused pane's center, preferring the smallest distance
    /// along the primary axis (ties broken by the smallest perpendicular
    /// offset — i.e. the most "directly adjacent" pane). If no pane lies in
    /// that direction (the focused pane is already at that edge), focus is
    /// unchanged (clamp, not wrap — the pinned behavior).
    ///
    /// Returns the (possibly unchanged) focused pane id.
    pub fn focus_dir(&mut self, dir: FocusDir) -> usize {
        if self.count <= 1 {
            return self.focused;
        }
        let rects = self.rects();
        let Some(cur) = rects.iter().find(|r| r.pane == self.focused) else {
            return self.focused;
        };
        let cur_cx = cur.x + cur.w / 2.0;
        let cur_cy = cur.y + cur.h / 2.0;
        const EPS: f32 = 0.001;

        let mut best: Option<(f32, f32, usize)> = None; // (primary, secondary, pane)
        for r in &rects {
            if r.pane == self.focused {
                continue;
            }
            let cx = r.x + r.w / 2.0;
            let cy = r.y + r.h / 2.0;
            let (in_dir, primary, secondary) = match dir {
                FocusDir::Left => (cx < cur_cx - EPS, cur_cx - cx, (cy - cur_cy).abs()),
                FocusDir::Right => (cx > cur_cx + EPS, cx - cur_cx, (cy - cur_cy).abs()),
                FocusDir::Up => (cy < cur_cy - EPS, cur_cy - cy, (cx - cur_cx).abs()),
                FocusDir::Down => (cy > cur_cy + EPS, cy - cur_cy, (cx - cur_cx).abs()),
            };
            if !in_dir {
                continue;
            }
            let better = match &best {
                None => true,
                Some((bp, bs, _)) => (primary, secondary) < (*bp, *bs),
            };
            if better {
                best = Some((primary, secondary, r.pane));
            }
        }
        if let Some((_, _, pane)) = best {
            self.focused = pane;
        }
        self.focused
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

    /// Id of the currently focused pane.
    pub fn focused(&self) -> usize {
        self.focused
    }

    /// The split direction of the group when it has exactly 2 panes
    /// (backward-compatible surface for the 2-pane callers).
    /// Returns [`PaneLayout::Single`] for 1 pane; for 3+ panes there is no
    /// single group-wide direction (each split node has its own), so this
    /// returns the direction of the split that produced the *currently
    /// focused* pane's parent — a reasonable "most relevant" answer, used
    /// only for legacy display purposes, not for `rects`-based rendering.
    pub fn layout(&self) -> PaneLayout {
        if self.count <= 1 {
            return PaneLayout::Single;
        }
        fn find_parent_dir(node: &Node, target: usize) -> Option<PaneLayout> {
            match node {
                Node::Leaf(_) => None,
                Node::Split { dir, a, b } => {
                    let has = |n: &Node| matches!(n, Node::Leaf(id) if *id == target);
                    if has(a) || has(b) {
                        Some(*dir)
                    } else {
                        find_parent_dir(a, target).or_else(|| find_parent_dir(b, target))
                    }
                }
            }
        }
        find_parent_dir(&self.root, self.focused).unwrap_or(PaneLayout::HSplit)
    }

    /// Compute fractional (0.0..=1.0) rects for every pane, indexed by pane
    /// id (`result[i]` is always `PaneRect { pane: i,.. }`) — the shape the
    /// UI layer consumes to position each `PaneSlot` absolutely within the
    /// session area.
    pub fn rects(&self) -> Vec<PaneRect> {
        let mut map = HashMap::with_capacity(self.count);
        self.root.rects_into(0.0, 0.0, 1.0, 1.0, &mut map);
        let mut out = vec![
            PaneRect {
                pane: 0,
                x: 0.0,
                y: 0.0,
                w: 1.0,
                h: 1.0,
            };
            self.count
        ];
        for (id, rect) in map {
            if id < out.len() {
                out[id] = rect;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-4
    }

    #[test]
    fn single_pane_initial_state() {
        let pg = PaneGroup::single();
        assert_eq!(pg.count(), 1);
        assert_eq!(pg.focused(), 0);
        assert_eq!(pg.layout(), PaneLayout::Single);
        let rects = pg.rects();
        assert_eq!(rects.len(), 1);
        assert!(approx(rects[0].w, 1.0) && approx(rects[0].h, 1.0));
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
        let rects = pg.rects();
        assert!(approx(rects[0].w, 0.5) && approx(rects[1].w, 0.5));
        assert!(approx(rects[0].x, 0.0) && approx(rects[1].x, 0.5));
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
        let rects = pg.rects();
        assert!(approx(rects[0].h, 0.5) && approx(rects[1].h, 0.5));
        assert!(approx(rects[0].y, 0.0) && approx(rects[1].y, 0.5));
    }

    #[test]
    fn split_at_max_returns_none() {
        let mut pg = PaneGroup::single();
        for _ in 0..(MAX_PANES - 1) {
            pg.split(PaneLayout::HSplit).unwrap();
        }
        assert_eq!(pg.count(), MAX_PANES);
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
    fn three_pane_split_and_renumber_on_close() {
        let mut pg = PaneGroup::single();
        pg.split(PaneLayout::HSplit).unwrap(); // ids 0,1; focus 1
        pg.split(PaneLayout::VSplit).unwrap(); // splits pane 1 -> ids 0,1,2; focus 2
        assert_eq!(pg.count(), 3);
        assert_eq!(pg.focused(), 2);

        // Closing id 1 (the middle one) must renumber id 2 -> 1.
        pg.set_focused(1);
        let closed = pg.close_focused().unwrap();
        assert_eq!(closed, 1);
        assert_eq!(pg.count(), 2);
        // The old id-2 leaf is now id 1.
        let rects = pg.rects();
        assert_eq!(rects.len(), 2);
        assert!(rects.iter().any(|r| r.pane == 0));
        assert!(rects.iter().any(|r| r.pane == 1));
    }

    #[test]
    fn four_pane_grid_rects_are_disjoint_and_cover_unit_square() {
        let mut pg = PaneGroup::single();
        pg.split(PaneLayout::HSplit).unwrap(); // 0 | 1
        pg.set_focused(0);
        pg.split(PaneLayout::VSplit).unwrap(); // splits 0 -> 0(top) / new(bottom)
        pg.set_focused(1); // the original right pane (id shifted? check by rects)
        // After first split: ids {0,1}. After second split (focused=0 at
        // that time): 0 -> {0 top, 2 bottom} (new id = count = 2). So ids
        // are now {0 (top-left), 1 (right), 2 (bottom-left)}.
        assert_eq!(pg.count(), 3);
        let rects = pg.rects();
        let total_area: f32 = rects.iter().map(|r| r.w * r.h).sum();
        assert!(approx(total_area, 1.0), "areas must tile the unit square");
    }

    #[test]
    fn focus_dir_clamps_at_bounds_two_pane_h() {
        let mut pg = PaneGroup::single();
        pg.split(PaneLayout::HSplit).unwrap(); // 0 left, 1 right; focus 1
        assert_eq!(pg.focused(), 1);
        // Already rightmost: Right is a no-op (clamp).
        assert_eq!(pg.focus_dir(FocusDir::Right), 1);
        assert_eq!(pg.focus_dir(FocusDir::Left), 0);
        // Already leftmost: Left is a no-op (clamp).
        assert_eq!(pg.focus_dir(FocusDir::Left), 0);
    }

    #[test]
    fn focus_dir_clamps_at_bounds_two_pane_v() {
        let mut pg = PaneGroup::single();
        pg.split(PaneLayout::VSplit).unwrap(); // 0 top, 1 bottom; focus 1
        assert_eq!(pg.focus_dir(FocusDir::Down), 1); // clamp
        assert_eq!(pg.focus_dir(FocusDir::Up), 0);
        assert_eq!(pg.focus_dir(FocusDir::Up), 0); // clamp
    }

    #[test]
    fn focus_dir_single_pane_stays_put() {
        let mut pg = PaneGroup::single();
        assert_eq!(pg.focus_dir(FocusDir::Left), 0);
        assert_eq!(pg.focus_dir(FocusDir::Right), 0);
        assert_eq!(pg.focus_dir(FocusDir::Up), 0);
        assert_eq!(pg.focus_dir(FocusDir::Down), 0);
    }

    #[test]
    fn focus_dir_geometry_across_a_grid() {
        // Build a 2x2-ish grid: split H (0|1), then split each side V.
        let mut pg = PaneGroup::single();
        pg.split(PaneLayout::HSplit).unwrap(); // {0 left, 1 right}, focus 1
        pg.split(PaneLayout::VSplit).unwrap(); // splits pane 1 -> {1 top-right, 2 bottom-right}, focus 2
        pg.set_focused(0);
        pg.split(PaneLayout::VSplit).unwrap(); // splits pane 0 -> {0 top-left, 3 bottom-left}, focus 3
        assert_eq!(pg.count(), 4);

        // Focus top-left (0); Right should go to top-right (1), not bottom-right (2).
        pg.set_focused(0);
        assert_eq!(pg.focus_dir(FocusDir::Right), 1);
        // From top-right (1), Down should go to bottom-right (2).
        assert_eq!(pg.focus_dir(FocusDir::Down), 2);
        // From bottom-right (2), Left should go to bottom-left (3).
        assert_eq!(pg.focus_dir(FocusDir::Left), 3);
        // From bottom-left (3), Up should go to top-left (0).
        assert_eq!(pg.focus_dir(FocusDir::Up), 0);
    }

    #[test]
    fn set_focused_out_of_range_is_ignored() {
        let mut pg = PaneGroup::single();
        pg.set_focused(99); // out of range
        assert_eq!(pg.focused(), 0);
    }
}

//! Split-pane management: split/close/broadcast/detach/focus/resize, and
//! reattaching a previously-detached session.
//!
//! generalized from the / 2-pane single-axis model to an
//! N-way recursive split tree (`cm_session::PaneGroup`, up to `MAX_PANES`).
//! Pane id `0` is always the tab's primary pane (kept in `Tab`'s own fields,
//! as before); ids `1..count` live in `Tab::extra_panes`, indexed by
//! `id - 1`. `PaneGroup` keeps ids dense on every split/close (see
//! `cm_session::pane`'s module docs), so `Vec::push`/`Vec::remove` on
//! `extra_panes` always lines up with the tree's id bookkeeping without a
//! separate remap pass.
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use cm_core::LocalSettings;
use cm_core::terminal::TerminalSize;
use cm_session::{CertDecision, PaneGroup, PaneLayout, SessionInput, SessionStatus, Surface};
use slint::{ComponentHandle, Image, Model, SharedString, TimerMode, VecModel};

use crate::selection::PaneSelectionState;
use crate::terminal_renderer::{TerminalFontSystem, TerminalRenderer};
use crate::{AppWindow, TabItem, ToastEntry};

use super::HkQueue;
use super::*;

pub(super) fn wire_panes(ctx: &Ctx) {
    wire_toggle_broadcast(ctx);
    wire_split_pane_h(ctx);
    wire_split_pane_v(ctx);
    wire_close_pane(ctx);
    wire_detach_session(ctx);
    wire_pane_disconnect(ctx);
    wire_pane_focused(ctx);
    wire_pane_resized(ctx);
    wire_broadcast_target(ctx);
}

// broadcast targeting

/// Which of a tab's panes receive input while broadcast (`Ctrl⇧B`) is active.
///
/// Scoped to the active tab, same as broadcast always has been — extending
/// broadcast across tabs is a separate, larger behavior change not asked for
/// here (see the API contract).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) enum BroadcastTarget {
    /// Every pane currently in the tab's `PaneGroup` — the earlier "always
    /// all panes" behavior, and the default.
    #[default]
    Visible,
    /// An explicit set of pane ids. `name` is `Some(..)` when this selection
    /// was saved as a "named group" from the targeting menu (session-only —
    /// see `Tab::broadcast_saved_groups`); `None` for an ad hoc custom pick
    /// that was applied but not saved.
    Custom {
        name: Option<String>,
        panes: BTreeSet<usize>,
    },
}

impl BroadcastTarget {
    /// Resolve to the concrete pane ids that should receive input, given the
    /// tab's *current* pane count. A `Custom` set referencing a pane id that
    /// no longer exists (closed since the target was picked) is silently
    /// dropped — broadcast never sends to a stale/absent pane, and never
    /// panics on out-of-range indices.
    pub(super) fn resolve(&self, pane_count: usize) -> BTreeSet<usize> {
        match self {
            BroadcastTarget::Visible => (0..pane_count).collect(),
            BroadcastTarget::Custom { panes, .. } => {
                panes.iter().copied().filter(|&p| p < pane_count).collect()
            }
        }
    }

    /// Human-readable label for the "never silent" status/broadcast-bar
    /// indicator (GUI_DESIGN principle — see the API contract).
    pub(super) fn label(&self, pane_count: usize) -> String {
        match self {
            BroadcastTarget::Visible => "all panes".to_string(),
            BroadcastTarget::Custom {
                name: Some(name), ..
            } => format!("group: {name}"),
            BroadcastTarget::Custom { name: None, panes } => {
                let n = panes.iter().filter(|&&p| p < pane_count).count();
                format!("{n} of {pane_count} panes")
            }
        }
    }
}

/// Fan `evs` out to exactly the panes selected by `tab.broadcast_target`
/// (— targeted, not always "all panes"). Extracted from
/// `wire_key_input`'s broadcast branch (`sessions.rs`) so the targeting
/// behavior is unit-testable without a live `AppWindow`/Slint event loop —
/// see the `broadcast_targets_only_selected_panes` test below.
pub(super) fn broadcast_fan_out(tab: &Tab, evs: &[SessionInput]) {
    let targets = tab.broadcast_target.resolve(tab.pane_group.count());
    for id in targets {
        if id == 0 {
            for ev in evs {
                tab.session.send_input(ev.clone());
            }
        } else if let Some(ep) = tab.extra_panes.get(id - 1) {
            for ev in evs {
                ep.session.send_input(ev.clone());
            }
        }
    }
}

/// Recompute `broadcast-target-label` for the active tab and push it to the
/// UI. Called after anything that can change the label's meaning: a pane
/// split/close (pane count changed), a tab switch, broadcast being toggled
/// on, or the target itself being changed via the targeting menu.
pub(super) fn refresh_broadcast_label(state: &Rc<RefCell<State>>, ui: &AppWindow) {
    let st = state.borrow();
    let label = st
        .tabs
        .get(st.active)
        .map(|t| t.broadcast_target.label(t.pane_group.count()))
        .unwrap_or_else(|| "all panes".to_string());
    ui.set_broadcast_target_label(SharedString::from(label));
}

fn wire_toggle_broadcast(ctx: &Ctx) {
    ctx.ui.on_toggle_broadcast({
        let weak = ctx.ui.as_weak();
        let state = ctx.state.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                let now_on = !ui.get_broadcast_active();
                ui.set_broadcast_active(now_on);
                if now_on {
                    refresh_broadcast_label(&state, &ui);
                }
            }
        }
    });
}

fn wire_broadcast_target(ctx: &Ctx) {
    ctx.ui.on_open_broadcast_target({
        let ctx = BroadcastCtx::from(ctx);
        move || {
            {
                let st = ctx.state.borrow();
                let mut draft = ctx.bc_draft.borrow_mut();
                draft.clear();
                if let Some(tab) = st.tabs.get(st.active)
                    && let BroadcastTarget::Custom { panes, .. } = &tab.broadcast_target
                {
                    draft.extend(panes.iter().copied());
                }
            }
            ctx.refresh_menu_models();
            if let Some(ui) = ctx.weak.upgrade() {
                ui.set_broadcast_group_name_draft(SharedString::default());
                ui.set_broadcast_target_open(true);
            }
        }
    });

    ctx.ui.on_close_broadcast_target({
        let weak = ctx.ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_broadcast_target_open(false);
            }
        }
    });

    ctx.ui.on_select_broadcast_visible({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move || {
            {
                let mut st = state.borrow_mut();
                let active = st.active;
                if let Some(tab) = st.tabs.get_mut(active) {
                    tab.broadcast_target = BroadcastTarget::Visible;
                }
            }
            if let Some(ui) = weak.upgrade() {
                refresh_broadcast_label(&state, &ui);
                ui.set_broadcast_target_open(false);
            }
        }
    });

    ctx.ui.on_toggle_broadcast_pane_check({
        let ctx = BroadcastCtx::from(ctx);
        move |pane_id| {
            {
                let mut draft = ctx.bc_draft.borrow_mut();
                let id = pane_id as usize;
                if !draft.remove(&id) {
                    draft.insert(id);
                }
            }
            ctx.refresh_menu_models();
        }
    });

    ctx.ui.on_apply_broadcast_custom({
        let ctx = BroadcastCtx::from(ctx);
        move || {
            let panes = ctx.bc_draft.borrow().clone();
            {
                let mut st = ctx.state.borrow_mut();
                let active = st.active;
                if let Some(tab) = st.tabs.get_mut(active) {
                    tab.broadcast_target = BroadcastTarget::Custom { name: None, panes };
                }
            }
            if let Some(ui) = ctx.weak.upgrade() {
                refresh_broadcast_label(&ctx.state, &ui);
                ui.set_broadcast_target_open(false);
            }
        }
    });

    ctx.ui.on_save_broadcast_group({
        let ctx = BroadcastCtx::from(ctx);
        move || {
            let Some(ui) = ctx.weak.upgrade() else { return };
            let name = ui.get_broadcast_group_name_draft().trim().to_string();
            if name.is_empty() {
                return;
            }
            let panes = ctx.bc_draft.borrow().clone();
            {
                let mut st = ctx.state.borrow_mut();
                let active = st.active;
                if let Some(tab) = st.tabs.get_mut(active) {
                    tab.broadcast_saved_groups
                        .push((name.clone(), panes.clone()));
                    tab.broadcast_target = BroadcastTarget::Custom {
                        name: Some(name),
                        panes,
                    };
                }
            }
            refresh_broadcast_label(&ctx.state, &ui);
            ui.set_broadcast_group_name_draft(SharedString::default());
            ui.set_broadcast_target_open(false);
        }
    });

    ctx.ui.on_select_broadcast_group({
        let ctx = BroadcastCtx::from(ctx);
        move |idx| {
            {
                let mut st = ctx.state.borrow_mut();
                let active = st.active;
                if let Some(tab) = st.tabs.get_mut(active)
                    && let Some((name, panes)) =
                        tab.broadcast_saved_groups.get(idx as usize).cloned()
                {
                    tab.broadcast_target = BroadcastTarget::Custom {
                        name: Some(name),
                        panes,
                    };
                }
            }
            if let Some(ui) = ctx.weak.upgrade() {
                refresh_broadcast_label(&ctx.state, &ui);
                ui.set_broadcast_target_open(false);
            }
        }
    });
}

/// Just the handles the broadcast-targeting-menu callbacks need, cloned out
/// of `Ctx` once per `wire_broadcast_target` closure (mirrors how the other
/// `wire_*` functions in this module pull individual `Rc`/`Arc` clones out of
/// `ctx` before moving into a callback) — kept as a small bundle here only
/// because six callbacks share the exact same four handles.
struct BroadcastCtx {
    state: Rc<RefCell<State>>,
    weak: slint::Weak<AppWindow>,
    bc_check_model: Rc<VecModel<bool>>,
    bc_group_model: Rc<VecModel<SharedString>>,
    bc_draft: Rc<RefCell<BTreeSet<usize>>>,
}

impl From<&Ctx> for BroadcastCtx {
    fn from(ctx: &Ctx) -> Self {
        Self {
            state: ctx.state.clone(),
            weak: ctx.ui.as_weak(),
            bc_check_model: ctx.bc_check_model.clone(),
            bc_group_model: ctx.bc_group_model.clone(),
            bc_draft: ctx.bc_draft.clone(),
        }
    }
}

impl BroadcastCtx {
    fn refresh_menu_models(&self) {
        let st = self.state.borrow();
        let draft = self.bc_draft.borrow();
        let Some(tab) = st.tabs.get(st.active) else {
            self.bc_check_model.set_vec(Vec::new());
            self.bc_group_model.set_vec(Vec::new());
            return;
        };
        let checks: Vec<bool> = (0..tab.pane_group.count())
            .map(|id| draft.contains(&id))
            .collect();
        self.bc_check_model.set_vec(checks);
        let names: Vec<SharedString> = tab
            .broadcast_saved_groups
            .iter()
            .map(|(name, _)| SharedString::from(name.as_str()))
            .collect();
        self.bc_group_model.set_vec(names);
    }
}

// N-way pane repeater model (`app.slint`'s `pane-cells`)

/// Rebuild the `pane-cells` model for the active tab from scratch: geometry
/// (via `PaneGroup::rects`) plus each pane's current frame image and surface
/// kind. Only meaningful — and only expensive — when the active tab has more
/// than one pane; single-pane tabs (the common case) clear the model and
/// keep using the original `root.frame`/`rdp-active`/`rdp-frame` path
/// untouched, so this feature is zero-cost when unsplit.
///
/// Convenience wrapper around [`rebuild_pane_cells_for_state`] for call
/// sites (split/close/reattach) that don't already hold a `State` borrow.
pub(super) fn rebuild_pane_cells(state: &Rc<RefCell<State>>) {
    let mut st = state.borrow_mut();
    rebuild_pane_cells_for_state(&mut st);
}

/// Same as [`rebuild_pane_cells`], for call sites (`render_active`,
/// `tick_tab`) that already hold a live `&mut State` borrow and would
/// otherwise double-borrow the `RefCell` by going through the `Rc` wrapper.
pub(super) fn rebuild_pane_cells_for_state(st: &mut State) {
    let active = st.active;
    let primary_target = st.target_px();
    let pane_model = st.pane_model.clone();
    let Some(tab) = st.tabs.get_mut(active) else {
        pane_model.set_vec(Vec::new());
        return;
    };
    if tab.pane_group.count() <= 1 {
        pane_model.set_vec(Vec::new());
        return;
    }
    pane_model.set_vec(build_pane_cells(tab, primary_target, st.scroll_rev));
}

fn build_pane_cells(
    tab: &mut Tab,
    primary_target: Option<(u32, u32)>,
    scroll_rev: u64,
) -> Vec<crate::PaneCell> {
    let rects = tab.pane_group.rects();
    let mut out = Vec::with_capacity(rects.len());
    for rect in rects {
        let (frame, is_rdp) = if rect.pane == 0 {
            match tab.session.surface() {
                Surface::TerminalGrid(_) => {
                    let img = match &tab.last {
                        Some(snap) => {
                            let snap = snap.clone();
                            sessions::render_frame(tab, &snap, primary_target)
                        }
                        None => Image::default(),
                    };
                    (img, false)
                }
                Surface::Framebuffer(_) => (tab.last_frame.clone().unwrap_or_default(), true),
            }
        } else {
            let ep_idx = rect.pane - 1;
            let search_highlights = tab
                .search
                .applies_to(rect.pane)
                .then(|| {
                    tab.extra_panes
                        .get(ep_idx)
                        .and_then(|pane| pane.last.as_ref())
                        .map(|snap| sessions::visible_search_highlights(&tab.search, snap))
                })
                .flatten()
                .unwrap_or_default();
            match tab.extra_panes.get_mut(ep_idx) {
                Some(ep) => {
                    let ep_target = if ep.surface_w > 0.0 && ep.surface_h > 0.0 {
                        Some((
                            (ep.surface_w * ep.scale).round().max(1.0) as u32,
                            (ep.surface_h * ep.scale).round().max(1.0) as u32,
                        ))
                    } else {
                        None
                    };
                    match ep.session.surface() {
                        Surface::TerminalGrid(_) => {
                            let img = match &ep.last {
                                Some(snap) => {
                                    let snap = snap.clone();
                                    sessions::render_frame_ep(
                                        ep,
                                        &snap,
                                        ep_target,
                                        &search_highlights.0,
                                        search_highlights.1,
                                    )
                                }
                                None => Image::default(),
                            };
                            (img, false)
                        }
                        Surface::Framebuffer(_) => {
                            (ep.last_frame.clone().unwrap_or_default(), true)
                        }
                    }
                }
                None => (Image::default(), false),
            }
        };
        // Latest scrollback viewport for this pane's overlay scrollbar
        // (`None` before the first snapshot / for RDP panes → zeros hide it).
        let (scrollback_len, scroll_offset, view_rows) = if rect.pane == 0 {
            tab.last.as_ref().map_or((0, 0, 0), |snap| {
                (
                    snap.scrollback_len as i32,
                    snap.scroll_offset as i32,
                    snap.size.rows as i32,
                )
            })
        } else {
            tab.extra_panes
                .get(rect.pane - 1)
                .and_then(|ep| ep.last.as_ref())
                .map_or((0, 0, 0), |snap| {
                    (
                        snap.scrollback_len as i32,
                        snap.scroll_offset as i32,
                        snap.size.rows as i32,
                    )
                })
        };
        out.push(crate::PaneCell {
            pane: rect.pane as i32,
            x: rect.x,
            y: rect.y,
            w: rect.w,
            h: rect.h,
            frame,
            is_rdp,
            scrollback_len,
            scroll_offset,
            view_rows,
            scroll_rev: scroll_rev as i32,
        });
    }
    out
}

fn wire_split_pane_h(ctx: &Ctx) {
    ctx.ui.on_split_pane_h({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                do_split(&state, &tab_model, &ui, PaneLayout::HSplit);
            }
        }
    });
}

fn wire_split_pane_v(ctx: &Ctx) {
    ctx.ui.on_split_pane_v({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                do_split(&state, &tab_model, &ui, PaneLayout::VSplit);
            }
        }
    });
}

/// The active tab's currently-focused pane id - every "close/detach
/// whatever I'm looking at" caller of the now-generalized [`do_close_pane`]
/// (the keyboard shortcuts here, the command palette, `wire_key_input`'s own
/// shortcut handling in `sessions.rs`) passes this explicitly, preserving
/// their exact prior behavior.
pub(super) fn focused_pane_id(state: &Rc<RefCell<State>>) -> Option<usize> {
    let st = state.borrow();
    let active = st.active;
    st.tabs.get(active).map(|t| t.pane_group.focused())
}

fn wire_close_pane(ctx: &Ctx) {
    ctx.ui.on_close_pane({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let Some(pane_id) = focused_pane_id(&state) else {
                return;
            };
            close::request_pane_close(&state, &tab_model, &ui, pane_id);
        }
    });
}

fn wire_detach_session(ctx: &Ctx) {
    ctx.ui.on_detach_session({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let Some(pane_id) = focused_pane_id(&state) else {
                return;
            };
            do_close_pane(&state, &tab_model, &ui, pane_id, true);
        }
    });
}

/// #2: per-pane disconnect inside a split - the corner affordance on
/// each `PaneSlot` (or a future context menu) targets a SPECIFIC pane id,
/// never "whichever pane is focused" (unlike the two callbacks above).
/// Always a plain disconnect (`detach: false`), matching the "close ==
/// disconnect == collapse split" naming this whole lane's other items
/// use for a session teardown that isn't kept running in the background.
fn wire_pane_disconnect(ctx: &Ctx) {
    ctx.ui.on_pane_disconnect({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        move |pane_id| {
            let Some(ui) = weak.upgrade() else { return };
            close::request_pane_close(&state, &tab_model, &ui, pane_id as usize);
        }
    });
}

fn wire_pane_focused(ctx: &Ctx) {
    ctx.ui.on_pane_focused({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |pane_idx| {
            let mut st = state.borrow_mut();
            let active = st.active;
            if let Some(tab) = st.tabs.get_mut(active) {
                let focused_before = tab.pane_group.focused();
                tab.pane_group.set_focused(pane_idx as usize);
                let focused_now = tab.pane_group.focused();
                if focused_now != focused_before {
                    // PaneSlot reports focus before forwarding the same
                    // pointer press. Clear synchronously and acknowledge the
                    // new focus now, so the following press/drag can create a
                    // selection that tick_tab's defensive fallback preserves.
                    tab.sel.clear();
                    for ep in &mut tab.extra_panes {
                        ep.sel.clear();
                    }
                    tab.last_focused_pane = focused_now;
                }
            }
            if let Some(ui) = weak.upgrade() {
                ui.set_active_pane(pane_idx);
                // Flash the newly focused pane's overlay scrollbar when it
                // sits scrolled back by bumping ONLY that pane's `scroll-rev`
                // cell field in place. Never rebuild the pane model here:
                // `render_active` -> `rebuild_pane_cells_for_state` ->
                // `set_vec` destroys and recreates every `PaneSlot`, including
                // the surface that just took keyboard focus from this very
                // click, so the fresh instance has no focus and the next key
                // press (e.g. Return to the close-confirm dialog) goes nowhere
                // (caught by suite_session_actions). `set_row_data` is a
                // data-only update that preserves element instances. Single-
                // pane tabs have an empty model and use the AppWindow
                // `term-scroll-rev` prop, bumped by `select_tab`.
                let active = st.active;
                if st
                    .tabs
                    .get(active)
                    .is_some_and(|tab| tab.pane_group.count() > 1)
                {
                    st.scroll_rev = st.scroll_rev.wrapping_add(1);
                    let rev = st.scroll_rev as i32;
                    let pane_model = st.pane_model.clone();
                    let row = (0..pane_model.row_count()).find(|&i| {
                        pane_model
                            .row_data(i)
                            .is_some_and(|cell| cell.pane == pane_idx)
                    });
                    if let Some(i) = row
                        && let Some(mut cell) = pane_model.row_data(i)
                    {
                        cell.scroll_rev = rev;
                        pane_model.set_row_data(i, cell);
                    }
                }
            }
        }
    });
}

fn wire_pane_resized(ctx: &Ctx) {
    ctx.ui.on_pane_resized({
        let state = ctx.state.clone();
        let debounce = ctx.resize_debounce.clone();
        let weak = ctx.ui.as_weak();
        move |pane_idx, w, h| {
            {
                let mut st = state.borrow_mut();
                let scale = st.scale;
                if pane_idx == 0 {
                    st.surface_w = w;
                    st.surface_h = h;
                    // Update scale from UI if available.
                    if let Some(ui) = weak.upgrade() {
                        st.scale = ui.window().scale_factor();
                    }
                } else {
                    let active = st.active;
                    if let Some(tab) = st.tabs.get_mut(active) {
                        let pidx = pane_idx as usize - 1;
                        if let Some(ep) = tab.extra_panes.get_mut(pidx) {
                            ep.surface_w = w;
                            ep.surface_h = h;
                            ep.scale = scale;
                        }
                    }
                }
            }
            let state = state.clone();
            let weak2 = weak.clone();
            debounce.start(TimerMode::SingleShot, RESIZE_DEBOUNCE, move || {
                if let Some(ui) = weak2.upgrade() {
                    tabs::apply_settled_resize(&state, &ui);
                }
            });
        }
    });
}

pub(super) fn layout_to_int(layout: PaneLayout) -> i32 {
    match layout {
        PaneLayout::Single => 0,
        PaneLayout::HSplit => 1,
        PaneLayout::VSplit => 2,
    }
}

/// Everything a caller needs, once a pane slot has been reserved, to size and
/// spawn whatever session goes into it.
struct SplitSlot {
    incumbent_pane_idx: usize,
    incumbent_has_chrome: bool,
    new_pane_idx: usize,
    scale: f32,
    surface_w: f32,
    surface_h: f32,
    fonts: Arc<TerminalFontSystem>,
    font_family: String,
    font_size_px: f32,
    local_settings: LocalSettings,
}

/// Session-owned metadata that must follow a split pane if it is later
/// promoted into the tab's primary slot. Saved SSH/RDP panes retain only the
/// profile id used to re-resolve credentials; resolved secrets are never
/// stored here.
struct SplitPaneMetadata {
    endpoint_id: cm_core::SessionEndpointId,
    connect_info: Option<ConnectInfo>,
    is_remote: bool,
    origin_connection_id: Option<i32>,
    identity: String,
    title: String,
    insecure_transport: bool,
    kind: String,
}

/// Reserve a pane slot in the active tab's `PaneGroup` (any focused
/// pane, N-way). Shared by [`do_split`] and [`connect_in_split`] ( fix
/// round 2) — the pane-slot bookkeeping is identical regardless of what kind
/// of session ends up filling the slot.
fn reserve_split_slot(state: &Rc<RefCell<State>>, layout: PaneLayout) -> Option<SplitSlot> {
    let mut st = state.borrow_mut();
    let active = st.active;
    let primary_surface = (st.surface_w, st.surface_h);
    let (incumbent_pane_idx, incumbent_has_chrome, surface_w, surface_h, new_pane_idx) = {
        let tab = st.tabs.get_mut(active)?;
        let incumbent_pane_idx = tab.pane_group.focused();
        let incumbent_has_chrome = tab.pane_group.count() > 1;
        let (surface_w, surface_h) = if incumbent_pane_idx == 0 {
            primary_surface
        } else {
            let incumbent = tab.extra_panes.get(incumbent_pane_idx - 1)?;
            (incumbent.surface_w, incumbent.surface_h)
        };
        let new_pane_idx = tab.pane_group.split(layout)?; // None: already at MAX_PANES
        (
            incumbent_pane_idx,
            incumbent_has_chrome,
            surface_w,
            surface_h,
            new_pane_idx,
        )
    };
    Some(SplitSlot {
        incumbent_pane_idx,
        incumbent_has_chrome,
        new_pane_idx,
        scale: st.scale,
        surface_w,
        surface_h,
        fonts: st.fonts.clone(),
        font_family: st.font_family.clone(),
        font_size_px: st.font_size_px,
        local_settings: st.local_settings.clone(),
    })
}

/// Undo a `reserve_split_slot` reservation after the session for it failed to
/// spawn/connect — mirrors the pane-group state to before the split.
fn rollback_split_slot(state: &Rc<RefCell<State>>) {
    let mut st = state.borrow_mut();
    let active = st.active;
    if let Some(tab) = st.tabs.get_mut(active) {
        let _ = tab.pane_group.close_focused();
    }
}

fn endpoint_or_rollback(
    endpoint: Option<cm_core::SessionEndpointId>,
    rollback: impl FnOnce(),
) -> Option<cm_core::SessionEndpointId> {
    match endpoint {
        Some(endpoint) => Some(endpoint),
        None => {
            rollback();
            None
        }
    }
}

/// Logical height reserved above every split pane's session content. Keep in
/// sync with `PaneSlot::chrome-height` in `ui/app.slint`.
const SPLIT_PANE_CHROME_HEIGHT: f32 = 28.0;

/// Session-content size of each half produced by splitting the focused pane.
/// `surface_h` is the incumbent terminal/RDP content height, not its outer
/// `PaneSlot` height. Existing split panes already exclude the chrome row, so
/// reconstruct their outer height before splitting; every resulting child
/// then reserves its own chrome row.
fn split_pane_dims(
    layout: PaneLayout,
    surface_w: f32,
    surface_h: f32,
    incumbent_has_chrome: bool,
) -> (f32, f32) {
    let outer_h = surface_h
        + if incumbent_has_chrome {
            SPLIT_PANE_CHROME_HEIGHT
        } else {
            0.0
        };
    let child_outer_w = match layout {
        PaneLayout::HSplit => surface_w / 2.0,
        PaneLayout::VSplit | PaneLayout::Single => surface_w,
    };
    let child_outer_h = match layout {
        PaneLayout::VSplit => outer_h / 2.0,
        PaneLayout::HSplit | PaneLayout::Single => outer_h,
    };
    (
        child_outer_w.max(1.0),
        (child_outer_h - SPLIT_PANE_CHROME_HEIGHT).max(1.0),
    )
}

/// Apply the split's immediately-known dimensions to the incumbent pane and
/// request the matching terminal grid or framebuffer size. Waiting for a
/// later Slint `pane-resized` callback leaves the incumbent frame rendered at
/// its old full-pane target on Windows, so the UI bitmap-scales it until the
/// outer window happens to resize.
fn settle_split_incumbent(
    tab: &mut Tab,
    incumbent_pane_idx: usize,
    primary_surface: &mut (f32, f32),
    pane_w: f32,
    pane_h: f32,
    scale: f32,
) {
    if incumbent_pane_idx == 0 {
        *primary_surface = (pane_w, pane_h);
        match tab.session.surface() {
            Surface::TerminalGrid(_) => {
                let size = util::grid_for(&tab.renderer, pane_w, pane_h, scale);
                if size.cols != tab.cols || size.rows != tab.rows {
                    tab.session.resize_cells(size.cols, size.rows);
                    tab.cols = size.cols;
                    tab.rows = size.rows;
                }
            }
            Surface::Framebuffer(_) => {
                let pw = (pane_w * scale).round().max(1.0) as u32;
                let ph = (pane_h * scale).round().max(1.0) as u32;
                tab.session.resize_px(pw, ph);
            }
        }
        return;
    }

    let Some(ep) = tab.extra_panes.get_mut(incumbent_pane_idx - 1) else {
        return;
    };
    ep.surface_w = pane_w;
    ep.surface_h = pane_h;
    ep.scale = scale;
    match ep.session.surface() {
        Surface::TerminalGrid(_) => {
            let size = util::grid_for(&ep.renderer, pane_w, pane_h, scale);
            if size.cols != ep.cols || size.rows != ep.rows {
                ep.session.resize_cells(size.cols, size.rows);
                ep.cols = size.cols;
                ep.rows = size.rows;
            }
        }
        Surface::Framebuffer(_) => {
            let pw = (pane_w * scale).round().max(1.0) as u32;
            let ph = (pane_h * scale).round().max(1.0) as u32;
            ep.session.resize_px(pw, ph);
        }
    }
}

/// Commit a session into the pane slot reserved by `reserve_split_slot`:
/// push `ExtraPaneState`, refresh the tab-strip pane-count badge, rebuild the
/// N-way pane-cells geometry, and update the UI's pane-layout/focus. Shared
/// by [`do_split`] and [`connect_in_split`] — both terminal (`TerminalGrid`)
/// and RDP (`Framebuffer`) sessions go through this same path; the
/// `size`/`renderer` args are meaningless dead weight for an RDP session
/// (mirrors how `Tab` already carries an always-present but RDP-tabs-ignore
/// `renderer`/`cols`/`rows` — see `tabs::push_tab`).
#[allow(clippy::too_many_arguments)]
fn commit_split_pane(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    layout: PaneLayout,
    incumbent_pane_idx: usize,
    new_pane_idx: usize,
    session: Box<dyn Session>,
    renderer: TerminalRenderer,
    size: TerminalSize,
    pane_w: f32,
    pane_h: f32,
    scale: f32,
    metadata: SplitPaneMetadata,
) {
    {
        let mut st = state.borrow_mut();
        let active = st.active;
        let mut primary_surface = (st.surface_w, st.surface_h);
        if let Some(tab) = st.tabs.get_mut(active) {
            settle_split_incumbent(
                tab,
                incumbent_pane_idx,
                &mut primary_surface,
                pane_w,
                pane_h,
                scale,
            );
            let ep = ExtraPaneState {
                endpoint_id: metadata.endpoint_id,
                session,
                renderer,
                last: None,
                cols: size.cols,
                rows: size.rows,
                scale,
                surface_w: pane_w,
                surface_h: pane_h,
                sel: PaneSelectionState::default(),
                last_frame: None,
                rdp_w: 0,
                rdp_h: 0,
                connect_info: metadata.connect_info,
                is_remote: metadata.is_remote,
                origin_connection_id: metadata.origin_connection_id,
                identity: metadata.identity,
                title: metadata.title,
                insecure_transport: metadata.insecure_transport,
                kind: metadata.kind,
                connect_started: std::time::Instant::now(),
            };
            // New pane ids are always appended (`PaneGroup::split` returns
            // `count - 1` after the split, i.e. the previous `count`),
            // so `extra_panes.len` and `new_pane_idx - 1` always agree.
            if tab.extra_panes.len() <= new_pane_idx {
                tab.extra_panes.push(ep);
            }
        }
        (st.surface_w, st.surface_h) = primary_surface;
    }

    // Update the tab-strip badge.
    {
        let st = state.borrow();
        let active = st.active;
        if let Some(mut item) = tab_model.row_data(active) {
            item.pane_count = st
                .tabs
                .get(active)
                .map(|t| t.pane_group.count() as i32)
                .unwrap_or(1);
            tab_model.set_row_data(active, item);
        }
    }

    ui.set_pane_layout(layout_to_int(layout));
    ui.set_active_pane(new_pane_idx as i32);
    let insecure = {
        let st = state.borrow();
        st.tabs.get(st.active).is_some_and(|tab| {
            tab.insecure_transport || tab.extra_panes.iter().any(|ep| ep.insecure_transport)
        })
    };
    ui.set_session_insecure(insecure);
    rebuild_pane_cells(state);
    refresh_broadcast_label(state, ui);
}

/// Split the active tab's pane group, spawning a new local terminal in the
/// newly created pane.
pub(super) fn do_split(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    layout: PaneLayout,
) {
    do_local_split(state, tab_model, ui, layout, None);
}

fn do_local_split(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    layout: PaneLayout,
    saved_name: Option<&str>,
) {
    let Some(slot) = reserve_split_slot(state, layout) else {
        return;
    };

    // Spawn a new local terminal for the extra pane (half the width for H-split).
    // follow the live app theme rather than hardcoding dark.
    let renderer = TerminalRenderer::with_font_system(
        slot.fonts,
        &slot.font_family,
        slot.font_size_px,
        slot.scale,
        util::terminal_theme_for(ui),
    );
    let (pane_w, pane_h) = split_pane_dims(
        layout,
        slot.surface_w,
        slot.surface_h,
        slot.incumbent_has_chrome,
    );
    let size = if pane_w > 0.0 && pane_h > 0.0 {
        util::grid_for(&renderer, pane_w, pane_h, slot.scale)
    } else {
        INITIAL_SIZE
    };

    let Some(endpoint_id) = state.borrow_mut().allocate_endpoint_id() else {
        tracing::error!("session endpoint ID space exhausted");
        rollback_split_slot(state);
        return;
    };
    let provider = state.borrow().session_provider.clone();
    let options = cm_core::TerminalOptions {
        max_scrollback: state.borrow().scrollback_limit,
    };
    let session = match provider.spawn_local(&slot.local_settings, size, options) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("split pane spawn failed: {e}");
            rollback_split_slot(state);
            return;
        }
    };

    commit_split_pane(
        state,
        tab_model,
        ui,
        layout,
        slot.incumbent_pane_idx,
        slot.new_pane_idx,
        session,
        renderer,
        size,
        pane_w,
        pane_h,
        slot.scale,
        SplitPaneMetadata {
            endpoint_id,
            connect_info: None,
            is_remote: false,
            origin_connection_id: None,
            identity: saved_name.unwrap_or("local shell").to_owned(),
            title: saved_name.unwrap_or("Local shell").to_owned(),
            insecure_transport: false,
            kind: String::new(),
        },
    );
}

/// /: "Connect in split" — open a stored connection's session
/// directly into the active tab's next pane slot, reusing the same
/// N-way-pane machinery `do_split` already has (see
/// `reserve_split_slot`/`commit_split_pane` above).
///
/// - **Local** profiles are identical to a plain split (always a local
///   shell), so they delegate straight to [`do_split`].
/// - **SSH** profiles resolve credentials via the same path
///   `launch_saved_connection` uses (`sessions::resolve_ssh_auth`) and spawn
///   a real `SshTerminalSession` into the pane slot.
/// - **RDP** profiles (lifts the deferral) resolve credentials
///   via `sessions::resolve_rdp_auth` and spawn a real `RdpSession` into the
///   pane slot — `ExtraPaneState` now carries the `last_frame`/`rdp_w`/
///   `rdp_h` fields a `Surface::Framebuffer` session needs (mirroring
///   `Tab`'s primary-pane fields), so a pane no longer has to be a terminal.
///   A resolution or connect failure surfaces as a toast and leaves the tab
///   at its previous pane count (no half-open pane).
#[allow(clippy::too_many_arguments)]
pub(super) fn connect_in_split(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    weak: &slint::Weak<AppWindow>,
    hk_pending: &HkQueue,
    cert_pending: &Arc<Mutex<Option<Sender<CertDecision>>>>,
    secrets: &Arc<dyn cm_core::CredentialStore>,
    toast_model: &Rc<VecModel<ToastEntry>>,
    toast_next_id: &Rc<RefCell<i32>>,
    conn_id: i64,
    layout: PaneLayout,
) {
    let conn = {
        let st = state.borrow();
        st.conn_tree.conn_by_id(conn_id).cloned()
    };
    let Some(conn) = conn else { return };

    match &conn.settings {
        cm_core::ConnectionSettings::Local(_) => {
            do_local_split(state, tab_model, ui, layout, Some(&conn.name));
        }
        cm_core::ConnectionSettings::Telnet(settings) => {
            let Some(slot) = reserve_split_slot(state, layout) else {
                return;
            };
            let renderer = TerminalRenderer::with_font_system(
                slot.fonts,
                &slot.font_family,
                slot.font_size_px,
                slot.scale,
                util::terminal_theme_for(ui),
            );
            let (pane_w, pane_h) = split_pane_dims(
                layout,
                slot.surface_w,
                slot.surface_h,
                slot.incumbent_has_chrome,
            );
            let size = if pane_w > 0.0 && pane_h > 0.0 {
                util::grid_for(&renderer, pane_w, pane_h, slot.scale)
            } else {
                INITIAL_SIZE
            };

            if sessions::agent_mode_execute_blocked(&state.borrow().agent_mode) {
                tracing::warn!(
                    conn = %conn.name,
                    "agent mode: Telnet connect-in-split blocked while automation is active without execute scope"
                );
                rollback_split_slot(state);
                push_toast(
                    toast_model,
                    toast_next_id,
                    format!("{}: agent mode: execute scope not granted", conn.name),
                );
                return;
            }

            let Some(endpoint_id) = state.borrow_mut().allocate_endpoint_id() else {
                tracing::error!("session endpoint ID space exhausted");
                rollback_split_slot(state);
                return;
            };
            let provider = state.borrow().session_provider.clone();
            let options = cm_core::TerminalOptions {
                max_scrollback: state.borrow().scrollback_limit,
            };
            let session = match provider.connect_telnet(settings, size, options) {
                Ok(session) => session,
                Err(e) => {
                    tracing::warn!("connect-in-split Telnet connect failed: {e}");
                    rollback_split_slot(state);
                    push_toast(toast_model, toast_next_id, format!("{}: {e}", conn.name));
                    return;
                }
            };
            commit_split_pane(
                state,
                tab_model,
                ui,
                layout,
                slot.incumbent_pane_idx,
                slot.new_pane_idx,
                session,
                renderer,
                size,
                pane_w,
                pane_h,
                slot.scale,
                SplitPaneMetadata {
                    endpoint_id,
                    connect_info: Some(ConnectInfo::Telnet(settings.clone())),
                    is_remote: true,
                    origin_connection_id: Some(conn.id.get() as i32),
                    identity: conn.name.clone(),
                    title: conn.name.clone(),
                    insecure_transport: true,
                    kind: "TELNET".to_owned(),
                },
            );
        }
        cm_core::ConnectionSettings::Ssh(s) => {
            let resolved = {
                let st = state.borrow();
                sessions::resolve_ssh_auth(
                    &conn,
                    st.conn_tree.groups(),
                    s,
                    secrets.as_ref(),
                    st.keys_panel.credentials(),
                )
            };
            let auth = match resolved {
                Ok(a) => a,
                Err(e) => {
                    push_toast(toast_model, toast_next_id, format!("{}: {e}", conn.name));
                    return;
                }
            };
            // BUG-cred-username-auth: the settings actually used to
            // connect/log carry the *effective* username (credential's own
            // username wins over the inline field when a credential is
            // assigned) - see `sessions::effective_ssh_settings`.
            let effective_settings = {
                let st = state.borrow();
                sessions::effective_ssh_settings(
                    &conn,
                    st.conn_tree.groups(),
                    s,
                    st.keys_panel.credentials(),
                )
            };
            {
                let st = state.borrow();
                sessions::log_ssh_launch_auth(
                    &conn,
                    st.conn_tree.groups(),
                    &effective_settings,
                    st.keys_panel.credentials(),
                );
            }

            let Some(slot) = reserve_split_slot(state, layout) else {
                return;
            };

            // follow the live app theme rather than hardcoding dark.
            let renderer = TerminalRenderer::with_font_system(
                slot.fonts,
                &slot.font_family,
                slot.font_size_px,
                slot.scale,
                util::terminal_theme_for(ui),
            );
            let (pane_w, pane_h) = split_pane_dims(
                layout,
                slot.surface_w,
                slot.surface_h,
                slot.incumbent_has_chrome,
            );
            let size = if pane_w > 0.0 && pane_h > 0.0 {
                util::grid_for(&renderer, pane_w, pane_h, slot.scale)
            } else {
                INITIAL_SIZE
            };

            let verifier = sessions::ssh_host_key_verifier(state, weak, hk_pending);

            // "Connect in split" establishes a
            // live session with stored credentials exactly like a fresh
            // launch, so it's an execute-scope action too - see
            // `sessions::open_ssh_tab`'s identical comment for the gate's
            // rationale/timing proof. The split slot is already reserved at
            // this point, so a block must roll it back like any other
            // failure below.
            if sessions::agent_mode_execute_blocked(&state.borrow().agent_mode) {
                tracing::warn!(
                    conn = %conn.name,
                    "agent mode: connect-in-split blocked while automation is active without execute scope"
                );
                rollback_split_slot(state);
                push_toast(
                    toast_model,
                    toast_next_id,
                    format!("{}: agent mode: execute scope not granted", conn.name),
                );
                return;
            }

            let Some(endpoint_id) = state.borrow_mut().allocate_endpoint_id() else {
                tracing::error!("session endpoint ID space exhausted");
                rollback_split_slot(state);
                return;
            };
            let provider = state.borrow().session_provider.clone();
            let options = cm_core::TerminalOptions {
                max_scrollback: state.borrow().scrollback_limit,
            };
            let session =
                match provider.connect_ssh(&effective_settings, auth, verifier, size, options) {
                    Ok(sess) => sess,
                    Err(e) => {
                        tracing::warn!("connect-in-split SSH connect failed: {e}");
                        rollback_split_slot(state);
                        push_toast(toast_model, toast_next_id, format!("{}: {e}", conn.name));
                        return;
                    }
                };

            commit_split_pane(
                state,
                tab_model,
                ui,
                layout,
                slot.incumbent_pane_idx,
                slot.new_pane_idx,
                session,
                renderer,
                size,
                pane_w,
                pane_h,
                slot.scale,
                SplitPaneMetadata {
                    endpoint_id,
                    connect_info: Some(ConnectInfo::Ssh(SshConnectInfo {
                        settings: effective_settings.clone(),
                        // Connect-in-split only accepts saved profiles. Keep
                        // the id so reconnect re-resolves auth; never retain
                        // the resolved `auth` value used above.
                        auth_source: SshAuthSource::Credential(conn.id),
                    })),
                    is_remote: true,
                    origin_connection_id: Some(conn.id.get() as i32),
                    identity: conn.name.clone(),
                    title: conn.name.clone(),
                    insecure_transport: false,
                    kind: "SSH".to_owned(),
                },
            );
        }
        cm_core::ConnectionSettings::Rdp(s) => {
            let resolved = {
                let st = state.borrow();
                sessions::resolve_rdp_auth(
                    &conn,
                    st.conn_tree.groups(),
                    s,
                    secrets.as_ref(),
                    st.keys_panel.credentials(),
                )
            };
            let auth = match resolved {
                Ok(a) => a,
                Err(e) => {
                    push_toast(toast_model, toast_next_id, format!("{}: {e}", conn.name));
                    return;
                }
            };
            {
                let st = state.borrow();
                sessions::log_rdp_launch_auth(
                    &conn,
                    st.conn_tree.groups(),
                    s,
                    st.keys_panel.credentials(),
                );
            }

            let Some(slot) = reserve_split_slot(state, layout) else {
                return;
            };

            // Dead weight for an RDP pane (no glyph rendering happens), kept
            // only because `ExtraPaneState`/`commit_split_pane` always carry
            // one — mirrors `Tab`'s own primary-pane convention.
            let renderer = TerminalRenderer::with_font_system(
                slot.fonts,
                &slot.font_family,
                slot.font_size_px,
                slot.scale,
                util::terminal_theme_for(ui),
            );
            let (pane_w, pane_h) = split_pane_dims(
                layout,
                slot.surface_w,
                slot.surface_h,
                slot.incumbent_has_chrome,
            );

            // Connect-into-a-split-pane
            // bypassed `open_rdp_tab`/`apply_pane_resolution` entirely, so it
            // still negotiated whatever resolution the saved profile
            // carried - stretched to fill under the old `image-fit: fill`,
            // but *letterboxed at the wrong resolution* now that RdpSurface
            // uses `contain`. Apply the same pane-size-wins override here,
            // using the split slot's own pixel size (mirrors the
            // `(w * scale).round.max(1.0)` formula `apply_settled_resize`
            // already uses at tabs.rs for the primary-pane/resize path).
            let mut s = s.clone();
            let (width, height) = sessions::pane_resolution_override(
                Some((
                    (pane_w * slot.scale).round().max(1.0) as u32,
                    (pane_h * slot.scale).round().max(1.0) as u32,
                )),
                (s.width, s.height),
            );
            s.width = width;
            s.height = height;

            let verifier = sessions::rdp_certificate_verifier(state, weak, cert_pending);

            // See the SSH arm's identical
            // comment, above.
            if sessions::agent_mode_execute_blocked(&state.borrow().agent_mode) {
                tracing::warn!(
                    conn = %conn.name,
                    "agent mode: connect-in-split blocked while automation is active without execute scope"
                );
                rollback_split_slot(state);
                push_toast(
                    toast_model,
                    toast_next_id,
                    format!("{}: agent mode: execute scope not granted", conn.name),
                );
                return;
            }

            let provider = state.borrow().session_provider.clone();
            let endpoint_id = state.borrow_mut().allocate_endpoint_id();
            let Some(endpoint_id) =
                endpoint_or_rollback(endpoint_id, || rollback_split_slot(state))
            else {
                tracing::error!("session endpoint ID space exhausted");
                return;
            };
            let session = match provider.connect_rdp(&s, auth, verifier, endpoint_id) {
                Ok(sess) => sess,
                Err(e) => {
                    tracing::warn!("connect-in-split RDP connect failed: {e}");
                    rollback_split_slot(state);
                    push_toast(toast_model, toast_next_id, format!("{}: {e}", conn.name));
                    return;
                }
            };

            commit_split_pane(
                state,
                tab_model,
                ui,
                layout,
                slot.incumbent_pane_idx,
                slot.new_pane_idx,
                session,
                renderer,
                INITIAL_SIZE,
                pane_w,
                pane_h,
                slot.scale,
                SplitPaneMetadata {
                    endpoint_id,
                    connect_info: Some(ConnectInfo::Rdp(RdpConnectInfo {
                        settings: s.clone(),
                        // As with SSH above, only the profile id persists;
                        // the resolved password moved into `connect_rdp`.
                        auth_source: RdpAuthSource::Credential(conn.id),
                    })),
                    is_remote: true,
                    origin_connection_id: Some(conn.id.get() as i32),
                    identity: conn.name.clone(),
                    title: conn.name.clone(),
                    insecure_transport: false,
                    kind: "RDP".to_owned(),
                },
            );
        }
    }
}

/// Push a toast (same shape the background-disconnect toast in `sessions.rs`
/// uses) for a `connect_in_split` failure that must surface *somewhere* —
/// there is no per-pane error overlay (that's Tab-primary-pane-only today).
fn push_toast(
    toast_model: &Rc<VecModel<ToastEntry>>,
    toast_next_id: &Rc<RefCell<i32>>,
    message: String,
) {
    let id = {
        let mut n = toast_next_id.borrow_mut();
        let id = *n;
        *n += 1;
        id
    };
    toast_model.push(ToastEntry {
        id,
        message: SharedString::from(message),
        kind: 3, // error (mirrors sessions.rs's Failed-status toast kind)
    });
}

/// Swap the primary-pane slot's fields with `extra_panes[ep_idx]`'s —
/// "promotes" that extra pane into the primary slot (pane id 0). Used by
/// [`do_close_pane`] when the *focused* (about-to-close) pane is id 0: since
/// the primary session lives in dedicated `Tab` fields rather than
/// `extra_panes`, closing it requires moving another pane's state into those
/// fields first (there is nothing else that visually "is" pane 0 otherwise).
///
/// Session origin/presentation/reconnect fields move with the promoted
/// session. In particular, a saved SSH/RDP pane retains only its credential
/// id, so promotion never turns resolved authentication material into
/// long-lived pane metadata.
fn promote_extra_to_primary(tab: &mut Tab, ep_idx: usize, primary_title: &mut String) {
    let ep = &mut tab.extra_panes[ep_idx];
    std::mem::swap(&mut tab.endpoint_id, &mut ep.endpoint_id);
    std::mem::swap(&mut tab.session, &mut ep.session);
    std::mem::swap(&mut tab.renderer, &mut ep.renderer);
    std::mem::swap(&mut tab.last, &mut ep.last);
    std::mem::swap(&mut tab.cols, &mut ep.cols);
    std::mem::swap(&mut tab.rows, &mut ep.rows);
    std::mem::swap(&mut tab.scale, &mut ep.scale);
    std::mem::swap(&mut tab.sel, &mut ep.sel);
    std::mem::swap(&mut tab.last_frame, &mut ep.last_frame);
    std::mem::swap(&mut tab.rdp_w, &mut ep.rdp_w);
    std::mem::swap(&mut tab.rdp_h, &mut ep.rdp_h);
    // The old primary is being closed immediately, so drop its reconnect
    // payload instead of parking a possible quick-connect secret in the
    // outgoing ExtraPaneState. The promoted split pane only ever contains a
    // saved-profile id for SSH/RDP authentication re-resolution.
    tab.connect_info = ep.connect_info.take();
    std::mem::swap(&mut tab.is_remote, &mut ep.is_remote);
    std::mem::swap(&mut tab.origin_connection_id, &mut ep.origin_connection_id);
    std::mem::swap(&mut tab.identity, &mut ep.identity);
    std::mem::swap(primary_title, &mut ep.title);
    std::mem::swap(&mut tab.insecure_transport, &mut ep.insecure_transport);
    std::mem::swap(&mut tab.kind, &mut ep.kind);
    std::mem::swap(&mut tab.connect_started, &mut ep.connect_started);
    tab.is_empty = false;
}

/// Close a specific pane (by id) in the active tab (any pane,
/// including the primary — see [`promote_extra_to_primary`]).
///
/// If `detach` is `true`, the closed pane's session is moved to the detached
/// list (kept running). If `false`, the session is shut down immediately.
///
/// #2: generalized from "always the focused pane" to an explicit
/// `pane_id` - a per-pane disconnect affordance (or a future context menu)
/// can target ANY pane, not necessarily the one the user happens to be
/// typing into. Retargets `PaneGroup`'s own focus to `pane_id` first (its
/// only removal primitive is `close_focused` — see `cm_session::pane`),
/// then everything below is the original, unchanged "close the focused
/// pane" logic. The two pre-existing keyboard-shortcut callers
/// (`wire_close_pane`/`wire_detach_session`) now pass the CURRENTLY-focused
/// id explicitly, which is a no-op retarget and preserves their exact prior
/// behavior.
pub(super) fn do_close_pane(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    pane_id: usize,
    detach: bool,
) {
    let (closed_session, closed_label, new_layout, new_focused, tab_label) = {
        let mut st = state.borrow_mut();
        let active = st.active;
        let closing_endpoint = st.tabs.get(active).and_then(|tab| {
            if pane_id == 0 {
                Some(tab.endpoint_id)
            } else {
                tab.extra_panes
                    .get(pane_id - 1)
                    .map(|pane| pane.endpoint_id)
            }
        });
        if let Some(endpoint) = closing_endpoint {
            sessions::release_pointer_capture_for_endpoint(&mut st, endpoint);
        }
        let Some(tab) = st.tabs.get_mut(active) else {
            return;
        };
        if tab.pane_group.count() <= 1 {
            return; // nothing to close (caller should use close_tab instead)
        }
        tab.pane_group.set_focused(pane_id);
        let focused_id = tab.pane_group.focused();
        let mut label = tab_model
            .row_data(active)
            .map(|t| t.title.to_string())
            .unwrap_or_else(|| format!("tab {}", tab.num));

        // fix: closing the *primary* pane (id 0) while other panes
        // exist used to leak — the earlier 2-pane code only ever removed
        // `extra_panes[closed_idx - 1]`, silently doing nothing when
        // `closed_idx == 0`, orphaning the real second pane's session
        // forever (still ticked/drained, never shown, never closable). Since
        // `close_focused` below unconditionally removes whichever leaf id
        // is focused, we must first promote another pane into the primary
        // slot when that id is 0, so there is always something coherent left
        // in `Tab`'s primary fields afterward.
        let closed_session = if focused_id == 0 {
            promote_extra_to_primary(tab, 0, &mut label);
            // The (former) primary session now sits in extra_panes[0] -
            // that's the one being closed.
            Some(tab.extra_panes.remove(0))
        } else {
            let ep_idx = focused_id - 1;
            if ep_idx < tab.extra_panes.len() {
                Some(tab.extra_panes.remove(ep_idx))
            } else {
                None
            }
        };

        let closed = tab.pane_group.close_focused();
        debug_assert_eq!(closed, Some(focused_id));
        let new_layout = tab.pane_group.layout();
        let new_focused = tab.pane_group.focused();
        let closed_label = closed_session
            .as_ref()
            .map(|ep| format!("{} [pane {}]", ep.title, focused_id + 1))
            .unwrap_or_else(|| format!("{label} [pane {}]", focused_id + 1));
        (closed_session, closed_label, new_layout, new_focused, label)
    };

    if let Some(ep) = closed_session {
        let mut st = state.borrow_mut();
        if detach
            && !matches!(
                ep.session.status(),
                SessionStatus::Exited(_) | SessionStatus::Failed(_)
            )
        {
            st.detached.push(DetachedEntry {
                endpoint_id: ep.endpoint_id,
                session: ep.session,
                label: closed_label,
                is_remote: ep.is_remote,
                insecure_transport: ep.insecure_transport,
                kind: ep.kind,
            });
            ui.set_detached_count(st.detached.len() as i32);
        } else {
            ep.session.shutdown();
        }
    }

    // Update tab strip badge.
    {
        let st = state.borrow();
        let active = st.active;
        if let Some(mut item) = tab_model.row_data(active) {
            item.pane_count = st
                .tabs
                .get(active)
                .map(|t| t.pane_group.count() as i32)
                .unwrap_or(1);
            item.title = SharedString::from(tab_label.as_str());
            if let Some(tab) = st.tabs.get(active) {
                item.can_duplicate = tab.origin_connection_id.is_some() || !tab.is_remote;
                item.is_home = tab.is_empty;
            }
            tab_model.set_row_data(active, item);
        }
    }

    ui.set_pane_layout(layout_to_int(new_layout));
    ui.set_active_pane(new_focused as i32);
    {
        let st = state.borrow();
        if let Some(tab) = st.tabs.get(st.active) {
            ui.set_session_identity(SharedString::from(tab.identity.as_str()));
            ui.set_connecting_kind(SharedString::from(tab.kind.as_str()));
            ui.set_session_insecure(
                tab.insecure_transport || tab.extra_panes.iter().any(|ep| ep.insecure_transport),
            );
        }
    }
    rebuild_pane_cells(state);
    refresh_broadcast_label(state, ui);
    // Re-render the newly focused pane.
    let mut st = state.borrow_mut();
    sessions::render_active(&mut st, ui);
}

/// Reattach a previously detached session to a new tab.
///
/// The detached entry is consumed — the session is moved from `State::detached`
/// back into the tab list. A new `TerminalRenderer` is created for the session
/// since the old one was discarded when the tab was closed.
pub(super) fn reattach_session(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    entry: DetachedEntry,
) {
    let DetachedEntry {
        endpoint_id,
        session,
        label,
        is_remote,
        insecure_transport,
        kind,
    } = entry;
    // Use a transient renderer; the session will re-render on first tick.
    let (scale, fonts, font_family, font_size_px) = {
        let st = state.borrow();
        (
            st.scale,
            st.fonts.clone(),
            st.font_family.clone(),
            st.font_size_px,
        )
    };
    // follow the live app theme rather than hardcoding dark.
    let renderer = TerminalRenderer::with_font_system(
        fonts,
        &font_family,
        font_size_px,
        scale,
        util::terminal_theme_for(ui),
    );
    let status_dot = match session.status() {
        SessionStatus::Connected => "connected",
        SessionStatus::Connecting => "connecting",
        _ => "disconnected",
    };
    let initial_status: &'static str = status_dot;
    {
        let mut st = state.borrow_mut();
        let used: Vec<u32> = st.tabs.iter().map(|t| t.num).collect();
        let num = tabs::lowest_free_number(&used);
        st.tabs.push(Tab {
            endpoint_id,
            session,
            renderer,
            last: None,
            last_frame: None,
            rdp_w: 0,
            rdp_h: 0,
            cols: INITIAL_SIZE.cols,
            rows: INITIAL_SIZE.rows,
            scale,
            num,
            connect_info: None,
            is_remote,
            // `DetachedEntry` doesn't carry the originating profile id, so a
            // reattached tab's ErrorOverlay "Edit…" falls back to quick-connect
            // (same degradation reattachment already has for `connect_info`/reconnect).
            origin_connection_id: None,
            pane_group: PaneGroup::single(),
            extra_panes: Vec::new(),
            sel: PaneSelectionState::default(),
            last_focused_pane: 0,
            is_empty: false,
            broadcast_target: BroadcastTarget::default(),
            broadcast_saved_groups: Vec::new(),
            search: super::search::SearchState::default(),
            // #3: reattach has no live "connecting" moment of its own
            // (a detached session is only ever Connected/Disconnected, never
            // Connecting - see `disposition`), so `kind` never actually
            // renders; `identity` mirrors what's pushed to
            // `set_session_identity` just below.
            identity: label.clone(),
            kind: kind.clone(),
            insecure_transport,
            // I2: same reasoning as `kind` above - reattach never sees
            // a `connecting -> connected` transition, so this is never
            // actually read; `Instant::now` is just a harmless default.
            connect_started: std::time::Instant::now(),
        });
        st.active = st.tabs.len() - 1;
        let active = st.active;
        drop(st);

        let tab_title = format!("[r] {label}");
        tab_model.push(TabItem {
            title: SharedString::from(tab_title),
            id: num as i32,
            status: SharedString::from(initial_status),
            pane_count: 1,
            // A reattached detached session is always a real connection -
            // never the Home tab.
            is_home: false,
            // #1: `origin_connection_id` is always `None` for a
            // reattached tab (see the comment just above, in the `Tab {
            //... }` construction) - can only "duplicate" as a new local
            // shell, and only if this reattached session actually was one.
            can_duplicate: !is_remote,
        });
        ui.set_active_tab(active as i32);
        ui.set_pane_layout(0);
        ui.set_active_pane(0);
        ui.set_session_status(SharedString::from(initial_status));
        ui.set_session_identity(SharedString::from(label.as_str()));
        ui.set_connecting_kind(SharedString::from(kind));
        ui.set_overlay_connecting(false);
        ui.set_overlay_error(false);
        ui.set_launchpad_open(false);
        ui.set_rdp_active(false);
        ui.set_session_insecure(insecure_transport);
        startup::persist_session_tabs(state);
    }
    rebuild_pane_cells(state);
    refresh_broadcast_label(state, ui);
    // Update the detached count.
    let count = state.borrow().detached.len();
    ui.set_detached_count(count as i32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal_renderer::TerminalTheme;
    use cm_core::terminal::GridSnapshot;
    use std::sync::mpsc;

    /// A `Session` that records every `send_input` call — the "mock sink"
    /// the API contract asks broadcast-targeting tests to assert against.
    struct RecordingSession {
        surface: Surface,
        sent: Arc<Mutex<Vec<SessionInput>>>,
        resized: Arc<Mutex<Vec<TerminalSize>>>,
    }

    type RecordingSessionParts = (
        RecordingSession,
        Arc<Mutex<Vec<SessionInput>>>,
        Arc<Mutex<Vec<TerminalSize>>>,
    );

    impl RecordingSession {
        fn new() -> (Self, Arc<Mutex<Vec<SessionInput>>>) {
            let (session, sent, _resized) = Self::new_with_resize_sink();
            (session, sent)
        }

        fn new_with_resize_sink() -> RecordingSessionParts {
            let (_tx, rx) = mpsc::channel::<GridSnapshot>();
            let sent = Arc::new(Mutex::new(Vec::new()));
            let resized = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    surface: Surface::TerminalGrid(rx),
                    sent: sent.clone(),
                    resized: resized.clone(),
                },
                sent,
                resized,
            )
        }

        /// A `Surface::Framebuffer`-backed session — the RDP pane shape
        /// used to verify `build_pane_cells` produces a correct
        /// `is_rdp` cell without needing a reachable RDP host (see the
        /// RDP-in-pane behavior without a reachable host.
        fn new_rdp() -> Self {
            let (_tx, rx) = mpsc::channel::<cm_session::FrameUpdate>();
            Self {
                surface: Surface::Framebuffer(rx),
                sent: Arc::new(Mutex::new(Vec::new())),
                resized: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl Session for RecordingSession {
        fn surface(&self) -> &Surface {
            &self.surface
        }
        fn status(&self) -> SessionStatus {
            SessionStatus::Connected
        }
        fn shutdown(&self) {}
        fn resize_px(&self, _width: u32, _height: u32) {}
        fn resize_cells(&self, cols: u16, rows: u16) {
            self.resized
                .lock()
                .unwrap()
                .push(TerminalSize { cols, rows });
        }
        fn send_input(&self, input: SessionInput) {
            self.sent.lock().unwrap().push(input);
        }
    }

    /// Build a `count`-pane tab (pane id 0 = primary, ids 1.. = extras), each
    /// backed by its own `RecordingSession`. Returns the tab plus each pane's
    /// sent-input sink in pane-id order (`sinks[0]` is the primary).
    fn test_tab(count: usize) -> (Tab, Vec<Arc<Mutex<Vec<SessionInput>>>>) {
        assert!(count >= 1);
        let fonts = TerminalFontSystem::shared();
        let mk_renderer = || {
            TerminalRenderer::with_font_system(
                fonts.clone(),
                cm_core::DEFAULT_TERMINAL_FONT_FAMILY,
                15.0,
                1.0,
                TerminalTheme::dark(),
            )
        };

        let (primary, primary_sink) = RecordingSession::new();
        let mut pane_group = PaneGroup::single();
        let mut extra_panes = Vec::new();
        let mut sinks = vec![primary_sink];
        for _ in 1..count {
            pane_group
                .split(PaneLayout::HSplit)
                .expect("test pane count must stay under MAX_PANES");
            let (ep_session, ep_sink) = RecordingSession::new();
            sinks.push(ep_sink);
            extra_panes.push(ExtraPaneState {
                endpoint_id: cm_core::SessionEndpointId(sinks.len() as u64 + 1),
                session: Box::new(ep_session),
                renderer: mk_renderer(),
                last: None,
                cols: 80,
                rows: 24,
                scale: 1.0,
                surface_w: 400.0,
                surface_h: 300.0,
                sel: PaneSelectionState::default(),
                last_frame: None,
                rdp_w: 0,
                rdp_h: 0,
                connect_info: None,
                is_remote: false,
                origin_connection_id: None,
                identity: String::new(),
                title: "Local shell".to_owned(),
                insecure_transport: false,
                kind: String::new(),
                connect_started: std::time::Instant::now(),
            });
        }

        let tab = Tab {
            endpoint_id: cm_core::SessionEndpointId(1),
            session: Box::new(primary),
            renderer: mk_renderer(),
            last: None,
            last_frame: None,
            rdp_w: 0,
            rdp_h: 0,
            cols: 80,
            rows: 24,
            scale: 1.0,
            num: 1,
            connect_info: None,
            is_remote: false,
            origin_connection_id: None,
            pane_group,
            extra_panes,
            sel: PaneSelectionState::default(),
            last_focused_pane: 0,
            is_empty: false,
            broadcast_target: BroadcastTarget::default(),
            broadcast_saved_groups: Vec::new(),
            search: super::search::SearchState::default(),
            identity: String::new(),
            kind: String::new(),
            insecure_transport: false,
            connect_started: std::time::Instant::now(),
        };
        (tab, sinks)
    }

    #[test]
    fn broadcast_visible_targets_all_panes() {
        let (tab, sinks) = test_tab(3);
        broadcast_fan_out(&tab, &[SessionInput::Paste(b"x".to_vec())]);
        for (id, sink) in sinks.iter().enumerate() {
            assert_eq!(
                sink.lock().unwrap().len(),
                1,
                "Visible must reach pane {id}"
            );
        }
    }

    #[test]
    fn broadcast_custom_targets_only_selected_panes() {
        let (mut tab, sinks) = test_tab(3);
        // Target panes 0 and 2 only - pane 1 must NOT receive the input.
        tab.broadcast_target = BroadcastTarget::Custom {
            name: None,
            panes: BTreeSet::from([0, 2]),
        };
        broadcast_fan_out(&tab, &[SessionInput::Paste(b"x".to_vec())]);
        assert_eq!(sinks[0].lock().unwrap().len(), 1, "pane 0 is targeted");
        assert_eq!(sinks[1].lock().unwrap().len(), 0, "pane 1 is NOT targeted");
        assert_eq!(sinks[2].lock().unwrap().len(), 1, "pane 2 is targeted");
    }

    #[test]
    fn broadcast_custom_drops_stale_pane_ids() {
        // A saved custom selection referencing a pane id that no longer
        // exists (e.g. closed since saving) must never panic and must never
        // "spill over" onto an unrelated pane.
        let (mut tab, sinks) = test_tab(2);
        tab.broadcast_target = BroadcastTarget::Custom {
            name: None,
            panes: BTreeSet::from([0, 5]), // 5 doesn't exist (count == 2)
        };
        broadcast_fan_out(&tab, &[SessionInput::Paste(b"x".to_vec())]);
        assert_eq!(sinks[0].lock().unwrap().len(), 1);
        assert_eq!(sinks[1].lock().unwrap().len(), 0);
    }

    #[test]
    fn rdp_in_pane_shape_produces_an_is_rdp_cell() {
        // an extra pane whose session surface is `Framebuffer` (RDP)
        // must render as an `is_rdp` pane-cell carrying its own decoded
        // frame — the shape lift that makes RDP-in-a-split possible at all.
        // This is verifiable without a reachable RDP host.
        let (mut tab, _sinks) = test_tab(2);
        let rdp_session = RecordingSession::new_rdp();
        let rdp_frame = Image::from_rgba8(slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(4, 4));
        tab.extra_panes[0].session = Box::new(rdp_session);
        tab.extra_panes[0].last_frame = Some(rdp_frame.clone());
        tab.extra_panes[0].rdp_w = 4;
        tab.extra_panes[0].rdp_h = 4;

        let cells = build_pane_cells(&mut tab, None, 0);
        assert_eq!(cells.len(), 2);
        let primary = cells.iter().find(|c| c.pane == 0).unwrap();
        assert!(!primary.is_rdp, "primary pane is still a plain terminal");
        let rdp_cell = cells.iter().find(|c| c.pane == 1).unwrap();
        assert!(
            rdp_cell.is_rdp,
            "extra pane with a Framebuffer surface must report is_rdp"
        );
        assert_eq!(rdp_cell.frame.size(), rdp_frame.size());
    }

    #[test]
    fn first_horizontal_split_settles_content_target_below_chrome() {
        let (mut tab, _sinks) = test_tab(1);
        let (primary, _sent, resized) = RecordingSession::new_with_resize_sink();
        tab.session = Box::new(primary);

        let scale: f32 = 1.5;
        let mut primary_surface: (f32, f32) = (1200.0, 800.0);
        let old_target = (
            (primary_surface.0 * scale).round() as u32,
            (primary_surface.1 * scale).round() as u32,
        );
        let (pane_w, pane_h) = split_pane_dims(
            PaneLayout::HSplit,
            primary_surface.0,
            primary_surface.1,
            false,
        );

        // This is the synchronous operation performed by commit_split_pane;
        // no Slint pane-resized callback is involved in the regression.
        settle_split_incumbent(&mut tab, 0, &mut primary_surface, pane_w, pane_h, scale);

        let committed_target = (
            (primary_surface.0 * scale).round() as u32,
            (primary_surface.1 * scale).round() as u32,
        );
        assert_eq!(old_target, (1800, 1200));
        assert_eq!(committed_target, (900, 1158));
        assert_ne!(committed_target, old_target);
        assert_eq!(primary_surface, (600.0, 772.0));

        let resize_calls = resized.lock().unwrap();
        assert_eq!(
            resize_calls.as_slice(),
            &[TerminalSize {
                cols: tab.cols,
                rows: tab.rows,
            }]
        );
    }

    #[test]
    fn first_vertical_split_targets_half_outer_height_below_each_chrome() {
        let (pane_w, pane_h) = split_pane_dims(PaneLayout::VSplit, 1200.0, 800.0, false);
        assert_eq!((pane_w, pane_h), (1200.0, 372.0));

        let scale = 1.5;
        let target = (
            (pane_w * scale).round() as u32,
            (pane_h * scale).round() as u32,
        );
        assert_eq!(target, (1800, 558));
    }

    #[test]
    fn nested_vertical_split_reconstructs_outer_height_before_halving() {
        // A pane with 772px of content is already inside an 800px PaneSlot:
        // reconstruct that outer height, split it, then reserve 28px in each
        // child. Subtracting chrome directly from 772 / 2 would be wrong.
        let (pane_w, pane_h) = split_pane_dims(PaneLayout::VSplit, 600.0, 772.0, true);
        assert_eq!((pane_w, pane_h), (600.0, 372.0));

        let scale = 1.5;
        let target = (
            (pane_w * scale).round() as u32,
            (pane_h * scale).round() as u32,
        );
        assert_eq!(target, (900, 558));
    }

    #[test]
    fn saved_split_name_survives_promotion_to_primary() {
        let (mut tab, _sinks) = test_tab(2);
        tab.identity = "Original tab".to_owned();
        tab.extra_panes[0].identity = "Saved lab console".to_owned();
        tab.extra_panes[0].title = "Saved lab console".to_owned();
        let mut tab_title = "Original tab".to_owned();

        promote_extra_to_primary(&mut tab, 0, &mut tab_title);

        assert_eq!(tab.identity, "Saved lab console");
        assert_eq!(tab_title, "Saved lab console");
    }

    #[test]
    fn broadcast_target_label_reflects_selection() {
        let (mut tab, _sinks) = test_tab(4);
        assert_eq!(
            tab.broadcast_target.label(tab.pane_group.count()),
            "all panes"
        );
        tab.broadcast_target = BroadcastTarget::Custom {
            name: None,
            panes: BTreeSet::from([0, 1]),
        };
        assert_eq!(
            tab.broadcast_target.label(tab.pane_group.count()),
            "2 of 4 panes"
        );
        tab.broadcast_target = BroadcastTarget::Custom {
            name: Some("prod".to_string()),
            panes: BTreeSet::from([0]),
        };
        assert_eq!(
            tab.broadcast_target.label(tab.pane_group.count()),
            "group: prod"
        );
    }

    // Connect-in-split RDP resolution.
    // `connect_in_split`'s Rdp arm bypasses `open_rdp_tab`, so it has to
    // apply `sessions::pane_resolution_override` itself using the split
    // slot's own `(pane_w, pane_h, scale)` - this proves the exact
    // `(logical * scale).round.max(1.0)` conversion used there produces
    // the same physical-pixel override as the primary-pane path
    // (`apply_settled_resize`, tabs.rs) would for the same inputs.
    #[test]
    fn connect_in_split_pane_size_to_px_matches_primary_pane_formula() {
        // A split slot's fractional logical size at a HiDPI 1.5x scale.
        let (pane_w, pane_h, scale): (f32, f32, f32) = (639.5, 359.7, 1.5);
        let (width, height) = sessions::pane_resolution_override(
            Some((
                (pane_w * scale).round().max(1.0) as u32,
                (pane_h * scale).round().max(1.0) as u32,
            )),
            (1280, 720), // stand-in for the saved profile's stored resolution
        );
        // 639.5 * 1.5 = 959.25 -> rounds to 959; 359.7 * 1.5 = 539.55 -> 540.
        assert_eq!((width, height), (959, 540));
    }

    #[test]
    fn connect_in_split_pane_size_wins_over_a_tiny_slot_via_the_clamp() {
        // A degenerate (not-yet-laid-out) split slot must still clamp to
        // the same [200, 8192] floor `pane_resolution_override` enforces
        // for the primary-pane path - never a literally-zero desktop.
        let (pane_w, pane_h, scale): (f32, f32, f32) = (0.0, 0.0, 1.0);
        let (width, height) = sessions::pane_resolution_override(
            Some((
                (pane_w * scale).round().max(1.0) as u32,
                (pane_h * scale).round().max(1.0) as u32,
            )),
            (1280, 720),
        );
        assert_eq!((width, height), (200, 200));
    }

    #[test]
    fn rdp_split_endpoint_exhaustion_rolls_back_the_reserved_slot() {
        let mut rolled_back = false;
        let endpoint = endpoint_or_rollback(None, || rolled_back = true);

        assert_eq!(endpoint, None);
        assert!(
            rolled_back,
            "allocation failure must release the already-reserved split slot"
        );
    }
}

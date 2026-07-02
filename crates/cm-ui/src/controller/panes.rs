//! Split-pane management: split/close/broadcast/detach/focus/resize, and
//! reattaching a previously-detached session.
use std::cell::RefCell;
use std::rc::Rc;

use cm_session::{LocalTerminalSession, PaneGroup, PaneLayout, SessionStatus, Surface};
use slint::{ComponentHandle, Model, SharedString, TimerMode, VecModel};

use crate::terminal_renderer::{TerminalRenderer, TerminalTheme};
use crate::{AppWindow, TabItem};

use super::*;

pub(super) fn wire_panes(ctx: &Ctx) {
    wire_toggle_broadcast(ctx);
    wire_split_pane_h(ctx);
    wire_split_pane_v(ctx);
    wire_close_pane(ctx);
    wire_detach_session(ctx);
    wire_pane_focused(ctx);
    wire_pane_resized(ctx);
}

fn wire_toggle_broadcast(ctx: &Ctx) {
    ctx.ui.on_toggle_broadcast({
        let weak = ctx.ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_broadcast_active(!ui.get_broadcast_active());
            }
        }
    });
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

fn wire_close_pane(ctx: &Ctx) {
    ctx.ui.on_close_pane({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                do_close_pane(&state, &tab_model, &ui, false);
            }
        }
    });
}

fn wire_detach_session(ctx: &Ctx) {
    ctx.ui.on_detach_session({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                do_close_pane(&state, &tab_model, &ui, true);
            }
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
                tab.pane_group.set_focused(pane_idx as usize);
            }
            if let Some(ui) = weak.upgrade() {
                ui.set_active_pane(pane_idx);
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

/// Split the active tab's pane group, spawning a new local terminal in pane 1.
pub(super) fn do_split(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    layout: PaneLayout,
) {
    let (new_pane_idx, scale, surface_w, surface_h, fonts, font_size_px, ls) = {
        let mut st = state.borrow_mut();
        let active = st.active;
        let Some(tab) = st.tabs.get_mut(active) else {
            return;
        };
        let Some(new_idx) = tab.pane_group.split(layout) else {
            return; // already at max panes
        };
        (
            new_idx,
            st.scale,
            st.surface_w,
            st.surface_h,
            st.fonts.clone(),
            st.font_size_px,
            st.local_settings.clone(),
        )
    };

    // Spawn a new local terminal for the extra pane (half the width for H-split).
    let renderer = TerminalRenderer::with_fonts(fonts, font_size_px, scale, TerminalTheme::dark());
    let pane_w = match layout {
        PaneLayout::HSplit => (surface_w / 2.0).max(1.0),
        PaneLayout::VSplit => surface_w,
        PaneLayout::Single => surface_w,
    };
    let pane_h = match layout {
        PaneLayout::VSplit => (surface_h / 2.0).max(1.0),
        _ => surface_h,
    };
    let size = if pane_w > 0.0 && pane_h > 0.0 {
        util::grid_for(&renderer, pane_w, pane_h, scale)
    } else {
        INITIAL_SIZE
    };

    let session = match LocalTerminalSession::spawn(&ls, size) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("split pane spawn failed: {e}");
            // Roll back the pane group change.
            let mut st = state.borrow_mut();
            let active = st.active;
            if let Some(tab) = st.tabs.get_mut(active) {
                // The split already happened in pane_group; close it back.
                let _ = tab.pane_group.close_focused();
            }
            return;
        }
    };

    {
        let mut st = state.borrow_mut();
        let active = st.active;
        if let Some(tab) = st.tabs.get_mut(active) {
            let ep = ExtraPaneState {
                session: Box::new(session),
                renderer,
                last: None,
                cols: size.cols,
                rows: size.rows,
                scale,
                surface_w: pane_w,
                surface_h: pane_h,
            };
            // Defensive: only push when the index is contiguous (2-pane case
            // always satisfies this; a future N-pane extension might not).
            if tab.extra_panes.len() <= new_pane_idx {
                tab.extra_panes.push(ep);
            }
        }
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
}

/// Close the focused pane in the active tab.
///
/// If `detach` is `true`, the closed pane's session is moved to the detached
/// list (kept running).  If `false`, the session is shut down immediately.
pub(super) fn do_close_pane(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    detach: bool,
) {
    let (closed_idx, new_layout, new_focused, tab_label) = {
        let mut st = state.borrow_mut();
        let active = st.active;
        let Some(tab) = st.tabs.get_mut(active) else {
            return;
        };
        if tab.pane_group.count() <= 1 {
            return; // nothing to close (caller should use close_tab instead)
        }
        let Some(closed) = tab.pane_group.close_focused() else {
            return;
        };
        let new_layout = tab.pane_group.layout();
        let new_focused = tab.pane_group.focused();
        let label = tab_model
            .row_data(active)
            .map(|t| t.title.to_string())
            .unwrap_or_else(|| format!("tab {}", tab.num));
        (closed, new_layout, new_focused, label)
    };

    // Remove the ExtraPaneState for the closed pane (index = closed_idx - 1
    // since extra_panes is 0-based for pane 1+).
    if closed_idx >= 1 {
        let ep_idx = closed_idx - 1;
        let mut st = state.borrow_mut();
        let active = st.active;
        if let Some(tab) = st.tabs.get_mut(active)
            && ep_idx < tab.extra_panes.len()
        {
            let ep = tab.extra_panes.remove(ep_idx);
            if detach
                && !matches!(
                    ep.session.status(),
                    SessionStatus::Exited(_) | SessionStatus::Failed(_)
                )
            {
                st.detached.push(DetachedEntry {
                    session: ep.session,
                    label: format!("{tab_label} [pane {}]", closed_idx + 1),
                });
                ui.set_detached_count(st.detached.len() as i32);
            } else {
                ep.session.shutdown();
            }
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
            tab_model.set_row_data(active, item);
        }
    }

    ui.set_pane_layout(layout_to_int(new_layout));
    ui.set_active_pane(new_focused as i32);
    // Re-render the newly focused pane.
    let mut st = state.borrow_mut();
    sessions::render_active(&mut st, ui);
}

/// Reattach a previously detached session to a new tab.
///
/// The detached entry is consumed — the session is moved from `State::detached`
/// back into the tab list.  A new `TerminalRenderer` is created for the session
/// since the old one was discarded when the tab was closed.
pub(super) fn reattach_session(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    entry: DetachedEntry,
) {
    let label = entry.label.clone();
    let session = entry.session;
    // Use a transient renderer; the session will re-render on first tick.
    let (scale, fonts, font_size_px) = {
        let st = state.borrow();
        (st.scale, st.fonts.clone(), st.font_size_px)
    };
    let renderer = TerminalRenderer::with_fonts(fonts, font_size_px, scale, TerminalTheme::dark());
    let status_dot = match session.status() {
        SessionStatus::Connected => "connected",
        SessionStatus::Connecting => "connecting",
        _ => "disconnected",
    };
    let initial_status: &'static str = status_dot;
    let is_remote = !matches!(session.surface(), Surface::TerminalGrid(_))
        || label.starts_with("SSH ")
        || label.starts_with("RDP ");
    {
        let mut st = state.borrow_mut();
        let used: Vec<u32> = st.tabs.iter().map(|t| t.num).collect();
        let num = tabs::lowest_free_number(&used);
        st.tabs.push(Tab {
            session,
            renderer,
            last: None,
            last_frame: None,
            rdp_w: 0,
            rdp_h: 0,
            rdp_clipboard: None,
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
        });
        st.active = st.tabs.len() - 1;
        let active = st.active;
        drop(st);

        let tab_title = format!("[r] {label}");
        tab_model.push(TabItem {
            title: SharedString::from(tab_title),
            id: 0,
            status: SharedString::from(initial_status),
            pane_count: 1,
        });
        ui.set_active_tab(active as i32);
        ui.set_pane_layout(0);
        ui.set_active_pane(0);
        ui.set_session_status(SharedString::from(initial_status));
        ui.set_session_identity(SharedString::from(label.as_str()));
        ui.set_overlay_connecting(false);
        ui.set_overlay_error(false);
        ui.set_launchpad_open(false);
        ui.set_rdp_active(false);
    }
    // Update the detached count.
    let count = state.borrow().detached.len();
    ui.set_detached_count(count as i32);
}

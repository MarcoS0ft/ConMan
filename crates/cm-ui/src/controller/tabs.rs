//! Tab lifecycle: push/open/select/close, and the resize-tab debounce path.
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use cm_session::{LocalTerminalSession, PaneGroup, Session, SessionStatus, Surface};
use slint::{ComponentHandle, Model, SharedString, TimerMode, VecModel};

use crate::selection::PaneSelectionState;
use crate::terminal_renderer::{TerminalRenderer, TerminalTheme};
use crate::{AppWindow, TabItem};

use super::*;

pub(super) fn wire_tabs(ctx: &Ctx) {
    wire_new_tab(ctx);
    wire_select_tab(ctx);
    wire_close_tab(ctx);
    wire_surface_resized(ctx);
}

fn wire_new_tab(ctx: &Ctx) {
    ctx.ui.on_new_tab({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                open_local_tab(&state, &tab_model, &ui);
            }
        }
    });
}

fn wire_select_tab(ctx: &Ctx) {
    ctx.ui.on_select_tab({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |idx| {
            if let Some(ui) = weak.upgrade() {
                select_tab(&state, &ui, idx);
            }
        }
    });
}

fn wire_close_tab(ctx: &Ctx) {
    ctx.ui.on_close_tab({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        move |idx| {
            if let Some(ui) = weak.upgrade() {
                close_tab(&state, &tab_model, &ui, idx as usize);
            }
        }
    });
}

fn wire_surface_resized(ctx: &Ctx) {
    {
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        let debounce = ctx.resize_debounce.clone();
        ctx.ui.on_surface_resized(move |w, h| {
            if let Some(ui) = weak.upgrade() {
                let mut st = state.borrow_mut();
                st.scale = ui.window().scale_factor();
                st.surface_w = w;
                st.surface_h = h;
                tracing::debug!("resize event  {w:.0}x{h:.0} logical (debouncing)");
                sessions::render_active(&mut st, &ui);
            }
            let state = state.clone();
            let weak = weak.clone();
            debounce.start(TimerMode::SingleShot, RESIZE_DEBOUNCE, move || {
                if let Some(ui) = weak.upgrade() {
                    apply_settled_resize(&state, &ui);
                }
            });
        });
    }
}

pub(super) fn lowest_free_number(used: &[u32]) -> u32 {
    let mut n = 1;
    while used.contains(&n) {
        n += 1;
    }
    n
}

pub(super) struct PushTabArgs {
    pub(super) session: Box<dyn Session>,
    pub(super) connect_info: Option<SshConnectInfo>,
    pub(super) is_remote: bool,
    /// RDP only: Arc to the drive thread's remote-clipboard slot (for CLIPRDR sync).
    pub(super) rdp_clipboard: Option<Arc<Mutex<Option<String>>>>,
    pub(super) title: String,
    pub(super) initial_status: &'static str,
    /// The stored connection id this tab was launched from, if any (P6.9 gap 16;
    /// see `Tab::origin_connection_id`).
    pub(super) origin_connection_id: Option<i32>,
    /// See `Tab::is_empty` (P6.14 gap 3). `false` for every real connect path.
    pub(super) is_empty: bool,
}

pub(super) fn push_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    args: PushTabArgs,
) {
    let PushTabArgs {
        session,
        connect_info,
        is_remote,
        rdp_clipboard,
        title,
        initial_status,
        origin_connection_id,
        is_empty,
    } = args;
    let mut st = state.borrow_mut();
    let scale = st.scale;
    let renderer = TerminalRenderer::with_fonts(
        st.fonts.clone(),
        st.font_size_px,
        scale,
        TerminalTheme::dark(),
    );
    let size = if st.surface_w > 0.0 && st.surface_h > 0.0 {
        util::grid_for(&renderer, st.surface_w, st.surface_h, scale)
    } else {
        INITIAL_SIZE
    };
    let used: Vec<u32> = st.tabs.iter().map(|t| t.num).collect();
    let num = lowest_free_number(&used);
    st.tabs.push(Tab {
        session,
        renderer,
        last: None,
        last_frame: None,
        rdp_w: 0,
        rdp_h: 0,
        rdp_clipboard,
        cols: size.cols,
        rows: size.rows,
        scale,
        num,
        connect_info,
        is_remote,
        origin_connection_id,
        pane_group: PaneGroup::single(),
        extra_panes: Vec::new(),
        sel: PaneSelectionState::default(),
        last_focused_pane: 0,
        is_empty,
    });
    st.active = st.tabs.len() - 1;
    let active = st.active;
    drop(st);

    tab_model.push(TabItem {
        title: SharedString::from(title),
        id: num as i32,
        status: SharedString::from(initial_status),
        pane_count: 1,
    });
    ui.set_active_tab(active as i32);
    ui.set_session_status(SharedString::from(initial_status));
    // P6.14: keep the "restore last session" snapshot current on every tab
    // open (write-through rather than a single on-exit hook -- robust
    // against a crash/kill, matching how other UI prefs already persist
    // eagerly on change, e.g. `sidebar_collapsed`/`active_panel`).
    startup::persist_session_tabs(state);
}

/// Opens a plain local-shell tab (terminal visible immediately).
pub(super) fn open_local_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
) {
    open_local_tab_inner(state, tab_model, ui, false);
}

/// P6.14 (gap 3): opens a tab backed by the same plain local shell, but
/// fronted by the Launchpad ("home" state) until the user picks something
/// from it. Used for the app's empty-workspace slot (non-first-launch
/// startup with nothing to restore) and for "explicitly emptied" -- closing
/// the last real tab lands here instead of quitting (see `close_tab`).
pub(super) fn open_empty_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
) {
    open_local_tab_inner(state, tab_model, ui, true);
}

fn open_local_tab_inner(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    is_empty: bool,
) {
    let (size, ls) = {
        let st = state.borrow();
        (st.current_grid(), st.local_settings.clone())
    };
    let session = match LocalTerminalSession::spawn(&ls, size) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("failed to open terminal: {e}");
            return;
        }
    };
    let used: Vec<u32> = state.borrow().tabs.iter().map(|t| t.num).collect();
    let num = lowest_free_number(&used);
    let title = format!("shell {num}");
    let identity = format!("shell {num}");
    push_tab(
        state,
        tab_model,
        ui,
        PushTabArgs {
            session: Box::new(session),
            connect_info: None,
            is_remote: false,
            rdp_clipboard: None,
            title,
            initial_status: "connected",
            origin_connection_id: None,
            is_empty,
        },
    );
    ui.set_session_identity(SharedString::from(identity));
    ui.set_overlay_connecting(false);
    ui.set_overlay_error(false);
    ui.set_rdp_active(false);
    if is_empty {
        ui.set_launchpad_open(true);
        launchpad::refresh_recents(state, ui);
    } else {
        ui.set_launchpad_open(false);
    }
}

pub(super) fn select_tab(state: &Rc<RefCell<State>>, ui: &AppWindow, idx: i32) {
    let mut st = state.borrow_mut();
    let idx = idx.max(0) as usize;
    if idx >= st.tabs.len() {
        return;
    }
    st.active = idx;
    ui.set_active_tab(idx as i32);
    let pane_layout = st.tabs[idx].pane_group.layout();
    ui.set_pane_layout(panes::layout_to_int(pane_layout));
    ui.set_active_pane(st.tabs[idx].pane_group.focused() as i32);
    let status = st.tabs[idx].session.status();
    let tab = &st.tabs[idx];
    overlays::update_overlays_from_status(ui, tab, &status);
    sessions::render_active(&mut st, ui);
    drop(st);
    startup::persist_session_tabs(state);
}

pub(super) fn close_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    idx: usize,
) {
    let mut st = state.borrow_mut();
    if idx >= st.tabs.len() {
        return;
    }
    let tab = st.tabs.remove(idx);
    let label = tab_model
        .row_data(idx)
        .map(|t| t.title.to_string())
        .unwrap_or_else(|| format!("tab {}", tab.num));
    // P5.1: Detach all sessions in this tab (keep running in the background).
    // Sessions that have already exited or failed are shut down immediately.
    let should_detach = |s: &dyn Session| {
        !matches!(
            s.status(),
            SessionStatus::Exited(_) | SessionStatus::Failed(_)
        )
    };
    if should_detach(tab.session.as_ref()) {
        st.detached.push(DetachedEntry {
            session: tab.session,
            label: label.clone(),
        });
    } else {
        tab.session.shutdown();
    }
    for (i, ep) in tab.extra_panes.into_iter().enumerate() {
        if should_detach(ep.session.as_ref()) {
            st.detached.push(DetachedEntry {
                session: ep.session,
                label: format!("{} [pane {}]", label, i + 2),
            });
        } else {
            ep.session.shutdown();
        }
    }
    tab_model.remove(idx);

    // Update detached count so the palette can show "Reattach" actions.
    ui.set_detached_count(st.detached.len() as i32);

    if st.tabs.is_empty() {
        drop(st);
        // P6.14 (gap 3): closing the last real tab lands on the Launchpad
        // home tab ("explicitly emptied") instead of quitting the app --
        // `open_empty_tab` persists its own snapshot (empty tab list).
        open_empty_tab(state, tab_model, ui);
        return;
    }
    if st.active >= idx && st.active > 0 {
        st.active -= 1;
    }
    if st.active >= st.tabs.len() {
        st.active = st.tabs.len() - 1;
    }
    let active = st.active;
    ui.set_active_tab(active as i32);
    // Reset pane layout when switching to a single-pane tab.
    let pane_layout = st.tabs[active].pane_group.layout();
    ui.set_pane_layout(panes::layout_to_int(pane_layout));
    ui.set_active_pane(st.tabs[active].pane_group.focused() as i32);
    let status = st.tabs[active].session.status();
    overlays::update_overlays_from_status(ui, &st.tabs[active], &status);
    sessions::render_active(&mut st, ui);
    drop(st);
    startup::persist_session_tabs(state);
}

pub(super) fn apply_settled_resize(state: &Rc<RefCell<State>>, ui: &AppWindow) {
    let mut st = state.borrow_mut();
    let scale = st.scale;
    let font_size_px = st.font_size_px;
    let (w, h) = (st.surface_w, st.surface_h);
    if w <= 0.0 || h <= 0.0 {
        return;
    }
    for tab in &mut st.tabs {
        if (tab.scale - scale).abs() > f32::EPSILON {
            tab.renderer.set_scale(font_size_px, scale);
            tab.scale = scale;
        }
        match tab.session.surface() {
            Surface::TerminalGrid(_) => {
                let size = util::grid_for(&tab.renderer, w, h, scale);
                if size.cols != tab.cols || size.rows != tab.rows {
                    tab.session.resize_cells(size.cols, size.rows);
                    tab.cols = size.cols;
                    tab.rows = size.rows;
                    tracing::debug!(
                        "resize commit -> {}x{} cells (settled)",
                        size.cols,
                        size.rows
                    );
                }
            }
            Surface::Framebuffer(_) => {
                let pw = (w * scale).round().max(1.0) as u32;
                let ph = (h * scale).round().max(1.0) as u32;
                tab.session.resize_px(pw, ph);
            }
        }
        // P5.1: Resize extra panes using their own reported dimensions.
        for ep in &mut tab.extra_panes {
            if ep.surface_w <= 0.0 || ep.surface_h <= 0.0 {
                continue;
            }
            if (ep.scale - scale).abs() > f32::EPSILON {
                ep.renderer.set_scale(font_size_px, scale);
                ep.scale = scale;
            }
            if matches!(ep.session.surface(), Surface::TerminalGrid(_)) {
                let ep_size = util::grid_for(&ep.renderer, ep.surface_w, ep.surface_h, scale);
                if ep_size.cols != ep.cols || ep_size.rows != ep.rows {
                    ep.session.resize_cells(ep_size.cols, ep_size.rows);
                    ep.cols = ep_size.cols;
                    ep.rows = ep_size.rows;
                }
            }
        }
    }
    sessions::render_active(&mut st, ui);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowest_free_number_reuses_gaps() {
        assert_eq!(lowest_free_number(&[]), 1);
        assert_eq!(lowest_free_number(&[1, 2, 3]), 4);
        assert_eq!(lowest_free_number(&[1, 3]), 2);
        assert_eq!(lowest_free_number(&[3, 1]), 2);
        assert_eq!(lowest_free_number(&[2, 3]), 1);
    }
}

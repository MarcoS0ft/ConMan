//! Tab lifecycle: push/open/select/close, and the resize-tab debounce path.
use std::cell::RefCell;
use std::rc::Rc;
use std::thread;

use cm_core::LocalSettings;
use cm_session::{PaneGroup, Session, SessionStatus, Surface};
use slint::{ComponentHandle, Model, SharedString, TimerMode, VecModel};

use crate::selection::PaneSelectionState;
use crate::terminal_renderer::TerminalRenderer;
use crate::{AppWindow, TabItem};

use super::*;

pub(super) fn wire_tabs(ctx: &Ctx) {
    wire_new_tab(ctx);
    wire_select_tab(ctx);
    wire_request_tab_select(ctx);
    wire_defer_tab_select(ctx);
    wire_move_tab(ctx);
    wire_close_tab(ctx);
    wire_tab_reconnect(ctx);
    wire_tab_disconnect(ctx);
    wire_tab_duplicate(ctx);
    wire_surface_resized(ctx);
}

fn wire_request_tab_select(ctx: &Ctx) {
    ctx.ui.on_request_tab_select({
        let weak = ctx.ui.as_weak();
        move |idx| {
            let Some(ui) = weak.upgrade() else { return };
            ui.invoke_select_tab(idx);
            let weak = ui.as_weak();
            // Let the selector's frame/conditional-surface bindings settle
            // before focusing the newly active surface or pane.
            slint::Timer::single_shot(std::time::Duration::from_millis(1), move || {
                if let Some(ui) = weak.upgrade() {
                    ui.invoke_focus_active_session();
                }
            });
        }
    });
}

fn wire_defer_tab_select(ctx: &Ctx) {
    ctx.ui.on_defer_tab_select({
        let weak = ctx.ui.as_weak();
        move |idx| {
            let weak = weak.clone();
            // Keyboard capture cannot remove its focused conditional surface
            // while that surface's key event is still unwinding.
            slint::Timer::single_shot(std::time::Duration::ZERO, move || {
                if let Some(ui) = weak.upgrade() {
                    ui.invoke_request_tab_select(idx);
                }
            });
        }
    });
}

fn wire_move_tab(ctx: &Ctx) {
    ctx.ui.on_move_tab({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        move |from, to| {
            if let Some(ui) = weak.upgrade() {
                move_tab(&state, &tab_model, &ui, from as usize, to as usize);
            }
        }
    });
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
                close::request_tab_close(&state, &tab_model, &ui, idx as usize);
            }
        }
    });
}

/// #1: the tab context menu's "Reconnect" - `sessions::reconnect_tab`
/// does the real work (shared with the ErrorOverlay's own Reconnect button),
/// but it writes AppWindow-level properties that are shared by whichever
/// tab is ACTIVE, not per-tab (see `reconnect_tab`'s own doc comment). Bring
/// the right-clicked tab into view first - mirrors how choosing "Connect"
/// on a tree row already opens+focuses a new tab rather than acting
/// off-screen - so those properties land on the tab the user actually
/// asked to reconnect.
fn wire_tab_reconnect(ctx: &Ctx) {
    ctx.ui.on_tab_reconnect({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        let hk_pending = ctx.hk_pending.clone();
        let cert_pending = ctx.cert_pending.clone();
        let secrets = ctx.secrets.clone();
        move |idx| {
            let Some(ui) = weak.upgrade() else { return };
            let idx = idx as usize;
            if idx >= state.borrow().tabs.len() {
                return;
            }
            select_tab(&state, &ui, idx as i32);
            sessions::reconnect_tab(
                &state,
                &tab_model,
                &ui,
                &weak,
                &hk_pending,
                &cert_pending,
                &secrets,
                idx,
            );
        }
    });
}

/// #1: the tab context menu's "Disconnect" - same active-tab-first
/// reasoning as [`wire_tab_reconnect`] (`sessions::disconnect_tab` writes
/// the same kind of AppWindow-shared overlay properties via
/// `fail_reconnect_in_place`).
fn wire_tab_disconnect(ctx: &Ctx) {
    ctx.ui.on_tab_disconnect({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        move |idx| {
            let Some(ui) = weak.upgrade() else { return };
            let idx = idx as usize;
            if idx >= state.borrow().tabs.len() {
                return;
            }
            select_tab(&state, &ui, idx as i32);
            close::request_tab_disconnect(&state, &tab_model, &ui, idx);
        }
    });
}

/// #1: the tab context menu's "Duplicate" - reuses
/// `sessions::launch_saved_connection` (the exact same stored-credential
/// connect path a tree-row double-click/Enter/context-menu Connect already
/// goes through) for a tab whose `origin_connection_id` is known, or
/// `open_local_tab` for a plain local shell with none. The UI already omits
/// this menu item when neither applies (`TabItem::can_duplicate`); the
/// `None` arm below is defense in depth, not the primary guard.
fn wire_tab_duplicate(ctx: &Ctx) {
    ctx.ui.on_tab_duplicate({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        let hk_pending = ctx.hk_pending.clone();
        let cert_pending = ctx.cert_pending.clone();
        let secrets = ctx.secrets.clone();
        move |idx| {
            let Some(ui) = weak.upgrade() else { return };
            let idx = idx as usize;
            let target = {
                let st = state.borrow();
                st.tabs
                    .get(idx)
                    .map(|t| (t.origin_connection_id, t.is_remote))
            };
            let Some((origin_connection_id, is_remote)) = target else {
                return;
            };
            match origin_connection_id {
                Some(conn_id) => {
                    let conn = {
                        let st = state.borrow();
                        st.conn_tree
                            .connections()
                            .iter()
                            .find(|c| c.id.get() as i32 == conn_id)
                            .cloned()
                    };
                    if let Some(conn) = conn {
                        sessions::launch_saved_connection(
                            &state,
                            &tab_model,
                            &ui,
                            &weak,
                            &hk_pending,
                            &cert_pending,
                            &secrets,
                            &conn,
                        );
                    }
                }
                None if !is_remote => open_local_tab(&state, &tab_model, &ui),
                None => {}
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
    pub(super) endpoint_id: Option<cm_core::SessionEndpointId>,
    pub(super) connect_info: Option<ConnectInfo>,
    pub(super) is_remote: bool,
    pub(super) title: String,
    pub(super) initial_status: &'static str,
    /// The stored connection id this tab was launched from, if any (
    /// see `Tab::origin_connection_id`).
    pub(super) origin_connection_id: Option<i32>,
    /// See `Tab::is_empty`. `false` for every real connect path.
    pub(super) is_empty: bool,
    /// See `Tab::identity` ( #3). Whatever the caller is about to (or
    /// just did) pass to `ui.set_session_identity`.
    pub(super) identity: String,
    /// See `Tab::kind` ( #3). `"SSH"`/`"RDP"`, or empty for local shells.
    pub(super) kind: String,
    /// See `Tab::insecure_transport`. True only for plain Telnet.
    pub(super) insecure_transport: bool,
}

pub(super) fn push_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    args: PushTabArgs,
) {
    let PushTabArgs {
        session,
        endpoint_id,
        connect_info,
        is_remote,
        title,
        initial_status,
        origin_connection_id,
        is_empty,
        identity,
        kind,
        insecure_transport,
    } = args;
    let mut st = state.borrow_mut();
    let scale = st.scale;
    let renderer = TerminalRenderer::with_font_system(
        st.fonts.clone(),
        &st.font_family,
        st.font_size_px,
        scale,
        // pick dark/light from the live app theme at spawn time
        // instead of always hardcoding dark.
        util::terminal_theme_for(ui),
    );
    let size = if st.surface_w > 0.0 && st.surface_h > 0.0 {
        util::grid_for(&renderer, st.surface_w, st.surface_h, scale)
    } else {
        INITIAL_SIZE
    };
    let used: Vec<u32> = st.tabs.iter().map(|t| t.num).collect();
    let num = lowest_free_number(&used);
    let Some(endpoint_id) = endpoint_id.or_else(|| st.allocate_endpoint_id()) else {
        tracing::error!("session endpoint ID space exhausted");
        session.shutdown();
        return;
    };
    st.tabs.push(Tab {
        endpoint_id,
        session,
        renderer,
        last: None,
        last_frame: None,
        rdp_w: 0,
        rdp_h: 0,
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
        broadcast_target: panes::BroadcastTarget::default(),
        broadcast_saved_groups: Vec::new(),
        search: super::search::SearchState::default(),
        identity,
        kind: kind.clone(),
        insecure_transport,
        connect_started: std::time::Instant::now(),
    });
    st.active = st.tabs.len() - 1;
    let active = st.active;
    drop(st);

    tab_model.push(TabItem {
        title: SharedString::from(title),
        id: num as i32,
        status: SharedString::from(initial_status),
        pane_count: 1,
        // #3: mirrors this exact tab's own `is_empty` - the Home tab
        // (and only the Home tab) is pushed with `is_empty: true`.
        is_home: is_empty,
        // #1: see `TabItem::can_duplicate`'s doc comment.
        can_duplicate: origin_connection_id.is_some() || !is_remote,
    });
    ui.set_active_tab(active as i32);
    ui.set_session_status(SharedString::from(initial_status));
    ui.set_connecting_kind(SharedString::from(kind));
    ui.set_session_insecure(insecure_transport);
    // keep the "restore last session" snapshot current on every tab
    // open (write-through rather than a single on-exit hook - robust
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

/// opens a tab backed by the same plain local shell, but
/// fronted by the Launchpad ("home" state) until the user picks something
/// from it. Used for the app's empty-workspace slot (non-first-launch
/// startup with nothing to restore) and for "explicitly emptied" - closing
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
    spawn_local_tab(state, tab_model, ui, ls, size, is_empty);
}

/// opens a local-shell tab for the quick-connect dialog's
/// "Local" kind, using the settings typed directly into the dialog instead
/// of the app-wide `local_settings` default. Never persisted - mirrors how
/// quick-connect SSH/RDP auth is `Direct`-provenance, in-memory only.
pub(super) fn open_local_tab_quick(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    ls: LocalSettings,
) {
    let size = state.borrow().current_grid();
    spawn_local_tab(state, tab_model, ui, ls, size, false);
}

/// Shared tail of [`open_local_tab_inner`] / [`open_local_tab_quick`]: spawn
/// the local shell and push its tab.
fn spawn_local_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    ls: LocalSettings,
    size: TerminalSize,
    is_empty: bool,
) {
    let provider = state.borrow().session_provider.clone();
    let options = cm_core::TerminalOptions {
        max_scrollback: state.borrow().scrollback_limit,
    };
    let session = match provider.spawn_local(&ls, size, options) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("failed to open terminal: {e}");
            return;
        }
    };
    let used: Vec<u32> = state.borrow().tabs.iter().map(|t| t.num).collect();
    let num = lowest_free_number(&used);
    // the Launchpad-fronted empty/"home" tab isn't a shell the
    // user asked for - it must never pick up the "shell N" numbering real
    // local-terminal tabs use (that's `Tab::num`/`lowest_free_number`'s job).
    // Give it an explicit, non-shell title instead of falling through to the
    // shell default below.
    let (title, identity) = if is_empty {
        ("Home".to_string(), "Home".to_string())
    } else {
        (format!("shell {num}"), format!("shell {num}"))
    };
    push_tab(
        state,
        tab_model,
        ui,
        PushTabArgs {
            session,
            endpoint_id: None,
            connect_info: None,
            is_remote: false,
            title,
            initial_status: "connected",
            origin_connection_id: None,
            is_empty,
            identity: identity.clone(),
            kind: String::new(),
            insecure_transport: false,
        },
    );
    ui.set_session_identity(SharedString::from(identity));
    ui.set_overlay_connecting(false);
    ui.set_overlay_error(false);
    ui.set_rdp_active(false);
    ui.set_session_insecure(false);
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
    // #3: re-push THIS tab's own cached identity/kind (Tab::identity /
    // Tab::kind) - these two are the only overlay-relevant properties
    // `update_overlays_from_status` doesn't already refresh from live status
    // (it derives `overlay_connecting`/`overlay_error`/`error_reason`/
    // `error_detail` fresh every call), so without this a switch to a tab
    // that's also Connecting/Failed kept showing whichever OTHER tab last
    // called `set_session_identity`/`set_connecting_kind` - the tab-content
    // bleed the user reported.
    ui.set_session_identity(SharedString::from(tab.identity.as_str()));
    ui.set_connecting_kind(SharedString::from(tab.kind.as_str()));
    ui.set_session_insecure(
        tab.insecure_transport || tab.extra_panes.iter().any(|ep| ep.insecure_transport),
    );
    // Flash the overlay scrollbar when switching into a scrolled-back
    // viewport. Bump first so the split cells stamped inside `render_active`
    // carry the new `rev`; the single-pane `rev` prop is set after (values
    // first, then `rev`) so `TerminalScrollbar` evaluates against fresh values.
    st.scroll_rev = st.scroll_rev.wrapping_add(1);
    sessions::render_active(&mut st, ui);
    ui.set_term_scroll_rev(st.scroll_rev as i32);
    drop(st);
    panes::refresh_broadcast_label(state, ui);
    startup::persist_session_tabs(state);
}

/// Moves one visual tab while keeping the controller vector, Slint model,
/// active tab, and tick-time active identity in lockstep.
fn move_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    from: usize,
    to: usize,
) {
    if from == to {
        return;
    }

    // Snapshot and validate every cross-model invariant before either owner
    // is mutated. A stale UI/controller seam is recoverable: log and ignore
    // the drag instead of crashing or leaving half the state reordered.
    let rows = (0..tab_model.row_count())
        .map(|idx| tab_model.row_data(idx))
        .collect::<Option<Vec<_>>>();
    let plan = {
        let st = state.borrow();
        let state_tabs = st
            .tabs
            .iter()
            .map(|tab| i32::try_from(tab.num).ok().map(|id| (id, tab.is_empty)))
            .collect::<Option<Vec<_>>>();
        match (state_tabs, rows.as_deref()) {
            (Some(state_tabs), Some(rows)) => {
                validated_move_plan(&state_tabs, rows, st.active, st.last_active_tab, from, to)
            }
            _ => None,
        }
    };
    let (Some(mut rows), Some(plan)) = (rows, plan) else {
        tracing::warn!(
            from,
            to,
            "tab reorder ignored because state/model invariants drifted"
        );
        return;
    };

    let row = rows.remove(from);
    rows.insert(to, row);
    {
        let mut st = state.borrow_mut();
        let tab = st.tabs.remove(from);
        st.tabs.insert(to, tab);
        st.active = plan.active;
        st.last_active_tab = plan.last_active;
    }
    tab_model.set_vec(rows);
    select_tab(state, ui, plan.active as i32);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MovePlan {
    active: usize,
    last_active: usize,
}

fn validated_move_plan(
    state_tabs: &[(i32, bool)],
    model_tabs: &[TabItem],
    active: usize,
    last_active: usize,
    from: usize,
    to: usize,
) -> Option<MovePlan> {
    let len = state_tabs.len();
    if len == 0
        || model_tabs.len() != len
        || from >= len
        || to >= len
        || active >= len
        || last_active >= len
        || state_tabs
            .iter()
            .zip(model_tabs)
            .any(|(&(id, home), row)| id != row.id || home != row.is_home)
    {
        return None;
    }

    let mut ids = state_tabs.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    ids.sort_unstable();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return None;
    }

    let home_positions = state_tabs
        .iter()
        .enumerate()
        .filter_map(|(idx, (_, home))| home.then_some(idx))
        .collect::<Vec<_>>();
    if home_positions.len() > 1
        || home_positions.first().is_some_and(|idx| *idx != 0)
        || (home_positions == [0] && (from == 0 || to == 0))
    {
        return None;
    }

    let remap = |index: usize| {
        if index == from {
            to
        } else if from < to && (from + 1..=to).contains(&index) {
            index - 1
        } else if to < from && (to..from).contains(&index) {
            index + 1
        } else {
            index
        }
    };
    Some(MovePlan {
        active: remap(active),
        last_active: remap(last_active),
    })
}

/// What to do with a tab's session when its tab is closed.
enum Disposition {
    /// Connected, disconnected, or already stopped; shut down synchronously.
    Shutdown,
    /// Still `Connecting`: hand teardown to a detached thread (see
    /// [`abort_connecting`]) instead of blocking the UI or parking it in the
    /// detached pool.
    AbortConnecting,
}

fn disposition(s: &dyn Session) -> Disposition {
    match s.status() {
        SessionStatus::Connecting => Disposition::AbortConnecting,
        SessionStatus::Connected
        | SessionStatus::Disconnected
        | SessionStatus::Exited(_)
        | SessionStatus::Failed(_) => Disposition::Shutdown,
    }
}

/// Tear down a session that was still `Connecting` when its tab closed.
///
/// `Session::shutdown` joins the driver thread, but a `Connecting` SSH/RDP
/// driver may be blocked inside the TCP connect/handshake (a blackholed host
/// can hold it for the OS-level connect timeout - tens of seconds). Calling
/// `shutdown` straight from the UI callback would freeze the whole app for
/// that long. Move the join to a detached thread instead: the connect
/// attempt still tears down completely (no leaked driver thread/socket),
/// just not on the UI's clock.
fn abort_connecting(session: Box<dyn Session>) {
    let _ = thread::Builder::new()
        .name("abort-connecting".to_owned())
        .spawn(move || session.shutdown());
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
    let closing_endpoints: Vec<_> = std::iter::once(st.tabs[idx].endpoint_id)
        .chain(st.tabs[idx].extra_panes.iter().map(|pane| pane.endpoint_id))
        .collect();
    for endpoint in closing_endpoints {
        sessions::release_pointer_capture_for_endpoint(&mut st, endpoint);
    }
    let tab = st.tabs.remove(idx);
    // Closing a tab terminates every session in it. Keeping a session alive
    // is an explicit action handled by the separate Detach command. A session
    // still `Connecting` is torn down off the UI thread because its driver
    // may be inside a blocking connect/handshake (see `abort_connecting`).
    match disposition(tab.session.as_ref()) {
        Disposition::Shutdown => tab.session.shutdown(),
        Disposition::AbortConnecting => abort_connecting(tab.session),
    }
    for ep in tab.extra_panes {
        match disposition(ep.session.as_ref()) {
            Disposition::Shutdown => ep.session.shutdown(),
            Disposition::AbortConnecting => abort_connecting(ep.session),
        }
    }
    tab_model.remove(idx);

    // Update detached count so the palette can show "Reattach" actions.
    ui.set_detached_count(st.detached.len() as i32);

    if st.tabs.is_empty() {
        drop(st);
        // closing the last real tab lands on the Launchpad
        // home tab ("explicitly emptied") instead of quitting the app -
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
    ui.set_session_identity(SharedString::from(st.tabs[active].identity.as_str()));
    ui.set_connecting_kind(SharedString::from(st.tabs[active].kind.as_str()));
    ui.set_session_insecure(
        st.tabs[active].insecure_transport
            || st.tabs[active]
                .extra_panes
                .iter()
                .any(|ep| ep.insecure_transport),
    );
    sessions::render_active(&mut st, ui);
    drop(st);
    panes::refresh_broadcast_label(state, ui);
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
        // Resize extra panes using their own reported dimensions.
        for ep in &mut tab.extra_panes {
            if ep.surface_w <= 0.0 || ep.surface_h <= 0.0 {
                continue;
            }
            if (ep.scale - scale).abs() > f32::EPSILON {
                ep.renderer.set_scale(font_size_px, scale);
                ep.scale = scale;
            }
            match ep.session.surface() {
                Surface::TerminalGrid(_) => {
                    let ep_size = util::grid_for(&ep.renderer, ep.surface_w, ep.surface_h, scale);
                    if ep_size.cols != ep.cols || ep_size.rows != ep.rows {
                        ep.session.resize_cells(ep_size.cols, ep_size.rows);
                        ep.cols = ep_size.cols;
                        ep.rows = ep_size.rows;
                    }
                }
                // RDP-in-pane resize reactivation, mirroring the
                // primary pane's `Framebuffer` arm above.
                Surface::Framebuffer(_) => {
                    let pw = (ep.surface_w * scale).round().max(1.0) as u32;
                    let ph = (ep.surface_h * scale).round().max(1.0) as u32;
                    ep.session.resize_px(pw, ph);
                }
            }
        }
    }
    sessions::render_active(&mut st, ui);
}

#[cfg(test)]
mod tests {
    use super::*;
    use cm_session::{ExitStatus, SessionInput};
    use std::sync::mpsc;

    /// A session whose `status` is fixed at construction, for exercising
    /// [`disposition`] against every [`SessionStatus`] variant without a real
    /// transport.
    struct FakeSession {
        status: SessionStatus,
        surface: Surface,
    }

    impl FakeSession {
        fn with_status(status: SessionStatus) -> Self {
            let (_tx, rx) = mpsc::channel::<cm_core::terminal::GridSnapshot>();
            Self {
                status,
                surface: Surface::TerminalGrid(rx),
            }
        }
    }

    impl Session for FakeSession {
        fn surface(&self) -> &Surface {
            &self.surface
        }
        fn status(&self) -> SessionStatus {
            self.status.clone()
        }
        fn shutdown(&self) {}
        fn resize_px(&self, _width: u32, _height: u32) {}
        fn send_input(&self, _input: SessionInput) {}
    }

    #[test]
    fn lowest_free_number_reuses_gaps() {
        assert_eq!(lowest_free_number(&[]), 1);
        assert_eq!(lowest_free_number(&[1, 2, 3]), 4);
        assert_eq!(lowest_free_number(&[1, 3]), 2);
        assert_eq!(lowest_free_number(&[3, 1]), 2);
        assert_eq!(lowest_free_number(&[2, 3]), 1);
    }

    fn row(id: i32, home: bool) -> TabItem {
        TabItem {
            id,
            is_home: home,
            ..Default::default()
        }
    }

    #[test]
    fn move_plan_remaps_active_indices_without_identity_lookups() {
        let state = [(1, false), (2, false), (3, false)];
        let model = [row(1, false), row(2, false), row(3, false)];
        assert_eq!(
            validated_move_plan(&state, &model, 1, 2, 0, 2),
            Some(MovePlan {
                active: 0,
                last_active: 1,
            })
        );
    }

    #[test]
    fn move_plan_rejects_drift_and_home_displacement() {
        let state = [(1, true), (2, false), (3, false)];
        let model = [row(1, true), row(2, false), row(3, false)];
        assert!(validated_move_plan(&state, &model, 0, 0, 0, 2).is_none());
        assert!(validated_move_plan(&state, &model, 0, 0, 2, 0).is_none());

        let drifted_ids = [row(1, true), row(9, false), row(3, false)];
        assert!(validated_move_plan(&state, &drifted_ids, 0, 0, 1, 2).is_none());
        let duplicate_state = [(1, false), (1, false), (3, false)];
        let duplicate_model = [row(1, false), row(1, false), row(3, false)];
        assert!(validated_move_plan(&duplicate_state, &duplicate_model, 0, 0, 1, 2).is_none());
        assert!(validated_move_plan(&state, &model, 3, 0, 1, 2).is_none());
    }

    /// (fixes): a `Connecting` session must abort, never detach
    /// - this is the crux of the Cancel/close-during-Connecting fix.
    #[test]
    fn disposition_aborts_connecting_instead_of_detaching() {
        let s = FakeSession::with_status(SessionStatus::Connecting);
        assert!(matches!(disposition(&s), Disposition::AbortConnecting));
    }

    #[test]
    fn disposition_shuts_down_connected_and_disconnected() {
        let connected = FakeSession::with_status(SessionStatus::Connected);
        assert!(matches!(disposition(&connected), Disposition::Shutdown));
        let disconnected = FakeSession::with_status(SessionStatus::Disconnected);
        assert!(matches!(disposition(&disconnected), Disposition::Shutdown));
    }

    #[test]
    fn disposition_shuts_down_exited_and_failed() {
        let exited = FakeSession::with_status(SessionStatus::Exited(ExitStatus {
            success: true,
            code: 0,
        }));
        assert!(matches!(disposition(&exited), Disposition::Shutdown));
        let failed = FakeSession::with_status(SessionStatus::Failed("boom".to_owned()));
        assert!(matches!(disposition(&failed), Disposition::Shutdown));
    }
}

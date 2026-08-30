//! User-initiated close confirmation.
//!
//! This module is deliberately a coordinator, not a second close engine.
//! [`tabs::close_tab`], [`panes::do_close_pane`], and
//! [`sessions::disconnect_tab`] remain unconditional executors. Only UI
//! requests enter here; detach and session-driven termination keep using the
//! executors directly.

use cm_core::{SettingKey, SettingsService};
use cm_session::SessionStatus;
use slint::{CloseRequestResponse, ComponentHandle, Model};

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseAction {
    CloseHome,
    CloseTab,
    DisconnectTab,
    ClosePane,
    Quit,
}

const MODAL_KEY_ESCAPE: i32 = 1;
const MODAL_KEY_TAB_FORWARD: i32 = 2;
const MODAL_KEY_TAB_BACKWARD: i32 = 3;
const MODAL_KEY_ACTIVATE: i32 = 4;
const MODAL_CONTROL_COUNT: i32 = 3;

/// A stable close target retained while the confirmation dialog is open.
///
/// Tab indices and pane ids can shift while an asynchronous session finishes,
/// so the pending intent retains the process-local tab number and endpoint id
/// instead. They are resolved back to the current index only on Confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CloseIntent {
    action: CloseAction,
    tab_num: Option<u32>,
    endpoint_id: Option<cm_core::SessionEndpointId>,
}

impl CloseIntent {
    fn quit() -> Self {
        Self {
            action: CloseAction::Quit,
            tab_num: None,
            endpoint_id: None,
        }
    }
}

fn is_active(status: SessionStatus) -> bool {
    matches!(status, SessionStatus::Connecting | SessionStatus::Connected)
}

fn tab_active_count(tab: &Tab) -> usize {
    if tab.is_empty {
        return 0;
    }
    usize::from(is_active(tab.session.status()))
        + tab
            .extra_panes
            .iter()
            .filter(|pane| is_active(pane.session.status()))
            .count()
}

fn total_active_count(state: &State) -> usize {
    state.tabs.iter().map(tab_active_count).sum::<usize>()
        + state
            .detached
            .iter()
            .filter(|entry| is_active(entry.session.status()))
            .count()
}

fn pane_active(tab: &Tab, endpoint_id: cm_core::SessionEndpointId) -> bool {
    if tab.endpoint_id == endpoint_id {
        return is_active(tab.session.status());
    }
    tab.extra_panes
        .iter()
        .find(|pane| pane.endpoint_id == endpoint_id)
        .is_some_and(|pane| is_active(pane.session.status()))
}

fn plural_connections(count: usize) -> &'static str {
    if count == 1 {
        "connection"
    } else {
        "connections"
    }
}

fn show_confirmation(
    state: &Rc<RefCell<State>>,
    ui: &AppWindow,
    intent: CloseIntent,
    title: &str,
    message: String,
    action_label: &str,
    allow_dont_ask: bool,
) {
    let mut st = state.borrow_mut();
    // A modal close decision is atomic. Do not silently replace its stable
    // target if a second close affordance is activated underneath the scrim.
    if st.pending_close.is_some() {
        return;
    }
    st.pending_close = Some(intent);
    drop(st);

    ui.set_close_confirm_title(title.into());
    ui.set_close_confirm_message(message.into());
    ui.set_close_confirm_action_label(action_label.into());
    ui.set_close_confirm_dont_ask(false);
    ui.set_close_confirm_allow_dont_ask(allow_dont_ask);
    // A modifier may already be down in an RDP destination when the user
    // opens this modal with the mouse. Balance it before the modal starts
    // owning keyboard input; subsequent modal-time presses are swallowed by
    // the paired guards below.
    ui.invoke_rdp_release_keys();
    // Cancel is the safe initial action. Reset through a sentinel so opening
    // consecutive dialogs still runs the Slint focus transfer.
    ui.set_close_confirm_focus_index(-1);
    ui.set_close_confirm_open(true);
    ui.set_close_confirm_focus_index(1);
}

fn refresh_key_guard(state: &State, ui: &AppWindow) {
    ui.set_close_confirm_key_guard_active(
        !state.close_modal_global_keys.is_empty() || !state.close_modal_rdp_keys.is_empty(),
    );
}

/// Terminal callbacks have only a key-down phase. The global Slint capture
/// handles real physical down/up pairing; this function protects direct
/// callback/automation entry points and keeps Escape behavior identical.
pub(super) fn guard_terminal_key(
    _state: &Rc<RefCell<State>>,
    ui: &AppWindow,
    special: i32,
) -> bool {
    if !ui.get_close_confirm_open() {
        return false;
    }
    if special == 4 {
        ui.invoke_close_confirm_cancel();
    }
    true
}

pub(super) fn guard_rdp_key_down(
    state: &Rc<RefCell<State>>,
    ui: &AppWindow,
    text: &str,
    special: i32,
) -> bool {
    if !ui.get_close_confirm_open() {
        return false;
    }
    {
        let mut st = state.borrow_mut();
        st.close_modal_rdp_keys.insert((text.to_owned(), special));
        refresh_key_guard(&st, ui);
    }
    if special == 4 {
        ui.invoke_close_confirm_cancel();
    }
    true
}

pub(super) fn guard_rdp_key_up(
    state: &Rc<RefCell<State>>,
    ui: &AppWindow,
    text: &str,
    special: i32,
) -> bool {
    let mut st = state.borrow_mut();
    let paired_modal_press = st.close_modal_rdp_keys.remove(&(text.to_owned(), special));
    let modal_open = ui.get_close_confirm_open();
    refresh_key_guard(&st, ui);
    paired_modal_press || modal_open
}

pub(super) fn request_tab_close(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    idx: usize,
) {
    let target = {
        let st = state.borrow();
        let Some(tab) = st.tabs.get(idx) else { return };
        (
            tab.num,
            tab.is_empty,
            tab_active_count(tab),
            st.confirm_close_active_tab,
        )
    };
    if target.1 {
        show_confirmation(
            state,
            ui,
            CloseIntent {
                action: CloseAction::CloseHome,
                tab_num: Some(target.0),
                endpoint_id: None,
            },
            "Close Home tab?",
            "Close the Home tab? It will return automatically when no other tabs remain."
                .to_owned(),
            "Close Home",
            false,
        );
        return;
    }
    if target.2 == 0 || !target.3 {
        tabs::close_tab(state, tab_model, ui, idx);
        return;
    }
    let label = tab_model
        .row_data(idx)
        .map(|item| item.title.to_string())
        .unwrap_or_else(|| "this tab".to_owned());
    show_confirmation(
        state,
        ui,
        CloseIntent {
            action: CloseAction::CloseTab,
            tab_num: Some(target.0),
            endpoint_id: None,
        },
        "Close active connection?",
        format!(
            "\"{label}\" has {} active {}. Closing the tab will disconnect {}.",
            target.2,
            plural_connections(target.2),
            if target.2 == 1 { "it" } else { "them" }
        ),
        "Close tab",
        true,
    );
}

pub(super) fn request_tab_disconnect(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    idx: usize,
) {
    let target = {
        let st = state.borrow();
        let Some(tab) = st.tabs.get(idx) else { return };
        (
            tab.num,
            tab.is_empty,
            tab_active_count(tab),
            st.confirm_close_active_tab,
        )
    };
    if target.1 {
        return;
    }
    if target.2 == 0 || !target.3 {
        sessions::disconnect_tab(state, tab_model, ui, idx);
        return;
    }
    let label = tab_model
        .row_data(idx)
        .map(|item| item.title.to_string())
        .unwrap_or_else(|| "this tab".to_owned());
    show_confirmation(
        state,
        ui,
        CloseIntent {
            action: CloseAction::DisconnectTab,
            tab_num: Some(target.0),
            endpoint_id: None,
        },
        "Disconnect active connection?",
        format!(
            "\"{label}\" has {} active {}. Disconnect {} now?",
            target.2,
            plural_connections(target.2),
            if target.2 == 1 { "it" } else { "them" }
        ),
        "Disconnect",
        true,
    );
}

pub(super) fn request_pane_close(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    pane_id: usize,
) {
    let active_tab = state.borrow().active;
    if state
        .borrow()
        .tabs
        .get(active_tab)
        .is_some_and(|tab| tab.pane_group.count() <= 1)
    {
        // Ctrl+Shift+W and the palette's Close pane action remain useful in
        // an unsplit tab: its only pane is the tab's session, so closing it is
        // exactly the tab-close intent (and uses the tab confirmation copy).
        request_tab_close(state, tab_model, ui, active_tab);
        return;
    }
    let target = {
        let st = state.borrow();
        let Some(tab) = st.tabs.get(st.active) else {
            return;
        };
        let endpoint_id = if pane_id == 0 {
            Some(tab.endpoint_id)
        } else {
            tab.extra_panes
                .get(pane_id - 1)
                .map(|pane| pane.endpoint_id)
        };
        let Some(endpoint_id) = endpoint_id else {
            return;
        };
        (
            tab.num,
            endpoint_id,
            pane_active(tab, endpoint_id),
            st.confirm_close_active_tab,
        )
    };
    if !target.2 || !target.3 {
        panes::do_close_pane(state, tab_model, ui, pane_id, false);
        return;
    }
    show_confirmation(
        state,
        ui,
        CloseIntent {
            action: CloseAction::ClosePane,
            tab_num: Some(target.0),
            endpoint_id: Some(target.1),
        },
        "Disconnect active connection?",
        "Closing this pane will terminate its active connection.".to_owned(),
        "Disconnect",
        true,
    );
}

fn request_quit(state: &Rc<RefCell<State>>, ui: &AppWindow) -> CloseRequestResponse {
    let (active, confirm, confirmed) = {
        let st = state.borrow();
        (
            total_active_count(&st),
            st.confirm_quit_active_connections,
            st.quit_confirmed,
        )
    };
    if confirmed || active == 0 || !confirm {
        return CloseRequestResponse::HideWindow;
    }
    show_confirmation(
        state,
        ui,
        CloseIntent::quit(),
        "Quit with active connections?",
        format!(
            "Connection Manager has {active} active {}. Quitting will disconnect {}.",
            plural_connections(active),
            if active == 1 { "it" } else { "them" }
        ),
        "Quit",
        true,
    );
    CloseRequestResponse::KeepWindowShown
}

pub(super) fn wire_close_confirmation(ctx: &Ctx) {
    ctx.ui.on_close_confirm_key_down({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |text, command| {
            let Some(ui) = weak.upgrade() else { return };
            let modal_open = ui.get_close_confirm_open();
            {
                let mut st = state.borrow_mut();
                st.close_modal_global_keys.insert(text.to_string());
                refresh_key_guard(&st, &ui);
            }
            if !modal_open {
                return;
            }
            match command {
                MODAL_KEY_ESCAPE => ui.invoke_close_confirm_cancel(),
                MODAL_KEY_TAB_FORWARD | MODAL_KEY_TAB_BACKWARD => {
                    let current = ui.get_close_confirm_focus_index();
                    let next = if ui.get_close_confirm_allow_dont_ask() {
                        let delta = if command == MODAL_KEY_TAB_FORWARD {
                            1
                        } else {
                            -1
                        };
                        (current + delta).rem_euclid(MODAL_CONTROL_COUNT)
                    } else if current == 1 {
                        2
                    } else {
                        1
                    };
                    ui.set_close_confirm_focus_index(next);
                }
                MODAL_KEY_ACTIVATE => match ui.get_close_confirm_focus_index() {
                    0 if ui.get_close_confirm_allow_dont_ask() => {
                        ui.set_close_confirm_dont_ask(!ui.get_close_confirm_dont_ask());
                    }
                    1 => ui.invoke_close_confirm_cancel(),
                    2 => ui.invoke_close_confirm_accept(),
                    _ => {}
                },
                _ => {}
            }
        }
    });

    ctx.ui.on_close_confirm_key_up({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |text| {
            let Some(ui) = weak.upgrade() else { return };
            let mut st = state.borrow_mut();
            st.close_modal_global_keys.remove(text.as_str());
            refresh_key_guard(&st, &ui);
        }
    });

    ctx.ui.on_close_confirm_cancel({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move || {
            state.borrow_mut().pending_close = None;
            if let Some(ui) = weak.upgrade() {
                ui.set_close_confirm_dont_ask(false);
                ui.set_close_confirm_open(false);
            }
        }
    });

    ctx.ui.on_close_confirm_accept({
        let state = ctx.state.clone();
        let config_store = ctx.config_store.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let intent = state.borrow_mut().pending_close.take();
            ui.set_close_confirm_open(false);
            let Some(intent) = intent else { return };

            // Construct only the narrow handles the synchronous continuation
            // needs; callback registration has already completed.
            let preference = (ui.get_close_confirm_allow_dont_ask()
                && ui.get_close_confirm_dont_ask())
            .then_some(match intent.action {
                CloseAction::Quit => Some((SettingKey::ConfirmQuitActiveConnections, true)),
                CloseAction::CloseTab | CloseAction::DisconnectTab | CloseAction::ClosePane => {
                    Some((SettingKey::ConfirmCloseActiveTab, false))
                }
                CloseAction::CloseHome => None,
            })
            .flatten();
            if let Some((key, is_quit)) = preference {
                {
                    let mut st = state.borrow_mut();
                    if is_quit {
                        st.confirm_quit_active_connections = false;
                    } else {
                        st.confirm_close_active_tab = false;
                    }
                }
                if is_quit {
                    ui.set_settings_confirm_quit_active_connections(false);
                } else {
                    ui.set_settings_confirm_close_active_tab(false);
                }
                if let Err(error) =
                    SettingsService::new(config_store.as_ref()).set_bool(key, false)
                {
                    tracing::warn!(%error, key = key.as_str(), "failed to persist close-confirmation preference");
                }
            }

            match intent.action {
                CloseAction::CloseHome | CloseAction::CloseTab | CloseAction::DisconnectTab => {
                    let Some(tab_num) = intent.tab_num else { return };
                    let idx = state
                        .borrow()
                        .tabs
                        .iter()
                        .position(|tab| tab.num == tab_num);
                    let Some(idx) = idx else { return };
                    if matches!(intent.action, CloseAction::CloseHome | CloseAction::CloseTab) {
                        tabs::close_tab(&state, &tab_model, &ui, idx);
                    } else {
                        tabs::select_tab(&state, &ui, idx as i32);
                        sessions::disconnect_tab(&state, &tab_model, &ui, idx);
                    }
                }
                CloseAction::ClosePane => {
                    let (Some(tab_num), Some(endpoint_id)) =
                        (intent.tab_num, intent.endpoint_id)
                    else {
                        return;
                    };
                    let target = {
                        let st = state.borrow();
                        let Some(tab_idx) = st.tabs.iter().position(|tab| tab.num == tab_num) else {
                            return;
                        };
                        let tab = &st.tabs[tab_idx];
                        let pane_id = if tab.endpoint_id == endpoint_id {
                            Some(0)
                        } else {
                            tab.extra_panes
                                .iter()
                                .position(|pane| pane.endpoint_id == endpoint_id)
                                .map(|idx| idx + 1)
                        };
                        pane_id.map(|pane_id| (tab_idx, pane_id))
                    };
                    let Some((tab_idx, pane_id)) = target else { return };
                    tabs::select_tab(&state, &ui, tab_idx as i32);
                    panes::do_close_pane(&state, &tab_model, &ui, pane_id, false);
                }
                CloseAction::Quit => {
                    state.borrow_mut().quit_confirmed = true;
                    if let Err(error) = ui.window().hide() {
                        tracing::warn!(%error, "failed to close application window");
                    }
                }
            }
        }
    });

    ctx.ui.window().on_close_requested({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else {
                return CloseRequestResponse::HideWindow;
            };
            request_quit(&state, &ui)
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_connecting_and_connected_are_active() {
        assert!(is_active(SessionStatus::Connecting));
        assert!(is_active(SessionStatus::Connected));
        assert!(!is_active(SessionStatus::Disconnected));
        assert!(!is_active(SessionStatus::Exited(cm_core::ExitStatus {
            code: 0,
            success: true,
        })));
        assert!(!is_active(SessionStatus::Failed("network".to_owned())));
    }

    #[test]
    fn intent_targets_are_stable_identities() {
        let intent = CloseIntent {
            action: CloseAction::ClosePane,
            tab_num: Some(42),
            endpoint_id: Some(cm_core::SessionEndpointId(7)),
        };
        assert_eq!(intent.tab_num, Some(42));
        assert_eq!(intent.endpoint_id, Some(cm_core::SessionEndpointId(7)));
    }
}

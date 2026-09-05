//! Session connect/reconnect paths, host-key/cert verifiers, input routing,
//! and the tick/render pump.
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use cm_core::terminal::GridSnapshot;
use cm_core::{
    Connection, ConnectionSettings, CredentialPurpose, Group, LocalSettings, RdpSettings, Secret,
    SshAuthMethod, SshSettings, TelnetSettings, TerminalOptions,
};
use cm_session::{
    CertDecision, CertInfo, CertVerifier, FailedSession, FocusDir, FrameUpdate, HostKeyDecision,
    HostKeyInfo, HostKeyVerifier, KbdInteractiveChallenge, KbdInteractiveHandler, PaneLayout,
    RdpAuthInput, SessionInput, SessionStatus, SshAuthInput, Surface,
};
use slint::{ComponentHandle, Image, Model, SharedString, Timer, TimerMode, VecModel};

use crate::input;
use crate::keys::KeysPanel;
use crate::{AppWindow, ConnRow, KbdPromptRow, TabItem, ToastEntry};

use super::*;

pub(super) fn wire_sessions(ctx: &Ctx) {
    wire_key_input(ctx);
    wire_session_actions(ctx);
    wire_pointer(ctx);
    wire_scroll(ctx);
    wire_scroll_scrub(ctx);
    wire_rdp_scroll(ctx);
    wire_quick_connect(ctx);
    wire_qc_connect(ctx);
    wire_host_key_accept(ctx);
    wire_host_key_reject(ctx);
    wire_cert_accept(ctx);
    wire_cert_reject(ctx);
    wire_kbd_answer_edited(ctx);
    wire_kbd_submit(ctx);
    wire_kbd_cancel(ctx);
    wire_rdp_key_down(ctx);
    wire_rdp_key_up(ctx);
    wire_rdp_release_keys(ctx);
    wire_row_activated(ctx);
    wire_reconnect(ctx);
}

fn wire_key_input(ctx: &Ctx) {
    ctx.ui.on_key_input({
        let state = ctx.state.clone();
        let tab_model_kb = ctx.tab_model.clone();
        let toast_model_kb = ctx.toast_model.clone();
        let toast_next_id_kb = ctx.toast_next_id.clone();
        let weak_kb = ctx.ui.as_weak();
        move |text, special, mods| {
            let Some(ui) = weak_kb.upgrade() else { return };
            if close::guard_terminal_key(&state, &ui, special) {
                return;
            }
            if ui.get_session_actions_open() {
                if special == 4 {
                    ui.set_session_actions_open(false);
                }
                // A menu owns keyboard input while open. In particular, Esc
                // dismisses without becoming a remote terminal/RDP key and
                // modifier snapshots cannot leak through menu navigation.
                return;
            }
            // while the terminal search overlay is open, the terminal
            // FocusScope still forwards keys here — route them to the query
            // box instead of the session/Ctrl+Shift dispatch below. `Ctrl⇧F` closes it (handled
            // inside `handle_search_key`); opening it is the ordinary
            // Ctrl+Shift dispatch case below, reached only when not open.
            if ui.get_terminal_search_open() {
                search::handle_search_key(&ui, &state, text.as_str(), special, mods);
                return;
            }

            // ──: Ctrl+Shift shortcut layer (reserved by GUI_DESIGN §5) ──
            // These are intercepted before forwarding to the session so they
            // never reach the remote shell. The terminal FocusScope passes all
            // Ctrl+Shift events to `key-input` (only Ctrl+K is intercepted in
            // Slint); we catch them here.
            let ctrl_shift =
                mods & (input::MOD_CTRL | input::MOD_SHIFT) == (input::MOD_CTRL | input::MOD_SHIFT);
            if ctrl_shift {
                let t = text.as_str();
                match (special, t) {
                    // Ctrl+Shift+F → open the terminal search overlay
                    //. Closing it is handled inside
                    // `search::handle_search_key`, reached via the
                    // `terminal_search_open` check above once it's open.
                    (0, "f" | "F") => {
                        search::open_search(&ui, &state);
                        return;
                    }
                    // Ctrl+Shift+\ or Ctrl+Shift+| → H-split.
                    (0, "\\" | "|") => {
                        panes::do_split(&state, &tab_model_kb, &ui, PaneLayout::HSplit);
                        return;
                    }
                    // Ctrl+Shift+- or Ctrl+Shift+_ → V-split.
                    (0, "-" | "_") => {
                        panes::do_split(&state, &tab_model_kb, &ui, PaneLayout::VSplit);
                        return;
                    }
                    // Ctrl+Shift+B → toggle broadcast.
                    (0, "b" | "B") => {
                        ui.set_broadcast_active(!ui.get_broadcast_active());
                        return;
                    }
                    // Ctrl+Shift+Up/Down/Left/Right → move focus using real
                    // pane geometry (`focus_dir` picks the nearest
                    // pane in that screen direction, not merely "prev/next
                    // id" — correct once panes are arranged in more than one
                    // row/column, which a plain delta could not do).
                    (5, _) => {
                        return dispatch_focus_dir(&state, &ui, FocusDir::Up);
                    }
                    (6, _) => {
                        return dispatch_focus_dir(&state, &ui, FocusDir::Down);
                    }
                    (7, _) => {
                        return dispatch_focus_dir(&state, &ui, FocusDir::Left);
                    }
                    (8, _) => {
                        return dispatch_focus_dir(&state, &ui, FocusDir::Right);
                    }
                    // Ctrl+Shift+W → close focused pane (detach = false → shutdown).
                    (0, "w" | "W") => {
                        if let Some(pane_id) = panes::focused_pane_id(&state) {
                            close::request_pane_close(&state, &tab_model_kb, &ui, pane_id);
                        }
                        return;
                    }
                    // Ctrl+Shift+D → detach session (keep session alive).
                    (0, "d" | "D") => {
                        if let Some(pane_id) = panes::focused_pane_id(&state) {
                            panes::do_close_pane(&state, &tab_model_kb, &ui, pane_id, true);
                        }
                        return;
                    }
                    // Ctrl+Shift+C → copy the focused pane's selection.
                    (0, "c" | "C") if focused_pane_is_terminal(&state.borrow()) => {
                        do_copy(&state);
                        return;
                    }
                    // Ctrl+Shift+V → paste the OS clipboard.
                    (0, "v" | "V") if focused_pane_is_terminal(&state.borrow()) => {
                        do_paste(&state);
                        return;
                    }
                    _ => {}
                }
                // — direct shortcuts on this same reserved layer, kept
                // as a separate pure classifier (`classify_ctrl_shift_shortcut`) so
                // the dispatch decision is unit-testable without a live UI/session.
                match classify_ctrl_shift_shortcut(special, t) {
                    CtrlShiftAction::NewTab => {
                        ui.invoke_new_tab();
                        return;
                    }
                    // Goes through the real `toggle-sidebar` callback (not a bare
                    // property flip) so the collapsed state persists the same as
                    // the chrome button does.
                    CtrlShiftAction::ToggleSidebar => {
                        ui.invoke_toggle_sidebar();
                        return;
                    }
                    CtrlShiftAction::None => {}
                }
            }

            // Mainstream terminal aliases. Ctrl+C is conditional: with a
            // selection it copies, without one it must remain the terminal's
            // interrupt key. Ctrl+V and Shift+Insert always request a paste
            // when the focused pane is a terminal. Exact modifier matching
            // leaves application/TUI combinations such as Ctrl+Alt+C alone.
            let (focused_terminal, plain_clipboard_shortcuts) = {
                let st = state.borrow();
                (
                    focused_pane_is_terminal(&st),
                    st.plain_copy_paste_shortcuts,
                )
            };
            if focused_terminal {
                match classify_terminal_clipboard_shortcut(
                    special,
                    text.as_str(),
                    mods,
                    plain_clipboard_shortcuts,
                ) {
                    TerminalClipboardAction::CopyIfSelected
                        if focused_pane_has_selection(&state.borrow()) =>
                    {
                        do_copy(&state);
                        return;
                    }
                    TerminalClipboardAction::Paste => {
                        do_paste(&state);
                        return;
                    }
                    TerminalClipboardAction::CopyIfSelected
                    | TerminalClipboardAction::None => {}
                }
            }

            // Shift+PageUp/PageDown scroll the terminal's own
            // scrollback by one page, intercepted before they would
            // otherwise be forwarded as a PageUp/PageDown key. Plain
            // (non-Shift, non-Ctrl) PageUp/PageDown still reach the session
            // unchanged — many apps (less, vim) handle it themselves.
            let plain_shift = mods & input::MOD_SHIFT != 0 && mods & input::MOD_CTRL == 0;
            if plain_shift && (special == PAGE_UP || special == PAGE_DOWN) {
                let page_rows = {
                    let st = state.borrow();
                    st.tabs
                        .get(st.active)
                        .map_or(24, |t| i64::from(t.rows.max(1)))
                };
                let delta = if special == PAGE_UP {
                    page_rows
                } else {
                    -page_rows
                };
                scroll_active_tab_by(&state, delta);
                return;
            }

            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active) {
                let evs: Vec<SessionInput> = input::map_key(text.as_str(), special, mods)
                    .into_iter()
                    .map(SessionInput::Key)
                    .collect();
                if evs.is_empty() {
                    return;
                }
                // ── Broadcast: fan to the targeted pane sessions ─────────────
                // targeted, not always "all panes" — resolves
                // `Tab::broadcast_target` (Visible/Custom) against the tab's
                // *current* pane count so a stale custom selection never
                // sends to a closed pane. Defaults to `Visible` (every pane),
                // identical to the earlier "always all panes" behavior. See
                // `panes::broadcast_fan_out` for the (unit-tested) targeting logic.
                if ui.get_broadcast_active() {
                    // the execute-scope gate also covers
                    // broadcast (fanning input out to multiple already-open
                    // sessions at once) - see open_ssh_tab's identical
                    // comment for the mechanism/rationale.
                    if agent_mode_execute_blocked(&st.agent_mode) {
                        tracing::warn!(
                            "agent mode: broadcast blocked while automation is active without execute scope"
                        );
                        let id = {
                            let mut n = toast_next_id_kb.borrow_mut();
                            let id = *n;
                            *n += 1;
                            id
                        };
                        toast_model_kb.push(ToastEntry {
                            id,
                            message: SharedString::from(
                                "agent mode: execute scope not granted -- broadcast blocked",
                            ),
                            kind: 3, // error
                        });
                        return;
                    }
                    panes::broadcast_fan_out(tab, &evs);
                    return;
                }
                // Not broadcasting — send only to the focused pane.
                let focused = tab.pane_group.focused();
                if focused == 0 {
                    for ev in evs {
                        tab.session.send_input(ev);
                    }
                } else {
                    let ep_idx = focused - 1;
                    if let Some(ep) = tab.extra_panes.get(ep_idx) {
                        for ev in evs {
                            ep.session.send_input(ev);
                        }
                    }
                }
            }
        }
    });
}

/// move focus in the active tab's pane group by screen direction
/// (`Ctrl⇧Arrows`) and push the new focused pane id to the UI.
fn dispatch_focus_dir(state: &Rc<RefCell<State>>, ui: &AppWindow, dir: FocusDir) {
    let new_focus = {
        let mut st = state.borrow_mut();
        let active = st.active;
        let Some(tab) = st.tabs.get_mut(active) else {
            return;
        };
        tab.pane_group.focus_dir(dir)
    };
    ui.set_active_pane(new_focus as i32);
}

/// The new Ctrl+Shift shortcuts, as a pure `(special, text)` ->
/// action classifier - kept separate from `wire_key_input`'s dispatch so the
/// decision is unit-testable without a live `AppWindow`/session `State`.
/// `special`/`text` are the same encoding `TerminalSurface.key-pressed`
/// packs in `app.slint` (see `crate::input::map_key`'s doc comment).
#[derive(Debug, PartialEq, Eq)]
pub(super) enum CtrlShiftAction {
    /// Ctrl+Shift+T — open a new local tab.
    NewTab,
    /// Ctrl+Shift+E — toggle the side panel.
    ToggleSidebar,
    /// Not one of this layer's direct shortcuts (falls through to the older
    /// split/broadcast/close/detach/focus-move arms, or to the session).
    None,
}

pub(super) fn classify_ctrl_shift_shortcut(special: i32, text: &str) -> CtrlShiftAction {
    match (special, text) {
        (0, "t" | "T") => CtrlShiftAction::NewTab,
        (0, "e" | "E") => CtrlShiftAction::ToggleSidebar,
        _ => CtrlShiftAction::None,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TerminalClipboardAction {
    CopyIfSelected,
    Paste,
    None,
}

/// Classify mainstream terminal clipboard aliases. The preference gates only
/// plain Ctrl+C/V; Shift+Insert remains available, and Ctrl+Shift+C/V stay in
/// the reserved shortcut layer above.
fn classify_terminal_clipboard_shortcut(
    special: i32,
    text: &str,
    mods: i32,
    plain_aliases_enabled: bool,
) -> TerminalClipboardAction {
    if input::is_modifier_special(special) {
        return TerminalClipboardAction::None;
    }
    match (special, text, mods) {
        (0, "c" | "C" | "\u{3}", input::MOD_CTRL) if plain_aliases_enabled => {
            TerminalClipboardAction::CopyIfSelected
        }
        (0, "v" | "V", input::MOD_CTRL) if plain_aliases_enabled => TerminalClipboardAction::Paste,
        (13, _, input::MOD_SHIFT) => TerminalClipboardAction::Paste,
        _ => TerminalClipboardAction::None,
    }
}

/// copy the focused pane's live selection to the OS clipboard
/// (`Ctrl+C` with a selection, or `Ctrl⇧C`). A no-op when nothing is selected
/// — never overwrites the clipboard with an empty string. The originating
/// selection is cleared later, and only if this exact asynchronous write
/// succeeds before the selection changes.
fn do_copy(state: &Rc<RefCell<State>>) {
    let mut st = state.borrow_mut();
    let active = st.active;
    let copy = {
        let Some(tab) = st.tabs.get(active) else {
            return;
        };
        let focused = tab.pane_group.focused();
        if focused == 0 {
            tab.last.as_ref().and_then(|snap| {
                Some((
                    tab.endpoint_id,
                    tab.sel.selection_generation()?,
                    tab.sel.copy_text(snap)?,
                ))
            })
        } else {
            tab.extra_panes.get(focused - 1).and_then(|ep| {
                ep.last.as_ref().and_then(|snap| {
                    Some((
                        ep.endpoint_id,
                        ep.sel.selection_generation()?,
                        ep.sel.copy_text(snap)?,
                    ))
                })
            })
        }
    };
    if let Some((target, selection_generation, text)) = copy {
        submit_terminal_selection_copy(&mut st, target, selection_generation, text);
    }
}

fn submit_terminal_selection_copy(
    st: &mut State,
    target: cm_core::SessionEndpointId,
    selection_generation: u64,
    text: String,
) {
    let replaced = st.sys_clipboard.submit_write(
        crate::clipboard::ClipboardWritePurpose::TerminalSelectionCopy {
            target,
            selection_generation,
        },
        crate::clipboard::ClipboardWrite::Text(text),
    );
    if let Some(replaced) = replaced {
        handle_replaced_clipboard_write(st, &replaced);
    }
}

/// paste the OS clipboard into the focused pane (keyboard aliases, or
/// a locally-owned right/middle click — see [`wire_pointer`]). Routed through
/// `SessionInput::Paste` -> `TerminalSession::paste`, which
/// bracketed-paste-wraps at the engine/session layer when the app enabled
/// DECSET 2004 (raw otherwise — see `cm_session::engine_owner::wrap_paste`).
fn do_paste(state: &Rc<RefCell<State>>) {
    let mut st = state.borrow_mut();
    let active = st.active;
    let Some(tab) = st.tabs.get(active) else {
        return;
    };
    let focused = tab.pane_group.focused();
    let target = if focused == 0 {
        tab.endpoint_id
    } else {
        tab.extra_panes
            .get(focused - 1)
            .map_or(tab.endpoint_id, |pane| pane.endpoint_id)
    };
    let _ = st.sys_clipboard.request_terminal_text(target);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FocusedSessionKind {
    None,
    Terminal { has_selection: bool },
    Rdp,
}

pub(super) fn focused_session_kind(st: &State) -> FocusedSessionKind {
    let Some(tab) = st.tabs.get(st.active) else {
        return FocusedSessionKind::None;
    };
    let focused = tab.pane_group.focused();
    let (surface, has_selection) = if focused == 0 {
        (tab.session.surface(), tab.sel.selection().is_some())
    } else if let Some(pane) = tab.extra_panes.get(focused - 1) {
        (pane.session.surface(), pane.sel.selection().is_some())
    } else {
        return FocusedSessionKind::None;
    };
    match surface {
        Surface::TerminalGrid(_) => FocusedSessionKind::Terminal { has_selection },
        Surface::Framebuffer(_) => FocusedSessionKind::Rdp,
    }
}

fn wire_session_actions(ctx: &Ctx) {
    ctx.ui.on_open_session_actions({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let kind = focused_session_kind(&state.borrow());
            ui.set_session_actions_terminal(matches!(kind, FocusedSessionKind::Terminal { .. }));
            ui.set_session_actions_rdp(kind == FocusedSessionKind::Rdp);
            ui.set_session_actions_has_selection(matches!(
                kind,
                FocusedSessionKind::Terminal {
                    has_selection: true
                }
            ));
            ui.set_session_actions_open(kind != FocusedSessionKind::None);
        }
    });
    ctx.ui.on_session_copy_selection({
        let state = ctx.state.clone();
        move || do_copy(&state)
    });
    ctx.ui.on_session_copy_visible({
        let state = ctx.state.clone();
        move || copy_visible_screen(&state)
    });
    ctx.ui.on_session_copy_all({
        let state = ctx.state.clone();
        move || copy_all_scrollback(&state)
    });
    ctx.ui.on_session_paste({
        let state = ctx.state.clone();
        move || do_paste(&state)
    });
    ctx.ui.on_session_find({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade()
                && matches!(
                    focused_session_kind(&state.borrow()),
                    FocusedSessionKind::Terminal { .. }
                )
            {
                search::open_search(&ui, &state);
            }
        }
    });
    ctx.ui.on_session_rdp_ctrl_alt_delete({
        let state = ctx.state.clone();
        move || send_focused_rdp_action(&state, input::rdp_ctrl_alt_delete_sequence())
    });
    ctx.ui.on_session_rdp_windows_key({
        let state = ctx.state.clone();
        move || send_focused_rdp_action(&state, input::rdp_windows_key_sequence())
    });
    ctx.ui.on_session_rdp_alt_tab({
        let state = ctx.state.clone();
        move || send_focused_rdp_action(&state, input::rdp_alt_tab_sequence())
    });
    ctx.ui.on_session_rdp_release_modifiers({
        let state = ctx.state.clone();
        move || send_focused_rdp_action(&state, input::rdp_release_all_modifiers_sequence())
    });
}

pub(super) fn send_focused_rdp_action(
    state: &Rc<RefCell<State>>,
    events: Vec<cm_core::RdpInputEvent>,
) {
    let st = state.borrow();
    let Some(tab) = st.tabs.get(st.active) else {
        return;
    };
    if focused_session_kind(&st) == FocusedSessionKind::Rdp {
        send_to_focused_pane(tab, SessionInput::Rdp(events));
    }
}

pub(super) fn copy_selection(state: &Rc<RefCell<State>>) {
    do_copy(state);
}

pub(super) fn paste(state: &Rc<RefCell<State>>) {
    do_paste(state);
}

pub(super) fn copy_visible_screen(state: &Rc<RefCell<State>>) {
    let mut st = state.borrow_mut();
    let Some(tab) = st.tabs.get(st.active) else {
        return;
    };
    let focused = tab.pane_group.focused();
    let snapshot = if focused == 0 {
        matches!(tab.session.surface(), Surface::TerminalGrid(_))
            .then(|| tab.last.as_ref())
            .flatten()
    } else {
        tab.extra_panes.get(focused - 1).and_then(|pane| {
            matches!(pane.session.surface(), Surface::TerminalGrid(_))
                .then(|| pane.last.as_ref())
                .flatten()
        })
    };
    let Some(text) = snapshot.map(snapshot_text).filter(|text| !text.is_empty()) else {
        return;
    };
    submit_ui_text_copy(&mut st, text);
}

pub(super) fn copy_all_scrollback(state: &Rc<RefCell<State>>) {
    let mut st = state.borrow_mut();
    let Some(tab) = st.tabs.get(st.active) else {
        return;
    };
    let focused = tab.pane_group.focused();
    let (target, session): (cm_core::SessionEndpointId, &dyn cm_session::Session) = if focused == 0
    {
        if !matches!(tab.session.surface(), Surface::TerminalGrid(_)) {
            return;
        }
        (tab.endpoint_id, tab.session.as_ref())
    } else {
        let Some(pane) = tab.extra_panes.get(focused - 1) else {
            return;
        };
        if !matches!(pane.session.surface(), Surface::TerminalGrid(_)) {
            return;
        }
        (pane.endpoint_id, pane.session.as_ref())
    };
    let (tx, rx) = std::sync::mpsc::channel();
    session.request_search_text(tx);
    st.pending_terminal_buffer_copies
        .push(PendingTerminalBufferCopy { target, reply: rx });
}

fn snapshot_text(snapshot: &GridSnapshot) -> String {
    let cols = usize::from(snapshot.size.cols);
    if cols == 0 {
        return String::new();
    }
    let mut lines = snapshot
        .cells
        .chunks(cols)
        .map(|row| {
            let mut line = String::new();
            for cell in row {
                line.push_str(&cell.grapheme);
            }
            line.trim_end().to_owned()
        })
        .collect::<Vec<_>>();
    trim_trailing_empty_lines(&mut lines);
    lines.join("\n")
}

fn buffer_lines_text(mut lines: Vec<String>) -> String {
    for line in &mut lines {
        *line = line.trim_end().to_owned();
    }
    trim_trailing_empty_lines(&mut lines);
    lines.join("\n")
}

fn trim_trailing_empty_lines(lines: &mut Vec<String>) {
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
}

fn submit_ui_text_copy(st: &mut State, text: String) {
    let replaced = st.sys_clipboard.submit_write(
        crate::clipboard::ClipboardWritePurpose::UiTextCopy,
        crate::clipboard::ClipboardWrite::Text(text),
    );
    if let Some(replaced) = replaced {
        handle_replaced_clipboard_write(st, &replaced);
    }
}

fn poll_terminal_buffer_copies(st: &mut State) {
    let mut idx = 0;
    while idx < st.pending_terminal_buffer_copies.len() {
        match st.pending_terminal_buffer_copies[idx].reply.try_recv() {
            Ok(lines) => {
                let request = st.pending_terminal_buffer_copies.remove(idx);
                // Stable identity prevents a reply from a closed/replaced pane
                // becoming an unrelated session's clipboard content.
                if endpoint_exists(st, request.target) {
                    let text = buffer_lines_text(lines);
                    if !text.is_empty() {
                        submit_ui_text_copy(st, text);
                    }
                }
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                st.pending_terminal_buffer_copies.remove(idx);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => idx += 1,
        }
    }
}

fn endpoint_exists(st: &State, endpoint: cm_core::SessionEndpointId) -> bool {
    st.tabs.iter().any(|tab| {
        tab.endpoint_id == endpoint
            || tab
                .extra_panes
                .iter()
                .any(|pane| pane.endpoint_id == endpoint)
    }) || st
        .detached
        .iter()
        .any(|detached| detached.endpoint_id == endpoint)
}

/// Mouse button discriminants mirrored from `input::map_mouse`; this file
/// decides whether a click belongs to a mouse-tracking TUI or local paste.
const BTN_MIDDLE: i32 = 3;
const BTN_RIGHT: i32 = 2;
const BTN_LEFT: i32 = 1;
const KIND_CANCEL: i32 = 0;
const KIND_PRESS: i32 = 1;
const KIND_RELEASE: i32 = 2;

fn pointer_pane_location(
    st: &State,
    endpoint: cm_core::SessionEndpointId,
) -> Option<(usize, usize)> {
    st.tabs.iter().enumerate().find_map(|(tab_idx, tab)| {
        if tab.endpoint_id == endpoint {
            return Some((tab_idx, 0));
        }
        tab.extra_panes
            .iter()
            .position(|pane| pane.endpoint_id == endpoint)
            .map(|extra_idx| (tab_idx, extra_idx + 1))
    })
}

/// Best-effort balancing release when the original pane disappeared or a new
/// press superseded an unfinished gesture. A detached session remains
/// addressable by endpoint; a shut-down one simply rejects the send.
fn release_captured_pointer(st: &State, capture: PointerGestureCapture) {
    match capture.surface {
        PointerGestureSurface::Terminal {
            forwarded_button: Some(button),
            row,
            col,
            mods,
        } => {
            if let Some(event) = input::map_mouse(button, KIND_RELEASE, row, col, mods) {
                send_to_endpoint(st, capture.endpoint, SessionInput::Mouse(event));
            }
        }
        PointerGestureSurface::Rdp {
            button,
            surface_w,
            surface_h,
            rdp_w,
            rdp_h,
            x,
            y,
        } => {
            let coords = input::RdpCoords {
                surface_w,
                surface_h,
                rdp_w,
                rdp_h,
            };
            let events = input::map_rdp_mouse(button, KIND_RELEASE, x, y, &coords);
            if !events.is_empty() {
                send_to_endpoint(st, capture.endpoint, SessionInput::Rdp(events));
            }
        }
        PointerGestureSurface::Terminal {
            forwarded_button: None,
            ..
        } => {}
    }
}

pub(super) fn release_pointer_capture_for_endpoint(
    st: &mut State,
    endpoint: cm_core::SessionEndpointId,
) {
    if st
        .pointer_gesture
        .is_some_and(|capture| capture.endpoint == endpoint)
    {
        let capture = st.pointer_gesture.take().expect("matching capture");
        release_captured_pointer(st, capture);
    }
}

/// `special` codes for PageUp/PageDown (see `input::map_key`'s doc comment
/// for the full table — these two are intercepted here, before
/// `input::map_key`, for the Shift+PageUp/PageDown scroll shortcut).
const PAGE_UP: i32 = 11;
const PAGE_DOWN: i32 = 12;

/// Lines scrolled per wheel notch when the app hasn't claimed the wheel via
/// mouse tracking; see `wire_scroll`.
const WHEEL_SCROLL_LINES: u32 = 3;

/// Map an overlay-scrollbar scrub fraction (0 = oldest/top, 1 = live
/// tail/bottom — matching `TerminalScrollbar`'s thumb geometry in
/// `ui/app.slint`) to an absolute `SessionInput::Scroll` offset for `snap`,
/// clamped to the available scrollback. Pure — unit-tested below.
fn fraction_to_offset(snap: &GridSnapshot, frac: f32) -> u32 {
    // Invert the thumb-y travel mapping in `TerminalScrollbar` (ui/app.slint):
    // the thumb travels over `scrollback_len` lines, so a travel fraction
    // `frac` (0 = top/oldest, 1 = live tail) maps to an offset of
    // `scrollback_len * (1 - frac)`. Normalizing by `scrollback_len` (not the
    // old `scrollback_len + rows` total) keeps the scrub 1:1 with the thumb --
    // frac 0 -> the oldest line, frac 1 -> the tail, midpoint -> the middle.
    if snap.scrollback_len == 0 {
        return 0;
    }
    let travel = f64::from(frac.clamp(0.0, 1.0));
    (f64::from(snap.scrollback_len) * (1.0 - travel)).round() as u32
}

/// Publish the primary pane's scrollback viewport state to the Slint overlay
/// scrollbar (`TerminalScrollbar` in `ui/app.slint`). Slint reveals the bar
/// on `scroll-offset` changes; `rev` is only bumped on tab/pane switches
/// (see `tabs::select_tab`, `panes::wire_pane_focused`), so steady output at
/// the live tail never flashes it.
pub(super) fn publish_scroll_state(tab: &Tab, ui: &AppWindow) {
    match tab.last.as_ref() {
        Some(snap) => {
            ui.set_term_scrollback_len(snap.scrollback_len as i32);
            ui.set_term_scroll_offset(snap.scroll_offset as i32);
            ui.set_term_view_rows(snap.size.rows as i32);
        }
        None => {
            ui.set_term_scrollback_len(0);
            ui.set_term_scroll_offset(0);
            ui.set_term_view_rows(0);
        }
    }
}

/// Scrub the **focused** pane's scrollback viewport to `frac` (unlike the
/// wheel path's historical always-primary scope, the overlay lives per-pane).
/// No-op for RDP surfaces and before the first snapshot arrives.
fn scrub_focused_by_fraction(tab: &Tab, frac: f32) {
    let focused = tab.pane_group.focused();
    let (surface, snap) = if focused == 0 {
        (tab.session.surface(), tab.last.as_ref())
    } else if let Some(ep) = tab.extra_panes.get(focused - 1) {
        (ep.session.surface(), ep.last.as_ref())
    } else {
        return;
    };
    if !matches!(surface, Surface::TerminalGrid(_)) {
        return;
    }
    let Some(snap) = snap else { return };
    let offset = fraction_to_offset(snap, frac);
    if offset == snap.scroll_offset {
        return;
    }
    send_to_focused_pane(tab, SessionInput::Scroll(offset));
}

/// Scrub one split pane by id (`PaneCell.pane`: 0 = primary, 1+ =
/// `extra_panes[id - 1]`). Same no-op rules as [`scrub_focused_by_fraction`].
fn scrub_pane_by_fraction(tab: &Tab, pane: i32, frac: f32) {
    let (surface, snap, target): (&Surface, Option<&GridSnapshot>, SessionTarget) = if pane == 0 {
        (
            tab.session.surface(),
            tab.last.as_ref(),
            SessionTarget::Primary,
        )
    } else if let Some(ep) = tab.extra_panes.get(pane as usize - 1) {
        (
            ep.session.surface(),
            ep.last.as_ref(),
            SessionTarget::Extra(pane as usize - 1),
        )
    } else {
        return;
    };
    if !matches!(surface, Surface::TerminalGrid(_)) {
        return;
    }
    let Some(snap) = snap else { return };
    let offset = fraction_to_offset(snap, frac);
    if offset == snap.scroll_offset {
        return;
    }
    match target {
        SessionTarget::Primary => tab.session.send_input(SessionInput::Scroll(offset)),
        SessionTarget::Extra(idx) => {
            if let Some(ep) = tab.extra_panes.get(idx) {
                ep.session.send_input(SessionInput::Scroll(offset));
            }
        }
    }
}

/// Which session `scrub_pane_by_fraction` resolved `pane` to, without holding
/// a borrow across the `send_input` call.
#[derive(Debug, Clone, Copy)]
enum SessionTarget {
    Primary,
    Extra(usize),
}

fn wire_scroll_scrub(ctx: &Ctx) {
    ctx.ui.on_scroll_scrub({
        let state = ctx.state.clone();
        move |frac| {
            let st = state.borrow();
            let Some(tab) = st.tabs.get(st.active) else {
                return;
            };
            scrub_focused_by_fraction(tab, frac);
        }
    });
    ctx.ui.on_pane_scroll_scrub({
        let state = ctx.state.clone();
        move |pane, frac| {
            let st = state.borrow();
            let Some(tab) = st.tabs.get(st.active) else {
                return;
            };
            scrub_pane_by_fraction(tab, pane, frac);
        }
    });
}
/// The scroll offset to request given the current one plus a signed `delta`
/// (positive = further into scrollback, negative = toward the tail), clamped
/// to what's actually available. Pure — shared by the wheel and
/// Shift+PageUp/PageDown paths.
fn clamp_scroll(current: &GridSnapshot, delta: i64) -> u32 {
    (i64::from(current.scroll_offset) + delta).clamp(0, i64::from(current.scrollback_len)) as u32
}

/// request a scroll-offset change for the active tab's **primary**
/// terminal session (matches `wire_scroll`'s pre-existing "always the active
/// tab's `session`, not whichever pane is focused" scope — see the task
/// report). No-op before the first snapshot arrives, or for a non-terminal
/// surface (RDP).
fn scroll_active_tab_by(state: &Rc<RefCell<State>>, delta: i64) {
    let st = state.borrow();
    let Some(tab) = st.tabs.get(st.active) else {
        return;
    };
    if !matches!(tab.session.surface(), Surface::TerminalGrid(_)) {
        return;
    }
    let Some(last) = tab.last.as_ref() else {
        return;
    };
    tab.session
        .send_input(SessionInput::Scroll(clamp_scroll(last, delta)));
}

fn wire_pointer(ctx: &Ctx) {
    ctx.ui.on_pointer({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |button, kind, x, y, mods| {
            let now = Instant::now();

            let mut st = state.borrow_mut();
            if kind == KIND_PRESS
                && let Some(stale) = st.pointer_gesture.take()
            {
                release_captured_pointer(&st, stale);
            }
            let captured = st.pointer_gesture;
            let current_location = st.tabs.get(st.active).map(|tab| {
                let focused = tab.pane_group.focused();
                let focused = if focused == 0 || tab.extra_panes.get(focused - 1).is_some() {
                    focused
                } else {
                    0
                };
                (st.active, focused)
            });
            let captured_location =
                captured.and_then(|capture| pointer_pane_location(&st, capture.endpoint));
            if captured.is_some() && captured_location.is_none() {
                let capture = st.pointer_gesture.take().expect("checked capture");
                release_captured_pointer(&st, capture);
                return;
            }
            let location = captured_location.or(current_location);
            let Some((active, focused)) = location else {
                if let Some(capture) = st.pointer_gesture.take() {
                    release_captured_pointer(&st, capture);
                }
                return;
            };
            let base_scale = st.tabs[active].scale;
            let (surface_w, surface_h) = (st.surface_w, st.surface_h);
            let copy_on_select = st.copy_on_select;
            let Some(tab) = st.tabs.get_mut(active) else {
                return;
            };
            // bundled fix (F-perf, finding R1): only the
            // selection-highlight path below needs a forced render (the
            // engine's own output still drives the normal tick-loop redraw).
            // Tracking whether *this* event actually changed the selection
            // means a plain button-less hover move - no selection, no mouse
            // event forwarded - no longer forces a full-grid raster.
            let mut selection_changed = false;
            let mut paste_target = None;
            let mut completed_copy = None;
            let mut next_capture = captured;
            let retain_capture = captured.is_some() || (kind == KIND_PRESS && button != 0);

            if focused == 0 || tab.extra_panes.get(focused - 1).is_none() {
                // Primary pane (or an out-of-range focus index — defensive
                // fallback matching the earlier behavior).
                match tab.session.surface() {
                    Surface::TerminalGrid(_) => {
                        let (row, col) = tab.renderer.cell_at(x * base_scale, y * base_scale);
                        let snap = tab.last.as_ref();
                        let mouse_tracking = snap.is_some_and(|snapshot| snapshot.mouse_tracking);
                        match tab.sel.route_pointer(
                            mouse_tracking,
                            mods & input::MOD_SHIFT != 0,
                            button,
                            kind,
                        ) {
                            crate::selection::PointerRoute::Terminal(
                                routed_button,
                                routed_kind,
                            ) => {
                                if let Some(ev) =
                                    input::map_mouse(routed_button, routed_kind, row, col, mods)
                                {
                                    tab.session.send_input(SessionInput::Mouse(ev));
                                }
                                if retain_capture {
                                    next_capture = Some(PointerGestureCapture {
                                        endpoint: tab.endpoint_id,
                                        surface: PointerGestureSurface::Terminal {
                                            forwarded_button: Some(routed_button),
                                            row,
                                            col,
                                            mods,
                                        },
                                    });
                                }
                            }
                            crate::selection::PointerRoute::Local => {
                                if retain_capture {
                                    next_capture = Some(PointerGestureCapture {
                                        endpoint: tab.endpoint_id,
                                        surface: PointerGestureSurface::Terminal {
                                            forwarded_button: None,
                                            row,
                                            col,
                                            mods,
                                        },
                                    });
                                }
                                if kind == KIND_PRESS && matches!(button, BTN_RIGHT | BTN_MIDDLE) {
                                    paste_target = Some(tab.endpoint_id);
                                } else {
                                    selection_changed =
                                        tab.sel.on_pointer(button, kind, (row, col), snap, now);
                                    if copy_on_select && kind == KIND_RELEASE && button == BTN_LEFT
                                    {
                                        completed_copy = tab.last.as_ref().and_then(|snapshot| {
                                            Some((
                                                tab.endpoint_id,
                                                tab.sel.selection_generation()?,
                                                tab.sel.copy_text(snapshot)?,
                                            ))
                                        });
                                    }
                                }
                            }
                            crate::selection::PointerRoute::Ignore => {}
                        }
                    }
                    Surface::Framebuffer(_) => {
                        let (gesture_button, surface_w, surface_h, rdp_w, rdp_h) = match captured {
                            Some(PointerGestureCapture {
                                endpoint,
                                surface:
                                    PointerGestureSurface::Rdp {
                                        button: gesture_button,
                                        surface_w,
                                        surface_h,
                                        rdp_w,
                                        rdp_h,
                                        ..
                                    },
                            }) if endpoint == tab.endpoint_id => {
                                (gesture_button, surface_w, surface_h, rdp_w, rdp_h)
                            }
                            _ => (button, surface_w, surface_h, tab.rdp_w, tab.rdp_h),
                        };
                        let coords = input::RdpCoords {
                            surface_w,
                            surface_h,
                            rdp_w,
                            rdp_h,
                        };
                        let routed_kind = if kind == KIND_CANCEL {
                            KIND_RELEASE
                        } else {
                            kind
                        };
                        let events =
                            input::map_rdp_mouse(gesture_button, routed_kind, x, y, &coords);
                        if !events.is_empty() {
                            tab.session.send_input(SessionInput::Rdp(events));
                        }
                        if retain_capture {
                            next_capture = Some(PointerGestureCapture {
                                endpoint: tab.endpoint_id,
                                surface: PointerGestureSurface::Rdp {
                                    button: gesture_button,
                                    surface_w,
                                    surface_h,
                                    rdp_w,
                                    rdp_h,
                                    x,
                                    y,
                                },
                            });
                        }
                    }
                }
            } else {
                let ep_idx = focused - 1;
                let ep = &mut tab.extra_panes[ep_idx];
                match ep.session.surface() {
                    Surface::TerminalGrid(_) => {
                        let (row, col) = ep.renderer.cell_at(x * ep.scale, y * ep.scale);
                        let snap = ep.last.as_ref();
                        let mouse_tracking = snap.is_some_and(|snapshot| snapshot.mouse_tracking);
                        match ep.sel.route_pointer(
                            mouse_tracking,
                            mods & input::MOD_SHIFT != 0,
                            button,
                            kind,
                        ) {
                            crate::selection::PointerRoute::Terminal(
                                routed_button,
                                routed_kind,
                            ) => {
                                if let Some(ev) =
                                    input::map_mouse(routed_button, routed_kind, row, col, mods)
                                {
                                    ep.session.send_input(SessionInput::Mouse(ev));
                                }
                                if retain_capture {
                                    next_capture = Some(PointerGestureCapture {
                                        endpoint: ep.endpoint_id,
                                        surface: PointerGestureSurface::Terminal {
                                            forwarded_button: Some(routed_button),
                                            row,
                                            col,
                                            mods,
                                        },
                                    });
                                }
                            }
                            crate::selection::PointerRoute::Local => {
                                if retain_capture {
                                    next_capture = Some(PointerGestureCapture {
                                        endpoint: ep.endpoint_id,
                                        surface: PointerGestureSurface::Terminal {
                                            forwarded_button: None,
                                            row,
                                            col,
                                            mods,
                                        },
                                    });
                                }
                                if kind == KIND_PRESS && matches!(button, BTN_RIGHT | BTN_MIDDLE) {
                                    paste_target = Some(ep.endpoint_id);
                                } else {
                                    selection_changed =
                                        ep.sel.on_pointer(button, kind, (row, col), snap, now);
                                    if copy_on_select && kind == KIND_RELEASE && button == BTN_LEFT
                                    {
                                        completed_copy = ep.last.as_ref().and_then(|snapshot| {
                                            Some((
                                                ep.endpoint_id,
                                                ep.sel.selection_generation()?,
                                                ep.sel.copy_text(snapshot)?,
                                            ))
                                        });
                                    }
                                }
                            }
                            crate::selection::PointerRoute::Ignore => {}
                        }
                    }
                    // RDP-in-pane pointer routing (lifts 's
                    // deferral) — same coordinate mapping `wire_pointer` uses
                    // for a primary-pane RDP surface, scoped to this pane's
                    // own reported size instead of the whole window's.
                    Surface::Framebuffer(_) => {
                        let (gesture_button, surface_w, surface_h, rdp_w, rdp_h) = match captured {
                            Some(PointerGestureCapture {
                                endpoint,
                                surface:
                                    PointerGestureSurface::Rdp {
                                        button: gesture_button,
                                        surface_w,
                                        surface_h,
                                        rdp_w,
                                        rdp_h,
                                        ..
                                    },
                            }) if endpoint == ep.endpoint_id => {
                                (gesture_button, surface_w, surface_h, rdp_w, rdp_h)
                            }
                            _ => (button, ep.surface_w, ep.surface_h, ep.rdp_w, ep.rdp_h),
                        };
                        let coords = input::RdpCoords {
                            surface_w,
                            surface_h,
                            rdp_w,
                            rdp_h,
                        };
                        let routed_kind = if kind == KIND_CANCEL {
                            KIND_RELEASE
                        } else {
                            kind
                        };
                        let events =
                            input::map_rdp_mouse(gesture_button, routed_kind, x, y, &coords);
                        if !events.is_empty() {
                            ep.session.send_input(SessionInput::Rdp(events));
                        }
                        if retain_capture {
                            next_capture = Some(PointerGestureCapture {
                                endpoint: ep.endpoint_id,
                                surface: PointerGestureSurface::Rdp {
                                    button: gesture_button,
                                    surface_w,
                                    surface_h,
                                    rdp_w,
                                    rdp_h,
                                    x,
                                    y,
                                },
                            });
                        }
                    }
                }
            }

            st.pointer_gesture = if matches!(kind, KIND_RELEASE | KIND_CANCEL) {
                None
            } else {
                next_capture
            };

            if let Some(target) = paste_target {
                let _ = st.sys_clipboard.request_terminal_text(target);
            }
            if let Some((target, selection_generation, text)) = completed_copy {
                submit_terminal_selection_copy(&mut st, target, selection_generation, text);
            }

            // a selection change has no new `GridSnapshot` of its own
            // (nothing was typed), so the tick loop's snapshot-driven redraw
            // would never pick it up — force one render now against the
            // pane's last known snapshot so the highlight (or its removal)
            // appears immediately rather than waiting for the next
            // unrelated output event.: gated on `selection_changed` so a
            // hover-only move (no selection, no forwarded mouse event) no
            // longer pays for a render it doesn't need.
            if selection_changed && let Some(ui) = weak.upgrade() {
                render_active(&mut st, &ui);
            }
        }
    });
}

fn wire_scroll(ctx: &Ctx) {
    ctx.ui.on_scroll({
        let state = ctx.state.clone();
        move |_dx, dy| {
            if dy == 0.0 {
                return;
            }
            let st = state.borrow();
            // Terminal scroll only — RDP scroll is handled by on_rdp_scroll (fix c).
            let Some(tab) = st.tabs.get(st.active) else {
                return;
            };
            if !matches!(tab.session.surface(), Surface::TerminalGrid(_)) {
                return;
            }
            let Some(last) = tab.last.as_ref() else {
                return;
            };
            if last.mouse_tracking {
                // The app has grabbed the wheel (e.g. less/vim/htop with
                // mouse reporting on) — forward it as a wheel-button mouse
                // event, exactly like earlier behavior.
                if let Some(ev) = input::map_scroll(dy, 0, 0, 0) {
                    tab.session.send_input(SessionInput::Mouse(ev));
                }
                return;
            }
            // no mouse-tracking app has claimed the wheel — scroll our
            // own scrollback viewport instead. Previously this silently did
            // nothing useful: `encode_mouse` returns empty bytes with no
            // mouse mode active, so a wheel notch was a no-op.
            let delta: i64 = if dy > 0.0 {
                i64::from(WHEEL_SCROLL_LINES)
            } else {
                -i64::from(WHEEL_SCROLL_LINES)
            };
            tab.session
                .send_input(SessionInput::Scroll(clamp_scroll(last, delta)));
        }
    });
}

fn wire_rdp_scroll(ctx: &Ctx) {
    ctx.ui.on_rdp_scroll({
        let state = ctx.state.clone();
        move |x, y, _dx, dy| {
            let st = state.borrow();
            let (surface_w, surface_h) = (st.surface_w, st.surface_h);
            let Some(tab) = st.tabs.get(st.active) else {
                return;
            };
            let focused = tab.pane_group.focused();
            let (surf, coords) = if focused == 0 {
                (
                    tab.session.surface(),
                    input::RdpCoords {
                        surface_w,
                        surface_h,
                        rdp_w: tab.rdp_w,
                        rdp_h: tab.rdp_h,
                    },
                )
            } else {
                let Some(ep) = tab.extra_panes.get(focused - 1) else {
                    return;
                };
                (
                    ep.session.surface(),
                    input::RdpCoords {
                        surface_w: ep.surface_w,
                        surface_h: ep.surface_h,
                        rdp_w: ep.rdp_w,
                        rdp_h: ep.rdp_h,
                    },
                )
            };
            if matches!(surf, Surface::Framebuffer(_)) {
                // Use actual pointer position instead of surface centre.
                let events = input::map_rdp_scroll(dy, x, y, &coords);
                if !events.is_empty() {
                    send_to_focused_pane(tab, SessionInput::Rdp(events));
                }
            }
        }
    });
}

fn wire_quick_connect(ctx: &Ctx) {
    ctx.ui.on_quick_connect({
        let weak = ctx.ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_quick_connect_open(true);
            }
        }
    });
}

/// the quick-connect dialog's kind selector — `qc-kind` in
/// `app.slint` (`QuickConnectForm`'s `kind` property, plumbed straight
/// through). Kept as a real enum (rather than matching the raw `i32` at every
/// call site) so an out-of-range value has one obvious fallback (`Ssh`,
/// matching the dialog's own default `kind: 0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QcKind {
    Ssh,
    Rdp,
    Telnet,
    Local,
}

impl From<i32> for QcKind {
    fn from(v: i32) -> Self {
        match v {
            1 => QcKind::Rdp,
            2 => QcKind::Telnet,
            3 => QcKind::Local,
            _ => QcKind::Ssh,
        }
    }
}

fn wire_qc_connect(ctx: &Ctx) {
    ctx.ui.on_qc_connect({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        let hk_pending = ctx.hk_pending.clone();
        let cert_pending = ctx.cert_pending.clone();
        let kbd_pending = ctx.kbd_pending.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            match QcKind::from(ui.get_qc_kind()) {
                QcKind::Ssh => {
                    qc_connect_ssh(&state, &tab_model, &ui, &weak, &hk_pending, &kbd_pending)
                }
                QcKind::Rdp => qc_connect_rdp(&state, &tab_model, &ui, &weak, &cert_pending),
                QcKind::Telnet => qc_connect_telnet(&state, &tab_model, &ui),
                QcKind::Local => qc_connect_local(&state, &tab_model, &ui),
            }
        }
    });
}

/// Closes the quick-connect dialog and clears every secret-bearing field.
/// Shared by the per-kind dispatchers so a typed password/
/// passphrase never lingers in the dialog's in-memory Slint properties past
/// the connect attempt that used it - the earlier SSH-only behavior,
/// generalized.
fn close_and_clear_qc_secrets(ui: &AppWindow) {
    ui.set_quick_connect_open(false);
    ui.set_qc_secret(Default::default());
    ui.set_qc_passphrase(Default::default());
}

/// Pure builder behind the SSH arm of quick-connect: turns the raw
/// dialog fields into `SshSettings`, or `None` if the connect is invalid
/// (host/username empty) - the same guard `wire_qc_connect`'s SSH path has
/// always had, just made independently testable.
fn qc_ssh_settings(host: &str, port: &str, username: &str) -> Option<SshSettings> {
    let host = host.trim();
    let username = username.trim();
    if host.is_empty() || username.is_empty() {
        return None;
    }
    Some(SshSettings {
        host: host.to_owned(),
        port: port.trim().parse().unwrap_or(SshSettings::DEFAULT_PORT),
        username: username.to_owned(),
        auth_method: SshAuthMethod::Password,
    })
}

fn qc_connect_ssh(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    weak: &slint::Weak<AppWindow>,
    hk_pending: &HkQueue,
    kbd_pending: &KbdQueue,
) {
    let host = ui.get_qc_host().to_string();
    let port_str = ui.get_qc_port().to_string();
    let username = ui.get_qc_username().to_string();
    let auth_method = ui.get_qc_auth_method();
    let secret_raw = ui.get_qc_secret().to_string();
    let pass_raw = ui.get_qc_passphrase().to_string();
    let Some(settings) = qc_ssh_settings(&host, &port_str, &username) else {
        return;
    };
    let auth = match auth_method {
        0 => SshAuthInput::Key {
            path: PathBuf::from(secret_raw),
            passphrase: if pass_raw.is_empty() {
                None
            } else {
                Some(Secret::from_string(pass_raw))
            },
        },
        1 => SshAuthInput::Password(Secret::from_string(secret_raw)),
        // auth-method 3 is "Keyboard interactive" — no upfront
        // secret; the handler prompts live once the server issues its
        // first challenge round.
        3 => SshAuthInput::KeyboardInteractive {
            handler: Arc::new(UiKbdInteractiveHandler {
                weak_ui: weak.clone(),
                pending: kbd_pending.clone(),
            }),
        },
        _ => SshAuthInput::Agent,
    };
    close_and_clear_qc_secrets(ui);
    let verifier = ssh_host_key_verifier(state, weak, hk_pending);
    // Quick-connect has no originating stored profile to edit on failure.
    open_ssh_tab(
        state,
        tab_model,
        ui,
        settings,
        auth,
        AuthProvenance::Direct,
        verifier,
        None,
    );
}

/// parses a "WIDTHxHEIGHT" resolution field (e.g. "1920x1080") into RDP
/// width/height. Falls back to `RdpSettings::DEFAULT_WIDTH`/`DEFAULT_HEIGHT`
/// for anything that doesn't parse cleanly - empty field, garbage text, or a
/// zero dimension - so a malformed typed value can never turn into a
/// zero-sized desktop request. `pub(super)`: also reused by the profile
/// editor's RDP field mapping (`tree_ctl::settings_from_form`) so the
/// two RDP forms parse resolution identically.
pub(super) fn parse_qc_resolution(s: &str) -> (u16, u16) {
    let defaults = (RdpSettings::DEFAULT_WIDTH, RdpSettings::DEFAULT_HEIGHT);
    let Some((w, h)) = s.split_once(['x', 'X']) else {
        return defaults;
    };
    let w: u16 = w.trim().parse().unwrap_or(0);
    let h: u16 = h.trim().parse().unwrap_or(0);
    if w == 0 || h == 0 { defaults } else { (w, h) }
}

/// Pure builder behind the RDP arm of quick-connect: turns
/// the raw dialog fields into `RdpSettings`, or `None` if the connect is
/// invalid (host/username empty) - mirrors [`qc_ssh_settings`].
fn qc_rdp_settings(
    host: &str,
    port: &str,
    username: &str,
    domain: &str,
    resolution: &str,
) -> Option<RdpSettings> {
    let host = host.trim();
    let username = username.trim();
    if host.is_empty() || username.is_empty() {
        return None;
    }
    let domain = domain.trim();
    let (width, height) = parse_qc_resolution(resolution);
    Some(RdpSettings {
        host: host.to_owned(),
        port: port.trim().parse().unwrap_or(RdpSettings::DEFAULT_PORT),
        domain: if domain.is_empty() {
            None
        } else {
            Some(domain.to_owned())
        },
        username: Some(username.to_owned()),
        width,
        height,
        color_depth: RdpSettings::default().color_depth,
    })
}

fn qc_connect_rdp(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    weak: &slint::Weak<AppWindow>,
    cert_pending: &Arc<Mutex<Option<Sender<CertDecision>>>>,
) {
    let host = ui.get_qc_host().to_string();
    let port_str = ui.get_qc_port().to_string();
    let username = ui.get_qc_username().to_string();
    let domain_raw = ui.get_qc_rdp_domain().to_string();
    let resolution_raw = ui.get_qc_rdp_resolution().to_string();
    let password_raw = ui.get_qc_secret().to_string();
    let Some(settings) = qc_rdp_settings(&host, &port_str, &username, &domain_raw, &resolution_raw)
    else {
        return;
    };
    let auth = RdpAuthInput {
        username: settings.username.clone().unwrap_or_default(),
        password: Secret::from_string(password_raw),
        domain: settings.domain.clone(),
    };
    close_and_clear_qc_secrets(ui);
    let verifier = rdp_certificate_verifier(state, weak, cert_pending);
    // Quick-connect has no originating stored profile to edit on failure.
    open_rdp_tab(
        state,
        tab_model,
        ui,
        settings,
        auth,
        AuthProvenance::Direct,
        verifier,
        None,
    );
}

/// Builds a Telnet quick-connect target. Login is performed interactively by
/// the remote application, so host and port are the entire connection input.
fn qc_telnet_settings(host: &str, port: &str) -> Option<TelnetSettings> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    Some(TelnetSettings {
        host: host.to_owned(),
        port: port.trim().parse().unwrap_or(TelnetSettings::DEFAULT_PORT),
    })
}

fn qc_connect_telnet(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
) {
    let host = ui.get_qc_host().to_string();
    let port = ui.get_qc_port().to_string();
    let Some(settings) = qc_telnet_settings(&host, &port) else {
        return;
    };
    // A prior SSH/RDP form visit may have populated these shared fields.
    // Telnet never consumes them; clear them before opening the session.
    close_and_clear_qc_secrets(ui);
    ui.set_qc_username(Default::default());
    ui.set_qc_rdp_domain(Default::default());
    open_telnet_tab(state, tab_model, ui, settings, None);
}

/// Pure builder behind the Local arm of quick-connect: a
/// local quick-connect just spawns a shell, so unlike the SSH/RDP builders
/// this never fails (an empty program falls back to the OS default shell,
/// same as the Settings panel's own local-shell defaults -
/// `settings_ctl::local_settings_from_app`, which this mirrors).
fn qc_local_settings(program: &str, args: &str, cwd: &str) -> LocalSettings {
    let program = program.trim();
    let cwd = cwd.trim();
    LocalSettings {
        program: if program.is_empty() {
            None
        } else {
            Some(program.to_owned())
        },
        args: if args.trim().is_empty() {
            Vec::new()
        } else {
            args.split_whitespace().map(String::from).collect()
        },
        working_dir: if cwd.is_empty() {
            None
        } else {
            Some(cwd.to_owned())
        },
        env: Vec::new(),
    }
}

/// `pub(super)` (rather than private, like the SSH/RDP dispatchers) so
/// `util::wire_local_qc_autoconnect`'s headless QA hook can drive the exact
/// same dispatch a real "Connect" click would ( xvfb screenshot gate:
/// "a Local quick-connect reaching a live shell").
pub(super) fn qc_connect_local(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
) {
    let program = ui.get_qc_local_program().to_string();
    let args = ui.get_qc_local_args().to_string();
    let cwd = ui.get_qc_local_cwd().to_string();
    let ls = qc_local_settings(&program, &args, &cwd);
    ui.set_quick_connect_open(false);
    tabs::open_local_tab_quick(state, tab_model, ui, ls);
}

fn wire_host_key_accept(ctx: &Ctx) {
    ctx.ui.on_host_key_accept({
        let pending = ctx.hk_pending.clone();
        let weak = ctx.ui.as_weak();
        move || {
            // Pop the front sender (oldest pending request) — (a).
            if let Ok(mut q) = pending.lock()
                && let Some(tx) = q.pop_front()
            {
                let _ = tx.send(HostKeyDecision::Accept);
            }
            if let Some(ui) = weak.upgrade() {
                ui.set_host_key_open(false);
            }
        }
    });
}

fn wire_host_key_reject(ctx: &Ctx) {
    ctx.ui.on_host_key_reject({
        let pending = ctx.hk_pending.clone();
        let weak = ctx.ui.as_weak();
        move || {
            // Pop the front sender (oldest pending request) — (a).
            if let Ok(mut q) = pending.lock()
                && let Some(tx) = q.pop_front()
            {
                let _ = tx.send(HostKeyDecision::Reject);
            }
            if let Some(ui) = weak.upgrade() {
                ui.set_host_key_open(false);
            }
        }
    });
}

fn wire_cert_accept(ctx: &Ctx) {
    ctx.ui.on_cert_accept({
        let pending = ctx.cert_pending.clone();
        let weak = ctx.ui.as_weak();
        move || {
            if let Ok(mut p) = pending.lock()
                && let Some(tx) = p.take()
            {
                let _ = tx.send(CertDecision::AcceptAndRemember);
            }
            if let Some(ui) = weak.upgrade() {
                ui.set_cert_dialog_open(false);
            }
        }
    });
}

fn wire_cert_reject(ctx: &Ctx) {
    ctx.ui.on_cert_reject({
        let pending = ctx.cert_pending.clone();
        let weak = ctx.ui.as_weak();
        move || {
            if let Ok(mut p) = pending.lock()
                && let Some(tx) = p.take()
            {
                let _ = tx.send(CertDecision::Reject);
            }
            if let Some(ui) = weak.upgrade() {
                ui.set_cert_dialog_open(false);
            }
        }
    });
}

/// The user edited one answer field in the keyboard-interactive dialog
///. Mutates the live `kbd-prompts` model in place — the value is only
/// ever read back out of it at submit time, never re-displayed or logged.
fn wire_kbd_answer_edited(ctx: &Ctx) {
    ctx.ui.on_kbd_answer_edited({
        let weak = ctx.ui.as_weak();
        move |idx, text| {
            let Some(ui) = weak.upgrade() else { return };
            let model = ui.get_kbd_prompts();
            let Ok(idx) = usize::try_from(idx) else {
                return;
            };
            if let Some(mut row) = model.row_data(idx) {
                row.value = text;
                model.set_row_data(idx, row);
            }
        }
    });
}

fn wire_kbd_submit(ctx: &Ctx) {
    ctx.ui.on_kbd_submit({
        let pending = ctx.kbd_pending.clone();
        let weak = ctx.ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let model = ui.get_kbd_prompts();
            let answers: Vec<Secret> = (0..model.row_count())
                .map(|i| {
                    let value = model.row_data(i).map(|r| r.value.to_string());
                    Secret::from_string(value.unwrap_or_default())
                })
                .collect();
            if let Ok(mut q) = pending.lock()
                && let Some(tx) = q.pop_front()
            {
                let _ = tx.send(Some(answers));
            }
            ui.set_kbd_open(false);
            ui.set_kbd_prompts(ModelRc::from(Rc::new(VecModel::<KbdPromptRow>::default())));
        }
    });
}

fn wire_kbd_cancel(ctx: &Ctx) {
    ctx.ui.on_kbd_cancel({
        let pending = ctx.kbd_pending.clone();
        let weak = ctx.ui.as_weak();
        move || {
            if let Ok(mut q) = pending.lock()
                && let Some(tx) = q.pop_front()
            {
                let _ = tx.send(None);
            }
            if let Some(ui) = weak.upgrade() {
                ui.set_kbd_open(false);
                ui.set_kbd_prompts(ModelRc::from(Rc::new(VecModel::<KbdPromptRow>::default())));
            }
        }
    });
}

/// Realizes the [`KbdInteractiveHandler`] round trip: shows
/// [`KbdInteractiveDialog`](crate) and blocks the calling (session driver)
/// thread until the user submits or cancels. Modeled directly on
/// [`UiHostKeyVerifier`] below — same pending-queue + `invoke_from_event_loop`
/// pattern, just carrying answers instead of a host-key decision.
pub(super) struct UiKbdInteractiveHandler {
    pub(super) weak_ui: slint::Weak<AppWindow>,
    pub(super) pending: KbdQueue,
}

impl KbdInteractiveHandler for UiKbdInteractiveHandler {
    fn respond(&self, challenge: &KbdInteractiveChallenge) -> Option<Vec<Secret>> {
        let (tx, rx) = std::sync::mpsc::channel::<Option<Vec<Secret>>>();
        if let Ok(mut q) = self.pending.lock() {
            q.push_back(tx);
        }
        let name = challenge.name.clone();
        let instructions = challenge.instructions.clone();
        let prompts: Vec<KbdPromptRow> = challenge
            .prompts
            .iter()
            .map(|p| KbdPromptRow {
                text: p.text.clone().into(),
                echo: p.echo,
                value: Default::default(),
            })
            .collect();
        let weak = self.weak_ui.clone();
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = weak.upgrade() else { return };
            ui.set_kbd_name(name.into());
            ui.set_kbd_instructions(instructions.into());
            ui.set_kbd_prompts(ModelRc::from(Rc::new(VecModel::from(prompts))));
            ui.set_kbd_open(true);
        });
        // A closed channel (UI gone before responding) fails soft to an
        // abort, same as an explicit cancel — never hangs the auth attempt.
        rx.recv().unwrap_or(None)
    }
}

/// Send transport-neutral input to whichever pane is focused in `tab` (id 0
/// = the primary session; id 1+ = `extra_panes[id - 1]`).: RDP-in-pane
/// means the RDP key/scroll callbacks (fired from *any* pane's `RdpSurface`,
/// not just a whole-tab-is-RDP primary) must route by focus like the
/// terminal key-input path already does, instead of always assuming the
/// primary session is the RDP one.
fn send_to_focused_pane(tab: &Tab, input: SessionInput) {
    let focused = tab.pane_group.focused();
    if focused == 0 {
        tab.session.send_input(input);
    } else if let Some(ep) = tab.extra_panes.get(focused - 1) {
        ep.session.send_input(input);
    }
}

fn wire_rdp_key_down(ctx: &Ctx) {
    ctx.ui.on_rdp_key_down({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |text, special, mods| {
            let Some(ui) = weak.upgrade() else { return };
            if close::guard_rdp_key_down(&state, &ui, text.as_str(), special) {
                return;
            }
            if ui.get_session_actions_open() {
                return;
            }
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active) {
                let events = input::map_rdp_key_down(text.as_str(), special, mods);
                if !events.is_empty() {
                    send_to_focused_pane(tab, SessionInput::Rdp(events));
                }
            }
        }
    });
}

fn wire_rdp_key_up(ctx: &Ctx) {
    ctx.ui.on_rdp_key_up({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |text, special, mods| {
            let Some(ui) = weak.upgrade() else { return };
            if close::guard_rdp_key_up(&state, &ui, text.as_str(), special) {
                return;
            }
            if ui.get_session_actions_open() {
                if special == 4 {
                    ui.set_session_actions_open(false);
                }
                return;
            }
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active) {
                let events = input::map_rdp_key_up(text.as_str(), special, mods);
                if !events.is_empty() {
                    send_to_focused_pane(tab, SessionInput::Rdp(events));
                }
            }
        }
    });
}

fn wire_rdp_release_keys(ctx: &Ctx) {
    ctx.ui.on_rdp_release_keys({
        let state = ctx.state.clone();
        move || {
            let st = state.borrow();
            // Focus loss can be caused by a tab switch whose controller state
            // has already advanced to the destination tab. Release every live
            // RDP pane instead of guessing which tab used to own focus. These
            // key-ups are idempotent.
            for tab in &st.tabs {
                if tab.kind == "RDP" {
                    tab.session
                        .send_input(SessionInput::Rdp(input::rdp_modifier_key_ups().into()));
                }
                for pane in &tab.extra_panes {
                    if pane.kind == "RDP" {
                        pane.session
                            .send_input(SessionInput::Rdp(input::rdp_modifier_key_ups().into()));
                    }
                }
            }
        }
    });
}

fn wire_row_activated(ctx: &Ctx) {
    ctx.ui.on_row_activated({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let cert_pending = ctx.cert_pending.clone();
        let hk_pending = ctx.hk_pending.clone();
        let secrets = ctx.secrets.clone();
        let weak = ctx.ui.as_weak();
        move |idx| {
            let Some(ui) = weak.upgrade() else { return };
            let row = {
                let st = state.borrow();
                st.conn_tree.flat().get(idx as usize).cloned()
            };
            let Some(row) = row else { return };
            if row.is_group {
                return; // groups are toggled by on_toggle_conn_row
            }
            // Look up the connection by id.
            let conn = {
                let st = state.borrow();
                st.conn_tree
                    .connections()
                    .iter()
                    .find(|c| c.id.get() as i32 == row.id)
                    .cloned()
            };
            let Some(conn) = conn else {
                tabs::open_local_tab(&state, &tab_model, &ui);
                return;
            };
            launch_saved_connection(
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
    });
}

/// Resolves and opens (or fails) a tab for a saved connection: the shared
/// stored-credential connect path used by both a tree-row click
/// ([`wire_row_activated`]) and the `CONMAN_TREE_AUTOLAUNCH` QA hook
/// (`controller/util.rs`) — both must exercise the identical
/// resolve-then-connect logic, never a placeholder/empty credential.
///
/// Also sets `origin_connection_id` on every tab this produces —
/// including the auth-error `Failed` tab — so the ErrorOverlay "Edit…" button
/// can reopen the originating profile even when the failure was a
/// credential-resolution error rather than a network/protocol one.
#[allow(clippy::too_many_arguments)]
pub(super) fn launch_saved_connection(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    weak: &slint::Weak<AppWindow>,
    hk_pending: &HkQueue,
    cert_pending: &Arc<Mutex<Option<Sender<CertDecision>>>>,
    secrets: &Arc<dyn cm_core::CredentialStore>,
    conn: &Connection,
) {
    let conn_id = conn.id;
    let tab_count_before = state.borrow().tabs.len();
    // record this as a recently-opened connection for the Launchpad
    // (recency only; best-effort - a failure here never blocks or fails the
    // connect attempt itself). This is the single shared entry point for
    // every way of opening a saved connection (tree click,
    // `CONMAN_TREE_AUTOLAUNCH`, the Launchpad's own "open recent", and
    // session restore), so recording it here covers all of them once.
    {
        let repo = state.borrow().io.repo.clone();
        if let Err(e) = repo.record_recent(conn_id, crate::tree::now_secs()) {
            tracing::warn!("record_recent: {e}");
        }
    }
    // remember which stored profile this tab came from so the
    // ErrorOverlay "Edit…" button can reopen it on failure.
    let origin_connection_id = Some(conn.id.get() as i32);
    match &conn.settings {
        ConnectionSettings::Local(_) => tabs::open_local_tab(state, tab_model, ui),
        ConnectionSettings::Telnet(s) => {
            tracing::info!(
                conn = %conn.name,
                kind = "telnet",
                host = %s.host,
                port = s.port,
                "launching connection"
            );
            open_telnet_tab(state, tab_model, ui, s.clone(), origin_connection_id);
        }
        ConnectionSettings::Ssh(s) => {
            let resolved = {
                let st = state.borrow();
                resolve_ssh_auth(
                    conn,
                    st.conn_tree.groups(),
                    s,
                    secrets.as_ref(),
                    st.keys_panel.credentials(),
                )
            };
            match resolved {
                Ok(auth) => {
                    // BUG-cred-username-auth: the settings actually used to
                    // connect/log/identify carry the *effective* username
                    // (credential's own username wins over the inline field
                    // when a credential is assigned) - see
                    // `effective_ssh_settings`.
                    let effective_settings = {
                        let st = state.borrow();
                        effective_ssh_settings(
                            conn,
                            st.conn_tree.groups(),
                            s,
                            st.keys_panel.credentials(),
                        )
                    };
                    {
                        let st = state.borrow();
                        log_ssh_launch_auth(
                            conn,
                            st.conn_tree.groups(),
                            &effective_settings,
                            st.keys_panel.credentials(),
                        );
                    }
                    let verifier = ssh_host_key_verifier(state, weak, hk_pending);
                    open_ssh_tab(
                        state,
                        tab_model,
                        ui,
                        effective_settings,
                        auth,
                        AuthProvenance::Credential(conn_id),
                        verifier,
                        origin_connection_id,
                    );
                }
                Err(err) => push_auth_failed_tab(
                    state,
                    tab_model,
                    ui,
                    format!("SSH {}", s.host),
                    format!("{}@{}:{}", s.username, s.host, s.port),
                    err.to_string(),
                    origin_connection_id,
                ),
            }
        }
        ConnectionSettings::Rdp(s) => {
            let resolved = {
                let st = state.borrow();
                resolve_rdp_auth(
                    conn,
                    st.conn_tree.groups(),
                    s,
                    secrets.as_ref(),
                    st.keys_panel.credentials(),
                )
            };
            match resolved {
                Ok(auth) => {
                    {
                        let st = state.borrow();
                        log_rdp_launch_auth(
                            conn,
                            st.conn_tree.groups(),
                            s,
                            st.keys_panel.credentials(),
                        );
                    }
                    let verifier = rdp_certificate_verifier(state, weak, cert_pending);
                    open_rdp_tab(
                        state,
                        tab_model,
                        ui,
                        s.clone(),
                        auth,
                        AuthProvenance::Credential(conn_id),
                        verifier,
                        origin_connection_id,
                    );
                }
                Err(err) => push_auth_failed_tab(
                    state,
                    tab_model,
                    ui,
                    format!("RDP {}", s.host),
                    format!(
                        "{}@{}:{}",
                        s.username.clone().unwrap_or_default(),
                        s.host,
                        s.port
                    ),
                    err.to_string(),
                    origin_connection_id,
                ),
            }
        }
    }

    // Every saved-profile launch above ultimately pushes one tab, but the
    // protocol-specific open paths deliberately derive labels for their
    // other callers (Quick Connect / debug hooks). Apply the saved profile's
    // user-facing name at this shared saved-only boundary instead. `Tab::
    // identity` is already the canonical active-session label cached across
    // tab switches, while `TabItem::title` is the tab-strip label, so no
    // second title representation is introduced.
    apply_saved_profile_label(
        state,
        tab_model,
        ui,
        tab_count_before,
        origin_connection_id,
        &conn.name,
    );
}

/// Applies a saved profile's name to the single tab produced by
/// [`launch_saved_connection`]. The before-count guard matters for Local:
/// unlike remote setup errors (which become Failed tabs), a local spawn error
/// opens no tab and must never rename whichever tab happened to be active.
fn apply_saved_profile_label(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    tab_count_before: usize,
    origin_connection_id: Option<i32>,
    label: &str,
) {
    let tab_idx = {
        let mut st = state.borrow_mut();
        if st.tabs.len() != tab_count_before + 1 || st.active != tab_count_before {
            return;
        }
        let tab = &mut st.tabs[tab_count_before];
        // Remote paths already carry this id. Local saved profiles previously
        // went through the generic shell helper, so attach their real origin
        // here as well; this is the existing canonical provenance field used
        // by duplicate/session persistence, not compatibility title state.
        tab.origin_connection_id = origin_connection_id;
        tab.identity = label.to_owned();
        tab_count_before
    };

    if let Some(mut item) = tab_model.row_data(tab_idx) {
        item.title = SharedString::from(label);
        item.can_duplicate = true;
        tab_model.set_row_data(tab_idx, item);
    }
    ui.set_session_identity(SharedString::from(label));
}

/// What [`wire_reconnect`] resolved for the active tab, before the old
/// session is shut down and the corresponding `reconnect_*_tab` is called.
/// Kept as one enum (rather than branching twice) so the "shut down the old
/// session, then reconnect" sequencing is written once regardless of kind.
enum ReconnectPlan {
    Ssh(
        SshSettings,
        AuthProvenance,
        Result<SshAuthInput, AuthResolveError>,
    ),
    Rdp(
        RdpSettings,
        AuthProvenance,
        Result<RdpAuthInput, AuthResolveError>,
    ),
    Telnet(TelnetSettings),
}

/// Reconnect replaces transport/auth state in place; it must not replace a
/// saved session's user-selected display label with a regenerated endpoint.
/// Quick Connect tabs have no origin and continue to use the freshly derived
/// endpoint label. The existing cached `identity` is the one canonical active
/// session label, so retaining it does not add parallel title state.
fn reconnect_display_label(
    state: &Rc<RefCell<State>>,
    tab_idx: usize,
    generated: String,
) -> String {
    let st = state.borrow();
    st.tabs
        .get(tab_idx)
        .filter(|tab| tab.origin_connection_id.is_some())
        .map(|tab| tab.identity.clone())
        .unwrap_or(generated)
}

/// Resolves the provenance + auth material for reconnecting an SSH tab
/// `Direct` (quick-connect) clones the cached [`SshAuthInput`]
/// verbatim; `Credential` (tree-launched) re-resolves fresh via
/// [`resolve_ssh_auth`] against the live credential store - the fetched
/// secret never lingers in `Tab` state longer than one connect attempt.
/// Pure and mock-testable (no live `AppWindow`/session needed) - extracted
/// from [`wire_reconnect`]'s inline match ( prep, no behavior change).
///
/// BUG-cred-username-auth: also returns the [`SshSettings`] actually used to
/// reconnect, with `username` re-derived via [`effective_ssh_settings`] -
/// without this, a reconnect would keep whatever username the tab's cached
/// `SshConnectInfo` happened to carry rather than re-applying the
/// credential-wins precedence, and a credentialed reconnect could regress to
/// an empty/stale username.
fn resolve_ssh_reconnect(
    ci: &SshConnectInfo,
    connections: &[Connection],
    groups: &[Group],
    secrets: &dyn cm_core::CredentialStore,
    credentials: &[cm_core::Credential],
) -> (
    SshSettings,
    AuthProvenance,
    Result<SshAuthInput, AuthResolveError>,
) {
    match &ci.auth_source {
        SshAuthSource::Direct(a) => (ci.settings.clone(), AuthProvenance::Direct, Ok(a.clone())),
        SshAuthSource::Credential(conn_id) => {
            let conn = connections.iter().find(|c| c.id == *conn_id);
            let result = conn
                .ok_or(AuthResolveError::NoCredentialAssigned)
                .and_then(|c| resolve_ssh_auth(c, groups, &ci.settings, secrets, credentials));
            let settings = match conn {
                Some(c) => effective_ssh_settings(c, groups, &ci.settings, credentials),
                None => ci.settings.clone(),
            };
            (settings, AuthProvenance::Credential(*conn_id), result)
        }
    }
}

/// RDP counterpart to [`resolve_ssh_reconnect`] - same
/// `Direct`-clones / `Credential`-re-resolves-fresh rule, via
/// [`resolve_rdp_auth`]. No settings re-derivation needed here (unlike SSH):
/// [`RdpAuthInput::username`] already carries the effective username, and
/// [`resolve_rdp_auth`] re-applies [`effective_auth_username`] fresh on every
/// call since `credentials` is now threaded through.
fn resolve_rdp_reconnect(
    ci: &RdpConnectInfo,
    connections: &[Connection],
    groups: &[Group],
    secrets: &dyn cm_core::CredentialStore,
    credentials: &[cm_core::Credential],
) -> (AuthProvenance, Result<RdpAuthInput, AuthResolveError>) {
    match &ci.auth_source {
        RdpAuthSource::Direct(a) => (AuthProvenance::Direct, Ok(a.clone())),
        RdpAuthSource::Credential(conn_id) => {
            let result = connections
                .iter()
                .find(|c| c.id == *conn_id)
                .ok_or(AuthResolveError::NoCredentialAssigned)
                .and_then(|c| resolve_rdp_auth(c, groups, &ci.settings, secrets, credentials));
            (AuthProvenance::Credential(*conn_id), result)
        }
    }
}

fn wire_reconnect(ctx: &Ctx) {
    ctx.ui.on_reconnect({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        let hk_pending = ctx.hk_pending.clone();
        let cert_pending = ctx.cert_pending.clone();
        let secrets = ctx.secrets.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let active_idx = state.borrow().active;
            reconnect_tab(
                &state,
                &tab_model,
                &ui,
                &weak,
                &hk_pending,
                &cert_pending,
                &secrets,
                active_idx,
            );
        }
    });
}

/// The ErrorOverlay's "Reconnect" button (above) and the tab context menu's
/// "Reconnect" item ( #1, `controller::tabs::wire_tab_reconnect`) share
/// this exact logic - the only difference is which `tab_idx` they target
/// (always `active` for the overlay button; whichever tab was right-clicked
/// for the menu item). **Callers that might target a non-active tab must
/// bring it into view first** (`tabs::select_tab`) before calling this -
/// every downstream function here (`reconnect_ssh_tab`/`reconnect_rdp_tab`/
/// `fail_reconnect_in_place`) writes AppWindow-level properties shared by
/// whichever tab is active (the exact single-shared-property shape Bug B's
/// stale-frame fix was about), so calling this for a tab that ISN'T active
/// would paint its reconnect over whatever tab the user is actually looking
/// at.
#[allow(clippy::too_many_arguments)]
pub(super) fn reconnect_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    weak: &slint::Weak<AppWindow>,
    hk_pending: &HkQueue,
    cert_pending: &Arc<Mutex<Option<Sender<CertDecision>>>>,
    secrets: &Arc<dyn cm_core::CredentialStore>,
    tab_idx: usize,
) {
    // /: `Credential`-sourced auth is re-resolved fresh here
    // (never cached as plaintext in `Tab` state) — `Direct`
    // (quick-connect) just clones the typed input as before. SSH and
    // RDP each carry their own settings/auth types, so the two kinds
    // build a `ReconnectPlan` variant rather than sharing one tuple
    // shape.
    let plan = {
        let st = state.borrow();
        st.tabs
            .get(tab_idx)
            .and_then(|t| t.connect_info.as_ref())
            .map(|ci| match ci {
                ConnectInfo::Ssh(ssh_ci) => {
                    let (settings, provenance, auth_result) = resolve_ssh_reconnect(
                        ssh_ci,
                        st.conn_tree.connections(),
                        st.conn_tree.groups(),
                        secrets.as_ref(),
                        st.keys_panel.credentials(),
                    );
                    ReconnectPlan::Ssh(settings, provenance, auth_result)
                }
                ConnectInfo::Rdp(rdp_ci) => {
                    let (provenance, auth_result) = resolve_rdp_reconnect(
                        rdp_ci,
                        st.conn_tree.connections(),
                        st.conn_tree.groups(),
                        secrets.as_ref(),
                        st.keys_panel.credentials(),
                    );
                    ReconnectPlan::Rdp(rdp_ci.settings.clone(), provenance, auth_result)
                }
                ConnectInfo::Telnet(settings) => ReconnectPlan::Telnet(settings.clone()),
            })
    };
    let Some(plan) = plan else { return };
    // Either way the old session is done — shut it down before
    // deciding whether a fresh connect attempt or the auth-error
    // overlay follows.
    {
        let st = state.borrow();
        if let Some(tab) = st.tabs.get(tab_idx) {
            tab.session.shutdown();
        }
    }
    match plan {
        ReconnectPlan::Ssh(settings, provenance, auth_result) => match auth_result {
            Ok(auth) => {
                let verifier = ssh_host_key_verifier(state, weak, hk_pending);
                reconnect_ssh_tab(
                    state, tab_model, ui, tab_idx, settings, auth, provenance, verifier,
                );
            }
            Err(e) => {
                fail_reconnect_in_place(state, tab_model, ui, tab_idx, e.to_string());
            }
        },
        ReconnectPlan::Rdp(settings, provenance, auth_result) => match auth_result {
            Ok(auth) => {
                let verifier = rdp_certificate_verifier(state, weak, cert_pending);
                reconnect_rdp_tab(
                    state, tab_model, ui, tab_idx, settings, auth, provenance, verifier,
                );
            }
            Err(e) => {
                fail_reconnect_in_place(state, tab_model, ui, tab_idx, e.to_string());
            }
        },
        ReconnectPlan::Telnet(settings) => {
            reconnect_telnet_tab(state, tab_model, ui, tab_idx, settings);
        }
    }
}

/// #1: the tab context menu's "Disconnect" - tears the session(s)
/// down but keeps the tab open, dropping it into the same Failed/
/// error-overlay state a spontaneous disconnect or a failed reconnect
/// already leaves a tab in (`fail_reconnect_in_place`), so "Reconnect" works
/// from the very same tab afterward. Shuts down every pane's session
/// (primary + any split extra panes) - this is a whole-TAB disconnect;
/// disconnecting a single pane within a split is 's own, separate
/// affordance. Caller must bring `tab_idx` into view first, same reasoning
/// as [`reconnect_tab`].
pub(super) fn disconnect_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    tab_idx: usize,
) {
    {
        let st = state.borrow();
        let Some(tab) = st.tabs.get(tab_idx) else {
            return;
        };
        tab.session.shutdown();
        for ep in &tab.extra_panes {
            ep.session.shutdown();
        }
    }
    fail_reconnect_in_place(state, tab_model, ui, tab_idx, "Disconnected".to_string());
}

/// One construction path for every SSH launch surface. The persisted setting
/// is live runtime state; the environment hook remains a debug-only QA aid.
pub(super) fn ssh_host_key_verifier(
    state: &Rc<RefCell<State>>,
    weak_ui: &slint::Weak<AppWindow>,
    pending: &HkQueue,
) -> Arc<dyn HostKeyVerifier> {
    let auto_accept = state.borrow().auto_accept_ssh_host_keys || util::ssh_auto_accept_keys();
    Arc::new(UiHostKeyVerifier {
        weak_ui: weak_ui.clone(),
        pending: pending.clone(),
        auto_accept,
    })
}

/// One construction path for every RDP launch surface. Keeping this beside
/// the SSH factory prevents Quick Connect, saved profiles, reconnects, and
/// split panes from drifting into different trust policies.
pub(super) fn rdp_certificate_verifier(
    state: &Rc<RefCell<State>>,
    weak_ui: &slint::Weak<AppWindow>,
    pending: &Arc<Mutex<Option<Sender<CertDecision>>>>,
) -> Arc<dyn CertVerifier> {
    let auto_accept = state.borrow().auto_accept_rdp_certificates || util::rdp_auto_accept_certs();
    Arc::new(UiCertVerifier {
        weak_ui: weak_ui.clone(),
        pending: pending.clone(),
        auto_accept,
    })
}

pub(super) struct UiHostKeyVerifier {
    pub(super) weak_ui: slint::Weak<AppWindow>,
    pub(super) pending: HkQueue,
    pub(super) auto_accept: bool,
}

impl HostKeyVerifier for UiHostKeyVerifier {
    fn decide(&self, info: &HostKeyInfo) -> HostKeyDecision {
        if self.auto_accept {
            tracing::warn!(
                host = %info.host,
                port = info.port,
                algorithm = %info.algorithm,
                fingerprint = %info.fingerprint,
                situation = ?info.situation,
                decision = "automatic",
                "ssh: host key automatically accepted by user setting"
            );
            return HostKeyDecision::Accept;
        }
        let (tx, rx) = std::sync::mpsc::channel::<HostKeyDecision>();
        if let Ok(mut q) = self.pending.lock() {
            q.push_back(tx);
        }
        let decision_info = info.clone();
        let info = info.clone();
        let weak = self.weak_ui.clone();
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = weak.upgrade() else { return };
            let mismatch = matches!(
                info.situation,
                cm_session::HostKeySituation::Mismatch { .. }
            );
            let stored_fp = if let cm_session::HostKeySituation::Mismatch {
                ref stored_fingerprint,
                ..
            } = info.situation
            {
                stored_fingerprint.clone()
            } else {
                String::new()
            };
            ui.set_host_key_mismatch(mismatch);
            ui.set_host_key_host(format!("{}:{}", info.host, info.port).into());
            ui.set_host_key_type(info.algorithm.clone().into());
            ui.set_host_key_fingerprint(info.fingerprint.clone().into());
            ui.set_host_key_stored_fp(stored_fp.into());
            ui.set_host_key_open(true);
        });
        let (decision, decision_source) = match rx.recv() {
            Ok(decision) => (decision, "user"),
            Err(_) => (HostKeyDecision::Reject, "dialog-unavailable"),
        };
        tracing::info!(
            host = %decision_info.host,
            port = decision_info.port,
            algorithm = %decision_info.algorithm,
            fingerprint = %decision_info.fingerprint,
            situation = ?decision_info.situation,
            decision = ?decision,
            decision_source,
            "ssh: host-key trust decision completed"
        );
        decision
    }
}

/// Shows the cert-accept dialog ( slint UI) and blocks the RDP connection
/// thread until the user accepts or rejects.
///
/// When `auto_accept` is true, the verifier immediately returns
/// `AcceptAndRemember` without showing the dialog. The value comes from the
/// secure-default application setting (or the debug-only QA environment hook).
pub(super) struct UiCertVerifier {
    pub(super) weak_ui: slint::Weak<AppWindow>,
    pub(super) pending: Arc<Mutex<Option<Sender<CertDecision>>>>,
    pub(super) auto_accept: bool,
}

impl CertVerifier for UiCertVerifier {
    fn decide(&self, info: &CertInfo) -> CertDecision {
        if self.auto_accept {
            tracing::warn!(
                host = %info.host,
                port = info.port,
                fingerprint = %info.fingerprint,
                subject = %info.subject,
                situation = ?info.situation,
                decision = "automatic",
                "rdp: certificate automatically accepted by user setting"
            );
            return CertDecision::AcceptAndRemember;
        }
        let (tx, rx) = std::sync::mpsc::channel::<CertDecision>();
        if let Ok(mut p) = self.pending.lock() {
            *p = Some(tx);
        }
        let decision_info = info.clone();
        let info = info.clone();
        let weak = self.weak_ui.clone();
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = weak.upgrade() else { return };
            let mismatch = matches!(info.situation, cm_session::CertSituation::Mismatch { .. });
            let stored_fp = if let cm_session::CertSituation::Mismatch {
                ref stored_fingerprint,
                ..
            } = info.situation
            {
                stored_fingerprint.clone()
            } else {
                String::new()
            };
            ui.set_cert_dialog_mismatch(mismatch);
            ui.set_cert_dialog_host(format!("{}:{}", info.host, info.port).into());
            ui.set_cert_dialog_subject(info.subject.clone().into());
            ui.set_cert_dialog_fingerprint(info.fingerprint.clone().into());
            ui.set_cert_dialog_stored_fp(stored_fp.into());
            ui.set_cert_dialog_open(true);
        });
        let (decision, decision_source) = match rx.recv() {
            Ok(decision) => (decision, "user"),
            Err(_) => (CertDecision::Reject, "dialog-unavailable"),
        };
        tracing::info!(
            host = %decision_info.host,
            port = decision_info.port,
            fingerprint = %decision_info.fingerprint,
            subject = %decision_info.subject,
            situation = ?decision_info.situation,
            decision = ?decision,
            decision_source,
            "rdp: certificate trust decision completed"
        );
        decision
    }
}

pub(super) fn render_frame(
    tab: &mut Tab,
    snap: &GridSnapshot,
    target: Option<(u32, u32)>,
) -> Image {
    let sel = tab.sel.selection().copied();
    let (matches, current) = if tab.search.applies_to(0) {
        visible_search_highlights(&tab.search, snap)
    } else {
        (Vec::new(), None)
    };
    let (w, h) = target.unwrap_or_else(|| tab.renderer.pixel_size(snap.size));
    let buf = tab
        .renderer
        .render_to_full(snap, w, h, sel.as_ref(), &matches, current);
    Image::from_rgba8(buf)
}

/// the active tab's search matches that fall within `snap`'s currently
/// displayed viewport window, translated to the index `render_to_full`
/// expects for `current_match` — `terminal_renderer::render_to_full`'s doc
/// asks callers to pre-filter for exactly this reason (an unfiltered 10k-line
/// match list would be scanned per-cell on every redraw).
pub(super) fn visible_search_highlights(
    search: &search::SearchState,
    snap: &GridSnapshot,
) -> (Vec<crate::terminal_renderer::SearchMatch>, Option<usize>) {
    if !search.is_open() {
        return (Vec::new(), None);
    }
    let abs_top = snap.scrollback_len.saturating_sub(snap.scroll_offset);
    let abs_bottom = abs_top + u32::from(snap.size.rows);
    let current_match = search
        .current()
        .and_then(|i| search.matches().get(i))
        .copied();
    let visible: Vec<_> = search
        .matches()
        .iter()
        .filter(|m| {
            let r = u32::from(m.row);
            r >= abs_top && r < abs_bottom
        })
        .copied()
        .collect();
    let current_idx = current_match.and_then(|cm| visible.iter().position(|m| *m == cm));
    (visible, current_idx)
}

pub(crate) fn drain_latest<T>(rx: &Receiver<T>) -> Option<T> {
    let mut latest = None;
    while let Ok(v) = rx.try_recv() {
        latest = Some(v);
    }
    latest
}

// Stored-credential resolution

/// Why resolving a saved connection's stored credential into real auth
/// material failed. Never carries secret bytes — only enough to build the
/// actionable message the auth-error overlay shows (spec: "No credential
/// assigned" / "Credential not found in keychain").
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AuthResolveError {
    /// Neither the connection nor any ancestor group names a credential.
    NoCredentialAssigned,
    /// A credential is assigned, but the keychain has no entry for the
    /// required purpose (never saved, or deleted out-of-band).
    NotFoundInKeychain,
    /// The keychain adapter itself failed. Wraps only the backend's own
    /// (already secret-free, per `cm_core::CredentialError`) message.
    Backend(String),
}

impl std::fmt::Display for AuthResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthResolveError::NoCredentialAssigned => write!(f, "No credential assigned"),
            AuthResolveError::NotFoundInKeychain => {
                write!(f, "Credential not found in keychain")
            }
            AuthResolveError::Backend(e) => write!(f, "Keychain error: {e}"),
        }
    }
}

// `resolve_auth` wraps `cm_core::resolve_connection_auth`, which performs
// the keychain lookup uniformly for every credential source.

/// BUG-cred-username-auth: the effective username actually sent to
/// authenticate a connection. Precedence follows `cm_core::Credential::username`
/// and the connection's `CredentialSource`, without pulling in
/// a `CredentialStore` (this function is display/settings-only, no keychain
/// I/O, so its signature - and every caller that has no store handy, e.g.
/// tree/profile-editor display - stays unchanged):
///
/// 1. [`cm_core::CredentialSource::Inline`]'s own `username`, when non-empty
/// - the mode-selector's Inline fields are authoritative once chosen,
///   same "most specific wins" the object case already followed.
/// 2. else, for `Object`/inherit: the resolved credential's own `username` -
///    when
///    [`resolve_effective_credential`] (own credential, or inherited from the
///    nearest ancestor group's default) finds one, AND its `username` is
///    non-empty. The credential object is the source of truth once assigned:
///    this is what makes a credentialed RoyalTS-imported connection (which
///    carries no inline username at all) authenticate with the right user
///    instead of an empty one.
/// 3. else `inline_username` - the connection's own typed username (Quick
///    Connect with inline creds, an explicit override, `Prompt` mode, or any
///    connection with no credential assigned).
/// 4. else empty - unchanged behavior for callers that require a non-empty
///    username (surfaces as the existing auth error).
///
/// [`resolve_effective_credential`]: cm_core::resolve_effective_credential
pub(super) fn effective_auth_username(
    conn: &Connection,
    groups: &[Group],
    inline_username: &str,
    credentials: &[cm_core::Credential],
) -> String {
    if let Some(cm_core::CredentialSource::Inline { username, .. }) = &conn.credential_source
        && !username.is_empty()
    {
        return username.clone();
    }
    let cred_username = cm_core::resolve_effective_credential(conn, groups).and_then(|id| {
        credentials
            .iter()
            .find(|c| c.id == id)
            .and_then(|c| c.username.clone())
            .filter(|u| !u.is_empty())
    });
    cred_username.unwrap_or_else(|| inline_username.to_owned())
}

/// SSH counterpart-helper: [`SshAuthInput`] carries no username field (unlike
/// [`RdpAuthInput`]) - the username actually used to connect lives entirely
/// on [`SshSettings::username`], which is what [`cm_session`]'s SSH backend
/// reads directly. This builds the [`SshSettings`] actually used to connect:
/// identical to `settings` except `username`, which follows
/// [`effective_auth_username`]'s precedence. Centralizing the override here
/// means every SSH launch/reconnect path (initial launch, connect-in-split,
/// reconnect) applies it identically.
pub(super) fn effective_ssh_settings(
    conn: &Connection,
    groups: &[Group],
    settings: &SshSettings,
    credentials: &[cm_core::Credential],
) -> SshSettings {
    let mut settings = settings.clone();
    settings.username = effective_auth_username(conn, groups, &settings.username, credentials);
    settings
}

/// whether `conn` has ANY credential source that could
/// actually produce a secret - i.e. `resolve_connection_auth` finding no
/// secret means "this purpose was never stored" (`NotFoundInKeychain`)
/// rather than "nothing is configured at all" (`NoCredentialAssigned`).
/// `Prompt` counts as "nothing assigned" here: it explicitly opts out of any
/// stored secret, and ConMan has no live connect-time prompt UX yet (per the
/// design brief's non-goals) - so today it fails exactly like an
/// unassigned connection always has, surfacing the same auth-error overlay
/// rather than inventing a prompt flow this 't build.
fn has_assigned_credential_source(conn: &Connection, groups: &[Group]) -> bool {
    match &conn.credential_source {
        Some(cm_core::CredentialSource::Object(_)) => true,
        Some(cm_core::CredentialSource::Inline { has_secret, .. }) => *has_secret,
        Some(cm_core::CredentialSource::Prompt) => false,
        None => cm_core::resolve_effective_credential(conn, groups).is_some(),
    }
}

/// E1/E3: a non-secret, human-readable tag for *how* `conn` gets its
/// credential - `"object:<name>#<id>"` (own or inherited), `"inline"`,
/// `"prompt"`, or `"none"` (nothing configured at all). Shared by the
/// release-safe launch log ([`log_ssh_launch_auth`]/[`log_rdp_launch_auth`])
/// and the E3 keychain-miss warning in [`no_secret_error`] - never the
/// secret itself, just which source it would have come from.
fn cred_source_label(
    conn: &Connection,
    groups: &[Group],
    credentials: &[cm_core::Credential],
) -> String {
    match &conn.credential_source {
        Some(cm_core::CredentialSource::Object(id)) => format!(
            "object:{}#{}",
            KeysPanel::cred_display_name(Some(*id), credentials),
            id.get()
        ),
        Some(cm_core::CredentialSource::Inline { .. }) => "inline".to_owned(),
        Some(cm_core::CredentialSource::Prompt) => "prompt".to_owned(),
        None => match cm_core::resolve_effective_credential(conn, groups) {
            Some(id) => format!(
                "object:{}#{}",
                KeysPanel::cred_display_name(Some(id), credentials),
                id.get()
            ),
            None => "none".to_owned(),
        },
    }
}

/// Maps a missing secret from [`cm_core::resolve_connection_auth`] to the
/// right [`AuthResolveError`] variant - see
/// [`has_assigned_credential_source`] for the distinction - and logs the
/// matching E2/E3 release-safe warning (never the secret itself; E3
/// carries [`cred_source_label`], not the credential/keychain contents).
fn no_secret_error(
    conn: &Connection,
    groups: &[Group],
    kind: &str,
    credentials: &[cm_core::Credential],
) -> AuthResolveError {
    if has_assigned_credential_source(conn, groups) {
        tracing::warn!(
            conn = %conn.name,
            cred_source = %cred_source_label(conn, groups, credentials),
            "connection launch aborted: credential secret missing from keychain"
        );
        AuthResolveError::NotFoundInKeychain
    } else {
        tracing::warn!(
            conn = %conn.name,
            kind = %kind,
            "connection launch aborted: no credential assigned"
        );
        AuthResolveError::NoCredentialAssigned
    }
}

/// Thin wrapper around [`cm_core::resolve_connection_auth`] mapping its
/// (secret-free, per `cm_core::CredentialError`'s own contract) backend
/// error into [`AuthResolveError::Backend`].
fn resolve_auth(
    conn: &Connection,
    groups: &[Group],
    credentials: &[cm_core::Credential],
    secrets: &dyn cm_core::CredentialStore,
    purpose: CredentialPurpose,
) -> Result<cm_core::ResolvedAuth, AuthResolveError> {
    cm_core::resolve_connection_auth(conn, groups, credentials, secrets, purpose)
        .map_err(|e| AuthResolveError::Backend(e.to_string()))
}

/// Resolves the real [`SshAuthInput`] for a tree-launched SSH connection -
/// a thin adapter over [`cm_core::resolve_connection_auth`]
/// (Object/inherit, Inline, and Prompt credential sources), per
/// `settings.auth_method`. Never falls back to an empty/placeholder password
/// — a missing assignment or keychain entry is a typed [`AuthResolveError`]
/// the caller turns into the auth-error overlay instead of attempting to
/// connect.
pub(super) fn resolve_ssh_auth(
    conn: &Connection,
    groups: &[Group],
    settings: &SshSettings,
    secrets: &dyn cm_core::CredentialStore,
    credentials: &[cm_core::Credential],
) -> Result<SshAuthInput, AuthResolveError> {
    // Agent auth needs no stored secret (Windows ssh-agent support is).
    if matches!(settings.auth_method, SshAuthMethod::Agent) {
        return Ok(SshAuthInput::Agent);
    }
    match settings.auth_method {
        SshAuthMethod::Password => {
            let resolved = resolve_auth(
                conn,
                groups,
                credentials,
                secrets,
                CredentialPurpose::Password,
            )?;
            let secret = resolved
                .secret
                .ok_or_else(|| no_secret_error(conn, groups, "ssh", credentials))?;
            Ok(SshAuthInput::Password(secret))
        }
        SshAuthMethod::PublicKey { .. } => {
            let resolved_key = resolve_auth(
                conn,
                groups,
                credentials,
                secrets,
                CredentialPurpose::SshKey,
            )?;
            let key_pem = resolved_key
                .secret
                .ok_or_else(|| no_secret_error(conn, groups, "ssh", credentials))?;
            // Passphrase is optional - CredentialKind::SshKey has none, and
            // Inline never carries a key/passphrase at all (password-only,
            // per the non-goals) - either way a miss here is `None`,
            // not an error, matching `fetch_secret`'s old optional-purpose
            // contract.
            let passphrase = resolve_auth(
                conn,
                groups,
                credentials,
                secrets,
                CredentialPurpose::SshPassphrase,
            )?
            .secret;
            Ok(SshAuthInput::KeyMaterial {
                key_pem,
                passphrase,
            })
        }
        SshAuthMethod::Agent => unreachable!("handled above"),
    }
}

/// Resolves the real [`RdpAuthInput`] for a tree-launched RDP connection -
/// a thin adapter over [`cm_core::resolve_connection_auth`],
/// password-only (ConMan has no RDP key-based auth), same credential-source
/// coverage as [`resolve_ssh_auth`].
///
/// `domain`: [`cm_core::ResolvedAuth::domain`] is populated ONLY for
/// `Inline` (a credential object has no domain field, and `Prompt`/inherit
/// carry none either) - so an Inline connection's own typed domain wins,
/// and everything else falls back to the connection's own
/// [`RdpSettings::domain`] unchanged.
pub(super) fn resolve_rdp_auth(
    conn: &Connection,
    groups: &[Group],
    settings: &RdpSettings,
    secrets: &dyn cm_core::CredentialStore,
    credentials: &[cm_core::Credential],
) -> Result<RdpAuthInput, AuthResolveError> {
    let resolved = resolve_auth(
        conn,
        groups,
        credentials,
        secrets,
        CredentialPurpose::Password,
    )?;
    let password = resolved
        .secret
        .ok_or_else(|| no_secret_error(conn, groups, "rdp", credentials))?;
    Ok(RdpAuthInput {
        username: resolved.username,
        password,
        domain: resolved.domain.or_else(|| settings.domain.clone()),
    })
}

/// E1: logs the *non-secret* auth context a successfully-resolved SSH
/// launch is about to use - which credential (object name + id) or
/// fallback source (`ssh-agent`/`inline`/`prompt`/`none`), and which
/// username, are actually being handed to
/// [`cm_session::SessionProvider::connect_ssh`]. Fires from every launch path
/// that goes through [`resolve_ssh_auth`]: `launch_saved_connection` (tree
/// click / `CONMAN_TREE_AUTOLAUNCH` / Launchpad) and `connect_in_split`
/// (`controller/panes.rs`).
///
/// BUG-cred-username-auth: `username` is computed via
/// [`effective_auth_username`] - the *effective* username actually sent
/// (credential's own username when one is assigned and non-empty, else
/// `settings.username`) - not `settings.username` directly, so the log is
/// truthful regardless of whether the caller already applied the same
/// precedence to the `settings` it passes in.
///
/// ABSOLUTE RULE: never log the password/secret/passphrase/key material -
/// only the credential's name/id, the resolved username, and connection
/// metadata (host/port). Release-safe ( E1, promoted from the old
/// `#[cfg(debug_assertions)]`-only line): operators debugging
/// "authed as the wrong user" (the exact BUG-cred-username-auth class) need
/// this signal outside dev builds too. None of these fields are secret -
/// see the rule above and [`cred_source_label`]'s own doc comment.
pub(super) fn log_ssh_launch_auth(
    conn: &Connection,
    groups: &[Group],
    settings: &SshSettings,
    credentials: &[cm_core::Credential],
) {
    let cred_source = if matches!(settings.auth_method, SshAuthMethod::Agent) {
        "ssh-agent".to_owned()
    } else {
        cred_source_label(conn, groups, credentials)
    };
    let username = effective_auth_username(conn, groups, &settings.username, credentials);
    tracing::info!(
        conn = %conn.name,
        kind = "ssh",
        host = %settings.host,
        port = settings.port,
        cred_source = %cred_source,
        username = %username,
        "launching connection"
    );
}

/// RDP counterpart to [`log_ssh_launch_auth`] - same rule, plus `domain`
/// (RDP-specific auth context, always from `settings` - credentials have no
/// domain field). BUG-cred-username-auth: `username` is likewise the
/// *effective* username via [`effective_auth_username`], not
/// `settings.username` directly (see [`resolve_rdp_auth`]).
pub(super) fn log_rdp_launch_auth(
    conn: &Connection,
    groups: &[Group],
    settings: &RdpSettings,
    credentials: &[cm_core::Credential],
) {
    let cred_source = cred_source_label(conn, groups, credentials);
    let username = effective_auth_username(
        conn,
        groups,
        settings.username.as_deref().unwrap_or(""),
        credentials,
    );
    tracing::info!(
        conn = %conn.name,
        kind = "rdp",
        host = %settings.host,
        port = settings.port,
        cred_source = %cred_source,
        username = %username,
        domain = %settings.domain.clone().unwrap_or_default(),
        "launching connection"
    );
}

/// Sets the error-overlay UI state for `reason` - shared by the synchronous
/// connect-failure branches and the credential-resolution failure paths
/// below. Every caller here is a genuine failure (a synchronous connect
/// error, a missing/unresolvable credential, an agent-mode execute-gate
/// denial) - #3's neutral "Session ended" framing is only for a
/// clean `Disconnected`/`Exited` end (`overlays::update_overlays_from_status`),
/// never for these, so this always marks the overlay as a real failure.
fn set_error_overlay(ui: &AppWindow, reason: &str) {
    ui.set_overlay_connecting(false);
    ui.set_overlay_error(true);
    ui.set_launchpad_open(false);
    ui.set_error_is_failure(true);
    ui.set_error_reason(SharedString::from(reason));
    ui.set_error_detail(SharedString::from(""));
}

/// Pushes a new `Failed` tab for a credential-resolution error -
/// mirrors the synchronous-setup-error handling in [`open_ssh_tab`] but never
/// attempts a network connection with a placeholder/empty credential.
/// `origin_connection_id` is threaded through unchanged so the
/// ErrorOverlay "Edit…" button reopens the originating profile even when the
/// failure never reached the network layer.
fn push_auth_failed_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    title: String,
    identity: String,
    reason: String,
    origin_connection_id: Option<i32>,
) {
    push_failed_remote_tab(
        state,
        tab_model,
        ui,
        title,
        identity,
        reason,
        origin_connection_id,
        String::new(),
        false,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_failed_remote_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    title: String,
    identity: String,
    reason: String,
    origin_connection_id: Option<i32>,
    kind: String,
    insecure_transport: bool,
) {
    tabs::push_tab(
        state,
        tab_model,
        ui,
        tabs::PushTabArgs {
            session: Box::new(FailedSession::new(reason.clone())),
            endpoint_id: None,
            connect_info: None,
            is_remote: true,
            title,
            initial_status: "error",
            origin_connection_id,
            is_empty: false,
            identity: identity.clone(),
            kind: kind.clone(),
            insecure_transport,
        },
    );
    ui.set_session_identity(SharedString::from(identity));
    ui.set_connecting_kind(SharedString::from(kind));
    ui.set_session_insecure(insecure_transport);
    ui.set_rdp_active(false);
    set_error_overlay(ui, &reason);
}

/// Replaces the active tab's session with a `Failed` one after a reconnect's
/// credential re-resolution fails. The caller has already shut down
/// the old session; this never attempts to reconnect with stale/empty auth.
/// The tab's own `origin_connection_id` is untouched (only `session`/`last`
/// are replaced), so the ErrorOverlay "Edit…" button still works afterward.
fn fail_reconnect_in_place(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    tab_idx: usize,
    reason: String,
) {
    {
        let mut st = state.borrow_mut();
        if let Some(tab) = st.tabs.get_mut(tab_idx) {
            tab.session = Box::new(FailedSession::new(reason.clone()));
            tab.last = None;
        }
    }
    if let Some(mut item) = tab_model.row_data(tab_idx) {
        item.status = SharedString::from("error");
        tab_model.set_row_data(tab_idx, item);
    }
    set_error_overlay(ui, &reason);
}

/// the execute-scope launch/broadcast gate. True only when
/// an agent write-tool call (`click_element`/`invoke_accessibility_action`/
/// `dispatch_key_event`) is *actually in flight* through the proxy
/// (`AgentModeConfig::mcp_interaction_active`) AND `execute` isn't granted.
///
/// A human-initiated launch is never inside that window (nothing sets the
/// counter except the proxy forwarding an agent's own write-tool call), so
/// this never gates a plain user click. The one accepted exception is the
/// fail-safe over-restriction documented on `mcp_interaction_active`: a
/// human click that happens to land in the same (short, tens-of-
/// milliseconds) window as an unrelated agent write-tool call is spuriously
/// refused too - over-restricting, never under-restricting, and rare
/// enough (and cheap enough to just retry) to accept for v1.
pub(super) fn agent_mode_execute_blocked(agent_mode: &Option<crate::AgentModeConfig>) -> bool {
    match agent_mode {
        Some(cfg) if cfg.mcp_interaction_active() => {
            let granted = cfg
                .scopes
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            !granted.execute
        }
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn open_ssh_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    settings: SshSettings,
    auth: SshAuthInput,
    provenance: AuthProvenance,
    verifier: Arc<dyn HostKeyVerifier>,
    origin_connection_id: Option<i32>,
) {
    let size = state.borrow().current_grid();
    let terminal_options = TerminalOptions {
        max_scrollback: state.borrow().scrollback_limit,
    };
    let identity = format!("{}@{}:{}", settings.username, settings.host, settings.port);
    let title = format!("SSH {}", settings.host);
    // the execute-scope launch gate. Covers every caller of
    // this function - tree-launched connections, split-pane connects,
    // quick-connect, and the debug autoinit hook - since they all funnel
    // through here rather than dialing `connect_ssh` themselves.
    if agent_mode_execute_blocked(&state.borrow().agent_mode) {
        tracing::warn!(
            conn = %identity,
            "agent mode: launch blocked while automation is active without execute scope"
        );
        push_auth_failed_tab(
            state,
            tab_model,
            ui,
            title,
            identity,
            "agent mode: execute scope not granted".to_string(),
            origin_connection_id,
        );
        return;
    }
    // Only `Direct` (quick-connect / debug autoinit) clones the auth for
    // reconnect - `Credential`-sourced auth is re-resolved fresh each time
    // (never cache the fetched secret in `Tab` state).
    let auth_source = match provenance {
        AuthProvenance::Direct => SshAuthSource::Direct(auth.clone()),
        AuthProvenance::Credential(id) => SshAuthSource::Credential(id),
    };
    let provider = state.borrow().session_provider.clone();
    match provider.connect_ssh(&settings, auth, verifier, size, terminal_options) {
        Ok(session) => {
            let ci = SshConnectInfo {
                settings,
                auth_source,
            };
            tabs::push_tab(
                state,
                tab_model,
                ui,
                tabs::PushTabArgs {
                    session,
                    endpoint_id: None,
                    connect_info: Some(ConnectInfo::Ssh(ci)),
                    is_remote: true,
                    title,
                    initial_status: "connecting",
                    origin_connection_id,
                    is_empty: false,
                    identity: identity.clone(),
                    kind: "SSH".to_owned(),
                    insecure_transport: false,
                },
            );
            ui.set_session_identity(SharedString::from(identity));
            ui.set_overlay_connecting(true);
            ui.set_overlay_error(false);
            ui.set_launchpad_open(false);
            ui.set_connecting_kind(SharedString::from("SSH"));
            ui.set_rdp_active(false);
            // #2: `push_tab` makes this brand-new tab active but never
            // touches `root.frame` - the same single AppWindow-level
            // property Bug B's fix (`de72222`) already established isn't
            // per-tab, and neither `push_tab` nor the routine tick loop
            // calls `render_active` to refresh it on a fresh launch (only
            // `select_tab`/`close_tab`/reconnect do). Without this, the
            // property stays bound to whatever the PREVIOUSLY active tab
            // last painted (typically the Home tab's local shell) until
            // this session's own first `GridSnapshot` drains - exactly the
            // "local shell flashes before the remote paints" bleed. Blank
            // it immediately, mirroring `reconnect_ssh_tab`'s identical fix.
            ui.set_frame(Image::default());
        }
        Err(e) => {
            // (b): surface synchronous setup errors as a Failed
            // tab with the error overlay, not just an eprintln!.
            let reason = e.to_string();
            push_auth_failed_tab(
                state,
                tab_model,
                ui,
                title,
                identity,
                reason,
                origin_connection_id,
            );
        }
    }
}

pub(super) fn open_telnet_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    settings: TelnetSettings,
    origin_connection_id: Option<i32>,
) {
    let size = state.borrow().current_grid();
    let terminal_options = TerminalOptions {
        max_scrollback: state.borrow().scrollback_limit,
    };
    let identity = format!("{}:{}", settings.host, settings.port);
    let title = format!("TELNET {}", settings.host);
    if agent_mode_execute_blocked(&state.borrow().agent_mode) {
        tracing::warn!(
            conn = %identity,
            "agent mode: Telnet launch blocked while automation is active without execute scope"
        );
        push_failed_remote_tab(
            state,
            tab_model,
            ui,
            title,
            identity,
            "agent mode: execute scope not granted".to_owned(),
            origin_connection_id,
            "TELNET".to_owned(),
            true,
        );
        return;
    }

    let provider = state.borrow().session_provider.clone();
    match provider.connect_telnet(&settings, size, terminal_options) {
        Ok(session) => {
            tabs::push_tab(
                state,
                tab_model,
                ui,
                tabs::PushTabArgs {
                    session,
                    endpoint_id: None,
                    connect_info: Some(ConnectInfo::Telnet(settings)),
                    is_remote: true,
                    title,
                    initial_status: "connecting",
                    origin_connection_id,
                    is_empty: false,
                    identity: identity.clone(),
                    kind: "TELNET".to_owned(),
                    insecure_transport: true,
                },
            );
            ui.set_session_identity(SharedString::from(identity));
            ui.set_overlay_connecting(true);
            ui.set_overlay_error(false);
            ui.set_launchpad_open(false);
            ui.set_connecting_kind(SharedString::from("TELNET"));
            ui.set_session_insecure(true);
            ui.set_rdp_active(false);
            // The terminal frame is shared across tabs. Blank it until this
            // Telnet session produces its first GridSnapshot.
            ui.set_frame(Image::default());
        }
        Err(e) => push_failed_remote_tab(
            state,
            tab_model,
            ui,
            title,
            identity,
            e.to_string(),
            origin_connection_id,
            "TELNET".to_owned(),
            true,
        ),
    }
}

/// Pure decision behind [`apply_pane_resolution`]: the pane's live pixel
/// size (`target_px`, when known) wins over whatever `(width, height)` the
/// caller already had - persisted profile, quick-connect typed value, or
/// the `RdpSettings::default` autoinit uses - which is the "resize to
/// window" behavior #10 asks for. Clamped to a sane desktop-size range
/// so a transient 0/huge readout can never produce a degenerate resolution.
/// Falls back to `current` unchanged when no pane has ever reported its
/// size yet (the very first tab at startup, before any `surface-resized`
/// event).
pub(super) fn pane_resolution_override(
    target_px: Option<(u32, u32)>,
    current: (u16, u16),
) -> (u16, u16) {
    match target_px {
        Some((pw, ph)) => (pw.clamp(200, 8192) as u16, ph.clamp(200, 8192) as u16),
        None => current,
    }
}

/// #10: overwrite `settings.width`/`settings.height` with the active
/// pane's live pixel size via [`pane_resolution_override`] (`State::target_px`
/// is the same HiDPI-corrected value `apply_settled_resize` feeds to
/// `Session::resize_px` after connect) - negotiating the desktop at the
/// pane's actual size is what lets `RdpSurface`'s `Image` display 1:1
/// instead of bitmap-scaling.
fn apply_pane_resolution(state: &Rc<RefCell<State>>, settings: &mut RdpSettings) {
    let target = state.borrow().target_px();
    let (width, height) = pane_resolution_override(target, (settings.width, settings.height));
    settings.width = width;
    settings.height = height;
}

#[allow(clippy::too_many_arguments)]
pub(super) fn open_rdp_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    mut settings: RdpSettings,
    auth: RdpAuthInput,
    provenance: AuthProvenance,
    verifier: Arc<dyn CertVerifier>,
    origin_connection_id: Option<i32>,
) {
    // #10: the pane's live pixel size (when known) wins over whatever
    // resolution the settings carried in (persisted profile / quick-connect
    // typed value / autoinit default) - negotiating the desktop at the
    // pane's actual size is what lets `RdpSurface`'s `Image` display 1:1
    // instead of bitmap-scaling. See `apply_pane_resolution`.
    apply_pane_resolution(state, &mut settings);
    let title = format!("RDP {}", settings.host);
    let identity = format!("{}@{}:{}", auth.username, settings.host, settings.port);
    // the execute-scope launch gate - see open_ssh_tab's
    // identical comment.
    if agent_mode_execute_blocked(&state.borrow().agent_mode) {
        tracing::warn!(
            conn = %identity,
            "agent mode: launch blocked while automation is active without execute scope"
        );
        push_auth_failed_tab(
            state,
            tab_model,
            ui,
            title,
            identity,
            "agent mode: execute scope not granted".to_string(),
            origin_connection_id,
        );
        return;
    }
    // Only `Direct` (quick-connect / debug autoinit) clones the auth for
    // reconnect - `Credential`-sourced auth is re-resolved fresh each time
    // (/: never cache the fetched secret in `Tab` state).
    let auth_source = match provenance {
        AuthProvenance::Direct => RdpAuthSource::Direct(auth.clone()),
        AuthProvenance::Credential(id) => RdpAuthSource::Credential(id),
    };
    let provider = state.borrow().session_provider.clone();
    let Some(endpoint_id) = state.borrow_mut().allocate_endpoint_id() else {
        tracing::error!("session endpoint ID space exhausted");
        return;
    };
    let session = match provider.connect_rdp(&settings, auth, verifier, endpoint_id) {
        Ok(s) => s,
        Err(e) => {
            // mirrors open_ssh_tab's synchronous-setup-error handling
            // surface it as a Failed tab with the error overlay instead of
            // silently doing nothing (the earlier behavior here).
            tracing::warn!("RDP connect error: {e}");
            push_auth_failed_tab(
                state,
                tab_model,
                ui,
                title,
                identity,
                e.to_string(),
                origin_connection_id,
            );
            return;
        }
    };
    let ci = RdpConnectInfo {
        settings,
        auth_source,
    };
    tabs::push_tab(
        state,
        tab_model,
        ui,
        tabs::PushTabArgs {
            session,
            endpoint_id: Some(endpoint_id),
            connect_info: Some(ConnectInfo::Rdp(ci)),
            is_remote: true,
            title,
            initial_status: "connecting",
            origin_connection_id,
            is_empty: false,
            identity: identity.clone(),
            kind: "RDP".to_owned(),
            insecure_transport: false,
        },
    );
    ui.set_session_identity(SharedString::from(identity));
    ui.set_overlay_connecting(true);
    ui.set_overlay_error(false);
    ui.set_launchpad_open(false);
    ui.set_connecting_kind(SharedString::from("RDP"));
    ui.set_rdp_active(true);
    // #2: see `open_ssh_tab`'s identical comment - `root.rdp-frame`
    // is the same kind of single AppWindow-level property, and `push_tab`
    // doesn't touch it either. Blank it so this fresh RDP tab never briefly
    // shows the previously-active tab's last painted frame.
    ui.set_rdp_frame(Image::default());
}

/// RDP counterpart to [`reconnect_ssh_tab`]: replaces the
/// active tab's session in place after the caller has already shut down the
/// old one. Reuses the exact same persistent cert store [`open_rdp_tab`]
/// uses, so an already-trusted cert never re-prompts on reconnect.
#[allow(clippy::too_many_arguments)]
pub(super) fn reconnect_rdp_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    tab_idx: usize,
    mut settings: RdpSettings,
    auth: RdpAuthInput,
    provenance: AuthProvenance,
    verifier: Arc<dyn CertVerifier>,
) {
    // #10: re-apply the pane's current pixel size on every reconnect
    // too, so a reconnect after the user has resized the window picks up
    // the new size rather than replaying whatever resolution the original
    // connect stored in `RdpConnectInfo`.
    apply_pane_resolution(state, &mut settings);
    let endpoint_identity = format!("{}@{}:{}", auth.username, settings.host, settings.port);
    let display_label = reconnect_display_label(state, tab_idx, endpoint_identity.clone());
    // Reconnect is an execute-scope action too -
    // an agent driving the ErrorOverlay's "Reconnect" button re-establishes a
    // live session with stored credentials, same as a fresh launch. See
    // `open_ssh_tab`'s identical comment for the gate's rationale/timing
    // proof. The old session is already shut down by this point (the caller,
    // `wire_reconnect`, does that before dispatching), so on a block the tab
    // just stays in the Failed state `fail_reconnect_in_place` leaves it in -
    // never a silent no-op.
    if agent_mode_execute_blocked(&state.borrow().agent_mode) {
        tracing::warn!(
            conn = %endpoint_identity,
            "agent mode: reconnect blocked while automation is active without execute scope"
        );
        fail_reconnect_in_place(
            state,
            tab_model,
            ui,
            tab_idx,
            "agent mode: execute scope not granted".to_string(),
        );
        return;
    }
    let auth_source = match provenance {
        AuthProvenance::Direct => RdpAuthSource::Direct(auth.clone()),
        AuthProvenance::Credential(id) => RdpAuthSource::Credential(id),
    };
    let provider = state.borrow().session_provider.clone();
    let Some(endpoint_id) = state.borrow_mut().allocate_endpoint_id() else {
        fail_reconnect_in_place(
            state,
            tab_model,
            ui,
            tab_idx,
            "Session identity space exhausted".to_owned(),
        );
        return;
    };
    match provider.connect_rdp(&settings, auth, verifier, endpoint_id) {
        Ok(new_session) => {
            let ci = RdpConnectInfo {
                settings,
                auth_source,
            };
            {
                let mut st = state.borrow_mut();
                if let Some(tab) = st.tabs.get_mut(tab_idx) {
                    tab.endpoint_id = endpoint_id;
                    tab.session = new_session;
                    tab.connect_info = Some(ConnectInfo::Rdp(ci));
                    tab.last_frame = None;
                    // #3: keep the cached identity/kind (select_tab
                    // re-pushes these on every switch) in step with a
                    // reconnect, same as the fresh-connect path.
                    tab.identity = display_label.clone();
                    tab.kind = "RDP".to_owned();
                    tab.insecure_transport = false;
                    // I2: this reconnect's own connecting -> connected
                    // transition needs its own start time, not the tab's
                    // original one (that would report a stale, way-too-long
                    // "perceived_ms" spanning the whole prior session).
                    tab.connect_started = std::time::Instant::now();
                }
            }
            if let Some(mut item) = tab_model.row_data(tab_idx) {
                item.status = SharedString::from("connecting");
                tab_model.set_row_data(tab_idx, item);
            }
            ui.set_session_identity(SharedString::from(display_label));
            ui.set_overlay_connecting(true);
            ui.set_overlay_error(false);
            ui.set_connecting_kind(SharedString::from("RDP"));
            ui.set_session_insecure(false);
            ui.set_rdp_active(true);
            //.99 GPU verify Bug B: `root.rdp-frame` is a single AppWindow-
            // level property (app.slint's RdpSurface reads `root.rdp-frame`
            // for whichever tab is active) - it is only ever WRITTEN when a
            // new `FrameUpdate` actually drains for the active tab
            // (`tick_tab`'s `Surface::Framebuffer` arm, below). Clearing
            // `tab.last_frame` above (the Rust-side model) does nothing to
            // that UI property on its own, so without this the OLD frame -
            // from the session that was just torn down - stays bound and
            // visible for however long the new handshake takes to deliver
            // its first decoded frame. `reconnect_rdp_tab` only ever
            // operates on the active tab (the ErrorOverlay's Reconnect
            // button is always for the tab it's showing on), so blanking
            // here, right when the reconnect is committed to, closes that
            // window immediately rather than waiting for the next tick.
            ui.set_rdp_frame(Image::default());
        }
        Err(e) => {
            tracing::warn!("RDP reconnect error: {e}");
            ui.set_error_reason(SharedString::from(e.to_string()));
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn reconnect_ssh_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    tab_idx: usize,
    settings: SshSettings,
    auth: SshAuthInput,
    provenance: AuthProvenance,
    verifier: Arc<dyn HostKeyVerifier>,
) {
    let size = state.borrow().current_grid();
    let terminal_options = TerminalOptions {
        max_scrollback: state.borrow().scrollback_limit,
    };
    let endpoint_identity = format!("{}@{}:{}", settings.username, settings.host, settings.port);
    let display_label = reconnect_display_label(state, tab_idx, endpoint_identity.clone());
    // See `reconnect_rdp_tab`'s identical
    // comment - Reconnect is an execute-scope action, gated the same way.
    if agent_mode_execute_blocked(&state.borrow().agent_mode) {
        tracing::warn!(
            conn = %endpoint_identity,
            "agent mode: reconnect blocked while automation is active without execute scope"
        );
        fail_reconnect_in_place(
            state,
            tab_model,
            ui,
            tab_idx,
            "agent mode: execute scope not granted".to_string(),
        );
        return;
    }
    let auth_source = match provenance {
        AuthProvenance::Direct => SshAuthSource::Direct(auth.clone()),
        AuthProvenance::Credential(id) => SshAuthSource::Credential(id),
    };
    let provider = state.borrow().session_provider.clone();
    match provider.connect_ssh(&settings, auth, verifier, size, terminal_options) {
        Ok(new_session) => {
            let ci = SshConnectInfo {
                settings,
                auth_source,
            };
            {
                let mut st = state.borrow_mut();
                if let Some(tab) = st.tabs.get_mut(tab_idx) {
                    tab.session = new_session;
                    tab.connect_info = Some(ConnectInfo::Ssh(ci));
                    tab.last = None;
                    // #3: see the RDP counterpart's identical comment
                    // (reconnect_rdp_tab, above).
                    tab.identity = display_label.clone();
                    tab.kind = "SSH".to_owned();
                    tab.insecure_transport = false;
                    // I2: see the RDP counterpart's identical comment
                    // (reconnect_rdp_tab, above).
                    tab.connect_started = std::time::Instant::now();
                }
            }
            if let Some(mut item) = tab_model.row_data(tab_idx) {
                item.status = SharedString::from("connecting");
                tab_model.set_row_data(tab_idx, item);
            }
            ui.set_session_identity(SharedString::from(display_label));
            ui.set_overlay_connecting(true);
            ui.set_overlay_error(false);
            ui.set_connecting_kind(SharedString::from("SSH"));
            ui.set_session_insecure(false);
            //.99 GPU verify Bug B: same stale-frame class as
            // `reconnect_rdp_tab`'s identical comment - `root.frame` is the
            // same kind of single AppWindow-level property (`render_frame`'s
            // output), only ever rewritten when a new `GridSnapshot` drains
            // for the active tab. Blank it here too so a terminal reconnect
            // can't briefly show the just-torn-down session's last screen.
            ui.set_frame(Image::default());
        }
        Err(e) => {
            tracing::warn!("SSH reconnect error: {e}");
            ui.set_error_reason(SharedString::from(e.to_string()));
        }
    }
}

pub(super) fn reconnect_telnet_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    tab_idx: usize,
    settings: TelnetSettings,
) {
    let size = state.borrow().current_grid();
    let terminal_options = TerminalOptions {
        max_scrollback: state.borrow().scrollback_limit,
    };
    let endpoint_identity = format!("{}:{}", settings.host, settings.port);
    let display_label = reconnect_display_label(state, tab_idx, endpoint_identity.clone());
    if agent_mode_execute_blocked(&state.borrow().agent_mode) {
        tracing::warn!(
            conn = %endpoint_identity,
            "agent mode: Telnet reconnect blocked while automation is active without execute scope"
        );
        fail_reconnect_in_place(
            state,
            tab_model,
            ui,
            tab_idx,
            "agent mode: execute scope not granted".to_owned(),
        );
        return;
    }

    let provider = state.borrow().session_provider.clone();
    match provider.connect_telnet(&settings, size, terminal_options) {
        Ok(new_session) => {
            {
                let mut st = state.borrow_mut();
                if let Some(tab) = st.tabs.get_mut(tab_idx) {
                    tab.session = new_session;
                    tab.connect_info = Some(ConnectInfo::Telnet(settings));
                    tab.last = None;
                    tab.identity = display_label.clone();
                    tab.kind = "TELNET".to_owned();
                    tab.insecure_transport = true;
                    tab.connect_started = std::time::Instant::now();
                }
            }
            if let Some(mut item) = tab_model.row_data(tab_idx) {
                item.status = SharedString::from("connecting");
                tab_model.set_row_data(tab_idx, item);
            }
            ui.set_session_identity(SharedString::from(display_label));
            ui.set_overlay_connecting(true);
            ui.set_overlay_error(false);
            ui.set_connecting_kind(SharedString::from("TELNET"));
            ui.set_session_insecure(true);
            ui.set_rdp_active(false);
            ui.set_frame(Image::default());
        }
        Err(e) => {
            tracing::warn!("Telnet reconnect error: {e}");
            fail_reconnect_in_place(state, tab_model, ui, tab_idx, e.to_string());
        }
    }
}

/// Drain and render one tab's surfaces (primary + extra panes), sync its
/// status dot / overlays / toast, and report whether it should be queued for
/// closing (local shell that has exited).
///
/// Extracted from [`tick`]'s per-tab loop body ( function-size budget) -
/// pure code move, identical logic, same field-by-field mutation of `st`. The
/// 9-parameter signature mirrors `tick`'s own (state access + the model/ui
/// handles it forwards); bundling them would be a needless intermediate type
/// for a single private call site.
#[allow(clippy::too_many_arguments)]
fn tick_tab(
    st: &mut State,
    i: usize,
    active: usize,
    target: Option<(u32, u32)>,
    conn_model: &Rc<VecModel<ConnRow>>,
    tab_model: &Rc<VecModel<TabItem>>,
    toast_model: &Rc<VecModel<ToastEntry>>,
    toast_next_id: &Rc<RefCell<i32>>,
    ui: &AppWindow,
) -> bool {
    // selection lifecycle, "clears on focus change": a pane-focus switch
    // (Ctrl+Shift+arrow, or clicking a different pane) invalidates every
    // pane's selection in this tab — cheap and simple, and correct since a
    // selection is only ever meaningful while its pane is the one receiving
    // input. Pointer focus changes clear synchronously in
    // `panes::wire_pane_focused` so the same gesture's new selection survives;
    // this tick check remains a defensive fallback for keyboard/programmatic
    // focus-changing call sites.
    let focused_now = st.tabs[i].pane_group.focused();
    if st.tabs[i].last_focused_pane != focused_now {
        st.tabs[i].sel.clear();
        for ep in &mut st.tabs[i].extra_panes {
            ep.sel.clear();
        }
        st.tabs[i].last_focused_pane = focused_now;
    }

    // whether anything this tab's currently-visible panes render
    // changed this tick — gates the (only-when-split) `pane-cells` rebuild
    // below so a single-pane tab (the common case) never pays for it.
    let mut panes_updated = false;

    // Poll the focused-pane search request every tick while it's open. A poll that
    // (re)computes matches has no snapshot of its own to ride along with, so
    // force a render + refresh the overlay's match-count UI now (same
    // "no new GridSnapshot, but the highlight changed" situation
    // `wire_pointer`'s `selection_changed` handles for mouse selection).
    if i == active && st.tabs[i].search.is_open() && st.tabs[i].search.poll() {
        search::refresh_search_ui_from(ui, st);
        if st.tabs[i].search.target_pane() == 0 {
            if let Some(snap) = st.tabs[i].last.clone() {
                let img = render_frame(&mut st.tabs[i], &snap, target);
                ui.set_frame(img);
            }
        } else {
            panes_updated = true;
        }
    }

    // Drain the latest update for this tab's primary surface.
    match st.tabs[i].session.surface() {
        Surface::TerminalGrid(rx) => {
            if let Some(snap) = drain_latest(rx) {
                // "Clears on new output that scrolls the region" (or a
                // resize) — see `PaneSelectionState::invalidate_if_stale`.
                st.tabs[i].sel.invalidate_if_stale(&snap);
                if i == active {
                    let img = render_frame(&mut st.tabs[i], &snap, target);
                    ui.set_frame(img);
                    publish_scroll_state(&st.tabs[i], ui);
                    panes_updated = true;
                }
                st.tabs[i].last = Some(snap);
            }
        }
        Surface::Framebuffer(rx) => {
            if let Some(frame) = drain_latest(rx) {
                let img = frame_to_image(&frame);
                if i == active {
                    ui.set_rdp_frame(img.clone());
                    panes_updated = true;
                }
                st.tabs[i].last_frame = Some(img);
                st.tabs[i].rdp_w = frame.width;
                st.tabs[i].rdp_h = frame.height;
            }
        }
    }

    // Drain extra pane surfaces (pane 1+;, generalized to N in).
    // (f): collect extra panes that have Exited/Failed for collapse.
    let mut extra_panes_to_close: Vec<usize> = Vec::new();
    for ep_idx in 0..st.tabs[i].extra_panes.len() {
        match st.tabs[i].extra_panes[ep_idx].session.surface() {
            Surface::TerminalGrid(rx) => {
                if let Some(snap) = drain_latest(rx) {
                    st.tabs[i].extra_panes[ep_idx]
                        .sel
                        .invalidate_if_stale(&snap);
                    st.tabs[i].extra_panes[ep_idx].last = Some(snap);
                    if i == active {
                        panes_updated = true;
                    }
                }
            }
            // RDP-in-pane (lifts 's deferral) — decode into this
            // pane's own `last_frame`/`rdp_w`/`rdp_h`, mirroring the primary
            // pane's `Surface::Framebuffer` arm above.
            Surface::Framebuffer(rx) => {
                if let Some(frame) = drain_latest(rx) {
                    let img = frame_to_image(&frame);
                    st.tabs[i].extra_panes[ep_idx].last_frame = Some(img);
                    st.tabs[i].extra_panes[ep_idx].rdp_w = frame.width;
                    st.tabs[i].extra_panes[ep_idx].rdp_h = frame.height;
                    if i == active {
                        panes_updated = true;
                    }
                }
            }
        }
        // Auto-collapse extra pane when its session exits/fails (fix f).
        // A split pane has no ErrorOverlay of its own, so surface an
        // asynchronous failure before removing the pane; otherwise the
        // reason disappears with the session in this same tick.
        let ep_status = st.tabs[i].extra_panes[ep_idx].session.status();
        match ep_status {
            SessionStatus::Failed(reason) => {
                let title = &st.tabs[i].extra_panes[ep_idx].title;
                let id = {
                    let mut n = toast_next_id.borrow_mut();
                    let id = *n;
                    *n += 1;
                    id
                };
                toast_model.push(ToastEntry {
                    id,
                    message: SharedString::from(format!("{title}: connection failed – {reason}")),
                    kind: 3,
                });
                extra_panes_to_close.push(ep_idx);
            }
            SessionStatus::Exited(_) => extra_panes_to_close.push(ep_idx),
            _ => {}
        }
    }
    // Collapse exited extra panes (process in reverse order to keep indices valid).
    for &ep_idx in extra_panes_to_close.iter().rev() {
        let ep = st.tabs[i].extra_panes.remove(ep_idx);
        ep.session.shutdown();
        // Close the corresponding pane slot in the group tracker.
        // pane index = ep_idx + 1 (extra_panes are panes 1+).
        // PaneGroup::close_focused requires us to focus the pane first.
        st.tabs[i].pane_group.set_focused(ep_idx + 1);
        st.tabs[i].pane_group.close_focused();
        panes_updated = true;
    }
    if i == active && panes_updated && st.tabs[i].pane_group.count() > 1 {
        panes::rebuild_pane_cells_for_state(st);
    }
    if !extra_panes_to_close.is_empty() {
        // Tab-strip badge update applies to ALL tabs whose pane count changed,
        // not only the active one (fix j: background tabs must sync their badge).
        if let Some(mut item) = tab_model.row_data(i) {
            let new_count = st.tabs[i].pane_group.count() as i32;
            if item.pane_count != new_count {
                item.pane_count = new_count;
                tab_model.set_row_data(i, item);
            }
        }
        if i == active {
            let new_layout = st.tabs[i].pane_group.layout();
            let new_focused = st.tabs[i].pane_group.focused();
            ui.set_pane_layout(panes::layout_to_int(new_layout));
            ui.set_active_pane(new_focused as i32);
            ui.set_session_insecure(
                st.tabs[i].insecure_transport
                    || st.tabs[i]
                        .extra_panes
                        .iter()
                        .any(|ep| ep.insecure_transport),
            );
        }
    }

    let status = st.tabs[i].session.status();
    let dot = match &status {
        SessionStatus::Connecting => "connecting",
        SessionStatus::Connected => "connected",
        SessionStatus::Failed(_) => "error",
        SessionStatus::Disconnected | SessionStatus::Exited(_) => "disconnected",
    };
    if let Some(mut item) = tab_model.row_data(i)
        && item.status.as_str() != dot
    {
        // I2: the user-perceived connect duration - only the
        // connecting -> connected edge (never local shells, which start
        // "connected" and so never see this transition; never a plain
        // reconnect-retry-loop edge, since those all still pass through
        // exactly one "connecting" -> "connected" pair here too).
        if item.status.as_str() == "connecting" && dot == "connected" {
            tracing::info!(
                title = %item.title,
                kind = %st.tabs[i].kind,
                perceived_ms = st.tabs[i].connect_started.elapsed().as_millis(),
                "connection established (user-perceived)"
            );
        }
        // emit a toast when a background tab disconnects/fails.
        if i != active
            && st.tabs[i].is_remote
            && matches!(
                status,
                SessionStatus::Disconnected | SessionStatus::Failed(_)
            )
        {
            let msg = match &status {
                SessionStatus::Failed(r) => {
                    format!("{}: connection failed – {r}", item.title.as_str())
                }
                _ => format!("{}: disconnected", item.title.as_str()),
            };
            let kind: i32 = if matches!(status, SessionStatus::Failed(_)) {
                3
            } else {
                2
            };
            let id = {
                let mut n = toast_next_id.borrow_mut();
                let id = *n;
                *n += 1;
                id
            };
            toast_model.push(ToastEntry {
                id,
                message: SharedString::from(msg),
                kind,
            });
        }
        item.status = SharedString::from(dot);
        tab_model.set_row_data(i, item);

        // #4: refresh the connection tree's live-status overlay right
        // where a tab's own status transition is ALREADY detected (this
        // `if`'s whole condition), rather than adding a new unconditional
        // per-tick poll - a tab with no `origin_connection_id` (a local
        // shell, or a quick-connect with nothing stored to point back to)
        // has no tree row to update, so skip the (otherwise harmless but
        // pointless) whole-tree walk for those.
        if st.tabs[i].origin_connection_id.is_some() {
            tree_ctl::refresh_conn_model(st, conn_model);
        }
    }

    if i == active {
        overlays::update_overlays_from_status(ui, &st.tabs[i], &status);
    }

    !st.tabs[i].is_remote && matches!(status, SessionStatus::Exited(_))
}

fn focused_rdp_owner(st: &State) -> Option<cm_core::SessionEndpointId> {
    let tab = st.tabs.get(st.active)?;
    let focused = tab.pane_group.focused();
    if focused == 0 {
        matches!(tab.session.surface(), Surface::Framebuffer(_)).then_some(tab.endpoint_id)
    } else {
        let pane = tab.extra_panes.get(focused - 1)?;
        matches!(pane.session.surface(), Surface::Framebuffer(_)).then_some(pane.endpoint_id)
    }
}

fn focused_pane_is_terminal(st: &State) -> bool {
    let Some(tab) = st.tabs.get(st.active) else {
        return false;
    };
    let focused = tab.pane_group.focused();
    if focused == 0 {
        matches!(tab.session.surface(), Surface::TerminalGrid(_))
    } else {
        tab.extra_panes
            .get(focused - 1)
            .is_some_and(|pane| matches!(pane.session.surface(), Surface::TerminalGrid(_)))
    }
}

fn focused_pane_has_selection(st: &State) -> bool {
    let Some(tab) = st.tabs.get(st.active) else {
        return false;
    };
    let focused = tab.pane_group.focused();
    if focused == 0 {
        tab.sel.selection().is_some()
    } else {
        tab.extra_panes
            .get(focused - 1)
            .is_some_and(|pane| pane.sel.selection().is_some())
    }
}

/// Resolve a completed terminal copy by stable endpoint, then clear only the
/// selection generation captured by that request. Returns whether a visible
/// selection changed and therefore needs a fresh render.
fn clear_terminal_selection_if_generation(
    st: &mut State,
    target: cm_core::SessionEndpointId,
    selection_generation: u64,
) -> bool {
    for tab in &mut st.tabs {
        if tab.endpoint_id == target {
            return tab.sel.clear_if_generation(selection_generation);
        }
        if let Some(pane) = tab
            .extra_panes
            .iter_mut()
            .find(|pane| pane.endpoint_id == target)
        {
            return pane.sel.clear_if_generation(selection_generation);
        }
    }
    false
}

fn send_to_endpoint(st: &State, endpoint: cm_core::SessionEndpointId, input: SessionInput) -> bool {
    for tab in &st.tabs {
        if tab.endpoint_id == endpoint {
            tab.session.send_input(input);
            return true;
        }
        for pane in &tab.extra_panes {
            if pane.endpoint_id == endpoint {
                pane.session.send_input(input);
                return true;
            }
        }
    }
    for detached in &st.detached {
        if detached.endpoint_id == endpoint {
            detached.session.send_input(input);
            return true;
        }
    }
    false
}

fn collect_rdp_clipboard_events(
    st: &State,
) -> Vec<(cm_core::SessionEndpointId, cm_core::RdpClipboardEvent)> {
    let mut events = Vec::new();
    for tab in &st.tabs {
        events.extend(
            tab.session
                .drain_rdp_clipboard_events()
                .into_iter()
                .map(|event| (tab.endpoint_id, event)),
        );
        for pane in &tab.extra_panes {
            events.extend(
                pane.session
                    .drain_rdp_clipboard_events()
                    .into_iter()
                    .map(|event| (pane.endpoint_id, event)),
            );
        }
    }
    for detached in &st.detached {
        events.extend(
            detached
                .session
                .drain_rdp_clipboard_events()
                .into_iter()
                .map(|event| (detached.endpoint_id, event)),
        );
    }
    events
}

pub(super) fn handle_replaced_clipboard_write(
    st: &mut State,
    request: &crate::clipboard::ClipboardWriteRequest,
) {
    if let crate::clipboard::ClipboardWritePurpose::RdpInstall { owner, revision } = request.purpose
        && let Some(pending) = st.clipboard_pending_remote.remove(&(owner, revision))
        && let Some(path) = pending.staging_root
    {
        cleanup_staging_path(st, &path);
    }
}

fn cleanup_staging_path(st: &State, path: &std::path::Path) {
    if let Some(root) = st.secure_clipboard_root.as_ref()
        && let Err(error) = root.cleanup_staging_path(path)
    {
        tracing::debug!(reason = ?error, "clipboard staging cleanup rejected");
    }
}

fn update_installed_file_lease(
    lease: &mut Option<(cm_core::ClipboardSnapshot, std::path::PathBuf)>,
    installed: cm_core::ClipboardSnapshot,
    new_staging: Option<std::path::PathBuf>,
) -> Vec<std::path::PathBuf> {
    let mut cleanup = Vec::new();
    if lease
        .as_ref()
        .is_some_and(|(snapshot, _)| *snapshot != installed)
        && let Some((_, old_path)) = lease.take()
    {
        cleanup.push(old_path);
    }
    if let Some(path) = new_staging
        && let Some((_, old_path)) = lease.replace((installed, path.clone()))
        && old_path != path
    {
        cleanup.push(old_path);
    }
    cleanup
}

fn observation_needs_publication(
    origin: Option<&(
        cm_core::SessionEndpointId,
        cm_core::RemoteClipboardRevision,
        cm_core::ClipboardSnapshot,
    )>,
    owner: cm_core::SessionEndpointId,
    snapshot: &cm_core::ClipboardSnapshot,
) -> bool {
    !origin.is_some_and(|(origin_owner, _, origin_snapshot)| {
        *origin_owner == owner && origin_snapshot == snapshot
    })
}

fn cleanup_unused_source_leases(st: &mut State) {
    let paths = st
        .clipboard_source_leases
        .iter()
        .filter_map(|(path, lease)| lease.cleanup_ready().then_some(path.clone()))
        .collect::<Vec<_>>();
    for path in paths {
        st.clipboard_source_leases.remove(&path);
        cleanup_staging_path(st, &path);
    }
}

fn mark_source_unobserved(st: &mut State) {
    if let Some(path) = st.clipboard_observed_source.take()
        && let Some(lease) = st.clipboard_source_leases.get_mut(&path)
    {
        lease.still_observed = false;
    }
    cleanup_unused_source_leases(st);
}

fn observe_source_staging(
    st: &mut State,
    snapshot: &cm_core::ClipboardSnapshot,
    source_root: Option<std::path::PathBuf>,
) {
    if st.clipboard_observed_source != source_root {
        mark_source_unobserved(st);
    }
    let Some(path) = source_root else {
        return;
    };
    let lease = st
        .clipboard_source_leases
        .entry(path.clone())
        .or_insert_with(|| ClipboardSourceLease {
            snapshot: snapshot.clone(),
            still_observed: true,
            users: BTreeSet::new(),
        });
    lease.snapshot = snapshot.clone();
    lease.still_observed = true;
    st.clipboard_observed_source = Some(path);
}

fn retire_source_staging(st: &mut State, path: &std::path::Path) {
    if st.clipboard_observed_source.as_deref() == Some(path) {
        st.clipboard_observed_source = None;
    }
    if let Some(lease) = st.clipboard_source_leases.get_mut(path) {
        lease.still_observed = false;
        cleanup_unused_source_leases(st);
    } else {
        cleanup_staging_path(st, path);
    }
}

fn retain_source_for_publication(
    st: &mut State,
    endpoint: cm_core::SessionEndpointId,
    revision: cm_core::LocalClipboardRevision,
    snapshot: &cm_core::ClipboardSnapshot,
) {
    if let Some(path) = st.clipboard_observed_source.as_ref()
        && let Some(lease) = st.clipboard_source_leases.get_mut(path)
        && lease.still_observed
        && lease.snapshot == *snapshot
    {
        lease.retain(endpoint, revision);
    }
}

fn release_source_publication(
    st: &mut State,
    endpoint: cm_core::SessionEndpointId,
    revision: cm_core::LocalClipboardRevision,
) {
    for lease in st.clipboard_source_leases.values_mut() {
        lease.release(endpoint, revision);
    }
    cleanup_unused_source_leases(st);
}

fn release_source_endpoint(st: &mut State, endpoint: cm_core::SessionEndpointId) {
    for lease in st.clipboard_source_leases.values_mut() {
        lease.users.retain(|(user, _)| *user != endpoint);
    }
    cleanup_unused_source_leases(st);
}

fn allocate_local_clipboard_revision(next: &mut u64) -> Option<cm_core::LocalClipboardRevision> {
    let revision = cm_core::LocalClipboardRevision(*next);
    *next = next.checked_add(1)?;
    Some(revision)
}

fn begin_terminal_clipboard_disable(
    disabled: &mut bool,
    owner: &mut Option<cm_core::SessionEndpointId>,
) -> Option<cm_core::SessionEndpointId> {
    *disabled = true;
    owner.take()
}

fn focused_clipboard_owner(
    disabled: bool,
    focused: Option<cm_core::SessionEndpointId>,
) -> Option<cm_core::SessionEndpointId> {
    if disabled { None } else { focused }
}

fn disable_clipboard_bridge(st: &mut State) {
    let old_owner = begin_terminal_clipboard_disable(
        &mut st.clipboard_bridge_disabled,
        &mut st.clipboard_owner,
    );
    if let Some(old_owner) = old_owner {
        let _ = send_to_endpoint(
            st,
            old_owner,
            SessionInput::RdpClipboard(cm_core::RdpClipboardCommand::SetActive(false)),
        );
    }
    st.sys_clipboard.set_rdp_demand(None);

    // No acknowledgement can make a publication usable after the bridge has
    // failed closed. Retire every source user now so a late result cannot
    // retain staging indefinitely.
    st.clipboard_endpoint_sync.clear();
    st.clipboard_observed_source = None;
    for lease in st.clipboard_source_leases.values_mut() {
        lease.still_observed = false;
        lease.users.clear();
    }
    cleanup_unused_source_leases(st);
    st.clipboard_remote_origin = None;

    // Do not eagerly remove `clipboard_pending_remote`: a platform write may
    // already be executing. Its bounded result path remains responsible for
    // adopting or cleaning that staging root without racing the OS call.
}

fn publish_local_clipboard(
    st: &mut State,
    owner: cm_core::SessionEndpointId,
    snapshot: cm_core::ClipboardSnapshot,
) {
    if st.clipboard_bridge_disabled {
        return;
    }
    let Some(revision) = allocate_local_clipboard_revision(&mut st.next_local_clipboard_revision)
    else {
        disable_clipboard_bridge(st);
        return;
    };
    retain_source_for_publication(st, owner, revision, &snapshot);
    let sync = st.clipboard_endpoint_sync.entry(owner).or_default();
    if sync.inflight.is_some() {
        if let Some((replaced, _)) = sync.latest_pending.replace((revision, snapshot)) {
            release_source_publication(st, owner, replaced);
        }
        return;
    }
    if send_to_endpoint(
        st,
        owner,
        SessionInput::RdpClipboard(cm_core::RdpClipboardCommand::PublishLocal {
            revision,
            snapshot,
        }),
    ) {
        st.clipboard_endpoint_sync
            .entry(owner)
            .or_default()
            .inflight = Some(revision);
    } else {
        st.clipboard_endpoint_sync.remove(&owner);
        release_source_publication(st, owner, revision);
    }
}

fn complete_local_advertisement(
    st: &mut State,
    endpoint: cm_core::SessionEndpointId,
    revision: cm_core::LocalClipboardRevision,
) {
    let pending = {
        let Some(sync) = st.clipboard_endpoint_sync.get_mut(&endpoint) else {
            return;
        };
        if sync.inflight != Some(revision) {
            return;
        }
        sync.inflight = None;
        sync.latest_pending.take()
    };
    release_source_publication(st, endpoint, revision);
    if let Some((next_revision, snapshot)) = pending {
        if send_to_endpoint(
            st,
            endpoint,
            SessionInput::RdpClipboard(cm_core::RdpClipboardCommand::PublishLocal {
                revision: next_revision,
                snapshot,
            }),
        ) {
            st.clipboard_endpoint_sync
                .entry(endpoint)
                .or_default()
                .inflight = Some(next_revision);
        } else {
            st.clipboard_endpoint_sync.remove(&endpoint);
            release_source_publication(st, endpoint, next_revision);
        }
    }
}

/// Pump clipboard work and report whether a terminal selection was cleared by
/// a successful copy completion. The caller uses the signal to repaint even
/// when no new terminal grid snapshot arrived in this tick.
fn tick_clipboard(st: &mut State) -> bool {
    let mut terminal_selection_cleared = false;
    let live_endpoints = st
        .tabs
        .iter()
        .flat_map(|tab| {
            std::iter::once(tab.endpoint_id)
                .chain(tab.extra_panes.iter().map(|pane| pane.endpoint_id))
        })
        .chain(st.detached.iter().map(|entry| entry.endpoint_id))
        .collect::<std::collections::BTreeSet<_>>();
    let stale_sync = st
        .clipboard_endpoint_sync
        .keys()
        .filter(|endpoint| !live_endpoints.contains(endpoint))
        .copied()
        .collect::<Vec<_>>();
    for endpoint in stale_sync {
        st.clipboard_endpoint_sync.remove(&endpoint);
        release_source_endpoint(st, endpoint);
    }
    let stale_installs = st
        .clipboard_pending_remote
        .keys()
        .filter(|(endpoint, _)| !live_endpoints.contains(endpoint))
        .copied()
        .collect::<Vec<_>>();
    for key in stale_installs {
        if let Some(pending) = st.clipboard_pending_remote.remove(&key)
            && let Some(path) = pending.staging_root
        {
            cleanup_staging_path(st, &path);
        }
    }
    if st.clipboard_bridge_disabled {
        disable_clipboard_bridge(st);
    }
    let owner = focused_clipboard_owner(st.clipboard_bridge_disabled, focused_rdp_owner(st));
    if owner != st.clipboard_owner {
        if let Some(old) = st.clipboard_owner.take() {
            let _ = send_to_endpoint(
                st,
                old,
                SessionInput::RdpClipboard(cm_core::RdpClipboardCommand::SetActive(false)),
            );
        }
        let Some(generation) = st.clipboard_demand_generation.checked_add(1) else {
            disable_clipboard_bridge(st);
            return terminal_selection_cleared;
        };
        st.clipboard_owner = owner;
        st.clipboard_demand_generation = generation;
        if let Some(new_owner) = owner {
            let _ = send_to_endpoint(
                st,
                new_owner,
                SessionInput::RdpClipboard(cm_core::RdpClipboardCommand::SetActive(true)),
            );
            st.sys_clipboard
                .set_rdp_demand(Some(st.clipboard_demand_generation));
        } else {
            st.sys_clipboard.set_rdp_demand(None);
            mark_source_unobserved(st);
        }
    }

    let events = collect_rdp_clipboard_events(st);
    for (endpoint, event) in events {
        match event {
            cm_core::RdpClipboardEvent::RemoteContent { revision, content }
                if Some(endpoint) == st.clipboard_owner =>
            {
                let (write, snapshot, staging_root) = match content {
                    cm_core::RemoteClipboardContent::Text(text) => {
                        let snapshot = cm_core::ClipboardSnapshot::Text(text.clone());
                        (crate::clipboard::ClipboardWrite::Text(text), snapshot, None)
                    }
                    cm_core::RemoteClipboardContent::Files {
                        staging_root,
                        paths,
                    } => {
                        let snapshot = cm_core::ClipboardSnapshot::Files(paths.clone());
                        (
                            crate::clipboard::ClipboardWrite::Files(paths),
                            snapshot,
                            Some(staging_root),
                        )
                    }
                };
                st.clipboard_pending_remote.insert(
                    (endpoint, revision),
                    PendingRemoteInstall {
                        snapshot,
                        staging_root,
                    },
                );
                let replaced = st.sys_clipboard.submit_write(
                    crate::clipboard::ClipboardWritePurpose::RdpInstall {
                        owner: endpoint,
                        revision,
                    },
                    write,
                );
                if let Some(replaced) = replaced {
                    handle_replaced_clipboard_write(st, &replaced);
                }
            }
            cm_core::RdpClipboardEvent::RemoteContent {
                content: cm_core::RemoteClipboardContent::Files { staging_root, .. },
                ..
            } => cleanup_staging_path(st, &staging_root),
            cm_core::RdpClipboardEvent::RemoteContent { .. } => {}
            cm_core::RdpClipboardEvent::LocalAdvertiseResult { revision, .. } => {
                complete_local_advertisement(st, endpoint, revision);
            }
        }
    }

    let results = st.sys_clipboard.drain_results();
    for path in results.retired_source_roots {
        retire_source_staging(st, &path);
    }
    for result in results.terminal_reads {
        tracing::trace!(
            request_id = result.request_id,
            "terminal clipboard read completed"
        );
        if let Ok(Some(text)) = result.text
            && !text.is_empty()
        {
            let _ = send_to_endpoint(st, result.target, SessionInput::Paste(text.into_bytes()));
        }
    }
    for result in results.write_results {
        tracing::trace!(request_id = result.request_id, purpose = ?result.purpose, "clipboard write completed");
        if let crate::clipboard::ClipboardWriteOutcome::Failed(reason) = result.outcome {
            tracing::debug!(
                request_id = result.request_id,
                ?reason,
                "clipboard write failed"
            );
        }
        match result.purpose {
            crate::clipboard::ClipboardWritePurpose::RdpInstall { owner, revision } => {
                if let Some(pending) = st.clipboard_pending_remote.remove(&(owner, revision)) {
                    if result.outcome == crate::clipboard::ClipboardWriteOutcome::Written {
                        if st.clipboard_bridge_disabled {
                            st.clipboard_remote_origin = None;
                        } else {
                            st.clipboard_remote_origin =
                                Some((owner, revision, pending.snapshot.clone()));
                        }
                        let cleanup = update_installed_file_lease(
                            &mut st.clipboard_staged_lease,
                            pending.snapshot,
                            pending.staging_root,
                        );
                        for path in cleanup {
                            cleanup_staging_path(st, &path);
                        }
                    } else if let Some(path) = pending.staging_root {
                        cleanup_staging_path(st, &path);
                    }
                }
            }
            crate::clipboard::ClipboardWritePurpose::TerminalSelectionCopy {
                target,
                selection_generation,
            } if result.outcome == crate::clipboard::ClipboardWriteOutcome::Written => {
                terminal_selection_cleared |=
                    clear_terminal_selection_if_generation(st, target, selection_generation);
                st.clipboard_remote_origin = None;
                if let Some((_, path)) = st.clipboard_staged_lease.take() {
                    cleanup_staging_path(st, &path);
                }
            }
            crate::clipboard::ClipboardWritePurpose::TerminalSelectionCopy { .. } => {}
            crate::clipboard::ClipboardWritePurpose::UiTextCopy
                if result.outcome == crate::clipboard::ClipboardWriteOutcome::Written =>
            {
                st.clipboard_remote_origin = None;
                if let Some((_, path)) = st.clipboard_staged_lease.take() {
                    cleanup_staging_path(st, &path);
                }
            }
            crate::clipboard::ClipboardWritePurpose::UiTextCopy => {}
        }
    }
    if let Some(observation) = results.observation {
        let Some(owner) = st.clipboard_owner else {
            if let Some(path) = observation.source_staging_root {
                cleanup_staging_path(st, &path);
            }
            return terminal_selection_cleared;
        };
        if observation.demand_generation != st.clipboard_demand_generation {
            if let Some(path) = observation.source_staging_root {
                cleanup_staging_path(st, &path);
            }
            return terminal_selection_cleared;
        }
        tracing::trace!(
            sequence = observation.sequence,
            "host clipboard revision observed"
        );
        observe_source_staging(st, &observation.snapshot, observation.source_staging_root);
        if st
            .clipboard_staged_lease
            .as_ref()
            .is_some_and(|(snapshot, _)| *snapshot != observation.snapshot)
            && let Some((_, path)) = st.clipboard_staged_lease.take()
        {
            cleanup_staging_path(st, &path);
        }
        if observation_needs_publication(
            st.clipboard_remote_origin.as_ref(),
            owner,
            &observation.snapshot,
        ) {
            if st
                .clipboard_remote_origin
                .as_ref()
                .is_none_or(|(_, _, snapshot)| *snapshot != observation.snapshot)
            {
                st.clipboard_remote_origin = None;
            }
            publish_local_clipboard(st, owner, observation.snapshot);
        }
    }
    terminal_selection_cleared
}

pub(super) fn tick(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    conn_model: &Rc<VecModel<ConnRow>>,
    toast_model: &Rc<VecModel<ToastEntry>>,
    toast_next_id: &Rc<RefCell<i32>>,
    ui: &AppWindow,
) {
    let mut st = state.borrow_mut();
    let active = st.active;
    poll_terminal_buffer_copies(&mut st);
    let terminal_selection_cleared = tick_clipboard(&mut st);
    let target = st.target_px();
    let mut to_close: Vec<usize> = Vec::new();

    // selection lifecycle, "clears on focus change": a tab switch
    // invalidates the selection of both the tab losing view and the one
    // gaining it (a leftover highlight on the outgoing tab would look like a
    // stale/incorrect selection if the user switches back). Detected
    // reactively here (up to one ~16ms tick of latency, imperceptible)
    // instead of at every `select_tab`/`row-activated` call site, so tab
    // switching stays entirely out of this lane's touched files.
    if st.last_active_tab != active {
        let old = st.last_active_tab;
        if let Some(tab) = st.tabs.get_mut(old) {
            tab.sel.clear();
            for ep in &mut tab.extra_panes {
                ep.sel.clear();
            }
        }
        if let Some(tab) = st.tabs.get_mut(active) {
            tab.sel.clear();
            for ep in &mut tab.extra_panes {
                ep.sel.clear();
            }
        }
        // the search overlay is a single global `terminal-search-open`
        // property tied conceptually to the active tab's primary pane — a
        // tab switch closes it rather than leaving it open over unrelated
        // content (the per-tab `SearchState` itself, including its last
        // query, is preserved so reopening it later on that tab resumes).
        if ui.get_terminal_search_open() {
            ui.set_terminal_search_open(false);
            if let Some(tab) = st.tabs.get_mut(old) {
                tab.search.close();
            }
        }
        st.last_active_tab = active;
    }

    for i in 0..st.tabs.len() {
        if tick_tab(
            &mut st,
            i,
            active,
            target,
            conn_model,
            tab_model,
            toast_model,
            toast_next_id,
            ui,
        ) {
            to_close.push(i);
        }
    }
    if terminal_selection_cleared {
        render_active(&mut st, ui);
    }

    // Drain detached sessions to prevent channel saturation.
    let mut detached_to_remove: Vec<usize> = Vec::new();
    for (di, d) in st.detached.iter().enumerate() {
        match d.session.surface() {
            Surface::TerminalGrid(rx) => {
                drain_latest(rx); // discard
            }
            Surface::Framebuffer(rx) => {
                drain_latest(rx); // discard
            }
        }
        if matches!(
            d.session.status(),
            SessionStatus::Exited(_) | SessionStatus::Failed(_)
        ) {
            detached_to_remove.push(di);
        }
    }
    for &di in detached_to_remove.iter().rev() {
        let d = st.detached.remove(di);
        d.session.shutdown();
    }
    if !detached_to_remove.is_empty() {
        ui.set_detached_count(st.detached.len() as i32);
    }

    for &i in to_close.iter().rev() {
        let tab = st.tabs.remove(i);
        tab.session.shutdown();
        for ep in tab.extra_panes {
            ep.session.shutdown();
        }
        tab_model.remove(i);
        if i <= st.active && st.active > 0 {
            st.active -= 1;
        }
    }
    if !to_close.is_empty() {
        if st.tabs.is_empty() {
            drop(st);
            let _ = slint::quit_event_loop();
            return;
        }
        if st.active >= st.tabs.len() {
            st.active = st.tabs.len() - 1;
        }
        let active = st.active;
        ui.set_active_tab(active as i32);
        let status = st.tabs[active].session.status();
        overlays::update_overlays_from_status(ui, &st.tabs[active], &status);
        render_active(&mut st, ui);
    }
}

/// Re-push the application terminal palette to every open renderer (primary and
/// extra panes across all tabs). The palette is currently fixed dark and is
/// deliberately independent of the surrounding application-shell theme.
///
/// Every renderer's `theme` field is updated so a *background* tab picks up the
/// right palette the next time it renders (tab switch, new output); only the
/// currently visible pane(s) need (and get) an immediate re-render here.
pub(super) fn apply_terminal_theme_to_all(state: &Rc<RefCell<State>>, ui: &AppWindow) {
    let theme = util::terminal_theme_for(ui);
    let mut st = state.borrow_mut();
    for tab in &mut st.tabs {
        tab.renderer.set_theme(theme.clone());
        for ep in &mut tab.extra_panes {
            ep.renderer.set_theme(theme.clone());
        }
    }
    render_active(&mut st, ui);
}

pub(super) fn render_active(st: &mut State, ui: &AppWindow) {
    let active = st.active;
    let target = st.target_px();
    if let Some(tab) = st.tabs.get_mut(active) {
        match &tab.session.surface() {
            Surface::TerminalGrid(_) => {
                //.99 GPU verify Bug B: `root.frame`/`root.rdp-frame` are
                // single AppWindow-level properties shared by whatever tab
                // is active (app.slint's TerminalSurface/RdpSurface both
                // read `root.frame`/`root.rdp-frame`, never a per-tab
                // value) - they only get overwritten when a snapshot/frame
                // actually exists to render. Skipping the setter entirely
                // when there isn't one yet (a brand-new tab, or one whose
                // `last`/`last_frame` a reconnect just cleared) used to
                // leave whatever the PREVIOUSLY active tab last rendered
                // still bound - the "another tab's content bleeds through"
                // half of the bug report. Always write it, falling back to
                // a blank `Image` (same convention `panes.rs` already uses
                // via `unwrap_or_default` for a pane with no frame yet).
                let img = match tab.last.clone() {
                    Some(snap) => render_frame(tab, &snap, target),
                    None => Image::default(),
                };
                ui.set_frame(img);
                ui.set_rdp_active(false);
                publish_scroll_state(tab, ui);
            }
            Surface::Framebuffer(_) => {
                ui.set_rdp_frame(tab.last_frame.clone().unwrap_or_default());
                ui.set_rdp_active(true);
                // RDP has no scrollback viewport — hide the terminal overlay.
                ui.set_term_scrollback_len(0);
                ui.set_term_scroll_offset(0);
                ui.set_term_view_rows(0);
            }
        }
    }
    // N-way pane repeater — rebuilds `pane-cells` (geometry + every
    // pane's current frame) when the active tab has more than one pane; a
    // no-op (clears the model) otherwise, so single-pane tabs never pay for
    // this beyond the `count` check.
    panes::rebuild_pane_cells_for_state(st);
}

pub(super) fn render_frame_ep(
    ep: &mut ExtraPaneState,
    snap: &GridSnapshot,
    target: Option<(u32, u32)>,
    matches: &[crate::terminal_renderer::SearchMatch],
    current: Option<usize>,
) -> Image {
    let sel = ep.sel.selection().copied();
    let buf = match target {
        Some((w, h)) => ep
            .renderer
            .render_to_full(snap, w, h, sel.as_ref(), matches, current),
        None => {
            let (w, h) = ep.renderer.pixel_size(snap.size);
            ep.renderer
                .render_to_full(snap, w, h, sel.as_ref(), matches, current)
        }
    };
    Image::from_rgba8(buf)
}

pub(super) fn frame_to_image(frame: &FrameUpdate) -> Image {
    use slint::Rgba8Pixel;
    let mut buf =
        slint::SharedPixelBuffer::<Rgba8Pixel>::new(frame.width as u32, frame.height as u32);
    let bytes = buf.make_mut_bytes();
    let copy_len = bytes.len().min(frame.rgba.len());
    bytes[..copy_len].copy_from_slice(&frame.rgba[..copy_len]);
    // The RDP desktop framebuffer is always opaque (ironrdp's own
    // `DecodedImage` treats it that way - see upstream ironrdp-session's
    // image.rs comment "Framebuffer is always opaque, so we can skip alpha
    // channel change"), but several of its fast-path bitmap/tile decoders
    // (raw 32bpp updates, RemoteFX tile copies) blit source bytes verbatim
    // and leave the 4th (alpha) byte at whatever the wire padding contained
    // typically `0x00`. Slint's software renderer blits full-frame
    // `Image`s without honoring per-pixel alpha, so a zero alpha channel was
    // invisible there; the femtovg (GPU-accelerated) backend performs real
    // alpha blending and renders an all-zero-alpha frame as fully
    // transparent - i.e. a black screen showing the pane's dark background
    // through it. Force full opacity here so the frame composites
    // identically on every rendering backend.
    for px in bytes.chunks_exact_mut(4) {
        px[3] = 0xff;
    }
    Image::from_rgba8(buf)
}

pub(super) fn wire_tick(ctx: &Ctx) -> Timer {
    let redraw = Timer::default();
    let state = ctx.state.clone();
    let tab_model = ctx.tab_model.clone();
    let conn_model = ctx.conn_model.clone();
    let toast_model = ctx.toast_model.clone();
    let toast_next_id = ctx.toast_next_id.clone();
    let weak = ctx.ui.as_weak();
    redraw.start(TimerMode::Repeated, REDRAW_INTERVAL, move || {
        if let Some(ui) = weak.upgrade() {
            tick(
                &state,
                &tab_model,
                &conn_model,
                &toast_model,
                &toast_next_id,
                &ui,
            );
        }
    });
    redraw
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::mpsc;

    use cm_core::{
        Cell, CellAttrs, Color, ConnectionId, ConnectionKind, Credential, CredentialError,
        CredentialId, CredentialKind, CredentialRef, CursorShape, CursorState, GroupId,
    };

    #[test]
    fn drain_latest_keeps_only_the_last() {
        let (tx, rx) = mpsc::channel::<i32>();
        assert_eq!(drain_latest(&rx), None);
        tx.send(1).unwrap();
        tx.send(2).unwrap();
        tx.send(3).unwrap();
        assert_eq!(drain_latest(&rx), Some(3));
        assert_eq!(drain_latest(&rx), None);
    }

    fn scrub_snap(scrollback_len: u32, scroll_offset: u32, rows: u16) -> GridSnapshot {
        GridSnapshot {
            size: cm_core::TerminalSize { rows, cols: 80 },
            cells: Vec::new(),
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

    #[test]
    fn scrub_fraction_maps_ends_to_top_and_tail() {
        // 100 lines of scrollback, 20-row viewport: fraction 0 shows the
        // oldest line (offset == len), fraction 1 the live tail (offset 0).
        let snap = scrub_snap(100, 0, 20);
        assert_eq!(fraction_to_offset(&snap, 0.0), 100);
        assert_eq!(fraction_to_offset(&snap, 1.0), 0);
    }

    #[test]
    fn scrub_fraction_midpoint_rounds_to_middle() {
        let snap = scrub_snap(100, 0, 20);
        // Travel is over scrollback_len (100), not total: 0.5 -> 100*(1-0.5)
        // = offset 50 (the middle of the scrollback), matching the thumb.
        assert_eq!(fraction_to_offset(&snap, 0.5), 50);
    }

    #[test]
    fn scrub_fraction_clamps_out_of_range() {
        let snap = scrub_snap(100, 0, 20);
        assert_eq!(fraction_to_offset(&snap, -0.5), 100);
        assert_eq!(fraction_to_offset(&snap, 1.5), 0);
    }

    #[test]
    fn scrub_fraction_empty_buffer_is_tail() {
        let snap = scrub_snap(0, 0, 0);
        assert_eq!(fraction_to_offset(&snap, 0.5), 0);
        let no_scrollback = scrub_snap(0, 0, 24);
        assert_eq!(fraction_to_offset(&no_scrollback, 0.0), 0);
        assert_eq!(fraction_to_offset(&no_scrollback, 1.0), 0);
    }

    #[test]
    fn visible_copy_trims_row_padding_and_blank_tail() {
        let size = cm_core::TerminalSize { rows: 3, cols: 4 };
        let graphemes = ["a", "b", " ", " ", "c", " ", " ", " ", " ", " ", " ", " "];
        let snapshot = GridSnapshot {
            size,
            cells: graphemes
                .into_iter()
                .map(|grapheme| Cell {
                    grapheme: grapheme.to_owned(),
                    fg: Color::Default,
                    bg: Color::Default,
                    attrs: CellAttrs::empty(),
                    width: 1,
                })
                .collect(),
            cursor: CursorState {
                row: 0,
                col: 0,
                visible: false,
                shape: CursorShape::Block,
            },
            scrollback_len: 0,
            scroll_offset: 0,
            mouse_tracking: false,
        };
        assert_eq!(snapshot_text(&snapshot), "ab\nc");
    }

    #[test]
    fn whole_buffer_copy_preserves_internal_blank_lines_only() {
        assert_eq!(
            buffer_lines_text(vec![
                "first  ".to_owned(),
                String::new(),
                "last ".to_owned(),
                "   ".to_owned(),
            ]),
            "first\n\nlast"
        );
    }

    // ── RDP black screen on the femtovg backend ─────────
    // ironrdp's fast-path bitmap/tile decoders copy raw source bytes for the
    // RGB channels but leave the alpha byte at whatever the wire padding
    // held (typically 0x00) - the software renderer blits full-frame
    // `Image`s without honoring per-pixel alpha, so this went unnoticed
    // there, but femtovg alpha-blends for real and rendered an all-zero-alpha
    // frame as fully transparent (black over the pane background).
    // `frame_to_image` must force every pixel opaque regardless of the
    // decoded frame's alpha bytes.
    #[test]
    fn frame_to_image_forces_full_opacity() {
        // 2x1 RGBA frame: one pixel with alpha already 0xff, one with the
        // zero-alpha padding ironrdp's raw-copy decoders leave behind.
        let frame = FrameUpdate {
            width: 2,
            height: 1,
            rgba: vec![
                10, 20, 30, 0xff, // pixel 0: alpha already opaque
                40, 50, 60, 0x00, // pixel 1: zero alpha (the bug trigger)
            ],
        };
        let img = frame_to_image(&frame);
        let buf = img.to_rgba8().expect("from_rgba8 image round-trips");
        let bytes = buf.as_bytes();
        assert_eq!(bytes, &[10, 20, 30, 0xff, 40, 50, 60, 0xff]);
    }

    // ── connect-time resolution follows the pane, not the
    // persisted/typed value (the bitmap-scaling bug) ────────────────────

    #[test]
    fn pane_resolution_override_prefers_the_live_pane_size() {
        // The pane is known to be 1024x768 - that wins over whatever the
        // saved profile/quick-connect form had (a stand-in for the stored
        // 1280x720 default).
        assert_eq!(
            pane_resolution_override(Some((1024, 768)), (1280, 720)),
            (1024, 768)
        );
    }

    #[test]
    fn pane_resolution_override_falls_back_when_pane_size_unknown() {
        // No pane has reported its size yet (e.g. the very first tab at
        // startup) - keep whatever the caller already had.
        assert_eq!(pane_resolution_override(None, (1280, 720)), (1280, 720));
    }

    #[test]
    fn pane_resolution_override_clamps_degenerate_readouts() {
        // A transient 0 (not yet laid out) or an absurdly large readout
        // must never reach RdpSettings verbatim.
        assert_eq!(
            pane_resolution_override(Some((0, 0)), (1280, 720)),
            (200, 200)
        );
        assert_eq!(
            pane_resolution_override(Some((50_000, 50_000)), (1280, 720)),
            (8192, 8192)
        );
    }

    // ──: Ctrl+Shift direct-shortcut classifier ───────────────────

    #[test]
    fn ctrl_shift_t_is_new_tab() {
        assert_eq!(
            classify_ctrl_shift_shortcut(0, "t"),
            CtrlShiftAction::NewTab
        );
        assert_eq!(
            classify_ctrl_shift_shortcut(0, "T"),
            CtrlShiftAction::NewTab
        );
    }

    #[test]
    fn ctrl_shift_e_is_toggle_sidebar() {
        assert_eq!(
            classify_ctrl_shift_shortcut(0, "e"),
            CtrlShiftAction::ToggleSidebar
        );
        assert_eq!(
            classify_ctrl_shift_shortcut(0, "E"),
            CtrlShiftAction::ToggleSidebar
        );
    }

    #[test]
    fn tab_and_digits_are_not_terminal_ctrl_shift_shortcuts() {
        assert_eq!(classify_ctrl_shift_shortcut(2, ""), CtrlShiftAction::None);
        for digit in '0'..='9' {
            assert_eq!(
                classify_ctrl_shift_shortcut(0, &digit.to_string()),
                CtrlShiftAction::None
            );
        }
    }

    #[test]
    fn ctrl_shift_unrelated_keys_fall_through() {
        assert_eq!(classify_ctrl_shift_shortcut(0, "z"), CtrlShiftAction::None);
        assert_eq!(classify_ctrl_shift_shortcut(0, "\\"), CtrlShiftAction::None);
        assert_eq!(classify_ctrl_shift_shortcut(5, ""), CtrlShiftAction::None);
    }

    #[test]
    fn plain_ctrl_c_and_ctrl_v_are_terminal_clipboard_aliases() {
        assert_eq!(
            classify_terminal_clipboard_shortcut(0, "c", input::MOD_CTRL, true),
            TerminalClipboardAction::CopyIfSelected
        );
        assert_eq!(
            classify_terminal_clipboard_shortcut(0, "\u{3}", input::MOD_CTRL, true),
            TerminalClipboardAction::CopyIfSelected
        );
        assert_eq!(
            classify_terminal_clipboard_shortcut(0, "V", input::MOD_CTRL, true),
            TerminalClipboardAction::Paste
        );
    }

    #[test]
    fn physical_modifier_specials_are_never_clipboard_aliases() {
        for special in 27..=34 {
            assert_eq!(
                classify_terminal_clipboard_shortcut(
                    special,
                    if special == 30 { "\u{16}" } else { "" },
                    input::MOD_CTRL,
                    true,
                ),
                TerminalClipboardAction::None
            );
        }
        assert_eq!(
            classify_terminal_clipboard_shortcut(0, "\u{16}", input::MOD_CTRL, true),
            TerminalClipboardAction::None,
            "ambiguous U+0016 must not stand in for Ctrl+V"
        );
    }

    #[test]
    fn shift_insert_is_a_terminal_paste_alias() {
        assert_eq!(
            classify_terminal_clipboard_shortcut(13, "", input::MOD_SHIFT, false),
            TerminalClipboardAction::Paste
        );
    }

    #[test]
    fn terminal_clipboard_aliases_require_exact_modifiers() {
        assert_eq!(
            classify_terminal_clipboard_shortcut(0, "c", input::MOD_CTRL | input::MOD_ALT, true,),
            TerminalClipboardAction::None
        );
        assert_eq!(
            classify_terminal_clipboard_shortcut(0, "c", input::MOD_CTRL | input::MOD_SHIFT, true,),
            TerminalClipboardAction::None
        );
        assert_eq!(
            classify_terminal_clipboard_shortcut(13, "", 0, true),
            TerminalClipboardAction::None
        );
    }

    #[test]
    fn disabling_plain_aliases_preserves_shift_insert_only() {
        assert_eq!(
            classify_terminal_clipboard_shortcut(0, "c", input::MOD_CTRL, false),
            TerminalClipboardAction::None
        );
        assert_eq!(
            classify_terminal_clipboard_shortcut(0, "v", input::MOD_CTRL, false),
            TerminalClipboardAction::None
        );
        assert_eq!(
            classify_terminal_clipboard_shortcut(13, "", input::MOD_SHIFT, false),
            TerminalClipboardAction::Paste
        );
    }

    // resolve_ssh_auth / resolve_rdp_auth -----------------------------

    /// A `CredentialStore` mock: pre-seeded entries plus an optional key that
    /// always reports a backend error, so the `AuthResolveError::Backend`
    /// path is exercised without a real keychain.
    #[derive(Default)]
    struct MockCredentialStore {
        entries: HashMap<(String, String), Secret>,
        error_key: Option<(String, String)>,
    }

    impl MockCredentialStore {
        fn new() -> Self {
            Self::default()
        }

        fn with(mut self, id: CredentialId, purpose: CredentialPurpose, secret: &str) -> Self {
            let r = CredentialRef::new(id, purpose);
            self.entries.insert(
                (r.service().to_owned(), r.account().to_owned()),
                Secret::from_string(secret.to_owned()),
            );
            self
        }

        fn failing(mut self, id: CredentialId, purpose: CredentialPurpose) -> Self {
            let r = CredentialRef::new(id, purpose);
            self.error_key = Some((r.service().to_owned(), r.account().to_owned()));
            self
        }
    }

    impl cm_core::CredentialStore for MockCredentialStore {
        fn store(&self, _key: &CredentialRef, _secret: &Secret) -> Result<(), CredentialError> {
            unimplemented!("not exercised by these tests")
        }

        fn get(&self, key: &CredentialRef) -> Result<Option<Secret>, CredentialError> {
            let k = (key.service().to_owned(), key.account().to_owned());
            if self.error_key.as_ref() == Some(&k) {
                return Err(CredentialError::Backend(
                    "simulated backend failure".to_owned(),
                ));
            }
            Ok(self.entries.get(&k).cloned())
        }

        fn delete(&self, _key: &CredentialRef) -> Result<(), CredentialError> {
            unimplemented!("not exercised by these tests")
        }
    }

    fn ssh_settings(auth_method: SshAuthMethod) -> SshSettings {
        SshSettings {
            host: "10.0.0.1".to_owned(),
            port: 22,
            username: "ops".to_owned(),
            auth_method,
        }
    }

    fn make_group(id: i64, parent_id: Option<i64>, default_credential: Option<i64>) -> Group {
        Group {
            id: GroupId::new(id),
            parent_id: parent_id.map(GroupId::new),
            name: "group".to_owned(),
            sort: 0,
            default_credential: default_credential.map(CredentialId::new),
        }
    }

    fn make_ssh_conn(
        group_id: Option<i64>,
        credential: Option<i64>,
        auth_method: SshAuthMethod,
    ) -> Connection {
        Connection::new(
            ConnectionId::new(1),
            group_id.map(GroupId::new),
            "conn".to_owned(),
            ConnectionKind::Ssh,
            ConnectionSettings::Ssh(ssh_settings(auth_method)),
            credential.map(|id| cm_core::CredentialSource::Object(CredentialId::new(id))),
            0,
            0,
            0,
        )
        .unwrap()
    }

    fn make_rdp_conn(group_id: Option<i64>, credential: Option<i64>) -> Connection {
        Connection::new(
            ConnectionId::new(2),
            group_id.map(GroupId::new),
            "rdp-conn".to_owned(),
            ConnectionKind::Rdp,
            ConnectionSettings::Rdp(RdpSettings {
                host: "10.0.0.2".to_owned(),
                username: Some("admin".to_owned()),
                domain: Some("CORP".to_owned()),
                ..RdpSettings::default()
            }),
            credential.map(|id| cm_core::CredentialSource::Object(CredentialId::new(id))),
            0,
            0,
            0,
        )
        .unwrap()
    }

    /// BUG-cred-username-auth test helper: an RDP connection with NO inline
    /// username - the shape a RoyalTS import produces, where the username
    /// lives only on the assigned credential.
    fn make_rdp_conn_no_inline_username(
        group_id: Option<i64>,
        credential: Option<i64>,
    ) -> Connection {
        Connection::new(
            ConnectionId::new(3),
            group_id.map(GroupId::new),
            "rdp-conn-imported".to_owned(),
            ConnectionKind::Rdp,
            ConnectionSettings::Rdp(RdpSettings {
                host: "srv-win01".to_owned(),
                username: None,
                domain: None,
                ..RdpSettings::default()
            }),
            credential.map(|id| cm_core::CredentialSource::Object(CredentialId::new(id))),
            0,
            0,
            0,
        )
        .unwrap()
    }

    /// BUG-cred-username-auth test helper: a minimal [`Credential`] carrying
    /// only the fields the username-precedence logic reads.
    fn make_credential(id: i64, username: Option<&str>) -> Credential {
        Credential {
            id: CredentialId::new(id),
            name: "cred".to_owned(),
            kind: CredentialKind::Password,
            folder_id: None,
            username: username.map(str::to_owned),
        }
    }

    #[test]
    fn resolve_ssh_auth_password_own_credential() {
        let conn = make_ssh_conn(None, Some(1), SshAuthMethod::Password);
        let store = MockCredentialStore::new().with(
            CredentialId::new(1),
            CredentialPurpose::Password,
            "s3cret",
        );
        let settings = ssh_settings(SshAuthMethod::Password);
        let auth = resolve_ssh_auth(&conn, &[], &settings, &store, &[]).expect("should resolve");
        match auth {
            SshAuthInput::Password(s) => assert_eq!(s.expose(), b"s3cret"),
            other => panic!("expected Password, got {other:?}"),
        }
    }

    #[test]
    fn resolve_ssh_auth_inherits_group_default_credential() {
        let group = make_group(10, None, Some(7));
        let conn = make_ssh_conn(Some(10), None, SshAuthMethod::Password);
        let store = MockCredentialStore::new().with(
            CredentialId::new(7),
            CredentialPurpose::Password,
            "grouppw",
        );
        let settings = ssh_settings(SshAuthMethod::Password);
        let auth = resolve_ssh_auth(&conn, &[group], &settings, &store, &[])
            .expect("should resolve via inherited group default");
        match auth {
            SshAuthInput::Password(s) => assert_eq!(s.expose(), b"grouppw"),
            other => panic!("expected Password, got {other:?}"),
        }
    }

    #[test]
    fn resolve_ssh_auth_own_credential_overrides_group_default() {
        let group = make_group(10, None, Some(7));
        let conn = make_ssh_conn(Some(10), Some(1), SshAuthMethod::Password);
        let store = MockCredentialStore::new()
            .with(CredentialId::new(1), CredentialPurpose::Password, "ownpw")
            .with(CredentialId::new(7), CredentialPurpose::Password, "grouppw");
        let settings = ssh_settings(SshAuthMethod::Password);
        let auth = resolve_ssh_auth(&conn, &[group], &settings, &store, &[])
            .expect("should resolve to the connection's own credential");
        match auth {
            SshAuthInput::Password(s) => assert_eq!(s.expose(), b"ownpw"),
            other => panic!("expected Password, got {other:?}"),
        }
    }

    #[test]
    fn resolve_ssh_auth_no_credential_assigned() {
        let conn = make_ssh_conn(None, None, SshAuthMethod::Password);
        let store = MockCredentialStore::new();
        let settings = ssh_settings(SshAuthMethod::Password);
        let err = resolve_ssh_auth(&conn, &[], &settings, &store, &[])
            .expect_err("should fail: no credential assigned anywhere");
        assert_eq!(err, AuthResolveError::NoCredentialAssigned);
        assert_eq!(err.to_string(), "No credential assigned");
    }

    #[test]
    fn resolve_ssh_auth_credential_missing_from_keychain() {
        let conn = make_ssh_conn(None, Some(2), SshAuthMethod::Password);
        let store = MockCredentialStore::new(); // nothing stored for id 2
        let settings = ssh_settings(SshAuthMethod::Password);
        let err = resolve_ssh_auth(&conn, &[], &settings, &store, &[])
            .expect_err("should fail: keychain has no entry");
        assert_eq!(err, AuthResolveError::NotFoundInKeychain);
        assert_eq!(err.to_string(), "Credential not found in keychain");
    }

    #[test]
    fn resolve_ssh_auth_keychain_backend_error_surfaces() {
        let conn = make_ssh_conn(None, Some(3), SshAuthMethod::Password);
        let store =
            MockCredentialStore::new().failing(CredentialId::new(3), CredentialPurpose::Password);
        let settings = ssh_settings(SshAuthMethod::Password);
        let err = resolve_ssh_auth(&conn, &[], &settings, &store, &[])
            .expect_err("should surface the backend error");
        assert!(matches!(err, AuthResolveError::Backend(_)));
    }

    #[test]
    fn resolve_ssh_auth_key_material_without_passphrase() {
        let auth_method = SshAuthMethod::PublicKey {
            key_ref: CredentialRef::new(CredentialId::new(4), CredentialPurpose::SshKey),
        };
        let conn = make_ssh_conn(None, Some(4), auth_method.clone());
        let store = MockCredentialStore::new().with(
            CredentialId::new(4),
            CredentialPurpose::SshKey,
            "PEM-TEXT",
        );
        let settings = ssh_settings(auth_method);
        let auth = resolve_ssh_auth(&conn, &[], &settings, &store, &[])
            .expect("should resolve key material");
        match auth {
            SshAuthInput::KeyMaterial {
                key_pem,
                passphrase,
            } => {
                assert_eq!(key_pem.expose(), b"PEM-TEXT");
                assert!(passphrase.is_none(), "no passphrase was stored");
            }
            other => panic!("expected KeyMaterial, got {other:?}"),
        }
    }

    #[test]
    fn resolve_ssh_auth_key_material_with_passphrase() {
        let auth_method = SshAuthMethod::PublicKey {
            key_ref: CredentialRef::new(CredentialId::new(5), CredentialPurpose::SshKey),
        };
        let conn = make_ssh_conn(None, Some(5), auth_method.clone());
        let store = MockCredentialStore::new()
            .with(CredentialId::new(5), CredentialPurpose::SshKey, "PEM-TEXT")
            .with(
                CredentialId::new(5),
                CredentialPurpose::SshPassphrase,
                "hunter2",
            );
        let settings = ssh_settings(auth_method);
        let auth = resolve_ssh_auth(&conn, &[], &settings, &store, &[])
            .expect("should resolve key material with passphrase");
        match auth {
            SshAuthInput::KeyMaterial {
                key_pem,
                passphrase,
            } => {
                assert_eq!(key_pem.expose(), b"PEM-TEXT");
                assert_eq!(
                    passphrase.expect("passphrase must be present").expose(),
                    b"hunter2"
                );
            }
            other => panic!("expected KeyMaterial, got {other:?}"),
        }
    }

    #[test]
    fn resolve_ssh_auth_agent_needs_no_credential() {
        let conn = make_ssh_conn(None, None, SshAuthMethod::Agent);
        let store = MockCredentialStore::new();
        let settings = ssh_settings(SshAuthMethod::Agent);
        let auth = resolve_ssh_auth(&conn, &[], &settings, &store, &[])
            .expect("agent auth needs no stored credential");
        assert!(matches!(auth, SshAuthInput::Agent));
    }

    #[test]
    fn resolve_rdp_auth_own_credential() {
        let conn = make_rdp_conn(None, Some(6));
        let store = MockCredentialStore::new().with(
            CredentialId::new(6),
            CredentialPurpose::Password,
            "rdppw",
        );
        let settings = RdpSettings {
            host: "10.0.0.2".to_owned(),
            username: Some("admin".to_owned()),
            domain: Some("CORP".to_owned()),
            ..RdpSettings::default()
        };
        // Credential #6 isn't in the credentials list here (empty slice) -
        // exercises the "credential id resolves but the object itself isn't
        // found" fallback-to-inline path, same as `<deleted>` display
        // elsewhere.
        let auth = resolve_rdp_auth(&conn, &[], &settings, &store, &[]).expect("should resolve");
        assert_eq!(auth.username, "admin");
        assert_eq!(auth.domain.as_deref(), Some("CORP"));
        assert_eq!(auth.password.expose(), b"rdppw");
    }

    #[test]
    fn resolve_rdp_auth_inherits_group_default_credential() {
        let group = make_group(20, None, Some(8));
        let conn = make_rdp_conn(Some(20), None);
        let store = MockCredentialStore::new().with(
            CredentialId::new(8),
            CredentialPurpose::Password,
            "grouprdp",
        );
        let settings = RdpSettings {
            host: "10.0.0.2".to_owned(),
            username: Some("admin".to_owned()),
            ..RdpSettings::default()
        };
        let auth = resolve_rdp_auth(&conn, &[group], &settings, &store, &[])
            .expect("should resolve via inherited group default");
        assert_eq!(auth.password.expose(), b"grouprdp");
    }

    #[test]
    fn resolve_rdp_auth_no_credential_assigned() {
        let conn = make_rdp_conn(None, None);
        let store = MockCredentialStore::new();
        let settings = RdpSettings::default();
        let err = resolve_rdp_auth(&conn, &[], &settings, &store, &[])
            .expect_err("should fail: no credential assigned anywhere");
        assert_eq!(err, AuthResolveError::NoCredentialAssigned);
    }

    #[test]
    fn resolve_rdp_auth_credential_missing_from_keychain() {
        let conn = make_rdp_conn(None, Some(9));
        let store = MockCredentialStore::new(); // nothing stored for id 9
        let settings = RdpSettings::default();
        let err = resolve_rdp_auth(&conn, &[], &settings, &store, &[])
            .expect_err("should fail: keychain has no entry");
        assert_eq!(err, AuthResolveError::NotFoundInKeychain);
    }

    // BUG-cred-username-auth: effective_auth_username / effective_ssh_settings
    // / resolve_rdp_auth username precedence - -------------------------------

    #[test]
    fn effective_auth_username_credential_wins_when_assigned_and_non_empty() {
        let conn = make_rdp_conn(None, Some(6));
        let creds = vec![make_credential(6, Some("admin-from-cred"))];
        assert_eq!(
            effective_auth_username(&conn, &[], "", &creds),
            "admin-from-cred"
        );
    }

    #[test]
    fn effective_auth_username_falls_back_to_inline_when_credential_username_empty() {
        let conn = make_rdp_conn(None, Some(6));
        let creds = vec![make_credential(6, Some(""))];
        assert_eq!(
            effective_auth_username(&conn, &[], "inline-user", &creds),
            "inline-user"
        );
    }

    #[test]
    fn effective_auth_username_falls_back_to_inline_when_credential_username_none() {
        let conn = make_rdp_conn(None, Some(6));
        let creds = vec![make_credential(6, None)];
        assert_eq!(
            effective_auth_username(&conn, &[], "inline-user", &creds),
            "inline-user"
        );
    }

    #[test]
    fn effective_auth_username_falls_back_to_inline_when_no_credential_assigned() {
        let conn = make_rdp_conn(None, None);
        assert_eq!(
            effective_auth_username(&conn, &[], "inline-user", &[]),
            "inline-user"
        );
    }

    #[test]
    fn effective_auth_username_inherits_group_default_credential_username() {
        let group = make_group(20, None, Some(8));
        let conn = make_rdp_conn(Some(20), None);
        let creds = vec![make_credential(8, Some("group-admin"))];
        assert_eq!(
            effective_auth_username(&conn, &[group], "inline", &creds),
            "group-admin"
        );
    }

    /// THE regression test for BUG-cred-username-auth (RDP half): a
    /// credentialed RDP connection with an EMPTY inline `settings.username`
    /// (exactly the RoyalTS-imported shape - the username lives on the
    /// credential object, not inline) plus a credential whose `username` is
    /// "admin" must resolve `RdpAuthInput.username == "admin"`, not empty.
    /// **Must FAIL on master**: earlier, `resolve_rdp_auth` used
    /// `settings.username.clone.unwrap_or_default` verbatim and never
    /// looked at the credential's `username` at all - the live bug
    /// (`username=` blank in the auth log).
    #[test]
    fn resolve_rdp_auth_credential_username_wins_over_empty_inline_username() {
        let conn = make_rdp_conn_no_inline_username(None, Some(6));
        let store = MockCredentialStore::new().with(
            CredentialId::new(6),
            CredentialPurpose::Password,
            "rdppw",
        );
        let credentials = vec![make_credential(6, Some("admin"))];
        let settings = RdpSettings {
            host: "10.0.0.2".to_owned(),
            username: None, // no inline username - RoyalTS-imported style
            domain: Some("CORP".to_owned()),
            ..RdpSettings::default()
        };
        let auth =
            resolve_rdp_auth(&conn, &[], &settings, &store, &credentials).expect("should resolve");
        assert_eq!(
            auth.username, "admin",
            "the assigned credential's username must be used when the inline \
             username is empty (BUG-cred-username-auth)"
        );
        assert_eq!(auth.domain.as_deref(), Some("CORP"), "domain stays inline");
    }

    /// Non-regression (item c): a connection with an inline username and NO
    /// credential assigned still uses the inline username unchanged.
    #[test]
    fn resolve_rdp_auth_uses_inline_username_when_no_credential_username() {
        let settings = RdpSettings {
            host: "10.0.0.2".to_owned(),
            username: Some("typed-user".to_owned()),
            domain: Some("CORP".to_owned()),
            ..RdpSettings::default()
        };
        // Build `conn` with these same settings directly, rather than via
        // `make_rdp_conn` (which hardcodes its own, different username).
        // `resolve_connection_auth`'s username fallback reads `conn.settings`
        // directly, not the `settings` param passed to `resolve_rdp_auth` -
        // in production the two are always the same object, so a mismatched
        // pair here would only be a test artifact, not a real scenario.
        let conn = Connection::new(
            ConnectionId::new(2),
            None,
            "rdp-conn".to_owned(),
            ConnectionKind::Rdp,
            ConnectionSettings::Rdp(settings.clone()),
            Some(cm_core::CredentialSource::Object(CredentialId::new(6))),
            0,
            0,
            0,
        )
        .unwrap();
        let store = MockCredentialStore::new().with(
            CredentialId::new(6),
            CredentialPurpose::Password,
            "rdppw",
        );
        // Credential #6 exists but has no username of its own.
        let credentials = vec![make_credential(6, None)];
        let auth =
            resolve_rdp_auth(&conn, &[], &settings, &store, &credentials).expect("should resolve");
        assert_eq!(auth.username, "typed-user");
    }

    /// SSH counterpart of [`resolve_ssh_auth`]'s SSH equivalent
    /// (BUG-cred-username-auth). [`SshAuthInput`] carries no username field
    /// - the effective username is applied to [`SshSettings`] via
    ///   [`effective_ssh_settings`], which every SSH launch/reconnect path uses
    ///   before connecting. **Must FAIL on master**: `effective_ssh_settings`
    ///   doesn't exist there and every call site used the connection's inline
    ///   (empty) `settings.username` verbatim.
    #[test]
    fn effective_ssh_settings_credential_username_wins_over_empty_inline_username() {
        let conn = make_ssh_conn(None, Some(1), SshAuthMethod::Password);
        let credentials = vec![make_credential(1, Some("opsuser"))];
        let settings = SshSettings {
            host: "10.0.0.1".to_owned(),
            port: 22,
            username: String::new(), // no inline username
            auth_method: SshAuthMethod::Password,
        };
        let effective = effective_ssh_settings(&conn, &[], &settings, &credentials);
        assert_eq!(
            effective.username, "opsuser",
            "the assigned credential's username must be used when the inline \
             username is empty (BUG-cred-username-auth)"
        );
    }

    #[test]
    fn effective_ssh_settings_uses_inline_username_when_no_credential_assigned() {
        let conn = make_ssh_conn(None, None, SshAuthMethod::Agent);
        let settings = ssh_settings(SshAuthMethod::Agent); // inline username "ops"
        let effective = effective_ssh_settings(&conn, &[], &settings, &[]);
        assert_eq!(effective.username, "ops");
    }

    #[test]
    fn effective_ssh_settings_uses_inline_username_when_credential_username_empty() {
        let conn = make_ssh_conn(None, Some(1), SshAuthMethod::Password);
        let credentials = vec![make_credential(1, Some(""))];
        let settings = ssh_settings(SshAuthMethod::Password); // inline username "ops"
        let effective = effective_ssh_settings(&conn, &[], &settings, &credentials);
        assert_eq!(effective.username, "ops");
    }

    /// Non-regression (item d): key-material auth resolution itself is
    /// untouched by the username fix - `resolve_ssh_auth` never looked at
    /// username before and still doesn't; `effective_ssh_settings` only
    /// changes the login name that goes alongside whatever auth material was
    /// resolved (agent, password, or key).
    #[test]
    fn resolve_ssh_auth_key_material_unaffected_by_username_fix() {
        let auth_method = SshAuthMethod::PublicKey {
            key_ref: CredentialRef::new(CredentialId::new(4), CredentialPurpose::SshKey),
        };
        let conn = make_ssh_conn(None, Some(4), auth_method.clone());
        let store = MockCredentialStore::new().with(
            CredentialId::new(4),
            CredentialPurpose::SshKey,
            "PEM-TEXT",
        );
        let settings = ssh_settings(auth_method);
        let auth = resolve_ssh_auth(&conn, &[], &settings, &store, &[])
            .expect("should resolve key material");
        match auth {
            SshAuthInput::KeyMaterial { key_pem, .. } => assert_eq!(key_pem.expose(), b"PEM-TEXT"),
            other => panic!("expected KeyMaterial, got {other:?}"),
        }
        // The login name for a key-auth connection still follows the same
        // credential-wins precedence - the credential's username applies to
        // *which account* the key logs into, independent of the key material.
        let credentials = vec![make_credential(4, Some("keyuser"))];
        let effective = effective_ssh_settings(&conn, &[], &settings, &credentials);
        assert_eq!(effective.username, "keyuser");
    }

    // ──: quick-connect kind selector → settings mapping ────────

    #[test]
    fn qc_kind_from_int_maps_all_four_kinds() {
        assert_eq!(QcKind::from(0), QcKind::Ssh);
        assert_eq!(QcKind::from(1), QcKind::Rdp);
        assert_eq!(QcKind::from(2), QcKind::Telnet);
        assert_eq!(QcKind::from(3), QcKind::Local);
    }

    #[test]
    fn qc_kind_from_int_falls_back_to_ssh() {
        // Out-of-range values fall back to the dialog's own default (kind 0).
        assert_eq!(QcKind::from(-1), QcKind::Ssh);
        assert_eq!(QcKind::from(99), QcKind::Ssh);
    }

    #[test]
    fn qc_ssh_settings_builds_from_fields() {
        let s = qc_ssh_settings("web-prod-01", "2222", "ops").expect("valid fields");
        assert_eq!(s.host, "web-prod-01");
        assert_eq!(s.port, 2222);
        assert_eq!(s.username, "ops");
        assert_eq!(s.auth_method, SshAuthMethod::Password);
    }

    #[test]
    fn qc_ssh_settings_rejects_empty_host_or_username() {
        assert!(qc_ssh_settings("", "22", "ops").is_none());
        assert!(qc_ssh_settings("host", "22", "").is_none());
        assert!(qc_ssh_settings("  ", "22", "  ").is_none());
    }

    #[test]
    fn qc_ssh_settings_falls_back_to_default_port_on_bad_input() {
        let s = qc_ssh_settings("host", "not-a-port", "ops").expect("valid");
        assert_eq!(s.port, SshSettings::DEFAULT_PORT);
        let s = qc_ssh_settings("host", "", "ops").expect("valid");
        assert_eq!(s.port, SshSettings::DEFAULT_PORT);
    }

    #[test]
    fn parse_qc_resolution_parses_widthxheight() {
        assert_eq!(parse_qc_resolution("1920x1080"), (1920, 1080));
        assert_eq!(parse_qc_resolution("800X600"), (800, 600));
        assert_eq!(parse_qc_resolution(" 1280 x 720 "), (1280, 720));
    }

    #[test]
    fn parse_qc_resolution_falls_back_on_garbage() {
        let defaults = (RdpSettings::DEFAULT_WIDTH, RdpSettings::DEFAULT_HEIGHT);
        assert_eq!(parse_qc_resolution(""), defaults);
        assert_eq!(parse_qc_resolution("garbage"), defaults);
        assert_eq!(parse_qc_resolution("0x0"), defaults);
        assert_eq!(parse_qc_resolution("1920x0"), defaults);
        assert_eq!(parse_qc_resolution("x"), defaults);
    }

    #[test]
    fn qc_rdp_settings_builds_from_fields() {
        let s = qc_rdp_settings("win-01", "3390", "administrator", "CORP", "1920x1080")
            .expect("valid fields");
        assert_eq!(s.host, "win-01");
        assert_eq!(s.port, 3390);
        assert_eq!(s.username.as_deref(), Some("administrator"));
        assert_eq!(s.domain.as_deref(), Some("CORP"));
        assert_eq!(s.width, 1920);
        assert_eq!(s.height, 1080);
    }

    #[test]
    fn qc_rdp_settings_empty_domain_is_none() {
        let s = qc_rdp_settings("win-01", "3389", "admin", "", "1280x720").expect("valid");
        assert!(s.domain.is_none());
    }

    #[test]
    fn qc_rdp_settings_rejects_empty_host_or_username() {
        assert!(qc_rdp_settings("", "3389", "admin", "", "1280x720").is_none());
        assert!(qc_rdp_settings("win-01", "3389", "", "", "1280x720").is_none());
    }

    #[test]
    fn qc_rdp_settings_falls_back_to_default_port_on_bad_input() {
        let s = qc_rdp_settings("win-01", "nope", "admin", "", "1280x720").expect("valid");
        assert_eq!(s.port, RdpSettings::DEFAULT_PORT);
    }

    #[test]
    fn qc_telnet_settings_are_host_port_only() {
        let settings = qc_telnet_settings(" telnet-host ", "2323").expect("valid Telnet");
        assert_eq!(settings.host, "telnet-host");
        assert_eq!(settings.port, 2323);
        assert!(qc_telnet_settings("  ", "23").is_none());
        assert_eq!(
            qc_telnet_settings("host", "bad").unwrap().port,
            TelnetSettings::DEFAULT_PORT
        );
    }

    #[test]
    fn qc_local_settings_splits_args_on_whitespace() {
        let ls = qc_local_settings("/bin/bash", "-l  -i", "/tmp");
        assert_eq!(ls.program.as_deref(), Some("/bin/bash"));
        assert_eq!(ls.args, vec!["-l".to_owned(), "-i".to_owned()]);
        assert_eq!(ls.working_dir.as_deref(), Some("/tmp"));
        assert!(ls.env.is_empty());
    }

    #[test]
    fn qc_local_settings_empty_fields_fall_back_to_defaults() {
        let ls = qc_local_settings("", "", "");
        assert_eq!(ls.program, None);
        assert!(ls.args.is_empty());
        assert_eq!(ls.working_dir, None);
    }

    // ──: RDP reconnect reuses stored RdpConnectInfo + creds ────

    #[test]
    fn resolve_ssh_reconnect_direct_clones_the_cached_auth() {
        let ci = SshConnectInfo {
            settings: ssh_settings(SshAuthMethod::Password),
            auth_source: SshAuthSource::Direct(SshAuthInput::Password(Secret::from_string(
                "typed-pw".to_owned(),
            ))),
        };
        let store = MockCredentialStore::new();
        let (settings, provenance, auth) = resolve_ssh_reconnect(&ci, &[], &[], &store, &[]);
        assert!(matches!(provenance, AuthProvenance::Direct));
        assert_eq!(
            settings.username, "ops",
            "Direct settings pass through unchanged"
        );
        match auth.expect("direct auth always resolves") {
            SshAuthInput::Password(s) => assert_eq!(s.expose(), b"typed-pw"),
            other => panic!("expected Password, got {other:?}"),
        }
    }

    #[test]
    fn resolve_ssh_reconnect_credential_reresolves_fresh() {
        let conn = make_ssh_conn(None, Some(1), SshAuthMethod::Password);
        let ci = SshConnectInfo {
            settings: ssh_settings(SshAuthMethod::Password),
            auth_source: SshAuthSource::Credential(conn.id),
        };
        let store = MockCredentialStore::new().with(
            CredentialId::new(1),
            CredentialPurpose::Password,
            "fresh-pw",
        );
        let (_, provenance, auth) = resolve_ssh_reconnect(&ci, &[conn], &[], &store, &[]);
        assert!(matches!(provenance, AuthProvenance::Credential(_)));
        match auth.expect("credential resolves from the mock store") {
            SshAuthInput::Password(s) => assert_eq!(s.expose(), b"fresh-pw"),
            other => panic!("expected Password, got {other:?}"),
        }
    }

    /// BUG-cred-username-auth: a reconnect must not regress to an empty
    /// username - the returned settings re-derive the effective username
    /// from the *live* connection + credentials list, not whatever the
    /// tab's stale cached `SshConnectInfo.settings.username` happened to be.
    #[test]
    fn resolve_ssh_reconnect_credential_username_wins_over_empty_inline_username() {
        let conn = make_ssh_conn(None, Some(1), SshAuthMethod::Password);
        let ci = SshConnectInfo {
            settings: SshSettings {
                host: "10.0.0.1".to_owned(),
                port: 22,
                username: String::new(), // no inline username
                auth_method: SshAuthMethod::Password,
            },
            auth_source: SshAuthSource::Credential(conn.id),
        };
        let store = MockCredentialStore::new().with(
            CredentialId::new(1),
            CredentialPurpose::Password,
            "fresh-pw",
        );
        let credentials = vec![make_credential(1, Some("opsuser"))];
        let (settings, _, auth) = resolve_ssh_reconnect(&ci, &[conn], &[], &store, &credentials);
        assert_eq!(settings.username, "opsuser");
        auth.expect("credential resolves from the mock store");
    }

    #[test]
    fn resolve_ssh_reconnect_credential_missing_connection_fails() {
        let ci = SshConnectInfo {
            settings: ssh_settings(SshAuthMethod::Password),
            auth_source: SshAuthSource::Credential(ConnectionId::new(404)),
        };
        let store = MockCredentialStore::new();
        let (_, _, auth) = resolve_ssh_reconnect(&ci, &[], &[], &store, &[]);
        assert_eq!(
            auth.expect_err("connection no longer exists"),
            AuthResolveError::NoCredentialAssigned
        );
    }

    #[test]
    fn resolve_rdp_reconnect_direct_clones_the_cached_auth() {
        let ci = RdpConnectInfo {
            settings: RdpSettings::default(),
            auth_source: RdpAuthSource::Direct(RdpAuthInput {
                username: "admin".to_owned(),
                password: Secret::from_string("typed-rdp-pw".to_owned()),
                domain: None,
            }),
        };
        let store = MockCredentialStore::new();
        let (provenance, auth) = resolve_rdp_reconnect(&ci, &[], &[], &store, &[]);
        assert!(matches!(provenance, AuthProvenance::Direct));
        let auth = auth.expect("direct auth always resolves");
        assert_eq!(auth.username, "admin");
        assert_eq!(auth.password.expose(), b"typed-rdp-pw");
    }

    #[test]
    fn resolve_rdp_reconnect_credential_reresolves_fresh() {
        let conn = make_rdp_conn(None, Some(6));
        let ci = RdpConnectInfo {
            settings: RdpSettings {
                host: "10.0.0.2".to_owned(),
                username: Some("admin".to_owned()),
                ..RdpSettings::default()
            },
            auth_source: RdpAuthSource::Credential(conn.id),
        };
        let store = MockCredentialStore::new().with(
            CredentialId::new(6),
            CredentialPurpose::Password,
            "fresh-rdp-pw",
        );
        let (provenance, auth) = resolve_rdp_reconnect(&ci, &[conn], &[], &store, &[]);
        assert!(matches!(provenance, AuthProvenance::Credential(_)));
        let auth = auth.expect("credential resolves from the mock store");
        assert_eq!(auth.password.expose(), b"fresh-rdp-pw");
    }

    /// BUG-cred-username-auth: RDP reconnect must not regress to an empty
    /// username either - `resolve_rdp_auth` re-applies the credential-wins
    /// precedence fresh on every reconnect since `credentials` is threaded
    /// all the way through.
    #[test]
    fn resolve_rdp_reconnect_credential_username_wins_over_empty_inline_username() {
        let conn = make_rdp_conn_no_inline_username(None, Some(6));
        let ci = RdpConnectInfo {
            settings: RdpSettings {
                host: "srv-win01".to_owned(),
                username: None, // no inline username - RoyalTS-imported style
                ..RdpSettings::default()
            },
            auth_source: RdpAuthSource::Credential(conn.id),
        };
        let store = MockCredentialStore::new().with(
            CredentialId::new(6),
            CredentialPurpose::Password,
            "fresh-rdp-pw",
        );
        let credentials = vec![make_credential(6, Some("admin"))];
        let (_, auth) = resolve_rdp_reconnect(&ci, &[conn], &[], &store, &credentials);
        let auth = auth.expect("credential resolves from the mock store");
        assert_eq!(auth.username, "admin");
    }

    #[test]
    fn resolve_rdp_reconnect_credential_missing_connection_fails() {
        let ci = RdpConnectInfo {
            settings: RdpSettings::default(),
            auth_source: RdpAuthSource::Credential(ConnectionId::new(404)),
        };
        let store = MockCredentialStore::new();
        let (_, auth) = resolve_rdp_reconnect(&ci, &[], &[], &store, &[]);
        assert_eq!(
            auth.expect_err("connection no longer exists"),
            AuthResolveError::NoCredentialAssigned
        );
    }

    // ── agent_mode_execute_blocked (the execute-gate) ──────────

    fn agent_mode_fixture(
        interaction_count: usize,
        read: bool,
        write: bool,
        execute: bool,
    ) -> crate::AgentModeConfig {
        crate::AgentModeConfig {
            external_port: 0,
            scopes: Arc::new(std::sync::RwLock::new(cm_core::ScopeSet {
                read,
                write,
                execute,
            })),
            mcp_interaction_count: Arc::new(std::sync::atomic::AtomicUsize::new(interaction_count)),
        }
    }

    #[test]
    fn execute_gate_never_blocks_when_agent_mode_is_off() {
        assert!(!agent_mode_execute_blocked(&None));
    }

    #[test]
    fn execute_gate_never_blocks_when_no_write_interaction_is_in_flight() {
        // Agent mode is on, execute is even NOT granted - but nothing is
        // actually mid-flight, so this must be indistinguishable from a
        // plain human click: never blocked.
        let cfg = agent_mode_fixture(0, true, true, false);
        assert!(!agent_mode_execute_blocked(&Some(cfg)));
    }

    #[test]
    fn execute_gate_does_not_block_when_execute_is_granted() {
        let cfg = agent_mode_fixture(1, true, true, true);
        assert!(!agent_mode_execute_blocked(&Some(cfg)));
    }

    #[test]
    fn execute_gate_blocks_a_write_tool_in_flight_without_execute_granted() {
        // The adversarial case review will test: write granted, execute not,
        // and an agent write-tool call (e.g. click_element on Connect) is
        // actually in flight right now.
        let cfg = agent_mode_fixture(1, true, true, false);
        assert!(agent_mode_execute_blocked(&Some(cfg)));
    }

    #[test]
    fn source_file_lease_survives_observation_replacement_until_backend_result() {
        let endpoint = cm_core::SessionEndpointId(4);
        let revision = cm_core::LocalClipboardRevision(12);
        let mut lease = ClipboardSourceLease {
            snapshot: cm_core::ClipboardSnapshot::Files(vec!["/synthetic/a".into()]),
            still_observed: true,
            users: BTreeSet::new(),
        };
        lease.retain(endpoint, revision);
        lease.still_observed = false;
        assert!(
            !lease.cleanup_ready(),
            "backend publication still owns staging"
        );
        lease.release(endpoint, revision);
        assert!(
            lease.cleanup_ready(),
            "ACK/rejection releases the last user"
        );
    }

    #[test]
    fn superseded_pending_source_publication_releases_only_its_revision() {
        let endpoint = cm_core::SessionEndpointId(5);
        let first = cm_core::LocalClipboardRevision(1);
        let latest = cm_core::LocalClipboardRevision(2);
        let mut lease = ClipboardSourceLease {
            snapshot: cm_core::ClipboardSnapshot::Files(vec!["/synthetic/b".into()]),
            still_observed: false,
            users: BTreeSet::new(),
        };
        lease.retain(endpoint, first);
        lease.retain(endpoint, latest);
        lease.release(endpoint, latest);
        assert!(!lease.cleanup_ready());
        lease.release(endpoint, first);
        assert!(lease.cleanup_ready());
    }

    #[test]
    fn successful_text_install_retires_old_file_lease_but_failure_preserves_it() {
        let old = std::path::PathBuf::from("/synthetic/old-stage");
        let mut lease = Some((
            cm_core::ClipboardSnapshot::Files(vec!["/synthetic/old-stage/a".into()]),
            old.clone(),
        ));

        // A failed write never calls the successful-update helper.
        assert_eq!(lease.as_ref().map(|(_, path)| path), Some(&old));
        let cleanup = update_installed_file_lease(
            &mut lease,
            cm_core::ClipboardSnapshot::Text("replacement".into()),
            None,
        );
        assert_eq!(cleanup, vec![old]);
        assert!(lease.is_none());
    }

    #[test]
    fn remote_origin_suppression_is_same_endpoint_only() {
        let snapshot = cm_core::ClipboardSnapshot::Text("synthetic".into());
        let origin = (
            cm_core::SessionEndpointId(1),
            cm_core::RemoteClipboardRevision(8),
            snapshot.clone(),
        );
        assert!(!observation_needs_publication(
            Some(&origin),
            cm_core::SessionEndpointId(1),
            &snapshot
        ));
        assert!(observation_needs_publication(
            Some(&origin),
            cm_core::SessionEndpointId(2),
            &snapshot
        ));
        assert!(observation_needs_publication(
            Some(&origin),
            cm_core::SessionEndpointId(1),
            &cm_core::ClipboardSnapshot::Text("changed".into())
        ));
    }

    #[test]
    fn local_revision_exhaustion_permanently_disables_owner_reactivation() {
        let active = cm_core::SessionEndpointId(7);
        let later_focus = cm_core::SessionEndpointId(8);
        let mut next_revision = u64::MAX;
        let mut disabled = false;
        let mut owner = Some(active);

        assert_eq!(
            allocate_local_clipboard_revision(&mut next_revision),
            None,
            "the terminal counter value is never issued or wrapped"
        );
        let deactivated = begin_terminal_clipboard_disable(&mut disabled, &mut owner);

        assert_eq!(deactivated, Some(active));
        assert!(disabled);
        assert_eq!(owner, None);
        assert_eq!(next_revision, u64::MAX);
        assert_eq!(
            focused_clipboard_owner(disabled, Some(later_focus)),
            None,
            "later focus changes cannot restart a failed-closed bridge"
        );
    }
}

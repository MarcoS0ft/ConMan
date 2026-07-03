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
    Connection, ConnectionSettings, CredentialPurpose, CredentialRef, Group, RdpSettings, Secret,
    SshAuthMethod, SshSettings,
};
use cm_session::{
    CertDecision, CertInfo, CertStore, CertVerifier, FailedSession, FrameUpdate, HostKeyDecision,
    HostKeyInfo, HostKeyVerifier, KnownHosts, PaneLayout, RdpAuthInput, RdpSession, SessionInput,
    SessionStatus, SshAuthInput, SshTerminalSession, Surface,
};
use slint::{ComponentHandle, Image, Model, SharedString, Timer, TimerMode, VecModel};

use crate::input;
use crate::{AppWindow, TabItem, ToastEntry};

use super::*;

pub(super) fn wire_sessions(ctx: &Ctx) {
    wire_key_input(ctx);
    wire_pointer(ctx);
    wire_scroll(ctx);
    wire_rdp_scroll(ctx);
    wire_quick_connect(ctx);
    wire_qc_connect(ctx);
    wire_host_key_accept(ctx);
    wire_host_key_reject(ctx);
    wire_cert_accept(ctx);
    wire_cert_reject(ctx);
    wire_rdp_key_down(ctx);
    wire_rdp_key_up(ctx);
    wire_row_activated(ctx);
    wire_reconnect(ctx);
}

fn wire_key_input(ctx: &Ctx) {
    ctx.ui.on_key_input({
        let state = ctx.state.clone();
        let pal_model_kb = ctx.palette_model.clone();
        let tab_model_kb = ctx.tab_model.clone();
        let weak_kb = ctx.ui.as_weak();
        move |text, special, mods| {
            let Some(ui) = weak_kb.upgrade() else { return };
            if ui.get_palette_open() {
                palette::handle_palette_key(
                    &ui,
                    &state,
                    &tab_model_kb,
                    &pal_model_kb,
                    text,
                    special,
                    mods,
                );
                return;
            }

            // ── P5.1: Ctrl+Shift shortcut layer (reserved by GUI_DESIGN §5) ──
            // These are intercepted before forwarding to the session so they
            // never reach the remote shell.  The terminal FocusScope passes all
            // Ctrl+Shift events to `key-input` (only Ctrl+K is intercepted in
            // Slint); we catch them here.
            let ctrl_shift =
                mods & (input::MOD_CTRL | input::MOD_SHIFT) == (input::MOD_CTRL | input::MOD_SHIFT);
            if ctrl_shift {
                let t = text.as_str();
                match (special, t) {
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
                    // Ctrl+Shift+Up → focus pane up (prev; intuitive for VSplit).
                    (5, _) => {
                        let new_focus = {
                            let mut st = state.borrow_mut();
                            let active = st.active;
                            if let Some(tab) = st.tabs.get_mut(active) {
                                tab.pane_group.focus_move(-1)
                            } else {
                                return;
                            }
                        };
                        ui.set_active_pane(new_focus as i32);
                        return;
                    }
                    // Ctrl+Shift+Down → focus pane down (next; intuitive for VSplit).
                    (6, _) => {
                        let new_focus = {
                            let mut st = state.borrow_mut();
                            let active = st.active;
                            if let Some(tab) = st.tabs.get_mut(active) {
                                tab.pane_group.focus_move(1)
                            } else {
                                return;
                            }
                        };
                        ui.set_active_pane(new_focus as i32);
                        return;
                    }
                    // Ctrl+Shift+Left → focus pane left (prev; intuitive for HSplit).
                    (7, _) => {
                        let new_focus = {
                            let mut st = state.borrow_mut();
                            let active = st.active;
                            if let Some(tab) = st.tabs.get_mut(active) {
                                tab.pane_group.focus_move(-1)
                            } else {
                                return;
                            }
                        };
                        ui.set_active_pane(new_focus as i32);
                        return;
                    }
                    // Ctrl+Shift+Right → focus pane right (next; intuitive for HSplit).
                    (8, _) => {
                        let new_focus = {
                            let mut st = state.borrow_mut();
                            let active = st.active;
                            if let Some(tab) = st.tabs.get_mut(active) {
                                tab.pane_group.focus_move(1)
                            } else {
                                return;
                            }
                        };
                        ui.set_active_pane(new_focus as i32);
                        return;
                    }
                    // Ctrl+Shift+W → close focused pane (detach = false → shutdown).
                    (0, "w" | "W") => {
                        panes::do_close_pane(&state, &tab_model_kb, &ui, false);
                        return;
                    }
                    // Ctrl+Shift+D → detach session (keep session alive).
                    (0, "d" | "D") => {
                        panes::do_close_pane(&state, &tab_model_kb, &ui, true);
                        return;
                    }
                    // Ctrl+Shift+C → copy the focused pane's selection (P6.5).
                    (0, "c" | "C") => {
                        do_copy(&state);
                        return;
                    }
                    // Ctrl+Shift+V → paste the OS clipboard (P6.5).
                    (0, "v" | "V") => {
                        do_paste(&state);
                        return;
                    }
                    _ => {}
                }
                // P6.9 (gap 17) — direct shortcuts on this same reserved layer, kept
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
                    CtrlShiftAction::NextTab => {
                        let n = tab_model_kb.row_count();
                        if n > 0 {
                            let next = (ui.get_active_tab() as usize + 1) % n;
                            tabs::select_tab(&state, &ui, next as i32);
                        }
                        return;
                    }
                    CtrlShiftAction::JumpToTab(idx) => {
                        if idx < tab_model_kb.row_count() {
                            tabs::select_tab(&state, &ui, idx as i32);
                        }
                        return;
                    }
                    CtrlShiftAction::None => {}
                }
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
                // ── Broadcast: fan to ALL pane sessions ──────────────────────
                if ui.get_broadcast_active() {
                    // Send to primary + every extra pane.  The focused pane is
                    // already covered here, so we return to avoid a double-send.
                    for ev in &evs {
                        tab.session.send_input(ev.clone());
                    }
                    for ep in &tab.extra_panes {
                        for ev in &evs {
                            ep.session.send_input(ev.clone());
                        }
                    }
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

/// The new P6.9 (gap 17) Ctrl+Shift shortcuts, as a pure `(special, text)` ->
/// action classifier -- kept separate from `wire_key_input`'s dispatch so the
/// decision is unit-testable without a live `AppWindow`/session `State`.
/// `special`/`text` are the same encoding `TerminalSurface.key-pressed`
/// packs in `app.slint` (see `crate::input::map_key`'s doc comment).
#[derive(Debug, PartialEq, Eq)]
pub(super) enum CtrlShiftAction {
    /// Ctrl+Shift+T — open a new local tab.
    NewTab,
    /// Ctrl+Shift+E — toggle the side panel.
    ToggleSidebar,
    /// Ctrl+Shift+Tab — switch to the next tab (wraps around).
    NextTab,
    /// Ctrl+Shift+1..9 — jump directly to the Nth tab (0-based index here;
    /// the shortcut itself is 1-based, i.e. Ctrl+Shift+1 -> `JumpToTab(0)`).
    JumpToTab(usize),
    /// Not one of this layer's direct shortcuts (falls through to the older
    /// P5.1 split/broadcast/close/detach/focus-move arms, or to the session).
    None,
}

pub(super) fn classify_ctrl_shift_shortcut(special: i32, text: &str) -> CtrlShiftAction {
    match (special, text) {
        (0, "t" | "T") => CtrlShiftAction::NewTab,
        (0, "e" | "E") => CtrlShiftAction::ToggleSidebar,
        (2, _) => CtrlShiftAction::NextTab,
        (0, digit)
            if digit.len() == 1
                && digit.chars().next().is_some_and(|c| c.is_ascii_digit())
                && digit != "0" =>
        {
            // Safe: guarded above to be exactly one ASCII digit '1'..='9'.
            let d = digit
                .chars()
                .next()
                .and_then(|c| c.to_digit(10))
                .unwrap_or(1);
            CtrlShiftAction::JumpToTab((d as usize).saturating_sub(1))
        }
        _ => CtrlShiftAction::None,
    }
}

/// P6.5: copy the focused pane's live selection to the OS clipboard
/// (`Ctrl⇧C`). A no-op when nothing is selected — never overwrites the
/// clipboard with an empty string. Does not clear the selection (pinned
/// lifecycle rule: "copying does not clear").
fn do_copy(state: &Rc<RefCell<State>>) {
    let mut st = state.borrow_mut();
    let active = st.active;
    let Some(tab) = st.tabs.get(active) else {
        return;
    };
    let focused = tab.pane_group.focused();
    let text = if focused == 0 {
        tab.last.as_ref().and_then(|snap| tab.sel.copy_text(snap))
    } else {
        tab.extra_panes
            .get(focused - 1)
            .and_then(|ep| ep.last.as_ref().and_then(|snap| ep.sel.copy_text(snap)))
    };
    if let Some(text) = text {
        st.sys_clipboard.set_text(text);
    }
}

/// P6.5: paste the OS clipboard into the focused pane (`Ctrl⇧V`, and
/// middle-click on Linux — see [`wire_pointer`]). Routed through
/// `SessionInput::Paste` -> `TerminalSession::paste()`, which
/// bracketed-paste-wraps at the engine/session layer when the app enabled
/// DECSET 2004 (raw otherwise — see `cm_session::engine_owner::wrap_paste`).
fn do_paste(state: &Rc<RefCell<State>>) {
    let mut st = state.borrow_mut();
    let Some(text) = st.sys_clipboard.get_text() else {
        return;
    };
    if text.is_empty() {
        return;
    }
    let active = st.active;
    let Some(tab) = st.tabs.get(active) else {
        return;
    };
    let focused = tab.pane_group.focused();
    let bytes = text.into_bytes();
    if focused == 0 {
        tab.session.send_input(SessionInput::Paste(bytes));
    } else if let Some(ep) = tab.extra_panes.get(focused - 1) {
        ep.session.send_input(SessionInput::Paste(bytes));
    } else {
        tab.session.send_input(SessionInput::Paste(bytes));
    }
}

/// Mouse button discriminant for a middle-click (see `input::map_mouse`'s
/// button encoding, mirrored here since this file, not `input.rs`, decides
/// what a middle-click *does* on the terminal surface).
const BTN_MIDDLE: i32 = 3;
const KIND_PRESS: i32 = 1;

/// Whether the pane currently focused in `tab` is a terminal surface (as
/// opposed to an RDP framebuffer, which has no selection/paste concept).
/// Extra panes are terminal-only in practice today (RDP-in-a-split-pane is a
/// noted unimplemented edge case — see `tick_tab`'s framebuffer-drain
/// comment), but this checks the real surface rather than assuming it.
fn focused_surface_is_terminal(tab: &Tab) -> bool {
    let focused = tab.pane_group.focused();
    let surf = if focused == 0 {
        tab.session.surface()
    } else {
        match tab.extra_panes.get(focused - 1) {
            Some(ep) => ep.session.surface(),
            None => tab.session.surface(),
        }
    };
    matches!(surf, Surface::TerminalGrid(_))
}

fn wire_pointer(ctx: &Ctx) {
    ctx.ui.on_pointer({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |button, kind, x, y, mods| {
            let now = Instant::now();

            // P6.5: middle-click paste (Linux convenience — the regular OS
            // clipboard, not the X11 PRIMARY selection; see the task report's
            // note on that simplification). Checked read-only up front so it
            // never fights the mutable pass below over the borrow.
            if button == BTN_MIDDLE && kind == KIND_PRESS {
                let is_terminal = {
                    let st = state.borrow();
                    st.tabs
                        .get(st.active)
                        .is_some_and(focused_surface_is_terminal)
                };
                if is_terminal {
                    do_paste(&state);
                }
                return;
            }

            let mut st = state.borrow_mut();
            let active = st.active;
            let base_scale = st.scale;
            let (surface_w, surface_h) = (st.surface_w, st.surface_h);
            let Some(tab) = st.tabs.get_mut(active) else {
                return;
            };
            let focused = tab.pane_group.focused();
            // P6.8 bundled fix (F-perf, P6.17 finding R1): only the
            // selection-highlight path below needs a forced render (the
            // engine's own output still drives the normal tick-loop redraw).
            // Tracking whether *this* event actually changed the selection
            // means a plain button-less hover move -- no selection, no mouse
            // event forwarded -- no longer forces a full-grid raster.
            let mut selection_changed = false;

            if focused == 0 || tab.extra_panes.get(focused - 1).is_none() {
                // Primary pane (or an out-of-range focus index — defensive
                // fallback matching the pre-P6.5 behavior).
                match tab.session.surface() {
                    Surface::TerminalGrid(_) => {
                        let (row, col) = tab.renderer.cell_at(x * base_scale, y * base_scale);
                        let snap = tab.last.as_ref();
                        selection_changed = tab.sel.on_pointer(button, kind, (row, col), snap, now);
                        if let Some(ev) = input::map_mouse(button, kind, row, col, mods) {
                            tab.session.send_input(SessionInput::Mouse(ev));
                        }
                    }
                    Surface::Framebuffer(_) => {
                        let coords = input::RdpCoords {
                            surface_w,
                            surface_h,
                            rdp_w: tab.rdp_w,
                            rdp_h: tab.rdp_h,
                        };
                        let events = input::map_rdp_mouse(button, kind, x, y, &coords);
                        if !events.is_empty() {
                            tab.session.send_input(SessionInput::Rdp(events));
                        }
                    }
                }
            } else {
                let ep_idx = focused - 1;
                let ep = &mut tab.extra_panes[ep_idx];
                if matches!(ep.session.surface(), Surface::TerminalGrid(_)) {
                    let (row, col) = ep.renderer.cell_at(x * ep.scale, y * ep.scale);
                    let snap = ep.last.as_ref();
                    selection_changed = ep.sel.on_pointer(button, kind, (row, col), snap, now);
                    if let Some(ev) = input::map_mouse(button, kind, row, col, mods) {
                        ep.session.send_input(SessionInput::Mouse(ev));
                    }
                }
            }

            // P6.5: a selection change has no new `GridSnapshot` of its own
            // (nothing was typed), so the tick loop's snapshot-driven redraw
            // would never pick it up — force one render now against the
            // pane's last known snapshot so the highlight (or its removal)
            // appears immediately rather than waiting for the next
            // unrelated output event. P6.8: gated on `selection_changed` so a
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
            let st = state.borrow();
            // Terminal scroll only — RDP scroll is handled by on_rdp_scroll (fix c).
            if let Some(tab) = st.tabs.get(st.active)
                && matches!(tab.session.surface(), Surface::TerminalGrid(_))
                && let Some(ev) = input::map_scroll(dy, 0, 0, 0)
            {
                tab.session.send_input(SessionInput::Mouse(ev));
            }
        }
    });
}

fn wire_rdp_scroll(ctx: &Ctx) {
    ctx.ui.on_rdp_scroll({
        let state = ctx.state.clone();
        move |x, y, _dx, dy| {
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active)
                && matches!(tab.session.surface(), Surface::Framebuffer(_))
            {
                let w = st.surface_w;
                let h = st.surface_h;
                let rdp_w = tab.rdp_w;
                let rdp_h = tab.rdp_h;
                let coords = input::RdpCoords {
                    surface_w: w,
                    surface_h: h,
                    rdp_w,
                    rdp_h,
                };
                // Use actual pointer position instead of surface centre.
                let events = input::map_rdp_scroll(dy, x, y, &coords);
                if !events.is_empty() {
                    tab.session.send_input(SessionInput::Rdp(events));
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

fn wire_qc_connect(ctx: &Ctx) {
    ctx.ui.on_qc_connect({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        let hk_pending = ctx.hk_pending.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let host = ui.get_qc_host().trim().to_owned();
            let port_str = ui.get_qc_port().trim().to_owned();
            let username = ui.get_qc_username().trim().to_owned();
            let auth_method = ui.get_qc_auth_method();
            let secret_raw = ui.get_qc_secret().to_string();
            let pass_raw = ui.get_qc_passphrase().to_string();
            if host.is_empty() || username.is_empty() {
                return;
            }
            let port = port_str.parse::<u16>().unwrap_or(22);
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
                _ => SshAuthInput::Agent,
            };
            let settings = SshSettings {
                host,
                port,
                username,
                auth_method: SshAuthMethod::Password,
            };
            ui.set_quick_connect_open(false);
            ui.set_qc_secret(Default::default());
            ui.set_qc_passphrase(Default::default());
            let auto_accept = util::ssh_auto_accept_keys();
            let verifier = Arc::new(UiHostKeyVerifier {
                weak_ui: weak.clone(),
                pending: hk_pending.clone(),
                auto_accept,
            });
            // Quick-connect has no originating stored profile to edit on failure.
            open_ssh_tab(
                &state,
                &tab_model,
                &ui,
                settings,
                auth,
                AuthProvenance::Direct,
                verifier,
                None,
            );
        }
    });
}

fn wire_host_key_accept(ctx: &Ctx) {
    ctx.ui.on_host_key_accept({
        let pending = ctx.hk_pending.clone();
        let weak = ctx.ui.as_weak();
        move || {
            // Pop the front sender (oldest pending request) — carry-over fix (a).
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
            // Pop the front sender (oldest pending request) — carry-over fix (a).
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

fn wire_rdp_key_down(ctx: &Ctx) {
    ctx.ui.on_rdp_key_down({
        let state = ctx.state.clone();
        move |text, special, mods| {
            // Local→remote clipboard sync: intercept Ctrl+V, announce our clipboard.
            if mods & input::MOD_CTRL != 0 && text.as_str().eq_ignore_ascii_case("v") {
                let paste_text = state.borrow_mut().sys_clipboard.get_text();
                if let Some(text_to_paste) = paste_text {
                    let st = state.borrow();
                    if let Some(tab) = st.tabs.get(st.active) {
                        tab.session
                            .send_input(SessionInput::RdpPaste(text_to_paste));
                    }
                }
                // Fall through: also send the Ctrl+V scancodes so the remote app triggers
                // a clipboard request after we've announced our content.
            }
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active) {
                let events = input::map_rdp_key_down(text.as_str(), special, mods);
                if !events.is_empty() {
                    tab.session.send_input(SessionInput::Rdp(events));
                }
            }
        }
    });
}

fn wire_rdp_key_up(ctx: &Ctx) {
    ctx.ui.on_rdp_key_up({
        let state = ctx.state.clone();
        move |text, special, mods| {
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active) {
                let events = input::map_rdp_key_up(text.as_str(), special, mods);
                if !events.is_empty() {
                    tab.session.send_input(SessionInput::Rdp(events));
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
/// stored-credential connect path (P6.4) used by both a tree-row click
/// ([`wire_row_activated`]) and the `CONMAN_TREE_AUTOLAUNCH` QA hook
/// (`controller/util.rs`) — both must exercise the identical
/// resolve-then-connect logic, never a placeholder/empty credential.
///
/// Also sets `origin_connection_id` (P6.9 gap 16) on every tab this produces —
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
    // P6.9 (gap 16): remember which stored profile this tab came from so the
    // ErrorOverlay "Edit…" button can reopen it on failure.
    let origin_connection_id = Some(conn.id.get() as i32);
    match &conn.settings {
        ConnectionSettings::Local(_) => tabs::open_local_tab(state, tab_model, ui),
        ConnectionSettings::Ssh(s) => {
            let resolved = {
                let st = state.borrow();
                resolve_ssh_auth(conn, st.conn_tree.groups(), s, secrets.as_ref())
            };
            match resolved {
                Ok(auth) => {
                    let auto_accept = util::ssh_auto_accept_keys();
                    let verifier = Arc::new(UiHostKeyVerifier {
                        weak_ui: weak.clone(),
                        pending: hk_pending.clone(),
                        auto_accept,
                    });
                    open_ssh_tab(
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
                resolve_rdp_auth(conn, st.conn_tree.groups(), s, secrets.as_ref())
            };
            match resolved {
                Ok(auth) => {
                    let auto_accept = util::rdp_auto_accept_certs();
                    let verifier = Arc::new(UiCertVerifier {
                        weak_ui: weak.clone(),
                        pending: cert_pending.clone(),
                        auto_accept,
                    });
                    open_rdp_tab(
                        state,
                        tab_model,
                        ui,
                        s.clone(),
                        auth,
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
}

fn wire_reconnect(ctx: &Ctx) {
    ctx.ui.on_reconnect({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        let hk_pending = ctx.hk_pending.clone();
        let secrets = ctx.secrets.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            // P6.4: `Credential`-sourced auth is re-resolved fresh here (never
            // cached as plaintext in `Tab` state) — `Direct` (quick-connect)
            // just clones the typed input as before.
            let resolved = {
                let st = state.borrow();
                let idx = st.active;
                st.tabs
                    .get(idx)
                    .and_then(|t| t.connect_info.as_ref())
                    .map(|ci| {
                        let settings = ci.settings.clone();
                        let (provenance, auth_result) = match &ci.auth_source {
                            SshAuthSource::Direct(a) => (AuthProvenance::Direct, Ok(a.clone())),
                            SshAuthSource::Credential(conn_id) => {
                                let result = st
                                    .conn_tree
                                    .connections()
                                    .iter()
                                    .find(|c| c.id == *conn_id)
                                    .ok_or(AuthResolveError::NoCredentialAssigned)
                                    .and_then(|c| {
                                        resolve_ssh_auth(
                                            c,
                                            st.conn_tree.groups(),
                                            &settings,
                                            secrets.as_ref(),
                                        )
                                    });
                                (AuthProvenance::Credential(*conn_id), result)
                            }
                        };
                        (idx, settings, provenance, auth_result)
                    })
            };
            let Some((active_idx, settings, provenance, auth_result)) = resolved else {
                return;
            };
            // Either way the old session is done — shut it down before
            // deciding whether a fresh connect attempt or the auth-error
            // overlay follows.
            {
                let st = state.borrow();
                if let Some(tab) = st.tabs.get(active_idx) {
                    tab.session.shutdown();
                }
            }
            match auth_result {
                Ok(auth) => {
                    let auto_accept = util::ssh_auto_accept_keys();
                    let verifier = Arc::new(UiHostKeyVerifier {
                        weak_ui: weak.clone(),
                        pending: hk_pending.clone(),
                        auto_accept,
                    });
                    reconnect_ssh_tab(
                        &state, &tab_model, &ui, active_idx, settings, auth, provenance, verifier,
                    );
                }
                Err(e) => {
                    fail_reconnect_in_place(&state, &tab_model, &ui, active_idx, e.to_string());
                }
            }
        }
    });
}

pub(super) struct UiHostKeyVerifier {
    pub(super) weak_ui: slint::Weak<AppWindow>,
    pub(super) pending: HkQueue,
    pub(super) auto_accept: bool,
}

impl HostKeyVerifier for UiHostKeyVerifier {
    fn decide(&self, info: &HostKeyInfo) -> HostKeyDecision {
        if self.auto_accept {
            return HostKeyDecision::Accept;
        }
        let (tx, rx) = std::sync::mpsc::channel::<HostKeyDecision>();
        if let Ok(mut q) = self.pending.lock() {
            q.push_back(tx);
        }
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
        rx.recv().unwrap_or(HostKeyDecision::Reject)
    }
}

/// Shows the cert-accept dialog (P4.2 slint UI) and blocks the RDP connection
/// thread until the user accepts or rejects.
///
/// When `auto_accept` is `true` (debug builds only, set via
/// `CONMAN_RDP_AUTO_ACCEPT_CERTS=1` — see `util::rdp_auto_accept_certs`,
/// P6.3 gap 24) the verifier immediately returns `AcceptAndRemember` without
/// showing the dialog — useful for headless CI / screenshot tests. Always
/// `false` in release.
pub(super) struct UiCertVerifier {
    pub(super) weak_ui: slint::Weak<AppWindow>,
    pub(super) pending: Arc<Mutex<Option<Sender<CertDecision>>>>,
    pub(super) auto_accept: bool,
}

impl CertVerifier for UiCertVerifier {
    fn decide(&self, info: &CertInfo) -> CertDecision {
        if self.auto_accept {
            return CertDecision::AcceptAndRemember;
        }
        let (tx, rx) = std::sync::mpsc::channel::<CertDecision>();
        if let Ok(mut p) = self.pending.lock() {
            *p = Some(tx);
        }
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
        rx.recv().unwrap_or(CertDecision::Reject)
    }
}

pub(super) fn render_frame(
    tab: &mut Tab,
    snap: &GridSnapshot,
    target: Option<(u32, u32)>,
) -> Image {
    let sel = tab.sel.selection().copied();
    let buf = match target {
        Some((w, h)) => tab.renderer.render_to_selected(snap, w, h, sel.as_ref()),
        None => tab.renderer.render_selected(snap, sel.as_ref()),
    };
    Image::from_rgba8(buf)
}

pub(crate) fn drain_latest<T>(rx: &Receiver<T>) -> Option<T> {
    let mut latest = None;
    while let Ok(v) = rx.try_recv() {
        latest = Some(v);
    }
    latest
}

// ---------------------------------------------------------------------------
// Stored-credential resolution (P6.4)
// ---------------------------------------------------------------------------

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

/// Fetches the secret for `(credential_id, purpose)`. `Ok(None)` means the
/// purpose was never stored — valid for optional purposes (an SSH key with no
/// passphrase); callers that require the purpose use [`require_secret`].
fn fetch_secret(
    secrets: &dyn cm_core::CredentialStore,
    id: cm_core::CredentialId,
    purpose: CredentialPurpose,
) -> Result<Option<Secret>, AuthResolveError> {
    secrets
        .get(&CredentialRef::new(id, purpose))
        .map_err(|e| AuthResolveError::Backend(e.to_string()))
}

/// Like [`fetch_secret`], but "not stored" is itself the error — for purposes
/// that are mandatory once a credential of the relevant kind is assigned.
fn require_secret(
    secrets: &dyn cm_core::CredentialStore,
    id: cm_core::CredentialId,
    purpose: CredentialPurpose,
) -> Result<Secret, AuthResolveError> {
    fetch_secret(secrets, id, purpose)?.ok_or(AuthResolveError::NotFoundInKeychain)
}

/// Resolves the real [`SshAuthInput`] for a tree-launched SSH connection:
/// [`cm_core::resolve_effective_credential`] (own credential → nearest
/// ancestor group default), then a keychain fetch keyed by credential id +
/// purpose, per `settings.auth_method`. Never falls back to an empty/placeholder
/// password — a missing assignment or keychain entry is a typed
/// [`AuthResolveError`] the caller turns into the auth-error overlay instead
/// of attempting to connect.
pub(super) fn resolve_ssh_auth(
    conn: &Connection,
    groups: &[Group],
    settings: &SshSettings,
    secrets: &dyn cm_core::CredentialStore,
) -> Result<SshAuthInput, AuthResolveError> {
    // Agent auth needs no stored secret (Windows ssh-agent support is P6.13).
    if matches!(settings.auth_method, SshAuthMethod::Agent) {
        return Ok(SshAuthInput::Agent);
    }
    let cred_id = cm_core::resolve_effective_credential(conn, groups)
        .ok_or(AuthResolveError::NoCredentialAssigned)?;
    match settings.auth_method {
        SshAuthMethod::Password => {
            let secret = require_secret(secrets, cred_id, CredentialPurpose::Password)?;
            Ok(SshAuthInput::Password(secret))
        }
        SshAuthMethod::PublicKey { .. } => {
            let key_pem = require_secret(secrets, cred_id, CredentialPurpose::SshKey)?;
            // Passphrase is optional -- CredentialKind::SshKey has none.
            let passphrase = fetch_secret(secrets, cred_id, CredentialPurpose::SshPassphrase)?;
            Ok(SshAuthInput::KeyMaterial {
                key_pem,
                passphrase,
            })
        }
        SshAuthMethod::Agent => unreachable!("handled above"),
    }
}

/// Resolves the real [`RdpAuthInput`] for a tree-launched RDP connection:
/// same credential-resolution chain as [`resolve_ssh_auth`], password-only
/// (ConMan has no RDP key-based auth). `username`/`domain` come from the
/// connection's own settings -- the credential holds only the password secret.
pub(super) fn resolve_rdp_auth(
    conn: &Connection,
    groups: &[Group],
    settings: &RdpSettings,
    secrets: &dyn cm_core::CredentialStore,
) -> Result<RdpAuthInput, AuthResolveError> {
    let cred_id = cm_core::resolve_effective_credential(conn, groups)
        .ok_or(AuthResolveError::NoCredentialAssigned)?;
    let password = require_secret(secrets, cred_id, CredentialPurpose::Password)?;
    Ok(RdpAuthInput {
        username: settings.username.clone().unwrap_or_default(),
        password,
        domain: settings.domain.clone(),
    })
}

/// Sets the error-overlay UI state for `reason` -- shared by the synchronous
/// connect-failure branches and the P6.4 credential-resolution failure paths
/// below.
fn set_error_overlay(ui: &AppWindow, reason: &str) {
    ui.set_overlay_connecting(false);
    ui.set_overlay_error(true);
    ui.set_launchpad_open(false);
    ui.set_error_reason(SharedString::from(reason));
    ui.set_error_detail(SharedString::from(""));
}

/// Pushes a new `Failed` tab for a credential-resolution error (P6.4) --
/// mirrors the synchronous-setup-error handling in [`open_ssh_tab`] but never
/// attempts a network connection with a placeholder/empty credential.
/// `origin_connection_id` is threaded through unchanged (P6.9 gap 16) so the
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
    tabs::push_tab(
        state,
        tab_model,
        ui,
        tabs::PushTabArgs {
            session: Box::new(FailedSession::new(reason.clone())),
            connect_info: None,
            is_remote: true,
            rdp_clipboard: None,
            title,
            initial_status: "error",
            origin_connection_id,
        },
    );
    ui.set_session_identity(SharedString::from(identity));
    ui.set_rdp_active(false);
    set_error_overlay(ui, &reason);
}

/// Replaces the active tab's session with a `Failed` one after a reconnect's
/// credential re-resolution fails (P6.4). The caller has already shut down
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
    let identity = format!("{}@{}:{}", settings.username, settings.host, settings.port);
    let title = format!("SSH {}", settings.host);
    // Only `Direct` (quick-connect / debug autoinit) clones the auth for
    // reconnect -- `Credential`-sourced auth is re-resolved fresh each time
    // (P6.4: never cache the fetched secret in `Tab` state).
    let auth_source = match provenance {
        AuthProvenance::Direct => SshAuthSource::Direct(auth.clone()),
        AuthProvenance::Credential(id) => SshAuthSource::Credential(id),
    };
    match SshTerminalSession::connect(&settings, auth, verifier, KnownHosts::with_defaults(), size)
    {
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
                    session: Box::new(session),
                    connect_info: Some(ci),
                    is_remote: true,
                    rdp_clipboard: None,
                    title,
                    initial_status: "connecting",
                    origin_connection_id,
                },
            );
            ui.set_session_identity(SharedString::from(identity));
            ui.set_overlay_connecting(true);
            ui.set_overlay_error(false);
            ui.set_launchpad_open(false);
            ui.set_connecting_kind(SharedString::from("SSH"));
            ui.set_rdp_active(false);
        }
        Err(e) => {
            // Carry-over fix (b): surface synchronous setup errors as a Failed
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

pub(super) fn open_rdp_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    settings: RdpSettings,
    auth: RdpAuthInput,
    verifier: Arc<dyn CertVerifier>,
    origin_connection_id: Option<i32>,
) {
    let title = format!("RDP {}", settings.host);
    let identity = format!("{}@{}:{}", auth.username, settings.host, settings.port);
    // Use a persistent cert store in the OS app-data dir so accepted certs survive restarts.
    let cert_store = {
        let path = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("conman")
            .join("cert_trust.json");
        CertStore::new_persistent(path)
    };
    let session = match RdpSession::connect(&settings, auth, verifier, cert_store) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("RDP connect error: {e}");
            return;
        }
    };
    // Retain a reference to the drive thread's clipboard slot for remote→local sync.
    let rdp_clipboard = Some(Arc::clone(&session.remote_clipboard));
    tabs::push_tab(
        state,
        tab_model,
        ui,
        tabs::PushTabArgs {
            session: Box::new(session),
            connect_info: None,
            is_remote: true,
            rdp_clipboard,
            title,
            initial_status: "connecting",
            origin_connection_id,
        },
    );
    ui.set_session_identity(SharedString::from(identity));
    ui.set_overlay_connecting(true);
    ui.set_overlay_error(false);
    ui.set_launchpad_open(false);
    ui.set_connecting_kind(SharedString::from("RDP"));
    ui.set_rdp_active(true);
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
    let identity = format!("{}@{}:{}", settings.username, settings.host, settings.port);
    let auth_source = match provenance {
        AuthProvenance::Direct => SshAuthSource::Direct(auth.clone()),
        AuthProvenance::Credential(id) => SshAuthSource::Credential(id),
    };
    match SshTerminalSession::connect(&settings, auth, verifier, KnownHosts::with_defaults(), size)
    {
        Ok(new_session) => {
            let ci = SshConnectInfo {
                settings,
                auth_source,
            };
            {
                let mut st = state.borrow_mut();
                if let Some(tab) = st.tabs.get_mut(tab_idx) {
                    tab.session = Box::new(new_session);
                    tab.connect_info = Some(ci);
                    tab.last = None;
                }
            }
            if let Some(mut item) = tab_model.row_data(tab_idx) {
                item.status = SharedString::from("connecting");
                tab_model.set_row_data(tab_idx, item);
            }
            ui.set_session_identity(SharedString::from(identity));
            ui.set_overlay_connecting(true);
            ui.set_overlay_error(false);
            ui.set_connecting_kind(SharedString::from("SSH"));
        }
        Err(e) => {
            tracing::warn!("SSH reconnect error: {e}");
            ui.set_error_reason(SharedString::from(e.to_string()));
        }
    }
}

/// Drain and render one tab's surfaces (primary + extra panes), sync its
/// status dot / overlays / toast, and report whether it should be queued for
/// closing (local shell that has exited).
///
/// Extracted from [`tick`]'s per-tab loop body (P6.1 function-size budget) --
/// pure code move, identical logic, same field-by-field mutation of `st`. The
/// 8-parameter signature mirrors `tick`'s own (state access + the 3 model/ui
/// handles it forwards); bundling them would be a needless intermediate type
/// for a single private call site.
#[allow(clippy::too_many_arguments)]
fn tick_tab(
    st: &mut State,
    i: usize,
    active: usize,
    target: Option<(u32, u32)>,
    tab_model: &Rc<VecModel<TabItem>>,
    toast_model: &Rc<VecModel<ToastEntry>>,
    toast_next_id: &Rc<RefCell<i32>>,
    ui: &AppWindow,
) -> bool {
    // P6.5 selection lifecycle, "clears on focus change": a pane-focus switch
    // (Ctrl+Shift+arrow, or clicking a different pane) invalidates every
    // pane's selection in this tab — cheap and simple, and correct since a
    // selection is only ever meaningful while its pane is the one receiving
    // input. Checked every tick rather than at each focus-changing call site
    // so this stays entirely within this file (`sessions.rs`) regardless of
    // which controller module actually calls `PaneGroup::set_focused`.
    let focused_now = st.tabs[i].pane_group.focused();
    if st.tabs[i].last_focused_pane != focused_now {
        st.tabs[i].sel.clear();
        for ep in &mut st.tabs[i].extra_panes {
            ep.sel.clear();
        }
        st.tabs[i].last_focused_pane = focused_now;
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
                }
                st.tabs[i].last = Some(snap);
            }
        }
        Surface::Framebuffer(rx) => {
            if let Some(frame) = drain_latest(rx) {
                let img = frame_to_image(&frame);
                if i == active {
                    ui.set_rdp_frame(img.clone());
                }
                st.tabs[i].last_frame = Some(img);
                st.tabs[i].rdp_w = frame.width;
                st.tabs[i].rdp_h = frame.height;
            }
            // Remote→local clipboard sync: poll slot written by the drive thread.
            if let Some(ref arc) = st.tabs[i].rdp_clipboard.clone()
                && let Ok(mut slot) = arc.try_lock()
                && let Some(text) = slot.take()
            {
                st.sys_clipboard.set_text(text);
            }
        }
    }

    // P5.1: Drain extra pane surfaces (pane 1+).
    // Carry-over fix (f): collect extra panes that have Exited/Failed for collapse.
    let mut extra_panes_to_close: Vec<usize> = Vec::new();
    for ep_idx in 0..st.tabs[i].extra_panes.len() {
        match st.tabs[i].extra_panes[ep_idx].session.surface() {
            Surface::TerminalGrid(rx) => {
                if let Some(snap) = drain_latest(rx) {
                    st.tabs[i].extra_panes[ep_idx]
                        .sel
                        .invalidate_if_stale(&snap);
                    if i == active {
                        // ep_idx 0 = pane 1 → pane-frame-2.
                        if ep_idx == 0 {
                            let ep = &mut st.tabs[i].extra_panes[ep_idx];
                            let ep_target = if ep.surface_w > 0.0 && ep.surface_h > 0.0 {
                                Some((
                                    (ep.surface_w * ep.scale).round().max(1.0) as u32,
                                    (ep.surface_h * ep.scale).round().max(1.0) as u32,
                                ))
                            } else {
                                None
                            };
                            let img = render_frame_ep(ep, &snap, ep_target);
                            ui.set_pane_frame_2(img);
                        }
                    }
                    st.tabs[i].extra_panes[ep_idx].last = Some(snap);
                }
            }
            Surface::Framebuffer(rx) => {
                // Drain but discard (RDP-in-pane is an unimplemented edge case; noted).
                drain_latest(rx);
            }
        }
        // Auto-collapse extra pane when its local shell exits/fails (fix f).
        let ep_status = st.tabs[i].extra_panes[ep_idx].session.status();
        if matches!(
            ep_status,
            SessionStatus::Exited(_) | SessionStatus::Failed(_)
        ) {
            extra_panes_to_close.push(ep_idx);
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
        // P5.3b: emit a toast when a background tab disconnects/fails.
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
    }

    if i == active {
        overlays::update_overlays_from_status(ui, &st.tabs[i], &status);
    }

    !st.tabs[i].is_remote && matches!(status, SessionStatus::Exited(_))
}

pub(super) fn tick(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    toast_model: &Rc<VecModel<ToastEntry>>,
    toast_next_id: &Rc<RefCell<i32>>,
    ui: &AppWindow,
) {
    let mut st = state.borrow_mut();
    let active = st.active;
    let target = st.target_px();
    let mut to_close: Vec<usize> = Vec::new();

    // P6.5 selection lifecycle, "clears on focus change": a tab switch
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
        st.last_active_tab = active;
    }

    for i in 0..st.tabs.len() {
        if tick_tab(
            &mut st,
            i,
            active,
            target,
            tab_model,
            toast_model,
            toast_next_id,
            ui,
        ) {
            to_close.push(i);
        }
    }

    // P5.1: Drain detached sessions to prevent channel saturation.
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

/// Re-push the light/dark terminal palette to every open renderer (primary pane +
/// extra panes, across all tabs) on a live app theme switch (P6.8, gap 9 — closes
/// P6.17 finding V1: "theme switch recolors both chrome and terminal").
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
                if let Some(snap) = tab.last.clone() {
                    let img = render_frame(tab, &snap, target);
                    ui.set_frame(img);
                }
                ui.set_rdp_active(false);
            }
            Surface::Framebuffer(_) => {
                if let Some(img) = tab.last_frame.clone() {
                    ui.set_rdp_frame(img);
                }
                ui.set_rdp_active(true);
            }
        }
        // P5.1: Render extra pane(s).
        for (ep_idx, ep) in tab.extra_panes.iter_mut().enumerate() {
            if ep_idx == 0 {
                // pane 1 → pane-frame-2
                if let Some(snap) = ep.last.clone() {
                    let ep_target = if ep.surface_w > 0.0 && ep.surface_h > 0.0 {
                        Some((
                            (ep.surface_w * ep.scale).round().max(1.0) as u32,
                            (ep.surface_h * ep.scale).round().max(1.0) as u32,
                        ))
                    } else {
                        None
                    };
                    let img = render_frame_ep(ep, &snap, ep_target);
                    ui.set_pane_frame_2(img);
                }
            }
        }
    }
}

pub(super) fn render_frame_ep(
    ep: &mut ExtraPaneState,
    snap: &GridSnapshot,
    target: Option<(u32, u32)>,
) -> Image {
    let sel = ep.sel.selection().copied();
    let buf = match target {
        Some((w, h)) => ep.renderer.render_to_selected(snap, w, h, sel.as_ref()),
        None => ep.renderer.render_selected(snap, sel.as_ref()),
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
    Image::from_rgba8(buf)
}

pub(super) fn wire_tick(ctx: &Ctx) -> Timer {
    let redraw = Timer::default();
    let state = ctx.state.clone();
    let tab_model = ctx.tab_model.clone();
    let toast_model = ctx.toast_model.clone();
    let toast_next_id = ctx.toast_next_id.clone();
    let weak = ctx.ui.as_weak();
    redraw.start(TimerMode::Repeated, REDRAW_INTERVAL, move || {
        if let Some(ui) = weak.upgrade() {
            tick(&state, &tab_model, &toast_model, &toast_next_id, &ui);
        }
    });
    redraw
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::mpsc;

    use cm_core::{ConnectionId, ConnectionKind, CredentialError, CredentialId, GroupId};

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

    // ── gap 17: Ctrl+Shift direct-shortcut classifier ───────────────────

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
    fn ctrl_shift_tab_is_next_tab() {
        // special == 2 is the Tab key (see `input::map_key`'s special-code table);
        // the text payload is irrelevant for this arm.
        assert_eq!(
            classify_ctrl_shift_shortcut(2, ""),
            CtrlShiftAction::NextTab
        );
    }

    #[test]
    fn ctrl_shift_digits_1_to_9_jump_to_zero_based_index() {
        for d in 1..=9 {
            let text = d.to_string();
            assert_eq!(
                classify_ctrl_shift_shortcut(0, &text),
                CtrlShiftAction::JumpToTab(d - 1),
                "Ctrl+Shift+{d} should jump to 0-based index {}",
                d - 1
            );
        }
    }

    #[test]
    fn ctrl_shift_0_is_not_a_tab_jump() {
        // "0" is deliberately excluded -- there is no "tab 0" in 1-based UI counting.
        assert_eq!(classify_ctrl_shift_shortcut(0, "0"), CtrlShiftAction::None);
    }

    #[test]
    fn ctrl_shift_unrelated_keys_fall_through() {
        assert_eq!(classify_ctrl_shift_shortcut(0, "z"), CtrlShiftAction::None);
        assert_eq!(classify_ctrl_shift_shortcut(0, "\\"), CtrlShiftAction::None);
        assert_eq!(classify_ctrl_shift_shortcut(5, ""), CtrlShiftAction::None);
    }

    // -- P6.4: resolve_ssh_auth / resolve_rdp_auth ---------------------------

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
            credential.map(CredentialId::new),
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
            credential.map(CredentialId::new),
            0,
            0,
            0,
        )
        .unwrap()
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
        let auth = resolve_ssh_auth(&conn, &[], &settings, &store).expect("should resolve");
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
        let auth = resolve_ssh_auth(&conn, &[group], &settings, &store)
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
        let auth = resolve_ssh_auth(&conn, &[group], &settings, &store)
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
        let err = resolve_ssh_auth(&conn, &[], &settings, &store)
            .expect_err("should fail: no credential assigned anywhere");
        assert_eq!(err, AuthResolveError::NoCredentialAssigned);
        assert_eq!(err.to_string(), "No credential assigned");
    }

    #[test]
    fn resolve_ssh_auth_credential_missing_from_keychain() {
        let conn = make_ssh_conn(None, Some(2), SshAuthMethod::Password);
        let store = MockCredentialStore::new(); // nothing stored for id 2
        let settings = ssh_settings(SshAuthMethod::Password);
        let err = resolve_ssh_auth(&conn, &[], &settings, &store)
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
        let err = resolve_ssh_auth(&conn, &[], &settings, &store)
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
        let auth =
            resolve_ssh_auth(&conn, &[], &settings, &store).expect("should resolve key material");
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
        let auth = resolve_ssh_auth(&conn, &[], &settings, &store)
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
        let auth = resolve_ssh_auth(&conn, &[], &settings, &store)
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
        let auth = resolve_rdp_auth(&conn, &[], &settings, &store).expect("should resolve");
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
        let auth = resolve_rdp_auth(&conn, &[group], &settings, &store)
            .expect("should resolve via inherited group default");
        assert_eq!(auth.password.expose(), b"grouprdp");
    }

    #[test]
    fn resolve_rdp_auth_no_credential_assigned() {
        let conn = make_rdp_conn(None, None);
        let store = MockCredentialStore::new();
        let settings = RdpSettings::default();
        let err = resolve_rdp_auth(&conn, &[], &settings, &store)
            .expect_err("should fail: no credential assigned anywhere");
        assert_eq!(err, AuthResolveError::NoCredentialAssigned);
    }

    #[test]
    fn resolve_rdp_auth_credential_missing_from_keychain() {
        let conn = make_rdp_conn(None, Some(9));
        let store = MockCredentialStore::new(); // nothing stored for id 9
        let settings = RdpSettings::default();
        let err = resolve_rdp_auth(&conn, &[], &settings, &store)
            .expect_err("should fail: keychain has no entry");
        assert_eq!(err, AuthResolveError::NotFoundInKeychain);
    }
}

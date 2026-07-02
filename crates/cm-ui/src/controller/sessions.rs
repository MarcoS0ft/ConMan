//! Session connect/reconnect paths, host-key/cert verifiers, input routing,
//! and the tick/render pump.
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

use cm_core::terminal::GridSnapshot;
use cm_core::{ConnectionSettings, RdpSettings, Secret, SshAuthMethod, SshSettings};
use cm_session::{
    CertDecision, CertInfo, CertStore, CertVerifier, FailedSession, FrameUpdate, HostKeyDecision,
    HostKeyInfo, HostKeyVerifier, KnownHosts, PaneLayout, RdpAuthInput, RdpSession, Session,
    SessionInput, SessionStatus, SshAuthInput, SshTerminalSession, Surface,
};
use slint::{ComponentHandle, Image, Model, SharedString, Timer, TimerMode, VecModel};

use crate::input;
use crate::terminal_renderer::TerminalRenderer;
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

fn wire_pointer(ctx: &Ctx) {
    ctx.ui.on_pointer({
        let state = ctx.state.clone();
        move |button, kind, x, y, mods| {
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active) {
                let focused = tab.pane_group.focused();
                // Route pointer to the focused pane's session.
                let (session, renderer, scale): (&dyn Session, &TerminalRenderer, f32) =
                    if focused == 0 {
                        (tab.session.as_ref(), &tab.renderer, st.scale)
                    } else {
                        let ep_idx = focused - 1;
                        if let Some(ep) = tab.extra_panes.get(ep_idx) {
                            (ep.session.as_ref(), &ep.renderer, ep.scale)
                        } else {
                            (tab.session.as_ref(), &tab.renderer, st.scale)
                        }
                    };
                match session.surface() {
                    Surface::TerminalGrid(_) => {
                        let (row, col) = renderer.cell_at(x * scale, y * scale);
                        if let Some(ev) = input::map_mouse(button, kind, row, col, mods) {
                            session.send_input(SessionInput::Mouse(ev));
                        }
                    }
                    Surface::Framebuffer(_) => {
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
                        let events = input::map_rdp_mouse(button, kind, x, y, &coords);
                        if !events.is_empty() {
                            session.send_input(SessionInput::Rdp(events));
                        }
                    }
                }
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
            open_ssh_tab(&state, &tab_model, &ui, settings, auth, verifier, None);
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
                let paste_text = state
                    .borrow_mut()
                    .sys_clipboard
                    .as_mut()
                    .and_then(|cb| cb.get_text().ok());
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
            // P6.9 (gap 16): remember which stored profile this tab came from so
            // the ErrorOverlay "Edit…" button can reopen it on failure.
            let origin_connection_id = Some(conn.id.get() as i32);
            match conn.settings {
                ConnectionSettings::Local(_) => tabs::open_local_tab(&state, &tab_model, &ui),
                ConnectionSettings::Ssh(s) => {
                    let auth = SshAuthInput::Password(Secret::from_string(String::new()));
                    let auto_accept = util::ssh_auto_accept_keys();
                    let verifier = Arc::new(UiHostKeyVerifier {
                        weak_ui: weak.clone(),
                        pending: hk_pending.clone(),
                        auto_accept,
                    });
                    open_ssh_tab(
                        &state,
                        &tab_model,
                        &ui,
                        s,
                        auth,
                        verifier,
                        origin_connection_id,
                    );
                }
                ConnectionSettings::Rdp(s) => {
                    let auto_accept = util::rdp_auto_accept_certs();
                    let verifier = Arc::new(UiCertVerifier {
                        weak_ui: weak.clone(),
                        pending: cert_pending.clone(),
                        auto_accept,
                    });
                    // Use username from settings; password from keychain is out of scope.
                    let auth = RdpAuthInput {
                        username: s.username.clone().unwrap_or_default(),
                        password: cm_core::Secret::from_string(String::new()),
                        domain: None,
                    };
                    open_rdp_tab(
                        &state,
                        &tab_model,
                        &ui,
                        s,
                        auth,
                        verifier,
                        origin_connection_id,
                    );
                }
            }
        }
    });
}

fn wire_reconnect(ctx: &Ctx) {
    ctx.ui.on_reconnect({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        let hk_pending = ctx.hk_pending.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let (active_idx, connect_info_opt) = {
                let st = state.borrow();
                let idx = st.active;
                let info = st.tabs.get(idx).and_then(|t| {
                    t.connect_info
                        .as_ref()
                        .map(|c| (c.settings.clone(), c.auth.clone()))
                });
                (idx, info)
            };
            let Some((settings, auth)) = connect_info_opt else {
                return;
            };
            {
                let st = state.borrow();
                if let Some(tab) = st.tabs.get(active_idx) {
                    tab.session.shutdown();
                }
            }
            let auto_accept = util::ssh_auto_accept_keys();
            let verifier = Arc::new(UiHostKeyVerifier {
                weak_ui: weak.clone(),
                pending: hk_pending.clone(),
                auto_accept,
            });
            reconnect_ssh_tab(
                &state, &tab_model, &ui, active_idx, settings, auth, verifier,
            );
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
    let buf = match target {
        Some((w, h)) => tab.renderer.render_to(snap, w, h),
        None => tab.renderer.render(snap),
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

pub(super) fn open_ssh_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    settings: SshSettings,
    auth: SshAuthInput,
    verifier: Arc<dyn HostKeyVerifier>,
    origin_connection_id: Option<i32>,
) {
    let size = state.borrow().current_grid();
    let identity = format!("{}@{}:{}", settings.username, settings.host, settings.port);
    let title = format!("SSH {}", settings.host);
    let auth_for_reconnect = auth.clone();
    match SshTerminalSession::connect(&settings, auth, verifier, KnownHosts::with_defaults(), size)
    {
        Ok(session) => {
            let ci = SshConnectInfo {
                settings,
                auth: auth_for_reconnect,
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
            ui.set_overlay_connecting(false);
            ui.set_overlay_error(true);
            ui.set_launchpad_open(false);
            ui.set_error_reason(SharedString::from(reason));
            ui.set_error_detail(SharedString::from(""));
            ui.set_rdp_active(false);
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

pub(super) fn reconnect_ssh_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    tab_idx: usize,
    settings: SshSettings,
    auth: SshAuthInput,
    verifier: Arc<dyn HostKeyVerifier>,
) {
    let size = state.borrow().current_grid();
    let identity = format!("{}@{}:{}", settings.username, settings.host, settings.port);
    let auth_for_reconnect = auth.clone();
    match SshTerminalSession::connect(&settings, auth, verifier, KnownHosts::with_defaults(), size)
    {
        Ok(new_session) => {
            let ci = SshConnectInfo {
                settings,
                auth: auth_for_reconnect,
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
    // Drain the latest update for this tab's primary surface.
    match st.tabs[i].session.surface() {
        Surface::TerminalGrid(rx) => {
            if let Some(snap) = drain_latest(rx) {
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
            if let (Some(ref arc), Some(ref mut cb)) =
                (st.tabs[i].rdp_clipboard.clone(), st.sys_clipboard.as_mut())
                && let Ok(mut slot) = arc.try_lock()
                && let Some(text) = slot.take()
            {
                let _ = cb.set_text(text);
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
    let buf = match target {
        Some((w, h)) => ep.renderer.render_to(snap, w, h),
        None => ep.renderer.render(snap),
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
    use std::sync::mpsc;

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
}

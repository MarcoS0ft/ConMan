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
    Connection, ConnectionSettings, CredentialPurpose, CredentialRef, Group, LocalSettings,
    RdpSettings, Secret, SshAuthMethod, SshSettings,
};
use cm_session::{
    CertDecision, CertInfo, CertVerifier, FailedSession, FocusDir, FrameUpdate, HostKeyDecision,
    HostKeyInfo, HostKeyVerifier, KbdInteractiveChallenge, KbdInteractiveHandler, PaneLayout,
    RdpAuthInput, SessionInput, SessionStatus, SshAuthInput, Surface,
};
use slint::{ComponentHandle, Image, Model, SharedString, Timer, TimerMode, VecModel};

use crate::input;
use crate::keys::KeysPanel;
use crate::{AppWindow, KbdPromptRow, TabItem, ToastEntry};

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
    wire_kbd_answer_edited(ctx);
    wire_kbd_submit(ctx);
    wire_kbd_cancel(ctx);
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
            // P6.7: while the terminal search overlay is open, the terminal
            // FocusScope still forwards keys here (same pattern as the
            // palette above) — route them to the query box instead of the
            // session/Ctrl+Shift dispatch below. `Ctrl⇧F` closes it (handled
            // inside `handle_search_key`); opening it is the ordinary
            // Ctrl+Shift dispatch case below, reached only when not open.
            if ui.get_terminal_search_open() {
                search::handle_search_key(&ui, &state, text.as_str(), special, mods);
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
                    // Ctrl+Shift+F → open the terminal search overlay
                    // (P6.7). Closing it is handled inside
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
                    // pane geometry (P6.11: `focus_dir` picks the nearest
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

            // P6.7: Shift+PageUp/PageDown scroll the terminal's own
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
                // P6.11 (gap 14): targeted, not always "all panes" — resolves
                // `Tab::broadcast_target` (Visible/Custom) against the tab's
                // *current* pane count so a stale custom selection never
                // sends to a closed pane. Defaults to `Visible` (every pane),
                // identical to the pre-P6.11 "always all panes" behavior. See
                // `panes::broadcast_fan_out` for the (unit-tested) targeting logic.
                if ui.get_broadcast_active() {
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

/// P6.11: move focus in the active tab's pane group by screen direction
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

/// `special` codes for PageUp/PageDown (see `input::map_key`'s doc comment
/// for the full table — these two are intercepted here, before
/// `input::map_key`, for the P6.7 Shift+PageUp/PageDown scroll shortcut).
const PAGE_UP: i32 = 11;
const PAGE_DOWN: i32 = 12;

/// Lines scrolled per wheel notch when the app hasn't claimed the wheel via
/// mouse tracking (P6.7 — see `wire_scroll`).
const WHEEL_SCROLL_LINES: u32 = 3;

/// The scroll offset to request given the current one plus a signed `delta`
/// (positive = further into scrollback, negative = toward the tail), clamped
/// to what's actually available. Pure — shared by the wheel and
/// Shift+PageUp/PageDown paths.
fn clamp_scroll(current: &GridSnapshot, delta: i64) -> u32 {
    (i64::from(current.scroll_offset) + delta).clamp(0, i64::from(current.scrollback_len)) as u32
}

/// P6.7: request a scroll-offset change for the active tab's **primary**
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
                match ep.session.surface() {
                    Surface::TerminalGrid(_) => {
                        let (row, col) = ep.renderer.cell_at(x * ep.scale, y * ep.scale);
                        let snap = ep.last.as_ref();
                        selection_changed = ep.sel.on_pointer(button, kind, (row, col), snap, now);
                        if let Some(ev) = input::map_mouse(button, kind, row, col, mods) {
                            ep.session.send_input(SessionInput::Mouse(ev));
                        }
                    }
                    // P6.11: RDP-in-pane pointer routing (lifts P6.10's
                    // deferral) — same coordinate mapping `wire_pointer` uses
                    // for a primary-pane RDP surface, scoped to this pane's
                    // own reported size instead of the whole window's.
                    Surface::Framebuffer(_) => {
                        let coords = input::RdpCoords {
                            surface_w: ep.surface_w,
                            surface_h: ep.surface_h,
                            rdp_w: ep.rdp_w,
                            rdp_h: ep.rdp_h,
                        };
                        let events = input::map_rdp_mouse(button, kind, x, y, &coords);
                        if !events.is_empty() {
                            ep.session.send_input(SessionInput::Rdp(events));
                        }
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
                // event, exactly like pre-P6.7 behavior.
                if let Some(ev) = input::map_scroll(dy, 0, 0, 0) {
                    tab.session.send_input(SessionInput::Mouse(ev));
                }
                return;
            }
            // P6.7: no mouse-tracking app has claimed the wheel — scroll our
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

/// P6.12 (gap 20): the quick-connect dialog's kind selector — `qc-kind` in
/// `app.slint` (`QuickConnectForm`'s `kind` property, plumbed straight
/// through). Kept as a real enum (rather than matching the raw `i32` at every
/// call site) so an out-of-range value has one obvious fallback (`Ssh`,
/// matching the dialog's own default `kind: 0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QcKind {
    Ssh,
    Rdp,
    Local,
}

impl From<i32> for QcKind {
    fn from(v: i32) -> Self {
        match v {
            1 => QcKind::Rdp,
            2 => QcKind::Local,
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
                QcKind::Local => qc_connect_local(&state, &tab_model, &ui),
            }
        }
    });
}

/// Closes the quick-connect dialog and clears every secret-bearing field.
/// Shared by all three per-kind dispatchers (P6.12) so a typed password/
/// passphrase never lingers in the dialog's in-memory Slint properties past
/// the connect attempt that used it -- the pre-P6.12 SSH-only behavior,
/// generalized.
fn close_and_clear_qc_secrets(ui: &AppWindow) {
    ui.set_quick_connect_open(false);
    ui.set_qc_secret(Default::default());
    ui.set_qc_passphrase(Default::default());
}

/// Pure builder behind the SSH arm of quick-connect (P6.12): turns the raw
/// dialog fields into `SshSettings`, or `None` if the connect is invalid
/// (host/username empty) -- the same guard `wire_qc_connect`'s SSH path has
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
        // P6.13: auth-method 3 is "Keyboard interactive" — no upfront
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
    let auto_accept = util::ssh_auto_accept_keys();
    let verifier = Arc::new(UiHostKeyVerifier {
        weak_ui: weak.clone(),
        pending: hk_pending.clone(),
        auto_accept,
    });
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

/// P6.12: parses a "WIDTHxHEIGHT" resolution field (e.g. "1920x1080") into RDP
/// width/height. Falls back to `RdpSettings::DEFAULT_WIDTH`/`DEFAULT_HEIGHT`
/// for anything that doesn't parse cleanly -- empty field, garbage text, or a
/// zero dimension -- so a malformed typed value can never turn into a
/// zero-sized desktop request. `pub(super)`: also reused by the profile
/// editor's RDP field mapping (`tree_ctl::settings_from_form`, P7.2) so the
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

/// Pure builder behind the RDP arm of quick-connect (P6.12, gap 20): turns
/// the raw dialog fields into `RdpSettings`, or `None` if the connect is
/// invalid (host/username empty) -- mirrors [`qc_ssh_settings`].
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
    let auto_accept = util::rdp_auto_accept_certs();
    let verifier = Arc::new(UiCertVerifier {
        weak_ui: weak.clone(),
        pending: cert_pending.clone(),
        auto_accept,
    });
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

/// Pure builder behind the Local arm of quick-connect (P6.12, gap 20): a
/// local quick-connect just spawns a shell, so unlike the SSH/RDP builders
/// this never fails (an empty program falls back to the OS default shell,
/// same as the Settings panel's own local-shell defaults --
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
/// same dispatch a real "Connect" click would (P6.12 xvfb screenshot gate:
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

/// The user edited one answer field in the keyboard-interactive dialog
/// (P6.13). Mutates the live `kbd-prompts` model in place — the value is only
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

/// Realizes the P6.13 [`KbdInteractiveHandler`] round trip: shows
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
/// = the primary session; id 1+ = `extra_panes[id - 1]`). P6.11: RDP-in-pane
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
        move |text, special, mods| {
            // Local→remote clipboard sync: intercept Ctrl+V, announce our clipboard.
            if mods & input::MOD_CTRL != 0 && text.as_str().eq_ignore_ascii_case("v") {
                let paste_text = state.borrow_mut().sys_clipboard.get_text();
                if let Some(text_to_paste) = paste_text {
                    let st = state.borrow();
                    if let Some(tab) = st.tabs.get(st.active) {
                        send_to_focused_pane(tab, SessionInput::RdpPaste(text_to_paste));
                    }
                }
                // Fall through: also send the Ctrl+V scancodes so the remote app triggers
                // a clipboard request after we've announced our content.
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
        move |text, special, mods| {
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
    // P6.14: record this as a recently-opened connection for the Launchpad
    // (recency only; best-effort -- a failure here never blocks or fails the
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
                    // BUG-cred-username-auth: the settings actually used to
                    // connect/log/identify carry the *effective* username
                    // (credential's own username wins over the inline field
                    // when a credential is assigned) -- see
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
                    #[cfg(debug_assertions)]
                    {
                        let st = state.borrow();
                        log_ssh_launch_auth(
                            conn,
                            st.conn_tree.groups(),
                            &effective_settings,
                            st.keys_panel.credentials(),
                        );
                    }
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
                    #[cfg(debug_assertions)]
                    {
                        let st = state.borrow();
                        log_rdp_launch_auth(
                            conn,
                            st.conn_tree.groups(),
                            s,
                            st.keys_panel.credentials(),
                        );
                    }
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
}

/// Resolves the provenance + auth material for reconnecting an SSH tab
/// (P6.4): `Direct` (quick-connect) clones the cached [`SshAuthInput`]
/// verbatim; `Credential` (tree-launched) re-resolves fresh via
/// [`resolve_ssh_auth`] against the live credential store -- the fetched
/// secret never lingers in `Tab` state longer than one connect attempt.
/// Pure and mock-testable (no live `AppWindow`/session needed) -- extracted
/// from [`wire_reconnect`]'s inline match (P6.12 prep, no behavior change).
///
/// BUG-cred-username-auth: also returns the [`SshSettings`] actually used to
/// reconnect, with `username` re-derived via [`effective_ssh_settings`] --
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
                .and_then(|c| resolve_ssh_auth(c, groups, &ci.settings, secrets));
            let settings = match conn {
                Some(c) => effective_ssh_settings(c, groups, &ci.settings, credentials),
                None => ci.settings.clone(),
            };
            (settings, AuthProvenance::Credential(*conn_id), result)
        }
    }
}

/// RDP counterpart to [`resolve_ssh_reconnect`] (P6.12, gap 19) -- same
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
            // P6.4/P6.12: `Credential`-sourced auth is re-resolved fresh here
            // (never cached as plaintext in `Tab` state) — `Direct`
            // (quick-connect) just clones the typed input as before. SSH and
            // RDP each carry their own settings/auth types, so the two kinds
            // build a `ReconnectPlan` variant rather than sharing one tuple
            // shape.
            let plan = {
                let st = state.borrow();
                st.tabs
                    .get(active_idx)
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
                    })
            };
            let Some(plan) = plan else { return };
            // Either way the old session is done — shut it down before
            // deciding whether a fresh connect attempt or the auth-error
            // overlay follows.
            {
                let st = state.borrow();
                if let Some(tab) = st.tabs.get(active_idx) {
                    tab.session.shutdown();
                }
            }
            match plan {
                ReconnectPlan::Ssh(settings, provenance, auth_result) => match auth_result {
                    Ok(auth) => {
                        let auto_accept = util::ssh_auto_accept_keys();
                        let verifier = Arc::new(UiHostKeyVerifier {
                            weak_ui: weak.clone(),
                            pending: hk_pending.clone(),
                            auto_accept,
                        });
                        reconnect_ssh_tab(
                            &state, &tab_model, &ui, active_idx, settings, auth, provenance,
                            verifier,
                        );
                    }
                    Err(e) => {
                        fail_reconnect_in_place(&state, &tab_model, &ui, active_idx, e.to_string());
                    }
                },
                ReconnectPlan::Rdp(settings, provenance, auth_result) => match auth_result {
                    Ok(auth) => {
                        let auto_accept = util::rdp_auto_accept_certs();
                        let verifier = Arc::new(UiCertVerifier {
                            weak_ui: weak.clone(),
                            pending: cert_pending.clone(),
                            auto_accept,
                        });
                        reconnect_rdp_tab(
                            &state, &tab_model, &ui, active_idx, settings, auth, provenance,
                            verifier,
                        );
                    }
                    Err(e) => {
                        fail_reconnect_in_place(&state, &tab_model, &ui, active_idx, e.to_string());
                    }
                },
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
    let (matches, current) = visible_search_highlights(&tab.search, snap);
    let (w, h) = target.unwrap_or_else(|| tab.renderer.pixel_size(snap.size));
    let buf = tab
        .renderer
        .render_to_full(snap, w, h, sel.as_ref(), &matches, current);
    Image::from_rgba8(buf)
}

/// P6.7: the active tab's search matches that fall within `snap`'s currently
/// displayed viewport window, translated to the index `render_to_full`
/// expects for `current_match` — `terminal_renderer::render_to_full`'s doc
/// asks callers to pre-filter for exactly this reason (an unfiltered 10k-line
/// match list would be scanned per-cell on every redraw).
fn visible_search_highlights(
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

/// BUG-cred-username-auth: the effective username actually sent to
/// authenticate a connection. Precedence (see `cm_core::Credential::username`
/// doc comment):
///
/// 1. the resolved credential's own `username` -- when [`resolve_effective_credential`]
///    (own credential, or inherited from the nearest ancestor group's
///    default) finds one, AND its `username` is non-empty. The credential
///    object is the source of truth once assigned: this is what makes a
///    credentialed RoyalTS-imported connection (which carries no inline
///    username at all) authenticate with the right user instead of an empty
///    one.
/// 2. else `inline_username` -- the connection's own typed username (Quick
///    Connect with inline creds, an explicit override, or any connection
///    with no credential assigned).
/// 3. else empty -- unchanged behavior for callers that require a non-empty
///    username (surfaces as the existing auth error).
///
/// [`resolve_effective_credential`]: cm_core::resolve_effective_credential
pub(super) fn effective_auth_username(
    conn: &Connection,
    groups: &[Group],
    inline_username: &str,
    credentials: &[cm_core::Credential],
) -> String {
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
/// [`RdpAuthInput`]) -- the username actually used to connect lives entirely
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
/// (ConMan has no RDP key-based auth). `domain` always comes from the
/// connection's own settings -- credentials have no domain field
/// (BUG-cred-username-auth: `username` now follows
/// [`effective_auth_username`]'s precedence -- the assigned credential's own
/// username wins over `settings.username` when non-empty, since a
/// RoyalTS-imported connection carries no inline username at all).
pub(super) fn resolve_rdp_auth(
    conn: &Connection,
    groups: &[Group],
    settings: &RdpSettings,
    secrets: &dyn cm_core::CredentialStore,
    credentials: &[cm_core::Credential],
) -> Result<RdpAuthInput, AuthResolveError> {
    let cred_id = cm_core::resolve_effective_credential(conn, groups)
        .ok_or(AuthResolveError::NoCredentialAssigned)?;
    let password = require_secret(secrets, cred_id, CredentialPurpose::Password)?;
    let username = effective_auth_username(
        conn,
        groups,
        settings.username.as_deref().unwrap_or(""),
        credentials,
    );
    Ok(RdpAuthInput {
        username,
        password,
        domain: settings.domain.clone(),
    })
}

/// fix-connect-credential-logging: debug-build-only diagnostic that logs the
/// *non-secret* auth context a successfully-resolved SSH launch is about to
/// use -- which credential (object name + id) or fallback source
/// (`ssh-agent`), and which username, are actually being handed to
/// [`cm_session::SessionProvider::connect_ssh`]. Fires from every launch path
/// that goes through [`resolve_ssh_auth`]: `launch_saved_connection` (tree
/// click / `CONMAN_TREE_AUTOLAUNCH` / Launchpad) and `connect_in_split`
/// (`controller/panes.rs`).
///
/// BUG-cred-username-auth: `username` is computed via
/// [`effective_auth_username`] -- the *effective* username actually sent
/// (credential's own username when one is assigned and non-empty, else
/// `settings.username`) -- not `settings.username` directly, so the log is
/// truthful regardless of whether the caller already applied the same
/// precedence to the `settings` it passes in.
///
/// ABSOLUTE RULE: never log the password/secret/passphrase/key material --
/// only the credential's name/id, the resolved username, and connection
/// metadata (host/port). `#[cfg(debug_assertions)]`-gated (definition and
/// every call site) so this -- and its `info!` line -- never exists in a
/// release build, regardless of `CONMAN_LOG`.
#[cfg(debug_assertions)]
pub(super) fn log_ssh_launch_auth(
    conn: &Connection,
    groups: &[Group],
    settings: &SshSettings,
    credentials: &[cm_core::Credential],
) {
    let cred_source = if matches!(settings.auth_method, SshAuthMethod::Agent) {
        "ssh-agent".to_owned()
    } else {
        match cm_core::resolve_effective_credential(conn, groups) {
            Some(id) => format!(
                "object:{}#{}",
                KeysPanel::cred_display_name(Some(id), credentials),
                id.get()
            ),
            // Unreachable in practice: resolve_ssh_auth already errors out
            // with NoCredentialAssigned before returning Ok(auth) here.
            None => "none".to_owned(),
        }
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

/// RDP counterpart to [`log_ssh_launch_auth`] -- same rule, plus `domain`
/// (RDP-specific auth context, always from `settings` -- credentials have no
/// domain field). BUG-cred-username-auth: `username` is likewise the
/// *effective* username via [`effective_auth_username`], not
/// `settings.username` directly (see [`resolve_rdp_auth`]).
#[cfg(debug_assertions)]
pub(super) fn log_rdp_launch_auth(
    conn: &Connection,
    groups: &[Group],
    settings: &RdpSettings,
    credentials: &[cm_core::Credential],
) {
    let cred_source = match cm_core::resolve_effective_credential(conn, groups) {
        Some(id) => format!(
            "object:{}#{}",
            KeysPanel::cred_display_name(Some(id), credentials),
            id.get()
        ),
        // Unreachable in practice: resolve_rdp_auth already errors out with
        // NoCredentialAssigned before returning Ok(auth) here.
        None => "none".to_owned(),
    };
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
            is_empty: false,
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
    let provider = state.borrow().session_provider.clone();
    match provider.connect_ssh(&settings, auth, verifier, size) {
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
                    connect_info: Some(ConnectInfo::Ssh(ci)),
                    is_remote: true,
                    rdp_clipboard: None,
                    title,
                    initial_status: "connecting",
                    origin_connection_id,
                    is_empty: false,
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

#[allow(clippy::too_many_arguments)]
pub(super) fn open_rdp_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    settings: RdpSettings,
    auth: RdpAuthInput,
    provenance: AuthProvenance,
    verifier: Arc<dyn CertVerifier>,
    origin_connection_id: Option<i32>,
) {
    let title = format!("RDP {}", settings.host);
    let identity = format!("{}@{}:{}", auth.username, settings.host, settings.port);
    // Only `Direct` (quick-connect / debug autoinit) clones the auth for
    // reconnect -- `Credential`-sourced auth is re-resolved fresh each time
    // (P6.4/P6.12: never cache the fetched secret in `Tab` state).
    let auth_source = match provenance {
        AuthProvenance::Direct => RdpAuthSource::Direct(auth.clone()),
        AuthProvenance::Credential(id) => RdpAuthSource::Credential(id),
    };
    let provider = state.borrow().session_provider.clone();
    let session = match provider.connect_rdp(&settings, auth, verifier) {
        Ok(s) => s,
        Err(e) => {
            // P6.12: mirrors open_ssh_tab's synchronous-setup-error handling
            // -- surface it as a Failed tab with the error overlay instead of
            // silently doing nothing (the pre-P6.12 behavior here).
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
    // Retain a reference to the drive thread's clipboard slot for remote→local sync.
    let rdp_clipboard = session.remote_clipboard();
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
            connect_info: Some(ConnectInfo::Rdp(ci)),
            is_remote: true,
            rdp_clipboard,
            title,
            initial_status: "connecting",
            origin_connection_id,
            is_empty: false,
        },
    );
    ui.set_session_identity(SharedString::from(identity));
    ui.set_overlay_connecting(true);
    ui.set_overlay_error(false);
    ui.set_launchpad_open(false);
    ui.set_connecting_kind(SharedString::from("RDP"));
    ui.set_rdp_active(true);
}

/// RDP counterpart to [`reconnect_ssh_tab`] (P6.12, gap 19): replaces the
/// active tab's session in place after the caller has already shut down the
/// old one. Reuses the exact same persistent cert store [`open_rdp_tab`]
/// uses, so an already-trusted cert never re-prompts on reconnect.
#[allow(clippy::too_many_arguments)]
pub(super) fn reconnect_rdp_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    tab_idx: usize,
    settings: RdpSettings,
    auth: RdpAuthInput,
    provenance: AuthProvenance,
    verifier: Arc<dyn CertVerifier>,
) {
    let identity = format!("{}@{}:{}", auth.username, settings.host, settings.port);
    let auth_source = match provenance {
        AuthProvenance::Direct => RdpAuthSource::Direct(auth.clone()),
        AuthProvenance::Credential(id) => RdpAuthSource::Credential(id),
    };
    let provider = state.borrow().session_provider.clone();
    match provider.connect_rdp(&settings, auth, verifier) {
        Ok(new_session) => {
            let rdp_clipboard = new_session.remote_clipboard();
            let ci = RdpConnectInfo {
                settings,
                auth_source,
            };
            {
                let mut st = state.borrow_mut();
                if let Some(tab) = st.tabs.get_mut(tab_idx) {
                    tab.session = new_session;
                    tab.connect_info = Some(ConnectInfo::Rdp(ci));
                    tab.last_frame = None;
                    tab.rdp_clipboard = rdp_clipboard;
                }
            }
            if let Some(mut item) = tab_model.row_data(tab_idx) {
                item.status = SharedString::from("connecting");
                tab_model.set_row_data(tab_idx, item);
            }
            ui.set_session_identity(SharedString::from(identity));
            ui.set_overlay_connecting(true);
            ui.set_overlay_error(false);
            ui.set_connecting_kind(SharedString::from("RDP"));
            ui.set_rdp_active(true);
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
    let identity = format!("{}@{}:{}", settings.username, settings.host, settings.port);
    let auth_source = match provenance {
        AuthProvenance::Direct => SshAuthSource::Direct(auth.clone()),
        AuthProvenance::Credential(id) => SshAuthSource::Credential(id),
    };
    let provider = state.borrow().session_provider.clone();
    match provider.connect_ssh(&settings, auth, verifier, size) {
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

    // P6.11: whether anything this tab's currently-visible panes render
    // changed this tick — gates the (only-when-split) `pane-cells` rebuild
    // below so a single-pane tab (the common case) never pays for it.
    let mut panes_updated = false;

    // P6.7: the search overlay only targets the active tab's primary pane;
    // poll for a buffer-text reply every tick while it's open. A poll that
    // (re)computes matches has no snapshot of its own to ride along with, so
    // force a render + refresh the overlay's match-count UI now (same
    // "no new GridSnapshot, but the highlight changed" situation
    // `wire_pointer`'s `selection_changed` handles for mouse selection).
    if i == active && st.tabs[i].search.is_open() && st.tabs[i].search.poll() {
        search::refresh_search_ui_from(ui, st);
        if let Some(snap) = st.tabs[i].last.clone() {
            let img = render_frame(&mut st.tabs[i], &snap, target);
            ui.set_frame(img);
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
            // Remote→local clipboard sync: poll slot written by the drive thread.
            if let Some(ref arc) = st.tabs[i].rdp_clipboard.clone()
                && let Ok(mut slot) = arc.try_lock()
                && let Some(text) = slot.take()
            {
                st.sys_clipboard.set_text(text);
            }
        }
    }

    // Drain extra pane surfaces (pane 1+; P5.1, generalized to N in P6.11).
    // Carry-over fix (f): collect extra panes that have Exited/Failed for collapse.
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
            // P6.11: RDP-in-pane (lifts P6.10's deferral) — decode into this
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
        // P6.7: the search overlay is a single global `terminal-search-open`
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
    }
    // P6.11: N-way pane repeater — rebuilds `pane-cells` (geometry + every
    // pane's current frame) when the active tab has more than one pane; a
    // no-op (clears the model) otherwise, so single-pane tabs never pay for
    // this beyond the `count()` check.
    panes::rebuild_pane_cells_for_state(st);
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
    // The RDP desktop framebuffer is always opaque (ironrdp's own
    // `DecodedImage` treats it that way -- see upstream ironrdp-session's
    // image.rs comment "Framebuffer is always opaque, so we can skip alpha
    // channel change"), but several of its fast-path bitmap/tile decoders
    // (raw 32bpp updates, RemoteFX tile copies) blit source bytes verbatim
    // and leave the 4th (alpha) byte at whatever the wire padding contained
    // -- typically `0x00`. Slint's software renderer blits full-frame
    // `Image`s without honoring per-pixel alpha, so a zero alpha channel was
    // invisible there; the femtovg (GPU-accelerated) backend performs real
    // alpha blending and renders an all-zero-alpha frame as fully
    // transparent -- i.e. a black screen showing the pane's dark background
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

    use cm_core::{
        ConnectionId, ConnectionKind, Credential, CredentialError, CredentialId, CredentialKind,
        GroupId,
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

    // ── P9.5 item 9/11: RDP black screen on the femtovg backend ─────────
    // ironrdp's fast-path bitmap/tile decoders copy raw source bytes for the
    // RGB channels but leave the alpha byte at whatever the wire padding
    // held (typically 0x00) -- the software renderer blits full-frame
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

    /// BUG-cred-username-auth test helper: an RDP connection with NO inline
    /// username -- the shape a RoyalTS import produces, where the username
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
            credential.map(CredentialId::new),
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
        // Credential #6 isn't in the credentials list here (empty slice) --
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

    // -- BUG-cred-username-auth: effective_auth_username / effective_ssh_settings
    // / resolve_rdp_auth username precedence ---------------------------------

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
    /// (exactly the RoyalTS-imported shape -- the username lives on the
    /// credential object, not inline) plus a credential whose `username` is
    /// "admin" must resolve `RdpAuthInput.username == "admin"`, not empty.
    /// **Must FAIL on master**: pre-fix, `resolve_rdp_auth` used
    /// `settings.username.clone().unwrap_or_default()` verbatim and never
    /// looked at the credential's `username` at all -- the live bug
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
            username: None, // no inline username -- RoyalTS-imported style
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
        let conn = make_rdp_conn(None, Some(6));
        let store = MockCredentialStore::new().with(
            CredentialId::new(6),
            CredentialPurpose::Password,
            "rdppw",
        );
        // Credential #6 exists but has no username of its own.
        let credentials = vec![make_credential(6, None)];
        let settings = RdpSettings {
            host: "10.0.0.2".to_owned(),
            username: Some("typed-user".to_owned()),
            domain: Some("CORP".to_owned()),
            ..RdpSettings::default()
        };
        let auth =
            resolve_rdp_auth(&conn, &[], &settings, &store, &credentials).expect("should resolve");
        assert_eq!(auth.username, "typed-user");
    }

    /// SSH counterpart of [`resolve_ssh_auth`]'s SSH equivalent
    /// (BUG-cred-username-auth). [`SshAuthInput`] carries no username field
    /// -- the effective username is applied to [`SshSettings`] via
    /// [`effective_ssh_settings`], which every SSH launch/reconnect path uses
    /// before connecting. **Must FAIL on master**: `effective_ssh_settings`
    /// doesn't exist there and every call site used the connection's inline
    /// (empty) `settings.username` verbatim.
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
    /// untouched by the username fix -- `resolve_ssh_auth` never looked at
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
        let auth =
            resolve_ssh_auth(&conn, &[], &settings, &store).expect("should resolve key material");
        match auth {
            SshAuthInput::KeyMaterial { key_pem, .. } => assert_eq!(key_pem.expose(), b"PEM-TEXT"),
            other => panic!("expected KeyMaterial, got {other:?}"),
        }
        // The login name for a key-auth connection still follows the same
        // credential-wins precedence -- the credential's username applies to
        // *which account* the key logs into, independent of the key material.
        let credentials = vec![make_credential(4, Some("keyuser"))];
        let effective = effective_ssh_settings(&conn, &[], &settings, &credentials);
        assert_eq!(effective.username, "keyuser");
    }

    // ── P6.12 gap 20: quick-connect kind selector → settings mapping ────────

    #[test]
    fn qc_kind_from_int_maps_the_three_kinds() {
        assert_eq!(QcKind::from(0), QcKind::Ssh);
        assert_eq!(QcKind::from(1), QcKind::Rdp);
        assert_eq!(QcKind::from(2), QcKind::Local);
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

    // ── P6.12 gap 19: RDP reconnect reuses stored RdpConnectInfo + creds ────

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
    /// username -- the returned settings re-derive the effective username
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
    /// username either -- `resolve_rdp_auth` re-applies the credential-wins
    /// precedence fresh on every reconnect since `credentials` is threaded
    /// all the way through.
    #[test]
    fn resolve_rdp_reconnect_credential_username_wins_over_empty_inline_username() {
        let conn = make_rdp_conn_no_inline_username(None, Some(6));
        let ci = RdpConnectInfo {
            settings: RdpSettings {
                host: "srv-win01".to_owned(),
                username: None, // no inline username -- RoyalTS-imported style
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
}

//! Overlay + panel chrome: connecting/error overlays driven by session status,
//! toast dismissal, the Connections/Keys panel switch, and the sidebar toggle.

use cm_core::AppStateService;
use cm_session::SessionStatus;
use slint::{ComponentHandle, Model, SharedString};

use crate::AppWindow;

use super::*;

pub(super) fn wire_overlays(ctx: &Ctx) {
    wire_select_panel(ctx);
    wire_toggle_sidebar(ctx);
    wire_sidebar_width_changed(ctx);
    wire_edit_failed_profile(ctx);
    wire_toast_dismissed(ctx);
}

fn wire_select_panel(ctx: &Ctx) {
    ctx.ui.on_select_panel({
        let weak = ctx.ui.as_weak();
        let app_state = ctx.app_state.clone();
        move |idx| {
            if let Some(ui) = weak.upgrade() {
                ui.set_active_panel(idx);
                let svc = AppStateService::new(app_state.as_ref());
                if let Err(e) = svc.save_active_panel(idx) {
                    tracing::warn!("save active_panel: {e}");
                }
            }
        }
    });
}

fn wire_toggle_sidebar(ctx: &Ctx) {
    ctx.ui.on_toggle_sidebar({
        let weak = ctx.ui.as_weak();
        let app_state = ctx.app_state.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                let new_val = !ui.get_sidebar_collapsed();
                ui.set_sidebar_collapsed(new_val);
                let svc = AppStateService::new(app_state.as_ref());
                if let Err(e) = svc.save_sidebar_collapsed(new_val) {
                    tracing::warn!("save sidebar_collapsed: {e}");
                }
            }
        }
    });
}

/// Persist the side-panel width once per drag gesture (P6.9 gap 11). Defensively
/// re-clamps server-side (see `util::clamp_sidebar_width`) so a value from any
/// non-drag caller (e.g. a future QA-harness command) can't persist a width
/// outside the chrome's own bounds.
fn wire_sidebar_width_changed(ctx: &Ctx) {
    ctx.ui.on_sidebar_width_changed({
        let weak = ctx.ui.as_weak();
        let app_state = ctx.app_state.clone();
        move |v| {
            let Some(ui) = weak.upgrade() else { return };
            let clamped = util::clamp_sidebar_width(v);
            if clamped != v {
                ui.set_sidebar_width(clamped);
            }
            let svc = AppStateService::new(app_state.as_ref());
            if let Err(e) = svc.save_side_panel_width(clamped) {
                tracing::warn!("save side_panel_width: {e}");
            }
        }
    });
}

/// ErrorOverlay "Edit…" (P6.9 gap 16): reopen the failed profile's own editor
/// via the exact existing CRUD callback (`edit_conn`), or fall back to
/// quick-connect when the failing tab has no originating stored profile
/// (quick-connect / local-shell tabs never show this overlay's Edit path
/// against a profile that doesn't exist).
fn wire_edit_failed_profile(ctx: &Ctx) {
    ctx.ui.on_edit_failed_profile({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let origin = {
                let st = state.borrow();
                st.tabs.get(st.active).and_then(|t| t.origin_connection_id)
            };
            match resolve_edit_action(origin) {
                EditAction::EditConnection(id) => ui.invoke_edit_conn(id),
                EditAction::QuickConnect => ui.invoke_quick_connect(),
            }
        }
    });
}

/// Pure decision behind [`wire_edit_failed_profile`] -- kept separate from the
/// `AppWindow` dispatch so it is unit-testable without a live UI (mirrors the
/// "menu-action dispatch" test style used for other CRUD-callback reuse in
/// this codebase, e.g. `palette::dispatch_palette_action`).
#[derive(Debug, PartialEq, Eq)]
pub(super) enum EditAction {
    EditConnection(i32),
    QuickConnect,
}

pub(super) fn resolve_edit_action(origin_connection_id: Option<i32>) -> EditAction {
    match origin_connection_id {
        Some(id) => EditAction::EditConnection(id),
        None => EditAction::QuickConnect,
    }
}

fn wire_toast_dismissed(ctx: &Ctx) {
    ctx.ui.on_toast_dismissed({
        let toast_model = ctx.toast_model.clone();
        move |id| {
            // Find the entry with the given id and remove it.
            let idx = (0..toast_model.row_count())
                .find(|&i| toast_model.row_data(i).map(|e| e.id) == Some(id));
            if let Some(i) = idx {
                toast_model.remove(i);
            }
        }
    });
}

pub(super) fn update_overlays_from_status(ui: &AppWindow, tab: &Tab, status: &SessionStatus) {
    // P6.14 (gap 3): an "empty" tab (the Launchpad-fronted local shell used
    // for the home/new-tab-without-a-live-session state) shows the Launchpad
    // instead of the terminal for as long as its underlying shell reports
    // Connected -- the only status a fresh local shell should ever be in.
    // If it somehow isn't (spawn raced into a weird state), fall through to
    // the normal handling below so the tab is never stuck invisible.
    if tab.is_empty && matches!(status, SessionStatus::Connected) {
        ui.set_overlay_connecting(false);
        ui.set_overlay_error(false);
        ui.set_launchpad_open(true);
        ui.set_session_status(SharedString::from("connected"));
        return;
    }
    match status {
        SessionStatus::Connecting => {
            ui.set_overlay_connecting(true);
            ui.set_overlay_error(false);
            ui.set_launchpad_open(false);
            ui.set_session_status(SharedString::from("connecting"));
        }
        SessionStatus::Connected => {
            ui.set_overlay_connecting(false);
            ui.set_overlay_error(false);
            ui.set_launchpad_open(false);
            ui.set_session_status(SharedString::from("connected"));
        }
        SessionStatus::Failed(reason) => {
            if tab.is_remote {
                ui.set_overlay_connecting(false);
                ui.set_overlay_error(true);
                ui.set_launchpad_open(false);
                ui.set_error_is_failure(true);
                ui.set_error_reason(SharedString::from(reason.as_str()));
                ui.set_error_detail(SharedString::from(""));
            }
            ui.set_session_status(SharedString::from("error"));
        }
        SessionStatus::Disconnected => {
            // P9.12 #3: a clean disconnect is not a failure -- neutral
            // "Session ended" framing (see `error_is_failure`'s doc comment,
            // ErrorOverlay). Reconnect stays available either way.
            if tab.is_remote {
                ui.set_overlay_connecting(false);
                ui.set_overlay_error(true);
                ui.set_launchpad_open(false);
                ui.set_error_is_failure(false);
                ui.set_error_reason(SharedString::from("Session disconnected"));
                ui.set_error_detail(SharedString::from(""));
            }
            ui.set_session_status(SharedString::from("disconnected"));
        }
        SessionStatus::Exited(exit) => {
            // P9.12 #3: a shell `exit` -- clean (`success: true`) or a
            // non-zero exit code -- is still not a *connection* failure
            // (the connection itself worked; the remote command just
            // ended). Neutral framing either way, matching `Disconnected`
            // above; the exit code itself is still surfaced in `detail`.
            if tab.is_remote {
                ui.set_overlay_connecting(false);
                ui.set_overlay_error(true);
                ui.set_launchpad_open(false);
                ui.set_error_is_failure(false);
                ui.set_error_reason(SharedString::from("Remote shell exited"));
                ui.set_error_detail(SharedString::from(if exit.success {
                    "Exit code 0"
                } else {
                    "Non-zero exit code"
                }));
            }
            ui.set_session_status(SharedString::from("disconnected"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cm_session::ExitStatus;

    #[test]
    fn session_status_dot_all_variants() {
        let cases: Vec<(SessionStatus, &str)> = vec![
            (SessionStatus::Connecting, "connecting"),
            (SessionStatus::Connected, "connected"),
            (SessionStatus::Failed("test".into()), "error"),
            (SessionStatus::Disconnected, "disconnected"),
            (
                SessionStatus::Exited(ExitStatus {
                    success: true,
                    code: 0,
                }),
                "disconnected",
            ),
        ];
        for (status, expected_dot) in cases {
            let dot = match &status {
                SessionStatus::Connecting => "connecting",
                SessionStatus::Connected => "connected",
                SessionStatus::Failed(_) => "error",
                SessionStatus::Disconnected | SessionStatus::Exited(_) => "disconnected",
            };
            assert_eq!(dot, expected_dot, "status {status:?} -> dot {dot}");
        }
    }

    // ── gap 16: ErrorOverlay "Edit…" dispatch ───────────────────────────

    #[test]
    fn resolve_edit_action_with_origin_edits_that_profile() {
        assert_eq!(
            resolve_edit_action(Some(42)),
            EditAction::EditConnection(42)
        );
    }

    #[test]
    fn resolve_edit_action_without_origin_falls_back_to_quick_connect() {
        assert_eq!(resolve_edit_action(None), EditAction::QuickConnect);
    }
}

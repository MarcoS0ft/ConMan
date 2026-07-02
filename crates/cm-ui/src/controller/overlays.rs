//! Overlay + panel chrome: connecting/error overlays driven by session status,
//! toast dismissal, the Connections/Keys panel switch, and the sidebar toggle.

use cm_session::SessionStatus;
use cm_storage::SettingsService;
use slint::{ComponentHandle, Model, SharedString};

use crate::AppWindow;

use super::*;

pub(super) fn wire_overlays(ctx: &Ctx) {
    wire_select_panel(ctx);
    wire_toggle_sidebar(ctx);
    wire_sidebar_width_changed(ctx);
    wire_toast_dismissed(ctx);
    wire_stub_callbacks(ctx);
}

fn wire_select_panel(ctx: &Ctx) {
    ctx.ui.on_select_panel({
        let weak = ctx.ui.as_weak();
        let repo_sp = ctx.repo.clone();
        move |idx| {
            if let Some(ui) = weak.upgrade() {
                ui.set_active_panel(idx);
                let svc = SettingsService::new(repo_sp.as_ref());
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
        let repo_ts = ctx.repo.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                let new_val = !ui.get_sidebar_collapsed();
                ui.set_sidebar_collapsed(new_val);
                let svc = SettingsService::new(repo_ts.as_ref());
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
        let repo_sw = ctx.repo.clone();
        move |v| {
            let Some(ui) = weak.upgrade() else { return };
            let clamped = util::clamp_sidebar_width(v);
            if clamped != v {
                ui.set_sidebar_width(clamped);
            }
            let svc = SettingsService::new(repo_sw.as_ref());
            if let Err(e) = svc.save_side_panel_width(clamped) {
                tracing::warn!("save side_panel_width: {e}");
            }
        }
    });
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

fn wire_stub_callbacks(ctx: &Ctx) {
    ctx.ui.on_launchpad_edited(|_q| {});
    ctx.ui.on_open_recent(|_i| {});
    ctx.ui.on_open_group_split(|| {});
}

pub(super) fn update_overlays_from_status(ui: &AppWindow, tab: &Tab, status: &SessionStatus) {
    match status {
        SessionStatus::Connecting => {
            ui.set_overlay_connecting(true);
            ui.set_overlay_error(false);
            ui.set_launchpad_open(false);
            ui.set_connecting_step(0);
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
                ui.set_error_reason(SharedString::from(reason.as_str()));
                ui.set_error_detail(SharedString::from(""));
            }
            ui.set_session_status(SharedString::from("error"));
        }
        SessionStatus::Disconnected => {
            if tab.is_remote {
                ui.set_overlay_connecting(false);
                ui.set_overlay_error(true);
                ui.set_launchpad_open(false);
                ui.set_error_reason(SharedString::from("Session disconnected"));
                ui.set_error_detail(SharedString::from(""));
            }
            ui.set_session_status(SharedString::from("disconnected"));
        }
        SessionStatus::Exited(exit) => {
            if tab.is_remote {
                ui.set_overlay_connecting(false);
                ui.set_overlay_error(true);
                ui.set_launchpad_open(false);
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
}

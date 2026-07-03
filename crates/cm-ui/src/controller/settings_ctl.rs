//! Settings persistence: theme/density/accent/font-size/shell path-args-cwd/
//! startup-behavior callbacks, plus the AppSettings <-> live-UI helpers.

use cm_core::LocalSettings;
use cm_storage::SettingsService;
use slint::ComponentHandle;

use crate::AppWindow;

use super::*;

pub(super) fn wire_settings_ctl(ctx: &Ctx) {
    wire_theme_changed(ctx);
    wire_density_changed(ctx);
    wire_accent_changed(ctx);
    wire_settings_font_size_changed(ctx);
    wire_settings_shell_path_changed(ctx);
    wire_settings_shell_args_changed(ctx);
    wire_settings_shell_cwd_changed(ctx);
    wire_startup_behavior_changed(ctx);
}

fn wire_theme_changed(ctx: &Ctx) {
    ctx.ui.on_theme_changed({
        let repo_s = ctx.repo.clone();
        let state_tc = ctx.state.clone();
        let weak_tc = ctx.ui.as_weak();
        move |idx| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_theme_mode(idx) {
                tracing::warn!("save theme_mode: {e}");
            }
            // P6.8 (gap 9): re-push the terminal palette to every open renderer so
            // the grid recolors together with the chrome. The `.slint` handler
            // (`settings_panel.slint`'s Theme segmented control) writes
            // `Theme.dark-mode` *before* invoking this callback, so
            // `ui.get_dark_mode()` here already reflects the new mode.
            if let Some(ui) = weak_tc.upgrade() {
                sessions::apply_terminal_theme_to_all(&state_tc, &ui);
            }
        }
    });
}

fn wire_density_changed(ctx: &Ctx) {
    ctx.ui.on_density_changed({
        let repo_s = ctx.repo.clone();
        move |idx| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_density(idx) {
                tracing::warn!("save density: {e}");
            }
        }
    });
}

fn wire_accent_changed(ctx: &Ctx) {
    ctx.ui.on_accent_changed({
        let repo_s = ctx.repo.clone();
        move |idx| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_accent_index(idx) {
                tracing::warn!("save accent_index: {e}");
            }
        }
    });
}

fn wire_settings_font_size_changed(ctx: &Ctx) {
    ctx.ui.on_settings_font_size_changed({
        let repo_s = ctx.repo.clone();
        let state_fs = ctx.state.clone();
        let weak_fs = ctx.ui.as_weak();
        move |v| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_font_size(v) {
                tracing::warn!("save font_size: {e}");
            }
            // Apply font size change to all live renderers immediately.
            {
                let mut st = state_fs.borrow_mut();
                let new_px = v as f32;
                st.font_size_px = new_px;
                let scale = st.scale;
                for tab in &mut st.tabs {
                    tab.renderer.set_scale(new_px, scale);
                    for ep in &mut tab.extra_panes {
                        ep.renderer.set_scale(new_px, scale);
                    }
                }
                // Drop borrow before calling apply_settled_resize (fix g).
            }
            // Commit new cell dimensions to PTY/engine for all tabs (carry-over fix g).
            if let Some(ui) = weak_fs.upgrade() {
                tabs::apply_settled_resize(&state_fs, &ui);
            }
        }
    });
}

fn wire_settings_shell_path_changed(ctx: &Ctx) {
    ctx.ui.on_settings_shell_path_changed({
        let repo_s = ctx.repo.clone();
        let state_sp = ctx.state.clone();
        move |v| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_shell_path(v.as_str()) {
                tracing::warn!("save shell_path: {e}");
            }
            let mut st = state_sp.borrow_mut();
            st.local_settings.program = if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            };
        }
    });
}

fn wire_settings_shell_args_changed(ctx: &Ctx) {
    ctx.ui.on_settings_shell_args_changed({
        let repo_s = ctx.repo.clone();
        let state_sa = ctx.state.clone();
        move |v| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_shell_args(v.as_str()) {
                tracing::warn!("save shell_args: {e}");
            }
            let mut st = state_sa.borrow_mut();
            st.local_settings.args = if v.is_empty() {
                Vec::new()
            } else {
                v.split_whitespace().map(String::from).collect()
            };
        }
    });
}

fn wire_settings_shell_cwd_changed(ctx: &Ctx) {
    ctx.ui.on_settings_shell_cwd_changed({
        let repo_s = ctx.repo.clone();
        let state_sc = ctx.state.clone();
        move |v| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_shell_cwd(v.as_str()) {
                tracing::warn!("save shell_cwd: {e}");
            }
            let mut st = state_sc.borrow_mut();
            st.local_settings.working_dir = if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            };
        }
    });
}

fn wire_startup_behavior_changed(ctx: &Ctx) {
    ctx.ui.on_startup_behavior_changed({
        let repo_s = ctx.repo.clone();
        move |v| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_startup_behavior(v) {
                tracing::warn!("save startup_behavior: {e}");
            }
        }
    });
}

pub(super) fn local_settings_from_app(s: &cm_storage::AppSettings) -> LocalSettings {
    LocalSettings {
        program: if s.shell_path.is_empty() {
            None
        } else {
            Some(s.shell_path.clone())
        },
        args: if s.shell_args.is_empty() {
            Vec::new()
        } else {
            s.shell_args.split_whitespace().map(String::from).collect()
        },
        working_dir: if s.shell_cwd.is_empty() {
            None
        } else {
            Some(s.shell_cwd.clone())
        },
        env: Vec::new(),
    }
}

/// Push all persisted settings into the live UI globals.
///
/// Called once at startup after `AppWindow` is created.  `Theme.density` and
/// `Theme.dark-mode` are in-out globals in Slint; the aliases on `AppWindow`
/// (`density`, `dark-mode`) are bidirectional bindings, so writing them here
/// updates the Theme global immediately.
///
/// NOTE (P1.5): In the current binary the repository is in-memory, so none of
/// these values survive process restart.  End-to-end persistence will be
/// observable once the disk-backed repository lands in P1.5.
pub(super) fn apply_settings_to_ui(s: &cm_storage::AppSettings, ui: &AppWindow) {
    ui.set_theme_mode(s.theme_mode);
    ui.set_density(s.density);
    ui.set_accent_index(s.accent_index);
    ui.set_settings_font_size(s.font_size);
    ui.set_settings_shell_path(s.shell_path.as_str().into());
    ui.set_settings_shell_args(s.shell_args.as_str().into());
    ui.set_settings_shell_cwd(s.shell_cwd.as_str().into());
    ui.set_startup_behavior(s.startup_behavior);
    ui.set_active_panel(s.active_panel);
    ui.set_sidebar_collapsed(s.sidebar_collapsed);
    // P6.9 (gap 11): restore the persisted side-panel width, defensively
    // re-clamped in case the stored value predates a bounds change.
    ui.set_sidebar_width(util::clamp_sidebar_width(s.side_panel_width));

    // Apply theme-mode to the live Theme.dark-mode token (system is already the
    // default; dark/light need an explicit override).
    match s.theme_mode {
        0 => ui.set_dark_mode(true),
        1 => ui.set_dark_mode(false),
        _ => {} // 2 (system): leave Theme.dark-mode at its Palette-derived default
    }

    // Restore persisted accent color.  `apply-accent-index` is implemented in
    // Slint as `Theme.accent = Theme.accent-presets[idx]`, so invoking it here
    // ensures the correct color is live immediately, not just the swatch index.
    ui.invoke_apply_accent_index(s.accent_index);
}

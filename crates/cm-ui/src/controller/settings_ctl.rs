//! Settings persistence: theme/density/accent/font-size/shell path-args-cwd/
//! startup-behavior callbacks, plus the AppSettings <-> live-UI helpers.

use cm_core::LocalSettings;
use cm_storage::SettingsService;
use slint::ComponentHandle;

use crate::AppWindow;

use super::*;

pub(super) fn wire_settings_ctl(
    ui: &AppWindow,
    state: &Rc<RefCell<State>>,
    repo: &Arc<dyn cm_core::ConnectionRepository>,
) {
    wire_theme_changed(ui, repo);
    wire_density_changed(ui, repo);
    wire_accent_changed(ui, repo);
    wire_settings_font_size_changed(ui, state, repo);
    wire_settings_shell_path_changed(ui, state, repo);
    wire_settings_shell_args_changed(ui, state, repo);
    wire_settings_shell_cwd_changed(ui, state, repo);
    wire_startup_behavior_changed(ui, repo);
}

fn wire_theme_changed(ui: &AppWindow, repo: &Arc<dyn cm_core::ConnectionRepository>) {
    ui.on_theme_changed({
        let repo_s = repo.clone();
        move |idx| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_theme_mode(idx) {
                eprintln!("conman: save theme_mode: {e}");
            }
        }
    });
}

fn wire_density_changed(ui: &AppWindow, repo: &Arc<dyn cm_core::ConnectionRepository>) {
    ui.on_density_changed({
        let repo_s = repo.clone();
        move |idx| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_density(idx) {
                eprintln!("conman: save density: {e}");
            }
        }
    });
}

fn wire_accent_changed(ui: &AppWindow, repo: &Arc<dyn cm_core::ConnectionRepository>) {
    ui.on_accent_changed({
        let repo_s = repo.clone();
        move |idx| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_accent_index(idx) {
                eprintln!("conman: save accent_index: {e}");
            }
        }
    });
}

fn wire_settings_font_size_changed(
    ui: &AppWindow,
    state: &Rc<RefCell<State>>,
    repo: &Arc<dyn cm_core::ConnectionRepository>,
) {
    ui.on_settings_font_size_changed({
        let repo_s = repo.clone();
        let state_fs = state.clone();
        let weak_fs = ui.as_weak();
        move |v| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_font_size(v) {
                eprintln!("conman: save font_size: {e}");
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

fn wire_settings_shell_path_changed(
    ui: &AppWindow,
    state: &Rc<RefCell<State>>,
    repo: &Arc<dyn cm_core::ConnectionRepository>,
) {
    ui.on_settings_shell_path_changed({
        let repo_s = repo.clone();
        let state_sp = state.clone();
        move |v| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_shell_path(v.as_str()) {
                eprintln!("conman: save shell_path: {e}");
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

fn wire_settings_shell_args_changed(
    ui: &AppWindow,
    state: &Rc<RefCell<State>>,
    repo: &Arc<dyn cm_core::ConnectionRepository>,
) {
    ui.on_settings_shell_args_changed({
        let repo_s = repo.clone();
        let state_sa = state.clone();
        move |v| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_shell_args(v.as_str()) {
                eprintln!("conman: save shell_args: {e}");
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

fn wire_settings_shell_cwd_changed(
    ui: &AppWindow,
    state: &Rc<RefCell<State>>,
    repo: &Arc<dyn cm_core::ConnectionRepository>,
) {
    ui.on_settings_shell_cwd_changed({
        let repo_s = repo.clone();
        let state_sc = state.clone();
        move |v| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_shell_cwd(v.as_str()) {
                eprintln!("conman: save shell_cwd: {e}");
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

fn wire_startup_behavior_changed(ui: &AppWindow, repo: &Arc<dyn cm_core::ConnectionRepository>) {
    ui.on_startup_behavior_changed({
        let repo_s = repo.clone();
        move |v| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_startup_behavior(v) {
                eprintln!("conman: save startup_behavior: {e}");
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

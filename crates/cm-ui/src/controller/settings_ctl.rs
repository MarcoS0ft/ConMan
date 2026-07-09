//! Settings persistence: theme/density/accent/font-size/shell path-args-cwd/
//! startup-behavior callbacks, plus the AppSettings <-> live-UI helpers.

use cm_core::{AppSettings, LocalSettings, SettingsService};
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
    wire_render_backend_changed(ctx);
    #[cfg(feature = "agent-mode")]
    wire_agent_mode_ctl(ctx);
}

/// Map the Rendering segmented-control index to the persisted `render.backend`
/// string. 0 = Auto (clears the cache → re-probe next launch), 1 = Software
/// (pins the safe fallback), 2 = Hardware (pins the accelerated renderer).
fn render_backend_str(idx: i32) -> &'static str {
    match idx {
        1 => "software",
        2 => "accelerated",
        _ => "auto",
    }
}

/// Inverse of [`render_backend_str`]: persisted string → control index.
fn render_backend_index(v: &str) -> i32 {
    match v {
        "software" => 1,
        "accelerated" => 2,
        _ => 0, // "auto", absent, or unknown
    }
}

fn wire_render_backend_changed(ctx: &Ctx) {
    ctx.ui.on_render_backend_changed({
        let repo_s = ctx.repo.clone();
        move |idx| {
            // Persist only; the renderer switch takes effect on next launch
            // (the Settings UI says "Applied on restart"). "auto" clears the
            // cache so the probe runs again; "software"/"accelerated" pin it.
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_renderer_backend(render_backend_str(idx)) {
                tracing::warn!("save render.backend: {e}");
            }
        }
    });
}

// ── P8.6-B: Automation / Agent mode ─────────────────────────────────────────
// `automation.enabled`/`automation.scopes` are loaded/saved separately from
// the rest of `AppSettings` (they're deliberately excluded from export --
// see `EXPORT_EXCLUDED_SETTING_KEYS`, cm-storage), so they get their own
// startup-apply function (`apply_agent_mode_to_ui`) rather than folding into
// `apply_settings_to_ui` below.

#[cfg(feature = "agent-mode")]
fn agent_mode_scopes_from_ui(ui: &AppWindow) -> cm_core::ScopeSet {
    cm_core::ScopeSet {
        read: ui.get_agent_mode_scope_read(),
        write: ui.get_agent_mode_scope_write(),
        execute: ui.get_agent_mode_scope_execute(),
    }
}

/// Persists a new granted-scopes set, then -- if the proxy is actually
/// running this session (`agent_mode` is `Some`) -- writes it straight into
/// the shared `Arc<RwLock<ScopeSet>>` the proxy thread reads on every
/// `tools/call`. This is the P8.6-A "Reload behavior": a scope change takes
/// effect on the proxy's very next request, no restart needed (only the
/// master enable/disable toggle is restart-only -- see
/// `wire_agent_mode_enabled_changed`).
#[cfg(feature = "agent-mode")]
fn persist_and_reload_agent_mode_scopes(
    repo: &dyn cm_core::ConnectionRepository,
    agent_mode: &Option<crate::AgentModeConfig>,
    scopes: cm_core::ScopeSet,
) {
    let svc = SettingsService::new(repo);
    if let Err(e) = svc.save_automation_scopes(scopes) {
        tracing::warn!("save automation.scopes: {e}");
    }
    if let Some(cfg) = agent_mode
        && let Ok(mut guard) = cfg.scopes.write()
    {
        *guard = scopes;
    }
}

#[cfg(feature = "agent-mode")]
fn wire_agent_mode_ctl(ctx: &Ctx) {
    wire_agent_mode_enabled_changed(ctx);
    wire_agent_mode_scope_read_changed(ctx);
    wire_agent_mode_scope_write_changed(ctx);
    wire_agent_mode_scope_execute_changed(ctx);
}

#[cfg(feature = "agent-mode")]
fn wire_agent_mode_enabled_changed(ctx: &Ctx) {
    ctx.ui.on_agent_mode_enabled_changed({
        let repo_s = ctx.repo.clone();
        move |v| {
            // Persist only -- takes effect on next launch (the Settings UI
            // says "Applied on restart"); see `conman`'s `agent_mode` module
            // doc for why the running proxy can't be started/stopped live.
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_automation_enabled(v) {
                tracing::warn!("save automation.enabled: {e}");
            }
        }
    });
}

#[cfg(feature = "agent-mode")]
fn wire_agent_mode_scope_read_changed(ctx: &Ctx) {
    ctx.ui.on_agent_mode_scope_read_changed({
        let repo_s = ctx.repo.clone();
        let agent_mode = ctx.agent_mode.clone();
        let weak = ctx.ui.as_weak();
        move |_| {
            let Some(ui) = weak.upgrade() else { return };
            let scopes = agent_mode_scopes_from_ui(&ui);
            persist_and_reload_agent_mode_scopes(repo_s.as_ref(), &agent_mode, scopes);
        }
    });
}

#[cfg(feature = "agent-mode")]
fn wire_agent_mode_scope_write_changed(ctx: &Ctx) {
    ctx.ui.on_agent_mode_scope_write_changed({
        let repo_s = ctx.repo.clone();
        let agent_mode = ctx.agent_mode.clone();
        let weak = ctx.ui.as_weak();
        move |_| {
            let Some(ui) = weak.upgrade() else { return };
            let scopes = agent_mode_scopes_from_ui(&ui);
            persist_and_reload_agent_mode_scopes(repo_s.as_ref(), &agent_mode, scopes);
        }
    });
}

#[cfg(feature = "agent-mode")]
fn wire_agent_mode_scope_execute_changed(ctx: &Ctx) {
    ctx.ui.on_agent_mode_scope_execute_changed({
        let repo_s = ctx.repo.clone();
        let agent_mode = ctx.agent_mode.clone();
        let weak = ctx.ui.as_weak();
        move |_| {
            let Some(ui) = weak.upgrade() else { return };
            let scopes = agent_mode_scopes_from_ui(&ui);
            persist_and_reload_agent_mode_scopes(repo_s.as_ref(), &agent_mode, scopes);
        }
    });
}

/// Applies the persisted `automation.enabled`/scopes plus the composition
/// root's live [`crate::AgentModeConfig`] (whether the proxy is actually
/// listening this session) to the Settings UI. Unconditional call site
/// (`assemble`, controller/mod.rs); this function itself is feature-gated --
/// a non-`agent-mode` build never calls it, so `agent-mode-available` stays
/// at its Slint-compiled default (`false`), keeping the whole section hidden
/// (see `AgentModeConfig`'s doc comment for the accepted trade-off: the
/// section's *markup* still compiles into every build's Slint resources --
/// only the Rust wiring and the listener itself are feature-gated).
#[cfg(feature = "agent-mode")]
pub(super) fn apply_agent_mode_to_ui(
    repo: &dyn cm_core::ConnectionRepository,
    agent_mode: Option<&crate::AgentModeConfig>,
    ui: &AppWindow,
) {
    ui.set_agent_mode_available(true);
    let svc = SettingsService::new(repo);
    match svc.load_automation() {
        Ok(automation) => {
            ui.set_agent_mode_enabled(automation.enabled);
            ui.set_agent_mode_scope_read(automation.scopes.read);
            ui.set_agent_mode_scope_write(automation.scopes.write);
            ui.set_agent_mode_scope_execute(automation.scopes.execute);
        }
        Err(e) => tracing::warn!("load automation settings: {e}"),
    }
    let details = agent_mode
        .map(|cfg| format!("127.0.0.1:{}", cfg.external_port))
        .unwrap_or_default();
    ui.set_agent_mode_connection_details(details.as_str().into());
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

pub(super) fn local_settings_from_app(s: &AppSettings) -> LocalSettings {
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
pub(super) fn apply_settings_to_ui(s: &AppSettings, ui: &AppWindow) {
    ui.set_theme_mode(s.theme_mode);
    ui.set_density(s.density);
    ui.set_accent_index(s.accent_index);
    ui.set_settings_font_size(s.font_size);
    ui.set_settings_shell_path(s.shell_path.as_str().into());
    ui.set_settings_shell_args(s.shell_args.as_str().into());
    ui.set_settings_shell_cwd(s.shell_cwd.as_str().into());
    ui.set_startup_behavior(s.startup_behavior);
    // P7.1 cont.: reflect the persisted renderer backend ("auto" default) in
    // the Rendering control.
    ui.set_render_backend(render_backend_index(&s.renderer_backend));
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

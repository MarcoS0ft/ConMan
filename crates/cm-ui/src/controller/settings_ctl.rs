//! Editable application preferences and their live UI/runtime projection.

#[cfg(feature = "agent-mode")]
use cm_core::ScopeSet;
use cm_core::{
    AccentColor, AppConfigStore, AppSettings, AppState, Density, LocalSettings, RendererBackend,
    SettingKey, SettingsService, StartupBehavior, TerminalTheme, ThemeMode,
};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::AppWindow;

use super::*;

pub(super) fn wire_settings_ctl(ctx: &Ctx) {
    wire_theme_changed(ctx);
    wire_density_changed(ctx);
    wire_accent_changed(ctx);
    wire_terminal_theme_changed(ctx);
    wire_settings_font_family_changed(ctx);
    wire_settings_font_size_changed(ctx);
    wire_scrollback_limit_changed(ctx);
    wire_settings_shell_path_changed(ctx);
    wire_settings_shell_args_changed(ctx);
    wire_settings_shell_cwd_changed(ctx);
    wire_plain_copy_paste_changed(ctx);
    wire_copy_on_select_changed(ctx);
    wire_confirm_close_active_tab_changed(ctx);
    wire_confirm_quit_active_connections_changed(ctx);
    wire_auto_accept_ssh_host_keys_changed(ctx);
    wire_auto_accept_rdp_certificates_changed(ctx);
    wire_startup_behavior_changed(ctx);
    wire_render_backend_changed(ctx);
    wire_open_config(ctx);
    wire_reload_config(ctx);
    wire_copy_build_info(ctx);
    #[cfg(feature = "agent-mode")]
    wire_agent_mode_ctl(ctx);
}

fn persist(store: &dyn AppConfigStore, key: SettingKey, value: &str) {
    if let Err(error) = SettingsService::new(store).set(key, value) {
        tracing::warn!(key = key.as_str(), %error, "failed to save setting");
    }
}

fn theme_from_index(index: i32) -> ThemeMode {
    match index {
        0 => ThemeMode::Dark,
        1 => ThemeMode::Light,
        _ => ThemeMode::System,
    }
}

fn theme_index(theme: ThemeMode) -> i32 {
    match theme {
        ThemeMode::Dark => 0,
        ThemeMode::Light => 1,
        ThemeMode::System => 2,
    }
}

fn accent_from_index(index: i32) -> AccentColor {
    match index {
        1 => AccentColor::Teal,
        2 => AccentColor::Green,
        3 => AccentColor::Purple,
        4 => AccentColor::System,
        _ => AccentColor::Blue,
    }
}

fn accent_index(accent: AccentColor) -> i32 {
    match accent {
        AccentColor::Blue => 0,
        AccentColor::Teal => 1,
        AccentColor::Green => 2,
        AccentColor::Purple => 3,
        AccentColor::System => 4,
    }
}

fn density_from_index(index: i32) -> Density {
    if index == 1 {
        Density::Cosy
    } else {
        Density::Compact
    }
}

fn density_index(density: Density) -> i32 {
    i32::from(density == Density::Cosy)
}

fn terminal_theme_from_index(index: i32) -> TerminalTheme {
    if index == 1 {
        TerminalTheme::Light
    } else {
        TerminalTheme::Dark
    }
}

fn terminal_theme_index(theme: TerminalTheme) -> i32 {
    i32::from(theme == TerminalTheme::Light)
}

fn startup_from_index(index: i32) -> StartupBehavior {
    if index == 1 {
        StartupBehavior::Restore
    } else {
        StartupBehavior::Clean
    }
}

fn startup_index(startup: StartupBehavior) -> i32 {
    i32::from(startup == StartupBehavior::Restore)
}

fn render_backend_from_index(index: i32) -> RendererBackend {
    match index {
        1 => RendererBackend::Software,
        2 => RendererBackend::Accelerated,
        _ => RendererBackend::Auto,
    }
}

fn render_backend_index(backend: RendererBackend) -> i32 {
    match backend {
        RendererBackend::Auto => 0,
        RendererBackend::Software => 1,
        RendererBackend::Accelerated => 2,
    }
}

fn wire_render_backend_changed(ctx: &Ctx) {
    ctx.ui.on_render_backend_changed({
        let store = ctx.config_store.clone();
        move |index| {
            persist(
                store.as_ref(),
                SettingKey::RendererBackend,
                render_backend_from_index(index).as_str(),
            );
        }
    });
}

#[cfg(feature = "agent-mode")]
fn agent_mode_scopes_from_ui(ui: &AppWindow) -> ScopeSet {
    ScopeSet {
        read: ui.get_agent_mode_scope_read(),
        write: ui.get_agent_mode_scope_write(),
        execute: ui.get_agent_mode_scope_execute(),
    }
}

#[cfg(feature = "agent-mode")]
fn persist_and_reload_agent_mode_scopes(
    store: &dyn AppConfigStore,
    agent_mode: &Option<crate::AgentModeConfig>,
    scopes: ScopeSet,
) {
    persist(store, SettingKey::AutomationScopes, &scopes.format());
    if let Some(config) = agent_mode
        && let Ok(mut guard) = config.scopes.write()
    {
        *guard = scopes;
    }
}

#[cfg(feature = "agent-mode")]
fn wire_agent_mode_ctl(ctx: &Ctx) {
    ctx.ui.on_agent_mode_enabled_changed({
        let store = ctx.config_store.clone();
        move |enabled| {
            persist(
                store.as_ref(),
                SettingKey::AutomationEnabled,
                if enabled { "true" } else { "false" },
            );
        }
    });

    macro_rules! wire_scope {
        ($callback:ident) => {
            ctx.ui.$callback({
                let store = ctx.config_store.clone();
                let agent_mode = ctx.state.borrow().agent_mode.clone();
                let weak = ctx.ui.as_weak();
                move |_| {
                    let Some(ui) = weak.upgrade() else { return };
                    persist_and_reload_agent_mode_scopes(
                        store.as_ref(),
                        &agent_mode,
                        agent_mode_scopes_from_ui(&ui),
                    );
                }
            });
        };
    }
    wire_scope!(on_agent_mode_scope_read_changed);
    wire_scope!(on_agent_mode_scope_write_changed);
    wire_scope!(on_agent_mode_scope_execute_changed);
}

#[cfg(feature = "agent-mode")]
pub(super) fn apply_agent_mode_to_ui(
    store: &dyn AppConfigStore,
    agent_mode: Option<&crate::AgentModeConfig>,
    ui: &AppWindow,
) {
    ui.set_agent_mode_available(true);
    match SettingsService::new(store).load_automation() {
        Ok(automation) => {
            ui.set_agent_mode_enabled(automation.enabled);
            ui.set_agent_mode_scope_read(automation.scopes.read);
            ui.set_agent_mode_scope_write(automation.scopes.write);
            ui.set_agent_mode_scope_execute(automation.scopes.execute);
        }
        Err(error) => tracing::warn!(%error, "failed to load automation settings"),
    }
    ui.set_agent_mode_connection_details(
        agent_mode
            .map(|config| format!("127.0.0.1:{}", config.external_port))
            .unwrap_or_default()
            .into(),
    );
}

fn wire_theme_changed(ctx: &Ctx) {
    ctx.ui.on_theme_changed({
        let store = ctx.config_store.clone();
        let weak = ctx.ui.as_weak();
        move |index| {
            persist(
                store.as_ref(),
                SettingKey::Theme,
                theme_from_index(index).as_str(),
            );
            if let Some(ui) = weak.upgrade() {
                match theme_from_index(index) {
                    ThemeMode::Dark => ui.set_dark_mode(true),
                    ThemeMode::Light => ui.set_dark_mode(false),
                    ThemeMode::System => {}
                }
            }
        }
    });
}

fn wire_density_changed(ctx: &Ctx) {
    ctx.ui.on_density_changed({
        let store = ctx.config_store.clone();
        move |index| {
            persist(
                store.as_ref(),
                SettingKey::Density,
                density_from_index(index).as_str(),
            );
        }
    });
}

fn wire_accent_changed(ctx: &Ctx) {
    ctx.ui.on_accent_changed({
        let store = ctx.config_store.clone();
        let weak = ctx.ui.as_weak();
        move |index| {
            persist(
                store.as_ref(),
                SettingKey::AccentColor,
                accent_from_index(index).as_str(),
            );
            if let Some(ui) = weak.upgrade() {
                ui.invoke_apply_accent_index(index);
            }
        }
    });
}

fn wire_terminal_theme_changed(ctx: &Ctx) {
    ctx.ui.on_settings_terminal_theme_changed({
        let store = ctx.config_store.clone();
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |index| {
            let theme = terminal_theme_from_index(index);
            persist(store.as_ref(), SettingKey::TerminalTheme, theme.as_str());
            state.borrow_mut().terminal_theme = theme;
            if let Some(ui) = weak.upgrade() {
                sessions::apply_terminal_theme_to_all(&state, &ui);
            }
        }
    });
}

fn wire_settings_font_family_changed(ctx: &Ctx) {
    ctx.ui.on_settings_font_family_changed({
        let store = ctx.config_store.clone();
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |family| {
            let requested = family.to_string();
            let (effective, selected_index) = {
                let mut state = state.borrow_mut();
                let mut effective = state.fonts.resolve_family(&requested);
                for tab in &mut state.tabs {
                    effective = tab.renderer.set_preferred_family(&effective).to_owned();
                    for pane in &mut tab.extra_panes {
                        let pane_effective = pane.renderer.set_preferred_family(&effective);
                        debug_assert_eq!(pane_effective, effective);
                    }
                }
                state.font_family.clone_from(&effective);
                let selected_index = state
                    .fonts
                    .available_monospace_families()
                    .iter()
                    .position(|candidate| candidate == &effective)
                    .unwrap_or(0) as i32;
                (effective, selected_index)
            };
            if let Some(ui) = weak.upgrade() {
                ui.set_settings_font_family(effective.as_str().into());
                ui.set_settings_font_family_index(selected_index);
                tabs::apply_settled_resize(&state, &ui);
            }
            persist(store.as_ref(), SettingKey::FontFamily, &effective);
        }
    });
}

fn wire_settings_font_size_changed(ctx: &Ctx) {
    ctx.ui.on_settings_font_size_changed({
        let store = ctx.config_store.clone();
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |value| {
            persist(store.as_ref(), SettingKey::FontSize, &value.to_string());
            {
                let mut state = state.borrow_mut();
                state.font_size_px = value as f32;
                let scale = state.scale;
                for tab in &mut state.tabs {
                    tab.renderer.set_scale(value as f32, scale);
                    for pane in &mut tab.extra_panes {
                        pane.renderer.set_scale(value as f32, scale);
                    }
                }
            }
            if let Some(ui) = weak.upgrade() {
                tabs::apply_settled_resize(&state, &ui);
            }
        }
    });
}

fn wire_scrollback_limit_changed(ctx: &Ctx) {
    ctx.ui.on_settings_scrollback_limit_changed({
        let store = ctx.config_store.clone();
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move |raw| {
            let parsed = raw
                .trim()
                .parse::<usize>()
                .ok()
                .filter(|value| *value <= cm_core::MAX_SCROLLBACK_LIMIT);
            let Some(value) = parsed else {
                if let Some(ui) = weak.upgrade() {
                    ui.set_settings_scrollback_limit(
                        state.borrow().scrollback_limit.to_string().into(),
                    );
                }
                tracing::warn!(
                    value = %raw,
                    "scrollback limit must be between 0 and {}",
                    cm_core::MAX_SCROLLBACK_LIMIT,
                );
                return;
            };
            persist(
                store.as_ref(),
                SettingKey::ScrollbackLimit,
                &value.to_string(),
            );
            state.borrow_mut().scrollback_limit = value;
            if let Some(ui) = weak.upgrade() {
                ui.set_settings_scrollback_limit(value.to_string().into());
            }
        }
    });
}

fn wire_settings_shell_path_changed(ctx: &Ctx) {
    ctx.ui.on_settings_shell_path_changed({
        let store = ctx.config_store.clone();
        let state = ctx.state.clone();
        move |value| {
            persist(store.as_ref(), SettingKey::Command, value.as_str());
            state.borrow_mut().local_settings.program =
                (!value.is_empty()).then(|| value.to_string());
        }
    });
}

fn wire_settings_shell_args_changed(ctx: &Ctx) {
    ctx.ui.on_settings_shell_args_changed({
        let store = ctx.config_store.clone();
        let state = ctx.state.clone();
        move |value| {
            persist(store.as_ref(), SettingKey::CommandArgs, value.as_str());
            state.borrow_mut().local_settings.args = split_args(value.as_str());
        }
    });
}

fn wire_settings_shell_cwd_changed(ctx: &Ctx) {
    ctx.ui.on_settings_shell_cwd_changed({
        let store = ctx.config_store.clone();
        let state = ctx.state.clone();
        move |value| {
            persist(store.as_ref(), SettingKey::WorkingDirectory, value.as_str());
            state.borrow_mut().local_settings.working_dir =
                (!value.is_empty()).then(|| value.to_string());
        }
    });
}

macro_rules! wire_bool_setting {
    ($fn_name:ident, $callback:ident, $key:expr, $field:ident) => {
        fn $fn_name(ctx: &Ctx) {
            ctx.ui.$callback({
                let store = ctx.config_store.clone();
                let state = ctx.state.clone();
                move |value| {
                    persist(store.as_ref(), $key, if value { "true" } else { "false" });
                    state.borrow_mut().$field = value;
                }
            });
        }
    };
}

wire_bool_setting!(
    wire_plain_copy_paste_changed,
    on_settings_plain_copy_paste_changed,
    SettingKey::PlainCopyPasteShortcuts,
    plain_copy_paste_shortcuts
);
wire_bool_setting!(
    wire_copy_on_select_changed,
    on_settings_copy_on_select_changed,
    SettingKey::CopyOnSelect,
    copy_on_select
);
wire_bool_setting!(
    wire_confirm_close_active_tab_changed,
    on_settings_confirm_close_active_tab_changed,
    SettingKey::ConfirmCloseActiveTab,
    confirm_close_active_tab
);
wire_bool_setting!(
    wire_confirm_quit_active_connections_changed,
    on_settings_confirm_quit_active_connections_changed,
    SettingKey::ConfirmQuitActiveConnections,
    confirm_quit_active_connections
);
wire_bool_setting!(
    wire_auto_accept_ssh_host_keys_changed,
    on_settings_auto_accept_ssh_host_keys_changed,
    SettingKey::AutoAcceptSshHostKeys,
    auto_accept_ssh_host_keys
);
wire_bool_setting!(
    wire_auto_accept_rdp_certificates_changed,
    on_settings_auto_accept_rdp_certificates_changed,
    SettingKey::AutoAcceptRdpCertificates,
    auto_accept_rdp_certificates
);

fn wire_startup_behavior_changed(ctx: &Ctx) {
    ctx.ui.on_startup_behavior_changed({
        let store = ctx.config_store.clone();
        move |index| {
            persist(
                store.as_ref(),
                SettingKey::Startup,
                startup_from_index(index).as_str(),
            );
        }
    });
}

fn wire_open_config(ctx: &Ctx) {
    ctx.ui.on_settings_open_config({
        let store = ctx.config_store.clone();
        let path = ctx.config_path.clone();
        let io = ctx.state.borrow().io.clone();
        move || {
            let result = store
                .document_text()
                .and_then(|document| store.replace_document(&document))
                .map_err(|error| error.to_string())
                .and_then(|()| {
                    cm_platform::open_path(path.clone()).map_err(|error| error.to_string())
                });
            if let Err(error) = result {
                io.push_toast(format!("Could not open config: {error}"), 3);
            }
        }
    });
}

fn wire_reload_config(ctx: &Ctx) {
    ctx.ui.on_settings_reload_config({
        let store = ctx.config_store.clone();
        let state = ctx.state.clone();
        let app_state = ctx.app_state.clone();
        let weak = ctx.ui.as_weak();
        let io = ctx.state.borrow().io.clone();
        move || match SettingsService::new(store.as_ref()).load_with_warnings() {
            Ok(loaded) => {
                let Some(ui) = weak.upgrade() else { return };
                let machine = cm_core::AppStateService::new(app_state.as_ref())
                    .load()
                    .unwrap_or_default();
                apply_settings_to_ui(&loaded.settings, &machine, &ui);
                apply_settings_to_runtime(&state, &ui, &loaded.settings);
                #[cfg(feature = "agent-mode")]
                apply_agent_mode_to_ui(store.as_ref(), state.borrow().agent_mode.as_ref(), &ui);
                for warning in &loaded.warnings {
                    tracing::warn!(
                        key = warning.key.as_str(),
                        value = %warning.value,
                        "invalid config value, using default: {}",
                        warning.message
                    );
                }
                let message = if loaded.warnings.is_empty() {
                    "Configuration reloaded".to_owned()
                } else {
                    format!(
                        "Configuration reloaded with {} warning(s)",
                        loaded.warnings.len()
                    )
                };
                io.push_toast(message, if loaded.warnings.is_empty() { 1 } else { 2 });
            }
            Err(error) => io.push_toast(format!("Could not reload config: {error}"), 3),
        }
    });
}

fn wire_copy_build_info(ctx: &Ctx) {
    ctx.ui.on_settings_copy_build_info({
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let details = ui.get_settings_build_details().to_string();
            if details.is_empty() {
                return;
            }
            let mut state = state.borrow_mut();
            let replaced = state.sys_clipboard.submit_write(
                crate::clipboard::ClipboardWritePurpose::UiTextCopy,
                crate::clipboard::ClipboardWrite::Text(details),
            );
            if let Some(replaced) = replaced {
                sessions::handle_replaced_clipboard_write(&mut state, &replaced);
            }
        }
    });
}

fn split_args(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_owned).collect()
}

pub(super) fn local_settings_from_app(settings: &AppSettings) -> LocalSettings {
    LocalSettings {
        program: (!settings.command.is_empty()).then(|| settings.command.clone()),
        args: split_args(&settings.command_args),
        working_dir: (!settings.working_directory.is_empty())
            .then(|| settings.working_directory.clone()),
        env: Vec::new(),
    }
}

pub(super) fn apply_settings_to_ui(settings: &AppSettings, state: &AppState, ui: &AppWindow) {
    ui.set_theme_mode(theme_index(settings.theme));
    ui.set_density(density_index(settings.density));
    ui.set_accent_index(accent_index(settings.accent_color));
    ui.set_settings_terminal_theme(terminal_theme_index(settings.terminal_theme));
    ui.set_settings_font_size(settings.font_size);
    ui.set_settings_scrollback_limit(settings.scrollback_limit.to_string().into());
    ui.set_settings_shell_path(settings.command.as_str().into());
    ui.set_settings_shell_args(settings.command_args.as_str().into());
    ui.set_settings_shell_cwd(settings.working_directory.as_str().into());
    ui.set_settings_plain_copy_paste(settings.plain_copy_paste_shortcuts);
    ui.set_settings_copy_on_select(settings.copy_on_select);
    ui.set_settings_confirm_close_active_tab(settings.confirm_close_active_tab);
    ui.set_settings_confirm_quit_active_connections(settings.confirm_quit_active_connections);
    ui.set_settings_auto_accept_ssh_host_keys(settings.auto_accept_ssh_host_keys);
    ui.set_settings_auto_accept_rdp_certificates(settings.auto_accept_rdp_certificates);
    ui.set_startup_behavior(startup_index(settings.startup));
    ui.set_render_backend(render_backend_index(settings.renderer_backend));
    ui.set_active_panel(state.active_panel);
    ui.set_sidebar_collapsed(state.sidebar_collapsed);
    ui.set_sidebar_width(util::clamp_sidebar_width(state.side_panel_width));

    match settings.theme {
        ThemeMode::Dark => ui.set_dark_mode(true),
        ThemeMode::Light => ui.set_dark_mode(false),
        ThemeMode::System => {}
    }
    ui.invoke_apply_accent_index(accent_index(settings.accent_color));
}

fn apply_settings_to_runtime(state: &Rc<RefCell<State>>, ui: &AppWindow, settings: &AppSettings) {
    {
        let mut state = state.borrow_mut();
        state.font_size_px = settings.font_size as f32;
        state.local_settings = local_settings_from_app(settings);
        state.plain_copy_paste_shortcuts = settings.plain_copy_paste_shortcuts;
        state.copy_on_select = settings.copy_on_select;
        state.confirm_close_active_tab = settings.confirm_close_active_tab;
        state.confirm_quit_active_connections = settings.confirm_quit_active_connections;
        state.auto_accept_ssh_host_keys = settings.auto_accept_ssh_host_keys;
        state.auto_accept_rdp_certificates = settings.auto_accept_rdp_certificates;
        state.terminal_theme = settings.terminal_theme;
        state.scrollback_limit = settings.scrollback_limit;

        let effective = state.fonts.resolve_family(&settings.font_family);
        state.font_family.clone_from(&effective);
        let scale = state.scale;
        let size = state.font_size_px;
        for tab in &mut state.tabs {
            tab.renderer.set_preferred_family(&effective);
            tab.renderer.set_scale(size, scale);
            for pane in &mut tab.extra_panes {
                pane.renderer.set_preferred_family(&effective);
                pane.renderer.set_scale(size, scale);
            }
        }
    }
    apply_terminal_font_settings_to_ui(&state.borrow(), ui);
    sessions::apply_terminal_theme_to_all(state, ui);
    tabs::apply_settled_resize(state, ui);
}

pub(super) fn apply_terminal_font_settings_to_ui(state: &State, ui: &AppWindow) {
    let families = state
        .fonts
        .available_monospace_families()
        .iter()
        .map(|family| SharedString::from(family.as_str()))
        .collect::<Vec<_>>();
    let selected_index = state
        .fonts
        .available_monospace_families()
        .iter()
        .position(|family| family == &state.font_family)
        .unwrap_or(0) as i32;

    ui.set_settings_font_families(ModelRc::new(VecModel::from(families)));
    ui.set_settings_font_family(state.font_family.as_str().into());
    ui.set_settings_font_family_index(selected_index);
}

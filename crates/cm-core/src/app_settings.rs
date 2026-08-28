//! Typed application preferences and machine-local state.
//!
//! User preferences are stored in the editable `config.conman` document via
//! [`AppConfigStore`]. Machine/runtime state is deliberately separate and is
//! stored via [`AppStateRepository`]. Connection data and credentials do not
//! cross either boundary.

use crate::error::{AppConfigError, RepositoryError};
use crate::ids::ConnectionId;
use crate::ports::{AppConfigStore, AppStateRepository};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

pub const DEFAULT_TERMINAL_FONT_FAMILY: &str = "JetBrainsMono Nerd Font Mono";
pub const MIN_FONT_SIZE: i32 = 6;
pub const MAX_FONT_SIZE: i32 = 72;
pub const DEFAULT_SCROLLBACK_LIMIT: usize = 10_000;
/// Maximum configurable terminal history ceiling in lines. Terminal sessions
/// also enforce a separate 64 MiB backing-store ceiling, so content-dense rows
/// may reach the memory ceiling before this line ceiling.
pub const MAX_SCROLLBACK_LIMIT: usize = 32_768;

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire),+ }
            }
        }
        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
        impl FromStr for $name {
            type Err = &'static str;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($wire => Ok(Self::$variant),)+
                    _ => Err(concat!("unsupported ", stringify!($name), " value")),
                }
            }
        }
    };
}

string_enum!(ThemeMode { System => "system", Dark => "dark", Light => "light" });
string_enum!(AccentColor {
    Blue => "blue", Teal => "teal", Green => "green", Purple => "purple", System => "system"
});
string_enum!(Density { Compact => "compact", Cosy => "cosy" });
string_enum!(TerminalTheme { Dark => "dark", Light => "light" });
string_enum!(StartupBehavior { Clean => "clean", Restore => "restore" });
string_enum!(RendererBackend {
    Auto => "auto", Software => "software", Accelerated => "accelerated"
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScopeSet {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl ScopeSet {
    /// Runtime parsing is resilient. Strict config validation is provided by
    /// [`SettingKey::validate_value`].
    pub fn parse(csv: &str) -> Self {
        let mut scopes = Self::default();
        for token in csv.split(',').map(str::trim) {
            match token {
                "read" => scopes.read = true,
                "write" => scopes.write = true,
                "execute" => scopes.execute = true,
                _ => {}
            }
        }
        scopes
    }

    pub fn format(self) -> String {
        let mut parts = Vec::with_capacity(3);
        if self.read {
            parts.push("read");
        }
        if self.write {
            parts.push("write");
        }
        if self.execute {
            parts.push("execute");
        }
        parts.join(",")
    }

    fn validate(csv: &str) -> Result<(), &'static str> {
        if csv
            .split(',')
            .map(str::trim)
            .all(|token| token.is_empty() || matches!(token, "read" | "write" | "execute"))
        {
            Ok(())
        } else {
            Err("expected a comma-separated subset of read, write, execute")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AutomationSettings {
    pub enabled: bool,
    pub scopes: ScopeSet,
}

/// Canonical known keys in `config.conman`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettingKey {
    Theme,
    AccentColor,
    Density,
    TerminalTheme,
    FontFamily,
    FontSize,
    ScrollbackLimit,
    Command,
    CommandArgs,
    WorkingDirectory,
    Startup,
    RendererBackend,
    PlainCopyPasteShortcuts,
    CopyOnSelect,
    ConfirmCloseActiveTab,
    ConfirmQuitActiveConnections,
    AutomationEnabled,
    AutomationScopes,
}

pub const ALL_SETTING_KEYS: &[SettingKey] = &[
    SettingKey::Theme,
    SettingKey::AccentColor,
    SettingKey::Density,
    SettingKey::TerminalTheme,
    SettingKey::FontFamily,
    SettingKey::FontSize,
    SettingKey::ScrollbackLimit,
    SettingKey::Command,
    SettingKey::CommandArgs,
    SettingKey::WorkingDirectory,
    SettingKey::Startup,
    SettingKey::RendererBackend,
    SettingKey::PlainCopyPasteShortcuts,
    SettingKey::CopyOnSelect,
    SettingKey::ConfirmCloseActiveTab,
    SettingKey::ConfirmQuitActiveConnections,
    SettingKey::AutomationEnabled,
    SettingKey::AutomationScopes,
];

impl SettingKey {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Theme => "theme",
            Self::AccentColor => "accent-color",
            Self::Density => "density",
            Self::TerminalTheme => "terminal-theme",
            Self::FontFamily => "font-family",
            Self::FontSize => "font-size",
            Self::ScrollbackLimit => "scrollback-limit",
            Self::Command => "command",
            Self::CommandArgs => "command-args",
            Self::WorkingDirectory => "working-directory",
            Self::Startup => "startup",
            Self::RendererBackend => "renderer-backend",
            Self::PlainCopyPasteShortcuts => "plain-copy-paste-shortcuts",
            Self::CopyOnSelect => "copy-on-select",
            Self::ConfirmCloseActiveTab => "confirm-close-active-tab",
            Self::ConfirmQuitActiveConnections => "confirm-quit-active-connections",
            Self::AutomationEnabled => "automation-enabled",
            Self::AutomationScopes => "automation-scopes",
        }
    }

    /// Empty means reset to the built-in default and is valid for every key.
    pub fn validate_value(self, value: &str) -> Result<(), AppConfigError> {
        if value.is_empty() {
            return Ok(());
        }
        let result: Result<(), String> = match self {
            Self::Theme => parse_enum::<ThemeMode>(value),
            Self::AccentColor => parse_enum::<AccentColor>(value),
            Self::Density => parse_enum::<Density>(value),
            Self::TerminalTheme => parse_enum::<TerminalTheme>(value),
            Self::Startup => parse_enum::<StartupBehavior>(value),
            Self::RendererBackend => parse_enum::<RendererBackend>(value),
            Self::FontSize => parse_range(value, MIN_FONT_SIZE as usize, MAX_FONT_SIZE as usize),
            Self::ScrollbackLimit => parse_range(value, 0, MAX_SCROLLBACK_LIMIT),
            Self::PlainCopyPasteShortcuts
            | Self::CopyOnSelect
            | Self::ConfirmCloseActiveTab
            | Self::ConfirmQuitActiveConnections
            | Self::AutomationEnabled => parse_bool(value),
            Self::AutomationScopes => ScopeSet::validate(value).map_err(str::to_owned),
            Self::FontFamily | Self::Command | Self::CommandArgs | Self::WorkingDirectory => Ok(()),
        };
        result.map_err(|message| AppConfigError::InvalidValue {
            key: self.as_str().to_owned(),
            message,
        })
    }
}

impl FromStr for SettingKey {
    type Err = ();
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        ALL_SETTING_KEYS
            .iter()
            .copied()
            .find(|key| key.as_str() == value)
            .ok_or(())
    }
}

fn parse_enum<T: FromStr>(value: &str) -> Result<(), String>
where
    T::Err: Display,
{
    value
        .parse::<T>()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn parse_range(value: &str, min: usize, max: usize) -> Result<(), String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("expected an integer from {min} through {max}"))?;
    if (min..=max).contains(&parsed) {
        Ok(())
    } else {
        Err(format!("expected an integer from {min} through {max}"))
    }
}

fn parse_bool(value: &str) -> Result<(), String> {
    match value {
        "true" | "false" => Ok(()),
        _ => Err("expected true or false".to_owned()),
    }
}

/// Complete user-preference snapshot. It contains no machine-local UI state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSettings {
    pub theme: ThemeMode,
    pub accent_color: AccentColor,
    pub density: Density,
    pub terminal_theme: TerminalTheme,
    pub font_family: String,
    pub font_size: i32,
    pub scrollback_limit: usize,
    pub command: String,
    pub command_args: String,
    pub working_directory: String,
    pub startup: StartupBehavior,
    pub renderer_backend: RendererBackend,
    pub plain_copy_paste_shortcuts: bool,
    pub copy_on_select: bool,
    pub confirm_close_active_tab: bool,
    pub confirm_quit_active_connections: bool,
    pub automation: AutomationSettings,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: ThemeMode::System,
            accent_color: AccentColor::Blue,
            density: Density::Compact,
            terminal_theme: TerminalTheme::Dark,
            font_family: DEFAULT_TERMINAL_FONT_FAMILY.to_owned(),
            font_size: 14,
            scrollback_limit: DEFAULT_SCROLLBACK_LIMIT,
            command: String::new(),
            command_args: String::new(),
            working_directory: String::new(),
            startup: StartupBehavior::Clean,
            renderer_backend: RendererBackend::Auto,
            plain_copy_paste_shortcuts: true,
            copy_on_select: false,
            confirm_close_active_tab: true,
            confirm_quit_active_connections: true,
            automation: AutomationSettings::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingWarning {
    pub key: SettingKey,
    pub value: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedAppSettings {
    pub settings: AppSettings,
    pub warnings: Vec<SettingWarning>,
}

/// Typed facade over a line-preserving [`AppConfigStore`].
pub struct SettingsService<'a> {
    store: &'a dyn AppConfigStore,
}

impl std::fmt::Debug for SettingsService<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SettingsService").finish_non_exhaustive()
    }
}

impl<'a> SettingsService<'a> {
    pub fn new(store: &'a dyn AppConfigStore) -> Self {
        Self { store }
    }

    pub fn load(&self) -> Result<AppSettings, AppConfigError> {
        Ok(self.load_with_warnings()?.settings)
    }

    /// Invalid hand-edited values fall back independently and are returned as
    /// warnings so the caller can surface them without preventing startup.
    pub fn load_with_warnings(&self) -> Result<LoadedAppSettings, AppConfigError> {
        let mut s = AppSettings::default();
        let mut warnings = Vec::new();
        s.theme = self.read_parsed(SettingKey::Theme, s.theme, &mut warnings)?;
        s.accent_color =
            self.read_parsed(SettingKey::AccentColor, s.accent_color, &mut warnings)?;
        s.density = self.read_parsed(SettingKey::Density, s.density, &mut warnings)?;
        s.terminal_theme =
            self.read_parsed(SettingKey::TerminalTheme, s.terminal_theme, &mut warnings)?;
        s.font_family = self.read_string(SettingKey::FontFamily, &s.font_family)?;
        s.font_size = self.read_i32(
            SettingKey::FontSize,
            s.font_size,
            MIN_FONT_SIZE,
            MAX_FONT_SIZE,
            &mut warnings,
        )?;
        s.scrollback_limit = self.read_usize(
            SettingKey::ScrollbackLimit,
            s.scrollback_limit,
            MAX_SCROLLBACK_LIMIT,
            &mut warnings,
        )?;
        s.command = self.read_string(SettingKey::Command, &s.command)?;
        s.command_args = self.read_string(SettingKey::CommandArgs, &s.command_args)?;
        s.working_directory =
            self.read_string(SettingKey::WorkingDirectory, &s.working_directory)?;
        s.startup = self.read_parsed(SettingKey::Startup, s.startup, &mut warnings)?;
        s.renderer_backend = self.read_parsed(
            SettingKey::RendererBackend,
            s.renderer_backend,
            &mut warnings,
        )?;
        s.plain_copy_paste_shortcuts = self.read_bool(
            SettingKey::PlainCopyPasteShortcuts,
            s.plain_copy_paste_shortcuts,
            &mut warnings,
        )?;
        s.copy_on_select =
            self.read_bool(SettingKey::CopyOnSelect, s.copy_on_select, &mut warnings)?;
        s.confirm_close_active_tab = self.read_bool(
            SettingKey::ConfirmCloseActiveTab,
            s.confirm_close_active_tab,
            &mut warnings,
        )?;
        s.confirm_quit_active_connections = self.read_bool(
            SettingKey::ConfirmQuitActiveConnections,
            s.confirm_quit_active_connections,
            &mut warnings,
        )?;
        s.automation.enabled = self.read_bool(
            SettingKey::AutomationEnabled,
            s.automation.enabled,
            &mut warnings,
        )?;
        if let Some(raw) = self.raw(SettingKey::AutomationScopes)? {
            if let Err(message) = ScopeSet::validate(&raw) {
                warnings.push(warning(SettingKey::AutomationScopes, raw, message));
            } else {
                s.automation.scopes = ScopeSet::parse(&raw);
            }
        }
        Ok(LoadedAppSettings {
            settings: s,
            warnings,
        })
    }

    /// Persist all known preferences as one atomic document update.
    ///
    /// Every value is validated before the store is called. The adapter then
    /// applies the complete batch under its own document mutation boundary, so
    /// neither validation nor I/O failure can expose a partially updated
    /// settings snapshot.
    pub fn save(&self, s: &AppSettings) -> Result<(), AppConfigError> {
        let values = serialize_settings(s);
        for (key, value) in &values {
            key.validate_value(value)?;
        }
        let raw_values = values
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        self.store.set_values(&raw_values)
    }

    pub fn set(&self, key: SettingKey, value: &str) -> Result<(), AppConfigError> {
        key.validate_value(value)?;
        self.store.set_value(key.as_str(), value)
    }

    pub fn set_bool(&self, key: SettingKey, value: bool) -> Result<(), AppConfigError> {
        self.set(key, if value { "true" } else { "false" })
    }

    pub fn load_automation(&self) -> Result<AutomationSettings, AppConfigError> {
        Ok(self.load()?.automation)
    }

    fn raw(&self, key: SettingKey) -> Result<Option<String>, AppConfigError> {
        Ok(self
            .store
            .get_value(key.as_str())?
            .filter(|value| !value.is_empty()))
    }
    fn read_string(&self, key: SettingKey, default: &str) -> Result<String, AppConfigError> {
        Ok(self.raw(key)?.unwrap_or_else(|| default.to_owned()))
    }
    fn read_parsed<T: FromStr>(
        &self,
        key: SettingKey,
        default: T,
        warnings: &mut Vec<SettingWarning>,
    ) -> Result<T, AppConfigError>
    where
        T::Err: Display,
    {
        let Some(raw) = self.raw(key)? else {
            return Ok(default);
        };
        match raw.parse() {
            Ok(value) => Ok(value),
            Err(error) => {
                warnings.push(warning(key, raw, &error.to_string()));
                Ok(default)
            }
        }
    }
    fn read_bool(
        &self,
        key: SettingKey,
        default: bool,
        warnings: &mut Vec<SettingWarning>,
    ) -> Result<bool, AppConfigError> {
        let Some(raw) = self.raw(key)? else {
            return Ok(default);
        };
        match raw.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => {
                warnings.push(warning(key, raw, "expected true or false"));
                Ok(default)
            }
        }
    }
    fn read_i32(
        &self,
        key: SettingKey,
        default: i32,
        min: i32,
        max: i32,
        warnings: &mut Vec<SettingWarning>,
    ) -> Result<i32, AppConfigError> {
        let Some(raw) = self.raw(key)? else {
            return Ok(default);
        };
        match raw.parse::<i32>() {
            Ok(value) if (min..=max).contains(&value) => Ok(value),
            _ => {
                warnings.push(warning(key, raw, "integer is outside the supported range"));
                Ok(default)
            }
        }
    }
    fn read_usize(
        &self,
        key: SettingKey,
        default: usize,
        max: usize,
        warnings: &mut Vec<SettingWarning>,
    ) -> Result<usize, AppConfigError> {
        let Some(raw) = self.raw(key)? else {
            return Ok(default);
        };
        match raw.parse::<usize>() {
            Ok(value) if value <= max => Ok(value),
            _ => {
                warnings.push(warning(key, raw, "integer is outside the supported range"));
                Ok(default)
            }
        }
    }
}

fn serialize_settings(settings: &AppSettings) -> Vec<(SettingKey, String)> {
    vec![
        (SettingKey::Theme, settings.theme.to_string()),
        (SettingKey::AccentColor, settings.accent_color.to_string()),
        (SettingKey::Density, settings.density.to_string()),
        (
            SettingKey::TerminalTheme,
            settings.terminal_theme.to_string(),
        ),
        (SettingKey::FontFamily, settings.font_family.clone()),
        (SettingKey::FontSize, settings.font_size.to_string()),
        (
            SettingKey::ScrollbackLimit,
            settings.scrollback_limit.to_string(),
        ),
        (SettingKey::Command, settings.command.clone()),
        (SettingKey::CommandArgs, settings.command_args.clone()),
        (
            SettingKey::WorkingDirectory,
            settings.working_directory.clone(),
        ),
        (SettingKey::Startup, settings.startup.to_string()),
        (
            SettingKey::RendererBackend,
            settings.renderer_backend.to_string(),
        ),
        (
            SettingKey::PlainCopyPasteShortcuts,
            bool_wire(settings.plain_copy_paste_shortcuts).to_owned(),
        ),
        (
            SettingKey::CopyOnSelect,
            bool_wire(settings.copy_on_select).to_owned(),
        ),
        (
            SettingKey::ConfirmCloseActiveTab,
            bool_wire(settings.confirm_close_active_tab).to_owned(),
        ),
        (
            SettingKey::ConfirmQuitActiveConnections,
            bool_wire(settings.confirm_quit_active_connections).to_owned(),
        ),
        (
            SettingKey::AutomationEnabled,
            bool_wire(settings.automation.enabled).to_owned(),
        ),
        (
            SettingKey::AutomationScopes,
            settings.automation.scopes.format(),
        ),
    ]
}

fn warning(key: SettingKey, value: String, message: &str) -> SettingWarning {
    SettingWarning {
        key,
        value,
        message: message.to_owned(),
    }
}

// Machine-local keys are intentionally unrelated to public config keys.
pub const STATE_ACTIVE_PANEL: &str = "ui.active-panel";
pub const STATE_SIDEBAR_COLLAPSED: &str = "ui.sidebar-collapsed";
pub const STATE_SIDE_PANEL_WIDTH: &str = "ui.side-panel-width";
pub const STATE_FIRST_RUN_SEEDED: &str = "app.first-run-seeded";
pub const STATE_SESSION_TABS: &str = "session.tabs";
pub const STATE_RENDERER_PROBE_CACHE: &str = "render.probe-cache";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppState {
    pub active_panel: i32,
    pub sidebar_collapsed: bool,
    pub side_panel_width: i32,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            active_panel: 0,
            sidebar_collapsed: false,
            side_panel_width: 252,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionTabEntry {
    Local,
    Connection(ConnectionId),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SessionTabSnapshot {
    pub tabs: Vec<SessionTabEntry>,
    pub active: usize,
}

pub struct AppStateService<'a> {
    repo: &'a dyn AppStateRepository,
}

impl std::fmt::Debug for AppStateService<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppStateService").finish_non_exhaustive()
    }
}

impl<'a> AppStateService<'a> {
    pub fn new(repo: &'a dyn AppStateRepository) -> Self {
        Self { repo }
    }
    pub fn load(&self) -> Result<AppState, RepositoryError> {
        let d = AppState::default();
        Ok(AppState {
            active_panel: self.read_i32(STATE_ACTIVE_PANEL, d.active_panel)?,
            sidebar_collapsed: self.read_bool(STATE_SIDEBAR_COLLAPSED, d.sidebar_collapsed)?,
            side_panel_width: self.read_i32(STATE_SIDE_PANEL_WIDTH, d.side_panel_width)?,
        })
    }
    pub fn save_active_panel(&self, value: i32) -> Result<(), RepositoryError> {
        self.repo.set_state(STATE_ACTIVE_PANEL, &value.to_string())
    }
    pub fn save_sidebar_collapsed(&self, value: bool) -> Result<(), RepositoryError> {
        self.repo
            .set_state(STATE_SIDEBAR_COLLAPSED, bool_wire(value))
    }
    pub fn save_side_panel_width(&self, value: i32) -> Result<(), RepositoryError> {
        self.repo
            .set_state(STATE_SIDE_PANEL_WIDTH, &value.to_string())
    }
    pub fn load_first_run_seeded(&self) -> Result<bool, RepositoryError> {
        self.read_bool(STATE_FIRST_RUN_SEEDED, false)
    }
    pub fn save_first_run_seeded(&self) -> Result<(), RepositoryError> {
        self.repo.set_state(STATE_FIRST_RUN_SEEDED, "true")
    }
    pub fn save_session_tabs(&self, snapshot: &SessionTabSnapshot) -> Result<(), RepositoryError> {
        let json = serde_json::to_string(snapshot)
            .map_err(|error| RepositoryError::Backend(error.to_string()))?;
        self.repo.set_state(STATE_SESSION_TABS, &json)
    }
    pub fn load_session_tabs(&self) -> Result<Option<SessionTabSnapshot>, RepositoryError> {
        let Some(raw) = self.repo.get_state(STATE_SESSION_TABS)? else {
            return Ok(None);
        };
        Ok(serde_json::from_str::<SessionTabSnapshot>(&raw)
            .ok()
            .filter(|snapshot| !snapshot.tabs.is_empty()))
    }
    pub fn load_renderer_probe_cache(&self) -> Result<Option<RendererBackend>, RepositoryError> {
        Ok(self
            .repo
            .get_state(STATE_RENDERER_PROBE_CACHE)?
            .and_then(|raw| raw.parse().ok())
            .filter(|value| *value != RendererBackend::Auto))
    }
    pub fn save_renderer_probe_cache(
        &self,
        backend: RendererBackend,
    ) -> Result<(), RepositoryError> {
        if backend == RendererBackend::Auto {
            self.clear_renderer_probe_cache()
        } else {
            self.repo
                .set_state(STATE_RENDERER_PROBE_CACHE, backend.as_str())
        }
    }
    pub fn clear_renderer_probe_cache(&self) -> Result<(), RepositoryError> {
        self.repo.delete_state(STATE_RENDERER_PROBE_CACHE)
    }
    fn read_i32(&self, key: &str, default: i32) -> Result<i32, RepositoryError> {
        Ok(self
            .repo
            .get_state(key)?
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(default))
    }
    fn read_bool(&self, key: &str, default: bool) -> Result<bool, RepositoryError> {
        Ok(self
            .repo
            .get_state(key)?
            .and_then(|raw| match raw.as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            })
            .unwrap_or(default))
    }
}

fn bool_wire(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemoryConfig(Mutex<HashMap<String, String>>);
    impl AppConfigStore for MemoryConfig {
        fn get_value(&self, key: &str) -> Result<Option<String>, AppConfigError> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        fn set_value(&self, key: &str, value: &str) -> Result<(), AppConfigError> {
            self.0.lock().unwrap().insert(key.into(), value.into());
            Ok(())
        }
        fn set_values(&self, values: &[(&str, &str)]) -> Result<(), AppConfigError> {
            let mut stored = self.0.lock().unwrap();
            for (key, value) in values {
                stored.insert((*key).to_owned(), (*value).to_owned());
            }
            Ok(())
        }
        fn document_text(&self) -> Result<String, AppConfigError> {
            Ok(String::new())
        }
        fn replace_document(&self, _document: &str) -> Result<(), AppConfigError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MemoryState(Mutex<HashMap<String, String>>);
    impl AppStateRepository for MemoryState {
        fn get_state(&self, key: &str) -> Result<Option<String>, RepositoryError> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        fn set_state(&self, key: &str, value: &str) -> Result<(), RepositoryError> {
            self.0.lock().unwrap().insert(key.into(), value.into());
            Ok(())
        }
        fn delete_state(&self, key: &str) -> Result<(), RepositoryError> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
    }

    #[test]
    fn product_defaults_are_pinned() {
        let settings = AppSettings::default();
        assert_eq!(settings.theme, ThemeMode::System);
        assert_eq!(settings.accent_color, AccentColor::Blue);
        assert_eq!(settings.density, Density::Compact);
        assert_eq!(settings.terminal_theme, TerminalTheme::Dark);
        assert_eq!(settings.font_size, 14);
        assert_eq!(settings.scrollback_limit, 10_000);
        assert!(settings.plain_copy_paste_shortcuts);
        assert!(!settings.copy_on_select);
        assert!(settings.confirm_close_active_tab);
        assert!(settings.confirm_quit_active_connections);
        assert_eq!(settings.renderer_backend, RendererBackend::Auto);
        assert_eq!(settings.automation, AutomationSettings::default());
    }

    #[test]
    fn all_settings_round_trip_in_canonical_form() {
        let store = MemoryConfig::default();
        let service = SettingsService::new(&store);
        let expected = AppSettings {
            theme: ThemeMode::Dark,
            accent_color: AccentColor::Purple,
            density: Density::Cosy,
            terminal_theme: TerminalTheme::Light,
            font_family: "Cascadia Mono".into(),
            font_size: 21,
            scrollback_limit: 32_000,
            command: "pwsh.exe".into(),
            command_args: "-NoLogo".into(),
            working_directory: "C:\\work".into(),
            startup: StartupBehavior::Restore,
            renderer_backend: RendererBackend::Software,
            plain_copy_paste_shortcuts: false,
            copy_on_select: true,
            confirm_close_active_tab: false,
            confirm_quit_active_connections: false,
            automation: AutomationSettings {
                enabled: true,
                scopes: ScopeSet {
                    read: true,
                    write: false,
                    execute: true,
                },
            },
        };
        service.save(&expected).unwrap();
        assert_eq!(service.load().unwrap(), expected);
        assert_eq!(store.0.lock().unwrap()["automation-scopes"], "read,execute");
    }

    #[test]
    fn failed_bulk_save_leaves_the_original_snapshot_untouched() {
        struct FailingBatchStore {
            values: Mutex<HashMap<String, String>>,
            single_writes: Mutex<usize>,
            batch_writes: Mutex<usize>,
        }
        impl AppConfigStore for FailingBatchStore {
            fn get_value(&self, key: &str) -> Result<Option<String>, AppConfigError> {
                Ok(self.values.lock().unwrap().get(key).cloned())
            }
            fn set_value(&self, _key: &str, _value: &str) -> Result<(), AppConfigError> {
                *self.single_writes.lock().unwrap() += 1;
                unreachable!("bulk save must not degrade into individual writes")
            }
            fn set_values(&self, _values: &[(&str, &str)]) -> Result<(), AppConfigError> {
                *self.batch_writes.lock().unwrap() += 1;
                Err(AppConfigError::Backend(
                    "injected atomic-write failure".into(),
                ))
            }
            fn document_text(&self) -> Result<String, AppConfigError> {
                Ok(String::new())
            }
            fn replace_document(&self, _document: &str) -> Result<(), AppConfigError> {
                unreachable!("typed bulk save uses the atomic batch operation")
            }
        }

        let store = FailingBatchStore {
            values: Mutex::new(HashMap::from([
                ("theme".to_owned(), "light".to_owned()),
                ("font-size".to_owned(), "17".to_owned()),
                ("future-setting".to_owned(), "preserved".to_owned()),
            ])),
            single_writes: Mutex::new(0),
            batch_writes: Mutex::new(0),
        };
        let before = store.values.lock().unwrap().clone();
        let changed = AppSettings {
            theme: ThemeMode::Dark,
            font_size: 24,
            ..AppSettings::default()
        };

        assert!(SettingsService::new(&store).save(&changed).is_err());
        assert_eq!(*store.single_writes.lock().unwrap(), 0);
        assert_eq!(*store.batch_writes.lock().unwrap(), 1);
        assert_eq!(*store.values.lock().unwrap(), before);
    }

    #[test]
    fn invalid_bulk_snapshot_is_rejected_before_the_store_is_called() {
        struct PanicStore;
        impl AppConfigStore for PanicStore {
            fn get_value(&self, _key: &str) -> Result<Option<String>, AppConfigError> {
                unreachable!()
            }
            fn set_value(&self, _key: &str, _value: &str) -> Result<(), AppConfigError> {
                unreachable!()
            }
            fn set_values(&self, _values: &[(&str, &str)]) -> Result<(), AppConfigError> {
                unreachable!("validation must finish before touching the store")
            }
            fn document_text(&self) -> Result<String, AppConfigError> {
                unreachable!()
            }
            fn replace_document(&self, _document: &str) -> Result<(), AppConfigError> {
                unreachable!()
            }
        }
        let invalid = AppSettings {
            scrollback_limit: MAX_SCROLLBACK_LIMIT + 1,
            ..AppSettings::default()
        };
        assert!(SettingsService::new(&PanicStore).save(&invalid).is_err());
    }

    #[test]
    fn empty_values_reset_and_invalid_values_warn_per_key() {
        let store = MemoryConfig::default();
        for (key, value) in [
            ("theme", "sepia"),
            ("font-size", "999"),
            ("scrollback-limit", "many"),
            ("copy-on-select", "yes"),
            ("automation-scopes", "read,root"),
        ] {
            store.set_value(key, value).unwrap();
        }
        store.set_value("font-family", "").unwrap();
        let loaded = SettingsService::new(&store).load_with_warnings().unwrap();
        assert_eq!(loaded.settings, AppSettings::default());
        assert_eq!(loaded.warnings.len(), 5);
        assert!(
            loaded
                .warnings
                .iter()
                .any(|warning| warning.key == SettingKey::Theme)
        );
    }

    #[test]
    fn strict_validation_is_case_sensitive_and_checks_ranges() {
        assert_eq!(ALL_SETTING_KEYS.len(), 18);
        for key in ALL_SETTING_KEYS {
            key.validate_value("").unwrap();
        }
        SettingKey::ScrollbackLimit.validate_value("0").unwrap();
        SettingKey::ScrollbackLimit.validate_value("32768").unwrap();
        assert!(SettingKey::ScrollbackLimit.validate_value("32769").is_err());
        assert!(
            SettingKey::ScrollbackLimit
                .validate_value("1000000")
                .is_err()
        );
        assert!(SettingKey::FontSize.validate_value("5").is_err());
        assert!(SettingKey::Theme.validate_value("Dark").is_err());
        assert!(SettingKey::CopyOnSelect.validate_value("1").is_err());
        assert!(
            SettingKey::AutomationScopes
                .validate_value("read,admin")
                .is_err()
        );
        assert_eq!("renderer-backend".parse(), Ok(SettingKey::RendererBackend));
        assert!("Renderer-Backend".parse::<SettingKey>().is_err());
    }

    #[test]
    fn scope_format_is_stable_and_parse_is_runtime_resilient() {
        let scopes = ScopeSet {
            read: true,
            write: false,
            execute: true,
        };
        assert_eq!(scopes.format(), "read,execute");
        assert_eq!(ScopeSet::parse("read,junk,execute"), scopes);
    }

    #[test]
    fn ports_are_object_safe() {
        let config: Box<dyn AppConfigStore> = Box::new(MemoryConfig::default());
        let state: Box<dyn AppStateRepository> = Box::new(MemoryState::default());
        assert!(config.get_value("theme").unwrap().is_none());
        assert!(state.get_state(STATE_ACTIVE_PANEL).unwrap().is_none());
    }

    #[test]
    fn machine_state_round_trips_and_is_defensively_loaded() {
        let repo = MemoryState::default();
        let service = AppStateService::new(&repo);
        service.save_active_panel(2).unwrap();
        service.save_sidebar_collapsed(true).unwrap();
        service.save_side_panel_width(340).unwrap();
        assert_eq!(
            service.load().unwrap(),
            AppState {
                active_panel: 2,
                sidebar_collapsed: true,
                side_panel_width: 340,
            }
        );
        repo.set_state(STATE_ACTIVE_PANEL, "broken").unwrap();
        assert_eq!(service.load().unwrap().active_panel, 0);
    }

    #[test]
    fn first_run_tabs_and_renderer_cache_are_machine_state() {
        let repo = MemoryState::default();
        let service = AppStateService::new(&repo);
        assert!(!service.load_first_run_seeded().unwrap());
        service.save_first_run_seeded().unwrap();
        assert!(service.load_first_run_seeded().unwrap());
        let snapshot = SessionTabSnapshot {
            tabs: vec![
                SessionTabEntry::Connection(ConnectionId::new(7)),
                SessionTabEntry::Local,
            ],
            active: 1,
        };
        service.save_session_tabs(&snapshot).unwrap();
        assert_eq!(service.load_session_tabs().unwrap(), Some(snapshot));
        service
            .save_renderer_probe_cache(RendererBackend::Software)
            .unwrap();
        assert_eq!(
            service.load_renderer_probe_cache().unwrap(),
            Some(RendererBackend::Software)
        );
        service
            .save_renderer_probe_cache(RendererBackend::Auto)
            .unwrap();
        assert_eq!(service.load_renderer_probe_cache().unwrap(), None);
    }
}

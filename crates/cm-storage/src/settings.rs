//! Typed settings helpers for ConMan (P5.2).
//!
//! All persistent UI preferences live in the `settings(key, value)` table
//! (added in schema v2).  This module defines the canonical key strings and
//! a [`SettingsService`] that reads / writes typed values through a
//! [`ConnectionRepository`].
//!
//! ## Design
//! - Keys are `&'static str` constants so callers never construct strings.
//! - Values are stored as their `Display` string; parsing is infallible —
//!   on parse failure the default is returned (untrusted DB content).
//! - No `unwrap` / `panic` on I/O paths (CONVENTIONS §2.2).

use cm_core::{ConnectionRepository, RepositoryError};

// ---------------------------------------------------------------------------
// Key constants (single source of truth)
// ---------------------------------------------------------------------------

/// Theme mode: "0" dark, "1" light, "2" system.
pub const KEY_THEME_MODE: &str = "ui.theme_mode";
/// Accent preset index (into `Theme.accent-presets`).
pub const KEY_ACCENT_INDEX: &str = "ui.accent_index";
/// Density preset: "0" compact, "1" cosy.
pub const KEY_DENSITY: &str = "ui.density";
/// Terminal font size in pt (integer string).
pub const KEY_FONT_SIZE: &str = "terminal.font_size";
/// Default local shell executable path (may be empty).
pub const KEY_SHELL_PATH: &str = "terminal.shell_path";
/// Extra shell arguments (space-separated; may be empty).
pub const KEY_SHELL_ARGS: &str = "terminal.shell_args";
/// Default working directory for local sessions (may be empty = home).
pub const KEY_SHELL_CWD: &str = "terminal.shell_cwd";
/// Startup behavior: "0" clean start, "1" restore last session.
pub const KEY_STARTUP_BEHAVIOR: &str = "ui.startup_behavior";
/// Last active side-panel index (0 Connections, 1 Keys, 2 Settings).
pub const KEY_ACTIVE_PANEL: &str = "ui.active_panel";
/// Sidebar collapsed: "0" visible, "1" collapsed.
pub const KEY_SIDEBAR_COLLAPSED: &str = "ui.sidebar_collapsed";
/// First-run demo data seeded: "1" = already seeded, absent / "0" = not yet.
/// Gating on this setting (rather than `list_groups().is_empty()`) prevents
/// re-seeding when the user intentionally deletes all groups (CONVENTIONS §P1.5).
pub const KEY_FIRST_RUN_SEEDED: &str = "app.first_run_seeded";

// ---------------------------------------------------------------------------
// AppSettings — the loaded settings snapshot
// ---------------------------------------------------------------------------

/// All persistent UI preferences loaded from the repository at startup.
///
/// Fields are plain Rust values; the service converts to/from strings.
#[derive(Debug, Clone)]
pub struct AppSettings {
    /// 0 dark · 1 light · 2 system
    pub theme_mode: i32,
    /// Index into the accent preset list (0-based).
    pub accent_index: i32,
    /// 0 compact · 1 cosy
    pub density: i32,
    /// Terminal font size (pt).
    pub font_size: i32,
    /// Default local shell path (empty = OS default).
    pub shell_path: String,
    /// Extra shell arguments.
    pub shell_args: String,
    /// Default working directory (empty = home).
    pub shell_cwd: String,
    /// 0 clean start · 1 restore last session
    pub startup_behavior: i32,
    /// Last active side-panel index.
    pub active_panel: i32,
    /// Whether the sidebar was collapsed on last exit.
    pub sidebar_collapsed: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme_mode: 2,   // system
            accent_index: 0, // cool blue
            density: 0,      // compact
            font_size: 13,
            shell_path: String::new(),
            shell_args: String::new(),
            shell_cwd: String::new(),
            startup_behavior: 0, // clean start
            active_panel: 0,     // Connections
            sidebar_collapsed: false,
        }
    }
}

// ---------------------------------------------------------------------------
// SettingsService
// ---------------------------------------------------------------------------

/// Reads and writes [`AppSettings`] through a [`ConnectionRepository`].
///
/// The service is stateless — every call hits the DB.  This is fine because
/// settings are read once on startup and written on change; there is no
/// hot-path concern.
pub struct SettingsService<'a> {
    repo: &'a dyn ConnectionRepository,
}

impl std::fmt::Debug for SettingsService<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SettingsService").finish_non_exhaustive()
    }
}

impl<'a> SettingsService<'a> {
    /// Wrap `repo` in a service.
    pub fn new(repo: &'a dyn ConnectionRepository) -> Self {
        Self { repo }
    }

    /// Load all settings from the repository.  Any missing key falls back to
    /// the [`AppSettings::default`] value; any unparseable value does the same.
    ///
    /// # Errors
    /// Returns [`RepositoryError`] only if the underlying DB call fails in a
    /// way that is not simply "key not present".
    pub fn load(&self) -> Result<AppSettings, RepositoryError> {
        let mut s = AppSettings::default();
        s.theme_mode = self.read_i32(KEY_THEME_MODE, s.theme_mode)?;
        s.accent_index = self.read_i32(KEY_ACCENT_INDEX, s.accent_index)?;
        s.density = self.read_i32(KEY_DENSITY, s.density)?;
        s.font_size = self.read_i32(KEY_FONT_SIZE, s.font_size)?;
        s.shell_path = self.read_string(KEY_SHELL_PATH, &s.shell_path)?;
        s.shell_args = self.read_string(KEY_SHELL_ARGS, &s.shell_args)?;
        s.shell_cwd = self.read_string(KEY_SHELL_CWD, &s.shell_cwd)?;
        s.startup_behavior = self.read_i32(KEY_STARTUP_BEHAVIOR, s.startup_behavior)?;
        s.active_panel = self.read_i32(KEY_ACTIVE_PANEL, s.active_panel)?;
        s.sidebar_collapsed = self.read_bool(KEY_SIDEBAR_COLLAPSED, s.sidebar_collapsed)?;
        Ok(s)
    }

    /// Persist `theme_mode` (0 dark · 1 light · 2 system).
    pub fn save_theme_mode(&self, v: i32) -> Result<(), RepositoryError> {
        self.repo.set_setting(KEY_THEME_MODE, &v.to_string())
    }

    /// Persist `accent_index`.
    pub fn save_accent_index(&self, v: i32) -> Result<(), RepositoryError> {
        self.repo.set_setting(KEY_ACCENT_INDEX, &v.to_string())
    }

    /// Persist `density` (0 compact · 1 cosy).
    pub fn save_density(&self, v: i32) -> Result<(), RepositoryError> {
        self.repo.set_setting(KEY_DENSITY, &v.to_string())
    }

    /// Persist terminal `font_size`.
    pub fn save_font_size(&self, v: i32) -> Result<(), RepositoryError> {
        self.repo.set_setting(KEY_FONT_SIZE, &v.to_string())
    }

    /// Persist default `shell_path`.
    pub fn save_shell_path(&self, v: &str) -> Result<(), RepositoryError> {
        self.repo.set_setting(KEY_SHELL_PATH, v)
    }

    /// Persist default `shell_args`.
    pub fn save_shell_args(&self, v: &str) -> Result<(), RepositoryError> {
        self.repo.set_setting(KEY_SHELL_ARGS, v)
    }

    /// Persist default `shell_cwd`.
    pub fn save_shell_cwd(&self, v: &str) -> Result<(), RepositoryError> {
        self.repo.set_setting(KEY_SHELL_CWD, v)
    }

    /// Persist `startup_behavior`.
    pub fn save_startup_behavior(&self, v: i32) -> Result<(), RepositoryError> {
        self.repo.set_setting(KEY_STARTUP_BEHAVIOR, &v.to_string())
    }

    /// Persist `active_panel`.
    pub fn save_active_panel(&self, v: i32) -> Result<(), RepositoryError> {
        self.repo.set_setting(KEY_ACTIVE_PANEL, &v.to_string())
    }

    /// Persist `sidebar_collapsed`.
    pub fn save_sidebar_collapsed(&self, v: bool) -> Result<(), RepositoryError> {
        self.repo
            .set_setting(KEY_SIDEBAR_COLLAPSED, if v { "1" } else { "0" })
    }

    /// Read whether first-run demo data has been seeded.
    ///
    /// Returns `false` when the key is absent (pre-existing DB) or unparseable.
    pub fn load_first_run_seeded(&self) -> Result<bool, RepositoryError> {
        self.read_bool(KEY_FIRST_RUN_SEEDED, false)
    }

    /// Mark first-run demo data as seeded (persists "1").
    pub fn save_first_run_seeded(&self) -> Result<(), RepositoryError> {
        self.repo.set_setting(KEY_FIRST_RUN_SEEDED, "1")
    }

    // ── private helpers ────────────────────────────────────────────────────

    fn read_i32(&self, key: &str, default: i32) -> Result<i32, RepositoryError> {
        Ok(self
            .repo
            .get_setting(key)?
            .and_then(|v| v.parse().ok())
            .unwrap_or(default))
    }

    fn read_bool(&self, key: &str, default: bool) -> Result<bool, RepositoryError> {
        Ok(self
            .repo
            .get_setting(key)?
            .map(|v| v == "1")
            .unwrap_or(default))
    }

    fn read_string(&self, key: &str, default: &str) -> Result<String, RepositoryError> {
        Ok(self
            .repo
            .get_setting(key)?
            .unwrap_or_else(|| default.to_owned()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteRepository;

    fn fresh() -> SqliteRepository {
        SqliteRepository::open_in_memory().expect("in-memory repo")
    }

    #[test]
    fn defaults_returned_on_empty_db() {
        let repo = fresh();
        let svc = SettingsService::new(&repo);
        let s = svc.load().expect("load");
        assert_eq!(s.theme_mode, 2);
        assert_eq!(s.density, 0);
        assert_eq!(s.font_size, 13);
        assert!(!s.sidebar_collapsed);
        assert_eq!(s.active_panel, 0);
    }

    #[test]
    fn round_trip_all_fields() {
        let repo = fresh();
        let svc = SettingsService::new(&repo);

        svc.save_theme_mode(1).unwrap();
        svc.save_accent_index(3).unwrap();
        svc.save_density(1).unwrap();
        svc.save_font_size(16).unwrap();
        svc.save_shell_path("/usr/bin/zsh").unwrap();
        svc.save_shell_args("--login").unwrap();
        svc.save_shell_cwd("/home/user").unwrap();
        svc.save_startup_behavior(1).unwrap();
        svc.save_active_panel(2).unwrap();
        svc.save_sidebar_collapsed(true).unwrap();

        let s = svc.load().unwrap();
        assert_eq!(s.theme_mode, 1);
        assert_eq!(s.accent_index, 3);
        assert_eq!(s.density, 1);
        assert_eq!(s.font_size, 16);
        assert_eq!(s.shell_path, "/usr/bin/zsh");
        assert_eq!(s.shell_args, "--login");
        assert_eq!(s.shell_cwd, "/home/user");
        assert_eq!(s.startup_behavior, 1);
        assert_eq!(s.active_panel, 2);
        assert!(s.sidebar_collapsed);
    }

    #[test]
    fn corrupt_value_falls_back_to_default() {
        let repo = fresh();
        repo.set_setting(KEY_FONT_SIZE, "not-a-number").unwrap();
        let svc = SettingsService::new(&repo);
        let s = svc.load().unwrap();
        assert_eq!(s.font_size, 13, "corrupt value should fall back to default");
    }

    #[test]
    fn overwrite_updates_value() {
        let repo = fresh();
        let svc = SettingsService::new(&repo);
        svc.save_theme_mode(0).unwrap();
        svc.save_theme_mode(1).unwrap();
        let s = svc.load().unwrap();
        assert_eq!(s.theme_mode, 1);
    }
}

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
//!
//! **P6.15:** moved here from `cm-storage::settings` — this module only ever
//! depended on the [`ConnectionRepository`] *port*, never on the concrete
//! SQLite adapter, so it belongs in `cm-core` with the rest of the port
//! surface (gap 27 cont. — cuts the `cm-ui` → `cm-storage` concrete edge for
//! `SettingsService`/`AppSettings`; see
//! `docs/devel/memos/P6.15-sessionprovider-port.md`). Named `app_settings`
//! (not `settings`) to avoid colliding with `cm-core`'s existing, unrelated
//! private `settings` module (`ConnectionSettings`/`RdpSettings`/
//! `SshSettings` — per-connection-kind settings, not app-wide preferences).

use crate::error::RepositoryError;
use crate::ids::ConnectionId;
use crate::ports::ConnectionRepository;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Key constants (single source of truth)
// ---------------------------------------------------------------------------

/// Theme mode: "0" dark, "1" light, "2" system.
pub(crate) const KEY_THEME_MODE: &str = "ui.theme_mode";
/// Accent preset index (into `Theme.accent-presets`).
pub(crate) const KEY_ACCENT_INDEX: &str = "ui.accent_index";
/// Density preset: "0" compact, "1" cosy.
pub(crate) const KEY_DENSITY: &str = "ui.density";
/// Terminal font size in pt (integer string).
pub(crate) const KEY_FONT_SIZE: &str = "terminal.font_size";
/// Default local shell executable path (may be empty).
pub(crate) const KEY_SHELL_PATH: &str = "terminal.shell_path";
/// Extra shell arguments (space-separated; may be empty).
pub(crate) const KEY_SHELL_ARGS: &str = "terminal.shell_args";
/// Default working directory for local sessions (may be empty = home).
pub(crate) const KEY_SHELL_CWD: &str = "terminal.shell_cwd";
/// Startup behavior: "0" clean start, "1" restore last session.
pub(crate) const KEY_STARTUP_BEHAVIOR: &str = "ui.startup_behavior";
/// Last active side-panel index (0 Connections, 1 Keys, 2 Settings).
pub(crate) const KEY_ACTIVE_PANEL: &str = "ui.active_panel";
/// Sidebar collapsed: "0" visible, "1" collapsed.
pub(crate) const KEY_SIDEBAR_COLLAPSED: &str = "ui.sidebar_collapsed";
/// Side-panel width in logical px (integer string). P6.9 gap 11: the
/// `side-panel-width` token comment promised this persistence since P5.2.
pub(crate) const KEY_SIDE_PANEL_WIDTH: &str = "ui.side_panel_width";
/// First-run demo data seeded: "1" = already seeded, absent / "0" = not yet.
/// Gating on this setting (rather than `list_groups().is_empty()`) prevents
/// re-seeding when the user intentionally deletes all groups (CONVENTIONS §P1.5).
/// `pub` (not `pub(crate)`) — unlike the other keys above, this one is also
/// referenced from `cm-storage`'s export-envelope exclusion list
/// (`EXPORT_EXCLUDED_SETTING_KEYS`) so that list can reference the constant
/// instead of duplicating the literal string (drift guard).
pub const KEY_FIRST_RUN_SEEDED: &str = "app.first_run_seeded";
/// Persisted "restore last session" tab snapshot (P6.14, gap 4) — a JSON
/// [`SessionTabSnapshot`]. Absent, empty, or malformed all mean "nothing to
/// restore" (see [`SettingsService::load_session_tabs`]). Reuses the existing
/// `settings` key/value store rather than a new table: this is a single,
/// wholesale-replaced blob (never queried/filtered in SQL), unlike `recents`
/// which needs per-row upsert + ordering (see the schema memo).
///
/// `pub` (not `pub(crate)`) — see [`KEY_FIRST_RUN_SEEDED`]'s note; also
/// referenced from `cm-storage`'s export-envelope exclusion list.
pub const KEY_SESSION_TABS: &str = "ui.session_tabs";
/// Cached renderer backend (P7.1 cont.): persisted result of the startup
/// renderer probe so the expensive GPU-less probe runs at most once. One of
/// "software" | "accelerated" | "auto" (or absent). "auto"/absent means
/// "probe each launch"; only the "software" fallback is auto-persisted (safe
/// to carry to other hardware), never "accelerated" (see `render_backend`).
///
/// `pub` (not `pub(crate)`) — see [`KEY_FIRST_RUN_SEEDED`]'s note; also
/// referenced from `cm-storage`'s export-envelope exclusion list (P7.1 cont.:
/// a cached `accelerated` must never cross machines, see that list's docs).
pub const KEY_RENDERER_BACKEND: &str = "render.backend";

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
    /// Side-panel width in logical px, persisted across restarts (P6.9 gap 11).
    pub side_panel_width: i32,
    /// Persisted renderer backend (P7.1 cont.): "auto" (probe each launch),
    /// "software", or "accelerated". "auto" is the default. Surfaced in the
    /// Settings "Rendering" control; the actual renderer switch takes effect on
    /// the next launch.
    pub renderer_backend: String,
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
            side_panel_width: 252, // matches Theme.side-panel-width (cm-ui/ui/theme.slint)
            renderer_backend: "auto".to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Session-tab restore (P6.14, gap 4)
// ---------------------------------------------------------------------------

/// One restorable tab slot. Carries only what's needed to *reopen* a session,
/// never live state or secrets:
/// - `Local` — a plain local shell; restores as a fresh shell.
/// - `Connection` — a tree-launched, stored connection; restores through the
///   same credential-resolving connect path used everywhere else (the secret
///   is fetched fresh from the keychain, never cached here).
///
/// Any tab without a resolvable stored connection (quick-connect, reattached
/// sessions) is recorded as `Local` on save — there is nothing safe to
/// replay for those without either caching a secret or re-prompting, and the
/// task spec only asks for the tree-launched case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionTabEntry {
    Local,
    Connection(ConnectionId),
}

/// The full "last session" snapshot: an ordered tab list plus which one was
/// active. `active` is an index into `tabs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SessionTabSnapshot {
    pub tabs: Vec<SessionTabEntry>,
    pub active: usize,
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
        s.side_panel_width = self.read_i32(KEY_SIDE_PANEL_WIDTH, s.side_panel_width)?;
        // Read the raw value (including "auto") for the Settings UI; the
        // separate `load_renderer_backend` collapses "auto"/absent to None for
        // the startup precedence logic.
        s.renderer_backend = self.read_string(KEY_RENDERER_BACKEND, &s.renderer_backend)?;
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

    /// Persist `side_panel_width` (logical px).
    pub fn save_side_panel_width(&self, v: i32) -> Result<(), RepositoryError> {
        self.repo.set_setting(KEY_SIDE_PANEL_WIDTH, &v.to_string())
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

    /// Persist the "restore last session" tab snapshot (P6.14). Always
    /// writes, even an empty snapshot — [`load_session_tabs`] treats an
    /// empty `tabs` list the same as "absent".
    ///
    /// [`load_session_tabs`]: Self::load_session_tabs
    pub fn save_session_tabs(&self, snapshot: &SessionTabSnapshot) -> Result<(), RepositoryError> {
        // Our own struct, our own serializer -- this can't fail in practice,
        // but never panic on it (CONVENTIONS §2): fall back to an empty
        // snapshot's JSON rather than unwrap.
        let json = serde_json::to_string(snapshot).unwrap_or_else(|_| "{\"tabs\":[]}".to_owned());
        self.repo.set_setting(KEY_SESSION_TABS, &json)
    }

    /// Load the "restore last session" tab snapshot. Returns `Ok(None)` when
    /// the key is absent, the JSON is malformed (defensively parsed --
    /// CONVENTIONS §2: stored files are untrusted), or the snapshot's tab
    /// list is empty.
    pub fn load_session_tabs(&self) -> Result<Option<SessionTabSnapshot>, RepositoryError> {
        let Some(raw) = self.repo.get_setting(KEY_SESSION_TABS)? else {
            return Ok(None);
        };
        match serde_json::from_str::<SessionTabSnapshot>(&raw) {
            Ok(snap) if !snap.tabs.is_empty() => Ok(Some(snap)),
            _ => Ok(None),
        }
    }

    /// Cached renderer backend. `Ok(None)` when absent or "auto" (= probe each
    /// launch); otherwise the persisted backend string ("software" |
    /// "accelerated").
    pub fn load_renderer_backend(&self) -> Result<Option<String>, RepositoryError> {
        Ok(self
            .repo
            .get_setting(KEY_RENDERER_BACKEND)?
            .filter(|v| v != "auto" && !v.is_empty()))
    }

    /// Persist renderer backend ("software" | "accelerated" | "auto").
    pub fn save_renderer_backend(&self, v: &str) -> Result<(), RepositoryError> {
        self.repo.set_setting(KEY_RENDERER_BACKEND, v)
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
    use crate::connection::{Connection, Group};
    use crate::credential::{Credential, CredentialFolder};
    use crate::error::RepositoryError;
    use crate::ids::{CredentialFolderId, CredentialId, GroupId};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Minimal in-memory [`ConnectionRepository`] fake, settings-only (P6.15:
    /// `app_settings` moved from `cm-storage` to `cm-core`, which cannot
    /// depend on `cm-storage::SqliteRepository` — that would be a
    /// cm-core -> cm-storage dependency, the wrong direction). Every method
    /// besides `get_setting`/`set_setting` is a harmless stub; nothing in
    /// this test module calls them (mirrors the stub style already used by
    /// `cm-core/tests/domain.rs`'s own `InMemoryRepo`).
    #[derive(Default)]
    struct FakeRepo {
        settings: Mutex<HashMap<String, String>>,
    }

    impl ConnectionRepository for FakeRepo {
        fn list_connections(&self) -> Result<Vec<Connection>, RepositoryError> {
            Ok(Vec::new())
        }
        fn get_connection(&self, _id: ConnectionId) -> Result<Option<Connection>, RepositoryError> {
            Ok(None)
        }
        fn upsert_connection(&self, _conn: &Connection) -> Result<ConnectionId, RepositoryError> {
            Err(RepositoryError::Backend(
                "not implemented in FakeRepo".into(),
            ))
        }
        fn delete_connection(&self, _id: ConnectionId) -> Result<(), RepositoryError> {
            Ok(())
        }
        fn move_connection(
            &self,
            _id: ConnectionId,
            _new_group: Option<GroupId>,
            _new_sort: i64,
        ) -> Result<(), RepositoryError> {
            Ok(())
        }
        fn list_groups(&self) -> Result<Vec<Group>, RepositoryError> {
            Ok(Vec::new())
        }
        fn get_group(&self, _id: GroupId) -> Result<Option<Group>, RepositoryError> {
            Ok(None)
        }
        fn upsert_group(&self, _group: &Group) -> Result<GroupId, RepositoryError> {
            Err(RepositoryError::Backend(
                "not implemented in FakeRepo".into(),
            ))
        }
        fn delete_group(&self, _id: GroupId) -> Result<(), RepositoryError> {
            Ok(())
        }
        fn move_group(
            &self,
            _id: GroupId,
            _new_parent: Option<GroupId>,
            _new_sort: i64,
        ) -> Result<(), RepositoryError> {
            Ok(())
        }
        fn list_credentials(&self) -> Result<Vec<Credential>, RepositoryError> {
            Ok(Vec::new())
        }
        fn get_credential(&self, _id: CredentialId) -> Result<Option<Credential>, RepositoryError> {
            Ok(None)
        }
        fn upsert_credential(&self, _cred: &Credential) -> Result<CredentialId, RepositoryError> {
            Err(RepositoryError::Backend(
                "not implemented in FakeRepo".into(),
            ))
        }
        fn delete_credential(&self, _id: CredentialId) -> Result<(), RepositoryError> {
            Ok(())
        }
        fn list_credential_folders(&self) -> Result<Vec<CredentialFolder>, RepositoryError> {
            Ok(Vec::new())
        }
        fn get_credential_folder(
            &self,
            _id: CredentialFolderId,
        ) -> Result<Option<CredentialFolder>, RepositoryError> {
            Ok(None)
        }
        fn upsert_credential_folder(
            &self,
            _folder: &CredentialFolder,
        ) -> Result<CredentialFolderId, RepositoryError> {
            Err(RepositoryError::Backend(
                "not implemented in FakeRepo".into(),
            ))
        }
        fn delete_credential_folder(&self, _id: CredentialFolderId) -> Result<(), RepositoryError> {
            Ok(())
        }
        fn move_credential_folder(
            &self,
            _id: CredentialFolderId,
            _new_parent: Option<CredentialFolderId>,
            _new_sort: i64,
        ) -> Result<(), RepositoryError> {
            Ok(())
        }
        fn resolve_effective_credential(
            &self,
            _conn_id: ConnectionId,
        ) -> Result<Option<CredentialId>, RepositoryError> {
            Ok(None)
        }
        fn get_setting(&self, key: &str) -> Result<Option<String>, RepositoryError> {
            Ok(self.settings.lock().unwrap().get(key).cloned())
        }
        fn set_setting(&self, key: &str, value: &str) -> Result<(), RepositoryError> {
            self.settings
                .lock()
                .unwrap()
                .insert(key.to_owned(), value.to_owned());
            Ok(())
        }
        fn list_settings(&self) -> Result<Vec<(String, String)>, RepositoryError> {
            Ok(self
                .settings
                .lock()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        }
        fn record_recent(&self, _id: ConnectionId, _opened_at: i64) -> Result<(), RepositoryError> {
            Ok(())
        }
        fn list_recents(&self, _limit: usize) -> Result<Vec<(ConnectionId, i64)>, RepositoryError> {
            Ok(Vec::new())
        }
    }

    fn fresh() -> FakeRepo {
        FakeRepo::default()
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
        assert_eq!(s.side_panel_width, 252);
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
        svc.save_side_panel_width(340).unwrap();

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
        assert_eq!(s.side_panel_width, 340);
    }

    #[test]
    fn side_panel_width_round_trips_independently() {
        let repo = fresh();
        let svc = SettingsService::new(&repo);
        assert_eq!(svc.load().unwrap().side_panel_width, 252, "default");
        svc.save_side_panel_width(180).unwrap();
        assert_eq!(svc.load().unwrap().side_panel_width, 180);
        svc.save_side_panel_width(480).unwrap();
        assert_eq!(svc.load().unwrap().side_panel_width, 480);
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

    // ── P6.14: session-tab restore snapshot ─────────────────────────────

    #[test]
    fn load_session_tabs_absent_is_none() {
        let repo = fresh();
        let svc = SettingsService::new(&repo);
        assert_eq!(svc.load_session_tabs().unwrap(), None);
    }

    #[test]
    fn session_tabs_round_trip() {
        let repo = fresh();
        let svc = SettingsService::new(&repo);
        let snap = SessionTabSnapshot {
            tabs: vec![
                SessionTabEntry::Connection(ConnectionId::new(7)),
                SessionTabEntry::Local,
                SessionTabEntry::Connection(ConnectionId::new(3)),
            ],
            active: 1,
        };
        svc.save_session_tabs(&snap).unwrap();
        let loaded = svc.load_session_tabs().unwrap().expect("snapshot present");
        assert_eq!(loaded, snap);
    }

    #[test]
    fn saving_an_empty_snapshot_loads_as_none() {
        let repo = fresh();
        let svc = SettingsService::new(&repo);
        svc.save_session_tabs(&SessionTabSnapshot::default())
            .unwrap();
        assert_eq!(svc.load_session_tabs().unwrap(), None);
    }

    #[test]
    fn corrupt_session_tabs_json_falls_back_to_none() {
        let repo = fresh();
        repo.set_setting(KEY_SESSION_TABS, "not json").unwrap();
        let svc = SettingsService::new(&repo);
        assert_eq!(svc.load_session_tabs().unwrap(), None);
    }

    // ── P7.1: cached renderer backend ────────────────────────────────────

    #[test]
    fn renderer_backend_absent_is_none() {
        let repo = fresh();
        let svc = SettingsService::new(&repo);
        assert_eq!(svc.load_renderer_backend().unwrap(), None);
    }

    #[test]
    fn renderer_backend_round_trips() {
        let repo = fresh();
        let svc = SettingsService::new(&repo);
        svc.save_renderer_backend("software").unwrap();
        assert_eq!(
            svc.load_renderer_backend().unwrap(),
            Some("software".to_owned())
        );
        svc.save_renderer_backend("accelerated").unwrap();
        assert_eq!(
            svc.load_renderer_backend().unwrap(),
            Some("accelerated".to_owned())
        );
    }

    #[test]
    fn renderer_backend_auto_or_empty_is_none() {
        let repo = fresh();
        let svc = SettingsService::new(&repo);
        svc.save_renderer_backend("auto").unwrap();
        assert_eq!(
            svc.load_renderer_backend().unwrap(),
            None,
            "\"auto\" means probe each launch"
        );
        svc.save_renderer_backend("").unwrap();
        assert_eq!(svc.load_renderer_backend().unwrap(), None, "empty is None");
    }
}

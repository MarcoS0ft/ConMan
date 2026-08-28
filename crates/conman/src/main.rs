// B1: run as a Windows GUI app in release (no allocated console window).
// Debug keeps the console so the `tracing` stderr layer stays visible (see
// `logging.rs`); release logs to a rotating file instead.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! `conman` — the application binary and composition root.
//!
//! Opens a file-backed SQLite database resolved by `cm-platform::app_db_path`
//! for connections and machine-local state, plus an editable `config.conman`
//! resolved by `cm-platform::app_config_path` for user preferences.
//!
//! Dev-only convenience: behind the off-by-default `demo-seed` cargo feature,
//! a small demo dataset is seeded into an otherwise-empty DB on the very
//! first launch. Never present in a shipped/release artifact — opt in with
//! `cargo build -p conman --features demo-seed` (same posture as
//! `automation`).
//!
//! P6.16: before touching its selected config/database paths, acquires an
//! identity-scoped primary-instance lock (`cm_platform::single_instance`). A
//! second launch for the same paths activates that primary and exits; a launch
//! for another path pair remains independent.
//!
//! P6.3: installs the `tracing` subscriber before threaded startup begins (see
//! `logging.rs`) — a rotating file layer under `cm_platform::app_log_dir()` in
//! both builds (P9.8 §2a: debug used to be stderr-only, losing repros), plus a
//! console layer in debug (`windows_subsystem = "windows"` swallows stderr in
//! release, so the console layer is debug-only).
//!
//! P7.1: before logging or any Slint initialization, decides the renderer
//! (`render_backend::resolve`) — honors `SLINT_BACKEND`, then the editable
//! renderer preference, then machine-local probe state; automatic mode probes
//! the accelerated (winit+femtovg) renderer in a disposable
//! child process and forces the software renderer if it doesn't come up
//! (e.g. no usable hardware OpenGL), so the app renders instead of crashing.
//! This must run **before** `logging::init()` (see `render_backend`'s module
//! docs) — the decision is logged afterward, once a subscriber exists.

#[cfg(feature = "agent-mode")]
mod agent_mode;
mod logging;
mod render_backend;

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::Receiver;

use cm_core::{
    AppConfigError, AppConfigStore, AppSettings, AppStateRepository, AppStateService,
    LoadedAppSettings, SettingsService,
};
use cm_platform::app_log_dir;
use cm_platform::single_instance::{self, AcquireOutcome, InstanceIdentity};
use cm_platform::{
    TextConfigStore, app_config_path_candidate, app_db_path_candidate, prepare_app_config_path,
    prepare_app_db_path,
};
use cm_secrets::KeyringStore;
use cm_session::SessionProviderImpl;
use cm_storage::SqliteRepository;
use cm_ui::AppConfig;

// Pull the backend/renderer features into the shared `slint` build.
use slint as _;

fn main() -> ExitCode {
    // Parse all supported process arguments before renderer, filesystem,
    // database, keychain, or single-instance initialization. Help/version
    // remain effect-free and invalid combinations fail with usage instead of
    // accidentally launching with ignored arguments.
    let invocation = match cm_cli::parse_gui_args(std::env::args_os().skip(1)) {
        Ok(cm_cli::GuiParseOutcome::Run(invocation)) => invocation,
        Ok(cm_cli::GuiParseOutcome::Help(help) | cm_cli::GuiParseOutcome::Version(help)) => {
            return match cm_platform::write_stdout_line(&help) {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            };
        }
        Err(error) => {
            let _ = cm_platform::write_stderr_line(&error.render());
            return ExitCode::from(error.exit_code() as u8);
        }
    };

    // P7.1: the disposable renderer-probe child takes this branch and exits
    // immediately — no logging subscriber, no single-instance guard, no
    // storage, no keyring. See the `render_backend` module docs.
    if std::env::var_os(render_backend::PROBE_ENV_VAR).is_some() {
        return render_backend::run_probe_child();
    }

    // Capture both CLI and environment-selected identities before the
    // single-instance responder thread starts. CLI values win. Keeping these
    // as PathBuf/OsString throughout also preserves non-Unicode paths.
    let path_overrides = StartupPathOverrides::select(
        invocation,
        std::env::var_os(cm_platform::CONFIG_PATH_ENV_VAR),
        std::env::var_os(cm_platform::DB_PATH_ENV_VAR),
    );
    let startup_paths = match path_overrides.resolve() {
        Ok(paths) => paths,
        Err(error) => {
            write_startup_error(format_args!(
                "fatal: could not resolve configuration or database path: {error}"
            ));
            return ExitCode::FAILURE;
        }
    };
    let instance_identity = match InstanceIdentity::from_paths(
        &startup_paths.config_path,
        &startup_paths.database_path,
    ) {
        Ok(identity) => identity,
        Err(error) => {
            write_startup_error(format_args!(
                "fatal: could not derive the application instance identity: {error}"
            ));
            return ExitCode::FAILURE;
        }
    };

    // Acquire the identity-scoped lock before creating, reading, probing, or
    // migrating either selected path. A second launch with the same effective
    // pair activates its primary; a different pair owns an independent lock.
    let activation_rx = match preflight_single_instance(
        &instance_identity,
        single_instance::acquire,
    ) {
        Ok(preflight) => preflight,
        Err(PreflightExit::ActivatedPrimary) => {
            let _ = cm_platform::write_stdout_line(
                "another instance is already running; it has been asked to come to the foreground.",
            );
            return ExitCode::SUCCESS;
        }
        Err(PreflightExit::InstanceGuardUnavailable(reason)) => {
            write_startup_error(format_args!(
                "fatal: could not verify exclusive startup ({reason}); refusing to launch without the instance lock"
            ));
            return ExitCode::FAILURE;
        }
    };

    // Resolve and read the user-editable configuration before renderer or
    // storage initialization. Invalid values fall back independently inside
    // `SettingsService`; a syntax error falls back to all defaults for this
    // launch so a hand edit can never make the GUI unavailable. Genuine I/O
    // failures remain fatal because silently ignoring an unreadable config
    // would be surprising and could weaken automation policy.
    let config_path = match prepare_app_config_path(startup_paths.config_path) {
        Ok(path) => path,
        Err(error) => {
            write_startup_error(format_args!(
                "fatal: could not prepare configuration path: {error}"
            ));
            return ExitCode::FAILURE;
        }
    };
    let config_store = Arc::new(TextConfigStore::new(&config_path));
    let loaded_settings = match load_startup_settings(config_store.as_ref()) {
        Ok(settings) => settings,
        Err(error) => {
            write_startup_error(format_args!("fatal: could not read configuration: {error}"));
            return ExitCode::FAILURE;
        }
    };

    // P7.1 cont.: open storage *before* the renderer probe so the machine-local
    // renderer-backend cache can be consulted. Path preparation and
    // `SqliteRepository::open()` do not add any further background work. The
    // only live worker is the deliberately environment-blind single-instance
    // responder; see `render_backend::force_software_backend`'s invariant.
    let db_path = match prepare_app_db_path(startup_paths.database_path) {
        Ok(path) => path,
        Err(error) => {
            write_startup_error(format_args!(
                "fatal: could not prepare database path: {error}"
            ));
            return ExitCode::FAILURE;
        }
    };
    let repo_result = SqliteRepository::open(&db_path);
    let cached_renderer = repo_result
        .as_ref()
        .ok()
        .and_then(|repo| AppStateService::new(repo).load_renderer_probe_cache().ok())
        .flatten();

    // P7.1: resolve (and, if needed, apply) the renderer choice *before*
    // installing the logging subscriber. Forcing the software fallback needs
    // `std::env::set_var`; the already-running single-instance responder is
    // audited never to inspect or mutate the environment. See
    // `render_backend::force_software_backend`'s full invariant. Precedence:
    // explicit `SLINT_BACKEND` env
    // > explicit text-config preference > machine-local probe cache > probe.
    let renderer_decision =
        render_backend::resolve(loaded_settings.settings.renderer_backend, cached_renderer);

    // P8.6-A: same environment-safe window as the renderer decision above —
    // if agent-mode is enabled, this sets `SLINT_MCP_PORT` via `unsafe
    // std::env::set_var` before the Slint backend (which reads it) ever
    // initializes. See `agent_mode::prepare`'s doc comment.
    #[cfg(feature = "agent-mode")]
    let agent_mode_prepared = agent_mode::prepare(config_store.as_ref());

    // Install the tracing subscriber — everything below may log.
    let _logging_guard = logging::init();

    let build = cm_build_info::BuildInfo::current();
    tracing::info!(
        version = build.version,
        git_sha = build.git_sha.unwrap_or("unknown"),
        revision_count = ?build.revision_count,
        dirty = build.dirty,
        target = build.target,
        profile = build.profile,
        "conman starting"
    );
    let build_identity = ui_build_identity(build);
    tracing::info!(
        db = %db_path.display(),
        config = %config_path.display(),
        log_dir = %app_log_dir().unwrap_or_else(|_| std::env::temp_dir()).display(),
        "app dirs resolved"
    );
    if let Some(syntax_warning) = &loaded_settings.syntax_warning {
        tracing::warn!(reason = %syntax_warning, "configuration syntax error; using defaults for this launch");
    }
    for warning in &loaded_settings.warnings {
        tracing::warn!(
            key = warning.key.as_str(),
            value = %warning.value,
            reason = %warning.message,
            "invalid configuration value; using the built-in default"
        );
    }

    // Now that a subscriber exists, report the decision made above.
    render_backend::log_decision(&renderer_decision);

    // The DB open result is needed from here on; a failure is fatal.
    let repo = match repo_result {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("fatal: failed to open storage: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Install the platform-native keyring backend before any KeyringStore is
    // constructed.  Falls back to the in-memory mock backend if the native
    // backend is unavailable (headless CI, missing daemon, etc.) so startup
    // never fails due to keychain issues.
    cm_secrets::initialize_native_keyring();

    // Attach the keychain exactly once, then share this one opened SQLite
    // adapter through its independent connection, atomic-import, and
    // machine-state ports. This keeps them in one transaction domain without
    // conflating their interfaces.
    let secrets: Arc<dyn cm_core::CredentialStore> = Arc::new(KeyringStore::new());
    let repo = Arc::new(repo.with_credential_store(Arc::clone(&secrets)));
    let connection_repo: Arc<dyn cm_core::ConnectionRepository> = repo.clone();
    let import_repo: Arc<dyn cm_storage::AtomicImportRepository> = repo.clone();
    let app_state: Arc<dyn AppStateRepository> = repo;

    if let Some(new_value) = render_backend::persist_decision(&renderer_decision, cached_renderer)
        && let Err(error) =
            AppStateService::new(app_state.as_ref()).save_renderer_probe_cache(new_value)
    {
        tracing::warn!("could not persist renderer probe cache: {error}");
    }

    // P8.6-A: start the scope-enforcement proxy's accept-loop thread now
    // that a subscriber exists and thread-spawning is unrestricted — the
    // env-var-setting half already ran above, before `logging::init()`. A
    // `None` here (agent-mode disabled, or the feature isn't compiled in)
    // means no listener at all.
    #[cfg(feature = "agent-mode")]
    let agent_mode_handle = agent_mode_prepared.map(agent_mode::spawn);

    // P8.6-B: mirror the handle's cm-ui-relevant fields into the
    // cm-ui-owned `AgentModeConfig` (cm-ui cannot depend on conman's
    // `agent_mode::AgentModeHandle` directly -- see that type's doc comment).
    // Always constructed (as `None` outside the feature) so `build_config`'s
    // signature stays the same regardless of which features this binary was
    // built with.
    #[cfg(feature = "agent-mode")]
    let agent_mode_config = agent_mode_handle.map(|h| cm_ui::AgentModeConfig {
        external_port: h.external_port,
        scopes: h.scopes,
        mcp_interaction_count: h.mcp_interaction_count,
    });
    #[cfg(not(feature = "agent-mode"))]
    let agent_mode_config: Option<cm_ui::AgentModeConfig> = None;

    let config_store: Arc<dyn AppConfigStore> = config_store;
    let services = AppServices {
        repo: connection_repo,
        import_repo,
        app_state,
        config_store,
        config_path,
        build_identity,
        secrets,
    };
    let config = match build_config(services, activation_rx, agent_mode_config) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("fatal: failed to initialise storage: {e}");
            return ExitCode::FAILURE;
        }
    };
    match cm_ui::run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("fatal: {e}");
            ExitCode::FAILURE
        }
    }
}

fn write_startup_error(message: std::fmt::Arguments<'_>) {
    let safe = sanitized_startup_message(message);
    let _ = cm_platform::write_stderr_line(&safe);
}

fn sanitized_startup_message(message: std::fmt::Arguments<'_>) -> String {
    cm_cli::neutralize_terminal_text(&message.to_string())
}

struct StartupPathOverrides {
    config_path: Option<std::path::PathBuf>,
    database_path: Option<std::path::PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
struct StartupPaths {
    config_path: std::path::PathBuf,
    database_path: std::path::PathBuf,
}

impl StartupPathOverrides {
    fn select(
        invocation: cm_cli::GuiInvocation,
        environment_config: Option<std::ffi::OsString>,
        environment_database: Option<std::ffi::OsString>,
    ) -> Self {
        Self {
            config_path: invocation
                .config_path
                .or_else(|| environment_config.map(std::path::PathBuf::from)),
            database_path: invocation
                .database_path
                .or_else(|| environment_database.map(std::path::PathBuf::from)),
        }
    }

    fn resolve(self) -> Result<StartupPaths, cm_platform::PlatformError> {
        Ok(StartupPaths {
            config_path: match self.config_path {
                Some(path) => path,
                None => app_config_path_candidate()?,
            },
            database_path: match self.database_path {
                Some(path) => path,
                None => app_db_path_candidate()?,
            },
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PreflightExit {
    ActivatedPrimary,
    InstanceGuardUnavailable(String),
}

fn preflight_single_instance(
    identity: &InstanceIdentity,
    acquire: impl FnOnce(&InstanceIdentity) -> AcquireOutcome,
) -> Result<Option<Receiver<()>>, PreflightExit> {
    match acquire(identity) {
        // Start servicing immediately. The mpsc channel buffers activation
        // events until the UI consumes it after the rest of startup.
        AcquireOutcome::Acquired(handle) => Ok(Some(handle.into_activation_receiver())),
        AcquireOutcome::AlreadyRunning => Err(PreflightExit::ActivatedPrimary),
        AcquireOutcome::Unavailable(reason) => Err(PreflightExit::InstanceGuardUnavailable(reason)),
    }
}

fn ui_build_identity(build: cm_build_info::BuildInfo) -> cm_ui::BuildIdentity {
    cm_ui::BuildIdentity {
        version: build.version.to_owned(),
        details: format!(
            "Version: {}\nGit SHA: {}\nRevision: {}\nTarget: {}\nProfile: {}\nDirty: {}",
            build.version,
            build.git_sha.unwrap_or("unknown"),
            build
                .revision_count
                .map_or_else(|| "unknown".to_owned(), |revision| revision.to_string()),
            build.target,
            build.profile,
            build.dirty,
        ),
    }
}

struct StartupSettings {
    settings: AppSettings,
    warnings: Vec<cm_core::SettingWarning>,
    syntax_warning: Option<String>,
}

/// Load the text configuration with resilient hand-edit semantics.
///
/// Known invalid values are already converted to per-key warnings by the
/// core service. A syntactically malformed document cannot be queried by the
/// line-preserving store, so use the complete default snapshot for this
/// launch and retain the error for the startup log. Backend/I/O errors are
/// returned to the caller as fatal.
fn load_startup_settings(store: &dyn AppConfigStore) -> Result<StartupSettings, AppConfigError> {
    match SettingsService::new(store).load_with_warnings() {
        Ok(LoadedAppSettings { settings, warnings }) => Ok(StartupSettings {
            settings,
            warnings,
            syntax_warning: None,
        }),
        Err(error @ AppConfigError::Backend(_)) => Err(error),
        Err(error @ AppConfigError::Syntax { .. }) => Ok(StartupSettings {
            settings: AppSettings::default(),
            warnings: Vec::new(),
            syntax_warning: Some(error.to_string()),
        }),
        // `SettingsService::load_with_warnings` handles invalid known values
        // without returning them. Keep this branch defensive for future
        // non-exhaustive variants while preserving startup availability.
        Err(error) => Ok(StartupSettings {
            settings: AppSettings::default(),
            warnings: Vec::new(),
            syntax_warning: Some(error.to_string()),
        }),
    }
}

/// Build the [`AppConfig`] that the UI controller receives.
///
/// Receives the already-composed connection, app-state, text-config, and
/// keychain ports. Only when the dev-only `demo-seed` feature is enabled is a
/// small demo dataset seeded into a brand-new database; shipped builds leave
/// it empty for the Launchpad/welcome flow.
///
/// `activation_rx` (P6.16) is threaded straight through from the
/// single-instance guard acquired in `main` into the returned [`AppConfig`].
///
/// `agent_mode` (P8.6-B) is likewise threaded straight through -- `None`
/// unless `main` built (and the user enabled) the agent-mode proxy.
struct AppServices {
    repo: Arc<dyn cm_core::ConnectionRepository>,
    import_repo: Arc<dyn cm_storage::AtomicImportRepository>,
    app_state: Arc<dyn AppStateRepository>,
    config_store: Arc<dyn AppConfigStore>,
    config_path: std::path::PathBuf,
    build_identity: cm_ui::BuildIdentity,
    secrets: Arc<dyn cm_core::CredentialStore>,
}

fn build_config(
    services: AppServices,
    activation_rx: Option<Receiver<()>>,
    agent_mode: Option<cm_ui::AgentModeConfig>,
) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let AppServices {
        repo,
        import_repo,
        app_state,
        config_store,
        config_path,
        build_identity,
        secrets,
    } = services;
    // First-run state is machine-local and deliberately lives outside both
    // the editable config and the connection repository interface.
    let first_launch = {
        let svc = AppStateService::new(app_state.as_ref());
        let already_seeded = svc.load_first_run_seeded()?;
        let mut first_launch = false;
        if !already_seeded {
            if repo.list_groups()?.is_empty() {
                #[cfg(feature = "demo-seed")]
                seed_demo_data(repo.as_ref())?;
                first_launch = true;
            }
            svc.save_first_run_seeded()?;
        }
        first_launch
    };

    // Clipboard staging is bootstrapped once and shared with the UI worker and
    // concrete RDP provider. Failure disables file transfer only.
    let (secure_clipboard_root, provider_clipboard_root) =
        compose_clipboard_dependencies(cm_platform::secure_temp::SecureClipboardRoot::bootstrap);

    // ── Session provider (P6.15, gap 27) ────────────────────────────────────
    let session_provider: Arc<dyn cm_core::SessionProvider> =
        Arc::new(SessionProviderImpl::new(provider_clipboard_root));

    Ok(AppConfig {
        repo,
        import_repo,
        app_state,
        config_store,
        config_path,
        build_identity,
        secrets,
        session_provider,
        secure_clipboard_root,
        activation_rx,
        first_launch,
        agent_mode,
    })
}

fn compose_clipboard_dependencies<F>(
    bootstrap: F,
) -> (
    Option<Arc<cm_platform::secure_temp::SecureClipboardRoot>>,
    Option<Arc<cm_platform::secure_temp::SecureClipboardRoot>>,
)
where
    F: FnOnce() -> Result<
        cm_platform::secure_temp::SecureClipboardRoot,
        cm_platform::secure_temp::SecureTempError,
    >,
{
    match bootstrap() {
        Ok(root) => {
            let root = Arc::new(root);
            (Some(Arc::clone(&root)), Some(root))
        }
        Err(error) => {
            tracing::warn!(reason = ?error, "clipboard file staging unavailable");
            (None, None)
        }
    }
}

/// Populate the in-memory database with demo groups, connections, credential
/// folders, and credentials so the UI panels show realistic content out of the
/// box (and so xvfb screenshots capture a populated tree).
///
/// Dev-only: only compiled in when the off-by-default `demo-seed` cargo
/// feature is enabled (see the module docs and the call site in
/// `build_config`). Never present in a shipped/release artifact.
#[cfg(feature = "demo-seed")]
fn seed_demo_data(
    repo: &dyn cm_core::ConnectionRepository,
) -> Result<(), Box<dyn std::error::Error>> {
    use cm_core::{
        Connection, ConnectionId, ConnectionKind, ConnectionSettings, Credential, CredentialFolder,
        CredentialFolderId, CredentialId, CredentialKind, Group, GroupId, LocalSettings,
        SshAuthMethod, SshSettings,
    };

    let now: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // ── Credential folders ─────────────────────────────────────────────────
    let folder_work = CredentialFolder {
        id: CredentialFolderId::UNSAVED,
        parent_id: None,
        name: "Work".to_owned(),
        sort: 0,
    };
    let work_folder_id = repo.upsert_credential_folder(&folder_work)?;

    // ── Credentials ────────────────────────────────────────────────────────
    // A shared SSH key used by the Lab group.
    let ops_key = Credential {
        id: CredentialId::UNSAVED,
        name: "ops-ssh-key".to_owned(),
        kind: CredentialKind::SshKey,
        folder_id: Some(work_folder_id),
        username: Some("ops".to_owned()),
    };
    let ops_key_id = repo.upsert_credential(&ops_key)?;

    // A password credential for prod access.
    let prod_pass = Credential {
        id: CredentialId::UNSAVED,
        name: "prod-password".to_owned(),
        kind: CredentialKind::Password,
        folder_id: Some(work_folder_id),
        username: Some("admin".to_owned()),
    };
    let _prod_pass_id = repo.upsert_credential(&prod_pass)?;

    // ── Connection groups ──────────────────────────────────────────────────
    // Root group "Lab" — inherits ops-ssh-key for all its connections.
    let lab = Group {
        id: GroupId::UNSAVED,
        parent_id: None,
        name: "Lab".to_owned(),
        sort: 0,
        default_credential: Some(ops_key_id),
    };
    let lab_id = repo.upsert_group(&lab)?;

    // Sub-group "Lab/Dev" — no default credential (inherits from Lab).
    let lab_dev = Group {
        id: GroupId::UNSAVED,
        parent_id: Some(lab_id),
        name: "Dev".to_owned(),
        sort: 0,
        default_credential: None,
    };
    let lab_dev_id = repo.upsert_group(&lab_dev)?;

    // Root group "Prod" — no default credential.
    let prod = Group {
        id: GroupId::UNSAVED,
        parent_id: None,
        name: "Prod".to_owned(),
        sort: 1,
        default_credential: None,
    };
    let prod_id = repo.upsert_group(&prod)?;

    // ── Connections ────────────────────────────────────────────────────────
    let ssh_settings = |host: &str, port: u16, username: &str| {
        ConnectionSettings::Ssh(SshSettings {
            host: host.to_owned(),
            port,
            username: username.to_owned(),
            auth_method: SshAuthMethod::Password,
        })
    };

    let web_dev = Connection::new(
        ConnectionId::UNSAVED,
        Some(lab_dev_id),
        "web-dev-01".to_owned(),
        ConnectionKind::Ssh,
        ssh_settings("10.0.1.11", 22, "ops"),
        None, // inherit from Lab group → ops-ssh-key
        0,
        now,
        now,
    )?;
    repo.upsert_connection(&web_dev)?;

    let db_dev = Connection::new(
        ConnectionId::UNSAVED,
        Some(lab_dev_id),
        "db-dev".to_owned(),
        ConnectionKind::Ssh,
        ssh_settings("10.0.1.22", 22, "admin"),
        None,
        1,
        now,
        now,
    )?;
    repo.upsert_connection(&db_dev)?;

    let web_prod = Connection::new(
        ConnectionId::UNSAVED,
        Some(prod_id),
        "web-prod-01".to_owned(),
        ConnectionKind::Ssh,
        ssh_settings("10.0.4.11", 22, "ops"),
        None,
        0,
        now,
        now,
    )?;
    repo.upsert_connection(&web_prod)?;

    // A local terminal in the Prod group.
    let local_term = Connection::new(
        ConnectionId::UNSAVED,
        Some(prod_id),
        "local-shell".to_owned(),
        ConnectionKind::LocalTerminal,
        ConnectionSettings::Local(LocalSettings::default()),
        None,
        1,
        now,
        now,
    )?;
    repo.upsert_connection(&local_term)?;

    Ok(())
}

/// Proves the `demo-seed` feature gating (see the `[features]` doc comment in
/// `Cargo.toml` and the call site in `build_config` above): a fresh, empty DB
/// must stay empty by default (and always in a release artifact), and must
/// only pick up the demo dataset when this crate is built with
/// `--features demo-seed`.
#[cfg(test)]
mod demo_seed_gating_tests {
    use super::*;

    struct FailingConfigStore;

    impl AppConfigStore for FailingConfigStore {
        fn get_value(&self, _key: &str) -> Result<Option<String>, AppConfigError> {
            Err(AppConfigError::Backend("read failed".to_owned()))
        }

        fn set_value(&self, _key: &str, _value: &str) -> Result<(), AppConfigError> {
            unreachable!("startup load never writes")
        }

        fn set_values(&self, _values: &[(&str, &str)]) -> Result<(), AppConfigError> {
            unreachable!("startup load never writes")
        }

        fn document_text(&self) -> Result<String, AppConfigError> {
            unreachable!("startup typed load queries values")
        }

        fn replace_document(&self, _document: &str) -> Result<(), AppConfigError> {
            unreachable!("startup load never writes")
        }
    }

    #[test]
    fn prepared_startup_path_creates_its_parent_without_changing_the_path() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("nested").join("config.conman");
        let resolved = prepare_app_config_path(path.clone()).expect("prepare explicit config path");
        assert_eq!(resolved, path);
        assert!(resolved.parent().expect("parent").is_dir());
    }

    #[test]
    fn gui_parser_preserves_both_startup_path_overrides() {
        let outcome = cm_cli::parse_gui_args([
            "--config",
            "alternate/config.conman",
            "--database",
            "alternate/conman.sqlite",
        ])
        .expect("valid GUI invocation");
        let cm_cli::GuiParseOutcome::Run(invocation) = outcome else {
            panic!("path overrides must launch the application");
        };
        assert_eq!(
            invocation.config_path,
            Some(std::path::PathBuf::from("alternate/config.conman"))
        );
        assert_eq!(
            invocation.database_path,
            Some(std::path::PathBuf::from("alternate/conman.sqlite"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn gui_parser_preserves_non_unicode_startup_paths() {
        use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

        let raw_path = b"alternate/config-\xff.conman".to_vec();
        let outcome = cm_cli::parse_gui_args([
            std::ffi::OsString::from("--config"),
            std::ffi::OsString::from_vec(raw_path.clone()),
        ])
        .expect("non-Unicode paths are valid GUI arguments");
        let cm_cli::GuiParseOutcome::Run(invocation) = outcome else {
            panic!("path override must launch the application");
        };
        assert_eq!(
            invocation
                .config_path
                .expect("config path")
                .as_os_str()
                .as_bytes(),
            raw_path
        );
    }

    #[test]
    fn matching_explicit_identity_activates_before_touching_its_path() {
        let directory = tempfile::tempdir().expect("tempdir");
        let alternate_path = directory
            .path()
            .join("must-remain-absent")
            .join("alternate.sqlite");
        let overrides = StartupPathOverrides::select(
            cm_cli::GuiInvocation {
                config_path: None,
                database_path: Some(alternate_path.clone()),
            },
            None,
            None,
        );
        let paths = overrides.resolve().expect("resolve candidates");
        let identity = InstanceIdentity::from_paths(&paths.config_path, &paths.database_path)
            .expect("derive identity");

        let result = preflight_single_instance(&identity, |_| AcquireOutcome::AlreadyRunning);

        assert!(matches!(result, Err(PreflightExit::ActivatedPrimary)));
        assert!(
            !alternate_path.exists() && !alternate_path.parent().expect("parent").exists(),
            "identity derivation and preflight must not touch the alternate path"
        );
    }

    #[test]
    fn environment_path_overrides_form_identity_before_either_path_is_touched() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config_path = directory.path().join("config-absent").join("config.conman");
        let database_path = directory
            .path()
            .join("database-absent")
            .join("conman.sqlite");
        let overrides = StartupPathOverrides::select(
            cm_cli::GuiInvocation::default(),
            Some(config_path.clone().into_os_string()),
            Some(database_path.clone().into_os_string()),
        );
        let paths = overrides.resolve().expect("resolve candidates");
        assert_eq!(paths.config_path, config_path);
        assert_eq!(paths.database_path, database_path);
        let _identity = InstanceIdentity::from_paths(&paths.config_path, &paths.database_path)
            .expect("derive identity");
        assert!(!config_path.parent().expect("config parent").exists());
        assert!(!database_path.parent().expect("database parent").exists());
    }

    #[test]
    fn cli_path_identity_wins_over_environment_identity() {
        let overrides = StartupPathOverrides::select(
            cm_cli::GuiInvocation {
                config_path: Some("cli.conman".into()),
                database_path: Some("cli.sqlite".into()),
            },
            Some(std::ffi::OsString::from("environment.conman")),
            Some(std::ffi::OsString::from("environment.sqlite")),
        );
        assert_eq!(
            overrides.config_path,
            Some(std::path::PathBuf::from("cli.conman"))
        );
        assert_eq!(
            overrides.database_path,
            Some(std::path::PathBuf::from("cli.sqlite"))
        );
    }

    #[test]
    fn ordinary_second_launch_requests_activation() {
        let identity = InstanceIdentity::from_paths(
            std::path::Path::new("config.conman"),
            std::path::Path::new("conman.sqlite"),
        )
        .expect("derive identity");

        let result = preflight_single_instance(&identity, |_| AcquireOutcome::AlreadyRunning);

        assert!(matches!(result, Err(PreflightExit::ActivatedPrimary)));
    }

    #[test]
    fn ordinary_launch_never_proceeds_without_verified_instance_lock() {
        let identity = InstanceIdentity::from_paths(
            std::path::Path::new("config.conman"),
            std::path::Path::new("conman.sqlite"),
        )
        .expect("derive identity");
        let result = preflight_single_instance(&identity, |_| {
            AcquireOutcome::Unavailable("handshake timed out".to_owned())
        });
        assert!(matches!(
            result,
            Err(PreflightExit::InstanceGuardUnavailable(reason))
                if reason == "handshake timed out"
        ));
    }

    #[test]
    fn startup_diagnostics_neutralize_controls_osc_and_bidi() {
        let hostile_path = "config\u{001b}]0;owned\u{0007}\u{0085}\u{202e}.conman";
        let safe = sanitized_startup_message(format_args!("fatal: could not open {hostile_path}"));
        assert!(!safe.chars().any(char::is_control));
        assert!(!safe.contains('\u{202e}'));
        assert!(safe.contains("fatal: could not open config�]0;owned���.conman"));
    }

    #[test]
    fn build_identity_contains_copyable_diagnostic_fields() {
        let identity = ui_build_identity(cm_build_info::BuildInfo {
            version: "0.1.0-dev.42+g0123456789",
            git_sha: Some("0123456789abcdef0123456789abcdef01234567"),
            revision_count: Some(42),
            dirty: true,
            target: "x86_64-unknown-linux-gnu",
            profile: "debug",
        });
        assert_eq!(identity.version, "0.1.0-dev.42+g0123456789");
        for expected in [
            "Version: 0.1.0-dev.42+g0123456789",
            "Git SHA: 0123456789abcdef0123456789abcdef01234567",
            "Revision: 42",
            "Target: x86_64-unknown-linux-gnu",
            "Profile: debug",
            "Dirty: true",
        ] {
            assert!(identity.details.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn startup_config_uses_defaults_for_syntax_errors() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("config.conman");
        std::fs::write(&path, "not an assignment").expect("write malformed config");
        let store = TextConfigStore::new(path);

        let loaded = load_startup_settings(&store).expect("syntax is recoverable");
        assert_eq!(loaded.settings, AppSettings::default());
        assert!(loaded.syntax_warning.is_some());
    }

    #[test]
    fn startup_config_keeps_per_key_value_warnings() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("config.conman");
        std::fs::write(&path, "font-size = enormous\nscrollback-limit = 42\n")
            .expect("write config");
        let store = TextConfigStore::new(path);

        let loaded = load_startup_settings(&store).expect("known invalid value is recoverable");
        assert_eq!(loaded.settings.font_size, AppSettings::default().font_size);
        assert_eq!(loaded.settings.scrollback_limit, 42);
        assert_eq!(loaded.warnings.len(), 1);
        assert!(loaded.syntax_warning.is_none());
    }

    #[test]
    fn startup_config_keeps_backend_failures_fatal() {
        assert!(matches!(
            load_startup_settings(&FailingConfigStore),
            Err(AppConfigError::Backend(_))
        ));
    }

    #[test]
    fn clipboard_composition_bootstraps_once_and_shares_one_root() {
        let calls = std::cell::Cell::new(0);
        let (ui, provider) = compose_clipboard_dependencies(|| {
            calls.set(calls.get() + 1);
            cm_platform::secure_temp::SecureClipboardRoot::bootstrap()
        });
        assert_eq!(calls.get(), 1);
        assert!(Arc::ptr_eq(
            ui.as_ref().expect("UI root"),
            provider.as_ref().expect("provider root")
        ));
    }

    #[test]
    fn clipboard_composition_failure_is_single_attempt_and_disables_files() {
        let calls = std::cell::Cell::new(0);
        let (ui, provider) = compose_clipboard_dependencies(|| {
            calls.set(calls.get() + 1);
            Err(cm_platform::secure_temp::SecureTempError::Unavailable)
        });
        assert_eq!(calls.get(), 1);
        assert!(ui.is_none());
        assert!(provider.is_none());
    }

    fn build_test_config(
        directory: &tempfile::TempDir,
    ) -> Result<AppConfig, Box<dyn std::error::Error>> {
        let db_path = directory.path().join("ds-test.sqlite");
        let config_path = directory.path().join("config.conman");
        let secrets: Arc<dyn cm_core::CredentialStore> = Arc::new(KeyringStore::new());
        let repo =
            Arc::new(SqliteRepository::open(&db_path)?.with_credential_store(Arc::clone(&secrets)));
        let connection_repo: Arc<dyn cm_core::ConnectionRepository> = repo.clone();
        let import_repo: Arc<dyn cm_storage::AtomicImportRepository> = repo.clone();
        let app_state: Arc<dyn AppStateRepository> = repo;
        let config_store: Arc<dyn AppConfigStore> = Arc::new(TextConfigStore::new(&config_path));
        build_config(
            AppServices {
                repo: connection_repo,
                import_repo,
                app_state,
                config_store,
                config_path,
                build_identity: ui_build_identity(cm_build_info::BuildInfo::current()),
                secrets,
            },
            None,
            None,
        )
    }

    /// Default build (feature OFF, the release posture): first launch on a
    /// brand-new DB must leave the groups list empty -- no demo seed -- while
    /// still reporting a genuine `first_launch` so the Launchpad/welcome flow
    /// still shows.
    #[cfg(not(feature = "demo-seed"))]
    #[test]
    fn first_launch_on_empty_db_stays_empty_without_demo_seed_feature() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = build_test_config(&dir).expect("build_config");

        assert!(
            config.first_launch,
            "a brand-new empty DB must still report a genuine first launch"
        );
        let groups = config.repo.list_groups().expect("list_groups");
        assert!(
            groups.is_empty(),
            "default (demo-seed OFF) build must not seed any demo groups, got {groups:?}"
        );
    }

    #[test]
    fn identity_fails_closed_when_exclusivity_cannot_be_verified() {
        let directory = tempfile::tempdir().expect("tempdir");
        let alternate_path = directory
            .path()
            .join("must-remain-absent")
            .join("config.conman");
        let identity = InstanceIdentity::from_paths(&alternate_path, &directory.path().join("db"))
            .expect("derive identity");
        let result = preflight_single_instance(&identity, |_| {
            AcquireOutcome::Unavailable("handshake timed out".to_owned())
        });

        assert!(matches!(
            result,
            Err(PreflightExit::InstanceGuardUnavailable(reason))
                if reason == "handshake timed out"
        ));
        assert!(!alternate_path.parent().expect("parent").exists());
    }

    /// `--features demo-seed` build (dev-only opt-in): first launch on a
    /// brand-new DB seeds the demo "Lab"/"Prod" groups.
    #[cfg(feature = "demo-seed")]
    #[test]
    fn first_launch_on_empty_db_seeds_demo_groups_with_demo_seed_feature() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = build_test_config(&dir).expect("build_config");

        assert!(config.first_launch, "brand-new DB must report first launch");
        let groups = config.repo.list_groups().expect("list_groups");
        assert!(
            !groups.is_empty(),
            "demo-seed feature must seed demo groups on first launch"
        );
        assert!(
            groups.iter().any(|g| g.name == "Lab"),
            "expected the seeded 'Lab' group, got {groups:?}"
        );
        assert!(
            groups.iter().any(|g| g.name == "Prod"),
            "expected the seeded 'Prod' group, got {groups:?}"
        );
    }
}

// B1: run as a Windows GUI app in release (no allocated console window).
// Debug keeps the console so the `tracing` stderr layer stays visible (see
// `logging.rs`); release logs to a rotating file instead.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! `conman` — the application binary and composition root.
//!
//! P1.5: opens a **file-backed** SQLite database whose path is resolved by
//! `cm-platform::app_db_path()`.  On the very first launch (empty DB) a small
//! demo dataset is seeded; subsequent launches open and migrate the existing
//! DB without touching the user's data.
//!
//! P6.16: before touching storage or the keyring, tries to become the single
//! primary instance (`cm_platform::single_instance`). A second launch that
//! finds a primary already running asks it to activate and exits immediately;
//! a squatted lock port degrades to a normal (unlocked) launch rather than
//! blocking startup.
//!
//! P6.3: installs the `tracing` subscriber before anything else runs (see
//! `logging.rs`) — console layer in debug, rotating file layer under
//! `cm_platform::app_log_dir()` in release (`windows_subsystem = "windows"`
//! swallows stderr there).
//!
//! P7.1: before any of the above, decides the Slint renderer
//! (`render_backend::resolve`) — honors an explicit user `SLINT_BACKEND`,
//! otherwise probes the accelerated (winit+femtovg) renderer in a disposable
//! child process and forces the software renderer if it doesn't come up
//! (e.g. no usable hardware OpenGL), so the app renders instead of crashing.
//! This must run **before** `logging::init()` (see `render_backend`'s module
//! docs) — the decision is logged afterward, once a subscriber exists.

mod logging;
mod render_backend;

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::Receiver;

use cm_core::ConnectionRepository as _;
use cm_core::SettingsService;
use cm_platform::app_db_path;
use cm_platform::single_instance::{self, AcquireOutcome};
use cm_secrets::KeyringStore;
use cm_session::SessionProviderImpl;
use cm_storage::SqliteRepository;
use cm_ui::AppConfig;

// Pull the backend/renderer features into the shared `slint` build.
use slint as _;

fn main() -> ExitCode {
    // P7.1: the disposable renderer-probe child takes this branch and exits
    // immediately — no logging subscriber, no single-instance guard, no
    // storage, no keyring. See the `render_backend` module docs.
    if std::env::var_os(render_backend::PROBE_ENV_VAR).is_some() {
        return render_backend::run_probe_child();
    }

    // P7.1 cont.: open storage *before* the renderer probe so the persisted
    // renderer-backend cache can be consulted. Both `app_db_path()` and
    // `SqliteRepository::open()` are thread-free (SQLite spawns no threads), so
    // this stays safely inside the single-threaded window that
    // `render_backend::resolve` (which may `std::env::set_var`) requires —
    // `logging::init()` below is still the first thing that can spawn a thread.
    let db_path = match app_db_path() {
        Ok(p) => p,
        Err(e) => {
            // No tracing subscriber yet; use stderr for this pre-logging fatal.
            eprintln!("fatal: could not resolve database path: {e}");
            return ExitCode::FAILURE;
        }
    };
    let repo_result = SqliteRepository::open(&db_path);
    let cached: Option<String> = repo_result.as_ref().ok().and_then(|r| {
        SettingsService::new(r)
            .load_renderer_backend()
            .ok()
            .flatten()
    });

    // P7.1: resolve (and, if needed, apply) the renderer choice *before*
    // installing the logging subscriber. `logging::init()` is the first
    // thing below that can spawn a thread (the release build's non-blocking
    // log-appender worker); forcing the software fallback needs
    // `std::env::set_var`, which is only sound while the process is still
    // single-threaded. See `render_backend::force_software_backend`'s doc
    // comment for the full invariant. Precedence: explicit `SLINT_BACKEND` env
    // > persisted cache > probe (P7.1 cont.).
    let renderer_decision = render_backend::resolve(cached.as_deref());

    // Install the tracing subscriber — everything below may log.
    let _logging_guard = logging::init();

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

    // P7.1 cont.: persist the renderer-backend cache when (and only when)
    // `render_backend::persist_decision` says to — the single source of truth
    // (unit-tested) for both safety invariants: a freshly-forced *software*
    // fallback is auto-persisted at most once (so the expensive probe runs at
    // most once on GPU-less machines, and the decision travels with a DB
    // copy), while a probe that comes up *accelerated* is never auto-persisted
    // as such — except to clear a stale "software" cache back to "auto" on an
    // explicit `CONMAN_RENDER_REPROBE` re-probe, so future launches probe
    // afresh rather than staying stuck in software.
    if let Some(new_value) = render_backend::persist_decision(&renderer_decision, cached.as_deref())
        && let Err(e) = SettingsService::new(&repo).save_renderer_backend(new_value)
    {
        tracing::warn!("could not persist renderer backend cache: {e}");
    }

    // ── Single-instance guard (P6.16) — first, before storage/keyring ──────
    let activation_rx: Option<Receiver<()>> = match single_instance::acquire() {
        AcquireOutcome::AlreadyRunning => {
            tracing::info!(
                "another instance is already running; it has been asked to come to the foreground."
            );
            return ExitCode::SUCCESS;
        }
        AcquireOutcome::Acquired(guard) => Some(guard.listen()),
        AcquireOutcome::Unavailable(reason) => {
            tracing::warn!("single-instance guard unavailable ({reason}); continuing without it.");
            None
        }
    };

    // Install the platform-native keyring backend before any KeyringStore is
    // constructed.  Falls back to the in-memory mock backend if the native
    // backend is unavailable (headless CI, missing daemon, etc.) so startup
    // never fails due to keychain issues.
    init_keyring();

    let config = match build_config(repo, activation_rx) {
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

/// Install the OS-native keyring credential builder (P5.4).
///
/// Uses kernel keyutils on Linux (no daemon required), macOS Keychain, and
/// Windows Credential Manager.  If the native builder is unavailable (e.g. no
/// display in headless CI, or a missing/broken daemon) we fall back to the
/// in-memory mock backend so the application still starts and credentials are
/// kept for the session duration.
fn init_keyring() {
    #[cfg(target_os = "linux")]
    {
        keyring::set_default_credential_builder(keyring::keyutils::default_credential_builder());
    }
    #[cfg(target_os = "macos")]
    {
        keyring::set_default_credential_builder(keyring::macos::default_credential_builder());
    }
    #[cfg(target_os = "windows")]
    {
        keyring::set_default_credential_builder(keyring::windows::default_credential_builder());
    }
}

/// Build the [`AppConfig`] that the UI controller receives.
///
/// Takes the already-open file-backed SQLite `repo` (opened in `main` before
/// the renderer probe so the persisted renderer-backend cache can be read —
/// P7.1 cont.). On an empty / brand-new DB a small demo dataset is seeded once;
/// existing DBs are used as-is (migrations already ran on open).
///
/// `activation_rx` (P6.16) is threaded straight through from the
/// single-instance guard acquired in `main` into the returned [`AppConfig`].
fn build_config(
    repo: SqliteRepository,
    activation_rx: Option<Receiver<()>>,
) -> Result<AppConfig, Box<dyn std::error::Error>> {
    // Seed demo data only on the very first launch, gated on a persisted flag.
    // Seed demo data only when the DB is genuinely empty (no flag AND no groups).
    // The double guard handles two distinct cases:
    //  - Brand-new DB: flag absent + no groups → seed + set flag.
    //  - Pre-existing populated DB migrated from an older build that never set the
    //    flag: flag absent + groups present → set flag without seeding (backfill).
    // This ensures we never duplicate data on an already-populated DB (fix k).
    // P6.14: `first_launch` is `true` only in the genuine brand-new-DB case
    // (flag absent AND no groups) -- distinct from the "backfill" case (flag
    // absent but groups already present, e.g. a DB migrated from an older
    // build that never set the flag), which is not a first launch and must
    // not force a plain local-shell tab / skip the Launchpad-empty fallback.
    let first_launch = {
        let svc = SettingsService::new(&repo);
        let already_seeded = svc.load_first_run_seeded()?;
        let mut first_launch = false;
        if !already_seeded {
            if repo.list_groups()?.is_empty() {
                seed_demo_data(&repo)?;
                first_launch = true;
            }
            svc.save_first_run_seeded()?;
        }
        first_launch
    };

    let repo: Arc<dyn cm_core::ConnectionRepository> = Arc::new(repo);

    // ── Credential store (OS keychain) ─────────────────────────────────────
    let secrets: Arc<dyn cm_core::CredentialStore> = Arc::new(KeyringStore::new());

    // ── Session provider (P6.15, gap 27) ────────────────────────────────────
    let session_provider: Arc<dyn cm_core::SessionProvider> = Arc::new(SessionProviderImpl::new());

    Ok(AppConfig {
        repo,
        secrets,
        session_provider,
        activation_rx,
        first_launch,
    })
}

/// Populate the in-memory database with demo groups, connections, credential
/// folders, and credentials so the UI panels show realistic content out of the
/// box (and so xvfb screenshots capture a populated tree).
fn seed_demo_data(repo: &SqliteRepository) -> Result<(), Box<dyn std::error::Error>> {
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

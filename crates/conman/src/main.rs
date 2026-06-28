// B1: run as a Windows GUI app in release (no allocated console window).
// Debug keeps the console so `eprintln!` diagnostics remain visible.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! `conman` — the application binary and composition root.
//!
//! P1.5: opens a **file-backed** SQLite database whose path is resolved by
//! `cm-platform::app_db_path()`.  On the very first launch (empty DB) a small
//! demo dataset is seeded; subsequent launches open and migrate the existing
//! DB without touching the user's data.

use std::process::ExitCode;
use std::sync::Arc;

use cm_core::ConnectionRepository as _;
use cm_platform::app_db_path;
use cm_secrets::KeyringStore;
use cm_storage::{SettingsService, SqliteRepository};
use cm_ui::AppConfig;

// Pull the backend/renderer features into the shared `slint` build.
use slint as _;

fn main() -> ExitCode {
    // Install the platform-native keyring backend before any KeyringStore is
    // constructed.  Falls back to the in-memory mock backend if the native
    // backend is unavailable (headless CI, missing daemon, etc.) so startup
    // never fails due to keychain issues.
    init_keyring();

    let config = match build_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("conman: fatal: failed to initialise storage: {e}");
            return ExitCode::FAILURE;
        }
    };
    match cm_ui::run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("conman: fatal: {e}");
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
/// Opens (or creates) the file-backed SQLite DB at the OS data-dir path
/// returned by `cm-platform`.  On an empty / brand-new DB a small demo
/// dataset is seeded once; existing DBs are opened as-is (migrations run
/// automatically on open).
fn build_config() -> Result<AppConfig, Box<dyn std::error::Error>> {
    // ── Resolve DB path ────────────────────────────────────────────────────
    let db_path = app_db_path()?;

    // ── Repository (SQLite) ────────────────────────────────────────────────
    let repo = SqliteRepository::open(&db_path)?;

    // Seed demo data only on the very first launch, gated on a persisted flag.
    // Seed demo data only when the DB is genuinely empty (no flag AND no groups).
    // The double guard handles two distinct cases:
    //  - Brand-new DB: flag absent + no groups → seed + set flag.
    //  - Pre-existing populated DB migrated from an older build that never set the
    //    flag: flag absent + groups present → set flag without seeding (backfill).
    // This ensures we never duplicate data on an already-populated DB (fix k).
    {
        let svc = SettingsService::new(&repo);
        let already_seeded = svc.load_first_run_seeded()?;
        if !already_seeded {
            if repo.list_groups()?.is_empty() {
                seed_demo_data(&repo)?;
            }
            svc.save_first_run_seeded()?;
        }
    }

    let repo: Arc<dyn cm_core::ConnectionRepository> = Arc::new(repo);

    // ── Credential store (OS keychain) ─────────────────────────────────────
    let secrets: Arc<dyn cm_core::CredentialStore> = Arc::new(KeyringStore::new());

    Ok(AppConfig { repo, secrets })
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

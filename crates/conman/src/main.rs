// B1: run as a Windows GUI app in release (no allocated console window).
// Debug keeps the console so `eprintln!` diagnostics remain visible.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! `conman` — the application binary and composition root.
//!
//! P1.4 upgrade: this binary now constructs the real SQLite repository
//! (`cm-storage`) and OS keychain store (`cm-secrets`), seeds demo data on a
//! fresh in-memory database, and injects everything via [`cm_ui::AppConfig`].

use std::process::ExitCode;
use std::sync::Arc;

use cm_core::ConnectionRepository as _;
use cm_secrets::KeyringStore;
use cm_storage::SqliteRepository;
use cm_ui::AppConfig;

// Pull the backend/renderer features into the shared `slint` build.
use slint as _;

fn main() -> ExitCode {
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

/// Build the [`AppConfig`] that the UI controller receives.
///
/// Uses an in-memory SQLite database and seeds representative demo data so the
/// Connections + Keys panels show a populated tree immediately. A future task
/// (P1.5) will persist to the user's application-data directory.
fn build_config() -> Result<AppConfig, Box<dyn std::error::Error>> {
    // ── Repository (SQLite) ────────────────────────────────────────────────
    let repo = SqliteRepository::open_in_memory()?;
    seed_demo_data(&repo)?;
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

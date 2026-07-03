//! Import/export palette actions (P6.6): native file dialogs (`rfd`) wired to
//! the frozen `cm_storage::json_io` envelope. Secrets are excluded by default
//! on export (ARCHITECTURE §6) — this module never sets
//! `ExportOptions::include_secrets`, and no "include secrets" UI is exposed
//! (see the task spec's "Scope" note and `docs/devel/memos/P6.6-rfd-dep.md`).
//!
//! Split in two layers on purpose:
//! - **Dialog-showing entry points** (`export_via_dialog` / `import_via_dialog`)
//!   are the only functions that touch `rfd`; they are wired from the palette
//!   dispatch in `palette.rs` and are never called by a test (a native picker
//!   would block forever under `xvfb`/CI — see the memo).
//! - **Dialog-free functions** (`export_to_path` / `import_from_path`) take a
//!   `Path` directly. This is the headless seam the task spec asks for: tests
//!   drive these to assert the produced JSON excludes secrets and that import
//!   round-trips through a fresh repo.

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

use cm_core::{ConnectionRepository, CredentialStore};
use cm_storage::{ExportEnvelope, ExportOptions, ImportStats};
use slint::{SharedString, VecModel};

use crate::{AppWindow, ConnRow, CredRow, ToastEntry};

use super::{State, keys_ctl, tree_ctl};

/// Toast `kind` values — see `ToastEntry`'s doc comment in `ui/app.slint`:
/// 0=info · 1=success · 2=warning · 3=error.
const TOAST_SUCCESS: i32 = 1;
const TOAST_ERROR: i32 = 3;

/// Handles the Import/Export actions need beyond `state`/`ui`: the repo/secrets
/// adapters already injected into `Ctx`, and the Slint list models to refresh
/// after a successful import.
///
/// Cloned onto `State` (see `mod.rs`) rather than widening
/// `dispatch_palette_action`'s / `handle_palette_key`'s signatures: those
/// functions are also called from the QA harness's narrower handle set
/// (`qa_harness.rs`) and from the keyboard-dispatch path in `sessions.rs`
/// (both outside Lane D this wave) — this way neither call site changes.
#[derive(Clone)]
pub(super) struct ImportExportHandles {
    pub(super) repo: Arc<dyn ConnectionRepository>,
    pub(super) secrets: Arc<dyn CredentialStore>,
    pub(super) conn_model: Rc<VecModel<ConnRow>>,
    pub(super) cred_model: Rc<VecModel<CredRow>>,
    pub(super) toast_model: Rc<VecModel<ToastEntry>>,
    pub(super) toast_next_id: Rc<RefCell<i32>>,
}

impl ImportExportHandles {
    fn push_toast(&self, message: String, kind: i32) {
        let id = {
            let mut n = self.toast_next_id.borrow_mut();
            let id = *n;
            *n += 1;
            id
        };
        self.toast_model.push(ToastEntry {
            id,
            message: SharedString::from(message),
            kind,
        });
    }
}

// ---------------------------------------------------------------------------
// Dialog-free seam (headlessly testable)
// ---------------------------------------------------------------------------

/// Export the current tree to `path` as pretty JSON. Secrets are always
/// excluded — default [`ExportOptions`] (ARCHITECTURE §6); see the module doc.
pub(super) fn export_to_path(repo: &dyn ConnectionRepository, path: &Path) -> Result<(), String> {
    let json = cm_storage::export_to_json(repo, &ExportOptions::default(), None)
        .map_err(|e| format!("export failed: {e}"))?;
    std::fs::write(path, json).map_err(|e| format!("failed to write {}: {e}", path.display()))
}

/// Import `path` into `repo` (additive; see `cm_storage::json_io`'s module
/// docs for full semantics — never changed here, consumed as-is).
///
/// Returns the import stats plus how many secrets embedded in the file (if
/// any) were *not* written to the keychain — the "any skipped" half of the
/// summary toast. `import()` itself treats per-secret failures as non-fatal
/// (malformed hex/purpose, or a keychain write error), so this is computed
/// by comparing the envelope's original secret count to
/// `ImportStats::secrets_imported`.
pub(super) fn import_from_path(
    path: &Path,
    repo: &dyn ConnectionRepository,
    secrets: &dyn CredentialStore,
) -> Result<(ImportStats, usize), String> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    if json.trim().is_empty() {
        return Err("empty import file".to_string());
    }
    let envelope: ExportEnvelope =
        serde_json::from_str(&json).map_err(|e| format!("malformed JSON: {e}"))?;
    let total_secrets = envelope.credential_secrets.len();
    let stats = cm_storage::import(&envelope, repo, Some(secrets))
        .map_err(|e| format!("import failed: {e}"))?;
    let skipped_secrets = total_secrets.saturating_sub(stats.secrets_imported);
    Ok((stats, skipped_secrets))
}

/// Build the post-import summary/conflict toast message: counts imported,
/// plus a note of any secrets present in the file that were skipped.
fn summary_message(stats: &ImportStats, skipped_secrets: usize) -> String {
    let mut msg = format!(
        "Imported {} group(s), {} connection(s), {} credential(s)",
        stats.groups_imported, stats.connections_imported, stats.credentials_imported
    );
    if skipped_secrets > 0 {
        msg.push_str(&format!(" — {skipped_secrets} secret(s) skipped"));
    }
    msg
}

/// Reload the in-memory tree + credential panel from `repo` and push the
/// refreshed data into the Slint list models (connections + Keys trees).
fn refresh_after_import(io: &ImportExportHandles, state: &Rc<RefCell<State>>, ui: &AppWindow) {
    {
        let mut st = state.borrow_mut();
        if let Err(e) = st.conn_tree.reload(io.repo.as_ref()) {
            tracing::warn!("conn tree reload after import failed: {e}");
        }
        if let Err(e) = st.keys_panel.reload(io.repo.as_ref()) {
            tracing::warn!("keys panel reload after import failed: {e}");
        }
    }
    let st = state.borrow();
    tree_ctl::refresh_conn_model(&st, &io.conn_model);
    tree_ctl::refresh_group_name_list(&st, ui);
    keys_ctl::refresh_cred_model(&st, &io.cred_model);
    keys_ctl::refresh_cred_name_list(&st, ui);
}

// ---------------------------------------------------------------------------
// Dialog-showing entry points (never called from a test — see the memo)
// ---------------------------------------------------------------------------

/// Run the dialog-free exporter against `path` and toast the result. Shared
/// by [`export_via_dialog`] and the `CONMAN_AUTOEXPORT` headless test hook
/// (`util.rs`) — mirrors [`run_import`]'s split (P6.17 finding F3).
pub(super) fn run_export(io: &ImportExportHandles, path: &Path) {
    match export_to_path(io.repo.as_ref(), path) {
        Ok(()) => io.push_toast(format!("Exported to {}", path.display()), TOAST_SUCCESS),
        Err(e) => {
            tracing::warn!("export failed: {e}");
            io.push_toast(format!("Export failed: {e}"), TOAST_ERROR);
        }
    }
}

/// "Export connections…" palette action: prompt for a save path, then run
/// the dialog-free export.
pub(super) fn export_via_dialog(io: &ImportExportHandles) {
    let Some(path) = rfd::FileDialog::new()
        .set_title("Export connections")
        .set_file_name("conman-export.json")
        .add_filter("JSON", &["json"])
        .save_file()
    else {
        return; // user cancelled
    };
    run_export(io, &path);
}

/// "Import connections…" palette action: prompt for a file, then run the
/// dialog-free import.
pub(super) fn import_via_dialog(
    io: &ImportExportHandles,
    state: &Rc<RefCell<State>>,
    ui: &AppWindow,
) {
    let Some(path) = rfd::FileDialog::new()
        .set_title("Import connections")
        .add_filter("JSON", &["json"])
        .pick_file()
    else {
        return; // user cancelled
    };
    run_import(io, state, ui, &path);
}

/// Run the defensive importer against `path`, refresh the connection + Keys
/// trees, and toast a summary/conflict report. Shared by
/// [`import_via_dialog`] and the `CONMAN_AUTOIMPORT` headless test hook
/// (`util.rs`) that drives this same path — minus the native dialog — for
/// the xvfb screenshot gate on the post-import summary toast.
pub(super) fn run_import(
    io: &ImportExportHandles,
    state: &Rc<RefCell<State>>,
    ui: &AppWindow,
    path: &Path,
) {
    match import_from_path(path, io.repo.as_ref(), io.secrets.as_ref()) {
        Ok((stats, skipped_secrets)) => {
            refresh_after_import(io, state, ui);
            io.push_toast(summary_message(&stats, skipped_secrets), TOAST_SUCCESS);
        }
        Err(e) => {
            tracing::warn!("import failed: {e}");
            io.push_toast(format!("Import failed: {e}"), TOAST_ERROR);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use cm_core::{
        Connection, ConnectionId, ConnectionKind, ConnectionSettings, Credential, CredentialError,
        CredentialId, CredentialKind, CredentialRef, Group, GroupId, LocalSettings, Secret,
    };
    use cm_storage::SqliteRepository;
    use slint::Model;

    use super::*;

    fn repo_with_one_group_one_conn_one_cred() -> SqliteRepository {
        let repo = SqliteRepository::open_in_memory().expect("open in-memory db");
        let group_id = repo
            .upsert_group(&Group {
                id: GroupId::UNSAVED,
                parent_id: None,
                name: "prod".to_string(),
                sort: 0,
                default_credential: None,
            })
            .expect("upsert group");
        let cred_id = repo
            .upsert_credential(&Credential {
                id: CredentialId::UNSAVED,
                folder_id: None,
                name: "prod-password".to_string(),
                kind: CredentialKind::Password,
                username: Some("root".to_string()),
            })
            .expect("upsert credential");
        let conn = Connection::new(
            ConnectionId::UNSAVED,
            Some(group_id),
            "web-01".to_string(),
            ConnectionKind::LocalTerminal,
            ConnectionSettings::Local(LocalSettings::default()),
            Some(cred_id),
            0,
            0,
            0,
        )
        .expect("build connection");
        repo.upsert_connection(&conn).expect("upsert connection");
        repo
    }

    #[test]
    fn export_to_path_writes_a_file_excluding_secrets() {
        let repo = repo_with_one_group_one_conn_one_cred();
        let dir = tempfile::tempdir().expect("tmp dir");
        let path = dir.path().join("export.json");

        export_to_path(&repo, &path).expect("export should succeed");

        let json = std::fs::read_to_string(&path).expect("export file should exist");
        assert!(json.contains("\"web-01\""));
        assert!(json.contains("\"prod\""));
        // Secret-hygiene grep-gate: even though this repo has a credential
        // *reference*, no secret material is ever fetched (default
        // `ExportOptions`, `store: None`) — and the `credential_secrets`
        // field itself is omitted entirely when empty.
        assert!(!json.contains("credential_secrets"));
        assert!(!json.contains("secret_hex"));
    }

    #[test]
    fn export_then_import_round_trips_into_a_fresh_repo_minus_secrets() {
        let src_repo = repo_with_one_group_one_conn_one_cred();
        let dir = tempfile::tempdir().expect("tmp dir");
        let path = dir.path().join("export.json");
        export_to_path(&src_repo, &path).expect("export should succeed");

        let dst_repo = SqliteRepository::open_in_memory().expect("open dest db");
        let mock_store = MockStore::default();
        let (stats, skipped_secrets) =
            import_from_path(&path, &dst_repo, &mock_store).expect("import should succeed");

        assert_eq!(stats.groups_imported, 1);
        assert_eq!(stats.connections_imported, 1);
        assert_eq!(stats.credentials_imported, 1);
        // The export carried no secrets (excluded by default), so nothing to
        // skip and nothing written to the keychain on import either.
        assert_eq!(stats.secrets_imported, 0);
        assert_eq!(skipped_secrets, 0);

        let groups = dst_repo.list_groups().expect("list groups");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "prod");
        let conns = dst_repo.list_connections().expect("list connections");
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].name, "web-01");
    }

    #[test]
    fn import_from_path_rejects_malformed_json_without_panicking() {
        let dir = tempfile::tempdir().expect("tmp dir");
        let path = dir.path().join("bad.json");
        std::fs::write(&path, b"not json").unwrap();
        let repo = SqliteRepository::open_in_memory().expect("open db");
        let mock_store = MockStore::default();
        let err = import_from_path(&path, &repo, &mock_store).unwrap_err();
        assert!(err.contains("malformed JSON"));
    }

    #[test]
    fn import_from_path_rejects_empty_file_without_panicking() {
        let dir = tempfile::tempdir().expect("tmp dir");
        let path = dir.path().join("empty.json");
        std::fs::write(&path, b"").unwrap();
        let repo = SqliteRepository::open_in_memory().expect("open db");
        let mock_store = MockStore::default();
        let err = import_from_path(&path, &repo, &mock_store).unwrap_err();
        assert!(err.contains("empty"));
    }

    /// Builds an [`ImportExportHandles`] over an in-memory repo/mock keychain
    /// for `run_export`/`run_import`-level tests (P6.17 F3 / `CONMAN_AUTOEXPORT`).
    fn handles_for(repo: Arc<dyn ConnectionRepository>) -> ImportExportHandles {
        ImportExportHandles {
            repo,
            secrets: Arc::new(MockStore::default()),
            conn_model: Rc::new(VecModel::default()),
            cred_model: Rc::new(VecModel::default()),
            toast_model: Rc::new(VecModel::default()),
            toast_next_id: Rc::new(RefCell::new(0)),
        }
    }

    #[test]
    fn run_export_writes_the_file_and_toasts_success() {
        let repo: Arc<dyn ConnectionRepository> = Arc::new(repo_with_one_group_one_conn_one_cred());
        let io = handles_for(repo);
        let dir = tempfile::tempdir().expect("tmp dir");
        let path = dir.path().join("export.json");

        run_export(&io, &path);

        assert!(path.exists(), "export file should be written");
        assert_eq!(io.toast_model.row_count(), 1);
        let toast = io.toast_model.row_data(0).expect("toast pushed");
        assert_eq!(toast.kind, TOAST_SUCCESS);
        assert!(toast.message.contains("Exported to"));
    }

    #[test]
    fn run_export_to_an_unwritable_path_toasts_an_error() {
        let repo: Arc<dyn ConnectionRepository> = Arc::new(repo_with_one_group_one_conn_one_cred());
        let io = handles_for(repo);
        // A directory that doesn't exist -- `std::fs::write` fails.
        let bad_path = std::path::Path::new("/nonexistent-dir-for-conman-test/export.json");

        run_export(&io, bad_path);

        assert_eq!(io.toast_model.row_count(), 1);
        let toast = io.toast_model.row_data(0).expect("toast pushed");
        assert_eq!(toast.kind, TOAST_ERROR);
        assert!(toast.message.contains("Export failed"));
    }

    #[test]
    fn summary_message_reports_counts_and_skipped_secrets() {
        let stats = ImportStats {
            credential_folders_imported: 0,
            credentials_imported: 2,
            groups_imported: 1,
            connections_imported: 3,
            secrets_imported: 1,
        };
        let msg = summary_message(&stats, 1);
        assert!(msg.contains("1 group(s)"));
        assert!(msg.contains("3 connection(s)"));
        assert!(msg.contains("2 credential(s)"));
        assert!(msg.contains("1 secret(s) skipped"));

        let clean = summary_message(&stats, 0);
        assert!(!clean.contains("skipped"));
    }

    // ---- tiny test helper ---------------------------------------------------

    /// A minimal in-memory [`CredentialStore`] for tests that don't exercise
    /// the OS keychain, keyed the same way the real adapter is (by the
    /// opaque `CredentialRef` service/account pair — mirrors the equivalent
    /// helper in `cm-storage/tests/json_io.rs`).
    #[derive(Default)]
    struct MockStore {
        inner: Mutex<HashMap<(String, String), Vec<u8>>>,
    }

    impl CredentialStore for MockStore {
        fn store(&self, key: &CredentialRef, secret: &Secret) -> Result<(), CredentialError> {
            self.inner.lock().unwrap().insert(
                (key.service().to_string(), key.account().to_string()),
                secret.expose().to_vec(),
            );
            Ok(())
        }

        fn get(&self, key: &CredentialRef) -> Result<Option<Secret>, CredentialError> {
            Ok(self
                .inner
                .lock()
                .unwrap()
                .get(&(key.service().to_string(), key.account().to_string()))
                .cloned()
                .map(Secret::new))
        }

        fn delete(&self, key: &CredentialRef) -> Result<(), CredentialError> {
            self.inner
                .lock()
                .unwrap()
                .remove(&(key.service().to_string(), key.account().to_string()));
            Ok(())
        }
    }
}

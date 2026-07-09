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
//!
//! **P9.2:** `import_from_path` now dispatches on extension: `.rjson`
//! (RoyalTS) routes through the new `cm_storage::import` foreign-format
//! framework; `.json` keeps calling `json_io::import_from_json` directly,
//! byte-for-byte as before this task — see [`ImportOutcome`] for the shared
//! result shape (adds a warning count alongside the pre-existing stats /
//! skipped-secrets pair).
//!
//! **P9.3 (import-dispatch handoff):** `.csv` (ConMan's own CSV interchange
//! format) joins `.rjson` on the same `cm_storage::import` foreign-format
//! route -- mirrors that wiring exactly, just another extension in the
//! match.

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

/// Shared result shape for [`import_from_path`], covering both the native
/// `.json` path and any `cm_storage::import` foreign-format path (`.rjson`
/// today). `warnings` is `0` for the native path (it never produces any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImportOutcome {
    pub(super) stats: ImportStats,
    /// Secrets present in the file that were *not* written to the keychain
    /// — see the doc comment below for how this is computed.
    pub(super) skipped_secrets: usize,
    /// Counted foreign-format warnings (skipped node kinds, etc — P9.2).
    /// Always `0` for the native `.json` path.
    pub(super) warnings: usize,
}

/// Import `path` into `repo`, dispatching by extension:
///
/// - `.rjson` (RoyalTS, P9.2) and `.csv` (ConMan's own CSV interchange
///   format, P9.3) route through `cm_storage::import`'s foreign-format
///   framework (parses to an `ExportEnvelope`, then the same
///   `cm_storage::import()` seam as the native path).
/// - anything else falls through to the native `.json` envelope path
///   (additive; see `cm_storage::json_io`'s module docs for full semantics
///   — **never changed here**, consumed as-is), exactly as before this task.
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
) -> Result<ImportOutcome, String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if matches!(ext.as_str(), "rjson" | "csv") {
        let outcome = cm_storage::import::import_from_path(path, repo, Some(secrets))
            .map_err(|e| format!("import failed: {e}"))?;
        let skipped_secrets = outcome
            .secrets_attempted
            .saturating_sub(outcome.stats.secrets_imported);
        return Ok(ImportOutcome {
            stats: outcome.stats,
            skipped_secrets,
            warnings: outcome.warnings.len(),
        });
    }

    // ---- native `.json` path: byte-for-byte as before this task ----------
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
    Ok(ImportOutcome {
        stats,
        skipped_secrets,
        warnings: 0,
    })
}

/// Build the post-import summary/conflict toast message: counts imported,
/// plus a note of any secrets present in the file that were skipped, plus
/// (P9.2) a note of any foreign-format warnings (e.g. RoyalTS nodes skipped
/// as unsupported).
fn summary_message(outcome: &ImportOutcome) -> String {
    let mut msg = format!(
        "Imported {} group(s), {} connection(s), {} credential(s)",
        outcome.stats.groups_imported,
        outcome.stats.connections_imported,
        outcome.stats.credentials_imported
    );
    if outcome.skipped_secrets > 0 {
        msg.push_str(&format!(" — {} secret(s) skipped", outcome.skipped_secrets));
    }
    if outcome.warnings > 0 {
        msg.push_str(&format!(" — {} warning(s)", outcome.warnings));
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
        // P9.2: RoyalTS plaintext export format, routed through
        // `cm_storage::import::royalts` in `import_from_path` above.
        .add_filter("RoyalTS", &["rjson"])
        // P9.3: ConMan's own CSV interchange format.
        .add_filter("CSV", &["csv"])
        .add_filter("All supported", &["json", "rjson", "csv"])
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
        Ok(outcome) => {
            refresh_after_import(io, state, ui);
            io.push_toast(summary_message(&outcome), TOAST_SUCCESS);
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
        let outcome =
            import_from_path(&path, &dst_repo, &mock_store).expect("import should succeed");

        assert_eq!(outcome.stats.groups_imported, 1);
        assert_eq!(outcome.stats.connections_imported, 1);
        assert_eq!(outcome.stats.credentials_imported, 1);
        // The export carried no secrets (excluded by default), so nothing to
        // skip and nothing written to the keychain on import either.
        assert_eq!(outcome.stats.secrets_imported, 0);
        assert_eq!(outcome.skipped_secrets, 0);
        // The native `.json` path never produces foreign-format warnings.
        assert_eq!(outcome.warnings, 0);

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

    /// P9.2: `.rjson` (RoyalTS) dispatch — `import_from_path` routes to
    /// `cm_storage::import` instead of the native JSON path, and the
    /// warning count (the Web/VNC node skipped by the shared fixture) flows
    /// through to the returned [`ImportOutcome`].
    #[test]
    fn import_from_path_dispatches_rjson_extension_to_the_royalts_importer() {
        // Shared with `cm-storage`'s own fixture-driven parser tests — a
        // sanitized, hand-authored sample with no real hosts/secrets.
        let fixture_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../cm-storage/tests/fixtures/royalts_sample.rjson"
        );
        let repo = SqliteRepository::open_in_memory().expect("open db");
        let mock_store = MockStore::default();

        let outcome = import_from_path(fixture_path.as_ref(), &repo, &mock_store)
            .expect("royalts import should succeed");

        // Folders -> groups, RDP + SSH connections, the deduped credential
        // and its plaintext secret, and the skipped VNC node all resolved
        // via the shared cm-storage seam — see that crate's tests for the
        // detailed field-level assertions; here we only need to confirm the
        // *dispatch* wired the counts through to the UI-facing outcome.
        assert_eq!(outcome.stats.groups_imported, 3); // Production, Web Tier, Legacy Family Folder
        assert_eq!(outcome.stats.credentials_imported, 1); // deduped
        assert_eq!(outcome.stats.secrets_imported, 1);
        assert_eq!(outcome.skipped_secrets, 0);
        assert_eq!(outcome.warnings, 1); // the skipped VNC node

        let msg = summary_message(&outcome);
        assert!(msg.contains("1 warning(s)"));
    }

    /// P9.3: `.csv` (ConMan's own CSV interchange format) dispatch — mirrors
    /// the `.rjson` test above exactly, just the next extension in the same
    /// match. 7 data rows in the shared fixture, 1 (`no-host-ssh`, blank
    /// host) skipped with a counted warning.
    #[test]
    fn import_from_path_dispatches_csv_extension_to_the_csv_importer() {
        let fixture_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../cm-storage/tests/fixtures/csv_sample.csv"
        );
        let repo = SqliteRepository::open_in_memory().expect("open db");
        let mock_store = MockStore::default();

        let outcome = import_from_path(fixture_path.as_ref(), &repo, &mock_store)
            .expect("csv import should succeed");

        assert_eq!(outcome.stats.connections_imported, 6);
        assert_eq!(outcome.warnings, 1);
        assert!(outcome.stats.secrets_imported >= 3, "{:?}", outcome.stats);

        let conns = repo.list_connections().expect("list connections");
        assert!(conns.iter().any(|c| c.name == "web-01-ssh"));
        assert!(
            !conns.iter().any(|c| c.name == "no-host-ssh"),
            "the blank-host row must be skipped, not imported"
        );
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
            settings_imported: 0,
        };
        let msg = summary_message(&ImportOutcome {
            stats: stats.clone(),
            skipped_secrets: 1,
            warnings: 0,
        });
        assert!(msg.contains("1 group(s)"));
        assert!(msg.contains("3 connection(s)"));
        assert!(msg.contains("2 credential(s)"));
        assert!(msg.contains("1 secret(s) skipped"));
        assert!(!msg.contains("warning"));

        let clean = summary_message(&ImportOutcome {
            stats: stats.clone(),
            skipped_secrets: 0,
            warnings: 0,
        });
        assert!(!clean.contains("skipped"));
    }

    #[test]
    fn summary_message_reports_foreign_import_warnings() {
        let stats = ImportStats {
            credential_folders_imported: 0,
            credentials_imported: 1,
            groups_imported: 1,
            connections_imported: 2,
            secrets_imported: 1,
            settings_imported: 0,
        };
        let msg = summary_message(&ImportOutcome {
            stats,
            skipped_secrets: 0,
            warnings: 2,
        });
        assert!(msg.contains("2 warning(s)"));
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

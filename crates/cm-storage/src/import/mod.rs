//! Foreign-format connection import framework (P9.2).
//!
//! Every foreign importer follows the same shape: **parse** a third-party
//! file into an in-memory, v1-shaped [`ExportEnvelope`], then hand it to the
//! existing, unmodified [`crate::json_io::import`] seam. That reuses ID
//! remap, topo-sorted parent insertion, [`cm_core::Connection::new`]
//! domain validation, and the plaintext-secret → OS-keychain path — no new
//! import engine, no envelope schema change. Foreign importers are just
//! alternate front-ends producing the same envelope shape `cm_storage`'s
//! native JSON export already produces.
//!
//! ## How the next importer slots in
//! 1. Add `<format>.rs` with a `pub fn parse(contents: &str) -> Result<(ExportEnvelope,
//!    Vec<ImportWarning>), ImportExportError>` — mint synthetic, file-scoped
//!    IDs via `GroupId::new`/`CredentialId::new`/`ConnectionId::new` (they're
//!    only ever used as intra-envelope link keys; [`crate::json_io::import`]
//!    remaps every record to a fresh database ID regardless), push
//!    [`ImportWarning`]s for anything skipped or defaulted, and never touch a
//!    repository or keychain directly.
//! 2. Add a match arm to [`import_from_path`] for the new extension.
//! 3. That's it — [`ForeignImportOutcome`], the warning surfacing, and the
//!    `.json` native passthrough are all shared.
//!
//! `.rjson` (RoyalTS), `.csv` (ConMan's own CSV interchange format, P9.3),
//! and `.xml` (mRemoteNG, P9.4) are all implemented. `.xml` is the one
//! importer whose secrets are encrypted — [`import_from_path`] tries
//! mRemoteNG's built-in default password; a custom-password file surfaces
//! [`ImportExportError::PasswordRequired`], which the caller resolves by
//! re-invoking [`import_from_path_with_password`] with the user-supplied
//! password. Everything else (`.rtsz`, RoyalTS's encrypted vault format,
//! etc.) routes here to [`ImportExportError::Malformed`] ("no importer
//! registered"), not a panic.

pub mod csv;
pub mod mremoteng;
mod mremoteng_crypto;
pub mod royalts;

use std::path::Path;

use cm_core::{ConnectionRepository, CredentialStore};

use crate::json_io::{self, ExportEnvelope, ImportExportError, ImportStats};

/// A single non-fatal issue surfaced while translating a foreign file into an
/// [`ExportEnvelope`]: a skipped/unsupported node kind, a defaulted field,
/// anything the operator should see counted in the post-import summary but
/// that must never abort the import. Never silent — every occurrence pushes
/// one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportWarning {
    pub message: String,
}

impl ImportWarning {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Outcome of a foreign-format import: the [`ImportStats`] from the
/// underlying [`crate::json_io::import`] call, how many secrets the parser
/// *attempted* to carry (so the caller can compute a "skipped" count the same
/// way the native `.json` path does), and the counted [`ImportWarning`]s.
#[derive(Debug, Clone, Default)]
pub struct ForeignImportOutcome {
    pub stats: ImportStats,
    pub secrets_attempted: usize,
    pub warnings: Vec<ImportWarning>,
}

/// Dialog-free, extension-dispatching import entry point — the headless seam
/// this framework and its tests drive (mirrors the existing native JSON
/// import seam, `cm_ui::controller::import_export::import_from_path`, so both
/// are testable without a file picker).
///
/// - `.rjson` → [`royalts::parse`].
/// - `.csv` → [`csv::parse`] (P9.3).
/// - `.xml` → [`mremoteng::parse`] (P9.4), tried with mRemoteNG's built-in
///   default password — a custom-password file returns
///   [`ImportExportError::PasswordRequired`]; re-invoke via
///   [`import_from_path_with_password`] once the caller has prompted for it.
/// - `.json` → the existing native envelope import
///   ([`crate::json_io::import_from_json`]), **unchanged** — wrapped in
///   [`ForeignImportOutcome`] with no warnings so callers have one return
///   shape.
/// - anything else (including RoyalTS's encrypted `.rtsz` vault format) →
///   [`ImportExportError::Malformed`].
pub fn import_from_path(
    path: &Path,
    repo: &dyn ConnectionRepository,
    store: Option<&dyn CredentialStore>,
) -> Result<ForeignImportOutcome, ImportExportError> {
    import_from_path_with_password(path, repo, store, mremoteng_crypto::DEFAULT_PASSWORD)
}

/// Password-aware variant of [`import_from_path`] — every extension other
/// than `.xml` behaves identically (`password` is simply unused for them);
/// `.xml` decrypts with `password` instead of the built-in default. Exists so
/// a caller that got [`ImportExportError::PasswordRequired`] back from
/// [`import_from_path`] can prompt the user and retry without re-dispatching
/// by hand.
pub fn import_from_path_with_password(
    path: &Path,
    repo: &dyn ConnectionRepository,
    store: Option<&dyn CredentialStore>,
    password: &str,
) -> Result<ForeignImportOutcome, ImportExportError> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    let contents = std::fs::read_to_string(path).map_err(|e| {
        tracing::error!(path = %path.display(), error = %e, "failed to read import file");
        ImportExportError::Malformed(format!("failed to read {}: {e}", path.display()))
    })?;

    tracing::info!(
        path = %path.display(),
        ext = %ext,
        bytes = contents.len(),
        "importing connections file"
    );

    let (envelope, warnings): (ExportEnvelope, Vec<ImportWarning>) = match ext.as_str() {
        "rjson" => royalts::parse(&contents)?,
        "csv" => csv::parse(&contents)?,
        "xml" => mremoteng::parse(&contents, password)?,
        "json" => {
            if contents.trim().is_empty() {
                return Err(ImportExportError::Malformed("empty input".into()));
            }
            let envelope: ExportEnvelope = serde_json::from_str(&contents)?;
            (envelope, Vec::new())
        }
        other => {
            return Err(ImportExportError::Malformed(format!(
                "no importer registered for extension '.{other}'"
            )));
        }
    };

    let secrets_attempted = envelope.credential_secrets.len();
    let stats = json_io::import(&envelope, repo, store)?;
    tracing::info!(
        groups = stats.groups_imported,
        connections = stats.connections_imported,
        credentials = stats.credentials_imported,
        secrets = stats.secrets_imported,
        secrets_attempted,
        warnings = warnings.len(),
        "foreign import complete"
    );
    Ok(ForeignImportOutcome {
        stats,
        secrets_attempted,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use cm_core::{
        Connection, ConnectionId, ConnectionKind, ConnectionSettings, Credential, CredentialId,
        CredentialKind, CredentialSource, Group, GroupId, LocalSettings,
    };

    use super::*;
    use crate::SqliteRepository;

    #[test]
    fn json_extension_still_routes_through_the_unmodified_native_import() {
        // Regression: the native `.json` envelope path is untouched by this
        // framework — same behavior via `import_from_path` as calling
        // `json_io::import_from_json` directly.
        let src_repo = SqliteRepository::open_in_memory().expect("open src db");
        let group_id = src_repo
            .upsert_group(&Group {
                id: GroupId::UNSAVED,
                parent_id: None,
                name: "prod".to_string(),
                sort: 0,
                default_credential: None,
            })
            .expect("upsert group");
        let cred_id = src_repo
            .upsert_credential(&Credential {
                id: CredentialId::UNSAVED,
                folder_id: None,
                name: "prod-cred".to_string(),
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
            Some(CredentialSource::Object(cred_id)),
            0,
            0,
            0,
        )
        .expect("build connection");
        src_repo
            .upsert_connection(&conn)
            .expect("upsert connection");

        let json = crate::export_to_json(&src_repo, &crate::ExportOptions::default(), None)
            .expect("export");
        let dir = tempfile::tempdir().expect("tmp dir");
        let path = dir.path().join("export.json");
        std::fs::write(&path, json).expect("write export");

        let dst_repo = SqliteRepository::open_in_memory().expect("open dst db");
        let outcome = import_from_path(&path, &dst_repo, None).expect("json import should succeed");

        assert_eq!(outcome.stats.groups_imported, 1);
        assert_eq!(outcome.stats.connections_imported, 1);
        assert_eq!(outcome.stats.credentials_imported, 1);
        assert!(outcome.warnings.is_empty());
        assert_eq!(outcome.secrets_attempted, 0);
    }

    #[test]
    fn unregistered_extension_is_a_malformed_error_not_a_panic() {
        // `.xml` (mRemoteNG, P9.4) is now registered too (like `.csv` before
        // it) — use `.rtsz`, RoyalTS's encrypted-vault format, which the
        // P9.2 spec explicitly leaves out of scope, as a still-genuinely-
        // unregistered extension.
        let dir = tempfile::tempdir().expect("tmp dir");
        let path = dir.path().join("export.rtsz");
        std::fs::write(&path, b"not a real vault\n").unwrap();
        let repo = SqliteRepository::open_in_memory().expect("open db");
        let err = import_from_path(&path, &repo, None).unwrap_err();
        assert!(matches!(err, ImportExportError::Malformed(_)));
    }
}

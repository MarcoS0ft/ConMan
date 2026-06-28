/// Errors that can occur while opening or migrating the storage database.
///
/// These are surfaced via [`SqliteRepository::open`] / [`SqliteRepository::open_in_memory`].
/// Once the repository is open, all subsequent errors are reported as
/// [`cm_core::RepositoryError`].
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("cannot open database: {0}")]
    Open(String),
    #[error("schema migration failed: {0}")]
    Migration(String),
}

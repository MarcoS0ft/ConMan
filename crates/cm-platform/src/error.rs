use std::path::PathBuf;

/// Errors produced by `cm-platform`.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// The OS could not provide a user data directory (e.g., no home directory
    /// set).
    #[error("cannot determine the OS user data directory")]
    NoDataDir,

    /// Creating the application data directory failed.
    #[error("failed to create data directory {0}: {1}")]
    DataDirCreate(PathBuf, String),
}

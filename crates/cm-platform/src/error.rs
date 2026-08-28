use std::path::PathBuf;

/// Errors produced by `cm-platform`.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// The OS could not provide a user data directory (e.g., no home directory
    /// set).
    #[error("cannot determine the OS user data directory")]
    NoDataDir,

    /// The OS could not provide a user configuration directory.
    #[error("cannot determine the OS user configuration directory")]
    NoConfigDir,

    /// Creating the application data directory failed.
    #[error("failed to create data directory {0}: {1}")]
    DataDirCreate(PathBuf, String),

    /// Creating the user configuration directory failed.
    #[error("failed to create configuration directory {0}: {1}")]
    ConfigDirCreate(PathBuf, String),

    /// Launching the OS file handler failed.
    #[error("failed to open {0}: {1}")]
    PathOpen(PathBuf, String),
}

use std::io;

/// Classified failures from command dispatch and rendering.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("invalid command input: {0}")]
    Usage(String),
    #[error("connection {0} was not found")]
    NotFound(i64),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("import/export error: {0}")]
    ImportExport(String),
    #[error("filesystem error: {0}")]
    Filesystem(String),
    #[error("input error: {0}")]
    Input(String),
    #[error("output error: {0}")]
    Output(String),
}

impl CliError {
    /// Stable process exit code for scripts.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => 2,
            Self::NotFound(_) => 3,
            Self::Config(_) => 4,
            Self::Storage(_) | Self::ImportExport(_) | Self::Filesystem(_) | Self::Input(_) => 1,
            Self::Output(_) => 74,
        }
    }
}

impl From<io::Error> for CliError {
    fn from(error: io::Error) -> Self {
        Self::Filesystem(error.to_string())
    }
}

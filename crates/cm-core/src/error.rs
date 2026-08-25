use crate::kind::ConnectionKind;

/// Errors from a [`crate::ConnectionRepository`].
///
/// `Backend` carries an adapter-specific message; adapters must ensure no
/// secrets ever reach it (CONVENTIONS §2, secrets hygiene).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RepositoryError {
    #[error("entity not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("storage backend error: {0}")]
    Backend(String),
}

/// Errors from a [`crate::CredentialStore`].
///
/// `Backend` carries an adapter-specific message; it must never contain the
/// secret material itself.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialError {
    #[error("credential not found")]
    NotFound,
    #[error("keychain backend error: {0}")]
    Backend(String),
}

/// Domain-validation errors for in-memory invariants.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DomainError {
    #[error("connection settings variant ({found:?}) does not match declared kind ({expected:?})")]
    SettingsKindMismatch {
        expected: ConnectionKind,
        found: ConnectionKind,
    },
    #[error("Telnet host must not be empty or whitespace")]
    TelnetHostEmpty,
    #[error("Telnet connections must use CredentialSource::Prompt")]
    TelnetCredentialSourceMustPrompt,
}

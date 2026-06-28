//! `cm-storage` — persistence adapters for ConMan.
//!
//! Implements the [`ConnectionRepository`] port over SQLite via
//! [`SqliteRepository`].  The schema is versioned (migrations run on open);
//! it stores metadata and credential references only — secrets never touch the
//! store.
//!
//! [`ConnectionRepository`]: cm_core::ConnectionRepository

mod error;
pub mod migrations;
pub mod repository;

pub use error::StorageError;
pub use repository::SqliteRepository;

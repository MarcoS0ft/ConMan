//! `cm-storage` — persistence adapters for ConMan.
//!
//! Implements the [`ConnectionRepository`] port over SQLite via
//! [`SqliteRepository`].  The schema is versioned (migrations run on open);
//! it stores metadata and credential references only — secrets never touch the
//! store.
//!
//! JSON import/export lives in [`json_io`]; it is interchange-only — the
//! backing store remains SQLite.
//!
//! [`ConnectionRepository`]: cm_core::ConnectionRepository

mod error;
pub mod json_io;
pub mod migrations;
pub mod repository;
pub mod settings;

pub use error::StorageError;
pub use json_io::{
    ENVELOPE_VERSION, ExportEnvelope, ExportOptions, ExportedSecret, ImportExportError,
    ImportStats, export, export_to_json, import, import_from_json,
};
pub use repository::SqliteRepository;
pub use settings::{AppSettings, SessionTabEntry, SessionTabSnapshot, SettingsService};

//! `cm-storage` — persistence adapters for ConMan.
//!
//! Implements the [`ConnectionRepository`] and [`AppStateRepository`] ports
//! over SQLite via [`SqliteRepository`]. The schema is versioned (migrations
//! run on open); it stores connection metadata, credential references, and
//! machine-local runtime state. Secrets never touch the store.
//!
//! JSON import/export lives in [`json_io`]; it is interchange-only — the
//! backing store remains SQLite. Foreign-format connection import
//! (RoyalTS `.rjson`, and CSV/mRemoteNG to come) lives in [`import`] — each
//! foreign parser produces the same [`json_io::ExportEnvelope`] shape and
//! hands it to the shared atomic [`json_io::import`] seam; see that module's
//! docs for how the next importer slots in.
//!
//! User-editable preferences live in the text-config adapter, not SQLite and
//! not the connection JSON envelope.
//!
//! [`AppStateRepository`]: cm_core::AppStateRepository
//! [`ConnectionRepository`]: cm_core::ConnectionRepository

mod error;
pub mod import;
pub mod json_io;
pub mod migrations;
pub mod repository;

pub use error::StorageError;
pub use json_io::{
    ENVELOPE_VERSION, ExportEnvelope, ExportJsonOutcome, ExportOptions, ExportOutcome,
    ExportedSecret, ImportExportError, ImportStats, SecretExportReport, export, export_to_json,
    import, import_from_json,
};
pub use repository::{AtomicImportRepository, ImportTransaction, SqliteRepository};

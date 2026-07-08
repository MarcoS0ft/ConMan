//! `cm-storage` — persistence adapters for ConMan.
//!
//! Implements the [`ConnectionRepository`] port over SQLite via
//! [`SqliteRepository`].  The schema is versioned (migrations run on open);
//! it stores metadata and credential references only — secrets never touch the
//! store.
//!
//! JSON import/export lives in [`json_io`]; it is interchange-only — the
//! backing store remains SQLite. **P9.2:** foreign-format connection import
//! (RoyalTS `.rjson`, and CSV/mRemoteNG to come) lives in [`import`] — each
//! foreign parser produces the same [`json_io::ExportEnvelope`] shape and
//! hands it to the unmodified [`json_io::import`] seam; see that module's
//! docs for how the next importer slots in.
//!
//! **P6.15:** `AppSettings`/`SettingsService`/`SessionTabEntry`/
//! `SessionTabSnapshot` moved to `cm_core::app_settings` — they only ever
//! depended on the [`ConnectionRepository`] port, never on the concrete
//! SQLite adapter (gap 27 cont., cuts that `cm-ui` → `cm-storage` concrete
//! edge). `cm-ui` still depends on this crate for JSON import/export
//! (`json_io`) — that edge is adapter-shaped (serializes the on-disk schema's
//! envelope format) and was not flagged by the audit; see
//! `docs/devel/memos/P6.15-sessionprovider-port.md`.
//!
//! [`ConnectionRepository`]: cm_core::ConnectionRepository

mod error;
pub mod import;
pub mod json_io;
pub mod migrations;
pub mod repository;

pub use error::StorageError;
pub use json_io::{
    ENVELOPE_VERSION, ExportEnvelope, ExportOptions, ExportedSecret, ImportExportError,
    ImportStats, export, export_to_json, import, import_from_json,
};
pub use repository::SqliteRepository;

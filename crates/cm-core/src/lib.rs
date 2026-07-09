//! `cm-core` — the hexagonal core of ConMan.
//!
//! Holds the domain entities (connections, groups, credentials, credential
//! folders, connection kinds, settings, credential references), their value
//! objects (`CredentialRef`, `Secret`), the typed error enums, and the **port
//! traits** that adapters implement. Pure logic only: no I/O, no protocol or
//! storage libraries. Every other crate depends inward on this one.
//!
//! A saved connection profile *is* a [`Connection`]; there is no separate
//! `Profile` type. IDs are `i64` newtypes matching the SQLite rowid model; a
//! not-yet-persisted record is modelled with the sentinel value
//! [`ConnectionId::UNSAVED`] / [`GroupId::UNSAVED`] / [`CredentialId::UNSAVED`]
//! / [`CredentialFolderId::UNSAVED`] (`== 0`).

mod app_settings;
mod connection;
mod credential;
mod error;
mod ids;
mod kind;
mod ports;
pub mod rdp;
pub mod session;
pub mod session_ports;
mod settings;
pub mod ssh;
pub mod terminal;

pub use app_settings::{
    AppSettings, KEY_FIRST_RUN_SEEDED, KEY_RENDERER_BACKEND, KEY_SESSION_TABS, SessionTabEntry,
    SessionTabSnapshot, SettingsService,
};
pub use connection::{
    Connection, CredentialSource, Group, ResolvedAuth, resolve_connection_auth,
    resolve_effective_credential,
};
pub use credential::{
    Credential, CredentialFolder, CredentialKind, CredentialPurpose, CredentialRef, Secret,
};
pub use error::{CredentialError, DomainError, RepositoryError};
pub use ids::{ConnectionId, CredentialFolderId, CredentialId, GroupId};
pub use kind::ConnectionKind;
pub use ports::{ConnectionRepository, CredentialStore};
pub use session::{
    ExitStatus, FailedSession, FrameUpdate, RdpInputEvent, RdpMouseButton, Session, SessionInput,
    SessionStatus, Surface,
};
pub use session_ports::{SessionProvider, SessionSetupError};
pub use settings::{ConnectionSettings, LocalSettings, RdpSettings, SshAuthMethod, SshSettings};
pub use terminal::{
    Cell, CellAttrs, Color, CursorShape, CursorState, GridSnapshot, Key, KeyEvent, KeyModifiers,
    MouseAction, MouseButton, MouseEvent, TerminalEngine, TerminalSize,
};

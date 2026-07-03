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
mod settings;
pub mod ssh;
pub mod terminal;

pub use app_settings::{AppSettings, SessionTabEntry, SessionTabSnapshot, SettingsService};
pub use connection::{Connection, Group, resolve_effective_credential};
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
pub use settings::{ConnectionSettings, LocalSettings, RdpSettings, SshAuthMethod, SshSettings};
pub use terminal::{
    Cell, CellAttrs, Color, CursorShape, CursorState, GridSnapshot, Key, KeyEvent, KeyModifiers,
    MouseAction, MouseButton, MouseEvent, TerminalEngine, TerminalSize,
};

/// **Sketch only — `SessionProvider` is not yet finalized.**
///
/// `TerminalEngine` was finalized in P2.1 and now lives in [`crate::terminal`].
/// [`crate::session::Session`] (the unified session-lifecycle trait) and the
/// SSH/RDP auth-input and verifier-trait contracts ([`crate::ssh`],
/// [`crate::rdp`]) were relocated here from `cm-session` in P6.15 as the
/// shared vocabulary any `SessionProvider` port needs; the port trait itself
/// — tying those together into `spawn_local`/`connect_ssh`/`connect_rdp` — is
/// defined in a following change (`docs/devel/memos/
/// P6.15-sessionprovider-port.md`).
// TODO(P6.15 cont.): finalize SessionProvider signature.
pub mod session_ports {}

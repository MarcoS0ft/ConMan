//! `cm-core` — the hexagonal core of ConMan.
//!
//! Holds the domain entities (connections, groups, connection kinds, settings,
//! credential references), their value objects (`CredentialRef`, `Secret`), the
//! typed error enums, and the **port traits** that adapters implement. Pure
//! logic only: no I/O, no protocol or storage libraries. Every other crate
//! depends inward on this one.
//!
//! A saved connection profile *is* a [`Connection`]; there is no separate
//! `Profile` type. IDs are `i64` newtypes matching the SQLite rowid model; a
//! not-yet-persisted record is modelled with the sentinel value
//! [`ConnectionId::UNSAVED`] / [`GroupId::UNSAVED`] (`== 0`).

mod connection;
mod credential;
mod error;
mod ids;
mod kind;
mod ports;
mod settings;
pub mod terminal;

pub use connection::{Connection, Group};
pub use credential::{CredentialPurpose, CredentialRef, Secret};
pub use error::{CredentialError, DomainError, RepositoryError};
pub use ids::{ConnectionId, GroupId};
pub use kind::ConnectionKind;
pub use ports::{ConnectionRepository, CredentialStore};
pub use settings::{ConnectionSettings, LocalSettings, RdpSettings, SshAuthMethod, SshSettings};
pub use terminal::{
    Cell, CellAttrs, Color, CursorShape, CursorState, GridSnapshot, Key, KeyEvent, KeyModifiers,
    MouseAction, MouseButton, MouseEvent, TerminalEngine, TerminalSize,
};

/// Crate identifier printed by the skeleton `conman` binary to prove the
/// workspace dependency graph wires up. Scaffolding from P0.1; will be removed
/// once `conman` gains real logic.
pub const NAME: &str = "cm-core";

/// **Sketch only — `SessionProvider` is not yet finalized.**
///
/// `TerminalEngine` was finalized in P2.1 and now lives in [`crate::terminal`].
/// `SessionProvider` remains a sketch until the PTY/transport work (P2.2+).
/// Intended shape (ARCHITECTURE §3):
///
/// - `SessionProvider` — given a resolved connection config, establish a
///   session and return a handle exposing a *surface source* (framebuffer or
///   terminal grid), lifecycle (connect/disconnect/resize), and an input sink.
///
/// Its async / surface signature depends on later spikes and is deliberately
/// left unspecified here — locking it now would pre-empt those decisions.
// TODO(P2.2+): finalize SessionProvider signature.
pub mod session_ports {}

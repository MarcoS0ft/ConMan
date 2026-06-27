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

pub use connection::{Connection, Group};
pub use credential::{CredentialPurpose, CredentialRef, Secret};
pub use error::{CredentialError, DomainError, RepositoryError};
pub use ids::{ConnectionId, GroupId};
pub use kind::ConnectionKind;
pub use ports::{ConnectionRepository, CredentialStore};
pub use settings::{ConnectionSettings, LocalSettings, RdpSettings, SshAuthMethod, SshSettings};

/// **Sketch only — not finalized in P0.4.**
///
/// The session-layer ports are defined here once the P0.2 terminal spike and
/// the P0.3 surface spike land. Intended shape (ARCHITECTURE §3):
///
/// - `SessionProvider` — given a resolved connection config, establish a
///   session and return a handle exposing a *surface source* (framebuffer or
///   terminal grid), lifecycle (connect/disconnect/resize), and an input sink.
/// - `TerminalEngine` — feed raw bytes, maintain grid/cursor/scrollback, expose
///   a renderable snapshot, and encode key/mouse input into bytes.
///
/// Their async / surface signatures depend on the spikes and are deliberately
/// left unspecified here — locking them now would pre-empt those decisions.
// TODO(P2): finalize SessionProvider / TerminalEngine signatures.
pub mod session_ports {}

use serde::{Deserialize, Serialize};

/// Identifier for a [`crate::Connection`], a newtype over the SQLite rowid.
///
/// The sentinel [`ConnectionId::UNSAVED`] (`0`) marks a record that has not yet
/// been persisted; the repository assigns a real id on first upsert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConnectionId(i64);

impl ConnectionId {
    /// Sentinel for a connection that has not been persisted yet.
    pub const UNSAVED: ConnectionId = ConnectionId(0);

    /// Wraps a raw rowid.
    pub const fn new(value: i64) -> Self {
        ConnectionId(value)
    }

    /// Returns the underlying rowid.
    pub const fn get(self) -> i64 {
        self.0
    }

    /// Whether this id is the not-yet-persisted sentinel.
    pub const fn is_unsaved(self) -> bool {
        self.0 == ConnectionId::UNSAVED.0
    }
}

/// Identifier for a [`crate::Group`], a newtype over the SQLite rowid.
///
/// The sentinel [`GroupId::UNSAVED`] (`0`) marks a record that has not yet been
/// persisted; the repository assigns a real id on first upsert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupId(i64);

impl GroupId {
    /// Sentinel for a group that has not been persisted yet.
    pub const UNSAVED: GroupId = GroupId(0);

    /// Wraps a raw rowid.
    pub const fn new(value: i64) -> Self {
        GroupId(value)
    }

    /// Returns the underlying rowid.
    pub const fn get(self) -> i64 {
        self.0
    }

    /// Whether this id is the not-yet-persisted sentinel.
    pub const fn is_unsaved(self) -> bool {
        self.0 == GroupId::UNSAVED.0
    }
}

/// Identifier for a [`crate::Credential`], a newtype over the SQLite rowid.
///
/// The sentinel [`CredentialId::UNSAVED`] (`0`) marks a record that has not yet
/// been persisted; the repository assigns a real id on first upsert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialId(i64);

impl CredentialId {
    /// Sentinel for a credential that has not been persisted yet.
    pub const UNSAVED: CredentialId = CredentialId(0);

    /// Wraps a raw rowid.
    pub const fn new(value: i64) -> Self {
        CredentialId(value)
    }

    /// Returns the underlying rowid.
    pub const fn get(self) -> i64 {
        self.0
    }

    /// Whether this id is the not-yet-persisted sentinel.
    pub const fn is_unsaved(self) -> bool {
        self.0 == CredentialId::UNSAVED.0
    }
}

/// Identifier for a [`crate::CredentialFolder`], a newtype over the SQLite rowid.
///
/// The sentinel [`CredentialFolderId::UNSAVED`] (`0`) marks a record that has not yet
/// been persisted; the repository assigns a real id on first upsert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialFolderId(i64);

impl CredentialFolderId {
    /// Sentinel for a credential folder that has not been persisted yet.
    pub const UNSAVED: CredentialFolderId = CredentialFolderId(0);

    /// Wraps a raw rowid.
    pub const fn new(value: i64) -> Self {
        CredentialFolderId(value)
    }

    /// Returns the underlying rowid.
    pub const fn get(self) -> i64 {
        self.0
    }

    /// Whether this id is the not-yet-persisted sentinel.
    pub const fn is_unsaved(self) -> bool {
        self.0 == CredentialFolderId::UNSAVED.0
    }
}

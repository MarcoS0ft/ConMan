use crate::connection::{Connection, Group};
use crate::credential::{Credential, CredentialFolder, CredentialRef, Secret};
use crate::error::{CredentialError, RepositoryError};
use crate::ids::{ConnectionId, CredentialFolderId, CredentialId, GroupId};

/// Persistence port for connections, groups, credentials, and credential
/// folders. Synchronous (the SQLite adapter is sync; the binary wraps it for
/// async use) and object-safe, so it can be held as `dyn ConnectionRepository`.
///
/// # Delete semantics (pinned)
///
/// - **Group delete** is blocked if the group has child groups or connections
///   (returns [`RepositoryError::Conflict`]). The caller must first move or
///   delete all children.
/// - **Credential-folder delete** is blocked if the folder has sub-folders or
///   credentials (returns [`RepositoryError::Conflict`]).
/// - **Credential delete** is allowed even when it is referenced by connections
///   or groups; those references are nullified (`ON DELETE SET NULL`).
///
/// # Cycle invariant (pinned)
///
/// Both the group tree and the credential-folder tree are cycle-free. Any
/// [`move_group`][Self::move_group] or
/// [`move_credential_folder`][Self::move_credential_folder] that would make a
/// node its own ancestor is rejected with [`RepositoryError::Conflict`].
pub trait ConnectionRepository: Send + Sync {
    // -----------------------------------------------------------------------
    // Connections
    // -----------------------------------------------------------------------

    fn list_connections(&self) -> Result<Vec<Connection>, RepositoryError>;
    fn get_connection(&self, id: ConnectionId) -> Result<Option<Connection>, RepositoryError>;

    /// Inserts (when `conn.id == `[`ConnectionId::UNSAVED`]) or replaces an
    /// existing connection; returns the persisted id.
    fn upsert_connection(&self, conn: &Connection) -> Result<ConnectionId, RepositoryError>;
    fn delete_connection(&self, id: ConnectionId) -> Result<(), RepositoryError>;
    fn move_connection(
        &self,
        id: ConnectionId,
        new_group: Option<GroupId>,
        new_sort: i64,
    ) -> Result<(), RepositoryError>;

    // -----------------------------------------------------------------------
    // Groups
    // -----------------------------------------------------------------------

    fn list_groups(&self) -> Result<Vec<Group>, RepositoryError>;
    fn get_group(&self, id: GroupId) -> Result<Option<Group>, RepositoryError>;

    /// Inserts (when `group.id == `[`GroupId::UNSAVED`]) or replaces an
    /// existing group; returns the persisted id.
    fn upsert_group(&self, group: &Group) -> Result<GroupId, RepositoryError>;

    /// Delete is blocked when the group has child groups or connections.
    fn delete_group(&self, id: GroupId) -> Result<(), RepositoryError>;

    /// Moves a group to a new parent/sort position. Returns
    /// [`RepositoryError::Conflict`] if the move would create a cycle.
    fn move_group(
        &self,
        id: GroupId,
        new_parent: Option<GroupId>,
        new_sort: i64,
    ) -> Result<(), RepositoryError>;

    // -----------------------------------------------------------------------
    // Credentials
    // -----------------------------------------------------------------------

    fn list_credentials(&self) -> Result<Vec<Credential>, RepositoryError>;
    fn get_credential(&self, id: CredentialId) -> Result<Option<Credential>, RepositoryError>;

    /// Inserts (when `cred.id == `[`CredentialId::UNSAVED`]) or replaces an
    /// existing credential; returns the persisted id.
    fn upsert_credential(&self, cred: &Credential) -> Result<CredentialId, RepositoryError>;

    /// Deletes the credential; connections and groups that referenced it have
    /// their credential id nullified.
    fn delete_credential(&self, id: CredentialId) -> Result<(), RepositoryError>;

    // -----------------------------------------------------------------------
    // Credential folders
    // -----------------------------------------------------------------------

    fn list_credential_folders(&self) -> Result<Vec<CredentialFolder>, RepositoryError>;
    fn get_credential_folder(
        &self,
        id: CredentialFolderId,
    ) -> Result<Option<CredentialFolder>, RepositoryError>;

    /// Inserts (when `folder.id == `[`CredentialFolderId::UNSAVED`]) or replaces
    /// an existing folder; returns the persisted id.
    fn upsert_credential_folder(
        &self,
        folder: &CredentialFolder,
    ) -> Result<CredentialFolderId, RepositoryError>;

    /// Delete is blocked when the folder has sub-folders or credentials.
    fn delete_credential_folder(&self, id: CredentialFolderId) -> Result<(), RepositoryError>;

    /// Moves a credential folder to a new parent/sort position. Returns
    /// [`RepositoryError::Conflict`] if the move would create a cycle.
    fn move_credential_folder(
        &self,
        id: CredentialFolderId,
        new_parent: Option<CredentialFolderId>,
        new_sort: i64,
    ) -> Result<(), RepositoryError>;

    // -----------------------------------------------------------------------
    // Inheritance resolution
    // -----------------------------------------------------------------------

    /// Returns the effective [`CredentialId`] for a connection by walking the
    /// group inheritance chain:
    ///
    /// 1. The connection's own `credential_id` if set, else
    /// 2. The `default_credential_id` of the nearest ancestor group that has
    ///    one, else
    /// 3. `None`.
    fn resolve_effective_credential(
        &self,
        conn_id: ConnectionId,
    ) -> Result<Option<CredentialId>, RepositoryError>;

    // -----------------------------------------------------------------------
    // Settings
    // -----------------------------------------------------------------------

    fn get_setting(&self, key: &str) -> Result<Option<String>, RepositoryError>;
    fn set_setting(&self, key: &str, value: &str) -> Result<(), RepositoryError>;

    // -----------------------------------------------------------------------
    // Recents (P6.14 — Launchpad)
    // -----------------------------------------------------------------------

    /// Records that `id` was just opened at `opened_at` (epoch seconds),
    /// superseding any earlier record for the same connection. Recency only —
    /// not frecency (a nice-to-have noted, not implemented, by the P6.14 task
    /// spec). Best-effort: callers should treat a failure here as non-fatal to
    /// the connect attempt itself (see the schema memo,
    /// `docs/devel/memos/P6.14-recents-schema.md`).
    fn record_recent(&self, id: ConnectionId, opened_at: i64) -> Result<(), RepositoryError>;

    /// Returns up to `limit` `(connection id, opened_at)` pairs among
    /// recently-opened connections, most-recently-opened first. A connection
    /// deleted since it was recorded is never returned (its recents row is
    /// removed with it — see the schema memo).
    fn list_recents(&self, limit: usize) -> Result<Vec<(ConnectionId, i64)>, RepositoryError>;
}

/// Secret-storage port backed by the OS keychain. Secrets cross this boundary
/// only as [`Secret`] values; references are [`CredentialRef`]s.
pub trait CredentialStore: Send + Sync {
    fn store(&self, key: &CredentialRef, secret: &Secret) -> Result<(), CredentialError>;
    fn get(&self, key: &CredentialRef) -> Result<Option<Secret>, CredentialError>;
    fn delete(&self, key: &CredentialRef) -> Result<(), CredentialError>;
}

use crate::connection::{Connection, Group};
use crate::credential::{CredentialRef, Secret};
use crate::error::{CredentialError, RepositoryError};
use crate::ids::{ConnectionId, GroupId};

/// Persistence port for connections and groups.
///
/// Synchronous (the SQLite adapter is sync; the binary wraps it for async use)
/// and object-safe, so it can be held as `dyn ConnectionRepository`.
pub trait ConnectionRepository: Send + Sync {
    fn list_groups(&self) -> Result<Vec<Group>, RepositoryError>;
    fn list_connections(&self) -> Result<Vec<Connection>, RepositoryError>;
    fn get_connection(&self, id: ConnectionId) -> Result<Option<Connection>, RepositoryError>;

    /// Inserts a new record (id is [`ConnectionId::UNSAVED`]/[`GroupId::UNSAVED`])
    /// or updates an existing one, returning the persisted id.
    fn upsert_group(&self, group: &Group) -> Result<GroupId, RepositoryError>;
    fn upsert_connection(&self, conn: &Connection) -> Result<ConnectionId, RepositoryError>;

    fn delete_group(&self, id: GroupId) -> Result<(), RepositoryError>;
    fn delete_connection(&self, id: ConnectionId) -> Result<(), RepositoryError>;

    fn move_connection(
        &self,
        id: ConnectionId,
        new_group: Option<GroupId>,
        new_sort: i64,
    ) -> Result<(), RepositoryError>;
    fn move_group(
        &self,
        id: GroupId,
        new_parent: Option<GroupId>,
        new_sort: i64,
    ) -> Result<(), RepositoryError>;
}

/// Secret-storage port backed by the OS keychain. Secrets cross this boundary
/// only as [`Secret`] values; references are [`CredentialRef`]s.
pub trait CredentialStore: Send + Sync {
    fn store(&self, key: &CredentialRef, secret: &Secret) -> Result<(), CredentialError>;
    fn get(&self, key: &CredentialRef) -> Result<Option<Secret>, CredentialError>;
    fn delete(&self, key: &CredentialRef) -> Result<(), CredentialError>;
}

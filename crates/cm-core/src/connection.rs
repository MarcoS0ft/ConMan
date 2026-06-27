use serde::{Deserialize, Serialize};

use crate::credential::CredentialRef;
use crate::error::DomainError;
use crate::ids::{ConnectionId, GroupId};
use crate::kind::ConnectionKind;
use crate::settings::ConnectionSettings;

/// A node in the connection tree that holds connections and/or other groups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    /// Parent group; `None` means root level.
    pub parent_id: Option<GroupId>,
    pub name: String,
    /// Ordering among siblings.
    pub sort: i64,
}

/// A saved connection profile. Carries kind-specific [`ConnectionSettings`] and,
/// optionally, a [`CredentialRef`] into the keychain (never the secret itself).
///
/// Timestamps are `i64` epoch seconds (no `chrono` dependency).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    pub id: ConnectionId,
    /// Owning group; `None` means root level.
    pub group_id: Option<GroupId>,
    pub name: String,
    pub kind: ConnectionKind,
    pub settings: ConnectionSettings,
    pub credential_ref: Option<CredentialRef>,
    /// Ordering among siblings.
    pub sort: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Connection {
    /// Builds a connection, rejecting a `settings` variant that disagrees with
    /// `kind` ([`DomainError::SettingsKindMismatch`]).
    // The entity genuinely has this many independent fields; grouping them into
    // a sub-struct purely to satisfy the lint would obscure the data model.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ConnectionId,
        group_id: Option<GroupId>,
        name: String,
        kind: ConnectionKind,
        settings: ConnectionSettings,
        credential_ref: Option<CredentialRef>,
        sort: i64,
        created_at: i64,
        updated_at: i64,
    ) -> Result<Self, DomainError> {
        let conn = Self {
            id,
            group_id,
            name,
            kind,
            settings,
            credential_ref,
            sort,
            created_at,
            updated_at,
        };
        conn.validate()?;
        Ok(conn)
    }

    /// Checks the kind/settings invariant. Use this to defensively validate
    /// connections rehydrated from untrusted input (e.g. imported JSON).
    pub fn validate(&self) -> Result<(), DomainError> {
        let found = self.settings.kind();
        if found != self.kind {
            return Err(DomainError::SettingsKindMismatch {
                expected: self.kind,
                found,
            });
        }
        Ok(())
    }
}

use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::ids::{ConnectionId, CredentialId, GroupId};
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
    /// The credential inherited by connections in this group and its
    /// descendants unless overridden. `None` means no default (inherit from
    /// the parent group or leave unset).
    pub default_credential: Option<CredentialId>,
}

/// A saved connection profile. Carries kind-specific [`ConnectionSettings`]
/// and, optionally, a reference to a [`crate::Credential`] (never the secret
/// itself). The effective credential is resolved by
/// [`resolve_effective_credential`].
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
    /// Explicit credential override for this connection. `None` means inherit
    /// from the ancestor group chain (see [`resolve_effective_credential`]).
    pub credential: Option<CredentialId>,
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
        credential: Option<CredentialId>,
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
            credential,
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

/// Returns the effective [`CredentialId`] for a connection:
///
/// 1. `conn.credential` if explicitly set, or
/// 2. the `default_credential` of the nearest ancestor group that has one
///    (walking `parent_id` up the chain), or
/// 3. `None` if neither the connection nor any ancestor group specifies one.
///
/// The walk is bounded by `groups.len()` to be cycle-safe: a valid (acyclic)
/// group tree of N nodes has paths of at most N steps, so any longer walk
/// would imply a cycle and is terminated.
pub fn resolve_effective_credential(conn: &Connection, groups: &[Group]) -> Option<CredentialId> {
    if let Some(id) = conn.credential {
        return Some(id);
    }

    // Walk ancestor groups; bounded by group count for cycle safety.
    let max_depth = groups.len();
    let mut current_group_id = conn.group_id;
    for _ in 0..max_depth {
        let gid = current_group_id?;
        let group = groups.iter().find(|g| g.id == gid)?;
        if let Some(cred) = group.default_credential {
            return Some(cred);
        }
        current_group_id = group.parent_id;
    }
    None
}

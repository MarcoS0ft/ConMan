use std::sync::Mutex;

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionRepository, ConnectionSettings, Credential,
    CredentialFolder, CredentialFolderId, CredentialId, CredentialKind, Group, GroupId,
    RepositoryError,
};
use rusqlite::OptionalExtension as _;

use crate::error::StorageError;
use crate::migrations::run_migrations;

/// Maximum ancestor-walk depth when checking for cycles in either tree.
/// A valid (acyclic) tree of *N* nodes has paths of at most *N* steps; this
/// constant guards against walking an already-corrupt tree forever.
const MAX_TREE_DEPTH: usize = 1024;

// ---------------------------------------------------------------------------
// SqliteRepository
// ---------------------------------------------------------------------------

/// SQLite-backed adapter implementing [`ConnectionRepository`].
///
/// The underlying [`rusqlite::Connection`] is `!Sync`; access is serialised via
/// a [`Mutex`].  All structural mutations run inside an explicit transaction.
pub struct SqliteRepository {
    conn: Mutex<rusqlite::Connection>,
}

impl std::fmt::Debug for SqliteRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteRepository").finish_non_exhaustive()
    }
}

impl SqliteRepository {
    /// Opens (or creates) a SQLite database at `path` and applies any pending
    /// schema migrations.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        let start = std::time::Instant::now();
        tracing::info!(path = %path.display(), "opening SQLite database");
        let conn = rusqlite::Connection::open(path).map_err(|e| {
            tracing::error!(path = %path.display(), error = %e, "failed to open database");
            StorageError::Open(e.to_string())
        })?;
        let repo = Self::initialize(conn)?;
        tracing::info!(
            path = %path.display(),
            elapsed_ms = start.elapsed().as_millis(),
            "database ready"
        );
        Ok(repo)
    }

    /// Opens an in-memory database (data is lost when the repository is
    /// dropped).  Primarily for tests.
    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| StorageError::Open(e.to_string()))?;
        Self::initialize(conn)
    }

    fn initialize(mut conn: rusqlite::Connection) -> Result<Self, StorageError> {
        // WAL is a no-op for in-memory DBs; silently ignored. A genuine
        // failure (e.g. a filesystem that doesn't support WAL) still falls
        // back to the default journal mode, but is worth a WARN.
        if conn.execute_batch("PRAGMA journal_mode=WAL;").is_err() {
            tracing::warn!("WAL journal mode unavailable; using default");
        }
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|e| StorageError::Migration(e.to_string()))?;
        run_migrations(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, RepositoryError> {
        self.conn
            .lock()
            .map_err(|e| RepositoryError::Backend(format!("mutex poisoned: {e}")))
    }
}

// ---------------------------------------------------------------------------
// ConnectionRepository implementation
// ---------------------------------------------------------------------------

impl ConnectionRepository for SqliteRepository {
    // -----------------------------------------------------------------------
    // Connections
    // -----------------------------------------------------------------------

    fn list_connections(&self) -> Result<Vec<Connection>, RepositoryError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, group_id, kind, name, settings_json, credential_id, sort, \
                 created_at, updated_at \
                 FROM connections ORDER BY group_id, sort, id",
            )
            .map_err(map_err)?;
        let rows = stmt.query_map([], map_connection_row).map_err(map_err)?;
        rows.map(|r| r.map_err(map_err)?.into_connection())
            .collect()
    }

    fn get_connection(&self, id: ConnectionId) -> Result<Option<Connection>, RepositoryError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, group_id, kind, name, settings_json, credential_id, sort, \
             created_at, updated_at \
             FROM connections WHERE id = ?1",
            [id.get()],
            map_connection_row,
        )
        .optional()
        .map_err(map_err)?
        .map(|r| r.into_connection())
        .transpose()
    }

    fn upsert_connection(&self, c: &Connection) -> Result<ConnectionId, RepositoryError> {
        let conn = self.lock()?;
        let kind_str = connection_kind_str(c.kind);
        let settings_json = serde_json::to_string(&c.settings)
            .map_err(|e| RepositoryError::Backend(e.to_string()))?;
        let (host, port) = extract_host_port(&c.settings);

        if c.id.is_unsaved() {
            conn.execute(
                "INSERT INTO connections \
                 (group_id, kind, name, host, port, settings_json, credential_id, sort, \
                  created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    c.group_id.map(|g| g.get()),
                    kind_str,
                    c.name,
                    host,
                    port,
                    settings_json,
                    c.credential.map(|cr| cr.get()),
                    c.sort,
                    c.created_at,
                    c.updated_at,
                ],
            )
            .map_err(map_err)?;
            Ok(ConnectionId::new(conn.last_insert_rowid()))
        } else {
            let rows = conn
                .execute(
                    "UPDATE connections SET \
                     group_id=?1, kind=?2, name=?3, host=?4, port=?5, \
                     settings_json=?6, credential_id=?7, sort=?8, updated_at=?9 \
                     WHERE id=?10",
                    rusqlite::params![
                        c.group_id.map(|g| g.get()),
                        kind_str,
                        c.name,
                        host,
                        port,
                        settings_json,
                        c.credential.map(|cr| cr.get()),
                        c.sort,
                        c.updated_at,
                        c.id.get(),
                    ],
                )
                .map_err(map_err)?;
            if rows == 0 {
                return Err(RepositoryError::NotFound);
            }
            Ok(c.id)
        }
    }

    fn delete_connection(&self, id: ConnectionId) -> Result<(), RepositoryError> {
        let conn = self.lock()?;
        let rows = conn
            .execute("DELETE FROM connections WHERE id = ?1", [id.get()])
            .map_err(map_err)?;
        if rows == 0 {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    fn move_connection(
        &self,
        id: ConnectionId,
        new_group: Option<GroupId>,
        new_sort: i64,
    ) -> Result<(), RepositoryError> {
        let conn = self.lock()?;
        let rows = conn
            .execute(
                "UPDATE connections SET group_id=?1, sort=?2 WHERE id=?3",
                rusqlite::params![new_group.map(|g| g.get()), new_sort, id.get()],
            )
            .map_err(map_err)?;
        if rows == 0 {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Groups
    // -----------------------------------------------------------------------

    fn list_groups(&self) -> Result<Vec<Group>, RepositoryError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, parent_id, name, sort, default_credential_id \
                 FROM groups ORDER BY parent_id, sort, id",
            )
            .map_err(map_err)?;
        let rows = stmt.query_map([], map_group_row).map_err(map_err)?;
        rows.map(|r| r.map_err(map_err)).collect()
    }

    fn get_group(&self, id: GroupId) -> Result<Option<Group>, RepositoryError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, parent_id, name, sort, default_credential_id \
             FROM groups WHERE id = ?1",
            [id.get()],
            map_group_row,
        )
        .optional()
        .map_err(map_err)
    }

    fn upsert_group(&self, group: &Group) -> Result<GroupId, RepositoryError> {
        let conn = self.lock()?;
        if group.id.is_unsaved() {
            // New groups never have descendants, so no cycle is possible.
            conn.execute(
                "INSERT INTO groups (parent_id, name, sort, default_credential_id) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    group.parent_id.map(|p| p.get()),
                    group.name,
                    group.sort,
                    group.default_credential.map(|c| c.get()),
                ],
            )
            .map_err(map_err)?;
            Ok(GroupId::new(conn.last_insert_rowid()))
        } else {
            // Updating an existing group: check for cycles if the parent is changing.
            if would_create_group_cycle(&conn, group.id, group.parent_id)? {
                return Err(RepositoryError::Conflict(format!(
                    "reparenting group {} would create a cycle",
                    group.id.get()
                )));
            }
            let rows = conn
                .execute(
                    "UPDATE groups SET parent_id=?1, name=?2, sort=?3, \
                     default_credential_id=?4 WHERE id=?5",
                    rusqlite::params![
                        group.parent_id.map(|p| p.get()),
                        group.name,
                        group.sort,
                        group.default_credential.map(|c| c.get()),
                        group.id.get(),
                    ],
                )
                .map_err(map_err)?;
            if rows == 0 {
                return Err(RepositoryError::NotFound);
            }
            Ok(group.id)
        }
    }

    fn delete_group(&self, id: GroupId) -> Result<(), RepositoryError> {
        let conn = self.lock()?;

        // Block if there are child groups.
        let child_groups: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM groups WHERE parent_id = ?1",
                [id.get()],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        if child_groups > 0 {
            return Err(RepositoryError::Conflict(
                "group has child groups; move or delete them first".into(),
            ));
        }

        // Block if there are connections in the group.
        let child_conns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM connections WHERE group_id = ?1",
                [id.get()],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        if child_conns > 0 {
            return Err(RepositoryError::Conflict(
                "group has connections; move or delete them first".into(),
            ));
        }

        let rows = conn
            .execute("DELETE FROM groups WHERE id = ?1", [id.get()])
            .map_err(map_err)?;
        if rows == 0 {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    fn move_group(
        &self,
        id: GroupId,
        new_parent: Option<GroupId>,
        new_sort: i64,
    ) -> Result<(), RepositoryError> {
        let conn = self.lock()?;

        if would_create_group_cycle(&conn, id, new_parent)? {
            return Err(RepositoryError::Conflict(format!(
                "moving group {} under {:?} would create a cycle",
                id.get(),
                new_parent.map(|p| p.get()),
            )));
        }

        let rows = conn
            .execute(
                "UPDATE groups SET parent_id=?1, sort=?2 WHERE id=?3",
                rusqlite::params![new_parent.map(|p| p.get()), new_sort, id.get()],
            )
            .map_err(map_err)?;
        if rows == 0 {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Credentials
    // -----------------------------------------------------------------------

    fn list_credentials(&self) -> Result<Vec<Credential>, RepositoryError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, folder_id, name, kind, username \
                 FROM credentials ORDER BY folder_id, id",
            )
            .map_err(map_err)?;
        let rows = stmt.query_map([], map_credential_row).map_err(map_err)?;
        rows.map(|r| r.map_err(map_err)).collect()
    }

    fn get_credential(&self, id: CredentialId) -> Result<Option<Credential>, RepositoryError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, folder_id, name, kind, username \
             FROM credentials WHERE id = ?1",
            [id.get()],
            map_credential_row,
        )
        .optional()
        .map_err(map_err)
    }

    fn upsert_credential(&self, cred: &Credential) -> Result<CredentialId, RepositoryError> {
        let conn = self.lock()?;
        let kind_str = credential_kind_str(cred.kind);

        if cred.id.is_unsaved() {
            conn.execute(
                "INSERT INTO credentials (folder_id, name, kind, username) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    cred.folder_id.map(|f| f.get()),
                    cred.name,
                    kind_str,
                    cred.username,
                ],
            )
            .map_err(map_err)?;
            Ok(CredentialId::new(conn.last_insert_rowid()))
        } else {
            let rows = conn
                .execute(
                    "UPDATE credentials SET folder_id=?1, name=?2, kind=?3, username=?4 \
                     WHERE id=?5",
                    rusqlite::params![
                        cred.folder_id.map(|f| f.get()),
                        cred.name,
                        kind_str,
                        cred.username,
                        cred.id.get(),
                    ],
                )
                .map_err(map_err)?;
            if rows == 0 {
                return Err(RepositoryError::NotFound);
            }
            Ok(cred.id)
        }
    }

    fn delete_credential(&self, id: CredentialId) -> Result<(), RepositoryError> {
        let conn = self.lock()?;
        // ON DELETE SET NULL on connections.credential_id and
        // groups.default_credential_id is handled by the FK constraint.
        let rows = conn
            .execute("DELETE FROM credentials WHERE id = ?1", [id.get()])
            .map_err(map_err)?;
        if rows == 0 {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Credential folders
    // -----------------------------------------------------------------------

    fn list_credential_folders(&self) -> Result<Vec<CredentialFolder>, RepositoryError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, parent_id, name, sort \
                 FROM credential_folders ORDER BY parent_id, sort, id",
            )
            .map_err(map_err)?;
        let rows = stmt.query_map([], map_folder_row).map_err(map_err)?;
        rows.map(|r| r.map_err(map_err)).collect()
    }

    fn get_credential_folder(
        &self,
        id: CredentialFolderId,
    ) -> Result<Option<CredentialFolder>, RepositoryError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, parent_id, name, sort \
             FROM credential_folders WHERE id = ?1",
            [id.get()],
            map_folder_row,
        )
        .optional()
        .map_err(map_err)
    }

    fn upsert_credential_folder(
        &self,
        folder: &CredentialFolder,
    ) -> Result<CredentialFolderId, RepositoryError> {
        let conn = self.lock()?;

        if folder.id.is_unsaved() {
            conn.execute(
                "INSERT INTO credential_folders (parent_id, name, sort) \
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![folder.parent_id.map(|p| p.get()), folder.name, folder.sort,],
            )
            .map_err(map_err)?;
            Ok(CredentialFolderId::new(conn.last_insert_rowid()))
        } else {
            if would_create_folder_cycle(&conn, folder.id, folder.parent_id)? {
                return Err(RepositoryError::Conflict(format!(
                    "reparenting folder {} would create a cycle",
                    folder.id.get()
                )));
            }
            let rows = conn
                .execute(
                    "UPDATE credential_folders SET parent_id=?1, name=?2, sort=?3 \
                     WHERE id=?4",
                    rusqlite::params![
                        folder.parent_id.map(|p| p.get()),
                        folder.name,
                        folder.sort,
                        folder.id.get(),
                    ],
                )
                .map_err(map_err)?;
            if rows == 0 {
                return Err(RepositoryError::NotFound);
            }
            Ok(folder.id)
        }
    }

    fn delete_credential_folder(&self, id: CredentialFolderId) -> Result<(), RepositoryError> {
        let conn = self.lock()?;

        // Block if there are sub-folders.
        let sub_folders: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM credential_folders WHERE parent_id = ?1",
                [id.get()],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        if sub_folders > 0 {
            return Err(RepositoryError::Conflict(
                "folder has sub-folders; move or delete them first".into(),
            ));
        }

        // Block if there are credentials in the folder.
        let cred_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM credentials WHERE folder_id = ?1",
                [id.get()],
                |r| r.get(0),
            )
            .map_err(map_err)?;
        if cred_count > 0 {
            return Err(RepositoryError::Conflict(
                "folder has credentials; move or delete them first".into(),
            ));
        }

        let rows = conn
            .execute("DELETE FROM credential_folders WHERE id = ?1", [id.get()])
            .map_err(map_err)?;
        if rows == 0 {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    fn move_credential_folder(
        &self,
        id: CredentialFolderId,
        new_parent: Option<CredentialFolderId>,
        new_sort: i64,
    ) -> Result<(), RepositoryError> {
        let conn = self.lock()?;

        if would_create_folder_cycle(&conn, id, new_parent)? {
            return Err(RepositoryError::Conflict(format!(
                "moving folder {} under {:?} would create a cycle",
                id.get(),
                new_parent.map(|p| p.get()),
            )));
        }

        let rows = conn
            .execute(
                "UPDATE credential_folders SET parent_id=?1, sort=?2 WHERE id=?3",
                rusqlite::params![new_parent.map(|p| p.get()), new_sort, id.get()],
            )
            .map_err(map_err)?;
        if rows == 0 {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Inheritance resolution
    // -----------------------------------------------------------------------

    fn resolve_effective_credential(
        &self,
        conn_id: ConnectionId,
    ) -> Result<Option<CredentialId>, RepositoryError> {
        let conn = self.lock()?;

        // Fetch the connection's own credential and its group.
        let row: Option<(Option<i64>, Option<i64>)> = conn
            .query_row(
                "SELECT credential_id, group_id FROM connections WHERE id = ?1",
                [conn_id.get()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(map_err)?;

        let (explicit_cred, mut current_group) = row.ok_or(RepositoryError::NotFound)?;

        // Explicit credential on the connection wins immediately.
        if let Some(cid) = explicit_cred {
            return Ok(Some(CredentialId::new(cid)));
        }

        // Walk up the ancestor group chain, bounded for cycle safety.
        for _ in 0..MAX_TREE_DEPTH {
            let gid = match current_group {
                None => return Ok(None),
                Some(g) => g,
            };

            let group_row: Option<(Option<i64>, Option<i64>)> = conn
                .query_row(
                    "SELECT default_credential_id, parent_id FROM groups WHERE id = ?1",
                    [gid],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(map_err)?;

            let (default_cred, parent_id) = match group_row {
                None => return Ok(None), // group row missing; treat as root
                Some(pair) => pair,
            };

            if let Some(cid) = default_cred {
                return Ok(Some(CredentialId::new(cid)));
            }
            current_group = parent_id;
        }

        // Exceeded MAX_TREE_DEPTH: assume no credential rather than looping.
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Settings
    // -----------------------------------------------------------------------

    fn get_setting(&self, key: &str) -> Result<Option<String>, RepositoryError> {
        let conn = self.lock()?;
        conn.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
            r.get(0)
        })
        .optional()
        .map_err(map_err)
    }

    fn set_setting(&self, key: &str, value: &str) -> Result<(), RepositoryError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [key, value],
        )
        .map_err(map_err)?;
        Ok(())
    }

    fn list_settings(&self) -> Result<Vec<(String, String)>, RepositoryError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT key, value FROM settings ORDER BY key")
            .map_err(map_err)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(map_err)?;
        rows.map(|r| r.map_err(map_err)).collect()
    }

    // -----------------------------------------------------------------------
    // Recents (P6.14 — Launchpad)
    // -----------------------------------------------------------------------

    fn record_recent(&self, id: ConnectionId, opened_at: i64) -> Result<(), RepositoryError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO recents (connection_id, opened_at) VALUES (?1, ?2) \
             ON CONFLICT(connection_id) DO UPDATE SET opened_at = excluded.opened_at",
            rusqlite::params![id.get(), opened_at],
        )
        .map_err(map_err)?;
        Ok(())
    }

    fn list_recents(&self, limit: usize) -> Result<Vec<(ConnectionId, i64)>, RepositoryError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT connection_id, opened_at FROM recents ORDER BY opened_at DESC LIMIT ?1",
            )
            .map_err(map_err)?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = stmt
            .query_map(rusqlite::params![limit], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            })
            .map_err(map_err)?;
        rows.map(|r| {
            r.map(|(id, ts)| (ConnectionId::new(id), ts))
                .map_err(map_err)
        })
        .collect()
    }
}

// ---------------------------------------------------------------------------
// Row mappers
// ---------------------------------------------------------------------------

/// Intermediate representation of a `connections` row.  Deferred conversion
/// to [`Connection`] lets us return [`rusqlite::Error`] from the closure and
/// propagate richer [`RepositoryError`]s later.
struct ConnectionRow {
    id: i64,
    group_id: Option<i64>,
    kind_str: String,
    name: String,
    settings_json: String,
    credential_id: Option<i64>,
    sort: i64,
    created_at: i64,
    updated_at: i64,
}

impl ConnectionRow {
    fn into_connection(self) -> Result<Connection, RepositoryError> {
        let kind = parse_connection_kind(&self.kind_str)?;
        let settings: ConnectionSettings =
            serde_json::from_str(&self.settings_json).map_err(|e| {
                RepositoryError::Backend(format!(
                    "corrupt settings_json for connection {}: {e}",
                    self.id
                ))
            })?;
        // Validate kind/settings agreement defensively (untrusted DB content).
        Connection::new(
            ConnectionId::new(self.id),
            self.group_id.map(GroupId::new),
            self.name,
            kind,
            settings,
            self.credential_id.map(CredentialId::new),
            self.sort,
            self.created_at,
            self.updated_at,
        )
        .map_err(|e| {
            RepositoryError::Backend(format!(
                "domain validation error for connection {}: {e}",
                self.id
            ))
        })
    }
}

fn map_connection_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConnectionRow> {
    Ok(ConnectionRow {
        id: row.get(0)?,
        group_id: row.get(1)?,
        kind_str: row.get(2)?,
        name: row.get(3)?,
        settings_json: row.get(4)?,
        credential_id: row.get(5)?,
        sort: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn map_group_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Group> {
    Ok(Group {
        id: GroupId::new(row.get(0)?),
        parent_id: row.get::<_, Option<i64>>(1)?.map(GroupId::new),
        name: row.get(2)?,
        sort: row.get(3)?,
        default_credential: row.get::<_, Option<i64>>(4)?.map(CredentialId::new),
    })
}

fn map_credential_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Credential> {
    let kind_str: String = row.get(3)?;
    let kind = parse_credential_kind_rusqlite(&kind_str)?;
    Ok(Credential {
        id: CredentialId::new(row.get(0)?),
        folder_id: row.get::<_, Option<i64>>(1)?.map(CredentialFolderId::new),
        name: row.get(2)?,
        kind,
        username: row.get(4)?,
    })
}

fn map_folder_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CredentialFolder> {
    Ok(CredentialFolder {
        id: CredentialFolderId::new(row.get(0)?),
        parent_id: row.get::<_, Option<i64>>(1)?.map(CredentialFolderId::new),
        name: row.get(2)?,
        sort: row.get(3)?,
    })
}

// ---------------------------------------------------------------------------
// Kind serialisation helpers
// ---------------------------------------------------------------------------

fn connection_kind_str(kind: ConnectionKind) -> &'static str {
    match kind {
        ConnectionKind::Rdp => "rdp",
        ConnectionKind::Ssh => "ssh",
        ConnectionKind::LocalTerminal => "local",
    }
}

fn parse_connection_kind(s: &str) -> Result<ConnectionKind, RepositoryError> {
    match s {
        "rdp" => Ok(ConnectionKind::Rdp),
        "ssh" => Ok(ConnectionKind::Ssh),
        "local" => Ok(ConnectionKind::LocalTerminal),
        _ => Err(RepositoryError::Backend(format!(
            "unknown connection kind '{s}' in database"
        ))),
    }
}

fn credential_kind_str(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::Password => "password",
        CredentialKind::SshKey => "ssh-key",
        CredentialKind::SshKeyWithPassphrase => "ssh-key-with-passphrase",
    }
}

/// Credential-kind parser returning `rusqlite::Error` for use inside row
/// closures.
fn parse_credential_kind_rusqlite(s: &str) -> rusqlite::Result<CredentialKind> {
    match s {
        "password" => Ok(CredentialKind::Password),
        "ssh-key" => Ok(CredentialKind::SshKey),
        "ssh-key-with-passphrase" => Ok(CredentialKind::SshKeyWithPassphrase),
        _ => Err(rusqlite::Error::InvalidColumnType(
            3,
            format!("unknown credential kind '{s}'"),
            rusqlite::types::Type::Text,
        )),
    }
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

fn extract_host_port(settings: &ConnectionSettings) -> (Option<String>, Option<i64>) {
    match settings {
        ConnectionSettings::Rdp(s) => (Some(s.host.clone()), Some(i64::from(s.port))),
        ConnectionSettings::Ssh(s) => (Some(s.host.clone()), Some(i64::from(s.port))),
        ConnectionSettings::Local(_) => (None, None),
    }
}

fn map_err(e: rusqlite::Error) -> RepositoryError {
    RepositoryError::Backend(e.to_string())
}

// ---------------------------------------------------------------------------
// Cycle detection
// ---------------------------------------------------------------------------

/// Returns `true` if making `id` a child of `proposed_parent` would create a
/// cycle in the group tree.
///
/// Algorithm: walk *upward* from `proposed_parent` through `parent_id` links.
/// If we encounter `id`, there is a cycle.  The walk is bounded by
/// [`MAX_TREE_DEPTH`] to guard against already-corrupt trees.
fn would_create_group_cycle(
    conn: &rusqlite::Connection,
    id: GroupId,
    proposed_parent: Option<GroupId>,
) -> Result<bool, RepositoryError> {
    let Some(mut current) = proposed_parent else {
        return Ok(false); // moving to root is always safe
    };

    if current == id {
        return Ok(true); // direct self-parenting
    }

    for _ in 0..MAX_TREE_DEPTH {
        let maybe_parent: Option<Option<i64>> = conn
            .query_row(
                "SELECT parent_id FROM groups WHERE id = ?1",
                [current.get()],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_err)?;

        match maybe_parent {
            None => return Ok(false),       // current doesn't exist → no cycle
            Some(None) => return Ok(false), // reached root
            Some(Some(p)) => {
                current = GroupId::new(p);
                if current == id {
                    return Ok(true);
                }
            }
        }
    }

    // Exceeded depth — treat as cycle for safety.
    Ok(true)
}

/// Returns `true` if making `id` a child of `proposed_parent` would create a
/// cycle in the credential-folder tree.
fn would_create_folder_cycle(
    conn: &rusqlite::Connection,
    id: CredentialFolderId,
    proposed_parent: Option<CredentialFolderId>,
) -> Result<bool, RepositoryError> {
    let Some(mut current) = proposed_parent else {
        return Ok(false);
    };

    if current == id {
        return Ok(true);
    }

    for _ in 0..MAX_TREE_DEPTH {
        let maybe_parent: Option<Option<i64>> = conn
            .query_row(
                "SELECT parent_id FROM credential_folders WHERE id = ?1",
                [current.get()],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_err)?;

        match maybe_parent {
            None => return Ok(false),
            Some(None) => return Ok(false),
            Some(Some(p)) => {
                current = CredentialFolderId::new(p);
                if current == id {
                    return Ok(true);
                }
            }
        }
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a group + connection + credential + setting to a file-backed DB,
    /// drop the repository, reopen the same file, and assert all data is still
    /// present.
    #[test]
    fn file_backed_persistence_round_trip() {
        use cm_core::{
            Connection, ConnectionId, ConnectionKind, ConnectionSettings, Credential, CredentialId,
            CredentialKind, Group, GroupId, SshAuthMethod, SshSettings,
        };

        let dir = tempfile::tempdir().expect("tmp dir");
        let db_path = dir.path().join("test.sqlite");

        let now: i64 = 1_700_000_000;

        // ── First open: write data ─────────────────────────────────────────
        {
            let repo = SqliteRepository::open(&db_path).expect("open");

            let gid = repo
                .upsert_group(&Group {
                    id: GroupId::UNSAVED,
                    parent_id: None,
                    name: "persist-group".to_owned(),
                    sort: 0,
                    default_credential: None,
                })
                .expect("upsert group");

            let cred_id = repo
                .upsert_credential(&Credential {
                    id: CredentialId::UNSAVED,
                    folder_id: None,
                    name: "persist-cred".to_owned(),
                    kind: CredentialKind::Password,
                    username: Some("alice".to_owned()),
                })
                .expect("upsert credential");

            let conn = Connection::new(
                ConnectionId::UNSAVED,
                Some(gid),
                "persist-conn".to_owned(),
                ConnectionKind::Ssh,
                ConnectionSettings::Ssh(SshSettings {
                    host: "10.0.0.1".to_owned(),
                    port: 22,
                    username: "alice".to_owned(),
                    auth_method: SshAuthMethod::Password,
                }),
                Some(cred_id),
                0,
                now,
                now,
            )
            .expect("build connection");
            repo.upsert_connection(&conn).expect("upsert connection");

            repo.set_setting("persist-key", "persist-value")
                .expect("set setting");
        } // repo dropped here — connection closed

        // ── Second open: verify data survives ─────────────────────────────
        {
            let repo = SqliteRepository::open(&db_path).expect("reopen");

            let groups = repo.list_groups().expect("list groups");
            assert_eq!(groups.len(), 1, "group count");
            assert_eq!(groups[0].name, "persist-group");

            let conns = repo.list_connections().expect("list connections");
            assert_eq!(conns.len(), 1, "connection count");
            assert_eq!(conns[0].name, "persist-conn");

            let creds = repo.list_credentials().expect("list credentials");
            assert_eq!(creds.len(), 1, "credential count");
            assert_eq!(creds[0].name, "persist-cred");

            let val = repo
                .get_setting("persist-key")
                .expect("get setting")
                .expect("setting present");
            assert_eq!(val, "persist-value");
        }
    }

    // ── P6.14: recents ───────────────────────────────────────────────────

    fn mk_local_conn(repo: &SqliteRepository, name: &str) -> ConnectionId {
        use cm_core::{Connection, ConnectionKind, ConnectionSettings, LocalSettings};
        let conn = Connection::new(
            ConnectionId::UNSAVED,
            None,
            name.to_owned(),
            ConnectionKind::LocalTerminal,
            ConnectionSettings::Local(LocalSettings::default()),
            None,
            0,
            0,
            0,
        )
        .expect("build connection");
        repo.upsert_connection(&conn).expect("upsert connection")
    }

    #[test]
    fn list_recents_orders_most_recent_first() {
        let repo = SqliteRepository::open_in_memory().expect("open");
        let a = mk_local_conn(&repo, "a");
        let b = mk_local_conn(&repo, "b");
        let c = mk_local_conn(&repo, "c");

        repo.record_recent(a, 100).expect("record a");
        repo.record_recent(b, 300).expect("record b");
        repo.record_recent(c, 200).expect("record c");

        let recents = repo.list_recents(10).expect("list recents");
        assert_eq!(recents, vec![(b, 300), (c, 200), (a, 100)]);
    }

    #[test]
    fn record_recent_replaces_earlier_timestamp_not_duplicates() {
        let repo = SqliteRepository::open_in_memory().expect("open");
        let a = mk_local_conn(&repo, "a");

        repo.record_recent(a, 100).expect("record a first");
        repo.record_recent(a, 500).expect("record a again");

        let recents = repo.list_recents(10).expect("list recents");
        assert_eq!(recents, vec![(a, 500)], "one row, latest timestamp wins");
    }

    #[test]
    fn list_recents_respects_limit() {
        let repo = SqliteRepository::open_in_memory().expect("open");
        for i in 0..5 {
            let id = mk_local_conn(&repo, &format!("c{i}"));
            repo.record_recent(id, i64::from(i)).expect("record");
        }
        let recents = repo.list_recents(2).expect("list recents");
        assert_eq!(recents.len(), 2);
    }

    #[test]
    fn deleting_a_connection_removes_its_recents_row() {
        let repo = SqliteRepository::open_in_memory().expect("open");
        let a = mk_local_conn(&repo, "a");
        repo.record_recent(a, 100).expect("record a");
        repo.delete_connection(a).expect("delete connection");
        let recents = repo.list_recents(10).expect("list recents");
        assert!(recents.is_empty(), "cascade-deleted recents row");
    }
}

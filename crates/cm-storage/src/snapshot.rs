//! Bounded, transactionally coherent workspace reads.
use std::{mem::size_of, str};

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionSettings, Credential, CredentialFolder,
    CredentialFolderId, CredentialId, CredentialKind, CredentialPurpose, CredentialRef,
    CredentialSource, Group, GroupId, MAX_WORKSPACE_RECORDS, MAX_WORKSPACE_ROW_DECODE_BYTES,
    RepositoryError, SshAuthMethod, WorkspaceDto, WorkspaceRecordCounts, WorkspaceResultOverhead,
    WorkspaceRevision, WorkspaceSnapshotBuilder,
};
use rusqlite::{Row, TransactionBehavior, types::ValueRef};

use crate::repository::SqliteRepository;

const MAX_TEXT_CELL_BYTES: usize = 256 * 1024;
const MAX_SETTINGS_JSON_BYTES: usize = 128 * 1024;
const MAX_SNAPSHOT_SOURCE_BYTES: usize = 16 * 1024 * 1024;

const CONNECTION_SELECT: &str = "SELECT id, group_id, kind, name, settings_json, credential_id, cred_source_kind, inline_username, inline_domain, inline_has_secret, sort, created_at, updated_at FROM connections ORDER BY group_id, sort, id";
const GROUP_SELECT: &str = "SELECT id, parent_id, name, sort, default_credential_id FROM groups ORDER BY parent_id, sort, id";
const CREDENTIAL_SELECT: &str =
    "SELECT id, folder_id, name, kind, username FROM credentials ORDER BY folder_id, id";
const FOLDER_SELECT: &str =
    "SELECT id, parent_id, name, sort FROM credential_folders ORDER BY parent_id, sort, id";

const CONNECTION_TEXT_SUM: &str = "COALESCE(length(CAST(kind AS BLOB)),0)+COALESCE(length(CAST(name AS BLOB)),0)+COALESCE(length(CAST(host AS BLOB)),0)+COALESCE(length(CAST(settings_json AS BLOB)),0)+COALESCE(length(CAST(cred_source_kind AS BLOB)),0)+COALESCE(length(CAST(inline_username AS BLOB)),0)+COALESCE(length(CAST(inline_domain AS BLOB)),0)";
const GROUP_TEXT_SUM: &str = "COALESCE(length(CAST(name AS BLOB)),0)";
const CREDENTIAL_TEXT_SUM: &str = "COALESCE(length(CAST(name AS BLOB)),0)+COALESCE(length(CAST(kind AS BLOB)),0)+COALESCE(length(CAST(username AS BLOB)),0)";
const FOLDER_TEXT_SUM: &str = "COALESCE(length(CAST(name AS BLOB)),0)";

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceSnapshotError {
    #[error("workspace snapshot exceeds its resource limits")]
    ResourceLimit,
    #[error(transparent)]
    Persistence(#[from] RepositoryError),
}

impl SqliteRepository {
    /// Reads all workspace tables from one SQLite snapshot, validating source
    /// sizes before allocating typed rows. No partial result escapes on error.
    pub fn load_workspace_snapshot(
        &self,
        revision: WorkspaceRevision,
        overhead: WorkspaceResultOverhead<'_>,
    ) -> Result<WorkspaceDto, WorkspaceSnapshotError> {
        self.load_workspace_snapshot_with(revision, overhead, || {})
    }

    fn load_workspace_snapshot_with<F>(
        &self,
        revision: WorkspaceRevision,
        overhead: WorkspaceResultOverhead<'_>,
        after_preflight: F,
    ) -> Result<WorkspaceDto, WorkspaceSnapshotError>
    where
        F: FnOnce(),
    {
        let mut conn = self.lock().map_err(WorkspaceSnapshotError::Persistence)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sql_error)?;

        // The first COUNT establishes the SQLite read snapshot. Every size
        // preflight and every later table scan remains on this version.
        let counts = WorkspaceRecordCounts {
            connections: read_count(&tx, "connections")?,
            groups: read_count(&tx, "groups")?,
            credentials: read_count(&tx, "credentials")?,
            credential_folders: read_count(&tx, "credential_folders")?,
        };
        preflight_source_sizes(&tx)?;

        let mut builder = WorkspaceSnapshotBuilder::new(revision, counts, overhead)
            .map_err(|_| WorkspaceSnapshotError::ResourceLimit)?;
        after_preflight();

        let seen_connections = read_connections(&tx, &mut builder, counts.connections)?;
        let seen_groups = read_groups(&tx, &mut builder, counts.groups)?;
        let seen_credentials = read_credentials(&tx, &mut builder, counts.credentials)?;
        let seen_folders = read_folders(&tx, &mut builder, counts.credential_folders)?;
        if seen_connections != counts.connections
            || seen_groups != counts.groups
            || seen_credentials != counts.credentials
            || seen_folders != counts.credential_folders
        {
            return Err(persistence(
                "workspace row count changed inside read snapshot",
            ));
        }

        let snapshot = builder
            .finish()
            .map_err(|_| WorkspaceSnapshotError::ResourceLimit)?;
        tx.commit().map_err(sql_error)?;
        Ok(snapshot)
    }
}

fn read_count(
    tx: &rusqlite::Transaction<'_>,
    table: &'static str,
) -> Result<usize, WorkspaceSnapshotError> {
    let sql = match table {
        "connections" => "SELECT COUNT(*) FROM connections",
        "groups" => "SELECT COUNT(*) FROM groups",
        "credentials" => "SELECT COUNT(*) FROM credentials",
        "credential_folders" => "SELECT COUNT(*) FROM credential_folders",
        _ => unreachable!("table names are static"),
    };
    let count: i64 = tx.query_row(sql, [], |row| row.get(0)).map_err(sql_error)?;
    if count < 0 {
        return Err(persistence(format!("{table} count is negative")));
    }
    let count = usize::try_from(count).map_err(|_| WorkspaceSnapshotError::ResourceLimit)?;
    if count > MAX_WORKSPACE_RECORDS {
        return Err(WorkspaceSnapshotError::ResourceLimit);
    }
    Ok(count)
}

fn preflight_source_sizes(tx: &rusqlite::Transaction<'_>) -> Result<(), WorkspaceSnapshotError> {
    let summaries = [
        ("connections", "SELECT COALESCE(MAX(MAX(COALESCE(length(CAST(kind AS BLOB)),0),COALESCE(length(CAST(name AS BLOB)),0),COALESCE(length(CAST(host AS BLOB)),0),COALESCE(length(CAST(settings_json AS BLOB)),0),COALESCE(length(CAST(cred_source_kind AS BLOB)),0),COALESCE(length(CAST(inline_username AS BLOB)),0),COALESCE(length(CAST(inline_domain AS BLOB)),0))),0), COALESCE(MAX(length(CAST(settings_json AS BLOB))),0), COALESCE(SUM(".to_owned() + CONNECTION_TEXT_SUM + "),0) FROM connections"),
        ("groups", format!("SELECT COALESCE(MAX(COALESCE(length(CAST(name AS BLOB)),0)),0), 0, COALESCE(SUM({GROUP_TEXT_SUM}),0) FROM groups")),
        ("credentials", format!("SELECT COALESCE(MAX(MAX(COALESCE(length(CAST(name AS BLOB)),0),COALESCE(length(CAST(kind AS BLOB)),0),COALESCE(length(CAST(username AS BLOB)),0))),0), 0, COALESCE(SUM({CREDENTIAL_TEXT_SUM}),0) FROM credentials")),
        ("credential_folders", format!("SELECT COALESCE(MAX(COALESCE(length(CAST(name AS BLOB)),0)),0), 0, COALESCE(SUM({FOLDER_TEXT_SUM}),0) FROM credential_folders")),
    ];
    let mut source_total: i64 = 0;
    for (table, sql) in summaries {
        let (max_cell, max_settings, table_bytes): (i64, i64, i64) = tx
            .query_row(&sql, [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(sql_error)?;
        if max_cell < 0 || max_settings < 0 || table_bytes < 0 {
            return Err(persistence(format!("{table} size preflight is negative")));
        }
        if max_cell as usize > MAX_TEXT_CELL_BYTES
            || (table == "connections" && max_settings as usize > MAX_SETTINGS_JSON_BYTES)
        {
            return Err(WorkspaceSnapshotError::ResourceLimit);
        }
        source_total = source_total
            .checked_add(table_bytes)
            .ok_or(WorkspaceSnapshotError::ResourceLimit)?;
    }

    // A scalar query independently totals all text source bytes in the same
    // transaction. It returns no row payload to Rust.
    let global: i64 = tx
        .query_row(
            &format!(
                "SELECT (SELECT COALESCE(SUM({CONNECTION_TEXT_SUM}),0) FROM connections) + \
                 (SELECT COALESCE(SUM({GROUP_TEXT_SUM}),0) FROM groups) + \
                 (SELECT COALESCE(SUM({CREDENTIAL_TEXT_SUM}),0) FROM credentials) + \
                 (SELECT COALESCE(SUM({FOLDER_TEXT_SUM}),0) FROM credential_folders)"
            ),
            [],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    if global < 0 || global != source_total {
        return Err(persistence("workspace source-size preflight mismatch"));
    }
    if global as u64 > MAX_SNAPSHOT_SOURCE_BYTES as u64 {
        return Err(WorkspaceSnapshotError::ResourceLimit);
    }
    Ok(())
}

fn read_connections(
    tx: &rusqlite::Transaction<'_>,
    builder: &mut WorkspaceSnapshotBuilder<'_>,
    expected: usize,
) -> Result<usize, WorkspaceSnapshotError> {
    let mut statement = tx.prepare(CONNECTION_SELECT).map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut count = 0usize;
    while let Some(row) = rows.next().map_err(sql_error)? {
        if count >= expected {
            return Err(persistence("connections count/list mismatch"));
        }
        let id_raw: i64 = row.get(0).map_err(sql_error)?;
        let id = ConnectionId::new(id_raw);
        let group_id: Option<i64> = row.get(1).map_err(sql_error)?;
        let kind_tag = required_text(row, 2, "kind", id_raw, MAX_TEXT_CELL_BYTES)?;
        let kind = parse_connection_kind(kind_tag)
            .ok_or_else(|| row_persistence("connections", "kind", id_raw, "unknown stored tag"))?;
        let name = required_text(row, 3, "name", id_raw, MAX_TEXT_CELL_BYTES)?;
        let settings_json =
            required_text(row, 4, "settings_json", id_raw, MAX_SETTINGS_JSON_BYTES)?;
        let credential_id: Option<i64> = row.get(5).map_err(sql_error)?;
        let source_tag = required_text(row, 6, "cred_source_kind", id_raw, MAX_TEXT_CELL_BYTES)?;
        let inline_username = optional_text(row, 7, "inline_username", id_raw)?;
        let inline_domain = optional_text(row, 8, "inline_domain", id_raw)?;
        let inline_has_secret: i64 = row.get(9).map_err(sql_error)?;
        let sort: i64 = row.get(10).map_err(sql_error)?;
        let created_at: i64 = row.get(11).map_err(sql_error)?;
        let updated_at: i64 = row.get(12).map_err(sql_error)?;

        if inline_has_secret != 0 && inline_has_secret != 1 {
            return Err(row_persistence(
                "connections",
                "inline_has_secret",
                id_raw,
                "expected 0 or 1",
            ));
        }
        let retained_bytes = name
            .len()
            .checked_add(inline_username.map_or(0, str::len))
            .and_then(|n| n.checked_add(inline_domain.map_or(0, str::len)))
            .ok_or(WorkspaceSnapshotError::ResourceLimit)?;
        let (scratch_bound, destination_bound) =
            connection_bounds(settings_json.len(), retained_bytes)?;
        let permit = builder
            .reserve_connection_decode(scratch_bound, destination_bound)
            .map_err(|_| WorkspaceSnapshotError::ResourceLimit)?;

        let mut deserializer = serde_json::Deserializer::from_slice(settings_json.as_bytes());
        let settings = <ConnectionSettings as serde::Deserialize>::deserialize(&mut deserializer)
            .map_err(|_| {
            row_persistence("connections", "settings_json", id_raw, "invalid settings")
        })?;
        deserializer.end().map_err(|_| {
            row_persistence(
                "connections",
                "settings_json",
                id_raw,
                "invalid trailing data",
            )
        })?;
        if settings.kind() != kind {
            return Err(row_persistence(
                "connections",
                "settings_json",
                id_raw,
                "settings kind mismatch",
            ));
        }
        validate_public_key_ref(&settings, id_raw)?;

        let credential_source = match source_tag {
            "inherit" => None,
            "object" => credential_id.map(|id| CredentialSource::Object(CredentialId::new(id))),
            "inline" => Some(CredentialSource::Inline {
                username: owned_text(inline_username.unwrap_or_default())?,
                domain: inline_domain.map(owned_text).transpose()?,
                has_secret: inline_has_secret == 1,
            }),
            "prompt" => Some(CredentialSource::Prompt),
            _ => {
                return Err(row_persistence(
                    "connections",
                    "cred_source_kind",
                    id_raw,
                    "unknown stored tag",
                ));
            }
        };
        let value = Connection::new(
            id,
            group_id.map(GroupId::new),
            owned_text(name)?,
            kind,
            settings,
            credential_source,
            sort,
            created_at,
            updated_at,
        )
        .map_err(|_| {
            row_persistence("connections", "settings_json", id_raw, "invalid connection")
        })?;
        permit
            .push_connection(value)
            .map_err(|_| WorkspaceSnapshotError::ResourceLimit)?;
        count += 1;
    }
    Ok(count)
}

fn read_groups(
    tx: &rusqlite::Transaction<'_>,
    builder: &mut WorkspaceSnapshotBuilder<'_>,
    expected: usize,
) -> Result<usize, WorkspaceSnapshotError> {
    let mut statement = tx.prepare(GROUP_SELECT).map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut count = 0usize;
    while let Some(row) = rows.next().map_err(sql_error)? {
        if count >= expected {
            return Err(persistence("groups count/list mismatch"));
        }
        let id: i64 = row.get(0).map_err(sql_error)?;
        let parent: Option<i64> = row.get(1).map_err(sql_error)?;
        let name = required_text(row, 2, "name", id, MAX_TEXT_CELL_BYTES)?;
        let upper = row_text_bound(name.len())?;
        let permit = builder
            .reserve_group(upper)
            .map_err(|_| WorkspaceSnapshotError::ResourceLimit)?;
        let value = Group {
            id: GroupId::new(id),
            parent_id: parent.map(GroupId::new),
            name: owned_text(name)?,
            sort: row.get(3).map_err(sql_error)?,
            default_credential: row
                .get::<_, Option<i64>>(4)
                .map_err(sql_error)?
                .map(CredentialId::new),
        };
        permit
            .push_group(value)
            .map_err(|_| WorkspaceSnapshotError::ResourceLimit)?;
        count += 1;
    }
    Ok(count)
}

fn read_credentials(
    tx: &rusqlite::Transaction<'_>,
    builder: &mut WorkspaceSnapshotBuilder<'_>,
    expected: usize,
) -> Result<usize, WorkspaceSnapshotError> {
    let mut statement = tx.prepare(CREDENTIAL_SELECT).map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut count = 0usize;
    while let Some(row) = rows.next().map_err(sql_error)? {
        if count >= expected {
            return Err(persistence("credentials count/list mismatch"));
        }
        let id: i64 = row.get(0).map_err(sql_error)?;
        let folder: Option<i64> = row.get(1).map_err(sql_error)?;
        let name = required_text(row, 2, "name", id, MAX_TEXT_CELL_BYTES)?;
        let kind_tag = required_text(row, 3, "kind", id, MAX_TEXT_CELL_BYTES)?;
        let kind = parse_credential_kind(kind_tag)
            .ok_or_else(|| row_persistence("credentials", "kind", id, "unknown stored tag"))?;
        let username = optional_text(row, 4, "username", id)?;
        let upper = row_text_bound(
            name.len()
                .checked_add(username.map_or(0, str::len))
                .ok_or(WorkspaceSnapshotError::ResourceLimit)?,
        )?;
        let permit = builder
            .reserve_credential(upper)
            .map_err(|_| WorkspaceSnapshotError::ResourceLimit)?;
        let value = Credential {
            id: CredentialId::new(id),
            name: owned_text(name)?,
            kind,
            folder_id: folder.map(CredentialFolderId::new),
            username: username.map(owned_text).transpose()?,
        };
        permit
            .push_credential(value)
            .map_err(|_| WorkspaceSnapshotError::ResourceLimit)?;
        count += 1;
    }
    Ok(count)
}

fn read_folders(
    tx: &rusqlite::Transaction<'_>,
    builder: &mut WorkspaceSnapshotBuilder<'_>,
    expected: usize,
) -> Result<usize, WorkspaceSnapshotError> {
    let mut statement = tx.prepare(FOLDER_SELECT).map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut count = 0usize;
    while let Some(row) = rows.next().map_err(sql_error)? {
        if count >= expected {
            return Err(persistence("credential_folders count/list mismatch"));
        }
        let id: i64 = row.get(0).map_err(sql_error)?;
        let parent: Option<i64> = row.get(1).map_err(sql_error)?;
        let name = required_text(row, 2, "name", id, MAX_TEXT_CELL_BYTES)?;
        let permit = builder
            .reserve_credential_folder(row_text_bound(name.len())?)
            .map_err(|_| WorkspaceSnapshotError::ResourceLimit)?;
        let value = CredentialFolder {
            id: CredentialFolderId::new(id),
            parent_id: parent.map(CredentialFolderId::new),
            name: owned_text(name)?,
            sort: row.get(3).map_err(sql_error)?,
        };
        permit
            .push_credential_folder(value)
            .map_err(|_| WorkspaceSnapshotError::ResourceLimit)?;
        count += 1;
    }
    Ok(count)
}

fn row_text_bound(source_bytes: usize) -> Result<usize, WorkspaceSnapshotError> {
    // String allocations are constructed from borrowed source slices using
    // try_reserve_exact; retain extra headroom for a reported allocator cap.
    source_bytes
        .checked_add(size_of::<String>())
        .and_then(|n| n.checked_add(64))
        .ok_or(WorkspaceSnapshotError::ResourceLimit)
}

fn connection_bounds(
    settings_bytes: usize,
    retained_row_bytes: usize,
) -> Result<(usize, usize), WorkspaceSnapshotError> {
    if settings_bytes > MAX_SETTINGS_JSON_BYTES || retained_row_bytes > 3 * MAX_TEXT_CELL_BYTES {
        return Err(WorkspaceSnapshotError::ResourceLimit);
    }
    let args = settings_bytes
        .checked_add(1)
        .ok_or(WorkspaceSnapshotError::ResourceLimit)?
        / 3;
    let env = settings_bytes
        .checked_add(1)
        .ok_or(WorkspaceSnapshotError::ResourceLimit)?
        / 8;
    let args_capacity_peak = args
        .checked_mul(3)
        .ok_or(WorkspaceSnapshotError::ResourceLimit)?
        .max(4)
        .checked_mul(size_of::<String>())
        .ok_or(WorkspaceSnapshotError::ResourceLimit)?;
    let env_capacity_peak = env
        .checked_mul(3)
        .ok_or(WorkspaceSnapshotError::ResourceLimit)?
        .max(4)
        .checked_mul(size_of::<(String, String)>())
        .ok_or(WorkspaceSnapshotError::ResourceLimit)?;
    let scratch_bytes = args_capacity_peak
        .checked_add(env_capacity_peak)
        .and_then(|n| n.checked_add(settings_bytes))
        .and_then(|n| n.checked_add(settings_bytes.saturating_mul(3)))
        .and_then(|n| n.checked_add(retained_row_bytes))
        .and_then(|n| n.checked_add(8 * 1024))
        .ok_or(WorkspaceSnapshotError::ResourceLimit)?;
    if scratch_bytes > MAX_WORKSPACE_ROW_DECODE_BYTES {
        return Err(WorkspaceSnapshotError::ResourceLimit);
    }

    let args_final = args
        .checked_mul(2)
        .ok_or(WorkspaceSnapshotError::ResourceLimit)?
        .max(4)
        .checked_mul(size_of::<String>())
        .ok_or(WorkspaceSnapshotError::ResourceLimit)?;
    let env_final = env
        .checked_mul(2)
        .ok_or(WorkspaceSnapshotError::ResourceLimit)?
        .max(4)
        .checked_mul(size_of::<(String, String)>())
        .ok_or(WorkspaceSnapshotError::ResourceLimit)?;
    let destination_bytes = args_final
        .checked_add(env_final)
        .and_then(|n| n.checked_add(settings_bytes))
        .and_then(|n| n.checked_add(retained_row_bytes))
        .and_then(|n| n.checked_add(8 * 1024))
        .ok_or(WorkspaceSnapshotError::ResourceLimit)?;
    Ok((scratch_bytes, destination_bytes))
}

fn required_text<'r>(
    row: &'r Row<'_>,
    index: usize,
    column: &'static str,
    id: i64,
    max_bytes: usize,
) -> Result<&'r str, WorkspaceSnapshotError> {
    let bytes = match row.get_ref(index).map_err(sql_error)? {
        ValueRef::Text(bytes) => bytes,
        _ => return Err(row_persistence("row", column, id, "expected text")),
    };
    if bytes.len() > max_bytes {
        return Err(WorkspaceSnapshotError::ResourceLimit);
    }
    str::from_utf8(bytes).map_err(|_| row_persistence("row", column, id, "invalid UTF-8"))
}

fn optional_text<'r>(
    row: &'r Row<'_>,
    index: usize,
    column: &'static str,
    id: i64,
) -> Result<Option<&'r str>, WorkspaceSnapshotError> {
    match row.get_ref(index).map_err(sql_error)? {
        ValueRef::Null => Ok(None),
        ValueRef::Text(bytes) => {
            if bytes.len() > MAX_TEXT_CELL_BYTES {
                return Err(WorkspaceSnapshotError::ResourceLimit);
            }
            str::from_utf8(bytes)
                .map(Some)
                .map_err(|_| row_persistence("row", column, id, "invalid UTF-8"))
        }
        _ => Err(row_persistence("row", column, id, "expected text or NULL")),
    }
}

fn owned_text(value: &str) -> Result<String, WorkspaceSnapshotError> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| WorkspaceSnapshotError::ResourceLimit)?;
    owned.push_str(value);
    Ok(owned)
}

fn parse_connection_kind(value: &str) -> Option<ConnectionKind> {
    match value {
        "rdp" => Some(ConnectionKind::Rdp),
        "ssh" => Some(ConnectionKind::Ssh),
        "telnet" => Some(ConnectionKind::Telnet),
        "local" => Some(ConnectionKind::LocalTerminal),
        _ => None,
    }
}

fn parse_credential_kind(value: &str) -> Option<CredentialKind> {
    match value {
        "password" => Some(CredentialKind::Password),
        "ssh-key" => Some(CredentialKind::SshKey),
        "ssh-key-with-passphrase" => Some(CredentialKind::SshKeyWithPassphrase),
        _ => None,
    }
}

fn validate_public_key_ref(
    settings: &ConnectionSettings,
    id: i64,
) -> Result<(), WorkspaceSnapshotError> {
    let ConnectionSettings::Ssh(settings) = settings else {
        return Ok(());
    };
    let SshAuthMethod::PublicKey { key_ref } = &settings.auth_method else {
        return Ok(());
    };
    let mut components = key_ref.account().split(':');
    let owner = components.next();
    let entity_id = components
        .next()
        .and_then(|value| value.parse::<i64>().ok());
    let purpose = components.next();
    if key_ref.service() != CredentialRef::SERVICE
        || owner != Some("cred")
        || entity_id.is_none_or(|value| value <= 0)
        || purpose != Some(CredentialPurpose::SshKey.as_str())
        || components.next().is_some()
    {
        return Err(row_persistence(
            "connections",
            "settings_json",
            id,
            "invalid public-key credential reference",
        ));
    }
    Ok(())
}

fn sql_error(error: rusqlite::Error) -> WorkspaceSnapshotError {
    WorkspaceSnapshotError::Persistence(RepositoryError::Backend(error.to_string()))
}

fn persistence(message: impl Into<String>) -> WorkspaceSnapshotError {
    WorkspaceSnapshotError::Persistence(RepositoryError::Backend(message.into()))
}

fn row_persistence(
    table: &'static str,
    column: &'static str,
    id: i64,
    reason: &'static str,
) -> WorkspaceSnapshotError {
    persistence(format!("{table} row {id} column {column}: {reason}"))
}

#[cfg(test)]
mod tests {
    use cm_core::{ConnectionRepository, ConnectionSettings, LocalSettings, WorkspaceRevision};
    use rusqlite::Connection as SqliteConnection;
    use rusqlite::params;
    use tempfile::TempDir;

    use super::*;
    use crate::SqliteRepository;

    fn workspace() -> Result<WorkspaceDto, WorkspaceSnapshotError> {
        let repository = SqliteRepository::open_in_memory().unwrap();
        repository.load_workspace_snapshot(WorkspaceRevision(1), WorkspaceResultOverhead::Workspace)
    }

    fn settings_json(settings: &ConnectionSettings) -> String {
        serde_json::to_string(settings).unwrap()
    }

    fn insert_base_connection(conn: &SqliteConnection, kind: &str, json: &str) {
        conn.execute(
            "INSERT INTO connections(kind, name, settings_json) VALUES (?1, 'sample', ?2)",
            params![kind, json],
        )
        .unwrap();
    }

    #[test]
    fn empty_snapshot_and_revision_are_exact() {
        let snapshot = workspace().unwrap();
        assert_eq!(snapshot.revision, WorkspaceRevision(1));
        assert!(snapshot.connections.is_empty());
        assert!(snapshot.groups.is_empty());
        assert!(snapshot.credentials.is_empty());
        assert!(snapshot.credential_folders.is_empty());
    }

    #[test]
    fn snapshot_preserves_native_local_fields() {
        let repository = SqliteRepository::open_in_memory().unwrap();
        let value = Connection::new(
            ConnectionId::UNSAVED,
            None,
            "local profile".into(),
            ConnectionKind::LocalTerminal,
            ConnectionSettings::Local(LocalSettings {
                program: Some("/usr/bin/fish".into()),
                args: vec!["--login".into()],
                working_dir: Some("/tmp/work".into()),
                env: vec![("TERM".into(), "xterm-256color".into())],
            }),
            None,
            0,
            1,
            1,
        )
        .unwrap();
        repository.upsert_connection(&value).unwrap();
        let snapshot = repository
            .load_workspace_snapshot(WorkspaceRevision(2), WorkspaceResultOverhead::Workspace)
            .unwrap();
        assert_eq!(snapshot.connections[0].settings, value.settings);
    }

    #[test]
    fn snapshot_orders_each_table_by_its_persisted_list_key() {
        let repository = SqliteRepository::open_in_memory().unwrap();
        {
            let conn = repository.lock().unwrap();
            conn.execute_batch(
                "INSERT INTO groups(id,parent_id,name,sort) VALUES
                    (10,NULL,'g10',2),(20,NULL,'g20',1),(30,10,'g30',0);
                 INSERT INTO credential_folders(id,parent_id,name,sort) VALUES
                    (10,NULL,'f10',2),(20,NULL,'f20',1),(30,10,'f30',0);
                 INSERT INTO credentials(id,folder_id,name,kind) VALUES
                    (10,NULL,'c10','password'),(20,NULL,'c20','password'),
                    (30,10,'c30','password');
                 INSERT INTO connections(id,group_id,kind,name,settings_json,sort) VALUES
                    (10,10,'local','a','{\"local\":{\"program\":null,\"args\":[],\"working_dir\":null,\"env\":[]}}',2),
                    (20,10,'local','b','{\"local\":{\"program\":null,\"args\":[],\"working_dir\":null,\"env\":[]}}',1),
                    (30,20,'local','c','{\"local\":{\"program\":null,\"args\":[],\"working_dir\":null,\"env\":[]}}',0);",
            )
            .unwrap();
        }
        let snapshot = repository
            .load_workspace_snapshot(WorkspaceRevision(0), WorkspaceResultOverhead::Workspace)
            .unwrap();
        assert_eq!(
            snapshot
                .connections
                .iter()
                .map(|row| row.id.get())
                .collect::<Vec<_>>(),
            [20, 10, 30]
        );
        assert_eq!(
            snapshot
                .groups
                .iter()
                .map(|row| row.id.get())
                .collect::<Vec<_>>(),
            [20, 10, 30]
        );
        assert_eq!(
            snapshot
                .credentials
                .iter()
                .map(|row| row.id.get())
                .collect::<Vec<_>>(),
            [10, 20, 30]
        );
        assert_eq!(
            snapshot
                .credential_folders
                .iter()
                .map(|row| row.id.get())
                .collect::<Vec<_>>(),
            [20, 10, 30]
        );
    }

    #[test]
    fn preflight_rejects_settings_cell_over_128_kib_before_rows() {
        let repository = SqliteRepository::open_in_memory().unwrap();
        let conn = repository.lock().unwrap();
        let huge = format!(
            "{{\"local\":{{\"program\":\"{}\"}}}}",
            "x".repeat(MAX_SETTINGS_JSON_BYTES)
        );
        insert_base_connection(&conn, "local", &huge);
        drop(conn);
        assert!(matches!(
            repository
                .load_workspace_snapshot(WorkspaceRevision(0), WorkspaceResultOverhead::Workspace),
            Err(WorkspaceSnapshotError::ResourceLimit)
        ));
    }

    #[test]
    fn preflight_rejects_metadata_cell_over_256_kib_before_rows() {
        let repository = SqliteRepository::open_in_memory().unwrap();
        {
            let conn = repository.lock().unwrap();
            let name = "x".repeat(MAX_TEXT_CELL_BYTES + 1);
            conn.execute("INSERT INTO groups(name) VALUES (?1)", [name])
                .unwrap();
        }
        assert!(matches!(
            repository
                .load_workspace_snapshot(WorkspaceRevision(0), WorkspaceResultOverhead::Workspace),
            Err(WorkspaceSnapshotError::ResourceLimit)
        ));
    }

    #[test]
    fn malformed_settings_and_kind_mismatch_are_persistence_errors() {
        let repository = SqliteRepository::open_in_memory().unwrap();
        {
            let conn = repository.lock().unwrap();
            insert_base_connection(&conn, "ssh", "{broken");
        }
        assert!(matches!(
            repository
                .load_workspace_snapshot(WorkspaceRevision(0), WorkspaceResultOverhead::Workspace),
            Err(WorkspaceSnapshotError::Persistence(_))
        ));

        let repository = SqliteRepository::open_in_memory().unwrap();
        {
            let conn = repository.lock().unwrap();
            insert_base_connection(
                &conn,
                "ssh",
                &settings_json(&ConnectionSettings::Local(LocalSettings::default())),
            );
        }
        assert!(matches!(
            repository
                .load_workspace_snapshot(WorkspaceRevision(0), WorkspaceResultOverhead::Workspace),
            Err(WorkspaceSnapshotError::Persistence(_))
        ));
    }

    fn fill_one_table(conn: &SqliteConnection, table: &str, count: usize) {
        match table {
            "connections" => {
                let json = settings_json(&ConnectionSettings::Local(LocalSettings::default()));
                let mut statement = conn
                    .prepare("INSERT INTO connections(kind, name, settings_json) VALUES ('local', 'x', ?1)")
                    .unwrap();
                for _ in 0..count {
                    statement.execute([&json]).unwrap();
                }
            }
            "groups" => {
                let mut statement = conn
                    .prepare("INSERT INTO groups(name) VALUES ('x')")
                    .unwrap();
                for _ in 0..count {
                    statement.execute([]).unwrap();
                }
            }
            "credentials" => {
                let mut statement = conn
                    .prepare("INSERT INTO credentials(name, kind) VALUES ('x','password')")
                    .unwrap();
                for _ in 0..count {
                    statement.execute([]).unwrap();
                }
            }
            "credential_folders" => {
                let mut statement = conn
                    .prepare("INSERT INTO credential_folders(name) VALUES ('x')")
                    .unwrap();
                for _ in 0..count {
                    statement.execute([]).unwrap();
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn each_table_accepts_4096_and_rejects_4097_rows() {
        for table in ["connections", "groups", "credentials", "credential_folders"] {
            let repository = SqliteRepository::open_in_memory().unwrap();
            {
                let conn = repository.lock().unwrap();
                fill_one_table(&conn, table, MAX_WORKSPACE_RECORDS);
            }
            let snapshot = repository
                .load_workspace_snapshot(WorkspaceRevision(0), WorkspaceResultOverhead::Workspace)
                .unwrap();
            match table {
                "connections" => assert_eq!(snapshot.connections.len(), MAX_WORKSPACE_RECORDS),
                "groups" => assert_eq!(snapshot.groups.len(), MAX_WORKSPACE_RECORDS),
                "credentials" => assert_eq!(snapshot.credentials.len(), MAX_WORKSPACE_RECORDS),
                "credential_folders" => {
                    assert_eq!(snapshot.credential_folders.len(), MAX_WORKSPACE_RECORDS)
                }
                _ => unreachable!(),
            }

            let repository = SqliteRepository::open_in_memory().unwrap();
            {
                let conn = repository.lock().unwrap();
                fill_one_table(&conn, table, MAX_WORKSPACE_RECORDS + 1);
            }
            assert!(matches!(
                repository.load_workspace_snapshot(
                    WorkspaceRevision(0),
                    WorkspaceResultOverhead::Workspace
                ),
                Err(WorkspaceSnapshotError::ResourceLimit)
            ));
        }
    }

    #[test]
    fn aggregate_source_text_limit_is_preflighted() {
        let repository = SqliteRepository::open_in_memory().unwrap();
        {
            let conn = repository.lock().unwrap();
            let text = "x".repeat(4097);
            let mut statement = conn
                .prepare("INSERT INTO credentials(name, kind) VALUES (?1, 'password')")
                .unwrap();
            for _ in 0..MAX_WORKSPACE_RECORDS {
                statement.execute([&text]).unwrap();
            }
        }
        assert!(matches!(
            repository
                .load_workspace_snapshot(WorkspaceRevision(0), WorkspaceResultOverhead::Workspace),
            Err(WorkspaceSnapshotError::ResourceLimit)
        ));
    }

    #[test]
    fn two_connection_wal_reader_keeps_one_snapshot_after_writer_commit() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("snapshot.sqlite");
        let repository = SqliteRepository::open(&path).unwrap();
        repository
            .upsert_connection(
                &Connection::new(
                    ConnectionId::UNSAVED,
                    None,
                    "before".into(),
                    ConnectionKind::LocalTerminal,
                    ConnectionSettings::Local(LocalSettings::default()),
                    None,
                    0,
                    0,
                    0,
                )
                .unwrap(),
            )
            .unwrap();
        let writer = SqliteConnection::open(&path).unwrap();
        let snapshot = repository
            .load_workspace_snapshot_with(
                WorkspaceRevision(0),
                WorkspaceResultOverhead::Workspace,
                || {
                    writer.execute(
                        "INSERT INTO connections(kind,name,settings_json) VALUES('local','after','{\"local\":{\"program\":null,\"args\":[],\"working_dir\":null,\"env\":[]}}')",
                        [],
                    ).unwrap();
                },
            )
            .unwrap();
        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(snapshot.connections[0].name, "before");
        assert_eq!(
            repository
                .load_workspace_snapshot(WorkspaceRevision(1), WorkspaceResultOverhead::Workspace)
                .unwrap()
                .connections
                .len(),
            2
        );
    }
}

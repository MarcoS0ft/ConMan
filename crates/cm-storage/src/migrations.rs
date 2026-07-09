use rusqlite::OptionalExtension as _;

use crate::error::StorageError;

/// Latest schema version this build understands.
pub const CURRENT_VERSION: u32 = 4;

/// Ordered migration scripts.  Index `i` upgrades from version `i` to `i+1`,
/// i.e. `MIGRATIONS[0]` is the v0→v1 script (the initial schema).
const MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("../migrations/v1.sql")),
    (2, include_str!("../migrations/v2.sql")),
    (3, include_str!("../migrations/v3.sql")),
    (4, include_str!("../migrations/v4.sql")),
];

/// Applies all pending migrations on `conn`.  Safe to call on a fresh (empty)
/// database as well as on any partially-migrated one.
///
/// Each migration is wrapped in an explicit transaction, so a mid-migration
/// crash leaves the database at the previous clean version.
pub fn run_migrations(conn: &mut rusqlite::Connection) -> Result<(), StorageError> {
    ensure_version_table(conn)?;
    let current = read_version(conn)?;
    tracing::info!(
        from_version = current,
        target_version = CURRENT_VERSION,
        "running DB migrations"
    );
    let applied = apply_from(conn, current)?;
    tracing::info!(
        target_version = CURRENT_VERSION,
        applied,
        "migrations complete"
    );
    Ok(())
}

/// **Test helper only** — set up a database at the requested `version` without
/// applying later migrations.  Useful for writing upgrade-path tests.
#[cfg(test)]
pub fn setup_db_at_version(
    conn: &mut rusqlite::Connection,
    target_version: u32,
) -> Result<(), StorageError> {
    ensure_version_table(conn)?;
    let current = read_version(conn)?;
    for &(v, sql) in MIGRATIONS {
        if v <= current || v > target_version {
            continue;
        }
        run_one_migration(conn, v, sql)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn ensure_version_table(conn: &rusqlite::Connection) -> Result<(), StorageError> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);")
        .map_err(|e| StorageError::Migration(format!("cannot create schema_version: {e}")))?;
    Ok(())
}

fn read_version(conn: &rusqlite::Connection) -> Result<u32, StorageError> {
    let v: Option<u32> = conn
        .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
        .optional()
        .map_err(|e| StorageError::Migration(format!("cannot read schema_version: {e}")))?;
    Ok(v.unwrap_or(0))
}

/// Applies every pending migration, returning the count applied (for the
/// "migrations complete" summary log).
fn apply_from(conn: &mut rusqlite::Connection, from: u32) -> Result<usize, StorageError> {
    let mut applied = 0usize;
    for &(target, sql) in MIGRATIONS {
        if target <= from {
            continue;
        }
        run_one_migration(conn, target, sql)?;
        applied += 1;
    }
    Ok(applied)
}

fn run_one_migration(
    conn: &mut rusqlite::Connection,
    target_version: u32,
    sql: &str,
) -> Result<(), StorageError> {
    let start = std::time::Instant::now();
    tracing::info!(version = target_version, "applying migration");
    let result = apply_migration_tx(conn, target_version, sql);
    match &result {
        Ok(()) => tracing::debug!(
            version = target_version,
            elapsed_ms = start.elapsed().as_millis(),
            "migration applied"
        ),
        Err(e) => tracing::error!(version = target_version, error = %e, "migration failed"),
    }
    result
}

/// The actual transactional work for one migration — split out of
/// `run_one_migration` so every failure path (transaction start, batch apply,
/// version-row update, commit) funnels through one `Result` for the log above.
fn apply_migration_tx(
    conn: &mut rusqlite::Connection,
    target_version: u32,
    sql: &str,
) -> Result<(), StorageError> {
    let tx = conn
        .transaction()
        .map_err(|e| StorageError::Migration(format!("cannot start transaction: {e}")))?;
    tx.execute_batch(sql)
        .map_err(|e| StorageError::Migration(format!("v{target_version}: {e}")))?;
    // Update the version row inside the same transaction.
    tx.execute("DELETE FROM schema_version", [])
        .map_err(|e| StorageError::Migration(format!("cannot update version: {e}")))?;
    tx.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        [target_version],
    )
    .map_err(|e| StorageError::Migration(format!("cannot insert version: {e}")))?;
    tx.commit().map_err(|e| {
        StorageError::Migration(format!("cannot commit migration v{target_version}: {e}"))
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn open_in_memory() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory DB");
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .expect("FK pragma");
        conn
    }

    #[test]
    fn fresh_db_migrates_to_current_version() {
        let mut conn = open_in_memory();
        run_migrations(&mut conn).expect("migrations");
        let version: u32 = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .expect("version row");
        assert_eq!(version, CURRENT_VERSION);
    }

    #[test]
    fn idempotent_second_run() {
        let mut conn = open_in_memory();
        run_migrations(&mut conn).expect("first run");
        run_migrations(&mut conn).expect("second run should be a no-op");
        let version: u32 = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .expect("version row");
        assert_eq!(version, CURRENT_VERSION);
    }

    #[test]
    fn v1_to_v2_migration() {
        let mut conn = open_in_memory();

        // Set up only v1 (groups/connections/credentials/credential_folders;
        // no settings table yet).
        setup_db_at_version(&mut conn, 1).expect("v1 setup");

        let version: u32 = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .expect("version row");
        assert_eq!(version, 1, "should be at v1 before upgrade");

        // The settings table must not exist yet.
        let settings_missing = conn
            .execute("INSERT INTO settings (key, value) VALUES ('x', 'y')", [])
            .is_err();
        assert!(
            settings_missing,
            "settings table should not exist in v1 schema"
        );

        // Insert data that must survive the migration.
        conn.execute(
            "INSERT INTO groups (name, sort) VALUES ('survived-group', 0)",
            [],
        )
        .expect("insert group");

        // Apply all remaining migrations (v2 adds the settings table; later
        // versions, e.g. v3's `recents` table, ride along -- `run_migrations`
        // always walks to `CURRENT_VERSION`, so this asserts against that
        // constant rather than a version number that will go stale again).
        run_migrations(&mut conn).expect("migrate v1 → current");

        let version: u32 = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .expect("version row");
        assert_eq!(
            version, CURRENT_VERSION,
            "should be at the current version after migration"
        );

        // Settings table must now exist.
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('hello', 'world')",
            [],
        )
        .expect("insert into settings after migration");

        let val: String = conn
            .query_row("SELECT value FROM settings WHERE key = 'hello'", [], |r| {
                r.get(0)
            })
            .expect("read setting");
        assert_eq!(val, "world");

        // Pre-migration data survives.
        let name: String = conn
            .query_row("SELECT name FROM groups", [], |r| r.get(0))
            .expect("read group");
        assert_eq!(name, "survived-group");
    }

    #[test]
    fn v2_to_v3_migration_adds_recents_table() {
        let mut conn = open_in_memory();

        // Set up v2 (no recents table yet).
        setup_db_at_version(&mut conn, 2).expect("v2 setup");

        // Insert a connection that a `recents` row can reference once v3 lands.
        conn.execute("INSERT INTO groups (name, sort) VALUES ('g', 0)", [])
            .expect("insert group");
        conn.execute(
            "INSERT INTO connections (group_id, kind, name, settings_json, sort, created_at, updated_at) \
             VALUES (1, 'ssh', 'survived-conn', '{}', 0, 0, 0)",
            [],
        )
        .expect("insert connection");

        let recents_missing = conn
            .execute(
                "INSERT INTO recents (connection_id, opened_at) VALUES (1, 100)",
                [],
            )
            .is_err();
        assert!(
            recents_missing,
            "recents table should not exist in v2 schema"
        );

        run_migrations(&mut conn).expect("migrate v2 → current");

        let version: u32 = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .expect("version row");
        assert_eq!(
            version, CURRENT_VERSION,
            "should be at the current version after migration"
        );

        conn.execute(
            "INSERT INTO recents (connection_id, opened_at) VALUES (1, 100)",
            [],
        )
        .expect("insert into recents after migration");

        // ON DELETE CASCADE: deleting the connection removes its recents row.
        conn.execute("DELETE FROM connections WHERE id = 1", [])
            .expect("delete connection");
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM recents", [], |r| r.get(0))
            .expect("count recents");
        assert_eq!(remaining, 0, "recents row should cascade-delete");
    }

    #[test]
    fn v3_to_v4_migration_backfills_cred_source_kind() {
        let mut conn = open_in_memory();

        // Set up v3 (no cred_source_kind/inline_* columns yet).
        setup_db_at_version(&mut conn, 3).expect("v3 setup");

        conn.execute("INSERT INTO groups (name, sort) VALUES ('g', 0)", [])
            .expect("insert group");
        conn.execute(
            "INSERT INTO credentials (name, kind) VALUES ('cred', 'password')",
            [],
        )
        .expect("insert credential");

        // A connection with an explicit credential_id (today's "Object" case)...
        conn.execute(
            "INSERT INTO connections \
             (group_id, kind, name, settings_json, credential_id, sort, created_at, updated_at) \
             VALUES (1, 'ssh', 'with-credential', '{}', 1, 0, 0, 0)",
            [],
        )
        .expect("insert connection with credential_id");

        // ...and one without (today's "inherit from group" case).
        conn.execute(
            "INSERT INTO connections \
             (group_id, kind, name, settings_json, credential_id, sort, created_at, updated_at) \
             VALUES (1, 'ssh', 'without-credential', '{}', NULL, 1, 0, 0)",
            [],
        )
        .expect("insert connection without credential_id");

        let cred_source_kind_missing = conn
            .query_row(
                "SELECT cred_source_kind FROM connections LIMIT 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .is_err();
        assert!(
            cred_source_kind_missing,
            "cred_source_kind should not exist in v3 schema"
        );

        run_migrations(&mut conn).expect("migrate v3 → current");

        let version: u32 = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .expect("version row");
        assert_eq!(
            version, CURRENT_VERSION,
            "should be at the current version after migration"
        );

        // The explicit-credential row back-filled to 'object'.
        let with_cred_kind: String = conn
            .query_row(
                "SELECT cred_source_kind FROM connections WHERE name = 'with-credential'",
                [],
                |r| r.get(0),
            )
            .expect("read cred_source_kind");
        assert_eq!(with_cred_kind, "object");

        // The no-credential row stayed the default 'inherit'.
        let without_cred_kind: String = conn
            .query_row(
                "SELECT cred_source_kind FROM connections WHERE name = 'without-credential'",
                [],
                |r| r.get(0),
            )
            .expect("read cred_source_kind");
        assert_eq!(without_cred_kind, "inherit");

        // The new inline_* columns exist and default sanely.
        let (inline_username, inline_domain, inline_has_secret): (
            Option<String>,
            Option<String>,
            i64,
        ) = conn
            .query_row(
                "SELECT inline_username, inline_domain, inline_has_secret \
                 FROM connections WHERE name = 'without-credential'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("read inline_* columns");
        assert_eq!(inline_username, None);
        assert_eq!(inline_domain, None);
        assert_eq!(inline_has_secret, 0);

        // Pre-migration data survives.
        let name: String = conn
            .query_row(
                "SELECT name FROM connections WHERE name = 'with-credential'",
                [],
                |r| r.get(0),
            )
            .expect("read connection");
        assert_eq!(name, "with-credential");
    }
}

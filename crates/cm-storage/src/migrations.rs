use rusqlite::OptionalExtension as _;

use crate::error::StorageError;

/// Latest schema version this build understands.
pub const CURRENT_VERSION: u32 = 2;

/// Ordered migration scripts.  Index `i` upgrades from version `i` to `i+1`,
/// i.e. `MIGRATIONS[0]` is the v0→v1 script (the initial schema).
const MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("../migrations/v1.sql")),
    (2, include_str!("../migrations/v2.sql")),
];

/// Applies all pending migrations on `conn`.  Safe to call on a fresh (empty)
/// database as well as on any partially-migrated one.
///
/// Each migration is wrapped in an explicit transaction, so a mid-migration
/// crash leaves the database at the previous clean version.
pub fn run_migrations(conn: &mut rusqlite::Connection) -> Result<(), StorageError> {
    ensure_version_table(conn)?;
    let current = read_version(conn)?;
    apply_from(conn, current)
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

fn apply_from(conn: &mut rusqlite::Connection, from: u32) -> Result<(), StorageError> {
    for &(target, sql) in MIGRATIONS {
        if target <= from {
            continue;
        }
        run_one_migration(conn, target, sql)?;
    }
    Ok(())
}

fn run_one_migration(
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

        // Apply remaining migrations (v2 adds the settings table).
        run_migrations(&mut conn).expect("migrate v1 → v2");

        let version: u32 = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .expect("version row");
        assert_eq!(version, 2, "should be at v2 after migration");

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
}

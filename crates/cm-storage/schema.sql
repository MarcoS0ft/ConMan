-- ConMan pinned schema — version 4
-- This file documents the final schema produced by applying all migrations
-- (v1 through v4). It is the authoritative reference; do not execute it directly
-- (use SqliteRepository::open / open_in_memory which run migrations).

-- ---------------------------------------------------------------------------
-- schema_version — single-row version tracker
-- ---------------------------------------------------------------------------
-- Managed by the migration framework; value == 4 after a fresh install.
--   schema_version(version INTEGER NOT NULL)

-- ---------------------------------------------------------------------------
-- credential_folders — nestable credential folders
-- ---------------------------------------------------------------------------
-- Arbitrary-depth tree via parent_id. No cycles enforced by the repository.
-- Deleting a folder with children or credentials is blocked (ON DELETE RESTRICT).
CREATE TABLE IF NOT EXISTS credential_folders (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id INTEGER REFERENCES credential_folders(id) ON DELETE RESTRICT,
    name      TEXT    NOT NULL,
    sort      INTEGER NOT NULL DEFAULT 0  -- sibling ordering
);
CREATE INDEX IF NOT EXISTS idx_cf_parent ON credential_folders(parent_id, sort);

-- ---------------------------------------------------------------------------
-- credentials — shared, first-class credential metadata
-- ---------------------------------------------------------------------------
-- Many connections may reference the same credential (sharing).
-- Secrets are stored in the OS keychain, never here.
-- Deleting a folder that contains credentials is blocked (ON DELETE RESTRICT
-- on credentials.folder_id).
-- Deleting a credential nullifies connections.credential_id and
-- groups.default_credential_id (ON DELETE SET NULL).
CREATE TABLE IF NOT EXISTS credentials (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    folder_id INTEGER REFERENCES credential_folders(id) ON DELETE RESTRICT,
    name      TEXT    NOT NULL,
    kind      TEXT    NOT NULL,  -- 'password' | 'ssh-key' | 'ssh-key-with-passphrase'
    username  TEXT               -- non-secret metadata; may be NULL
);
CREATE INDEX IF NOT EXISTS idx_cred_folder ON credentials(folder_id);

-- ---------------------------------------------------------------------------
-- groups — connection tree nodes
-- ---------------------------------------------------------------------------
-- Arbitrary-depth tree via parent_id. No cycles enforced by the repository.
-- The repository deletes a group subtree and its connections atomically.
-- default_credential_id is inherited by connections in this group and
-- its descendants unless overridden at the connection or a nearer ancestor group.
CREATE TABLE IF NOT EXISTS groups (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id             INTEGER REFERENCES groups(id) ON DELETE RESTRICT,
    name                  TEXT    NOT NULL,
    sort                  INTEGER NOT NULL DEFAULT 0,
    default_credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_groups_parent ON groups(parent_id, sort);

-- ---------------------------------------------------------------------------
-- connections — saved connection profiles
-- ---------------------------------------------------------------------------
-- Belongs to a group (NULL = root level).
-- settings_json holds the full ConnectionSettings (kind-specific).
-- host and port are redundant extractions for quick display/search.
-- cred_source_kind selects inheritance, a shared credential object, inline
-- metadata, or an interactive prompt. Secrets always remain in the keychain.
CREATE TABLE IF NOT EXISTS connections (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id          INTEGER REFERENCES groups(id) ON DELETE RESTRICT,
    kind              TEXT    NOT NULL,  -- 'rdp' | 'ssh' | 'telnet' | 'local'
    name              TEXT    NOT NULL,
    host              TEXT,              -- extracted for quick access; NULL for local
    port              INTEGER,           -- extracted for quick access; NULL for local
    settings_json     TEXT    NOT NULL,  -- full ConnectionSettings as JSON
    credential_id     INTEGER REFERENCES credentials(id) ON DELETE SET NULL,
    sort              INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL DEFAULT 0,  -- epoch seconds
    updated_at        INTEGER NOT NULL DEFAULT 0,  -- epoch seconds
    cred_source_kind  TEXT    NOT NULL DEFAULT 'inherit',
    inline_username   TEXT,
    inline_domain     TEXT,
    inline_has_secret INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_conn_group ON connections(group_id, sort);

-- ---------------------------------------------------------------------------
-- app_state — machine-local application state (added in v2)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- recents — most-recently-opened saved connections (added in v3)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS recents (
    connection_id INTEGER PRIMARY KEY REFERENCES connections(id) ON DELETE CASCADE,
    opened_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_recents_opened_at ON recents(opened_at DESC);

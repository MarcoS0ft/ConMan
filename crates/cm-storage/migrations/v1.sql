-- v1: initial ConMan schema
-- Groups, connections, credentials, credential_folders.
-- Machine-local app-state table added in v2.

CREATE TABLE IF NOT EXISTS credential_folders (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id INTEGER REFERENCES credential_folders(id) ON DELETE RESTRICT,
    name      TEXT    NOT NULL,
    sort      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cf_parent ON credential_folders(parent_id, sort);

CREATE TABLE IF NOT EXISTS credentials (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    folder_id INTEGER REFERENCES credential_folders(id) ON DELETE RESTRICT,
    name      TEXT    NOT NULL,
    kind      TEXT    NOT NULL,
    username  TEXT
);
CREATE INDEX IF NOT EXISTS idx_cred_folder ON credentials(folder_id);

CREATE TABLE IF NOT EXISTS groups (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id             INTEGER REFERENCES groups(id) ON DELETE RESTRICT,
    name                  TEXT    NOT NULL,
    sort                  INTEGER NOT NULL DEFAULT 0,
    default_credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_groups_parent ON groups(parent_id, sort);

CREATE TABLE IF NOT EXISTS connections (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id      INTEGER REFERENCES groups(id) ON DELETE RESTRICT,
    kind          TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    host          TEXT,
    port          INTEGER,
    settings_json TEXT    NOT NULL,
    credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL,
    sort          INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL DEFAULT 0,
    updated_at    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_conn_group ON connections(group_id, sort);

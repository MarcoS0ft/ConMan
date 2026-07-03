-- v3: recents table for the Launchpad (P6.14).
--
-- One row per connection that has ever been opened; re-opening a connection
-- replaces its `opened_at` (recency only -- not frecency, see the schema
-- memo `docs/devel/memos/P6.14-recents-schema.md`). `ON DELETE CASCADE` keeps
-- this table from ever pointing at a deleted connection, so `list_recents`
-- never needs to filter dangling ids itself.

CREATE TABLE IF NOT EXISTS recents (
    connection_id INTEGER PRIMARY KEY REFERENCES connections(id) ON DELETE CASCADE,
    opened_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_recents_opened_at ON recents(opened_at DESC);

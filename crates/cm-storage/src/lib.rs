//! `cm-storage` — persistence adapters for ConMan.
//!
//! Implements the `ConnectionRepository` port over SQLite (the single backing
//! store, with versioned schema migrations) and provides defensive JSON
//! import/export as an interchange format. Stores metadata and credential
//! references only; secrets never touch the store.

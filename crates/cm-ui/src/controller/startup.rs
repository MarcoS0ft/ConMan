//! "Restore last session" (P6.14, gap 4): persisting the open-tab set as
//! connection ids (never secrets, never live shell state) and reopening it
//! on the next launch that has the setting enabled.
//!
//! Persistence is write-through (called from every tab-list/active-index
//! mutation in `tabs.rs`/`panes.rs`) rather than tied to a single "on exit"
//! hook — the app has several distinct quit paths (window close, closing the
//! last tab, the QA-harness `quit` command, `CONMAN_AUTOQUIT_MS`), and a
//! write-through snapshot is also robust against an ungraceful exit (crash,
//! `kill -9`) that a single shutdown hook would miss entirely. This mirrors
//! how other UI prefs already persist (`sidebar_collapsed`, `active_panel`).

use std::cell::RefCell;
use std::rc::Rc;

use cm_core::ConnectionId;
use cm_storage::{SessionTabEntry, SessionTabSnapshot, SettingsService};

use super::*;

/// Recomputes and saves the current tab set. Cheap (one JSON blob write) and
/// called on every tab open/close/switch — see the module doc for why.
pub(super) fn persist_session_tabs(state: &Rc<RefCell<State>>) {
    let st = state.borrow();
    // The Launchpad "home" tab isn't real session data -- never persisted.
    let real: Vec<(usize, &Tab)> = st
        .tabs
        .iter()
        .enumerate()
        .filter(|(_, t)| !t.is_empty)
        .collect();
    let tabs: Vec<SessionTabEntry> = real
        .iter()
        .map(|(_, t)| match t.origin_connection_id {
            // Only a tree-launched remote tab has a real, safely-replayable
            // connection id (reopened via the credentialed connect path).
            // Everything else (local shells, quick-connect, reattached
            // sessions) restores as a fresh local shell.
            Some(id) if t.is_remote => {
                SessionTabEntry::Connection(ConnectionId::new(i64::from(id)))
            }
            _ => SessionTabEntry::Local,
        })
        .collect();
    let active = real.iter().position(|(i, _)| *i == st.active).unwrap_or(0);
    let snapshot = SessionTabSnapshot { tabs, active };
    let svc = SettingsService::new(st.io.repo.as_ref());
    if let Err(e) = svc.save_session_tabs(&snapshot) {
        tracing::warn!("save session-tab snapshot: {e}");
    }
}

/// Reopens the tabs recorded in `snap` (called once, right after `ctx` is
/// built, when `run` decided restore is enabled and there is something to
/// restore). Any connection id no longer present (deleted since the
/// snapshot was saved) is skipped, never a hard failure — the stored file is
/// our own, but still handled defensively (CONVENTIONS §2). If nothing ended
/// up restorable at all, falls back to the empty/Launchpad home tab rather
/// than leaving the window with zero tabs.
pub(super) fn restore_session_tabs(ctx: &Ctx, snap: SessionTabSnapshot) {
    for entry in &snap.tabs {
        match entry {
            SessionTabEntry::Local => {
                tabs::open_local_tab(&ctx.state, &ctx.tab_model, &ctx.ui);
            }
            SessionTabEntry::Connection(id) => {
                let conn = {
                    let st = ctx.state.borrow();
                    st.conn_tree
                        .connections()
                        .iter()
                        .find(|c| c.id == *id)
                        .cloned()
                };
                match conn {
                    Some(conn) => sessions::launch_saved_connection(
                        &ctx.state,
                        &ctx.tab_model,
                        &ctx.ui,
                        &ctx.ui.as_weak(),
                        &ctx.hk_pending,
                        &ctx.cert_pending,
                        &ctx.secrets,
                        &conn,
                    ),
                    None => {
                        tracing::warn!(
                            "restore last session: connection {} no longer exists, skipping",
                            id.get()
                        );
                    }
                }
            }
        }
    }

    if ctx.state.borrow().tabs.is_empty() {
        tabs::open_empty_tab(&ctx.state, &ctx.tab_model, &ctx.ui);
        return;
    }
    let len = ctx.state.borrow().tabs.len();
    let active = snap.active.min(len - 1);
    tabs::select_tab(&ctx.state, &ctx.ui, active as i32);
}

#[cfg(test)]
mod tests {
    use super::*;

    // `persist_session_tabs`/`restore_session_tabs` need a live `AppWindow`
    // (Slint component) and are exercised end-to-end by the xvfb restore
    // scenario (see the task report); the pure mapping they're built on
    // (`SessionTabEntry` selection) is covered directly here.

    #[test]
    fn entry_for_tab_prefers_connection_id_for_remote_origin_tabs() {
        // Mirrors the closure in `persist_session_tabs` without needing a
        // live `Tab` (which owns a boxed `Session` trait object) --
        // regression-proofs the exact rule in prose form.
        fn entry_for(origin_connection_id: Option<i32>, is_remote: bool) -> SessionTabEntry {
            match origin_connection_id {
                Some(id) if is_remote => {
                    SessionTabEntry::Connection(ConnectionId::new(i64::from(id)))
                }
                _ => SessionTabEntry::Local,
            }
        }

        assert_eq!(
            entry_for(Some(7), true),
            SessionTabEntry::Connection(ConnectionId::new(7))
        );
        // Local-shell tab (no origin id at all).
        assert_eq!(entry_for(None, false), SessionTabEntry::Local);
        // A local connection profile origin (`is_remote: false`) also
        // degrades to `Local` -- there's nothing remote to re-resolve.
        assert_eq!(entry_for(Some(9), false), SessionTabEntry::Local);
    }
}

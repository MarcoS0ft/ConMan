//! Launchpad activation (P6.14, gap 3): real recents from the `recents`
//! table, a time-of-day greeting, search filtering, and recent activation.
//!
//! The "empty tab" concept (`Tab::is_empty`) that decides *when* the
//! Launchpad is shown lives in `tabs.rs` (tab lifecycle) and `overlays.rs`
//! (per-tab overlay state); this module owns its *content*.

use std::cell::RefCell;
use std::rc::Rc;

use cm_core::Connection;
use slint::{ComponentHandle, Model, SharedString};

use crate::RecentItem;
use crate::tree::conn_host_kind;

use super::*;

/// How many recents to show by default (query empty) and how many search
/// results to show while typing.
const MAX_RESULTS: usize = 10;

pub(super) fn wire_launchpad(ctx: &Ctx) {
    wire_launchpad_edited(ctx);
    wire_open_recent(ctx);
}

/// Recomputes a real greeting + the true "recents" list (empty query) and
/// pushes both into the UI. Called whenever an empty/Launchpad tab becomes
/// what the user is looking at (opened, or re-selected).
pub(super) fn refresh_recents(state: &Rc<RefCell<State>>, ui: &AppWindow) {
    ui.set_launchpad_greeting(SharedString::from(current_greeting()));
    let st = state.borrow();
    let items = recent_items(&st, MAX_RESULTS);
    st.launchpad_recents_model.set_vec(items);
}

fn wire_launchpad_edited(ctx: &Ctx) {
    ctx.ui.on_launchpad_edited({
        let state = ctx.state.clone();
        move |q| {
            let st = state.borrow();
            let items = search_or_recent(&st, q.as_str());
            st.launchpad_recents_model.set_vec(items);
        }
    });
}

fn wire_open_recent(ctx: &Ctx) {
    ctx.ui.on_open_recent({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        let hk_pending = ctx.hk_pending.clone();
        let cert_pending = ctx.cert_pending.clone();
        let secrets = ctx.secrets.clone();
        move |idx| {
            let Some(ui) = weak.upgrade() else { return };
            // `idx` is the position in whatever list is currently displayed
            // (recents, or the live search-filtered list) -- resolve the row
            // to its *displayed* id (`RecentItem.id`, the real connection
            // id), never `idx` itself.
            let conn_id = {
                let st = state.borrow();
                let items: Vec<RecentItem> = (0..st.launchpad_recents_model.row_count())
                    .filter_map(|i| st.launchpad_recents_model.row_data(i))
                    .collect();
                recent_id_at(&items, idx)
            };
            let Some(conn_id) = conn_id else { return };
            let conn = {
                let st = state.borrow();
                st.conn_tree.conn_by_id(conn_id as i64).cloned()
            };
            let Some(conn) = conn else { return };
            sessions::launch_saved_connection(
                &state,
                &tab_model,
                &ui,
                &weak,
                &hk_pending,
                &cert_pending,
                &secrets,
                &conn,
            );
        }
    });
}

/// Resolves `idx` (a `RecentItem` list position, from `on_open_recent`) to
/// the connection id displayed at that position, or `None` if out of range.
/// Pulled out of the wired closure so it's testable without a live
/// `AppWindow`/model (mirrors `overlays::resolve_edit_action`) -- the actual
/// list at click time may be the true recents or a live search-filtered
/// list, so this always resolves against *whatever* is currently displayed,
/// never a stale/cached recents snapshot.
fn recent_id_at(items: &[RecentItem], idx: i32) -> Option<i32> {
    usize::try_from(idx)
        .ok()
        .and_then(|i| items.get(i))
        .map(|item| item.id)
}

// ---------------------------------------------------------------------------
// Recents / search content
// ---------------------------------------------------------------------------

fn search_or_recent(st: &State, query: &str) -> Vec<RecentItem> {
    let q = query.trim();
    if q.is_empty() {
        recent_items(st, MAX_RESULTS)
    } else {
        search_items(st, q, MAX_RESULTS)
    }
}

/// The true "recents" list: the `recents` table, most-recently-opened first,
/// each row's `meta` a relative-time string ("2m ago").
fn recent_items(st: &State, limit: usize) -> Vec<RecentItem> {
    let rows = match st.io.repo.list_recents(limit) {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("list_recents: {e}");
            Vec::new()
        }
    };
    let now = crate::tree::now_secs();
    rows.into_iter()
        .filter_map(|(id, opened_at)| {
            st.conn_tree
                .conn_by_id(id.get())
                .map(|conn| (conn, opened_at))
        })
        .map(|(conn, opened_at)| {
            let status = status_for(st, conn.id.get());
            recent_item_for(conn, relative_time_secs(now, opened_at), status)
        })
        .collect()
}

/// Search-to-connect: every saved connection whose name or host/target
/// string contains `query` (case-insensitive), `meta` set to the host/target
/// string so results stay disambiguated even when several share a name.
fn search_items(st: &State, query: &str, limit: usize) -> Vec<RecentItem> {
    let q = query.to_lowercase();
    st.conn_tree
        .connections()
        .iter()
        .filter(|c| {
            let (host, _) = conn_host_kind(&c.settings);
            c.name.to_lowercase().contains(&q) || host.to_lowercase().contains(&q)
        })
        .take(limit)
        .map(|conn| {
            let (host, _) = conn_host_kind(&conn.settings);
            let status = status_for(st, conn.id.get());
            recent_item_for(conn, host, status)
        })
        .collect()
}

fn recent_item_for(conn: &Connection, meta: String, status: &'static str) -> RecentItem {
    let (_, kind) = conn_host_kind(&conn.settings);
    RecentItem {
        id: conn.id.get() as i32,
        name: SharedString::from(conn.name.clone()),
        meta: SharedString::from(meta),
        kind: SharedString::from(kind),
        status: SharedString::from(status),
    }
}

/// The status dot for a connection's Launchpad row: reflects a currently-open
/// tab launched from it, if any, else "disconnected" (not currently open).
fn status_for(st: &State, conn_id: i64) -> &'static str {
    let tab = st
        .tabs
        .iter()
        .find(|t| t.origin_connection_id == Some(conn_id as i32));
    match tab.map(|t| t.session.status()) {
        Some(cm_session::SessionStatus::Connecting) => "connecting",
        Some(cm_session::SessionStatus::Connected) => "connected",
        Some(cm_session::SessionStatus::Failed(_)) => "error",
        Some(cm_session::SessionStatus::Disconnected | cm_session::SessionStatus::Exited(_))
        | None => "disconnected",
    }
}

/// "just now" / "Nm ago" / "Nh ago" / "Nd ago" -- pure function of two epoch
/// timestamps so it's unit-testable without wall-clock flakiness.
fn relative_time_secs(now: i64, then: i64) -> String {
    let delta = (now - then).max(0);
    match delta {
        0..=59 => "just now".to_owned(),
        60..=3599 => format!("{}m ago", delta / 60),
        3600..=86399 => format!("{}h ago", delta / 3600),
        _ => format!("{}d ago", delta / 86400),
    }
}

/// A real (if coarse) greeting: UTC-hour buckets rather than a literal
/// hardcoded string. Deliberately not locale/timezone-aware -- pulling in a
/// local-time crate for a cosmetic greeting isn't worth a new-dependency
/// memo (CONVENTIONS §4); this is a known, low-stakes simplification.
pub(super) fn current_greeting() -> String {
    greeting_for_hour(current_utc_hour()).to_owned()
}

fn current_utc_hour() -> u32 {
    let secs = crate::tree::now_secs().max(0) as u64;
    ((secs / 3600) % 24) as u32
}

fn greeting_for_hour(hour_utc: u32) -> &'static str {
    match hour_utc {
        5..=11 => "Good morning.",
        12..=17 => "Good afternoon.",
        18..=22 => "Good evening.",
        _ => "Welcome back.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_time_buckets() {
        assert_eq!(relative_time_secs(100, 100), "just now");
        assert_eq!(relative_time_secs(160, 100), "1m ago");
        assert_eq!(relative_time_secs(100 + 3 * 3600, 100), "3h ago");
        assert_eq!(relative_time_secs(100 + 2 * 86400, 100), "2d ago");
        // Defensive: a future-looking `opened_at` (clock skew) never panics
        // or goes negative.
        assert_eq!(relative_time_secs(100, 500), "just now");
    }

    fn item(id: i32) -> RecentItem {
        RecentItem {
            id,
            name: SharedString::from("x"),
            meta: SharedString::from(""),
            kind: SharedString::from("SSH"),
            status: SharedString::from("disconnected"),
        }
    }

    #[test]
    fn recent_id_at_resolves_by_position_not_id() {
        let items = vec![item(42), item(7), item(99)];
        assert_eq!(recent_id_at(&items, 0), Some(42));
        assert_eq!(recent_id_at(&items, 1), Some(7));
        assert_eq!(recent_id_at(&items, 2), Some(99));
    }

    #[test]
    fn recent_id_at_out_of_range_is_none() {
        let items = vec![item(42)];
        assert_eq!(recent_id_at(&items, 1), None);
        assert_eq!(recent_id_at(&items, -1), None);
        assert_eq!(recent_id_at(&[], 0), None);
    }

    #[test]
    fn greeting_for_hour_covers_the_day() {
        assert_eq!(greeting_for_hour(0), "Welcome back.");
        assert_eq!(greeting_for_hour(8), "Good morning.");
        assert_eq!(greeting_for_hour(14), "Good afternoon.");
        assert_eq!(greeting_for_hour(20), "Good evening.");
        assert_eq!(greeting_for_hour(23), "Welcome back.");
    }
}

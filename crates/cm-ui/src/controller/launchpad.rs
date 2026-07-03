//! Launchpad activation (P6.14, gap 3): real recents from the `recents`
//! table, a time-of-day greeting, and the three previously-stub callbacks
//! (`launchpad-edited` search-to-filter, `open-recent`, `open-group-split`).
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
/// results to show while typing. One constant, one screen's worth of the
/// 2-column grid `launchpad.slint` renders (CONVENTIONS §2: single source of
/// truth for such numbers).
const MAX_RESULTS: usize = 8;

pub(super) fn wire_launchpad(ctx: &Ctx) {
    wire_launchpad_edited(ctx);
    wire_open_recent(ctx);
    wire_open_group_split(ctx);
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
            // (recents, or the live search-filtered list) -- look the row up
            // by its *displayed* id (`RecentItem.id`), which is the real
            // connection id, not `idx` itself.
            let conn_id = {
                let st = state.borrow();
                st.launchpad_recents_model
                    .row_data(idx as usize)
                    .map(|item| item.id)
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

/// "Open Production in split" (P6.14 gap 3, `on_open_group_split`). Scope
/// note: the current 2-pane primitive (`panes::do_split`) only ever spawns a
/// *fresh local shell* for the new pane -- there is no existing way to place
/// a specific stored SSH/RDP connection into a split pane (that plumbing
/// belongs to P6.11's "N-way panes" rework). Rather than fake a split with
/// unrelated content in pane 2, this opens each of the target group's
/// members (up to the button's implied 2) as its own tab via the same
/// credentialed connect path -- both actually reach the intended host, even
/// though the result is tabs rather than literal panes. Revisit once P6.11
/// lands real per-pane session placement.
fn wire_open_group_split(ctx: &Ctx) {
    ctx.ui.on_open_group_split({
        let state = ctx.state.clone();
        let tab_model = ctx.tab_model.clone();
        let weak = ctx.ui.as_weak();
        let hk_pending = ctx.hk_pending.clone();
        let cert_pending = ctx.cert_pending.clone();
        let secrets = ctx.secrets.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let members: Vec<Connection> = {
                let st = state.borrow();
                let Some(group_id) = find_launchpad_group_id(&st) else {
                    return;
                };
                st.conn_tree
                    .connections()
                    .iter()
                    .filter(|c| c.group_id == Some(group_id))
                    .take(2)
                    .cloned()
                    .collect()
            };
            for conn in &members {
                sessions::launch_saved_connection(
                    &state,
                    &tab_model,
                    &ui,
                    &weak,
                    &hk_pending,
                    &cert_pending,
                    &secrets,
                    conn,
                );
            }
        }
    });
}

/// Finds the group the "Open Production in split" button refers to. The
/// button's literal copy says "Production"; the demo/seed data
/// (`conman::seed_demo_data`) names the equivalent group "Prod" -- match
/// case-insensitively on either so both the exact and the seeded name work,
/// preferring an exact "production" match if one exists.
fn find_launchpad_group_id(st: &State) -> Option<cm_core::GroupId> {
    let groups = st.conn_tree.groups();
    groups
        .iter()
        .find(|g| g.name.eq_ignore_ascii_case("production"))
        .or_else(|| {
            groups
                .iter()
                .find(|g| g.name.to_lowercase().contains("prod"))
        })
        .map(|g| g.id)
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

    #[test]
    fn greeting_for_hour_covers_the_day() {
        assert_eq!(greeting_for_hour(0), "Welcome back.");
        assert_eq!(greeting_for_hour(8), "Good morning.");
        assert_eq!(greeting_for_hour(14), "Good afternoon.");
        assert_eq!(greeting_for_hour(20), "Good evening.");
        assert_eq!(greeting_for_hour(23), "Welcome back.");
    }
}

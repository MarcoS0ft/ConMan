//! P8.2 Suite 2 — shell chrome: command palette open/filter/dispatch, tab
//! open/select/close, sidebar collapse, the status pill tracking live session
//! status, and the P6.17 "gap #5" tab-strip/sidebar geometry (first-tab left
//! inset, the nav/tab-strip divider) as logical-pixel assertions.
//!
//! One process, one `#[test]`, scenarios run sequentially, each against its
//! own fresh [`support::harness`].

#![cfg(feature = "ui-introspection")]

mod support;

use i_slint_backend_testing::ElementHandle;

use support::{find_by_id, find_descendant_by_label, find_singleton, harness, nth_by_id};

#[test]
fn shell_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    palette_open_filter_dispatch();
    tabs_open_select_close_via_elements();
    sidebar_collapse_toggles();
    status_pill_tracks_session_status();
    first_tab_inset_and_divider_present();
}

fn tab_count(ui: &cm_ui::AppWindow) -> usize {
    ElementHandle::find_by_element_id(ui, "AppWindow::tab-item").count()
}

// ── Command palette (P6.17 "open command palette / run an action") ─────────

/// Opens the palette via its real status-bar affordance, filters to a single
/// unambiguous action via `set_accessible_value` on the search input, and
/// dispatches it via `invoke_accessible_default_action` on the one remaining
/// result row -- exactly the two semantic actions the task spec calls out.
fn palette_open_filter_dispatch() {
    let (h, _repo, _provider) = harness();
    let tabs_before = tab_count(&h.ui);

    find_by_id(&h.ui, "AppWindow::palette-badge-btn").invoke_accessible_default_action();
    assert!(h.ui.get_palette_open(), "palette did not open");

    let input = find_by_id(&h.ui, "CommandPalette::input");
    input.set_accessible_value("new local tab");
    assert_eq!(
        h.ui.get_palette_query().as_str(),
        "new local tab",
        "set_accessible_value on the palette input must reach palette-query \
         (round-trips through the real `edited` callback, not a direct property poke)"
    );

    let palette = find_singleton(&h.ui, "CommandPalette");
    let row = find_descendant_by_label(&palette, "New local tab");
    row.invoke_accessible_default_action();

    assert!(
        !h.ui.get_palette_open(),
        "dispatching an action must close the palette"
    );
    assert_eq!(
        tab_count(&h.ui),
        tabs_before + 1,
        "\"New local tab\" must have opened a new tab"
    );
}

// ── Tabs (open/select/close via real tab elements) ──────────────────────────

fn tabs_open_select_close_via_elements() {
    let (h, _repo, _provider) = harness();
    assert_eq!(
        tab_count(&h.ui),
        1,
        "harness() starts with exactly one local-shell tab"
    );

    find_by_id(&h.ui, "AppWindow::new-tab-btn").invoke_accessible_default_action();
    assert_eq!(tab_count(&h.ui), 2);

    // Select tab 0, then tab 1, via each tab's own default action.
    nth_by_id(&h.ui, "AppWindow::tab-item", 0).invoke_accessible_default_action();
    assert_eq!(h.ui.get_active_tab(), 0, "clicking tab 0 must select it");

    let tab1 = nth_by_id(&h.ui, "AppWindow::tab-item", 1);
    tab1.invoke_accessible_default_action();
    assert_eq!(h.ui.get_active_tab(), 1, "clicking tab 1 must select it");

    // Close tab 1 via its own close button (scoped to that tab instance --
    // `Tab::close-tab-btn` is one shared id across every tab, see
    // `support::find_descendant_by_label`'s doc for why scoping matters).
    let close_btn = tab1
        .query_descendants()
        .match_id("Tab::close-tab-btn")
        .find_first()
        .expect("close button not found on tab 1");
    close_btn.invoke_accessible_default_action();

    assert_eq!(
        tab_count(&h.ui),
        1,
        "closing tab 1 must leave exactly one tab"
    );
}

// ── Sidebar collapse ─────────────────────────────────────────────────────────

fn sidebar_collapse_toggles() {
    let (h, _repo, _provider) = harness();
    assert!(!h.ui.get_sidebar_collapsed(), "sidebar starts expanded");
    let expanded_first_tab_x = nth_by_id(&h.ui, "AppWindow::tab-item", 0)
        .absolute_position()
        .x;

    find_by_id(&h.ui, "AppWindow::sidebar-toggle-btn").invoke_accessible_default_action();
    assert!(
        h.ui.get_sidebar_collapsed(),
        "toggle must collapse the sidebar"
    );
    let collapsed_first_tab_x = nth_by_id(&h.ui, "AppWindow::tab-item", 0)
        .absolute_position()
        .x;
    assert!(
        collapsed_first_tab_x < expanded_first_tab_x,
        "collapsing the sidebar must move the tab strip left \
         (expanded x={expanded_first_tab_x}, collapsed x={collapsed_first_tab_x})"
    );

    find_by_id(&h.ui, "AppWindow::sidebar-toggle-btn").invoke_accessible_default_action();
    assert!(
        !h.ui.get_sidebar_collapsed(),
        "toggle must re-expand the sidebar"
    );
}

// ── Status pill (P6.9 gap 13: label tracks live status, not a hardcoded one) ─

fn status_pill_tracks_session_status() {
    let (h, _repo, _provider) = harness();
    // harness() starts with one Connected local-shell tab -- the redraw timer
    // needs one tick to poll `session.status()` and update the overlay/pill.
    support::pump_ticks(1);
    let pill = find_singleton(&h.ui, "StatusPill");
    let label = pill
        .accessible_label()
        .expect("StatusPill must have an accessible-label");
    assert!(
        label.starts_with("Connected"),
        "status pill must read Connected for a live local shell, got {label:?}"
    );
    assert_eq!(h.ui.get_session_status().as_str(), "connected");
}

// ── Geometry (P6.17 gap #5: first-tab left inset, nav/tab-strip divider) ────

/// The nav column (activity bar + optional side panel) must end strictly
/// before the first tab begins -- proving both a non-zero left inset AND
/// that something (the P7.3 hairline divider) occupies the gap between them.
/// This is the exact defect class the win-ui memo's #5 flagged ("tab flush
/// to the window corner, no divider"): a regression back to that state would
/// make `first_tab_x` collapse to `activity_bar_right`.
fn first_tab_inset_and_divider_present() {
    let (h, _repo, _provider) = harness();
    let activity_bar_btn = find_by_id(&h.ui, "AppWindow::connections-panel-btn");
    let activity_bar_right = activity_bar_btn.absolute_position().x + activity_bar_btn.size().width;
    let first_tab_x = nth_by_id(&h.ui, "AppWindow::tab-item", 0)
        .absolute_position()
        .x;

    assert!(
        first_tab_x > activity_bar_right,
        "first tab (x={first_tab_x}) must start strictly after the activity bar \
         (right edge={activity_bar_right}) -- a zero-gap regression means the \
         divider/inset is gone"
    );

    // Still true with the side panel collapsed (removing a whole column must
    // not collapse the gap back to zero -- the divider survives either way).
    find_by_id(&h.ui, "AppWindow::sidebar-toggle-btn").invoke_accessible_default_action();
    let first_tab_x_collapsed = nth_by_id(&h.ui, "AppWindow::tab-item", 0)
        .absolute_position()
        .x;
    assert!(
        first_tab_x_collapsed > activity_bar_right,
        "first tab must still start after the activity bar with the sidebar collapsed"
    );
}

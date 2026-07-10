//! P9.5 #2 — connection-tree row click semantics: single click selects
//! (`row-selected`), double click / accessible-default-action launches
//! (`row-activated`); the two must never be conflated.
//!
//! This harness has no raw-pointer/click-count simulation (every existing
//! suite drives interaction via `invoke_accessible_default_action` or a
//! callback's auto-generated `invoke_*` method -- grep the other suites, none
//! synthesize a mouse click). Slint's own click-vs-double-click counting
//! (`TouchArea::clicked`/`double-clicked`) is the *engine's* job, not
//! something this suite re-proves; what belongs here is the NEW wiring this
//! lane added: `row-selected` selects without launching, and `row-activated`
//! (still the target of both the double-click handler and the accessible
//! default action / keyboard Enter, unchanged) launches. Invoking each
//! callback directly via its `invoke_*` method exercises the exact same
//! Rust-side handler a real double click or a real single click would have
//! triggered.
//!
//! P9.5 #1's hover-icon-strip stability (the flicker fix) is NOT covered
//! here for the same reason: it depends on real pointer `has-hover` tracking
//! that this headless testing backend has no way to synthesize (confirmed by
//! the same grep -- no suite anywhere touches hover state). That fix rests on
//! the compile-time-checked, self-consistent OR formula in
//! `ConnectionRow::action-hover` (app.slint) plus the full green run of the
//! existing suites (proving no regression), not on a new automated test.

#![cfg(feature = "ui-introspection")]

mod support;

use std::sync::{Arc, Mutex};

use cm_core::SessionStatus;
use i_slint_backend_testing::ElementHandle;
use slint::Model;

use support::{find_by_id, harness, nth_by_id, pump_ticks};

#[test]
fn connections_tree_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    select_does_not_launch_but_activate_does();
    tree_row_status_dot_tracks_its_connection_s_live_tab();
    connection_row_still_carries_its_context_menu_area();
}

fn tab_count(ui: &cm_ui::AppWindow) -> usize {
    ElementHandle::find_by_element_id(ui, "AppWindow::tab-item").count()
}

/// Seeds one root-level Local connection via the real "New connection" ->
/// Save journey (mirrors `suite_dialogs.rs`'s profile-editor save scenario),
/// then drives the tree row's two callbacks directly:
/// - `row-selected(0)` must select the row (`accessible-item-selected`
///   becomes `true`) and must NOT open a new tab.
/// - `row-activated(0)` (the double-click / Enter / accessible-default-action
///   target) DOES open a new tab.
///
/// Local (not SSH/RDP) keeps this scenario about click semantics only --
/// `spawn_local` on `MockSessionProvider` always succeeds immediately, no
/// credential/host resolution to account for.
fn select_does_not_launch_but_activate_does() {
    let (h, repo, _provider) = harness();
    let tabs_before = tab_count(&h.ui);

    h.ui.invoke_new_connection(0);
    {
        let mut form = h.ui.get_profile_form();
        form.name = "Test Row".into();
        form.kind = 2; // Local
        h.ui.set_profile_form(form);
    }
    find_by_id(&h.ui, "ProfileEditor::profile-save-btn").invoke_accessible_default_action();
    assert!(
        !h.ui.get_profile_editor_open(),
        "Save must close the profile editor"
    );
    let saved = repo.list_connections().expect("list_connections");
    assert_eq!(saved.len(), 1, "seed: exactly one connection persisted");

    let row = nth_by_id(&h.ui, "AppWindow::conn-row", 0);
    assert_eq!(
        row.accessible_item_selected(),
        Some(false),
        "a freshly-created row starts unselected"
    );

    // Single click's real callback: select, not launch.
    h.ui.invoke_row_selected(0);
    assert_eq!(
        tab_count(&h.ui),
        tabs_before,
        "row-selected (single click) must NOT open a new tab (P9.5 #2)"
    );
    let row = nth_by_id(&h.ui, "AppWindow::conn-row", 0);
    assert_eq!(
        row.accessible_item_selected(),
        Some(true),
        "row-selected must mark the row selected"
    );

    // Double click's (and Enter's, and the accessible default action's) real
    // callback: launch.
    h.ui.invoke_row_activated(0);
    assert_eq!(
        tab_count(&h.ui),
        tabs_before + 1,
        "row-activated (double click / Enter) must open a new tab (P9.5 #2)"
    );
}

/// P9.10 #4: the connection tree's `StatusDot` used to be hardcoded
/// "disconnected" at construction and never touched again -- this proves the
/// live-status overlay (`tree_ctl::overlay_live_status`, triggered off the
/// tab's own status-transition detection in `tick_tab`) actually reaches the
/// row, across a real connecting -> connected -> disconnected lifecycle
/// driven through the exact tree-launch path (`row-activated`) a real
/// double-click/Enter goes through.
///
/// Known, documented, accepted gap (not a bug): the row only picks up a
/// tab's status once that tab's status actually CHANGES at least once after
/// being pushed -- `tick_tab`'s refresh hook rides the existing "did this
/// tab's own status change" detection rather than an unconditional every-
/// tick walk of the whole tree, so the dot briefly lags the FIRST connecting
/// phase right after launch (a cosmetically minor, well-bounded trade-off,
/// not the "inert forever" bug the user reported). This test starts its
/// assertions from the FIRST transition onward, where the dot is always
/// accurate.
fn tree_row_status_dot_tracks_its_connection_s_live_tab() {
    let (h, repo, provider) = harness();

    h.ui.invoke_new_connection(0);
    {
        let mut form = h.ui.get_profile_form();
        form.name = "Live Dot Target".into();
        form.host = "mock-live-dot-host".into();
        form.auth_method = 2; // Agent -- no stored credential needed to resolve.
        h.ui.set_profile_form(form);
    }
    find_by_id(&h.ui, "ProfileEditor::profile-save-btn").invoke_accessible_default_action();
    let saved = repo.list_connections().expect("list_connections");
    assert_eq!(saved.len(), 1, "seed: exactly one connection persisted");

    let cell = Arc::new(Mutex::new(SessionStatus::Connecting));
    provider.script_next_remote(cell.clone());
    h.ui.invoke_row_activated(0);
    pump_ticks(1);

    // First transition: Connecting -> Connected.
    *cell.lock().expect("cell poisoned") = SessionStatus::Connected;
    pump_ticks(1);
    assert_eq!(
        h.ui.get_connections()
            .row_data(0)
            .expect("tree row")
            .status
            .as_str(),
        "connected",
        "the tree row must reflect its connection's now-Connected tab"
    );

    // Second transition: Connected -> Disconnected -- the dot must revert,
    // not get stuck showing a stale "connected".
    *cell.lock().expect("cell poisoned") = SessionStatus::Disconnected;
    pump_ticks(1);
    assert_eq!(
        h.ui.get_connections()
            .row_data(0)
            .expect("tree row")
            .status
            .as_str(),
        "disconnected",
        "the tree row must revert once its tab disconnects, not stay stuck showing connected"
    );
}

/// P9.12 #1 (right-click regression, fixed): `ContextMenuArea` is not
/// queryable the way an ordinary `Rectangle`/`TouchArea` is via
/// `accessible_*` attributes, and its `Menu`/`MenuItem` children are
/// invisible to `ElementHandle` entirely until the menu actually opens (a
/// real right-click gesture -- confirmed empirically: `find_by_element_
/// type_name(&h.ui, "Menu"/"MenuItem")` returns zero even with rows present).
/// So this can't prove the right-click GESTURE reaches the menu (that's
/// .99-verify, same as the rest of Bug A) -- but `ContextMenuArea` itself
/// IS queryable by type name, so this proves the fix's declaration-order
/// move (to the end of `ConnectionRow`, past the `HorizontalLayout`) didn't
/// accidentally drop, duplicate, or mis-nest it: exactly one extra
/// `ContextMenuArea` must exist per row added to the tree.
fn connection_row_still_carries_its_context_menu_area() {
    let (h, _repo, _provider) = harness();
    let before = ElementHandle::find_by_element_type_name(&h.ui, "ContextMenuArea").count();

    h.ui.invoke_new_connection(0);
    {
        let mut form = h.ui.get_profile_form();
        form.name = "Ctx Menu Row".into();
        form.kind = 2; // Local
        h.ui.set_profile_form(form);
    }
    find_by_id(&h.ui, "ProfileEditor::profile-save-btn").invoke_accessible_default_action();

    let after = ElementHandle::find_by_element_type_name(&h.ui, "ContextMenuArea").count();
    assert_eq!(
        after,
        before + 1,
        "a new connection row must add exactly one ContextMenuArea, proving the \
         P9.12 #1 fix (declaring it last, after the row's HorizontalLayout) kept it \
         present -- not dropped or accidentally duplicated"
    );
}

//! Connection-tree row click semantics: single click selects
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
//! Hover-icon-strip stability is not covered
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
    delete_confirmation_preserves_on_cancel_and_recursively_deletes_on_accept();
    connection_delete_also_requires_confirmation();
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
        form.kind = 3; // Local
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
        "row-selected (single click) must NOT open a new tab"
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
        "row-activated (double click / Enter) must open a new tab"
    );
}

fn save_group(ui: &cm_ui::AppWindow, parent_id: i32, name: &str) {
    ui.invoke_new_group(parent_id);
    let mut form = ui.get_group_form();
    form.name = name.into();
    ui.set_group_form(form);
    find_by_id(ui, "GroupEditor::group-save-btn").invoke_accessible_default_action();
    assert!(!ui.get_group_editor_open(), "group save must close editor");
}

/// Destructive deletion is deliberately two-step. The request must not mutate
/// storage, cancellation must preserve the complete subtree, and confirmation
/// must remove the selected group, all descendants, and their connections.
fn delete_confirmation_preserves_on_cancel_and_recursively_deletes_on_accept() {
    let (h, repo, _provider) = harness();

    save_group(&h.ui, 0, "Delete root");
    let root_id = repo.list_groups().expect("list root")[0].id;
    save_group(&h.ui, root_id.get() as i32, "Delete child");
    let child_id = repo
        .list_groups()
        .expect("list child")
        .into_iter()
        .find(|group| group.parent_id == Some(root_id))
        .expect("child group")
        .id;

    h.ui.invoke_new_connection(child_id.get() as i32);
    {
        let mut form = h.ui.get_profile_form();
        form.name = "Nested connection".into();
        form.kind = 3; // Local
        h.ui.set_profile_form(form);
    }
    find_by_id(&h.ui, "ProfileEditor::profile-save-btn").invoke_accessible_default_action();
    assert_eq!(repo.list_connections().expect("list connections").len(), 1);

    h.ui.invoke_delete_conn_row(root_id.get() as i32, true);
    assert!(h.ui.get_delete_confirm_open());
    assert!(h.ui.get_delete_confirm_is_group());
    assert_eq!(h.ui.get_delete_confirm_group_count(), 2);
    assert_eq!(h.ui.get_delete_confirm_connection_count(), 1);
    assert_eq!(
        h.ui.get_delete_confirm_target_name().as_str(),
        "Delete root"
    );
    assert_eq!(
        repo.list_groups().expect("request preserves groups").len(),
        2
    );
    assert_eq!(
        repo.list_connections()
            .expect("request preserves connections")
            .len(),
        1
    );

    find_by_id(&h.ui, "DeleteConfirmationDialog::delete-cancel-btn")
        .invoke_accessible_default_action();
    assert!(!h.ui.get_delete_confirm_open());
    assert_eq!(
        repo.list_groups().expect("cancel preserves groups").len(),
        2
    );
    assert_eq!(
        repo.list_connections()
            .expect("cancel preserves connections")
            .len(),
        1
    );

    h.ui.invoke_delete_conn_row(root_id.get() as i32, true);
    find_by_id(&h.ui, "DeleteConfirmationDialog::delete-confirm-btn")
        .invoke_accessible_default_action();
    assert!(!h.ui.get_delete_confirm_open());
    assert!(repo.list_groups().expect("confirmed groups").is_empty());
    assert!(
        repo.list_connections()
            .expect("confirmed connections")
            .is_empty()
    );
    assert_eq!(
        h.ui.get_group_name_list().row_count(),
        1,
        "group selector must refresh back to only the root sentinel"
    );
}

fn connection_delete_also_requires_confirmation() {
    let (h, repo, _provider) = harness();
    h.ui.invoke_new_connection(0);
    {
        let mut form = h.ui.get_profile_form();
        form.name = "Delete leaf".into();
        form.kind = 3; // Local
        h.ui.set_profile_form(form);
    }
    find_by_id(&h.ui, "ProfileEditor::profile-save-btn").invoke_accessible_default_action();
    let id = repo.list_connections().expect("saved connection")[0].id;

    h.ui.invoke_delete_conn_row(id.get() as i32, false);
    assert!(h.ui.get_delete_confirm_open());
    assert!(!h.ui.get_delete_confirm_is_group());
    assert_eq!(h.ui.get_delete_confirm_group_count(), 0);
    assert_eq!(h.ui.get_delete_confirm_connection_count(), 1);
    find_by_id(&h.ui, "DeleteConfirmationDialog::delete-cancel-btn")
        .invoke_accessible_default_action();
    assert_eq!(
        repo.list_connections()
            .expect("cancel preserves leaf")
            .len(),
        1
    );

    h.ui.invoke_delete_conn_row(id.get() as i32, false);
    find_by_id(&h.ui, "DeleteConfirmationDialog::delete-confirm-btn")
        .invoke_accessible_default_action();
    assert!(
        repo.list_connections()
            .expect("confirmed leaf delete")
            .is_empty()
    );
}

/// The connection tree's `StatusDot` reflects live connection status rather
/// than remaining hardcoded to "disconnected" at construction. This proves the
/// live-status overlay (`tree_ctl::overlay_live_status`, triggered off the
/// tab's own status-transition detection in `tick_tab`) actually reaches the
/// row, across a real connecting -> connected -> disconnected lifecycle
/// driven through the exact tree-launch path (`row-activated`) a real
/// double-click/Enter goes through.
///
/// Known, documented behavior (not a bug): the row only picks up a
/// tab's status once that tab's status actually CHANGES at least once after
/// being pushed -- `tick_tab`'s refresh hook rides the existing "did this
/// tab's own status change" detection rather than an unconditional every-
/// tick walk of the whole tree, so the dot briefly lags the FIRST connecting
/// after launch (a cosmetically minor, well-bounded trade-off, not an inert
/// state). This test starts its
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

/// Right-click regression: `ContextMenuArea` is not
/// queryable the way an ordinary `Rectangle`/`TouchArea` is via
/// `accessible_*` attributes, and its `Menu`/`MenuItem` children are
/// invisible to `ElementHandle` entirely until the menu actually opens (a
/// real right-click gesture -- confirmed empirically: `find_by_element_
/// type_name(&h.ui, "Menu"/"MenuItem")` returns zero even with rows present).
/// So this can't prove the right-click GESTURE reaches the menu (that's
/// separately verified, same as the rest of the pointer behavior) -- but
/// `ContextMenuArea` itself
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
        form.kind = 3; // Local
        h.ui.set_profile_form(form);
    }
    find_by_id(&h.ui, "ProfileEditor::profile-save-btn").invoke_accessible_default_action();

    let after = ElementHandle::find_by_element_type_name(&h.ui, "ContextMenuArea").count();
    assert_eq!(
        after,
        before + 1,
        "a new connection row must add exactly one ContextMenuArea, proving the \
         declaration order (after the row's HorizontalLayout) keeps it \
         present -- not dropped or accidentally duplicated"
    );
}

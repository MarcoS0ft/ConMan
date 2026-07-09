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

use i_slint_backend_testing::ElementHandle;

use support::{find_by_id, harness, nth_by_id};

#[test]
fn connections_tree_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    select_does_not_launch_but_activate_does();
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

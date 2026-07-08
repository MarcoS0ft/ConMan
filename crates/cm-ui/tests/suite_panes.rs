//! P8.4 Suite -- split panes: H/V split growing `pane-count`, focus move
//! between panes (`active-pane`), and the broadcast toggle + targeting menu
//! (P6.9/P5.1/P6.11). Covers the P6.17 Linux J6 / Windows W7 journeys that
//! P8.2's three suites did not port.
//!
//! Every action below drives the real callback the keyboard shortcuts
//! (`Ctrl+Shift+\|-|B`, MCP/real-binary territory -- `dispatch_key_event`) and
//! the palette action ultimately call: `ui.invoke_split_pane_h()` /
//! `invoke_split_pane_v()` / `invoke_toggle_broadcast()` /
//! `invoke_pane_focused(idx)` are the exact `on_*` callbacks wired in
//! `controller/panes.rs::wire_panes`. This is the same "drive the semantic
//! action directly" pattern `suite_dialogs.rs` uses for
//! `invoke_quick_connect()`/`invoke_new_connection()` -- the keyboard-dispatch
//! *path* to these callbacks is a separate, real-input concern out of an
//! in-process element suite's reach (MCP's `dispatch_key_event` layer).

#![cfg(feature = "ui-introspection")]

mod support;

use i_slint_backend_testing::ElementRoot;
use slint::Model;
use support::{find_by_id, find_descendant_by_label, harness, pump_ticks};

#[test]
fn panes_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    split_h_then_v_grows_pane_count();
    focus_move_updates_active_pane();
    broadcast_toggle_and_target_menu();
}

fn active_tab_pane_count(h: &cm_ui::TestHarness) -> i32 {
    let idx = h.ui.get_active_tab();
    h.ui.get_tabs()
        .row_data(idx as usize)
        .expect("active tab row")
        .pane_count
}

/// J6/W7: `Ctrl+Shift+\` (H-split) then `Ctrl+Shift+-` (V-split) must grow
/// `pane_count` 1 -> 2 -> 3, mirroring the Windows run's "three panes"
/// journey (W7) on the N-way pane tree.
fn split_h_then_v_grows_pane_count() {
    let (h, _repo, _provider) = harness();
    assert_eq!(active_tab_pane_count(&h), 1, "harness starts single-pane");

    h.ui.invoke_split_pane_h();
    pump_ticks(1);
    assert_eq!(active_tab_pane_count(&h), 2, "H-split must grow to 2 panes");

    h.ui.invoke_split_pane_v();
    pump_ticks(1);
    assert_eq!(active_tab_pane_count(&h), 3, "V-split must grow to 3 panes");
}

/// J6: `Ctrl+Shift+Left/Right` moves focus between panes -- driven here via
/// the real `pane-focused(int)` callback each `PaneSlot`'s click handler
/// invokes (`app.slint:733/747`), asserted against `active-pane`.
fn focus_move_updates_active_pane() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_split_pane_h();
    pump_ticks(1);
    // `do_split` focuses the newly-created pane (id 1), not the original
    // primary pane -- confirmed against the real callback below rather than
    // assumed.
    assert_eq!(
        h.ui.get_active_pane(),
        1,
        "splitting must focus the new pane"
    );

    h.ui.invoke_pane_focused(0);
    pump_ticks(1);
    assert_eq!(
        h.ui.get_active_pane(),
        0,
        "focusing pane 0 must move focus back"
    );

    h.ui.invoke_pane_focused(1);
    pump_ticks(1);
    assert_eq!(
        h.ui.get_active_pane(),
        1,
        "focusing pane 1 must update active-pane"
    );
}

/// J6/W7: broadcast-armed shows the docked bar + status pill, and the
/// targeting menu ("Broadcast target...") lets a subset be selected --
/// asserted via the same `broadcast-target-label` the status pill/docked bar
/// both read (`app.slint:1643/1910`), never a separate ad hoc string.
fn broadcast_toggle_and_target_menu() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_split_pane_h();
    h.ui.invoke_split_pane_v();
    pump_ticks(1);
    assert_eq!(active_tab_pane_count(&h), 3);

    assert!(!h.ui.get_broadcast_active(), "broadcast starts off");
    h.ui.invoke_toggle_broadcast();
    pump_ticks(1);
    assert!(h.ui.get_broadcast_active(), "toggle must arm broadcast");
    assert_eq!(
        h.ui.get_broadcast_target_label().as_str(),
        "all panes",
        "default target is every visible pane"
    );

    // Open the targeting menu (the docked bar's "Broadcast target..." pill,
    // element `bc-target-touch`) and select "Pane 2" only via its real
    // checkbox element (`broadcast-pane-checks` starts all-unchecked on open
    // -- `on_open_broadcast_target` clears the draft whenever the current
    // target isn't already `Custom`, see `controller/panes.rs`).
    find_by_id(&h.ui, "AppWindow::bc-target-touch").invoke_accessible_default_action();
    assert!(h.ui.get_broadcast_target_open(), "targeting menu must open");

    find_descendant_by_label(&h.ui.root_element(), "Pane 2").invoke_accessible_default_action();
    find_by_id(&h.ui, "AppWindow::apply-broadcast-btn").invoke_accessible_default_action();
    pump_ticks(1);

    assert!(
        !h.ui.get_broadcast_target_open(),
        "Apply must close the targeting menu"
    );
    assert_eq!(
        h.ui.get_broadcast_target_label().as_str(),
        "1 of 3 panes",
        "selecting exactly Pane 2 must produce an honest \"1 of 3 panes\" label"
    );
}

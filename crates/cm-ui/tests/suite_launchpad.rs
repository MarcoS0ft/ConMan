//! P8.4 Suite -- Launchpad (P6.14), covering the P6.17 Linux J1 / Windows W10
//! journey ("the empty/home tab renders the Launchpad... while reporting
//! status connected") that P8.2's three suites did not port (`support::
//! harness()` always uses `first_launch: true`, which never reaches the
//! Launchpad -- see `controller/mod.rs::assemble`'s `if first_launch {
//! open_local_tab } else if restore_snapshot.is_none() { open_empty_tab }`
//! branch). This suite uses `support::harness_with(false)` to reach the
//! `open_empty_tab` branch deterministically (an in-memory repo with no
//! session-tab snapshot to restore).

#![cfg(feature = "ui-introspection")]

mod support;

use support::{find_by_id, harness_with, pump_ticks};

#[test]
fn launchpad_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    empty_tab_shows_launchpad_while_connected();
    launchpad_quick_connect_opens_the_real_dialog();
    new_tab_button_opens_a_live_shell_not_launchpad();
}

/// J1/W10: a non-first-launch start with nothing to restore lands on the
/// Launchpad-fronted empty/home tab -- `is_empty: true` in the tab model,
/// `launchpad_open: true`, greeting text present, AND the tab's own reported
/// status is still `"connected"` (P6.14's specific claim: an empty tab is not
/// a broken/disconnected one, it is a real, live, empty local shell wearing
/// a friendlier front-end).
fn empty_tab_shows_launchpad_while_connected() {
    let (h, _repo, _provider) = harness_with(false);
    pump_ticks(1);

    assert!(
        h.ui.get_launchpad_open(),
        "a clean, non-first-launch start with nothing to restore must open on the Launchpad"
    );
    assert!(
        !h.ui.get_launchpad_greeting().is_empty(),
        "Launchpad must render a real (non-empty) greeting"
    );
    assert_eq!(
        h.ui.get_session_status().as_str(),
        "connected",
        "the empty/Launchpad tab is a live, connected local shell, not a disconnected placeholder"
    );
    find_by_id(&h.ui, "Launchpad::launchpad-quick-connect-btn");
    find_by_id(&h.ui, "Launchpad::launchpad-open-group-btn");
}

/// Launchpad's own "Quick connect" primary button must dispatch through the
/// exact same `AppWindow::quick-connect()` callback the tab-strip/palette
/// quick-connect affordance uses (`app.slint`'s `Launchpad { quick-connect =>
/// { root.quick-connect(); } }` binding) -- not a Launchpad-local dialog.
fn launchpad_quick_connect_opens_the_real_dialog() {
    let (h, _repo, _provider) = harness_with(false);
    pump_ticks(1);
    assert!(h.ui.get_launchpad_open());

    find_by_id(&h.ui, "Launchpad::launchpad-quick-connect-btn").invoke_accessible_default_action();
    assert!(
        h.ui.get_quick_connect_open(),
        "Launchpad's Quick connect button must open the real QuickConnectForm dialog"
    );
}

/// P6.14's "empty-vs-real distinction" (W10's `34-launchpad-new-tab.png`):
/// the `+`-button new-tab action opens a live local shell tab, never another
/// Launchpad -- the Launchpad only ever fronts the *first*, already-empty
/// slot, not every subsequently-opened tab.
fn new_tab_button_opens_a_live_shell_not_launchpad() {
    let (h, _repo, _provider) = harness_with(false);
    pump_ticks(1);
    assert!(h.ui.get_launchpad_open(), "starts on the Launchpad tab");

    find_by_id(&h.ui, "AppWindow::new-tab-btn").invoke_accessible_default_action();
    pump_ticks(1);
    assert!(
        !h.ui.get_launchpad_open(),
        "the new tab opened by the + button must be a live shell, not another Launchpad"
    );
}

//! Launchpad coverage for the Linux J1 / Windows W10 journey: the empty/home
//! tab renders the Launchpad while reporting connected status. The regular
//! `harness()` always uses `first_launch: true`, which never reaches the
//! Launchpad. This suite uses `support::harness_with(false)` to reach the
//! `open_empty_tab` branch deterministically (an in-memory repo with no
//! session-tab snapshot to restore).

#![cfg(feature = "ui-introspection")]

mod support;

use std::rc::Rc;

use i_slint_backend_testing::ElementHandle;
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use support::{find_by_id, harness_with, pump_ticks};

#[test]
fn launchpad_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    empty_tab_shows_launchpad_while_connected();
    home_shows_the_branded_wordmark();
    launchpad_scrolls_at_compact_height();
    new_tab_button_opens_a_live_shell_not_launchpad();
    empty_tab_is_titled_home_not_shell_n();
}

fn home_shows_the_branded_wordmark() {
    let (h, _repo, _provider) = harness_with(false);
    pump_ticks(1);
    assert!(h.ui.get_launchpad_open());
    find_by_id(&h.ui, "Launchpad::launchpad-wordmark");
}

/// J1/W10: a non-first-launch start with nothing to restore lands on the
/// Launchpad-fronted empty/home tab -- `is_empty: true` in the tab model,
/// `launchpad_open: true`, greeting text present, AND the tab's own reported
/// status is still `"connected"` (an empty tab is not
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
}

fn launchpad_scrolls_at_compact_height() {
    let (h, _repo, _provider) = harness_with(false);
    h.ui.window()
        .set_size(slint::LogicalSize::new(720.0, 420.0));
    let rows = (0..10)
        .map(|idx| cm_ui::RecentItem {
            id: idx,
            name: SharedString::from(format!("Recent {idx}")),
            meta: SharedString::from("just now"),
            kind: SharedString::from("SSH"),
            status: SharedString::from("disconnected"),
        })
        .collect::<Vec<_>>();
    h.ui.set_launchpad_recents(ModelRc::from(Rc::new(VecModel::from(rows))));
    pump_ticks(1);

    let scroll = find_by_id(&h.ui, "Launchpad::launchpad-scroll");
    let first_row = ElementHandle::find_by_element_id(&h.ui, "Launchpad::recent-item-row")
        .next()
        .expect("a recent row must be visible before scrolling");
    let initial_y = first_row.absolute_position().y;
    scroll.scroll(0.0, -10_000.0);
    pump_ticks(1);
    assert!(
        first_row.absolute_position().y < initial_y,
        "the compact Launchpad must scroll its content vertically"
    );
}

/// The "empty-vs-real distinction" (W10's `34-launchpad-new-tab.png`):
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

/// BUG-home-tab-shell-title: the Launchpad-fronted empty/home tab is not a
/// shell the user asked to open, so its tab-strip label must read "Home",
/// never fall through to the "shell N" numbering real local-terminal tabs
/// use (`tabs.rs::spawn_local_tab`). A subsequently-opened *real* local-shell
/// tab must still get that "shell N" label untouched.
fn empty_tab_is_titled_home_not_shell_n() {
    let (h, _repo, _provider) = harness_with(false);
    pump_ticks(1);
    assert!(h.ui.get_launchpad_open(), "starts on the Launchpad tab");

    let home_title =
        h.ui.get_tabs()
            .row_data(0)
            .expect("home tab row")
            .title
            .to_string();
    assert_eq!(
        home_title, "Home",
        "the Launchpad-fronted empty tab must be titled 'Home', not a 'shell N' label"
    );

    find_by_id(&h.ui, "AppWindow::new-tab-btn").invoke_accessible_default_action();
    pump_ticks(1);
    let real_shell_title =
        h.ui.get_tabs()
            .row_data(1)
            .expect("real shell tab row")
            .title
            .to_string();
    assert!(
        real_shell_title.starts_with("shell "),
        "a real local-shell tab opened afterwards must keep its 'shell N' label, got {real_shell_title:?}"
    );
}

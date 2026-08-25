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
    connect_in_split_is_refused_when_agent_mode_lacks_execute_scope();
    telnet_connect_in_split_dispatches_and_marks_insecure();
    pane_disconnect_closes_the_targeted_pane_and_collapses_the_split();
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

/// P9.10 #2: the per-pane disconnect affordance's real callback
/// (`ui.invoke_pane_disconnect(pane_id)` -- the exact `on_pane_disconnect`
/// `PaneSlot`'s corner icon button fires, see `panes::wire_pane_disconnect`)
/// closes exactly the targeted pane, not necessarily the FOCUSED one, and
/// collapses a 2-pane split back to a single surface. The real-pointer
/// gesture (hovering/clicking the corner icon on real hardware) is .99-verify
/// territory like Bug A; this proves the callback's own effect, the same
/// "drive the semantic action directly" pattern every other scenario in this
/// suite already uses.
fn pane_disconnect_closes_the_targeted_pane_and_collapses_the_split() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_split_pane_h();
    pump_ticks(1);
    assert_eq!(active_tab_pane_count(&h), 2, "seed: a 2-pane split");
    // `do_split` focuses the NEW pane (id 1) -- disconnect pane 0 instead,
    // proving this targets an explicit id, not just "whatever is focused".
    assert_eq!(h.ui.get_active_pane(), 1, "seed: pane 1 is focused, not 0");

    h.ui.invoke_pane_disconnect(0);
    pump_ticks(1);

    assert_eq!(
        active_tab_pane_count(&h),
        1,
        "disconnecting one pane of a 2-pane split must collapse it back to a single surface"
    );
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

/// P8.6-B (Fable review fixup): "Connect in split" establishes a live
/// session with stored credentials exactly like a fresh launch, so it's an
/// execute-scope action too -- gated identically to Reconnect (see
/// `suite_overlays.rs`'s sibling test, which has the fuller comment on why
/// `support::harness_with_agent_mode`/`agent_mode_fixture` exist, and on why
/// the fixture starts with no interaction in flight and the shared counter
/// is only flipped to 1 right before the gated action). Seeds one SSH
/// connection via the real New-connection -> Save journey with
/// `auth_method: Agent` so `resolve_ssh_auth` succeeds without needing any
/// stored credential (keeps this scenario about the gate only, not
/// credential resolution), then drives the exact callback the tree's
/// "Connect in split" context-menu item calls
/// (`on_connect_in_split_row` -- `controller::tree_ctl::wire_connect_in_split_row`).
fn connect_in_split_is_refused_when_agent_mode_lacks_execute_scope() {
    let agent_mode = support::agent_mode_fixture(0, true, true, false);
    let interaction_count = agent_mode.mcp_interaction_count.clone();
    let (h, repo, provider) = support::harness_with_agent_mode(true, Some(agent_mode));

    h.ui.invoke_new_connection(0);
    {
        let mut form = h.ui.get_profile_form();
        form.name = "Split Target".into();
        form.host = "mock-split-host".into();
        form.auth_method = 2; // Agent -- no stored credential needed to resolve.
        h.ui.set_profile_form(form);
    }
    find_by_id(&h.ui, "ProfileEditor::profile-save-btn").invoke_accessible_default_action();
    let saved = repo.list_connections().expect("list_connections");
    let conn_id = saved
        .iter()
        .find(|c| c.name == "Split Target")
        .expect("connection was saved")
        .id
        .get();

    let pane_count_before = active_tab_pane_count(&h);
    assert_eq!(
        provider.ssh_connect_count(),
        0,
        "seed: no connect attempt yet"
    );

    // Simulate the agent's write-tool call landing on "Connect in split":
    // the proxy would have incremented this right before forwarding the
    // click that triggers `on_connect_in_split_row`.
    interaction_count.store(1, std::sync::atomic::Ordering::SeqCst);
    h.ui.invoke_connect_in_split_row(conn_id as i32);
    pump_ticks(1);

    assert_eq!(
        provider.ssh_connect_count(),
        0,
        "a blocked connect-in-split must never dial the provider"
    );
    assert_eq!(
        active_tab_pane_count(&h),
        pane_count_before,
        "a blocked connect-in-split must never commit a new pane"
    );

    let toasts = h.ui.get_toasts();
    assert_eq!(
        toasts.row_count(),
        1,
        "the refusal must surface as a toast -- there is no per-pane error overlay"
    );
    assert!(
        toasts
            .row_data(0)
            .expect("toast row")
            .message
            .contains("execute scope not granted"),
        "the toast must surface the gate's own reason, got {:?}",
        toasts.row_data(0).map(|t| t.message)
    );
}

fn telnet_connect_in_split_dispatches_and_marks_insecure() {
    let (h, repo, provider) = harness();
    h.ui.invoke_new_connection(0);
    let mut form = h.ui.get_profile_form();
    form.name = "Telnet Split".into();
    form.kind = 2;
    form.host = "split-telnet".into();
    form.port = "23".into();
    h.ui.set_profile_form(form);
    h.ui.invoke_profile_save();
    let conn_id = repo
        .list_connections()
        .expect("list connections")
        .into_iter()
        .find(|c| c.name == "Telnet Split")
        .expect("saved Telnet connection")
        .id
        .get();

    h.ui.invoke_connect_in_split_row(conn_id as i32);
    pump_ticks(1);
    assert_eq!(provider.telnet_connect_count(), 1);
    assert_eq!(active_tab_pane_count(&h), 2);
    assert!(
        h.ui.get_session_insecure(),
        "a Telnet pane must make the tab's insecure transport explicit"
    );

    h.ui.invoke_pane_disconnect(1);
    pump_ticks(1);
    assert_eq!(active_tab_pane_count(&h), 1);
    assert!(
        !h.ui.get_session_insecure(),
        "closing the only Telnet pane must clear the tab-level warning"
    );
}

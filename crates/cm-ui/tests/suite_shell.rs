//! P8.2 Suite 2 — shell chrome: command palette open/filter/dispatch, tab
//! open/select/close, sidebar collapse, the status pill tracking live session
//! status, and the P6.17 "gap #5" tab-strip/sidebar geometry (first-tab left
//! inset, the nav/tab-strip divider) as logical-pixel assertions.
//!
//! One process, one `#[test]`, scenarios run sequentially, each against its
//! own fresh [`support::harness`].

#![cfg(feature = "ui-introspection")]

mod support;

use std::sync::{Arc, Mutex};

use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionRepository, ConnectionSettings,
    CredentialSource, SessionStatus, SessionTabEntry, SessionTabSnapshot, SettingsService,
    TelnetSettings,
};
use cm_storage::SqliteRepository;
use i_slint_backend_testing::ElementHandle;
use slint::Model;

use support::{
    find_by_id, find_descendant_by_label, find_singleton, harness, harness_with, nth_by_id,
    pump_ticks,
};

#[test]
fn shell_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    palette_open_filter_dispatch();
    tabs_open_select_close_via_elements();
    sidebar_collapse_toggles();
    status_pill_tracks_session_status();
    first_tab_inset_and_divider_present();
    home_tab_is_flagged_is_home_and_a_new_local_tab_is_not();
    tab_duplicate_is_available_for_a_saved_connection_but_not_for_quick_connect();
    tab_disconnect_keeps_the_tab_open_and_tab_reconnect_dials_again();
    telnet_quick_connect_reconnect_and_insecure_tab_state();
    telnet_saved_launch_dispatches_provider();
    telnet_session_restore_dispatches_provider();
    telnet_reconnect_respects_execute_gate();
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

// ── P9.10: tab context menu / Home pill (element-reachable pieces) ─────────
//
// The right-click menu itself (opening it, the real gesture) is out of this
// harness's reach the same way Bug A's hover-icon click was -- Slint's
// `ContextMenuArea`/`Menu`/`MenuItem` aren't queryable `ElementHandle`s the
// way an ordinary `Rectangle`/`TouchArea` is (no existing suite anywhere
// touches one). What IS reachable and is exactly what needs proving: the
// `TabItem` fields the menu's `if` guards key off (`is-home`/`can-duplicate`)
// compute correctly, and each new callback (`tab-reconnect`/`tab-disconnect`/
// `tab-duplicate`, whatever real UI element ends up invoking them) does the
// right thing -- driven directly via their auto-generated `invoke_*` methods,
// the same "drive the semantic action directly" pattern this whole suite
// file already uses for the palette/quick-connect.

/// Mirrors `suite_overlays.rs`'s identical helper (kept local here rather
/// than shared -- each P8.2 suite binary is its own process/compilation
/// unit, some duplication across them is the accepted cost, see this file's
/// module doc and `support`'s).
fn connect_ssh_via_quick_connect(
    h: &cm_ui::TestHarness,
    provider: &Arc<support::MockSessionProvider>,
    host: &str,
) -> Arc<Mutex<SessionStatus>> {
    let cell = Arc::new(Mutex::new(SessionStatus::Connecting));
    provider.script_next_remote(cell.clone());

    h.ui.invoke_quick_connect();
    h.ui.set_qc_kind(0); // SSH
    h.ui.set_qc_host(host.into());
    h.ui.set_qc_username("ops".into());
    h.ui.set_qc_auth_method(1); // Password
    h.ui.set_qc_secret("mock-password".into());
    find_by_id(&h.ui, "QuickConnectForm::qc-connect-btn").invoke_accessible_default_action();

    cell
}

/// The Home/Launchpad-fronted tab (`harness_with(false)`, mirrors
/// `suite_launchpad.rs`'s own way of reaching it) must be flagged
/// `is-home: true` -- and only it; a plain new local-shell tab opened
/// alongside it must NOT be.
fn home_tab_is_flagged_is_home_and_a_new_local_tab_is_not() {
    let (h, _repo, _provider) = harness_with(false);
    assert_eq!(tab_count(&h.ui), 1, "seed: the empty/Home tab only");
    assert!(
        h.ui.get_tabs().row_data(0).expect("home tab row").is_home,
        "the Launchpad-fronted Home tab must be flagged is-home"
    );

    find_by_id(&h.ui, "AppWindow::new-tab-btn").invoke_accessible_default_action();
    assert_eq!(tab_count(&h.ui), 2);
    assert!(
        !h.ui.get_tabs().row_data(1).expect("new tab row").is_home,
        "a plain new local-shell tab must NOT be flagged is-home"
    );
}

/// `TabItem::can_duplicate` (the "Duplicate" menu item's `if` guard) must be
/// true for a tree-launched saved connection (has an `origin_connection_id`
/// to relaunch), true for a plain local shell (duplicate = a new shell, no
/// origin needed), and false for a quick-connect-originated remote tab (no
/// stored settings to safely relaunch -- the spec's explicit "omit the item
/// rather than launch nothing" rule).
fn tab_duplicate_is_available_for_a_saved_connection_but_not_for_quick_connect() {
    let (h, repo, provider) = harness();

    // Local shell (harness()'s own seed tab) -- no origin, not remote.
    assert!(
        h.ui.get_tabs()
            .row_data(0)
            .expect("seed tab row")
            .can_duplicate,
        "a plain local shell must be duplicable (relaunch = a new shell)"
    );

    // A tree-launched saved SSH connection -- has an origin_connection_id.
    h.ui.invoke_new_connection(0);
    {
        let mut form = h.ui.get_profile_form();
        form.name = "Dup Target".into();
        form.host = "mock-dup-host".into();
        form.auth_method = 2; // Agent -- no stored credential needed to resolve.
        h.ui.set_profile_form(form);
    }
    find_by_id(&h.ui, "ProfileEditor::profile-save-btn").invoke_accessible_default_action();
    let saved = repo.list_connections().expect("list_connections");
    let row_idx = saved
        .iter()
        .position(|c| c.name == "Dup Target")
        .expect("connection was saved");
    h.ui.invoke_row_activated(row_idx as i32);
    pump_ticks(1);
    let saved_tab_idx = tab_count(&h.ui) - 1;
    assert!(
        h.ui.get_tabs()
            .row_data(saved_tab_idx)
            .expect("saved-connection tab row")
            .can_duplicate,
        "a tree-launched saved connection must be duplicable (has an origin_connection_id)"
    );

    // Quick-connect -- no origin_connection_id, and it IS remote.
    let _cell = connect_ssh_via_quick_connect(&h, &provider, "mock-qc-host");
    let qc_tab_idx = tab_count(&h.ui) - 1;
    assert!(
        !h.ui
            .get_tabs()
            .row_data(qc_tab_idx)
            .expect("quick-connect tab row")
            .can_duplicate,
        "a quick-connect-originated remote tab must NOT be duplicable -- no stored \
         settings to safely relaunch"
    );
}

/// "Disconnect" tears the session down but keeps the tab open in the same
/// Failed/error-overlay state a spontaneous disconnect already leaves a tab
/// in -- then "Reconnect" from that same tab dials the provider again.
/// Drives both new callbacks directly via their `invoke_*` methods (the real
/// gesture, opening the context menu and clicking an item, is .99-verify
/// territory -- see this section's header comment).
fn tab_disconnect_keeps_the_tab_open_and_tab_reconnect_dials_again() {
    let (h, _repo, provider) = harness();
    let _cell = connect_ssh_via_quick_connect(&h, &provider, "mock-host");
    let idx = h.ui.get_active_tab();
    assert_eq!(
        provider.ssh_connect_count(),
        1,
        "seed: the quick-connect dialed the provider exactly once"
    );
    let tabs_before = tab_count(&h.ui);

    h.ui.invoke_tab_disconnect(idx);
    pump_ticks(1);

    assert_eq!(
        tab_count(&h.ui),
        tabs_before,
        "Disconnect must keep the tab open, not close it"
    );
    assert!(
        h.ui.get_overlay_error(),
        "Disconnect must drop the tab into the error/reconnect-available overlay"
    );
    assert!(
        h.ui.get_error_reason().contains("Disconnected"),
        "the overlay must surface the disconnect's own reason, got {:?}",
        h.ui.get_error_reason()
    );
    assert_eq!(
        h.ui.get_tabs()
            .row_data(idx as usize)
            .expect("tab row")
            .status
            .as_str(),
        "error",
        "the tab strip's own status dot must reflect the disconnect"
    );

    h.ui.invoke_tab_reconnect(idx);
    pump_ticks(1);

    assert_eq!(
        provider.ssh_connect_count(),
        2,
        "Reconnect (from the same tab Disconnect left in place) must dial the \
         provider again"
    );
    assert!(
        h.ui.get_overlay_connecting(),
        "Reconnect must show the connecting overlay again"
    );
    assert!(!h.ui.get_overlay_error(), "the error overlay must clear");
}

fn telnet_quick_connect_reconnect_and_insecure_tab_state() {
    let (h, _repo, provider) = harness();
    h.ui.set_frame(slint::Image::from_rgba8(slint::SharedPixelBuffer::<
        slint::Rgba8Pixel,
    >::new(2, 2)));
    h.ui.invoke_quick_connect();
    h.ui.set_qc_kind(2);
    h.ui.set_qc_host("mock-telnet-host".into());
    h.ui.set_qc_port("2323".into());
    h.ui.set_qc_username("must-be-cleared".into());
    h.ui.set_qc_secret("must-be-cleared".into());
    h.ui.invoke_qc_connect();
    pump_ticks(1);

    assert_eq!(provider.telnet_connect_count(), 1);
    assert_eq!(
        h.ui.get_session_identity().as_str(),
        "mock-telnet-host:2323"
    );
    assert_eq!(h.ui.get_connecting_kind().as_str(), "TELNET");
    assert!(h.ui.get_session_insecure());
    let cleared_size = h.ui.get_frame().size();
    assert_eq!(
        (cleared_size.width, cleared_size.height),
        (0, 0),
        "fresh Telnet launch must clear the shared terminal frame"
    );
    assert_eq!(h.ui.get_qc_username().as_str(), "");
    assert_eq!(h.ui.get_qc_secret().as_str(), "");
    // Element-level theme contract: protocol/security presentation remains
    // present in both palettes (no pixel/screenshot machinery needed).
    for dark_mode in [false, true] {
        h.ui.set_dark_mode(dark_mode);
        pump_ticks(1);
        find_by_id(&h.ui, "AppWindow::insecure-transport-label");
        assert_eq!(h.ui.get_connecting_kind().as_str(), "TELNET");
        assert!(h.ui.get_session_insecure());
    }
    let telnet_idx = h.ui.get_active_tab();
    assert_eq!(
        h.ui.get_tabs()
            .row_data(telnet_idx as usize)
            .unwrap()
            .title
            .as_str(),
        "TELNET mock-telnet-host"
    );

    h.ui.invoke_tab_disconnect(telnet_idx);
    h.ui.invoke_tab_reconnect(telnet_idx);
    pump_ticks(1);
    assert_eq!(provider.telnet_connect_count(), 2);
    assert!(
        h.ui.get_session_insecure(),
        "reconnect must preserve INSECURE"
    );

    nth_by_id(&h.ui, "AppWindow::tab-item", 0).invoke_accessible_default_action();
    pump_ticks(1);
    assert!(
        !h.ui.get_session_insecure(),
        "local tab must clear INSECURE"
    );
    assert_eq!(h.ui.get_connecting_kind().as_str(), "");

    nth_by_id(&h.ui, "AppWindow::tab-item", telnet_idx as usize).invoke_accessible_default_action();
    pump_ticks(1);
    assert!(
        h.ui.get_session_insecure(),
        "switching back must restore INSECURE"
    );
}

fn telnet_saved_launch_dispatches_provider() {
    let (h, repo, provider) = harness();
    h.ui.invoke_new_connection(0);
    let mut form = h.ui.get_profile_form();
    form.name = "Saved Telnet".into();
    form.kind = 2;
    form.host = "saved-telnet".into();
    form.port = "23".into();
    h.ui.set_profile_form(form);
    h.ui.invoke_profile_save();

    let saved = repo.list_connections().expect("list connections");
    let idx = saved.iter().position(|c| c.name == "Saved Telnet").unwrap();
    h.ui.invoke_row_activated(idx as i32);
    pump_ticks(1);
    assert_eq!(provider.telnet_connect_count(), 1);
    assert!(h.ui.get_session_insecure());
    assert_eq!(h.ui.get_connecting_kind().as_str(), "TELNET");
}

fn telnet_session_restore_dispatches_provider() {
    let repo: Arc<dyn ConnectionRepository> =
        Arc::new(SqliteRepository::open_in_memory().expect("open repo"));
    let conn = Connection::new(
        ConnectionId::UNSAVED,
        None,
        "Restored Telnet".to_owned(),
        ConnectionKind::Telnet,
        ConnectionSettings::Telnet(TelnetSettings {
            host: "restored-telnet".to_owned(),
            port: 23,
        }),
        Some(CredentialSource::Prompt),
        0,
        1,
        1,
    )
    .expect("valid Telnet connection");
    let id = repo.upsert_connection(&conn).expect("save connection");
    let settings = SettingsService::new(repo.as_ref());
    settings
        .save_startup_behavior(1)
        .expect("save startup setting");
    settings
        .save_session_tabs(&SessionTabSnapshot {
            tabs: vec![SessionTabEntry::Connection(id)],
            active: 0,
        })
        .expect("save session snapshot");

    let provider = support::MockSessionProvider::new();
    let h = cm_ui::build_for_test(cm_ui::AppConfig {
        repo,
        secrets: Arc::new(support::NullCredentialStore),
        session_provider: provider.clone(),
        activation_rx: None,
        first_launch: false,
        agent_mode: None,
    });
    pump_ticks(1);
    assert_eq!(provider.telnet_connect_count(), 1);
    assert_eq!(h.ui.get_session_identity().as_str(), "restored-telnet:23");
    assert!(h.ui.get_session_insecure());
}

fn telnet_reconnect_respects_execute_gate() {
    let agent_mode = support::agent_mode_fixture(0, true, true, false);
    let interaction_count = agent_mode.mcp_interaction_count.clone();
    let (h, _repo, provider) = support::harness_with_agent_mode(true, Some(agent_mode));
    h.ui.invoke_quick_connect();
    h.ui.set_qc_kind(2);
    h.ui.set_qc_host("gated-telnet".into());
    h.ui.invoke_qc_connect();
    pump_ticks(1);
    assert_eq!(provider.telnet_connect_count(), 1);

    interaction_count.store(1, std::sync::atomic::Ordering::SeqCst);
    let idx = h.ui.get_active_tab();
    h.ui.invoke_tab_reconnect(idx);
    pump_ticks(1);
    assert_eq!(
        provider.telnet_connect_count(),
        1,
        "blocked Telnet reconnect must not dial the provider"
    );
    assert!(
        h.ui.get_error_reason()
            .contains("execute scope not granted")
    );

    let blocked_mode = support::agent_mode_fixture(1, true, true, false);
    let (blocked, _repo, blocked_provider) =
        support::harness_with_agent_mode(true, Some(blocked_mode));
    blocked.ui.invoke_quick_connect();
    blocked.ui.set_qc_kind(2);
    blocked.ui.set_qc_host("blocked-launch".into());
    blocked.ui.invoke_qc_connect();
    pump_ticks(1);
    assert_eq!(
        blocked_provider.telnet_connect_count(),
        0,
        "blocked Telnet launch must not dial the provider"
    );
    assert!(
        blocked
            .ui
            .get_error_reason()
            .contains("execute scope not granted")
    );
}

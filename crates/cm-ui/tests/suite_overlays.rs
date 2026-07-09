//! P8.2 Suite 3 — overlay lifecycle under mock time: the connecting overlay
//! holding indefinitely (the win-ui memo §C spinner race is gone by
//! construction -- nothing here is timing-sensitive, because nothing is
//! real), resolving to a failure with Reconnect/Edit, and toast
//! appearance/expiry. Every scenario advances [`i_slint_backend_testing::
//! mock_elapsed_time`] explicitly (via `support::pump_ticks`/`pump_until`) --
//! zero real sleeping, so the whole suite completes in wall-clock
//! milliseconds despite covering a 3.2-second toast auto-dismiss.
//!
//! Uses [`support::MockSessionProvider`]: `connect_ssh` hands out a session
//! whose reported [`cm_core::SessionStatus`] is whatever cell the scenario
//! installed via `script_next_remote` -- a scenario that never mutates the
//! cell after connecting therefore has a session that reports `Connecting`
//! forever, by construction, not by racing a real handshake against a
//! timeout.

#![cfg(feature = "ui-introspection")]

mod support;

use std::sync::{Arc, Mutex};

use cm_core::SessionStatus;
use i_slint_backend_testing::{ElementHandle, ElementRoot};

use support::{find_by_id, harness, nth_by_id, pump_ticks, pump_until};

#[test]
fn overlays_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    connecting_overlay_holds_indefinitely_and_chrome_stays_reachable();
    connecting_resolves_to_error_overlay_with_reconnect_and_edit();
    background_tab_failure_toasts_and_auto_expires();
    switching_tabs_shows_each_tabs_own_identity_not_the_others();
}

fn toast_count(ui: &cm_ui::AppWindow) -> usize {
    ElementHandle::find_by_element_type_name(ui, "Toast").count()
}

/// Drives the quick-connect SSH flow through the real dialog + Connect
/// button, with the provider scripted to report `Connecting` and never
/// anything else, then hands back the shared status cell so the caller can
/// move the session forward later. `host` is parameterized (P9.5 #3's
/// per-tab-identity scenario opens two SSH tabs to two different hosts to
/// prove they don't bleed into each other).
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

/// A mock `SessionProvider` that never resolves ⇒ the connecting overlay
/// holds indefinitely -- and stays pane-scoped: the tab strip and sidebar
/// stay reachable and actionable the whole time (the overlay covers only the
/// session area, per `app.slint`'s `session-area` cell -- see the
/// `ConnectingOverlay { x:0; y:0; width:100%; height:100%; }` binding, 100%
/// of that cell, not the window). A Cancel affordance exists throughout.
fn connecting_overlay_holds_indefinitely_and_chrome_stays_reachable() {
    let (h, _repo, provider) = harness();
    let _cell = connect_ssh_via_quick_connect(&h, &provider, "mock-host");

    assert!(
        h.ui.get_overlay_connecting(),
        "connecting overlay must show immediately"
    );
    assert!(!h.ui.get_overlay_error(), "no error overlay yet");
    assert!(
        !h.ui.get_quick_connect_open(),
        "quick-connect must have closed on Connect"
    );

    // Pump a generous number of ticks (~1.6s of mock time) with the status
    // cell never touched -- the overlay must still be holding. This is the
    // "indefinitely" proof: no timeout fires because none exists, and no
    // sleeping happened to get here (wall-clock: this whole scenario runs in
    // well under a second of real time -- see the suite's determinism note in
    // the P8.2 task report).
    pump_ticks(100);
    assert!(
        h.ui.get_overlay_connecting(),
        "connecting overlay must still hold after 1.6s of mock time with no session resolution"
    );
    assert!(!h.ui.get_overlay_error());

    // Pane-scoped: the overlay covers the session area only, not the window
    // -- its top edge sits below the 40px tab strip, and it is strictly
    // shorter than the full window.
    let overlay = support::find_singleton(&h.ui, "ConnectingOverlay");
    let window_size = h.ui.root_element().size();
    assert!(
        overlay.absolute_position().y > 0.0,
        "connecting overlay must start below the tab strip, not at the window top"
    );
    let overlay_size = overlay.size();
    assert!(
        overlay_size.height < window_size.height,
        "connecting overlay ({overlay_size:?}) must be shorter than the window \
         ({window_size:?}) -- pane-scoped, not full-window"
    );

    // A Cancel affordance exists throughout -- checked here, before the
    // chrome-reachability actions below (which deliberately open/select a
    // *different* tab and would otherwise switch the active tab away from
    // the still-connecting one, taking this very overlay off-screen).
    find_by_id(&h.ui, "ConnectingOverlay::connecting-cancel-btn");

    // Chrome stays hit-testable: the tab strip's new-tab button and the
    // sidebar toggle both still find and still work while the overlay holds.
    let tabs_before = ElementHandle::find_by_element_id(&h.ui, "AppWindow::tab-item").count();
    find_by_id(&h.ui, "AppWindow::new-tab-btn").invoke_accessible_default_action();
    assert_eq!(
        ElementHandle::find_by_element_id(&h.ui, "AppWindow::tab-item").count(),
        tabs_before + 1,
        "the tab strip must still be reachable/actionable while the connecting overlay holds"
    );

    let collapsed_before = h.ui.get_sidebar_collapsed();
    find_by_id(&h.ui, "AppWindow::sidebar-toggle-btn").invoke_accessible_default_action();
    assert_ne!(
        h.ui.get_sidebar_collapsed(),
        collapsed_before,
        "the sidebar toggle must still be reachable/actionable while the connecting overlay holds"
    );
}

/// Once the scripted session resolves to `Failed`, the tick loop must swap
/// the connecting overlay for the error overlay with Reconnect/Edit -- no
/// sleeping, driven purely by mutating the shared status cell and pumping
/// mock ticks.
fn connecting_resolves_to_error_overlay_with_reconnect_and_edit() {
    let (h, _repo, provider) = harness();
    let cell = connect_ssh_via_quick_connect(&h, &provider, "mock-host");
    assert!(h.ui.get_overlay_connecting());

    *cell.lock().expect("cell poisoned") = SessionStatus::Failed("mock connect failure".into());

    let resolved = pump_until(50, || h.ui.get_overlay_error());
    assert!(
        resolved,
        "error overlay must appear within 50 mock ticks (~800ms) of the session failing"
    );
    assert!(
        !h.ui.get_overlay_connecting(),
        "connecting overlay must clear once failed"
    );
    assert!(
        h.ui.get_error_reason().contains("mock connect failure"),
        "error overlay must surface the session's failure reason, got {:?}",
        h.ui.get_error_reason()
    );

    find_by_id(&h.ui, "ErrorOverlay::error-reconnect-btn");
    find_by_id(&h.ui, "ErrorOverlay::error-edit-btn");
}

/// A background (non-active) remote tab failing pushes a toast (P5.3b); the
/// toast's own 3.2s auto-dismiss `Timer` (`components.slint::Toast`) fires
/// under mock time exactly like any other Slint timer -- no real waiting for
/// a duration this suite's determinism/teeth relies on staying instant.
fn background_tab_failure_toasts_and_auto_expires() {
    let (h, _repo, provider) = harness();
    let cell = connect_ssh_via_quick_connect(&h, &provider, "mock-host"); // tab 1 (active), Connecting

    // Open a second local tab (tab 2) so the SSH tab becomes a background tab.
    find_by_id(&h.ui, "AppWindow::new-tab-btn").invoke_accessible_default_action();
    assert_ne!(
        h.ui.get_active_tab(),
        1,
        "the SSH tab must no longer be active"
    );

    assert_eq!(toast_count(&h.ui), 0, "no toast yet");
    *cell.lock().expect("cell poisoned") = SessionStatus::Failed("mock background failure".into());

    let appeared = pump_until(50, || toast_count(&h.ui) == 1);
    assert!(
        appeared,
        "a toast must appear for the background tab's failure"
    );

    // The toast's own Timer auto-dismisses after 3.2s -- pump well past that
    // (a further ~240 ticks * 16ms ≈ 3.84s of mock time) with zero real
    // sleeping.
    let dismissed = pump_until(240, || toast_count(&h.ui) == 0);
    assert!(
        dismissed,
        "the toast must auto-dismiss after its 3.2s mock-time timer, got count={}",
        toast_count(&h.ui)
    );
}

/// P9.5 #3: the actual bug the user hit -- alternating tabs while a connect
/// is in progress showed the *connecting* tab's content in the tab switched
/// to. `AppWindow::session-identity`/`connecting-kind` are single properties
/// shared by whichever tab is active (feeding `ConnectingOverlay`); this
/// proves `select_tab` re-pushes the TARGET tab's own cached identity/kind
/// rather than leaving whichever tab most recently connected "stuck" on
/// screen. Two SSH tabs to two different (mock) hosts, both left
/// `Connecting` (scripted, never resolved) -- switching between them must
/// always show the switched-to tab's own host, never the other one's.
fn switching_tabs_shows_each_tabs_own_identity_not_the_others() {
    let (h, _repo, provider) = harness();
    let _cell_a = connect_ssh_via_quick_connect(&h, &provider, "host-a"); // tab 1, Connecting
    assert!(
        h.ui.get_session_identity().contains("host-a"),
        "tab 1 must show its own identity right after connecting, got {:?}",
        h.ui.get_session_identity()
    );

    let _cell_b = connect_ssh_via_quick_connect(&h, &provider, "host-b"); // tab 2, Connecting
    assert_eq!(h.ui.get_active_tab(), 2, "the just-opened tab is active");
    assert!(
        h.ui.get_session_identity().contains("host-b"),
        "the just-opened tab must show its own identity, got {:?}",
        h.ui.get_session_identity()
    );

    // Switch back to tab 1 (host-a) -- this is the repro: before the fix,
    // session-identity/connecting-kind were only ever set at connect time,
    // never refreshed on a plain tab switch, so this would still show
    // host-b's identity (whichever tab connected most recently) bled into
    // tab 1's view.
    nth_by_id(&h.ui, "AppWindow::tab-item", 1).invoke_accessible_default_action();
    assert_eq!(h.ui.get_active_tab(), 1);
    assert!(
        h.ui.get_session_identity().contains("host-a"),
        "switching to tab 1 (host-a) must show host-a's identity, not host-b's; got {:?}",
        h.ui.get_session_identity()
    );
    assert_eq!(h.ui.get_connecting_kind().as_str(), "SSH");
    assert!(
        h.ui.get_overlay_connecting(),
        "tab 1 is still Connecting (scripted, never resolved)"
    );

    // And switching to tab 2 (host-b) shows host-b's again -- the isolation
    // holds in both directions, not just "whichever was opened last".
    nth_by_id(&h.ui, "AppWindow::tab-item", 2).invoke_accessible_default_action();
    assert!(
        h.ui.get_session_identity().contains("host-b"),
        "switching to tab 2 (host-b) must show host-b's identity, not host-a's; got {:?}",
        h.ui.get_session_identity()
    );
}

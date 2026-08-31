//! P8.2 Suite 2 — shell chrome: command palette open/filter/dispatch, tab
//! open/select/close, sidebar collapse, the status pill tracking live session
//! status, and the P6.17 "gap #5" tab-strip/sidebar geometry (first-tab left
//! inset, the nav/tab-strip divider) as logical-pixel assertions.
//!
//! One process, one `#[test]`, scenarios run sequentially, each against its
//! own fresh [`support::harness`].

#![cfg(feature = "ui-introspection")]

mod support;

use std::rc::Rc;
use std::sync::{Arc, Mutex};

use cm_core::{
    AppConfigStore, AppStateRepository, AppStateService, Connection, ConnectionId, ConnectionKind,
    ConnectionRepository, ConnectionSettings, CredentialSource, SessionStatus, SessionTabEntry,
    SessionTabSnapshot, SettingKey, SettingsService, TelnetSettings,
};
use cm_storage::SqliteRepository;
use i_slint_backend_testing::{ElementHandle, ElementRoot};
use slint::platform::{Key, PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition, Model, ModelRc, VecModel};

use support::{
    find_by_id, find_by_id_opt, find_descendant_by_label, find_singleton, harness, harness_with,
    nth_by_id, pump_ticks,
};

#[test]
fn shell_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    palette_open_filter_dispatch();
    tabs_open_select_close_via_elements();
    home_close_uses_home_specific_confirmation();
    home_only_does_not_trigger_active_connection_quit_warning();
    close_confirmation_cancel_and_dont_ask();
    close_confirmation_owns_terminal_keyboard();
    native_window_close_requests_confirmation();
    closing_remote_tab_terminates_instead_of_detaching();
    sidebar_collapse_toggles();
    status_pill_tracks_session_status();
    first_tab_inset_and_divider_present();
    overflowing_tabs_keep_active_and_new_tab_reachable();
    tab_navigation_tracks_measured_overflow();
    credential_rows_fit_default_and_minimum_sidebar_widths();
    split_pane_chrome_never_overlays_session_content();
    home_tab_is_flagged_is_home_and_a_new_local_tab_is_not();
    tab_duplicate_is_available_for_a_saved_connection_but_not_for_quick_connect();
    tab_disconnect_keeps_the_tab_open_and_tab_reconnect_dials_again();
    telnet_quick_connect_reconnect_and_insecure_tab_state();
    telnet_saved_launch_dispatches_provider();
    telnet_session_restore_dispatches_provider();
    telnet_reconnect_respects_execute_gate();
    tab_accessible_value_tracks_status_and_pane_count();
    activity_bar_accessible_checked_tracks_active_panel_and_sidebar();
}

fn home_only_does_not_trigger_active_connection_quit_warning() {
    let (h, _repo, _provider) = harness_with(false);
    h.ui.window().dispatch_event(WindowEvent::CloseRequested);
    assert!(
        !h.ui.get_close_confirm_open(),
        "Home's implementation shell is not an active user connection"
    );
}

fn home_close_uses_home_specific_confirmation() {
    let (h, _repo, _provider) = harness_with(false);
    h.ui.invoke_new_tab();
    assert_eq!(tab_count(&h.ui), 2);

    h.ui.invoke_close_tab(0);
    assert!(h.ui.get_close_confirm_open());
    assert_eq!(h.ui.get_close_confirm_title().as_str(), "Close Home tab?");
    assert_eq!(h.ui.get_close_confirm_action_label().as_str(), "Close Home");
    assert!(
        !h.ui
            .get_close_confirm_message()
            .to_ascii_lowercase()
            .contains("connection"),
        "Home must not be described as an active connection"
    );
    assert!(
        ElementHandle::find_by_element_id(&h.ui, "CloseConfirmationDialog::close-confirm-dont-ask")
            .next()
            .is_none(),
        "Home close is a distinct decision and must not disable active-connection warnings"
    );

    h.ui.invoke_close_confirm_accept();
    assert_eq!(tab_count(&h.ui), 1);
    assert!(
        !h.ui.get_tabs().row_data(0).expect("remaining tab").is_home,
        "closing Home must preserve the connection tab"
    );
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
    assert!(
        h.ui.get_close_confirm_open(),
        "closing a connected local tab must ask for confirmation"
    );
    h.ui.invoke_close_confirm_accept();

    assert_eq!(
        tab_count(&h.ui),
        1,
        "closing tab 1 must leave exactly one tab"
    );
}

fn closing_remote_tab_terminates_instead_of_detaching() {
    let (h, _repo, provider) = harness();
    let cell = connect_ssh_via_quick_connect(&h, &provider, "close-me");
    *cell.lock().expect("status lock poisoned") = SessionStatus::Connected;
    h.ui.invoke_split_pane_h();
    let remote_idx = h.ui.get_active_tab() as usize;
    let shutdowns_before = provider.shutdown_count();

    h.ui.invoke_close_tab(remote_idx as i32);

    assert!(
        h.ui.get_close_confirm_open(),
        "an active remote tab must not close without confirmation"
    );
    assert_eq!(
        provider.shutdown_count(),
        shutdowns_before,
        "opening the confirmation must not terminate a session"
    );
    h.ui.invoke_close_confirm_accept();

    assert_eq!(
        provider.shutdown_count(),
        shutdowns_before + 2,
        "closing a tab must terminate both its connected remote session and its split session"
    );
    assert_eq!(
        h.ui.get_detached_count(),
        0,
        "closing a tab must not implicitly detach its session"
    );
}

fn close_confirmation_cancel_and_dont_ask() {
    let (h, _repo, _provider) = harness();

    // The same callback Ctrl+Shift+W and the palette's Close pane use. In an
    // unsplit tab, closing its only pane is a tab-close intent.
    h.ui.invoke_close_pane();
    assert!(h.ui.get_close_confirm_open());
    let dialog = find_singleton(&h.ui, "CloseConfirmationDialog");
    find_descendant_by_label(&dialog, "Don't ask again for this kind of close");
    find_descendant_by_label(&dialog, "Cancel");
    find_descendant_by_label(&dialog, "Close tab");

    h.ui.set_close_confirm_dont_ask(true);
    h.ui.invoke_close_confirm_cancel();
    assert!(!h.ui.get_close_confirm_open());
    assert!(
        SettingsService::new(h.config_store.as_ref())
            .load()
            .expect("load settings after cancel")
            .confirm_close_active_tab,
        "Cancel must not persist Don't ask again"
    );

    h.ui.invoke_close_tab(0);
    h.ui.set_close_confirm_dont_ask(true);
    h.ui.invoke_close_confirm_accept();
    assert!(
        !h.ui.get_settings_confirm_close_active_tab(),
        "the live Settings value must follow a confirmed Don't ask again"
    );
    assert!(
        !SettingsService::new(h.config_store.as_ref())
            .load()
            .expect("load settings after confirm")
            .confirm_close_active_tab,
        "Confirm must persist Don't ask again"
    );

    // Home is not an active connection. Its distinct confirmation remains
    // enabled and cannot alter the active-connection preference.
    h.ui.invoke_close_tab(0);
    assert!(h.ui.get_close_confirm_open());
    assert_eq!(h.ui.get_close_confirm_title().as_str(), "Close Home tab?");
    h.ui.invoke_close_confirm_cancel();
}

fn native_window_close_requests_confirmation() {
    let (h, _repo, _provider) = harness();
    h.ui.window().dispatch_event(WindowEvent::CloseRequested);
    assert!(
        h.ui.get_close_confirm_open(),
        "the native window close entry point must keep the window and ask"
    );
    assert_eq!(h.ui.get_close_confirm_action_label().as_str(), "Quit");
    h.ui.set_close_confirm_dont_ask(true);
    h.ui.invoke_close_confirm_cancel();
    assert!(
        SettingsService::new(h.config_store.as_ref())
            .load()
            .expect("load settings after quit cancel")
            .confirm_quit_active_connections,
        "cancelling native close must not alter the preference"
    );

    h.ui.window().dispatch_event(WindowEvent::CloseRequested);
    h.ui.set_close_confirm_dont_ask(true);
    h.ui.invoke_close_confirm_accept();
    assert!(
        !SettingsService::new(h.config_store.as_ref())
            .load()
            .expect("load settings after quit confirm")
            .confirm_quit_active_connections,
        "confirmed Don't ask again must persist for native window close"
    );

    // Some native backends issue a second close request while hiding. The
    // confirmed-quit guard must not reopen the dialog.
    h.ui.window().dispatch_event(WindowEvent::CloseRequested);
    assert!(!h.ui.get_close_confirm_open());
}

fn close_confirmation_owns_terminal_keyboard() {
    let (h, _repo, provider) = harness();
    let terminal = find_by_id(&h.ui, "TerminalSurface::ta");
    let origin = terminal.absolute_position();
    let size = terminal.size();
    let position = LogicalPosition::new(origin.x + size.width / 2.0, origin.y + size.height / 2.0);
    h.ui.window()
        .dispatch_event(WindowEvent::PointerMoved { position });
    h.ui.window().dispatch_event(WindowEvent::PointerPressed {
        position,
        button: PointerEventButton::Left,
    });
    h.ui.window().dispatch_event(WindowEvent::PointerReleased {
        position,
        button: PointerEventButton::Left,
    });

    h.ui.invoke_close_tab(0);
    let before = provider.terminal_key_input_count();

    // Automation/introspection can invoke the controller callback without a
    // physical Slint event; that boundary must be guarded too.
    h.ui.invoke_key_input("q".into(), 0, 0);
    assert_eq!(provider.terminal_key_input_count(), before);

    h.ui.window()
        .dispatch_event(WindowEvent::KeyPressed { text: "x".into() });
    h.ui.window()
        .dispatch_event(WindowEvent::KeyReleased { text: "x".into() });
    assert!(h.ui.get_close_confirm_open());
    assert_eq!(provider.terminal_key_input_count(), before);

    // Modal traversal is explicit because its top-level capture owns every
    // key before the focused terminal can see it. Cancel is the safe initial
    // target, then Tab cycles Confirm -> checkbox -> Cancel.
    assert_eq!(h.ui.get_close_confirm_focus_index(), 1);
    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Tab.into(),
    });
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Tab.into(),
    });
    assert_eq!(h.ui.get_close_confirm_focus_index(), 2);
    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Tab.into(),
    });
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Tab.into(),
    });
    assert_eq!(h.ui.get_close_confirm_focus_index(), 0);

    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Space.into(),
    });
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Space.into(),
    });
    assert!(h.ui.get_close_confirm_dont_ask());
    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Space.into(),
    });
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Space.into(),
    });
    assert!(!h.ui.get_close_confirm_dont_ask());

    // Shift+Tab wraps backward to Confirm and owns both modifier phases.
    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Shift.into(),
    });
    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Tab.into(),
    });
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Tab.into(),
    });
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Shift.into(),
    });
    assert_eq!(h.ui.get_close_confirm_focus_index(), 2);
    assert_eq!(provider.terminal_key_input_count(), before);

    // The shell-level Ctrl+K capture must also yield to the modal.
    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Control.into(),
    });
    h.ui.window()
        .dispatch_event(WindowEvent::KeyPressed { text: "k".into() });
    h.ui.window()
        .dispatch_event(WindowEvent::KeyReleased { text: "k".into() });
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Control.into(),
    });
    assert!(!h.ui.get_palette_open());
    assert_eq!(provider.terminal_key_input_count(), before);

    // Return activates the focused Cancel button, but its release remains
    // modal-owned after the callback closes the dialog.
    h.ui.set_close_confirm_focus_index(1);
    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Return.into(),
    });
    assert!(!h.ui.get_close_confirm_open());
    assert!(h.ui.get_close_confirm_key_guard_active());
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Return.into(),
    });
    assert!(!h.ui.get_close_confirm_key_guard_active());
    assert_eq!(provider.terminal_key_input_count(), before);

    // Reopen for the Escape phase-pair contract.
    h.ui.invoke_close_tab(0);

    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Escape.into(),
    });
    assert!(!h.ui.get_close_confirm_open());
    assert!(
        h.ui.get_close_confirm_key_guard_active(),
        "Escape key-up must remain owned after its key-down cancels the modal"
    );
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Escape.into(),
    });
    assert!(!h.ui.get_close_confirm_key_guard_active());
    assert_eq!(provider.terminal_key_input_count(), before);

    // Prove the same focused terminal route resumes after the modal closes.
    h.ui.window()
        .dispatch_event(WindowEvent::KeyPressed { text: "x".into() });
    assert!(provider.terminal_key_input_count() > before);

    // Confirm is independently keyboard-activatable and still owns its
    // release after the destructive callback replaces the last tab.
    let shutdowns_before = provider.shutdown_count();
    h.ui.invoke_close_tab(0);
    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Tab.into(),
    });
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Tab.into(),
    });
    assert_eq!(h.ui.get_close_confirm_focus_index(), 2);
    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Return.into(),
    });
    assert!(!h.ui.get_close_confirm_open());
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Return.into(),
    });
    assert!(!h.ui.get_close_confirm_key_guard_active());
    assert_eq!(provider.shutdown_count(), shutdowns_before + 1);
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

/// P10.3 VQ-3: the tab viewport may overflow, but the selected tab is
/// automatically revealed and the New Tab affordance is pinned outside the
/// scrolling region.  This uses the real button repeatedly at the observed
/// 900 px boundary rather than constructing a synthetic tab model.
fn overflowing_tabs_keep_active_and_new_tab_reachable() {
    let (h, _repo, _provider) = harness();
    h.ui.window()
        .set_size(slint::LogicalSize::new(900.0, 600.0));

    for _ in 0..8 {
        find_by_id(&h.ui, "AppWindow::new-tab-btn").invoke_accessible_default_action();
    }
    pump_ticks(1);

    let viewport = find_by_id(&h.ui, "AppWindow::tabs-viewport");
    let active_index = h.ui.get_active_tab() as usize;
    let active = nth_by_id(&h.ui, "AppWindow::tab-item", active_index);
    assert_horizontally_contained(&active, &viewport, "active overflow tab");

    let new_tab = find_by_id(&h.ui, "AppWindow::new-tab-btn");
    let window = h.ui.root_element();
    assert_horizontally_contained(&new_tab, &window, "pinned New Tab action");

    // Overflow navigation is itself a real, pinned action. Moving to the
    // previous tab must select and reveal it rather than merely shifting
    // pixels while leaving the active tab hidden.
    let previous = find_by_id(&h.ui, "AppWindow::tab-scroll-left-btn");
    previous.invoke_accessible_default_action();
    pump_ticks(1);
    assert_eq!(h.ui.get_active_tab() as usize, active_index - 1);
    let previous_active = nth_by_id(&h.ui, "AppWindow::tab-item", active_index - 1);
    assert_horizontally_contained(&previous_active, &viewport, "previous overflow tab");

    // It remains a real, usable action after overflow and reveals the newly
    // active tab without an outer-window resize.
    let before = h.ui.get_tabs().row_count();
    new_tab.invoke_accessible_default_action();
    pump_ticks(1);
    assert_eq!(h.ui.get_tabs().row_count(), before + 1);
    let newest = nth_by_id(&h.ui, "AppWindow::tab-item", h.ui.get_active_tab() as usize);
    assert_horizontally_contained(&newest, &viewport, "newly active overflow tab");
}

/// The navigation affordances are governed by actual available strip width,
/// not an arbitrary tab count. Two tabs fit beside a minimum sidebar at this
/// boundary, then overflow when the same sidebar is widened to its supported
/// maximum. The active item and pinned New Tab action remain reachable in
/// both states.
fn tab_navigation_tracks_measured_overflow() {
    let (h, _repo, _provider) = harness();
    h.ui.window()
        .set_size(slint::LogicalSize::new(900.0, 600.0));
    h.ui.set_sidebar_width(180);
    find_by_id(&h.ui, "AppWindow::new-tab-btn").invoke_accessible_default_action();
    pump_ticks(1);

    assert_eq!(h.ui.get_tabs().row_count(), 2);
    assert!(
        find_by_id_opt(&h.ui, "AppWindow::tab-scroll-left-btn").is_none()
            && find_by_id_opt(&h.ui, "AppWindow::tab-scroll-right-btn").is_none(),
        "tab navigation must stay absent while both tabs fit"
    );
    let viewport = find_by_id(&h.ui, "AppWindow::tabs-viewport");
    let active = nth_by_id(&h.ui, "AppWindow::tab-item", 1);
    assert_horizontally_contained(&active, &viewport, "fitting active tab");

    h.ui.set_sidebar_width(480);
    pump_ticks(1);
    let previous = find_by_id(&h.ui, "AppWindow::tab-scroll-left-btn");
    let next = find_by_id(&h.ui, "AppWindow::tab-scroll-right-btn");
    let narrow_viewport = find_by_id(&h.ui, "AppWindow::tabs-viewport");
    let narrow_active = nth_by_id(&h.ui, "AppWindow::tab-item", 1);
    assert_horizontally_contained(
        &narrow_active,
        &narrow_viewport,
        "active tab after measured overflow",
    );
    assert_horizontally_contained(
        &find_by_id(&h.ui, "AppWindow::new-tab-btn"),
        &h.ui.root_element(),
        "pinned New Tab under measured overflow",
    );

    previous.invoke_accessible_default_action();
    pump_ticks(1);
    assert_eq!(h.ui.get_active_tab(), 0);
    assert_horizontally_contained(
        &nth_by_id(&h.ui, "AppWindow::tab-item", 0),
        &narrow_viewport,
        "previous tab reached through overflow navigation",
    );

    next.invoke_accessible_default_action();
    pump_ticks(1);
    assert_eq!(h.ui.get_active_tab(), 1);
    assert_horizontally_contained(
        &nth_by_id(&h.ui, "AppWindow::tab-item", 1),
        &narrow_viewport,
        "next tab reached through overflow navigation",
    );
}

/// P10.3 VQ-4 (Credentials): long user data must yield to row actions and
/// panel bounds.  Check both the normal 252 px panel and its supported 180 px
/// minimum with the same intentionally oversized synthetic values.
fn credential_rows_fit_default_and_minimum_sidebar_widths() {
    let (h, _repo, _provider) = harness();
    h.ui.window()
        .set_size(slint::LogicalSize::new(900.0, 600.0));
    find_by_id(&h.ui, "AppWindow::keys-panel-btn").invoke_accessible_default_action();
    h.ui.set_credentials(ModelRc::from(Rc::new(VecModel::from(vec![
        cm_ui::CredRow {
            id: 1,
            label: "A deliberately long synthetic credential label for geometry".into(),
            kind: "SSH Key+PP".into(),
            username: "synthetic-user-with-a-deliberately-long-name".into(),
            is_folder: false,
            expanded: false,
            selected: false,
            depth: 0,
            used_by_label: "Used by 99 connections".into(),
        },
    ]))));

    for sidebar_width in [252, 180] {
        h.ui.set_sidebar_width(sidebar_width);
        pump_ticks(1);

        let panel = find_by_id(&h.ui, "AppWindow::credentials-panel");
        let heading = find_by_id(&h.ui, "AppWindow::credentials-heading");
        assert_eq!(
            heading.accessible_label().as_deref(),
            Some("CREDENTIALS"),
            "credential panel must expose its user-facing name"
        );

        let row = nth_by_id(&h.ui, "AppWindow::cred-row", 0);
        let name = find_by_id(&h.ui, "CredTreeRow::cred-name");
        let username = find_by_id(&h.ui, "CredTreeRow::cred-username");
        assert_horizontally_contained(&row, &panel, "credential row");
        assert_horizontally_contained(&name, &row, "elided credential name");
        assert_horizontally_contained(&username, &row, "elided credential username");

        let row_position = row.absolute_position();
        h.ui.window().dispatch_event(WindowEvent::PointerMoved {
            position: slint::LogicalPosition::new(
                row_position.x + 20.0,
                row_position.y + row.size().height / 2.0,
            ),
        });
        pump_ticks(1);
        let edit = find_descendant_by_label(&row, "Edit");
        let delete = find_descendant_by_label(&row, "Delete");
        assert_horizontally_contained(&edit, &row, "credential Edit action");
        assert_horizontally_contained(&delete, &row, "credential Delete action");
        assert_horizontally_contained(&name, &row, "credential name beside actions");
        assert_horizontally_contained(&username, &row, "credential username beside actions");

        for id in [
            "AppWindow::new-folder-btn",
            "AppWindow::new-credential-btn",
            "AppWindow::cred-filter-field",
        ] {
            assert_horizontally_contained(&find_by_id(&h.ui, id), &panel, id);
        }
    }
}

/// P10.3 VQ-6: each split reserves a real chrome row above its content.  At
/// the 900 px window and minimum sidebar width, both terminal surfaces must
/// begin below that row and the disconnect action must fit entirely within
/// it, so neither painting nor hit-testing can overlap session pixels.
fn split_pane_chrome_never_overlays_session_content() {
    let (h, _repo, _provider) = harness();
    h.ui.window()
        .set_size(slint::LogicalSize::new(900.0, 600.0));
    h.ui.set_sidebar_width(180);
    h.ui.invoke_split_pane_h();
    pump_ticks(1);

    let panes: Vec<_> = ElementHandle::find_by_element_type_name(&h.ui, "PaneSlot").collect();
    assert_eq!(
        panes.len(),
        2,
        "a horizontal split must expose two PaneSlots"
    );
    for (index, pane) in panes.iter().enumerate() {
        let content = pane
            .query_descendants()
            .match_id("PaneSlot::pane-content")
            .find_first()
            .unwrap_or_else(|| panic!("pane {index} has no reserved content area"));
        let chrome = pane
            .query_descendants()
            .match_id("PaneSlot::pane-chrome")
            .find_first()
            .unwrap_or_else(|| panic!("pane {index} has no action chrome"));
        let disconnect = find_descendant_by_label(pane, "Disconnect this pane");

        let chrome_bottom = chrome.absolute_position().y + chrome.size().height;
        let content_top = content.absolute_position().y;
        assert!(
            content_top >= chrome_bottom,
            "pane {index} content starts at {content_top}, above chrome bottom {chrome_bottom}"
        );
        assert_horizontally_contained(&disconnect, &chrome, "pane disconnect action");
        let action_bottom = disconnect.absolute_position().y + disconnect.size().height;
        assert!(
            action_bottom <= chrome_bottom,
            "pane {index} disconnect action extends into session content"
        );
    }
}

fn assert_horizontally_contained(inner: &ElementHandle, outer: &ElementHandle, description: &str) {
    let inner_left = inner.absolute_position().x;
    let inner_right = inner_left + inner.size().width;
    let outer_left = outer.absolute_position().x;
    let outer_right = outer_left + outer.size().width;
    const EPSILON: f32 = 0.5;
    assert!(
        inner_left + EPSILON >= outer_left && inner_right <= outer_right + EPSILON,
        "{description} bounds {inner_left}..{inner_right} escape container {outer_left}..{outer_right}"
    );
}

fn tab_accessible_value_tracks_status_and_pane_count() {
    let (h, _repo, provider) = harness();
    assert_eq!(
        nth_by_id(&h.ui, "AppWindow::tab-item", 0)
            .accessible_value()
            .as_deref(),
        Some("connected")
    );

    h.ui.invoke_split_pane_h();
    h.ui.invoke_split_pane_v();
    pump_ticks(1);
    assert_eq!(
        nth_by_id(&h.ui, "AppWindow::tab-item", 0)
            .accessible_value()
            .as_deref(),
        Some("connected · 3 panes")
    );

    let status = connect_ssh_via_quick_connect(&h, &provider, "status-parity-host");
    assert_eq!(
        nth_by_id(&h.ui, "AppWindow::tab-item", 1)
            .accessible_value()
            .as_deref(),
        Some("connecting")
    );
    *status.lock().expect("status lock poisoned") =
        SessionStatus::Failed("expected parity failure".into());
    assert!(support::pump_until(50, || {
        nth_by_id(&h.ui, "AppWindow::tab-item", 1)
            .accessible_value()
            .as_deref()
            == Some("error")
    }));
}

fn activity_bar_accessible_checked_tracks_active_panel_and_sidebar() {
    let (h, _repo, _provider) = harness();
    let checked = |id: &str| {
        find_by_id(&h.ui, id)
            .accessible_checked()
            .unwrap_or_else(|| panic!("{id} must expose accessible-checked"))
    };

    assert!(checked("AppWindow::connections-panel-btn"));
    assert!(!checked("AppWindow::keys-panel-btn"));
    assert!(!checked("AppWindow::settings-panel-btn"));

    find_by_id(&h.ui, "AppWindow::keys-panel-btn").invoke_accessible_default_action();
    assert!(!checked("AppWindow::connections-panel-btn"));
    assert!(checked("AppWindow::keys-panel-btn"));
    assert!(!checked("AppWindow::settings-panel-btn"));

    find_by_id(&h.ui, "AppWindow::settings-panel-btn").invoke_accessible_default_action();
    assert!(!checked("AppWindow::keys-panel-btn"));
    assert!(checked("AppWindow::settings-panel-btn"));

    assert!(!checked("AppWindow::sidebar-toggle-btn"));
    find_by_id(&h.ui, "AppWindow::sidebar-toggle-btn").invoke_accessible_default_action();
    assert!(h.ui.get_sidebar_collapsed());
    assert!(checked("AppWindow::sidebar-toggle-btn"));
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
    assert!(h.ui.get_close_confirm_open());
    h.ui.invoke_close_confirm_accept();
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
    assert!(h.ui.get_close_confirm_open());
    h.ui.invoke_close_confirm_accept();
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

    let shutdowns_before_close = provider.shutdown_count();
    h.ui.invoke_close_tab(telnet_idx);
    assert!(h.ui.get_close_confirm_open());
    h.ui.invoke_close_confirm_accept();
    assert_eq!(
        provider.shutdown_count(),
        shutdowns_before_close + 1,
        "closing the Telnet tab must terminate its session"
    );
    assert_eq!(h.ui.get_detached_count(), 0);

    h.ui.invoke_quick_connect();
    h.ui.set_qc_kind(2);
    h.ui.set_qc_host("mock-telnet-host".into());
    h.ui.set_qc_port("2323".into());
    h.ui.invoke_qc_connect();
    pump_ticks(1);
    assert_eq!(
        provider.telnet_connect_count(),
        3,
        "the same Telnet endpoint must be connectable again after closing its tab"
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
    let sqlite = Arc::new(SqliteRepository::open_in_memory().expect("open repo"));
    let repo: Arc<dyn ConnectionRepository> = sqlite.clone();
    let app_state: Arc<dyn AppStateRepository> = sqlite.clone();
    let config_store: Arc<dyn AppConfigStore> = Arc::new(support::MemoryConfigStore::default());
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
    SettingsService::new(config_store.as_ref())
        .set(SettingKey::Startup, "restore")
        .expect("save startup setting");
    AppStateService::new(app_state.as_ref())
        .save_session_tabs(&SessionTabSnapshot {
            tabs: vec![SessionTabEntry::Connection(id)],
            active: 0,
        })
        .expect("save session snapshot");

    let provider = support::MockSessionProvider::new();
    let h = cm_ui::build_for_test(cm_ui::AppConfig {
        repo,
        import_repo: sqlite,
        config_store,
        config_path: std::path::PathBuf::from("conman.ini"),
        app_state,
        build_identity: cm_ui::BuildIdentity::default(),
        secrets: Arc::new(support::NullCredentialStore),
        session_provider: provider.clone(),
        secure_clipboard_root: None,
        activation_rx: None,
        first_launch: false,
        agent_mode: None,
    });
    pump_ticks(1);
    assert_eq!(provider.telnet_connect_count(), 1);
    assert_eq!(h.ui.get_session_identity().as_str(), "Restored Telnet");
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

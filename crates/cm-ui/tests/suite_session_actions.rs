//! Contextual tab-strip Session Actions menu and focused-pane routing.

#![cfg(feature = "ui-introspection")]

mod support;

use cm_core::RdpInputEvent;
use slint::platform::{Key, PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition, Model};

use support::{
    find_by_id, find_descendant_by_label, find_descendant_by_label_opt, harness, pump_ticks,
};

#[test]
fn contextual_session_actions_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    terminal_menu_and_split_targeting();
    rdp_menu_and_split_targeting();
}

fn open_menu(ui: &cm_ui::AppWindow) -> i_slint_backend_testing::ElementHandle {
    find_by_id(ui, "AppWindow::session-actions-btn").invoke_accessible_default_action();
    assert!(ui.get_session_actions_open());
    find_by_id(ui, "AppWindow::session-actions-menu")
}

fn terminal_menu_and_split_targeting() {
    let (h, _repo, provider) = harness();

    h.ui.invoke_open_palette();
    assert!(palette_has(&h.ui, "Copy Visible Screen"));
    assert!(!palette_has(&h.ui, "Send Alt+Tab"));
    h.ui.set_palette_open(false);

    let menu = open_menu(&h.ui);
    assert!(find_descendant_by_label_opt(&menu, "Copy Visible Screen").is_some());
    assert!(find_descendant_by_label_opt(&menu, "Copy All Scrollback").is_some());
    assert!(find_descendant_by_label_opt(&menu, "Paste").is_some());
    assert!(find_descendant_by_label_opt(&menu, "Find").is_some());
    assert!(find_descendant_by_label_opt(&menu, "Send Alt+Tab").is_none());
    find_descendant_by_label(&menu, "Copy All Scrollback").invoke_accessible_default_action();
    assert!(!h.ui.get_session_actions_open());
    assert_eq!(provider.search_request_sessions(), vec![0]);
    pump_ticks(1); // drain the nonblocking buffer reply into the clipboard worker

    h.ui.invoke_split_pane_h();
    pump_ticks(1);
    assert_eq!(h.ui.get_active_pane(), 1);
    let menu = open_menu(&h.ui);
    find_descendant_by_label(&menu, "Copy All Scrollback").invoke_accessible_default_action();
    assert_eq!(
        provider.search_request_sessions(),
        vec![0, 1],
        "the action must target the focused extra terminal pane"
    );

    h.ui.invoke_pane_focused(0);
    let menu = open_menu(&h.ui);
    find_descendant_by_label(&menu, "Copy All Scrollback").invoke_accessible_default_action();
    assert_eq!(
        provider.search_request_sessions(),
        vec![0, 1, 0],
        "focus returning to pane 0 must route back to its session"
    );
}

fn rdp_menu_and_split_targeting() {
    let (h, _repo, provider) = harness();
    h.ui.invoke_quick_connect();
    h.ui.set_qc_kind(1);
    h.ui.set_qc_host("rdp-actions.example.invalid".into());
    h.ui.set_qc_username("synthetic-user".into());
    h.ui.set_qc_secret("synthetic-password".into());
    h.ui.invoke_qc_connect();
    pump_ticks(1);
    assert_eq!(provider.rdp_connect_count(), 1);

    h.ui.invoke_open_palette();
    assert!(palette_has(&h.ui, "Send Ctrl+Alt+Delete"));
    assert!(!palette_has(&h.ui, "Copy Visible Screen"));
    h.ui.set_palette_open(false);

    let menu = open_menu(&h.ui);
    assert!(find_descendant_by_label_opt(&menu, "Send Ctrl+Alt+Delete").is_some());
    assert!(find_descendant_by_label_opt(&menu, "Send Windows/Super").is_some());
    assert!(find_descendant_by_label_opt(&menu, "Send Alt+Tab").is_some());
    assert!(find_descendant_by_label_opt(&menu, "Release Modifiers").is_some());
    assert!(find_descendant_by_label_opt(&menu, "Copy Visible Screen").is_none());

    // RDP has separate down/up callbacks. Esc dismisses only after its key-up
    // so neither half of the local menu gesture can leak to the destination.
    h.ui.invoke_rdp_key_down("".into(), 4, 0);
    assert!(h.ui.get_session_actions_open());
    h.ui.invoke_rdp_key_up("".into(), 4, 0);
    assert!(!h.ui.get_session_actions_open());
    assert!(provider.rdp_keyboard_events_for(1).is_empty());

    let menu = open_menu(&h.ui);
    find_descendant_by_label(&menu, "Send Ctrl+Alt+Delete").invoke_accessible_default_action();

    assert_eq!(
        key_events(&provider.rdp_keyboard_events_for(1)),
        vec![
            (true, 0x1d, false),
            (true, 0x38, false),
            (true, 0x4f, true),
            (false, 0x4f, true),
            (false, 0x38, false),
            (false, 0x1d, false),
        ]
    );

    // Splitting creates and focuses a local pane. RDP-only callbacks must not
    // leak into the background RDP session until pane 0 is focused again.
    h.ui.invoke_split_pane_h();
    pump_ticks(1);
    assert_eq!(h.ui.get_active_pane(), 1);
    let before = provider.rdp_keyboard_events_for(1).len();
    h.ui.invoke_session_rdp_alt_tab();
    assert_eq!(provider.rdp_keyboard_events_for(1).len(), before);

    h.ui.invoke_pane_focused(0);
    h.ui.invoke_session_rdp_alt_tab();
    assert_eq!(
        key_events(&provider.rdp_keyboard_events_for(1)[before..]),
        vec![
            (true, 0x38, false),
            (true, 0x0f, false),
            (false, 0x0f, false),
            (false, 0x38, false),
        ]
    );

    // The close confirmation is above Session Actions in keyboard priority.
    // Exercise the real Slint key down/up route, including a modifier held
    // across Escape cancelling the modal.
    let area = find_by_id(&h.ui, "RdpSurface::rdp-ta");
    let origin = area.absolute_position();
    let size = area.size();
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

    h.ui.invoke_close_tab(h.ui.get_active_tab());
    assert!(h.ui.get_close_confirm_open());
    let before_modal_keys = provider.rdp_keyboard_events_for(1).len();
    h.ui.invoke_rdp_key_down("q".into(), 0, 0);
    h.ui.invoke_rdp_key_up("q".into(), 0, 0);
    assert_eq!(
        provider.rdp_keyboard_events_for(1).len(),
        before_modal_keys,
        "direct RDP callback entry points must also respect the modal"
    );

    // The real RDP-focused Slint boundary routes Return to the safe initial
    // Cancel button, while retaining ownership of the matching key-up.
    assert_eq!(h.ui.get_close_confirm_focus_index(), 1);
    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Return.into(),
    });
    assert!(!h.ui.get_close_confirm_open());
    assert!(h.ui.get_close_confirm_key_guard_active());
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Return.into(),
    });
    assert!(!h.ui.get_close_confirm_key_guard_active());
    assert_eq!(provider.rdp_keyboard_events_for(1).len(), before_modal_keys);

    h.ui.invoke_close_tab(h.ui.get_active_tab());
    assert!(h.ui.get_close_confirm_open());
    // Opening a confirmation deliberately balances any destination-side
    // modifiers, so compare subsequent modal input against that new baseline.
    let before_modal_keys = provider.rdp_keyboard_events_for(1).len();
    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Control.into(),
    });
    h.ui.window()
        .dispatch_event(WindowEvent::KeyPressed { text: "x".into() });
    h.ui.window()
        .dispatch_event(WindowEvent::KeyReleased { text: "x".into() });
    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Escape.into(),
    });
    assert!(!h.ui.get_close_confirm_open());
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Escape.into(),
    });
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Control.into(),
    });
    assert!(!h.ui.get_close_confirm_key_guard_active());
    assert_eq!(
        provider.rdp_keyboard_events_for(1).len(),
        before_modal_keys,
        "modal-owned RDP down/up events must never reach the destination"
    );
}

fn key_events(events: &[RdpInputEvent]) -> Vec<(bool, u8, bool)> {
    events
        .iter()
        .filter_map(|event| match event {
            RdpInputEvent::KeyDown { scancode, extended } => Some((true, *scancode, *extended)),
            RdpInputEvent::KeyUp { scancode, extended } => Some((false, *scancode, *extended)),
            _ => None,
        })
        .collect()
}

fn palette_has(ui: &cm_ui::AppWindow, label: &str) -> bool {
    let actions = ui.get_palette_actions();
    (0..actions.row_count()).any(|idx| {
        actions
            .row_data(idx)
            .is_some_and(|action| action.label.as_str() == label)
    })
}

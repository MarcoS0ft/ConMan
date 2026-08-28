//! Real Slint key-boundary coverage for application shortcuts across focus owners.

#![cfg(feature = "ui-introspection")]

mod support;

use slint::platform::{Key, PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition};
use std::cell::Cell;
use std::rc::Rc;

use cm_core::RdpInputEvent;

use support::{find_by_id, harness, pump_ticks};

#[test]
fn ctrl_k_is_global_across_settings_and_rdp_focus() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    let (settings, _repo, provider) = harness();
    assert_shift_insert_is_mapped_to_the_terminal_paste_shortcut(&settings.ui);
    find_by_id(&settings.ui, "AppWindow::settings-panel-btn").invoke_accessible_default_action();
    find_by_id(&settings.ui, "SettingsPanel::settings-shell-path-field")
        .mock_single_click(PointerEventButton::Left);
    dispatch_ctrl_k(&settings.ui);
    assert!(
        settings.ui.get_palette_open(),
        "Ctrl+K must open the palette while a Settings field owns focus"
    );
    settings.ui.set_palette_open(false);

    settings.ui.invoke_quick_connect();
    settings.ui.set_qc_kind(1);
    settings
        .ui
        .set_qc_host("rdp-shortcut.example.invalid".into());
    settings.ui.set_qc_username("synthetic-user".into());
    settings.ui.set_qc_secret("synthetic-password".into());
    settings.ui.invoke_qc_connect();
    pump_ticks(1);
    assert_eq!(provider.rdp_connect_count(), 1);
    focus_rdp_without_advancing_session_timer(&settings.ui);

    assert_modifier_round_trip(
        &settings.ui,
        &provider,
        Key::Shift,
        0x2A,
        false,
        "left Shift",
    );
    assert_modifier_round_trip(
        &settings.ui,
        &provider,
        Key::ShiftR,
        0x36,
        false,
        "right Shift",
    );
    assert_modifier_round_trip(
        &settings.ui,
        &provider,
        Key::Control,
        0x1D,
        false,
        "left Ctrl",
    );

    settings
        .ui
        .window()
        .dispatch_event(WindowEvent::KeyPressed {
            text: Key::Control.into(),
        });
    assert!(
        provider.rdp_keyboard_events().iter().any(|event| matches!(
            event,
            RdpInputEvent::KeyDown {
                scancode: 0x1D,
                extended: false
            }
        )),
        "RDP must receive the synthetic Ctrl press"
    );
    focus_element_without_advancing_session_timer(
        &settings.ui,
        &find_by_id(&settings.ui, "SettingsPanel::settings-shell-path-field"),
    );
    assert!(
        provider.rdp_keyboard_events().iter().any(|event| matches!(
            event,
            RdpInputEvent::KeyUp {
                scancode: 0x1D,
                extended: false
            }
        )),
        "RDP focus-loss routing must release synthetic Ctrl"
    );

    focus_rdp_without_advancing_session_timer(&settings.ui);
    dispatch_ctrl_k(&settings.ui);
    assert!(
        settings.ui.get_palette_open(),
        "Ctrl+K must open the palette while an RDP surface owns focus"
    );
}

fn assert_shift_insert_is_mapped_to_the_terminal_paste_shortcut(ui: &cm_ui::AppWindow) {
    find_by_id(ui, "TerminalSurface::ta").mock_single_click(PointerEventButton::Left);
    let observed = Rc::new(Cell::new(None));
    ui.on_key_input({
        let observed = Rc::clone(&observed);
        move |_text, special, mods| observed.set(Some((special, mods)))
    });
    ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Shift.into(),
    });
    ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Insert.into(),
    });
    ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Insert.into(),
    });
    ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Shift.into(),
    });
    assert_eq!(
        observed.get(),
        Some((13, 4)),
        "the real TerminalSurface boundary must encode Insert as special key 13 with Shift"
    );
}

fn assert_modifier_round_trip(
    ui: &cm_ui::AppWindow,
    provider: &support::MockSessionProvider,
    key: Key,
    expected_scancode: u8,
    expected_extended: bool,
    label: &str,
) {
    let before = provider.rdp_keyboard_events().len();
    ui.window()
        .dispatch_event(WindowEvent::KeyPressed { text: key.into() });
    ui.window()
        .dispatch_event(WindowEvent::KeyReleased { text: key.into() });
    let all_events = provider.rdp_keyboard_events();
    let events = &all_events[before..];

    assert_eq!(
        events.len(),
        2,
        "{label} must produce only its own RDP key-down/key-up pair: {events:?}"
    );
    assert!(
        matches!(
            events[0],
            RdpInputEvent::KeyDown { scancode, extended }
                if scancode == expected_scancode && extended == expected_extended
        ),
        "{label} produced the wrong key-down: {events:?}"
    );
    assert!(
        matches!(
            events[1],
            RdpInputEvent::KeyUp { scancode, extended }
                if scancode == expected_scancode && extended == expected_extended
        ),
        "{label} produced the wrong key-up: {events:?}"
    );
}

fn focus_rdp_without_advancing_session_timer(ui: &cm_ui::AppWindow) {
    let area = find_by_id(ui, "RdpSurface::rdp-ta");
    focus_element_without_advancing_session_timer(ui, &area);
}

fn focus_element_without_advancing_session_timer(
    ui: &cm_ui::AppWindow,
    area: &i_slint_backend_testing::ElementHandle,
) {
    let origin = area.absolute_position();
    let size = area.size();
    let position = LogicalPosition::new(origin.x + size.width / 2.0, origin.y + size.height / 2.0);
    ui.window()
        .dispatch_event(WindowEvent::PointerMoved { position });
    ui.window().dispatch_event(WindowEvent::PointerPressed {
        position,
        button: PointerEventButton::Left,
    });
    ui.window().dispatch_event(WindowEvent::PointerReleased {
        position,
        button: PointerEventButton::Left,
    });
}

fn dispatch_ctrl_k(ui: &cm_ui::AppWindow) {
    ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Control.into(),
    });
    ui.window()
        .dispatch_event(WindowEvent::KeyPressed { text: "k".into() });
    ui.window()
        .dispatch_event(WindowEvent::KeyReleased { text: "k".into() });
    ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Control.into(),
    });
}

//! Tab quality-of-life behavior at the real Slint/controller boundary.

#![cfg(feature = "ui-introspection")]

mod support;

use i_slint_backend_testing::ElementHandle;
use slint::platform::{Key, PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition, Model};

use support::{find_by_id, harness, harness_with, nth_by_id, pump_ticks};

#[test]
fn tab_qol_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    mouse_reorder_keeps_model_state_and_active_identity_in_sync();
    cancelled_mouse_reorder_is_a_no_op();
    ctrl_tab_wraps_without_leaking_tab_to_a_session();
    ctrl_digits_select_visual_positions_and_ignore_missing_positions();
    ctrl_zero_targets_home_and_digits_number_connections();
    mouse_tab_selection_restores_the_destination_session_focus();
    repeated_shortcuts_work_without_pointer_refocus();
    repeated_terminal_rdp_switches_use_the_same_activation_path();
    single_pane_mounts_only_the_active_protocol_surface();
    held_ctrl_can_navigate_repeatedly_without_release_leakage();
    ctrl_shift_tab_and_backtab_select_the_previous_tab();
    editable_fields_suppress_tab_navigation_but_not_ctrl_k();
    home_is_pinned_during_mouse_reordering();
    drag_feedback_has_active_source_and_live_target_geometry();
    reattached_tabs_keep_a_stable_nonzero_model_id();
    palette_can_reopen_immediately_after_every_close_path();
    palette_reopens_without_clicking_from_terminal_and_rdp_owners();
}

fn ctrl_zero_targets_home_and_digits_number_connections() {
    let (h, _repo, provider) = harness_with(false);
    open_local_tabs(&h.ui, 3);
    find_by_id(&h.ui, "TerminalSurface::ta").mock_single_click(PointerEventButton::Left);
    let before = provider.terminal_key_input_count();

    dispatch_ctrl_key(&h.ui, "0".into());
    assert_eq!(h.ui.get_active_tab(), 0, "Ctrl+0 must select Home");
    dispatch_ctrl_key(&h.ui, "1".into());
    assert_eq!(
        h.ui.get_active_tab(),
        1,
        "Ctrl+1 must select the first connection after Home"
    );
    dispatch_ctrl_key(&h.ui, "2".into());
    assert_eq!(
        h.ui.get_active_tab(),
        2,
        "Ctrl+2 must select the second connection after Home"
    );
    assert_eq!(provider.terminal_key_input_count(), before);
}

fn mouse_tab_selection_restores_the_destination_session_focus() {
    let (h, _repo, provider) = harness();
    open_local_tabs(&h.ui, 2);
    find_by_id(&h.ui, "TerminalSurface::ta").mock_single_click(PointerEventButton::Left);

    tab_touch(&h.ui, 0).mock_single_click(PointerEventButton::Left);
    pump_ticks(2);
    dispatch_key_pair(&h.ui, "x");

    assert_eq!(h.ui.get_active_tab(), 0);
    assert_eq!(
        provider.terminal_key_events_for(0).len(),
        1,
        "mouse selection must focus the destination session without another click"
    );
    assert!(provider.terminal_key_events_for(1).is_empty());
}

fn single_pane_mounts_only_the_active_protocol_surface() {
    let (h, _repo, _provider) = harness();
    let session_area = find_by_id(&h.ui, "AppWindow::session-area");

    let terminals =
        ElementHandle::find_by_element_id(&h.ui, "TerminalSurface::ta").collect::<Vec<_>>();
    let rdps = ElementHandle::find_by_element_id(&h.ui, "RdpSurface::rdp-ta").collect::<Vec<_>>();
    assert_eq!(
        terminals.len(),
        1,
        "the active terminal surface must be mounted"
    );
    assert!(
        rdps.is_empty(),
        "an inactive RDP surface must not consume layout"
    );
    assert!(
        (terminals[0].size().height - session_area.size().height).abs() < 1.0,
        "the terminal must receive the full single-pane session height"
    );

    h.ui.invoke_quick_connect();
    h.ui.set_qc_kind(1);
    h.ui.set_qc_host("rdp-layout.example.invalid".into());
    h.ui.set_qc_username("synthetic-user".into());
    h.ui.set_qc_secret("synthetic-password".into());
    h.ui.invoke_qc_connect();
    pump_ticks(2);

    let terminals =
        ElementHandle::find_by_element_id(&h.ui, "TerminalSurface::ta").collect::<Vec<_>>();
    let rdps = ElementHandle::find_by_element_id(&h.ui, "RdpSurface::rdp-ta").collect::<Vec<_>>();
    assert!(
        terminals.is_empty(),
        "an inactive terminal surface must not consume layout"
    );
    assert_eq!(rdps.len(), 1, "the active RDP surface must be mounted");
    assert!(
        (rdps[0].size().height - session_area.size().height).abs() < 1.0,
        "RDP must receive the full single-pane session height"
    );
}

fn titles(ui: &cm_ui::AppWindow) -> Vec<String> {
    let tabs = ui.get_tabs();
    (0..tabs.row_count())
        .map(|idx| tabs.row_data(idx).expect("tab row").title.to_string())
        .collect()
}

fn open_local_tabs(ui: &cm_ui::AppWindow, count: usize) {
    while ui.get_tabs().row_count() < count {
        ui.invoke_new_tab();
    }
}

fn tab_touch(ui: &cm_ui::AppWindow, index: usize) -> ElementHandle {
    nth_by_id(ui, "AppWindow::tab-item", index)
        .query_descendants()
        .match_id("Tab::touch")
        .find_first()
        .expect("tab drag surface")
}

fn center(element: &ElementHandle) -> LogicalPosition {
    let position = element.absolute_position();
    let size = element.size();
    LogicalPosition::new(
        position.x + size.width / 2.0,
        position.y + size.height / 2.0,
    )
}

fn mouse_reorder_keeps_model_state_and_active_identity_in_sync() {
    let (h, _repo, provider) = harness();
    open_local_tabs(&h.ui, 3);
    h.ui.invoke_select_tab(1);

    let first = tab_touch(&h.ui, 0);
    let third = tab_touch(&h.ui, 2);
    first.mock_drag(center(&third), PointerEventButton::Left);

    assert_eq!(titles(&h.ui), ["shell 2", "shell 3", "shell 1"]);
    assert_eq!(
        h.ui.get_active_tab(),
        0,
        "the active shell 2 identity must survive moving the tab before it"
    );

    // Selecting the moved visual row must also select the matching controller
    // session, proving the Rust state and Slint model moved together.
    h.ui.invoke_select_tab(2);
    h.ui.invoke_key_input("x".into(), 0, 0);
    assert_eq!(provider.terminal_key_events_for(0).len(), 1);
    assert!(provider.terminal_key_events_for(1).is_empty());
    assert!(provider.terminal_key_events_for(2).is_empty());
}

fn cancelled_mouse_reorder_is_a_no_op() {
    let (h, _repo, _provider) = harness();
    open_local_tabs(&h.ui, 3);
    let before = titles(&h.ui);
    let first = tab_touch(&h.ui, 0);
    let third = tab_touch(&h.ui, 2);
    let start = center(&first);
    let target = center(&third);

    h.ui.window()
        .dispatch_event(WindowEvent::PointerMoved { position: start });
    h.ui.window().dispatch_event(WindowEvent::PointerPressed {
        position: start,
        button: PointerEventButton::Left,
    });
    h.ui.window()
        .dispatch_event(WindowEvent::PointerMoved { position: target });
    h.ui.window().dispatch_event(WindowEvent::PointerExited);

    assert_eq!(
        titles(&h.ui),
        before,
        "a cancelled drag must not move a tab"
    );
    assert!(
        ElementHandle::find_by_element_id(&h.ui, "Tab::tab-drop-marker")
            .next()
            .is_none(),
        "cancelled drag feedback must be cleared"
    );
}

fn ctrl_tab_wraps_without_leaking_tab_to_a_session() {
    let (h, _repo, provider) = harness();
    open_local_tabs(&h.ui, 3);
    find_by_id(&h.ui, "TerminalSurface::ta").mock_single_click(PointerEventButton::Left);
    assert_eq!(h.ui.get_active_tab(), 2);
    let before = provider.terminal_key_input_count();

    dispatch_ctrl_key(&h.ui, Key::Tab.into());
    assert_eq!(
        h.ui.get_active_tab(),
        0,
        "Ctrl+Tab must wrap after the last tab"
    );
    dispatch_ctrl_key(&h.ui, Key::Tab.into());
    assert_eq!(h.ui.get_active_tab(), 1);
    assert_eq!(
        provider.terminal_key_input_count(),
        before,
        "neither the Ctrl+Tab press nor its release may leak to a session"
    );
}

fn ctrl_digits_select_visual_positions_and_ignore_missing_positions() {
    let (h, _repo, provider) = harness();
    open_local_tabs(&h.ui, 3);
    find_by_id(&h.ui, "TerminalSurface::ta").mock_single_click(PointerEventButton::Left);
    let before = provider.terminal_key_input_count();

    dispatch_ctrl_key(&h.ui, "1".into());
    assert_eq!(h.ui.get_active_tab(), 0);
    dispatch_ctrl_key(&h.ui, "3".into());
    assert_eq!(h.ui.get_active_tab(), 2);
    dispatch_ctrl_key(&h.ui, "9".into());
    assert_eq!(
        h.ui.get_active_tab(),
        2,
        "a valid shortcut whose visual position does not exist is a no-op"
    );
    assert_eq!(
        provider.terminal_key_input_count(),
        before,
        "recognized Ctrl+1..9 chords must be consumed even when that tab is absent"
    );
}

fn repeated_shortcuts_work_without_pointer_refocus() {
    let (h, _repo, provider) = harness();
    open_local_tabs(&h.ui, 3);
    find_by_id(&h.ui, "TerminalSurface::ta").mock_single_click(PointerEventButton::Left);
    let before = provider.terminal_key_input_count();

    dispatch_ctrl_key(&h.ui, "1".into());
    dispatch_ctrl_key(&h.ui, "3".into());
    dispatch_ctrl_key(&h.ui, Key::Tab.into());

    assert_eq!(h.ui.get_active_tab(), 0);
    assert_eq!(provider.terminal_key_input_count(), before);
}

fn repeated_terminal_rdp_switches_use_the_same_activation_path() {
    let (h, _repo, provider) = harness();
    h.ui.invoke_quick_connect();
    h.ui.set_qc_kind(1);
    h.ui.set_qc_host("rdp-tab-qol.example.invalid".into());
    h.ui.set_qc_username("synthetic-user".into());
    h.ui.set_qc_secret("synthetic-password".into());
    h.ui.invoke_qc_connect();
    pump_ticks(2);
    h.ui.invoke_new_tab();
    assert_eq!(h.ui.get_tabs().row_count(), 3);
    assert!(!h.ui.get_rdp_active());
    find_by_id(&h.ui, "TerminalSurface::ta").mock_single_click(PointerEventButton::Left);
    let terminal_before = provider.terminal_key_input_count();
    let rdp_before = provider.rdp_keyboard_events().len();

    for _ in 0..3 {
        dispatch_ctrl_key(&h.ui, "2".into());
        assert!(
            h.ui.get_rdp_active(),
            "visual tab 2 must activate its RDP surface"
        );
        dispatch_ctrl_key(&h.ui, "3".into());
        assert!(
            !h.ui.get_rdp_active(),
            "visual tab 3 must restore its terminal surface"
        );
    }
    assert_eq!(provider.terminal_key_input_count(), terminal_before);
    assert!(
        provider.rdp_keyboard_events()[rdp_before..]
            .iter()
            .all(|event| !matches!(
                event,
                cm_core::RdpInputEvent::KeyDown {
                    scancode: 0x03 | 0x04 | 0x0F,
                    ..
                }
            )),
        "the tab digit/Tab itself must never reach the RDP destination"
    );
}

fn held_ctrl_can_navigate_repeatedly_without_release_leakage() {
    let (h, _repo, provider) = harness();
    open_local_tabs(&h.ui, 3);
    find_by_id(&h.ui, "TerminalSurface::ta").mock_single_click(PointerEventButton::Left);
    let before = provider.terminal_key_input_count();

    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Control.into(),
    });
    dispatch_key_pair(&h.ui, "1");
    pump_ticks(2);
    dispatch_key_pair(&h.ui, "2");
    pump_ticks(2);
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Control.into(),
    });
    pump_ticks(1);

    assert_eq!(h.ui.get_active_tab(), 1);
    assert_eq!(provider.terminal_key_input_count(), before);
}

fn ctrl_shift_tab_and_backtab_select_the_previous_tab() {
    let (h, _repo, provider) = harness();
    open_local_tabs(&h.ui, 3);
    find_by_id(&h.ui, "TerminalSurface::ta").mock_single_click(PointerEventButton::Left);
    let before = provider.terminal_key_input_count();

    dispatch_ctrl_shift_key(&h.ui, Key::Tab.into());
    assert_eq!(h.ui.get_active_tab(), 1);
    dispatch_ctrl_shift_key(&h.ui, Key::Backtab.into());
    assert_eq!(h.ui.get_active_tab(), 0);
    assert_eq!(provider.terminal_key_input_count(), before);
}

fn editable_fields_suppress_tab_navigation_but_not_ctrl_k() {
    let (h, _repo, _provider) = harness();
    open_local_tabs(&h.ui, 3);
    find_by_id(&h.ui, "AppWindow::conn-filter-field").mock_single_click(PointerEventButton::Left);

    dispatch_ctrl_key(&h.ui, "1".into());
    dispatch_ctrl_key(&h.ui, Key::Tab.into());
    assert_eq!(
        h.ui.get_active_tab(),
        2,
        "an editable side-panel field must retain ordinary Ctrl chords"
    );

    dispatch_ctrl_key(&h.ui, "k".into());
    assert!(
        h.ui.get_palette_open(),
        "Ctrl+K remains intentionally global"
    );
}

fn home_is_pinned_during_mouse_reordering() {
    let (h, _repo, _provider) = harness_with(false);
    open_local_tabs(&h.ui, 3);
    let before = titles(&h.ui);

    let home = tab_touch(&h.ui, 0);
    let third = tab_touch(&h.ui, 2);
    home.mock_drag(center(&third), PointerEventButton::Left);
    assert_eq!(titles(&h.ui), before);

    let third = tab_touch(&h.ui, 2);
    let home = tab_touch(&h.ui, 0);
    third.mock_drag(center(&home), PointerEventButton::Left);
    assert_eq!(
        titles(&h.ui),
        [before[0].clone(), before[2].clone(), before[1].clone()],
        "another tab may approach Home but never displace it"
    );
}

fn drag_feedback_has_active_source_and_live_target_geometry() {
    let (h, _repo, _provider) = harness();
    open_local_tabs(&h.ui, 3);

    let indicator = find_by_id(&h.ui, "Tab::tab-active-indicator");
    let active_tab = nth_by_id(&h.ui, "AppWindow::tab-item", 2);
    assert!((indicator.size().height - 2.0).abs() < 0.1);
    assert!((indicator.absolute_position().x - active_tab.absolute_position().x).abs() < 0.5);

    let source = tab_touch(&h.ui, 0);
    let target = tab_touch(&h.ui, 2);
    let start = center(&source);
    let end = center(&target);
    h.ui.window()
        .dispatch_event(WindowEvent::PointerMoved { position: start });
    h.ui.window().dispatch_event(WindowEvent::PointerPressed {
        position: start,
        button: PointerEventButton::Left,
    });
    h.ui.window()
        .dispatch_event(WindowEvent::PointerMoved { position: end });

    let marker = find_by_id(&h.ui, "Tab::tab-drop-marker");
    let target_tab = nth_by_id(&h.ui, "AppWindow::tab-item", 2);
    assert!((marker.size().width - 3.0).abs() < 0.1);
    assert!(
        (marker.absolute_position().x + marker.size().width
            - (target_tab.absolute_position().x + target_tab.size().width))
            .abs()
            < 0.5,
        "rightward drag marker must sit on the target's trailing boundary"
    );

    h.ui.window().dispatch_event(WindowEvent::PointerReleased {
        position: end,
        button: PointerEventButton::Left,
    });
    assert!(
        ElementHandle::find_by_element_id(&h.ui, "Tab::tab-drop-marker")
            .next()
            .is_none(),
        "drop feedback must clear after release"
    );
}

fn reattached_tabs_keep_a_stable_nonzero_model_id() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_split_pane_h();
    pump_ticks(1);
    h.ui.invoke_detach_session();
    pump_ticks(1);
    assert_eq!(h.ui.get_detached_count(), 1);

    h.ui.invoke_open_palette();
    let actions = h.ui.get_palette_actions();
    let reattach = (0..actions.row_count())
        .find(|idx| {
            actions
                .row_data(*idx)
                .is_some_and(|action| action.label.as_str().starts_with("Reattach: "))
        })
        .expect("detached session must be offered for reattachment");
    h.ui.invoke_palette_activated(reattach as i32);
    pump_ticks(1);

    let tabs = h.ui.get_tabs();
    let ids = (0..tabs.row_count())
        .map(|idx| tabs.row_data(idx).expect("tab row").id)
        .collect::<Vec<_>>();
    assert!(ids.iter().all(|id| *id > 0));
    let mut unique = ids.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(ids.len(), unique.len(), "reattach IDs must remain unique");
}

fn palette_can_reopen_immediately_after_every_close_path() {
    let (h, _repo, _provider) = harness();
    find_by_id(&h.ui, "AppWindow::settings-panel-btn").invoke_accessible_default_action();
    find_by_id(&h.ui, "SettingsPanel::settings-shell-path-field")
        .mock_single_click(PointerEventButton::Left);

    dispatch_ctrl_key(&h.ui, "k".into());
    dispatch_key_pair(&h.ui, Key::Escape);
    dispatch_ctrl_key(&h.ui, "k".into());
    assert!(
        h.ui.get_palette_open(),
        "Escape close must permit immediate reopen"
    );

    dispatch_text(&h.ui, "new local tab");
    dispatch_key_pair(&h.ui, Key::Return);
    pump_ticks(1);
    dispatch_ctrl_key(&h.ui, "k".into());
    assert!(
        h.ui.get_palette_open(),
        "activation close must permit immediate reopen"
    );

    let outside = LogicalPosition::new(2.0, 2.0);
    h.ui.window()
        .dispatch_event(WindowEvent::PointerMoved { position: outside });
    h.ui.window().dispatch_event(WindowEvent::PointerPressed {
        position: outside,
        button: PointerEventButton::Left,
    });
    h.ui.window().dispatch_event(WindowEvent::PointerReleased {
        position: outside,
        button: PointerEventButton::Left,
    });
    dispatch_ctrl_key(&h.ui, "k".into());
    assert!(
        h.ui.get_palette_open(),
        "outside close must permit immediate reopen"
    );
    assert_eq!(h.ui.get_palette_query().as_str(), "");
}

fn palette_reopens_without_clicking_from_terminal_and_rdp_owners() {
    let (h, _repo, _provider) = harness();
    find_by_id(&h.ui, "TerminalSurface::ta").mock_single_click(PointerEventButton::Left);
    dispatch_ctrl_key(&h.ui, "k".into());
    dispatch_key_pair(&h.ui, Key::Escape);
    dispatch_ctrl_key(&h.ui, "k".into());
    assert!(
        h.ui.get_palette_open(),
        "terminal owner must reopen immediately"
    );
    dispatch_key_pair(&h.ui, Key::Escape);

    h.ui.invoke_quick_connect();
    h.ui.set_qc_kind(1);
    h.ui.set_qc_host("rdp-palette-focus.example.invalid".into());
    h.ui.set_qc_username("synthetic-user".into());
    h.ui.set_qc_secret("synthetic-password".into());
    h.ui.invoke_qc_connect();
    pump_ticks(1);
    find_by_id(&h.ui, "RdpSurface::rdp-ta").mock_single_click(PointerEventButton::Left);
    dispatch_ctrl_key(&h.ui, "k".into());
    dispatch_key_pair(&h.ui, Key::Escape);
    dispatch_ctrl_key(&h.ui, "k".into());
    assert!(h.ui.get_palette_open(), "RDP owner must reopen immediately");
}

fn dispatch_ctrl_key(ui: &cm_ui::AppWindow, text: slint::SharedString) {
    ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Control.into(),
    });
    dispatch_key_pair(ui, text);
    ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Control.into(),
    });
    pump_ticks(2);
}

fn dispatch_ctrl_shift_key(ui: &cm_ui::AppWindow, text: slint::SharedString) {
    ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Control.into(),
    });
    ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Shift.into(),
    });
    dispatch_key_pair(ui, text);
    ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Shift.into(),
    });
    ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Control.into(),
    });
    pump_ticks(2);
}

fn dispatch_text(ui: &cm_ui::AppWindow, text: &str) {
    for character in text.chars() {
        dispatch_key_pair(ui, character.to_string());
    }
}

fn dispatch_key_pair(ui: &cm_ui::AppWindow, text: impl Into<slint::SharedString> + Clone) {
    ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: text.clone().into(),
    });
    ui.window()
        .dispatch_event(WindowEvent::KeyReleased { text: text.into() });
}

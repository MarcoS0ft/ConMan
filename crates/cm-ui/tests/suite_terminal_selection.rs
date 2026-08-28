//! Real Slint pointer-boundary regression coverage for terminal selection.
//!
//! These scenarios deliberately drive the generated `TerminalSurface`'s
//! `TouchArea`. They do not invoke `AppWindow::pointer` directly: Slint's
//! buttonless move translation is the behavior that regressed.

#![cfg(feature = "ui-introspection")]

mod support;

use cm_core::{
    Cell, CellAttrs, Color, CursorShape, CursorState, GridSnapshot, MouseAction, MouseButton,
    RdpInputEvent, TerminalSize,
};
use i_slint_backend_testing::ElementHandle;
use slint::platform::{Key, PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition};

use support::{harness, pump_ticks};

#[test]
fn terminal_selection_pointer_boundary_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    local_drag_selects_without_forwarding_mouse_input();
    tmux_mouse_tracking_owns_drag_and_right_click();
    shift_overrides_tmux_mouse_tracking_for_local_selection();
    pointer_cancel_ends_selection_and_mouse_capture();
    mouse_tracking_is_scoped_to_the_targeted_split_pane();
    split_focus_switch_after_hover_routes_the_current_rdp_pane();
    split_focus_switch_during_drag_releases_the_original_tui();
    tab_switch_after_hover_routes_the_current_rdp_tab();
    tab_switch_during_drag_releases_the_original_tui();
    first_drag_after_split_focus_survives_redraw_tick();
}

fn terminal_touch_areas(ui: &cm_ui::AppWindow) -> Vec<ElementHandle> {
    let mut areas: Vec<_> = ElementHandle::find_by_element_id(ui, "TerminalSurface::ta").collect();
    areas.sort_by(|a, b| a.absolute_position().x.total_cmp(&b.absolute_position().x));
    areas
}

fn terminal_touch_area(ui: &cm_ui::AppWindow) -> ElementHandle {
    let mut areas = terminal_touch_areas(ui).into_iter();
    let area = areas
        .next()
        .expect("active single-pane terminal must expose TerminalSurface::ta");
    assert!(
        areas.next().is_none(),
        "single-pane harness must expose exactly one terminal TouchArea"
    );
    area
}

fn drag_target(area: &ElementHandle) -> LogicalPosition {
    let position = area.absolute_position();
    let size = area.size();
    LogicalPosition::new(
        position.x + size.width * 0.75,
        position.y + size.height * 0.5,
    )
}

fn terminal_snapshot(mouse_tracking: bool) -> GridSnapshot {
    let size = TerminalSize { rows: 24, cols: 80 };
    GridSnapshot {
        size,
        cells: (0..usize::from(size.rows) * usize::from(size.cols))
            .map(|_| Cell {
                grapheme: "x".to_owned(),
                fg: Color::Default,
                bg: Color::Default,
                attrs: CellAttrs::empty(),
                width: 1,
            })
            .collect(),
        cursor: CursorState {
            row: 0,
            col: 0,
            visible: false,
            shape: CursorShape::Block,
        },
        scrollback_len: 0,
        scroll_offset: 0,
        mouse_tracking,
    }
}

fn local_drag_selects_without_forwarding_mouse_input() {
    let (h, _repo, provider) = harness();
    let area = terminal_touch_area(&h.ui);

    area.mock_drag(drag_target(&area), PointerEventButton::Left);

    assert!(
        h.has_active_terminal_selection(),
        "a real TouchArea left drag must create a terminal selection"
    );

    assert!(
        provider.terminal_mouse_events().is_empty(),
        "without DEC mouse tracking the local selection gesture must not leak into the shell"
    );
}

fn tmux_mouse_tracking_owns_drag_and_right_click() {
    let (h, _repo, provider) = harness();
    provider.publish_terminal_grid(0, terminal_snapshot(true));
    pump_ticks(1);
    let area = terminal_touch_area(&h.ui);

    area.mock_drag(drag_target(&area), PointerEventButton::Left);

    assert!(
        !h.has_active_terminal_selection(),
        "a tmux-like mouse-tracking application must own an unmodified drag"
    );
    let events = provider.terminal_mouse_events();
    assert_eq!(
        events.first().map(|event| event.action),
        Some(MouseAction::Press),
        "drag must begin with a terminal left press"
    );
    assert_eq!(
        events.last().map(|event| event.action),
        Some(MouseAction::Release),
        "drag must end with a terminal left release"
    );
    assert!(
        events.iter().any(|event| event.action == MouseAction::Move),
        "Slint's buttonless captured moves must reach terminal mouse reporting"
    );
    assert!(
        events.iter().all(|event| event.button == MouseButton::Left),
        "every event in the captured left-drag sequence must retain the left button"
    );

    let before_right = events.len();
    let position = area.absolute_position();
    let center = LogicalPosition::new(position.x + 20.0, position.y + 20.0);
    h.ui.window().dispatch_event(WindowEvent::PointerPressed {
        position: center,
        button: PointerEventButton::Right,
    });
    h.ui.window().dispatch_event(WindowEvent::PointerReleased {
        position: center,
        button: PointerEventButton::Right,
    });
    let events = provider.terminal_mouse_events();
    assert!(
        matches!(
            &events[before_right..],
            [press, release]
                if press.button == MouseButton::Right
                    && press.action == MouseAction::Press
                    && release.button == MouseButton::Right
                    && release.action == MouseAction::Release
        ),
        "tracking must receive right-click instead of ConMan consuming it as paste"
    );
}

fn shift_overrides_tmux_mouse_tracking_for_local_selection() {
    let (h, _repo, provider) = harness();
    provider.publish_terminal_grid(0, terminal_snapshot(true));
    pump_ticks(1);
    let area = terminal_touch_area(&h.ui);

    h.ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Shift.into(),
    });
    area.mock_drag(drag_target(&area), PointerEventButton::Left);
    h.ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: Key::Shift.into(),
    });

    assert!(
        h.has_active_terminal_selection(),
        "Shift must override terminal mouse reporting for local selection"
    );
    assert!(
        provider.terminal_mouse_events().is_empty(),
        "a Shift-local drag must not leak any press, move, or release to the TUI"
    );
}

fn pointer_cancel_ends_selection_and_mouse_capture() {
    let (h, _repo, provider) = harness();
    provider.publish_terminal_grid(0, terminal_snapshot(true));
    pump_ticks(1);
    let area = terminal_touch_area(&h.ui);
    let position = area.absolute_position();
    let size = area.size();
    let center = LogicalPosition::new(
        position.x + size.width * 0.5,
        position.y + size.height * 0.5,
    );
    let later_hover = LogicalPosition::new(center.x + size.width * 0.2, center.y);

    h.ui.window()
        .dispatch_event(WindowEvent::PointerMoved { position: center });
    h.ui.window().dispatch_event(WindowEvent::PointerPressed {
        position: center,
        button: PointerEventButton::Left,
    });
    h.ui.window().dispatch_event(WindowEvent::PointerExited);
    h.ui.window().dispatch_event(WindowEvent::PointerMoved {
        position: later_hover,
    });

    assert!(
        !h.has_active_terminal_selection(),
        "hover after a cancelled press must not create a selection"
    );
    assert!(
        matches!(
            provider.terminal_mouse_events().as_slice(),
            [press, release]
                if press.button == MouseButton::Left
                    && press.action == MouseAction::Press
                    && release.button == MouseButton::Left
                    && release.action == MouseAction::Release
        ),
        "cancelled capture must forward exactly a left press/release pair and no later move"
    );
}

fn mouse_tracking_is_scoped_to_the_targeted_split_pane() {
    let (h, _repo, provider) = harness();
    h.ui.invoke_split_pane_h();
    pump_ticks(1);
    provider.publish_terminal_grid(1, terminal_snapshot(true));
    pump_ticks(1);

    let areas = terminal_touch_areas(&h.ui);
    assert_eq!(areas.len(), 2);
    areas[1].mock_drag(drag_target(&areas[1]), PointerEventButton::Left);
    assert!(
        !h.has_active_terminal_selection(),
        "the tracking extra pane must own its drag"
    );
    let tracking_event_count = provider.terminal_mouse_events().len();
    assert!(tracking_event_count >= 3);

    // The first gesture can redraw pane chrome/focus state. Re-query the
    // Slint elements so the second gesture targets the live primary surface,
    // not a handle from the previous item-tree generation.
    pump_ticks(1);
    let areas = terminal_touch_areas(&h.ui);
    areas[0].mock_drag(drag_target(&areas[0]), PointerEventButton::Left);
    assert_eq!(h.ui.get_active_pane(), 0);
    assert!(
        h.has_active_terminal_selection(),
        "the non-tracking primary pane must still make a local selection"
    );
    assert_eq!(
        provider.terminal_mouse_events().len(),
        tracking_event_count,
        "the primary pane's local drag must not be forwarded through the extra pane"
    );
}

fn center(area: &ElementHandle) -> LogicalPosition {
    let origin = area.absolute_position();
    let size = area.size();
    LogicalPosition::new(origin.x + size.width * 0.5, origin.y + size.height * 0.5)
}

fn press_left(ui: &cm_ui::AppWindow, position: LogicalPosition) {
    ui.window()
        .dispatch_event(WindowEvent::PointerMoved { position });
    ui.window().dispatch_event(WindowEvent::PointerPressed {
        position,
        button: PointerEventButton::Left,
    });
}

fn release_left(ui: &cm_ui::AppWindow, position: LogicalPosition) {
    ui.window().dispatch_event(WindowEvent::PointerReleased {
        position,
        button: PointerEventButton::Left,
    });
}

fn assert_balanced_left_click(events: &[cm_core::MouseEvent], label: &str) {
    assert!(
        matches!(
            events,
            [press, release]
                if press.button == MouseButton::Left
                    && press.action == MouseAction::Press
                    && release.button == MouseButton::Left
                    && release.action == MouseAction::Release
        ),
        "{label}: expected a balanced left press/release on the original endpoint, got {events:?}"
    );
}

fn quick_connect_rdp(h: &cm_ui::TestHarness, provider: &support::MockSessionProvider) {
    h.ui.invoke_quick_connect();
    h.ui.set_qc_kind(1);
    h.ui.set_qc_host("rdp-pointer.example.invalid".into());
    h.ui.set_qc_username("synthetic-user".into());
    h.ui.set_qc_secret("synthetic-password".into());
    h.ui.invoke_qc_connect();
    provider.publish_rdp_frame(0, 1280, 720);
    pump_ticks(1);
}

fn rdp_touch_area(ui: &cm_ui::AppWindow) -> ElementHandle {
    let mut areas = ElementHandle::find_by_element_id(ui, "RdpSurface::rdp-ta");
    let area = areas
        .next()
        .expect("active RDP pane must expose its TouchArea");
    assert!(areas.next().is_none(), "test expects exactly one RDP pane");
    area
}

fn split_focus_switch_after_hover_routes_the_current_rdp_pane() {
    let (h, _repo, provider) = harness();
    quick_connect_rdp(&h, &provider);
    h.ui.invoke_split_pane_h();
    pump_ticks(1);
    provider.publish_terminal_grid(1, terminal_snapshot(true));
    pump_ticks(1);

    let area = terminal_touch_area(&h.ui);
    h.ui.window().dispatch_event(WindowEvent::PointerMoved {
        position: center(&area),
    });
    h.ui.invoke_pane_focused(0);
    let area = rdp_touch_area(&h.ui);
    h.ui.window().dispatch_event(WindowEvent::PointerMoved {
        position: center(&area),
    });

    assert!(
        matches!(
            provider.rdp_pointer_events_for(1).as_slice(),
            [RdpInputEvent::MouseMove { .. }]
        ),
        "buttonless terminal hover must not pin routing away from the newly focused RDP pane"
    );
}

fn split_focus_switch_during_drag_releases_the_original_tui() {
    let (h, _repo, provider) = harness();
    h.ui.invoke_split_pane_h();
    pump_ticks(1);
    provider.publish_terminal_grid(1, terminal_snapshot(true));
    pump_ticks(1);

    let areas = terminal_touch_areas(&h.ui);
    assert_eq!(areas.len(), 2);
    let extra_position = center(&areas[1]);
    press_left(&h.ui, extra_position);
    h.ui.invoke_pane_focused(0);
    release_left(&h.ui, extra_position);

    assert_balanced_left_click(&provider.terminal_mouse_events_for(1), "split focus switch");
    assert!(
        provider.terminal_mouse_events_for(0).is_empty(),
        "release after a split focus switch must not leak into the newly focused pane"
    );
}

fn tab_switch_during_drag_releases_the_original_tui() {
    let (h, _repo, provider) = harness();
    h.ui.invoke_new_tab();
    pump_ticks(1);
    provider.publish_terminal_grid(1, terminal_snapshot(true));
    pump_ticks(1);

    let area = terminal_touch_area(&h.ui);
    let position = center(&area);
    press_left(&h.ui, position);
    h.ui.invoke_select_tab(0);
    release_left(&h.ui, position);

    assert_balanced_left_click(&provider.terminal_mouse_events_for(1), "tab switch");
    assert!(
        provider.terminal_mouse_events_for(0).is_empty(),
        "release after a tab switch must not leak into the newly selected tab"
    );
}

fn tab_switch_after_hover_routes_the_current_rdp_tab() {
    let (h, _repo, provider) = harness();
    quick_connect_rdp(&h, &provider);
    h.ui.invoke_new_tab();
    pump_ticks(1);
    provider.publish_terminal_grid(1, terminal_snapshot(true));
    pump_ticks(1);

    let area = terminal_touch_area(&h.ui);
    h.ui.window().dispatch_event(WindowEvent::PointerMoved {
        position: center(&area),
    });
    h.ui.invoke_select_tab(1);
    let area = rdp_touch_area(&h.ui);
    h.ui.window().dispatch_event(WindowEvent::PointerMoved {
        position: center(&area),
    });

    assert!(
        matches!(
            provider.rdp_pointer_events_for(1).as_slice(),
            [RdpInputEvent::MouseMove { .. }]
        ),
        "buttonless terminal hover must not pin routing away from the newly selected RDP tab"
    );
}

fn first_drag_after_split_focus_survives_redraw_tick() {
    let (h, _repo, _provider) = harness();
    h.ui.invoke_split_pane_h();
    pump_ticks(1);
    assert_eq!(h.ui.get_active_pane(), 1, "new split pane starts focused");

    let areas = terminal_touch_areas(&h.ui);
    assert_eq!(areas.len(), 2, "horizontal split must expose two terminals");
    let previously_unfocused_primary = &areas[0];
    previously_unfocused_primary.mock_drag(
        drag_target(previously_unfocused_primary),
        PointerEventButton::Left,
    );

    assert_eq!(
        h.ui.get_active_pane(),
        0,
        "dragging the primary pane must focus it through PaneSlot"
    );
    assert!(
        h.has_active_terminal_selection(),
        "the focus-changing drag must create a selection"
    );

    pump_ticks(1);
    assert!(
        h.has_active_terminal_selection(),
        "the next redraw tick must not erase the focus-changing drag selection"
    );
}

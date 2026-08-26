//! Real Slint pointer-boundary regression coverage for terminal selection.
//!
//! These scenarios deliberately drive the generated `TerminalSurface`'s
//! `TouchArea`. They do not invoke `AppWindow::pointer` directly: Slint's
//! buttonless move translation is the behavior that regressed.

#![cfg(feature = "ui-introspection")]

mod support;

use cm_core::{MouseAction, MouseButton};
use i_slint_backend_testing::ElementHandle;
use slint::platform::{PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition};

use support::{harness, pump_ticks};

#[test]
fn terminal_selection_pointer_boundary_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    real_touch_area_drag_selects_and_forwards_mouse_motion();
    pointer_cancel_ends_selection_and_mouse_capture();
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

fn real_touch_area_drag_selects_and_forwards_mouse_motion() {
    let (h, _repo, provider) = harness();
    let area = terminal_touch_area(&h.ui);

    area.mock_drag(drag_target(&area), PointerEventButton::Left);

    assert!(
        h.has_active_terminal_selection(),
        "a real TouchArea left drag must create a terminal selection"
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
}

fn pointer_cancel_ends_selection_and_mouse_capture() {
    let (h, _repo, provider) = harness();
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

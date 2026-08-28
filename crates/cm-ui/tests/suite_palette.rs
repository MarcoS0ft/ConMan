//! P10.3 VQ-9 — command-palette geometry at the real Slint boundary.

#![cfg(feature = "ui-introspection")]

mod support;

use i_slint_backend_testing::ElementHandle;
use slint::platform::{Key, PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition, Model};

use support::{find_by_id, harness, nth_by_id, pump_ticks};

#[test]
fn command_palette_keeps_groups_and_selection_visible() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    let (h, _repo, _provider) = harness();
    h.ui.window()
        .set_size(slint::LogicalSize::new(900.0, 600.0));

    find_by_id(&h.ui, "AppWindow::palette-badge-btn").invoke_accessible_default_action();
    assert!(h.ui.get_palette_open(), "palette did not open");
    pump_ticks(1);

    // The original defect placed PANELS at the bottom edge while its first
    // action was below the clip. Only headings whose first action is fully
    // visible may exist in the resting tree.
    let initial_headings = visible_group_headings(&h.ui);
    assert_eq!(
        initial_headings,
        vec!["ACTIONS"],
        "a group heading must not render without its first actionable row"
    );

    // Down-arrow through the focused palette's real Slint key boundary until
    // the first PANELS action is selected. The ScrollView must bring the
    // action and its heading into view without a synthetic property poke.
    for _ in 0..7 {
        dispatch_key_pair(&h.ui, Key::DownArrow);
    }
    pump_ticks(1);
    assert_eq!(h.ui.get_palette_selected(), 7);
    assert_fully_inside_results(&h.ui, 7);
    assert!(
        visible_group_headings(&h.ui).contains(&"PANELS"),
        "PANELS heading must appear when Focus Connections is fully visible"
    );

    let action_count = h.ui.get_palette_actions().row_count();
    for _ in 8..action_count {
        dispatch_key_pair(&h.ui, Key::DownArrow);
    }
    pump_ticks(1);
    assert_eq!(h.ui.get_palette_selected(), action_count as i32 - 1);
    assert_fully_inside_results(&h.ui, action_count - 1);

    // Every open is a fresh interaction: query/model/selection/scroll/focus
    // reset together rather than retaining the hidden component's state.
    dispatch_text(&h.ui, "open settings");
    assert_eq!(h.ui.get_palette_query().as_str(), "open settings");
    dispatch_key_pair(&h.ui, Key::Escape);
    find_by_id(&h.ui, "AppWindow::palette-badge-btn").invoke_accessible_default_action();
    assert_eq!(h.ui.get_palette_query().as_str(), "");
    assert_eq!(h.ui.get_palette_actions().row_count(), action_count);
    let results = find_by_id(&h.ui, "CommandPalette::results");
    results.scroll(0.0, -10_000.0);
    pump_ticks(1);
    dispatch_key_pair(&h.ui, Key::Escape);
    find_by_id(&h.ui, "AppWindow::palette-badge-btn").invoke_accessible_default_action();
    pump_ticks(1);
    assert_eq!(h.ui.get_palette_selected(), 0);
    assert_fully_inside_results(&h.ui, 0);

    // Typing after the second reopen proves focus was reacquired, not merely
    // that the externally-visible properties happened to be reset.
    dispatch_text(&h.ui, "n");
    assert_eq!(h.ui.get_palette_query().as_str(), "n");

    // The full-window Modal scrim still owns pointer dismissal outside the
    // centered card after keyboard ownership moved into CommandPalette.
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
    assert!(!h.ui.get_palette_open(), "outside click must still dismiss");
}

fn dispatch_text(ui: &cm_ui::AppWindow, text: &str) {
    for character in text.chars() {
        let text = character.to_string();
        ui.window().dispatch_event(WindowEvent::KeyPressed {
            text: text.clone().into(),
        });
        ui.window()
            .dispatch_event(WindowEvent::KeyReleased { text: text.into() });
    }
}

fn dispatch_key_pair(ui: &cm_ui::AppWindow, key: Key) {
    ui.window()
        .dispatch_event(WindowEvent::KeyPressed { text: key.into() });
    ui.window()
        .dispatch_event(WindowEvent::KeyReleased { text: key.into() });
}

fn visible_group_headings(ui: &cm_ui::AppWindow) -> Vec<&str> {
    ElementHandle::find_by_element_id(ui, "CommandPalette::group-label")
        .filter_map(|element| match element.accessible_label()?.as_str() {
            "ACTIONS" => Some("ACTIONS"),
            "PANELS" => Some("PANELS"),
            "DATA" => Some("DATA"),
            "PANES" => Some("PANES"),
            "TABS" => Some("TABS"),
            "SESSIONS" => Some("SESSIONS"),
            _ => None,
        })
        .collect()
}

fn assert_fully_inside_results(ui: &cm_ui::AppWindow, action_index: usize) {
    let results = find_by_id(ui, "CommandPalette::results");
    let row = nth_by_id(ui, "CommandPalette::action-row", action_index);
    let viewport_top = results.absolute_position().y;
    let viewport_bottom = viewport_top + results.size().height;
    let row_top = row.absolute_position().y;
    let row_bottom = row_top + row.size().height;
    assert!(
        row_top >= viewport_top - 0.5 && row_bottom <= viewport_bottom + 0.5,
        "selected action {action_index} must be fully visible: row={row_top}..{row_bottom}, \
         results={viewport_top}..{viewport_bottom}"
    );
}

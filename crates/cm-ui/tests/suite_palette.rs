//! P10.3 VQ-9 — command-palette geometry at the real Slint boundary.

#![cfg(feature = "ui-introspection")]

mod support;

use i_slint_backend_testing::ElementHandle;
use slint::{ComponentHandle, Model};

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

    // Down-arrow through the real AppWindow key-input callback until the
    // first PANELS action is selected. The ScrollView must bring the action
    // and its heading into view without a synthetic property poke.
    for _ in 0..7 {
        h.ui.invoke_key_input("".into(), 6, 0);
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
        h.ui.invoke_key_input("".into(), 6, 0);
    }
    pump_ticks(1);
    assert_eq!(h.ui.get_palette_selected(), action_count as i32 - 1);
    assert_fully_inside_results(&h.ui, action_count - 1);

    // Closing resets selection; reopening rebuilds the model. Verify that an
    // intervening mouse-wheel scroll cannot leave selected row zero off-screen
    // on the next opening (the query itself is intentionally untouched).
    h.ui.invoke_key_input("".into(), 4, 0);
    find_by_id(&h.ui, "AppWindow::palette-badge-btn").invoke_accessible_default_action();
    let results = find_by_id(&h.ui, "CommandPalette::results");
    results.scroll(0.0, -10_000.0);
    pump_ticks(1);
    h.ui.invoke_key_input("".into(), 4, 0);
    find_by_id(&h.ui, "AppWindow::palette-badge-btn").invoke_accessible_default_action();
    pump_ticks(1);
    assert_eq!(h.ui.get_palette_selected(), 0);
    assert_fully_inside_results(&h.ui, 0);
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

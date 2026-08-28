//! Windows-shaped Slint modifier-token coverage for terminal sessions.

#![cfg(feature = "ui-introspection")]

mod support;

use cm_core::{Cell, CellAttrs, Color, CursorShape, CursorState, GridSnapshot, Key, TerminalSize};
use slint::platform::{Key as SlintKey, PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition};

use support::{find_by_id, harness, pump_ticks};

#[test]
fn terminal_ctrl_modifier_boundary_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();

    let (h, _repo, provider) = harness();
    provider.publish_terminal_grid(0, terminal_snapshot("x"));
    pump_ticks(1);
    let area = find_by_id(&h.ui, "TerminalSurface::ta");
    area.mock_single_click(PointerEventButton::Left);
    // Focusing through the real TouchArea may produce a tiny captured move in
    // the testing backend. Fresh output invalidates any incidental selection,
    // matching normal terminal activity before the shortcut assertions.
    provider.publish_terminal_grid(0, terminal_snapshot("y"));
    pump_ticks(1);
    let area = find_by_id(&h.ui, "TerminalSurface::ta");
    assert!(!h.has_active_terminal_selection());

    dispatch_modifier(&h.ui, SlintKey::Control);
    dispatch_modifier(&h.ui, SlintKey::ControlR);
    assert!(
        provider.terminal_key_events_for(0).is_empty(),
        "standalone left/right Ctrl tokens must not become terminal characters"
    );
    assert_eq!(
        h.pending_terminal_paste_requests(),
        0,
        "standalone right Ctrl must not be mistaken for Ctrl+V"
    );

    dispatch_ctrl_char(&h.ui, "q");
    let events = provider.terminal_key_events_for(0);
    assert_eq!(events.len(), 1, "Ctrl+Q must emit exactly one terminal key");
    assert_eq!(events[0].key, Key::Char('q'));
    assert!(events[0].mods.ctrl, "Ctrl+Q must retain the Ctrl modifier");

    dispatch_ctrl_char(&h.ui, "c");
    let events = provider.terminal_key_events_for(0);
    assert_eq!(
        events.len(),
        2,
        "Ctrl+C without selection must reach the shell"
    );
    assert_eq!(events[1].key, Key::Char('c'));
    assert!(events[1].mods.ctrl, "the shell interrupt must retain Ctrl");

    let target = drag_target(&area);
    area.mock_drag(target, PointerEventButton::Left);
    assert!(h.has_active_terminal_selection());
    let before_copy = provider.terminal_key_events_for(0).len();
    dispatch_ctrl_char(&h.ui, "c");
    assert_eq!(
        provider.terminal_key_events_for(0).len(),
        before_copy,
        "Ctrl+C with a selection must be consumed as Copy"
    );

    let before_paste = h.pending_terminal_paste_requests();
    let before_keys = provider.terminal_key_events_for(0).len();
    dispatch_ctrl_char(&h.ui, "v");
    assert_eq!(
        h.pending_terminal_paste_requests(),
        before_paste + 1,
        "Ctrl+V must queue one terminal paste request"
    );
    assert_eq!(
        provider.terminal_key_events_for(0).len(),
        before_keys,
        "Ctrl+V must not also leak into the shell"
    );
}

fn dispatch_modifier(ui: &cm_ui::AppWindow, key: SlintKey) {
    ui.window()
        .dispatch_event(WindowEvent::KeyPressed { text: key.into() });
    ui.window()
        .dispatch_event(WindowEvent::KeyReleased { text: key.into() });
}

fn dispatch_ctrl_char(ui: &cm_ui::AppWindow, text: &str) {
    ui.window().dispatch_event(WindowEvent::KeyPressed {
        text: SlintKey::Control.into(),
    });
    ui.window()
        .dispatch_event(WindowEvent::KeyPressed { text: text.into() });
    ui.window()
        .dispatch_event(WindowEvent::KeyReleased { text: text.into() });
    ui.window().dispatch_event(WindowEvent::KeyReleased {
        text: SlintKey::Control.into(),
    });
}

fn drag_target(area: &i_slint_backend_testing::ElementHandle) -> LogicalPosition {
    let position = area.absolute_position();
    let size = area.size();
    LogicalPosition::new(
        position.x + size.width * 0.75,
        position.y + size.height * 0.5,
    )
}

fn terminal_snapshot(grapheme: &str) -> GridSnapshot {
    let size = TerminalSize { rows: 24, cols: 80 };
    GridSnapshot {
        size,
        cells: (0..usize::from(size.rows) * usize::from(size.cols))
            .map(|_| Cell {
                grapheme: grapheme.to_owned(),
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
        mouse_tracking: false,
    }
}

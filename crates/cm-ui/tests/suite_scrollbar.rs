//! Pointer-driven scrollbar geometry, paging, dragging, and fading regressions.
#![cfg(feature = "ui-introspection")]

mod support;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use i_slint_backend_testing::{ElementHandle, mock_elapsed_time};
use slint::platform::{PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition, Model};
use support::find_by_id;

#[test]
fn scrollbar_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();
    let app = cm_ui::AppWindow::new().unwrap();
    let ui = &app;
    ui.window()
        .set_size(slint::LogicalSize::new(1600.0, 1200.0));
    ui.set_term_scrollback_len(1000);
    ui.set_term_view_rows(100);
    ui.set_term_scroll_offset(500);
    let requests = Rc::new(RefCell::new(Vec::new()));
    ui.on_scroll_scrub({
        let requests = requests.clone();
        let weak = ui.as_weak();
        move |fraction| {
            let offset = (1000.0 * (1.0 - fraction)).round() as i32;
            requests.borrow_mut().push(offset);
            weak.upgrade().unwrap().set_term_scroll_offset(offset);
        }
    });
    mock_elapsed_time(Duration::from_millis(400));
    let rail = find_by_id(ui, "TerminalScrollbar::sb-touch");
    let thumb = find_by_id(ui, "TerminalScrollbar::thumb");
    assert!(rail.size().height > 500.0);
    assert_eq!(rail.size().width, 10.0);
    mock_elapsed_time(Duration::from_secs(3));
    assert_eq!(thumb.computed_opacity(), 1.0, "visible by default at rest");
    assert_eq!(thumb.size().width, 4.0, "subtle resting indicator");

    // The full width and both ends of the track must page, without jumping
    // to the pointer or turning movement during the press into a scrub.
    for x in [0.5, 5.0, 9.5] {
        ui.set_term_scroll_offset(500);
        let top = point(&rail, x, 5.0);
        press(ui, top);
        assert_eq!(ui.get_term_scroll_offset(), 600);
        moved(ui, point(&rail, x, 30.0));
        assert_eq!(ui.get_term_scroll_offset(), 600);
        release(ui, top);
        click(ui, point(&rail, x, rail.size().height - 5.0));
        assert_eq!(ui.get_term_scroll_offset(), 500);
    }
    ui.set_term_scroll_offset(950);
    click(ui, point(&rail, 5.0, 1.0));
    assert_eq!(ui.get_term_scroll_offset(), 1000, "page clamps at oldest");
    ui.set_term_scroll_offset(50);
    click(ui, point(&rail, 5.0, rail.size().height - 1.0));
    assert_eq!(ui.get_term_scroll_offset(), 0, "page clamps at live tail");

    // A grab near the thumb's top preserves its position; only moving it
    // scrubs, and the thumb reaches both extremes of the rail.
    ui.set_term_scroll_offset(500);
    let before = requests.borrow().len();
    let grab = point(&thumb, thumb.size().width / 2.0, 3.0);
    press(ui, grab);
    assert_eq!(requests.borrow().len(), before);
    moved(ui, point(&rail, 5.0, -30.0));
    assert_eq!(ui.get_term_scroll_offset(), 1000);
    moved(ui, point(&rail, 5.0, rail.size().height + 30.0));
    assert_eq!(ui.get_term_scroll_offset(), 0);
    release(ui, point(&rail, 5.0, rail.size().height + 30.0));

    ui.set_settings_always_show_scrollbar(false);
    moved(ui, LogicalPosition::new(100.0, 100.0));
    mock_elapsed_time(Duration::ZERO);
    mock_elapsed_time(Duration::from_millis(1000));
    ui.set_term_scroll_offset(200);
    mock_elapsed_time(Duration::ZERO);
    mock_elapsed_time(Duration::from_millis(1000));
    assert_eq!(thumb.computed_opacity(), 1.0, "activity resets hide delay");
    mock_elapsed_time(Duration::from_millis(350));
    moved(ui, point(&rail, 5.0, 30.0));
    mock_elapsed_time(Duration::from_millis(400));
    assert_eq!(thumb.computed_opacity(), 1.0, "hover restores a fading bar");
    assert_eq!(thumb.size().width, 8.0);
    mock_elapsed_time(Duration::from_secs(3));
    assert_eq!(rail.size().width, 10.0, "hover keeps the rail open");
    moved(ui, LogicalPosition::new(100.0, 100.0));
    mock_elapsed_time(Duration::from_millis(1300));
    mock_elapsed_time(Duration::from_millis(450));
    assert_eq!(rail.size().width, 0.0, "hidden rail cannot steal selection");
    ui.set_term_scrollback_len(1100);
    mock_elapsed_time(Duration::from_millis(100));
    assert_eq!(
        rail.size().width,
        0.0,
        "buffer growth alone does not reveal"
    );
    ui.set_settings_always_show_scrollbar(true);
    assert_eq!(rail.size().width, 10.0, "setting applies immediately");
    ui.set_term_scrollback_len(0);
    assert_eq!(rail.size().width, 0.0, "no history leaves no hit target");

    queued_scrubs_keep_the_final_request_and_target_the_correct_pane();
    incoming_snapshots_update_the_thumb_on_the_same_tick();
}

fn incoming_snapshots_update_the_thumb_on_the_same_tick() {
    let (h, _, provider) = support::harness();
    // Start at a stable live tail, then exercise the real pointer -> request
    // -> session snapshot -> redraw path. No direct UI property updates.
    provider.publish_terminal_grid(0, snapshot());
    support::pump_ticks(1);
    assert_eq!(h.ui.get_term_scrollback_len(), 1000);
    let rail = find_by_id(&h.ui, "TerminalScrollbar::sb-touch");
    let initial_y = find_by_id(&h.ui, "TerminalScrollbar::thumb")
        .absolute_position()
        .y;
    click(&h.ui, point(&rail, 5.0, rail.size().height / 2.0));
    assert_eq!(provider.terminal_scroll_offsets_for(0), [24]);
    let mut paged = snapshot();
    paged.scroll_offset = 24;
    provider.publish_terminal_grid(0, paged);
    support::pump_ticks(1);
    assert_eq!(
        h.ui.get_term_scroll_offset(),
        24,
        "one click and one snapshot must move the thumb"
    );
    let paged_y = find_by_id(&h.ui, "TerminalScrollbar::thumb")
        .absolute_position()
        .y;
    assert!(paged_y < initial_y);
    for offset in [500, 1000, 0] {
        let mut snap = snapshot();
        snap.scroll_offset = offset;
        provider.publish_terminal_grid(0, snap);
        support::pump_ticks(1);
        assert_eq!(h.ui.get_term_scroll_offset(), offset as i32);
    }
    h.ui.invoke_split_pane_h();
    for (pane, offset) in [(0, 250), (1, 750)] {
        let mut snap = snapshot();
        snap.scroll_offset = offset;
        provider.publish_terminal_grid(pane, snap);
        support::pump_ticks(1);
        let cell =
            h.ui.get_pane_cells()
                .iter()
                .find(|cell| cell.pane == pane as i32)
                .unwrap();
        assert_eq!(
            cell.scroll_offset, offset as i32,
            "split pane snapshot must publish in the same tick"
        );
    }
}

fn queued_scrubs_keep_the_final_request_and_target_the_correct_pane() {
    let (h, _, provider) = support::harness();
    provider.publish_terminal_grid(0, snapshot());
    support::pump_ticks(2);
    // No snapshot arrives between these requests. The last must not be
    // discarded simply because it matches the last published offset.
    h.ui.invoke_scroll_scrub(0.5);
    h.ui.invoke_scroll_scrub(1.0);
    assert_eq!(provider.terminal_scroll_offsets_for(0), [500, 0]);

    h.ui.invoke_split_pane_h();
    provider.publish_terminal_grid(1, snapshot());
    support::pump_ticks(2);
    h.ui.invoke_pane_scroll_scrub(1, 0.25);
    h.ui.invoke_pane_scroll_scrub(1, 1.0);
    assert_eq!(provider.terminal_scroll_offsets_for(1), [750, 0]);
    assert_eq!(provider.terminal_scroll_offsets_for(0), [500, 0]);

    let rails: Vec<_> =
        ElementHandle::find_by_element_id(&h.ui, "TerminalScrollbar::sb-touch").collect();
    assert_eq!(rails.len(), 2);
    assert!(rails.iter().all(|rail| rail.size().width == 10.0));
    h.ui.invoke_settings_always_show_scrollbar_changed(false);
    mock_elapsed_time(Duration::ZERO);
    mock_elapsed_time(Duration::from_millis(1300));
    mock_elapsed_time(Duration::from_millis(450));
    assert!(
        ElementHandle::find_by_element_id(&h.ui, "TerminalScrollbar::sb-touch")
            .all(|rail| rail.size().width == 0.0)
    );
    h.ui.invoke_settings_always_show_scrollbar_changed(true);
    assert!(
        ElementHandle::find_by_element_id(&h.ui, "TerminalScrollbar::sb-touch")
            .all(|rail| rail.size().width == 10.0)
    );
}

fn snapshot() -> cm_core::GridSnapshot {
    use cm_core::{Cell, CellAttrs, Color, CursorShape, CursorState, GridSnapshot, TerminalSize};
    let size = TerminalSize { rows: 24, cols: 80 };
    GridSnapshot {
        size,
        cells: vec![
            Cell {
                grapheme: "x".into(),
                fg: Color::Default,
                bg: Color::Default,
                attrs: CellAttrs::empty(),
                width: 1,
            };
            usize::from(size.rows) * usize::from(size.cols)
        ],
        cursor: CursorState {
            row: 0,
            col: 0,
            visible: false,
            shape: CursorShape::Block,
        },
        scrollback_len: 1000,
        scroll_offset: 0,
        mouse_tracking: false,
    }
}

fn point(element: &ElementHandle, x: f32, y: f32) -> LogicalPosition {
    let origin = element.absolute_position();
    LogicalPosition::new(origin.x + x, origin.y + y)
}

fn moved(ui: &cm_ui::AppWindow, position: LogicalPosition) {
    ui.window()
        .dispatch_event(WindowEvent::PointerMoved { position });
}

fn press(ui: &cm_ui::AppWindow, position: LogicalPosition) {
    moved(ui, position);
    ui.window().dispatch_event(WindowEvent::PointerPressed {
        position,
        button: PointerEventButton::Left,
    });
}

fn release(ui: &cm_ui::AppWindow, position: LogicalPosition) {
    ui.window().dispatch_event(WindowEvent::PointerReleased {
        position,
        button: PointerEventButton::Left,
    });
}

fn click(ui: &cm_ui::AppWindow, position: LogicalPosition) {
    press(ui, position);
    release(ui, position);
}

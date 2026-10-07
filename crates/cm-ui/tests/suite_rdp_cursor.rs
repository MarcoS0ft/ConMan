//! Remote cursor updates must render without a desktop frame and remain pane scoped.
#![cfg(all(feature = "ui-introspection", not(target_arch = "wasm32")))]
mod support;

use cm_core::RdpCursor;
use i_slint_backend_testing::ElementHandle;
use slint::platform::WindowEvent;
use slint::{ComponentHandle, LogicalPosition, Model};
use support::{harness, pump_ticks};

fn connect(h: &cm_ui::TestHarness, provider: &support::MockSessionProvider, index: usize) {
    h.ui.invoke_quick_connect();
    h.ui.set_qc_kind(1);
    h.ui.set_qc_host("cursor.example.invalid".into());
    h.ui.set_qc_username("synthetic-user".into());
    h.ui.set_qc_secret("synthetic-password".into());
    h.ui.invoke_qc_connect();
    provider.publish_rdp_frame(index, 1280, 720);
    pump_ticks(1);
}

fn bitmap() -> RdpCursor {
    RdpCursor::Bitmap {
        width: 24,
        height: 32,
        hotspot_x: 7,
        hotspot_y: 11,
        rgba: vec![255; 24 * 32 * 4].into(),
    }
}

#[test]
fn rdp_cursor_suite() {
    i_slint_backend_testing::init_integration_test_with_mock_time();
    let (h, _repo, provider) = harness();
    connect(&h, &provider, 0);
    assert_eq!(h.ui.get_rdp_cursor().kind, 0);
    provider.publish_rdp_cursor(0, bitmap());
    pump_ticks(1); // No framebuffer publication accompanies the cursor.
    let cursor = h.ui.get_rdp_cursor();
    assert_eq!(cursor.kind, 2);
    assert_eq!((cursor.hotspot_x, cursor.hotspot_y), (7, 11));
    assert_eq!(cursor.bitmap.size().width, 24);

    let area = ElementHandle::find_by_element_id(&h.ui, "RdpSurface::rdp-ta")
        .next()
        .unwrap();
    let position = area.absolute_position();
    let size = area.size();
    let mouse = LogicalPosition::new(
        position.x + size.width / 2.0,
        position.y + size.height / 2.0,
    );
    h.ui.window()
        .dispatch_event(WindowEvent::PointerMoved { position: mouse });
    pump_ticks(1);
    let overlay = ElementHandle::find_by_element_id(&h.ui, "RdpSurface::remote-cursor")
        .next()
        .unwrap();
    let scale = (size.width / 1280.0).min(size.height / 720.0);
    assert!((overlay.size().width - 24.0 * scale).abs() < 0.1);
    assert!((overlay.size().height - 32.0 * scale).abs() < 0.1);
    assert!((overlay.absolute_position().x - (mouse.x - 7.0 * scale)).abs() < 0.1);
    assert!((overlay.absolute_position().y - (mouse.y - 11.0 * scale)).abs() < 0.1);
    h.ui.window().dispatch_event(WindowEvent::PointerExited);
    pump_ticks(1);
    assert!(
        ElementHandle::find_by_element_id(&h.ui, "RdpSurface::remote-cursor")
            .next()
            .is_none()
    );

    provider.publish_rdp_cursor(0, RdpCursor::Hidden);
    pump_ticks(1);
    assert_eq!(h.ui.get_rdp_cursor().kind, 1);
    provider.publish_rdp_cursor(0, RdpCursor::Default);
    pump_ticks(1);
    assert_eq!(h.ui.get_rdp_cursor().kind, 0);
    provider.publish_rdp_cursor(0, bitmap());
    pump_ticks(1);

    connect(&h, &provider, 1);
    assert_eq!(
        h.ui.get_rdp_cursor().kind,
        0,
        "new tab cannot inherit old cursor"
    );
    provider.publish_rdp_cursor(1, RdpCursor::Hidden);
    pump_ticks(1);
    h.ui.invoke_select_tab(1);
    assert_eq!(
        h.ui.get_rdp_cursor().kind,
        2,
        "switch restores retained bitmap"
    );
    h.ui.invoke_select_tab(2);
    assert_eq!(h.ui.get_rdp_cursor().kind, 1);
    provider.publish_rdp_cursor(0, RdpCursor::Default);
    pump_ticks(1); // Background updates remain available on presentation.
    h.ui.invoke_select_tab(1);
    assert_eq!(h.ui.get_rdp_cursor().kind, 0);

    provider.publish_rdp_cursor(0, bitmap());
    pump_ticks(1);
    h.ui.invoke_split_pane_h();
    pump_ticks(1);
    let cells = h.ui.get_pane_cells();
    assert_eq!(cells.row_count(), 2);
    assert_eq!(cells.row_data(0).unwrap().cursor.kind, 2);
    assert_eq!(cells.row_data(1).unwrap().cursor.kind, 0);
    provider.publish_rdp_cursor(0, RdpCursor::Hidden);
    pump_ticks(1);
    assert_eq!(h.ui.get_pane_cells().row_data(0).unwrap().cursor.kind, 1);
    assert_eq!(h.ui.get_pane_cells().row_data(1).unwrap().cursor.kind, 0);
}

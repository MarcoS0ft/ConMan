//! Retained, coalesced cursor state shared by the RDP driver and UI.

use std::sync::Mutex;

use cm_core::RdpCursor;
use ironrdp_session::ActiveStageOutput;

#[derive(Debug, Default)]
pub(super) struct CursorMailbox(Mutex<(RdpCursor, bool)>);

impl CursorMailbox {
    pub(super) fn current(&self) -> RdpCursor {
        self.0.lock().expect("cursor mailbox poisoned").0.clone()
    }

    pub(super) fn take_update(&self) -> Option<RdpCursor> {
        let mut state = self.0.lock().expect("cursor mailbox poisoned");
        std::mem::take(&mut state.1).then(|| state.0.clone())
    }

    pub(super) fn process(&self, output: &ActiveStageOutput) {
        let cursor = match output {
            ActiveStageOutput::PointerDefault => RdpCursor::Default,
            ActiveStageOutput::PointerHidden => RdpCursor::Hidden,
            ActiveStageOutput::PointerBitmap(bitmap) => RdpCursor::Bitmap {
                width: bitmap.width,
                height: bitmap.height,
                hotspot_x: bitmap.hotspot_x,
                hotspot_y: bitmap.hotspot_y,
                rgba: bitmap.bitmap_data.clone().into(),
            },
            // Server position updates must not warp the user's local pointer.
            _ => return,
        };
        let mut state = self.0.lock().expect("cursor mailbox poisoned");
        if state.0 != cursor {
            *state = (cursor, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironrdp_graphics::pointer::DecodedPointer;
    use std::sync::Arc;

    #[test]
    fn cursor_updates_coalesce_and_remain_available_for_tab_switches() {
        let mailbox = CursorMailbox::default();
        assert_eq!(mailbox.current(), RdpCursor::Default);
        assert_eq!(mailbox.take_update(), None);
        mailbox.process(&ActiveStageOutput::PointerHidden);
        mailbox.process(&ActiveStageOutput::PointerBitmap(Arc::new(
            DecodedPointer {
                width: 2,
                height: 1,
                hotspot_x: 1,
                hotspot_y: 0,
                bitmap_data: vec![255, 0, 0, 255, 0, 0, 0, 0],
            },
        )));
        let expected = RdpCursor::Bitmap {
            width: 2,
            height: 1,
            hotspot_x: 1,
            hotspot_y: 0,
            rgba: vec![255, 0, 0, 255, 0, 0, 0, 0].into(),
        };
        assert_eq!(mailbox.take_update(), Some(expected.clone()));
        assert_eq!(mailbox.take_update(), None);
        assert_eq!(mailbox.current(), expected);
        mailbox.process(&ActiveStageOutput::PointerPosition { x: 20, y: 30 });
        assert_eq!(mailbox.take_update(), None);
        mailbox.process(&ActiveStageOutput::PointerHidden);
        assert_eq!(mailbox.take_update(), Some(RdpCursor::Hidden));
        mailbox.process(&ActiveStageOutput::PointerDefault);
        assert_eq!(mailbox.take_update(), Some(RdpCursor::Default));
    }
}

//! Private finite-state PNG frame preparation for the later WSS consumer.

mod frame;
mod png;
mod state;

#[cfg(test)]
mod tests;

const MAX_WIDTH: u16 = 3840;
const MAX_HEIGHT: u16 = 2160;
const TILE_SIZE: usize = 64;
const MAX_TILE_PNG_BYTES: usize = 20 * 1024;
const MAX_FRAME_PNG_BYTES: usize = 40 * 1024 * 1024;
const PNG_STREAM_WORKSPACE_BYTES: usize = 16 * 1024;
const PNG_CHUNK_BUFFER_BYTES: usize = 4 * 1024;
const MAX_TILE_COUNT: usize = 2040;
const MAX_TILE_PLAN_BYTES: usize = 24 + 16 * MAX_TILE_COUNT;
const FRAME_AND_LEASE_HEADERS_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FrameKind {
    Keyframe,
    Delta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TilePlan {
    pub(super) x: u16,
    pub(super) y: u16,
    pub(super) width: u16,
    pub(super) height: u16,
    pub(super) png_len: u32,
    pub(super) payload_offset: u32,
}

const FRAME_INTERVAL: std::time::Duration = std::time::Duration::from_nanos(33_333_334);
const FRAME_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_RESYNC_FAILURES: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StreamError {
    InvalidDimensions,
    InvalidRgbaLength,
    FrameTooLarge,
    ResourceLimit,
    PngTileTooLarge,
    EncodedFrameTooLarge,
    SequenceExhausted,
    EpochExhausted,
    StaleGeneration,
    InvalidAck,
    ResyncFailures,
    Closed,
    CodecFailure,
}

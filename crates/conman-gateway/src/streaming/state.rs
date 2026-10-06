use std::sync::{Arc, Weak};
use std::time::Instant;

use super::frame::FramePixels;
use super::png::encode_tiles;
use super::{
    FRAME_ACK_TIMEOUT, FRAME_AND_LEASE_HEADERS_BYTES, FRAME_INTERVAL, FrameKind,
    MAX_FRAME_PNG_BYTES, MAX_HEIGHT, MAX_TILE_COUNT, MAX_TILE_PLAN_BYTES, MAX_TILE_PNG_BYTES,
    MAX_WIDTH, PNG_STREAM_WORKSPACE_BYTES, StreamError, TILE_SIZE,
};

#[derive(Debug)]
pub(super) struct NativeFrame {
    pub(super) generation: u64,
    pub(super) width: u16,
    pub(super) height: u16,
    pub(super) rgba: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FrameAck {
    pub(super) generation: u64,
    pub(super) epoch: u64,
    pub(super) sequence: u64,
}

#[derive(Debug)]
pub(super) struct EncodedPayload {
    bytes: Vec<u8>,
    _lease: Arc<PayloadLease>,
}

impl EncodedPayload {
    pub(super) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug)]
struct PayloadLease;

#[derive(Debug)]
pub(super) struct PreparedFrame {
    generation: u64,
    epoch: u64,
    sequence: u64,
    base_sequence: Option<u64>,
    width: u16,
    height: u16,
    kind: FrameKind,
    total_png_bytes: u32,
    tiles: Vec<super::TilePlan>,
    png_payload: EncodedPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PreparedFrameMetadata {
    pub(super) generation: u64,
    pub(super) epoch: u64,
    pub(super) sequence: u64,
    pub(super) base_sequence: Option<u64>,
    pub(super) width: u16,
    pub(super) height: u16,
    pub(super) kind: FrameKind,
    pub(super) total_png_bytes: u32,
    pub(super) tile_count: usize,
}

impl PreparedFrame {
    pub(super) fn metadata(&self) -> PreparedFrameMetadata {
        PreparedFrameMetadata {
            generation: self.generation,
            epoch: self.epoch,
            sequence: self.sequence,
            base_sequence: self.base_sequence,
            width: self.width,
            height: self.height,
            kind: self.kind,
            total_png_bytes: self.total_png_bytes,
            tile_count: self.tiles.len(),
        }
    }

    pub(super) fn tiles(&self) -> &[super::TilePlan] {
        &self.tiles
    }

    pub(super) fn png_payload(&self) -> &[u8] {
        self.png_payload.as_slice()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OfferResult {
    StoredLatest { replaced: bool },
    Unchanged,
    RateLimited,
    AwaitingAck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AckResult {
    Accepted,
    Duplicate,
    Stale,
    TimedOut { output: StreamOutput },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StreamCloseReason {
    ResyncFailures,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StreamOutput {
    Noop,
    Abort { epoch: u64, sequence: u64 },
    Closed(StreamCloseReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TimeoutResult {
    NotDue,
    Resyncing { epoch: u64, sequence: u64 },
    Closed(StreamCloseReason),
}

#[derive(Debug)]
struct Candidate {
    frame: FramePixels,
    epoch: u64,
    sequence: u64,
    deadline: Instant,
}

#[derive(Debug)]
struct Baseline {
    frame: FramePixels,
    epoch: u64,
    sequence: u64,
}

#[derive(Debug)]
pub(super) struct FrameState {
    generation: u64,
    epoch: u64,
    next_sequence: Option<u64>,
    force_keyframe: bool,
    latest: Option<FramePixels>,
    candidate: Option<Candidate>,
    baseline: Option<Baseline>,
    last_ack: Option<FrameAck>,
    last_emit: Option<Instant>,
    payload_lease: Option<Weak<PayloadLease>>,
    resync_failures: u8,
    closed: bool,
}

impl FrameState {
    pub(super) fn new(generation: u64) -> Self {
        Self {
            generation,
            epoch: 0,
            next_sequence: Some(1),
            force_keyframe: true,
            latest: None,
            candidate: None,
            baseline: None,
            last_ack: None,
            last_emit: None,
            payload_lease: None,
            resync_failures: 0,
            closed: false,
        }
    }

    pub(super) fn offer(
        &mut self,
        frame: NativeFrame,
        now: Instant,
    ) -> Result<OfferResult, StreamError> {
        self.ensure_open()?;
        if frame.generation != self.generation {
            return Err(StreamError::StaleGeneration);
        }

        let mut pixels = FramePixels::new(frame.width, frame.height, frame.rgba)?;
        pixels.normalize_opaque();
        let replaced = self.latest.replace(pixels).is_some();

        if self.candidate.is_some() {
            return Ok(OfferResult::AwaitingAck);
        }
        if self.is_rate_limited(now) {
            return Ok(OfferResult::RateLimited);
        }
        Ok(OfferResult::StoredLatest { replaced })
    }

    pub(super) fn prepare_next(
        &mut self,
        now: Instant,
    ) -> Result<Option<PreparedFrame>, StreamError> {
        self.ensure_open()?;
        self.expire_payload_lease();
        if self.payload_lease.is_some() || self.candidate.is_some() || self.is_rate_limited(now) {
            return Ok(None);
        }

        let Some(frame) = self.latest.as_ref() else {
            return Ok(None);
        };
        let baseline = self.baseline.as_ref();
        let dimensions_match = baseline.is_some_and(|base| {
            base.frame.width == frame.width
                && base.frame.height == frame.height
                && base.epoch == self.epoch
        });
        let is_keyframe = self.force_keyframe || !dimensions_match;

        let epoch = if is_keyframe {
            match self.epoch.checked_add(1) {
                Some(epoch) => epoch,
                None => {
                    self.closed = true;
                    return Err(StreamError::EpochExhausted);
                }
            }
        } else {
            self.epoch
        };
        let sequence = match self.next_sequence {
            Some(sequence) => sequence,
            None => {
                self.closed = true;
                return Err(StreamError::SequenceExhausted);
            }
        };

        let encoded = encode_tiles(
            frame,
            if is_keyframe {
                None
            } else {
                baseline.map(|base| &base.frame)
            },
        )?;
        let Some(encoded) = encoded else {
            self.latest = None;
            return Ok(None);
        };
        let kind = encoded.kind;
        let base_sequence = if kind == FrameKind::Delta {
            baseline.map(|base| base.sequence)
        } else {
            None
        };
        let total_png_bytes =
            u32::try_from(encoded.payload.len()).map_err(|_| StreamError::EncodedFrameTooLarge)?;
        let width = frame.width;
        let height = frame.height;
        let deadline = now
            .checked_add(FRAME_ACK_TIMEOUT)
            .ok_or(StreamError::CodecFailure)?;

        let sequence_after = sequence.checked_add(1);
        let payload_lease = Arc::new(PayloadLease);
        self.payload_lease = Some(Arc::downgrade(&payload_lease));
        self.epoch = epoch;
        self.force_keyframe = false;
        self.next_sequence = sequence_after;
        self.last_emit = Some(now);
        let frame = self.latest.take().ok_or(StreamError::CodecFailure)?;
        self.candidate = Some(Candidate {
            frame,
            epoch,
            sequence,
            deadline,
        });

        Ok(Some(PreparedFrame {
            generation: self.generation,
            epoch,
            sequence,
            base_sequence,
            width,
            height,
            kind,
            total_png_bytes,
            tiles: encoded.plans,
            png_payload: EncodedPayload {
                bytes: encoded.payload,
                _lease: payload_lease,
            },
        }))
    }

    pub(super) fn acknowledge(
        &mut self,
        ack: FrameAck,
        now: Instant,
    ) -> Result<AckResult, StreamError> {
        self.ensure_open()?;
        if let Some(last_ack) = self.last_ack {
            if ack == last_ack {
                return Ok(AckResult::Duplicate);
            }
            if ack.generation == self.generation && ack.sequence < last_ack.sequence {
                return Ok(AckResult::Stale);
            }
        }

        let Some(candidate) = self.candidate.as_ref() else {
            return Err(self.invalid_ack());
        };
        if now >= candidate.deadline {
            return Ok(AckResult::TimedOut {
                output: self.timeout(now)?,
            });
        }
        if ack.generation != self.generation
            || ack.epoch != candidate.epoch
            || ack.sequence != candidate.sequence
        {
            if ack.generation == self.generation && ack.sequence < candidate.sequence {
                return Ok(AckResult::Stale);
            }
            return Err(self.invalid_ack());
        }

        let candidate = self.candidate.take().ok_or(StreamError::InvalidAck)?;
        self.baseline = Some(Baseline {
            frame: candidate.frame,
            epoch: candidate.epoch,
            sequence: candidate.sequence,
        });
        self.last_ack = Some(ack);
        self.resync_failures = 0;
        Ok(AckResult::Accepted)
    }

    pub(super) fn timeout(&mut self, now: Instant) -> Result<StreamOutput, StreamError> {
        self.ensure_open()?;
        let Some(candidate) = self.candidate.as_ref() else {
            return Ok(StreamOutput::Noop);
        };
        if now < candidate.deadline {
            return Ok(StreamOutput::Noop);
        }
        let epoch = candidate.epoch;
        let sequence = candidate.sequence;
        if self.abort_and_resync_inner(true) {
            self.closed = true;
            Ok(StreamOutput::Closed(StreamCloseReason::ResyncFailures))
        } else {
            Ok(StreamOutput::Abort { epoch, sequence })
        }
    }

    pub(super) fn timeout_result(&mut self, now: Instant) -> Result<TimeoutResult, StreamError> {
        match self.timeout(now)? {
            StreamOutput::Noop => Ok(TimeoutResult::NotDue),
            StreamOutput::Abort { epoch, sequence } => {
                Ok(TimeoutResult::Resyncing { epoch, sequence })
            }
            StreamOutput::Closed(reason) => Ok(TimeoutResult::Closed(reason)),
        }
    }

    pub(super) fn abort_and_resync(&mut self, _reason: ResyncReason) -> Result<(), StreamError> {
        self.ensure_open()?;
        if self.abort_and_resync_inner(false) {
            self.closed = true;
            return Err(StreamError::Closed);
        }
        Ok(())
    }

    fn abort_and_resync_inner(&mut self, count_failure: bool) -> bool {
        if let Some(candidate) = self.candidate.take()
            && self.latest.is_none()
        {
            self.latest = Some(candidate.frame);
        }
        self.force_keyframe = true;
        if count_failure {
            self.resync_failures = self.resync_failures.saturating_add(1);
        }
        self.resync_failures >= super::MAX_RESYNC_FAILURES
    }

    fn invalid_ack(&mut self) -> StreamError {
        if self.abort_and_resync_inner(true) {
            self.closed = true;
            StreamError::ResyncFailures
        } else {
            StreamError::InvalidAck
        }
    }

    fn is_rate_limited(&self, now: Instant) -> bool {
        self.last_emit
            .is_some_and(|last| now.saturating_duration_since(last) < FRAME_INTERVAL)
    }

    fn expire_payload_lease(&mut self) {
        if self
            .payload_lease
            .as_ref()
            .is_some_and(|lease| lease.upgrade().is_none())
        {
            self.payload_lease = None;
        }
    }

    fn ensure_open(&self) -> Result<(), StreamError> {
        if self.closed {
            Err(StreamError::Closed)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(super) fn set_counters_for_test(&mut self, epoch: u64, next_sequence: Option<u64>) {
        self.epoch = epoch;
        self.next_sequence = next_sequence;
        self.force_keyframe = true;
    }

    #[cfg(test)]
    pub(super) fn retained_frame_capacities_for_test(
        &self,
    ) -> (Option<usize>, Option<usize>, Option<usize>) {
        (
            self.latest.as_ref().map(|frame| frame.rgba.capacity()),
            self.candidate
                .as_ref()
                .map(|candidate| candidate.frame.rgba.capacity()),
            self.baseline
                .as_ref()
                .map(|baseline| baseline.frame.rgba.capacity()),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResyncReason {
    Timeout,
    InvalidAcknowledgement,
    Explicit,
}

pub(super) fn codec_reservation_bytes(width: u16, height: u16) -> Result<usize, StreamError> {
    if width == 0 || height == 0 || width > MAX_WIDTH || height > MAX_HEIGHT {
        return Err(StreamError::InvalidDimensions);
    }
    let frame_bytes = usize::from(width)
        .checked_mul(usize::from(height))
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(StreamError::FrameTooLarge)?;
    let tiles_x = usize::from(width).div_ceil(TILE_SIZE);
    let tiles_y = usize::from(height).div_ceil(TILE_SIZE);
    let tile_count = tiles_x
        .checked_mul(tiles_y)
        .ok_or(StreamError::FrameTooLarge)?;
    if tile_count > MAX_TILE_COUNT {
        return Err(StreamError::FrameTooLarge);
    }
    let payload_bound = (tile_count * MAX_TILE_PNG_BYTES).min(MAX_FRAME_PNG_BYTES);
    4usize
        .checked_mul(frame_bytes)
        .and_then(|frames| frames.checked_add(payload_bound))
        .and_then(|bytes| bytes.checked_add(MAX_TILE_PLAN_BYTES.min(24 + 16 * tile_count)))
        .and_then(|bytes| bytes.checked_add(FRAME_AND_LEASE_HEADERS_BYTES))
        .and_then(|bytes| bytes.checked_add(PNG_STREAM_WORKSPACE_BYTES))
        .ok_or(StreamError::FrameTooLarge)
}

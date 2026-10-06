use std::cell::Cell;
use std::io::{self, Write};

use png::{BitDepth, ColorType, DeflateCompression, Encoder, Filter};

use super::frame::{FramePixels, TileRect, tile_rects};
use super::{
    FrameKind, MAX_FRAME_PNG_BYTES, MAX_TILE_COUNT, MAX_TILE_PNG_BYTES, PNG_CHUNK_BUFFER_BYTES,
    StreamError, TilePlan,
};

#[derive(Debug)]
pub(super) struct EncodedTiles {
    pub(super) kind: FrameKind,
    pub(super) plans: Vec<TilePlan>,
    pub(super) payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LimitFailure {
    Tile,
    Frame,
}

struct BoundedFrameWriter<'a> {
    output: &'a mut Vec<u8>,
    tile_end_limit: usize,
    frame_end_limit: usize,
    failure: &'a Cell<Option<LimitFailure>>,
}

impl Write for BoundedFrameWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(end) = self.output.len().checked_add(bytes.len()) else {
            self.failure.set(Some(LimitFailure::Frame));
            return Err(io::Error::new(io::ErrorKind::WriteZero, "PNG frame bound"));
        };
        if end > self.tile_end_limit {
            self.failure.set(Some(LimitFailure::Tile));
            return Err(io::Error::new(io::ErrorKind::WriteZero, "PNG tile bound"));
        }
        if end > self.frame_end_limit {
            self.failure.set(Some(LimitFailure::Frame));
            return Err(io::Error::new(io::ErrorKind::WriteZero, "PNG frame bound"));
        }

        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn encode_tiles(
    frame: &FramePixels,
    baseline: Option<&FramePixels>,
) -> Result<Option<EncodedTiles>, StreamError> {
    encode_tiles_with_limits(frame, baseline, MAX_TILE_PNG_BYTES, MAX_FRAME_PNG_BYTES)
}

pub(super) fn encode_tiles_with_limits(
    frame: &FramePixels,
    baseline: Option<&FramePixels>,
    tile_cap: usize,
    frame_cap: usize,
) -> Result<Option<EncodedTiles>, StreamError> {
    let is_delta =
        baseline.is_some_and(|base| base.width == frame.width && base.height == frame.height);
    let kind = if is_delta {
        FrameKind::Delta
    } else {
        FrameKind::Keyframe
    };

    let tile_count = tile_rects(frame.width, frame.height)
        .filter(|tile| !is_delta || baseline.is_some_and(|base| !frame.tile_equals(base, *tile)))
        .count();
    if tile_count == 0 {
        return Ok(None);
    }
    if tile_count > MAX_TILE_COUNT {
        return Err(StreamError::FrameTooLarge);
    }

    let mut plans = Vec::new();
    plans
        .try_reserve_exact(tile_count)
        .map_err(|_| StreamError::ResourceLimit)?;
    if plans.capacity() > MAX_TILE_COUNT {
        return Err(StreamError::ResourceLimit);
    }

    let tile_total_bound = tile_rects(frame.width, frame.height)
        .count()
        .checked_mul(tile_cap)
        .ok_or(StreamError::FrameTooLarge)?;
    let frame_bound = frame_cap.min(tile_total_bound);
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(frame_bound)
        .map_err(|_| StreamError::ResourceLimit)?;
    if payload.capacity() > frame_bound {
        return Err(StreamError::ResourceLimit);
    }

    let limit_failure = Cell::new(None);
    for tile in tile_rects(frame.width, frame.height) {
        if is_delta && baseline.is_some_and(|base| frame.tile_equals(base, tile)) {
            continue;
        }

        let payload_offset = payload.len();
        let tile_end_limit = payload_offset
            .checked_add(tile_cap)
            .ok_or(StreamError::EncodedFrameTooLarge)?;
        encode_tile(
            frame,
            tile,
            &mut payload,
            tile_end_limit,
            frame_bound,
            &limit_failure,
        )?;

        let png_len = payload
            .len()
            .checked_sub(payload_offset)
            .ok_or(StreamError::EncodedFrameTooLarge)?;
        if png_len > tile_cap {
            return Err(StreamError::PngTileTooLarge);
        }
        let payload_offset =
            u32::try_from(payload_offset).map_err(|_| StreamError::EncodedFrameTooLarge)?;
        let png_len = u32::try_from(png_len).map_err(|_| StreamError::EncodedFrameTooLarge)?;
        plans.push(TilePlan {
            x: tile.x,
            y: tile.y,
            width: tile.width,
            height: tile.height,
            png_len,
            payload_offset,
        });
    }

    if payload.len() > frame_bound || payload.len() > frame_cap {
        return Err(StreamError::EncodedFrameTooLarge);
    }
    if plans.len() != tile_count
        || plans.capacity() > MAX_TILE_COUNT
        || payload.capacity() > frame_bound
    {
        return Err(StreamError::ResourceLimit);
    }

    Ok(Some(EncodedTiles {
        kind,
        plans,
        payload,
    }))
}

fn encode_tile(
    frame: &FramePixels,
    tile: TileRect,
    payload: &mut Vec<u8>,
    tile_end_limit: usize,
    frame_end_limit: usize,
    limit_failure: &Cell<Option<LimitFailure>>,
) -> Result<(), StreamError> {
    let sink = BoundedFrameWriter {
        output: payload,
        tile_end_limit,
        frame_end_limit,
        failure: limit_failure,
    };
    let mut encoder = Encoder::new(sink, u32::from(tile.width), u32::from(tile.height));
    encoder.set_color(ColorType::Rgba);
    encoder.set_depth(BitDepth::Eight);
    encoder.set_deflate_compression(DeflateCompression::FdeflateUltraFast);
    encoder.set_filter(Filter::NoFilter);

    let write_result = (|| -> Result<(), png::EncodingError> {
        let mut writer = encoder.write_header()?;
        {
            let mut stream = writer.stream_writer_with_size(PNG_CHUNK_BUFFER_BYTES)?;
            for row in tile.y..tile.y + tile.height {
                stream.write_all(frame.tile_row(tile, row))?;
            }
            stream.finish()?;
        }
        writer.finish()?;
        Ok(())
    })();

    if write_result.is_err() {
        return Err(match limit_failure.get() {
            Some(LimitFailure::Tile) => StreamError::PngTileTooLarge,
            Some(LimitFailure::Frame) => StreamError::EncodedFrameTooLarge,
            None => StreamError::CodecFailure,
        });
    }

    Ok(())
}

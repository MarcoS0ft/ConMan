use super::{MAX_HEIGHT, MAX_TILE_COUNT, MAX_WIDTH, StreamError, TILE_SIZE};

#[derive(Debug)]
pub(super) struct FramePixels {
    pub(super) width: u16,
    pub(super) height: u16,
    pub(super) rgba: Vec<u8>,
}

impl FramePixels {
    pub(super) fn new(width: u16, height: u16, rgba: Vec<u8>) -> Result<Self, StreamError> {
        if width == 0 || height == 0 || width > MAX_WIDTH || height > MAX_HEIGHT {
            return Err(StreamError::InvalidDimensions);
        }

        let expected = usize::from(width)
            .checked_mul(usize::from(height))
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or(StreamError::FrameTooLarge)?;
        if expected > usize::from(MAX_WIDTH) * usize::from(MAX_HEIGHT) * 4 {
            return Err(StreamError::FrameTooLarge);
        }
        if rgba.len() != expected {
            return Err(StreamError::InvalidRgbaLength);
        }
        if rgba.capacity() != expected {
            return Err(StreamError::ResourceLimit);
        }

        Ok(Self {
            width,
            height,
            rgba,
        })
    }

    pub(super) fn byte_len(&self) -> usize {
        self.rgba.len()
    }

    pub(super) fn normalize_opaque(&mut self) {
        for pixel in self.rgba.chunks_exact_mut(4) {
            pixel[3] = 255;
        }
    }

    pub(super) fn tile_equals(&self, other: &Self, tile: TileRect) -> bool {
        if self.width != other.width || self.height != other.height {
            return false;
        }

        let bytes_per_row = usize::from(tile.width) * 4;
        for row in tile.y..tile.y + tile.height {
            let start = (usize::from(row) * usize::from(self.width) + usize::from(tile.x)) * 4;
            let end = start + bytes_per_row;
            if self.rgba[start..end] != other.rgba[start..end] {
                return false;
            }
        }
        true
    }

    pub(super) fn tile_row(&self, tile: TileRect, row: u16) -> &[u8] {
        let start = (usize::from(row) * usize::from(self.width) + usize::from(tile.x)) * 4;
        let end = start + usize::from(tile.width) * 4;
        &self.rgba[start..end]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TileRect {
    pub(super) x: u16,
    pub(super) y: u16,
    pub(super) width: u16,
    pub(super) height: u16,
}

pub(super) fn tile_rects(width: u16, height: u16) -> impl Iterator<Item = TileRect> {
    let columns = usize::from(width).div_ceil(TILE_SIZE);
    let rows = usize::from(height).div_ceil(TILE_SIZE);
    let count = (columns * rows).min(MAX_TILE_COUNT);

    (0..count).map(move |index| {
        let column = index % columns;
        let row = index / columns;
        let x = column * TILE_SIZE;
        let y = row * TILE_SIZE;
        TileRect {
            x: x as u16,
            y: y as u16,
            width: (usize::from(width) - x).min(TILE_SIZE) as u16,
            height: (usize::from(height) - y).min(TILE_SIZE) as u16,
        }
    })
}

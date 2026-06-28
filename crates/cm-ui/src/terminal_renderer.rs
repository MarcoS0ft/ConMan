//! Glyph-atlas terminal renderer (P2.3).
//!
//! Rasterizes a [`cm_core::GridSnapshot`] into an RGBA [`slint::SharedPixelBuffer`]
//! using a software monospace glyph atlas — the approach benchmarked and recommended in
//! the P0.3 spike. Pure CPU work, headless-testable, no windowing/GPU dependency.
//!
//! ## Threading (`!Send` boundary, ARCHITECTURE §4 / P0.3)
//! [`TerminalRenderer::render`] returns a `SharedPixelBuffer`, which **is** `Send`. The
//! `slint::Image::from_rgba8` wrap (which yields a `!Send` `Image`) is deliberately *not*
//! done here — it happens on the UI thread in P2.4. So `render` is callable on the engine
//! thread that owns the (`!Send`) VT engine; only the buffer crosses to the UI thread.
//!
//! ## Fonts (bundled, see `assets/fonts/`)
//! Base: JetBrains Mono Nerd Font Mono (regular/bold/italic/bold-italic), SIL OFL-1.1.
//! Fallback: Symbols Nerd Font Mono, MIT. Lookup is **base → symbols**, so even a
//! non-patched base font would still get Nerd Font icon coverage (ARCHITECTURE §5). With
//! the bundled, already-patched JetBrains Mono the base resolves Nerd glyphs directly; the
//! fallback exists for the P2.4 user-font-picker case.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use cm_core::{CellAttrs, Color, CursorShape, GridSnapshot, TerminalSize};
use fontdue::{Font, FontSettings};
use slint::{Rgba8Pixel, SharedPixelBuffer};

// ── Bundled fonts ───────────────────────────────────────────────────────────────────
static FONT_REGULAR: &[u8] =
    include_bytes!("../assets/fonts/JetBrainsMonoNerdFontMono-Regular.ttf");
static FONT_BOLD: &[u8] = include_bytes!("../assets/fonts/JetBrainsMonoNerdFontMono-Bold.ttf");
static FONT_ITALIC: &[u8] = include_bytes!("../assets/fonts/JetBrainsMonoNerdFontMono-Italic.ttf");
static FONT_BOLD_ITALIC: &[u8] =
    include_bytes!("../assets/fonts/JetBrainsMonoNerdFontMono-BoldItalic.ttf");
static FONT_SYMBOLS: &[u8] = include_bytes!("../assets/fonts/SymbolsNerdFontMono-Regular.ttf");

/// An RGB color (no alpha; the buffer is composited opaque).
pub type Rgb = (u8, u8, u8);

/// Which font in the fallback chain resolves a given character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlyphSource {
    /// The styled base font (JetBrains Mono Nerd Font) has the glyph.
    Base,
    /// The base lacks it; the Symbols Nerd Font Mono fallback has it.
    Fallback,
    /// Neither font has the glyph (renders as the font's `.notdef`, usually blank).
    Missing,
}

/// Derived cell geometry, in **physical** pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CellMetrics {
    /// Cell advance width (physical px).
    pub cell_w: u32,
    /// Cell height / line height (physical px).
    pub cell_h: u32,
    /// Baseline offset from the top of the cell (physical px).
    pub baseline: i32,
    /// Font ascent (physical px, positive).
    pub ascent: f32,
    /// Font descent (physical px, negative or zero).
    pub descent: f32,
}

/// Terminal color theme: default fg/bg, the 16 ANSI base colors (extended to 256 via the
/// standard color-cube/grayscale formula), and the cursor color. One dark default ships;
/// a theming UI is P5.
#[derive(Debug, Clone)]
pub struct TerminalTheme {
    pub fg: Rgb,
    pub bg: Rgb,
    pub cursor: Rgb,
    /// The 16 ANSI colors (0-7 normal, 8-15 bright).
    pub ansi: [Rgb; 16],
}

impl TerminalTheme {
    /// A reasonable dark default (close to the common VS Code dark palette).
    #[must_use]
    pub fn dark() -> Self {
        Self {
            fg: (0xd4, 0xd4, 0xd4),
            bg: (0x1e, 0x1e, 0x1e),
            cursor: (0xd4, 0xd4, 0xd4),
            ansi: [
                (0x1e, 0x1e, 0x1e), // 0 black
                (0xcd, 0x31, 0x31), // 1 red
                (0x0d, 0xbc, 0x79), // 2 green
                (0xe5, 0xe5, 0x10), // 3 yellow
                (0x24, 0x72, 0xc8), // 4 blue
                (0xbc, 0x3f, 0xbc), // 5 magenta
                (0x11, 0xa8, 0xcd), // 6 cyan
                (0xe5, 0xe5, 0xe5), // 7 white
                (0x66, 0x66, 0x66), // 8 bright black
                (0xf1, 0x4c, 0x4c), // 9 bright red
                (0x23, 0xd1, 0x8b), // 10 bright green
                (0xf5, 0xf5, 0x43), // 11 bright yellow
                (0x3b, 0x8e, 0xea), // 12 bright blue
                (0xd6, 0x70, 0xd6), // 13 bright magenta
                (0x29, 0xb8, 0xdb), // 14 bright cyan
                (0xff, 0xff, 0xff), // 15 bright white
            ],
        }
    }

    /// Resolve a [`Color`] to concrete RGB. `is_fg` selects the default fg vs bg.
    fn resolve(&self, c: Color, is_fg: bool) -> Rgb {
        match c {
            Color::Default => {
                if is_fg {
                    self.fg
                } else {
                    self.bg
                }
            }
            Color::Palette(n) => self.palette_256(n),
            Color::Rgb { r, g, b } => (r, g, b),
        }
    }

    /// Map a 256-color index: 0-15 ANSI, 16-231 the 6×6×6 cube, 232-255 grayscale ramp.
    fn palette_256(&self, n: u8) -> Rgb {
        match n {
            0..=15 => self.ansi[n as usize],
            16..=231 => {
                let i = n - 16;
                let levels = [0u8, 95, 135, 175, 215, 255];
                (
                    levels[(i / 36 % 6) as usize],
                    levels[(i / 6 % 6) as usize],
                    levels[(i % 6) as usize],
                )
            }
            232..=255 => {
                let v = 8 + (n - 232) * 10;
                (v, v, v)
            }
        }
    }
}

/// Parsed bundled font faces (regular/bold/italic/bold-italic + symbols fallback).
///
/// Parsing the ~12 MB of bundled TTFs is the dominant cost of building a renderer, so the
/// faces are parsed **once** and shared across all tabs via an [`Arc`] (B4). The glyph
/// *atlas* (rasterized bitmaps) stays per-renderer because it is keyed by physical pixel
/// size, but the expensive face parse is amortized.
pub struct FontSet {
    // [regular, bold, italic, bold-italic]
    base: [Font; 4],
    symbols: Font,
}

impl std::fmt::Debug for FontSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FontSet").finish_non_exhaustive()
    }
}

impl FontSet {
    fn parse(faces: [&[u8]; 4], symbols: &[u8]) -> Self {
        let load = |bytes: &[u8]| {
            Font::from_bytes(bytes, FontSettings::default())
                .expect("bundled font must parse (compile-time invariant)")
        };
        Self {
            base: faces.map(load),
            symbols: load(symbols),
        }
    }

    /// The compiled-in bundled fonts, parsed once and shared process-wide. Cheap after the
    /// first call (clones an `Arc`).
    #[must_use]
    pub fn bundled() -> Arc<FontSet> {
        static BUNDLED: OnceLock<Arc<FontSet>> = OnceLock::new();
        BUNDLED
            .get_or_init(|| {
                Arc::new(FontSet::parse(
                    [FONT_REGULAR, FONT_BOLD, FONT_ITALIC, FONT_BOLD_ITALIC],
                    FONT_SYMBOLS,
                ))
            })
            .clone()
    }
}

// A rasterized glyph: coverage bitmap plus its placement metrics.
struct GlyphBitmap {
    w: usize,
    h: usize,
    xmin: i32,
    ymin: i32,
    cov: Vec<u8>,
}

/// Software glyph-atlas terminal renderer. See module docs.
pub struct TerminalRenderer {
    fonts: Arc<FontSet>,
    font_size_px: f32,
    scale_factor: f32,
    metrics: CellMetrics,
    theme: TerminalTheme,
    // (char, style index) -> rasterized glyph at the current physical size.
    cache: HashMap<(char, u8), GlyphBitmap>,
    // Size of the most recently rendered snapshot, for `cell_at` clamping.
    last_size: TerminalSize,
}

impl std::fmt::Debug for TerminalRenderer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalRenderer")
            .field("font_size_px", &self.font_size_px)
            .field("scale_factor", &self.scale_factor)
            .field("metrics", &self.metrics)
            .field("cached_glyphs", &self.cache.len())
            .finish()
    }
}

#[inline]
fn style_index(attrs: CellAttrs) -> u8 {
    match (attrs.bold(), attrs.italic()) {
        (false, false) => 0,
        (true, false) => 1,
        (false, true) => 2,
        (true, true) => 3,
    }
}

impl TerminalRenderer {
    /// Build a renderer from the (shared) bundled fonts at the given logical font size and
    /// display scale factor. Rasterization happens at physical pixels = `font_size_px *
    /// scale_factor`. Convenience wrapper over [`with_fonts`](Self::with_fonts) using the
    /// shared bundled face set.
    #[must_use]
    pub fn new(font_size_px: f32, scale_factor: f32, theme: TerminalTheme) -> Self {
        Self::with_fonts(FontSet::bundled(), font_size_px, scale_factor, theme)
    }

    /// Build a renderer over an explicit, shared [`FontSet`] (B4: lets every tab reuse the
    /// same parsed faces instead of re-parsing ~12 MB of TTFs per tab).
    #[must_use]
    pub fn with_fonts(
        fonts: Arc<FontSet>,
        font_size_px: f32,
        scale_factor: f32,
        theme: TerminalTheme,
    ) -> Self {
        let metrics = Self::compute_metrics(
            &fonts.base[0],
            Self::physical_px(font_size_px, scale_factor),
        );
        Self {
            fonts,
            font_size_px,
            scale_factor,
            metrics,
            theme,
            cache: HashMap::new(),
            last_size: TerminalSize { rows: 0, cols: 0 },
        }
    }

    fn physical_px(font_size_px: f32, scale_factor: f32) -> f32 {
        (font_size_px * scale_factor).max(1.0)
    }

    fn compute_metrics(regular: &Font, px: f32) -> CellMetrics {
        let line = regular
            .horizontal_line_metrics(px)
            .expect("monospace font has horizontal line metrics");
        // Monospace advance: every glyph shares one advance; sample a representative.
        let advance = regular.metrics('M', px).advance_width;
        let cell_w = advance.ceil().max(1.0) as u32;
        let ascent = line.ascent;
        let descent = line.descent; // <= 0
        let cell_h = (ascent - descent).ceil().max(1.0) as u32;
        let baseline = ascent.round() as i32;
        CellMetrics {
            cell_w,
            cell_h,
            baseline,
            ascent,
            descent,
        }
    }

    /// Current cell geometry (physical px).
    #[must_use]
    pub fn cell_metrics(&self) -> CellMetrics {
        self.metrics
    }

    /// Physical pixel dimensions of a grid of the given cell size: `(cols*cell_w,
    /// rows*cell_h)`.
    #[must_use]
    pub fn pixel_size(&self, size: TerminalSize) -> (u32, u32) {
        (
            u32::from(size.cols) * self.metrics.cell_w,
            u32::from(size.rows) * self.metrics.cell_h,
        )
    }

    /// Map physical pixel coordinates to a `(row, col)` cell, clamped to the most recently
    /// rendered grid size. Before the first `render`, returns `(0, 0)`.
    #[must_use]
    pub fn cell_at(&self, x_px: f32, y_px: f32) -> (u16, u16) {
        let col = (x_px.max(0.0) as u32) / self.metrics.cell_w.max(1);
        let row = (y_px.max(0.0) as u32) / self.metrics.cell_h.max(1);
        let max_col = self.last_size.cols.saturating_sub(1);
        let max_row = self.last_size.rows.saturating_sub(1);
        (
            (row.min(u32::from(max_row))) as u16,
            (col.min(u32::from(max_col))) as u16,
        )
    }

    /// Re-set the logical font size / scale factor and re-rasterize the atlas (the glyph
    /// cache is cleared; glyphs are re-baked lazily at the new physical size).
    pub fn set_scale(&mut self, font_size_px: f32, scale_factor: f32) {
        self.font_size_px = font_size_px;
        self.scale_factor = scale_factor;
        self.metrics = Self::compute_metrics(
            &self.fonts.base[0],
            Self::physical_px(font_size_px, scale_factor),
        );
        self.cache.clear();
    }

    /// Which font in the chain resolves `ch` (base → symbols → missing). The base style
    /// does not affect coverage, so this checks the regular base.
    #[must_use]
    pub fn glyph_source(&self, ch: char) -> GlyphSource {
        if self.fonts.base[0].lookup_glyph_index(ch) != 0 {
            GlyphSource::Base
        } else if self.fonts.symbols.lookup_glyph_index(ch) != 0 {
            GlyphSource::Fallback
        } else {
            GlyphSource::Missing
        }
    }

    // Ensure `ch` at `style` is cached at the current physical size; return it.
    fn glyph(&mut self, ch: char, style: u8) -> &GlyphBitmap {
        let key = (ch, style);
        if !self.cache.contains_key(&key) {
            let px = Self::physical_px(self.font_size_px, self.scale_factor);
            // Fallback chain: prefer the styled base; fall back to symbols for coverage.
            let font = if self.fonts.base[style as usize].lookup_glyph_index(ch) != 0 {
                &self.fonts.base[style as usize]
            } else if self.fonts.symbols.lookup_glyph_index(ch) != 0 {
                &self.fonts.symbols
            } else {
                &self.fonts.base[style as usize]
            };
            let (m, cov) = font.rasterize(ch, px);
            self.cache.insert(
                key,
                GlyphBitmap {
                    w: m.width,
                    h: m.height,
                    xmin: m.xmin,
                    ymin: m.ymin,
                    cov,
                },
            );
        }
        &self.cache[&key]
    }

    /// Rasterize a snapshot into a fresh RGBA pixel buffer of exactly
    /// [`pixel_size`](Self::pixel_size)`(snap.size)` (the grid's natural size).
    pub fn render(&mut self, snap: &GridSnapshot) -> SharedPixelBuffer<Rgba8Pixel> {
        let (w, h) = self.pixel_size(snap.size);
        self.render_to(snap, w, h)
    }

    /// Rasterize a snapshot into a buffer of an **exact** target physical size (B2).
    ///
    /// The grid is drawn at a constant cell size at the top-left; the sub-cell remainder
    /// (right/bottom strip that doesn't hold a full cell) is padded with the terminal
    /// background **inside the buffer**, and cells beyond `target` are clipped. Sizing the
    /// buffer to the surface means it is displayed 1:1 with no `image-fit` stretching — so
    /// resizing changes the cell *count*, not the glyph size. Pass the surface's physical
    /// pixel size (logical × scale_factor).
    pub fn render_to(
        &mut self,
        snap: &GridSnapshot,
        target_w: u32,
        target_h: u32,
    ) -> SharedPixelBuffer<Rgba8Pixel> {
        self.last_size = snap.size;
        let mut buf = SharedPixelBuffer::<Rgba8Pixel>::new(target_w.max(1), target_h.max(1));
        let w = buf.width();
        let h = buf.height();
        let stride = w as usize * 4;
        let bytes = buf.make_mut_bytes();

        // Pad the whole buffer with the terminal background first; cells overpaint their
        // own bg, leaving any sub-cell remainder as a clean bg margin (never scaled text).
        let bg = self.theme.bg;
        fill_rect(bytes, stride, 0, 0, w as usize, h as usize, bg);

        let cols = usize::from(snap.size.cols);
        let rows = usize::from(snap.size.rows);
        let cw = self.metrics.cell_w as usize;
        let ch_h = self.metrics.cell_h as usize;

        for row in 0..rows {
            for col in 0..cols {
                let idx = row * cols + col;
                let Some(cell) = snap.cells.get(idx) else {
                    continue;
                };

                // Resolve colors, applying reverse / dim / hidden.
                let mut fg = self.theme.resolve(cell.fg, true);
                let mut bg = self.theme.resolve(cell.bg, false);
                if cell.attrs.reverse() {
                    std::mem::swap(&mut fg, &mut bg);
                }
                if cell.attrs.dim() {
                    fg = (
                        (u16::from(fg.0) * 11 / 20) as u8,
                        (u16::from(fg.1) * 11 / 20) as u8,
                        (u16::from(fg.2) * 11 / 20) as u8,
                    );
                }
                let draw_glyph = !cell.attrs.hidden() && !cell.grapheme.is_empty();

                let ox = col * cw;
                let oy = row * ch_h;
                fill_rect(bytes, stride, ox, oy, cw, ch_h, bg);

                if draw_glyph {
                    let style = style_index(cell.attrs);
                    // First scalar of the grapheme cluster (combining marks are not shaped
                    // at P2.3; documented limitation — full shaping is later UI work).
                    if let Some(scalar) = cell.grapheme.chars().next() {
                        let metrics = self.metrics;
                        let g = self.glyph(scalar, style);
                        blit_glyph(bytes, stride, w, h, ox, oy, metrics.baseline, g, fg);
                    }
                }

                if !cell.attrs.hidden() {
                    if cell.attrs.underline() {
                        let y = oy + (self.metrics.baseline as usize + 1).min(ch_h - 1);
                        fill_rect(bytes, stride, ox, y, cw, 1.min(ch_h), fg);
                    }
                    if cell.attrs.strikethrough() {
                        let y = oy + ch_h / 2;
                        fill_rect(bytes, stride, ox, y, cw, 1, fg);
                    }
                }
            }
        }

        self.draw_cursor(bytes, stride, w, h, snap, cw, ch_h);
        buf
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_cursor(
        &mut self,
        bytes: &mut [u8],
        stride: usize,
        w: u32,
        h: u32,
        snap: &GridSnapshot,
        cw: usize,
        ch_h: usize,
    ) {
        let cur = snap.cursor;
        if !cur.visible {
            return;
        }
        let (row, col) = (usize::from(cur.row), usize::from(cur.col));
        if row >= usize::from(snap.size.rows) || col >= usize::from(snap.size.cols) {
            return;
        }
        let ox = col * cw;
        let oy = row * ch_h;
        let cursor_color = self.theme.cursor;
        match cur.shape {
            CursorShape::Block => {
                // Reverse-video: fill with cursor color, redraw glyph in the cell bg.
                fill_rect(bytes, stride, ox, oy, cw, ch_h, cursor_color);
                if let Some(cell) = snap.cells.get(row * usize::from(snap.size.cols) + col) {
                    let cell_bg = self.theme.resolve(cell.bg, false);
                    if !cell.grapheme.is_empty()
                        && let Some(scalar) = cell.grapheme.chars().next()
                    {
                        let style = style_index(cell.attrs);
                        let metrics = self.metrics;
                        let g = self.glyph(scalar, style);
                        blit_glyph(bytes, stride, w, h, ox, oy, metrics.baseline, g, cell_bg);
                    }
                }
            }
            CursorShape::Underline => {
                let bar = (ch_h / 10).max(2).min(ch_h);
                fill_rect(bytes, stride, ox, oy + ch_h - bar, cw, bar, cursor_color);
            }
            CursorShape::Bar => {
                let bar = (cw / 8).max(2).min(cw);
                fill_rect(bytes, stride, ox, oy, bar, ch_h, cursor_color);
            }
        }
    }
}

// ── Pixel helpers ───────────────────────────────────────────────────────────────────
fn fill_rect(bytes: &mut [u8], stride: usize, x: usize, y: usize, w: usize, h: usize, c: Rgb) {
    let width_px = stride / 4;
    let max_y = bytes.len() / stride;
    // Clip to the buffer in both axes so a cell straddling the right/bottom edge cannot
    // bleed into the next row or past the end of the buffer.
    for py in y..(y + h).min(max_y) {
        let row = py * stride;
        for px in x..(x + w).min(width_px) {
            let i = row + px * 4;
            bytes[i] = c.0;
            bytes[i + 1] = c.1;
            bytes[i + 2] = c.2;
            bytes[i + 3] = 0xff;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn blit_glyph(
    bytes: &mut [u8],
    stride: usize,
    w: u32,
    h: u32,
    ox: usize,
    oy: usize,
    baseline: i32,
    g: &GlyphBitmap,
    fg: Rgb,
) {
    // Glyph bitmap origin within the cell. Not clipped to the cell width, so a wide glyph
    // overflows into its trailing spacer column (the desired behavior for wide cells).
    let gx0 = ox as i32 + g.xmin;
    let gy0 = oy as i32 + baseline - (g.ymin + g.h as i32);
    for gy in 0..g.h {
        let py = gy0 + gy as i32;
        if py < 0 || py as u32 >= h {
            continue;
        }
        let row = py as usize * stride;
        for gx in 0..g.w {
            let px = gx0 + gx as i32;
            if px < 0 || px as u32 >= w {
                continue;
            }
            let cov = u32::from(g.cov[gy * g.w + gx]);
            if cov == 0 {
                continue;
            }
            let i = row + px as usize * 4;
            if i + 3 >= bytes.len() {
                continue;
            }
            let inv = 255 - cov;
            bytes[i] = ((u32::from(fg.0) * cov + u32::from(bytes[i]) * inv) / 255) as u8;
            bytes[i + 1] = ((u32::from(fg.1) * cov + u32::from(bytes[i + 1]) * inv) / 255) as u8;
            bytes[i + 2] = ((u32::from(fg.2) * cov + u32::from(bytes[i + 2]) * inv) / 255) as u8;
            bytes[i + 3] = 0xff;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cm_core::{Cell, CursorState, GridSnapshot, TerminalSize};

    fn mk(grapheme: &str, fg: Color, bg: Color, attrs: CellAttrs, width: u8) -> Cell {
        Cell {
            grapheme: grapheme.to_string(),
            fg,
            bg,
            attrs,
            width,
        }
    }

    fn blank_cursor() -> CursorState {
        CursorState {
            row: 0,
            col: 0,
            visible: false,
            shape: CursorShape::Block,
        }
    }

    fn snap(rows: u16, cols: u16, cells: Vec<Cell>, cursor: CursorState) -> GridSnapshot {
        GridSnapshot {
            size: TerminalSize { rows, cols },
            cells,
            cursor,
        }
    }

    // Read the pixel at physical (px, py) as (r,g,b).
    fn px_at(buf: &SharedPixelBuffer<Rgba8Pixel>, px: u32, py: u32) -> Rgb {
        let w = buf.width();
        let bytes = buf.as_bytes();
        let i = ((py * w + px) * 4) as usize;
        (bytes[i], bytes[i + 1], bytes[i + 2])
    }

    fn cell_center(r: &TerminalRenderer, row: u32, col: u32) -> (u32, u32) {
        let m = r.cell_metrics();
        (col * m.cell_w + m.cell_w / 2, row * m.cell_h + m.cell_h / 2)
    }

    // Copy the pixels of one cell into a Vec for comparison.
    fn cell_region(
        buf: &SharedPixelBuffer<Rgba8Pixel>,
        m: CellMetrics,
        row: u32,
        col: u32,
    ) -> Vec<u8> {
        let w = buf.width();
        let bytes = buf.as_bytes();
        let mut out = Vec::new();
        for y in row * m.cell_h..(row + 1) * m.cell_h {
            for x in col * m.cell_w..(col + 1) * m.cell_w {
                let i = ((y * w + x) * 4) as usize;
                out.extend_from_slice(&bytes[i..i + 4]);
            }
        }
        out
    }

    fn count_non_bg(
        buf: &SharedPixelBuffer<Rgba8Pixel>,
        m: CellMetrics,
        row: u32,
        col: u32,
        bg: Rgb,
    ) -> usize {
        let w = buf.width();
        let bytes = buf.as_bytes();
        let mut n = 0;
        for y in row * m.cell_h..(row + 1) * m.cell_h {
            for x in col * m.cell_w..(col + 1) * m.cell_w {
                let i = ((y * w + x) * 4) as usize;
                if (bytes[i], bytes[i + 1], bytes[i + 2]) != bg {
                    n += 1;
                }
            }
        }
        n
    }

    #[test]
    fn render_buffer_has_exact_pixel_size() {
        let mut r = TerminalRenderer::new(14.0, 1.0, TerminalTheme::dark());
        let size = TerminalSize { rows: 5, cols: 9 };
        let cells = vec![Cell::default(); size.cell_count()];
        let buf = r.render(&snap(5, 9, cells, blank_cursor()));
        let (w, h) = r.pixel_size(size);
        assert_eq!(buf.width(), w);
        assert_eq!(buf.height(), h);
        assert!(w > 0 && h > 0);
    }

    #[test]
    fn solid_bg_at_center() {
        let mut r = TerminalRenderer::new(14.0, 1.0, TerminalTheme::dark());
        let red = Color::Rgb {
            r: 200,
            g: 40,
            b: 40,
        };
        let cell = mk("", Color::Default, red, CellAttrs::empty(), 1);
        let buf = r.render(&snap(1, 1, vec![cell], blank_cursor()));
        let (cx, cy) = cell_center(&r, 0, 0);
        assert_eq!(px_at(&buf, cx, cy), (200, 40, 40));
    }

    #[test]
    fn reverse_swaps_fg_and_bg() {
        let mut r = TerminalRenderer::new(14.0, 1.0, TerminalTheme::dark());
        let blue = Color::Rgb {
            r: 20,
            g: 40,
            b: 200,
        };
        let red = Color::Rgb {
            r: 200,
            g: 40,
            b: 40,
        };
        // Blank cell, fg=blue bg=red, reverse -> painted bg becomes the fg (blue).
        let cell = mk("", blue, red, CellAttrs::REVERSE, 1);
        let buf = r.render(&snap(1, 1, vec![cell], blank_cursor()));
        let (cx, cy) = cell_center(&r, 0, 0);
        assert_eq!(px_at(&buf, cx, cy), (20, 40, 200));
    }

    #[test]
    fn nerd_font_glyph_renders_nonempty() {
        let mut r = TerminalRenderer::new(16.0, 1.0, TerminalTheme::dark());
        // Powerline right-arrow; the bundled patched base resolves it directly.
        assert_eq!(r.glyph_source('\u{E0B0}'), GlyphSource::Base);
        let bg = Color::Rgb { r: 0, g: 0, b: 0 };
        let fg = Color::Rgb {
            r: 255,
            g: 255,
            b: 255,
        };
        let cell = mk("\u{E0B0}", fg, bg, CellAttrs::empty(), 1);
        let buf = r.render(&snap(1, 1, vec![cell], blank_cursor()));
        let m = r.cell_metrics();
        assert!(
            count_non_bg(&buf, m, 0, 0, (0, 0, 0)) > 0,
            "Nerd glyph produced no ink"
        );
    }

    #[test]
    fn fallback_chain_resolves_via_symbols() {
        // Deterministically exercise the base->symbols fallback branch: build a FontSet
        // whose base lacks ASCII (the symbols font) with the JBM regular as the "symbols"
        // fallback. With the default fonts the patched base covers everything, so this is
        // the only way to hit the fallback path in a unit test (documented finding).
        let parse = |b: &[u8]| Font::from_bytes(b, FontSettings::default()).unwrap();
        let fonts = Arc::new(FontSet {
            base: [
                parse(FONT_SYMBOLS),
                parse(FONT_SYMBOLS),
                parse(FONT_SYMBOLS),
                parse(FONT_SYMBOLS),
            ],
            symbols: parse(FONT_REGULAR),
        });
        let mut r = TerminalRenderer::with_fonts(fonts, 16.0, 1.0, TerminalTheme::dark());
        assert_eq!(r.glyph_source('A'), GlyphSource::Fallback);
        let bg = Color::Rgb { r: 0, g: 0, b: 0 };
        let fg = Color::Rgb {
            r: 255,
            g: 255,
            b: 255,
        };
        let cell = mk("A", fg, bg, CellAttrs::empty(), 1);
        let buf = r.render(&snap(1, 1, vec![cell], blank_cursor()));
        let m = r.cell_metrics();
        assert!(
            count_non_bg(&buf, m, 0, 0, (0, 0, 0)) > 0,
            "fallback glyph produced no ink"
        );
    }

    #[test]
    fn wide_char_spacer_draws_no_glyph() {
        let mut r = TerminalRenderer::new(16.0, 1.0, TerminalTheme::dark());
        let m = r.cell_metrics();
        let wide_bg = Color::Rgb {
            r: 10,
            g: 10,
            b: 10,
        };
        let spacer_bg = Color::Rgb {
            r: 70,
            g: 20,
            b: 90,
        };
        let fg = Color::Rgb {
            r: 255,
            g: 255,
            b: 255,
        };
        // [wide CJK w2][spacer '' w1][ 'A' w1]
        let cells = vec![
            mk("世", fg, wide_bg, CellAttrs::empty(), 2),
            mk("", fg, spacer_bg, CellAttrs::empty(), 1),
            mk(
                "A",
                fg,
                Color::Rgb { r: 0, g: 0, b: 0 },
                CellAttrs::empty(),
                1,
            ),
        ];
        let buf = r.render(&snap(1, 3, cells, blank_cursor()));
        // Three columns wide.
        assert_eq!(buf.width(), m.cell_w * 3);
        // The spacer cell drew no glyph of its own: its center is its background.
        let (sx, sy) = cell_center(&r, 0, 1);
        assert_eq!(px_at(&buf, sx, sy), (70, 20, 90));
        // The trailing 'A' rendered.
        assert!(count_non_bg(&buf, m, 0, 2, (0, 0, 0)) > 0);
    }

    #[test]
    fn bold_and_italic_differ_from_plain() {
        let mut r = TerminalRenderer::new(18.0, 1.0, TerminalTheme::dark());
        let m = r.cell_metrics();
        let fg = Color::Rgb {
            r: 255,
            g: 255,
            b: 255,
        };
        let bg = Color::Rgb { r: 0, g: 0, b: 0 };
        let render_g = |r: &mut TerminalRenderer, attrs| {
            let buf = r.render(&snap(1, 1, vec![mk("g", fg, bg, attrs, 1)], blank_cursor()));
            cell_region(&buf, m, 0, 0)
        };
        let plain = render_g(&mut r, CellAttrs::empty());
        let bold = render_g(&mut r, CellAttrs::BOLD);
        let italic = render_g(&mut r, CellAttrs::ITALIC);
        assert_ne!(plain, bold, "bold should differ from plain");
        assert_ne!(plain, italic, "italic should differ from plain");
    }

    #[test]
    fn cell_at_round_trips_and_clamps() {
        let mut r = TerminalRenderer::new(15.0, 1.25, TerminalTheme::dark());
        let size = TerminalSize { rows: 6, cols: 8 };
        let _ = r.render(&snap(
            6,
            8,
            vec![Cell::default(); size.cell_count()],
            blank_cursor(),
        ));
        for row in 0..6u16 {
            for col in 0..8u16 {
                let (cx, cy) = cell_center(&r, u32::from(row), u32::from(col));
                assert_eq!(r.cell_at(cx as f32, cy as f32), (row, col));
            }
        }
        // Out-of-bounds clamps to the last row/col.
        assert_eq!(r.cell_at(1_000_000.0, 1_000_000.0), (5, 7));
        assert_eq!(r.cell_at(-50.0, -50.0), (0, 0));
    }

    #[test]
    fn set_scale_updates_metrics_consistently() {
        let mut r = TerminalRenderer::new(14.0, 1.0, TerminalTheme::dark());
        let m1 = r.cell_metrics();
        let size = TerminalSize { rows: 2, cols: 3 };
        let p1 = r.pixel_size(size);
        r.set_scale(14.0, 2.0);
        let m2 = r.cell_metrics();
        let p2 = r.pixel_size(size);
        assert!(
            m2.cell_w > m1.cell_w && m2.cell_h > m1.cell_h,
            "2x scale enlarges cells"
        );
        assert_eq!(p2, (m2.cell_w * 3, m2.cell_h * 2));
        // Roughly double (allow rounding slack).
        assert!((m2.cell_w as i64 - 2 * m1.cell_w as i64).abs() <= 2);
        assert!(p1.0 < p2.0);
    }

    #[test]
    fn cursor_block_overlays_cursor_color() {
        let mut r = TerminalRenderer::new(14.0, 1.0, TerminalTheme::dark());
        let theme = TerminalTheme::dark();
        let bg = Color::Rgb {
            r: 10,
            g: 10,
            b: 10,
        };
        let cells = vec![mk("", Color::Default, bg, CellAttrs::empty(), 1)];
        // Visible block cursor at (0,0).
        let cursor = CursorState {
            row: 0,
            col: 0,
            visible: true,
            shape: CursorShape::Block,
        };
        let buf = r.render(&snap(1, 1, cells.clone(), cursor));
        let (cx, cy) = cell_center(&r, 0, 0);
        assert_eq!(px_at(&buf, cx, cy), theme.cursor);
        // Invisible cursor: center stays the cell bg.
        let buf2 = r.render(&snap(1, 1, cells, blank_cursor()));
        assert_eq!(px_at(&buf2, cx, cy), (10, 10, 10));
    }

    #[test]
    fn palette_256_cube_and_grayscale() {
        let t = TerminalTheme::dark();
        // 16 = cube origin (0,0,0).
        assert_eq!(t.palette_256(16), (0, 0, 0));
        // 231 = cube max (255,255,255).
        assert_eq!(t.palette_256(231), (255, 255, 255));
        // 232 = first grayscale step.
        assert_eq!(t.palette_256(232), (8, 8, 8));
        // ANSI passthrough.
        assert_eq!(t.palette_256(1), t.ansi[1]);
    }

    #[test]
    fn renderer_buffer_is_send() {
        const fn assert_send<T: Send>() {}
        assert_send::<SharedPixelBuffer<Rgba8Pixel>>();
    }

    #[test]
    fn render_to_has_exact_target_size_and_bg_padding() {
        // B2: the buffer is the requested physical size, not a grid multiple, and the
        // sub-cell remainder is terminal background (constant cell size, never scaled).
        let mut r = TerminalRenderer::new(16.0, 1.0, TerminalTheme::dark());
        let m = r.cell_metrics();
        let cols = 5u16;
        let rows = 3u16;
        // Target deliberately larger than the grid, with a non-cell-multiple remainder.
        let target_w = m.cell_w * u32::from(cols) + 7;
        let target_h = m.cell_h * u32::from(rows) + 5;
        let cells = vec![Cell::default(); usize::from(cols) * usize::from(rows)];
        let buf = r.render_to(&snap(rows, cols, cells, blank_cursor()), target_w, target_h);
        assert_eq!((buf.width(), buf.height()), (target_w, target_h));
        // A pixel in the right padding strip (beyond the grid) is the terminal bg.
        let bg = TerminalTheme::dark().bg;
        assert_eq!(px_at(&buf, target_w - 1, 0), bg);
        assert_eq!(px_at(&buf, 0, target_h - 1), bg);
    }

    #[test]
    fn render_to_smaller_than_grid_clips_without_panic() {
        // Shrinking the surface below the grid must clip cleanly (no out-of-bounds / bleed).
        let mut r = TerminalRenderer::new(16.0, 1.0, TerminalTheme::dark());
        let m = r.cell_metrics();
        let cells = vec![
            mk(
                "X",
                Color::Rgb { r: 255, g: 0, b: 0 },
                Color::Default,
                CellAttrs::empty(),
                1,
            );
            80 * 24
        ];
        // Target smaller than one full row/col of the 80x24 grid.
        let buf = r.render_to(
            &snap(24, 80, cells, blank_cursor()),
            m.cell_w + 3,
            m.cell_h + 3,
        );
        assert_eq!((buf.width(), buf.height()), (m.cell_w + 3, m.cell_h + 3));
    }

    #[test]
    fn fonts_are_shared_across_renderers() {
        // B4: the bundled face set is parsed once and shared (same Arc allocation).
        let a = FontSet::bundled();
        let b = FontSet::bundled();
        assert!(Arc::ptr_eq(&a, &b));
    }

    /// B4 profiling aid (run with `--ignored --nocapture`): old per-tab cost was parsing
    /// the 5 bundled faces from scratch; new per-tab cost is `with_fonts` over a shared Arc.
    #[test]
    #[ignore = "profiling aid; run explicitly with --ignored --nocapture"]
    fn b4_profile_font_parse_vs_shared() {
        use std::time::Instant;
        let n = 8;
        let t = Instant::now();
        for _ in 0..n {
            let _ = FontSet::parse(
                [FONT_REGULAR, FONT_BOLD, FONT_ITALIC, FONT_BOLD_ITALIC],
                FONT_SYMBOLS,
            );
        }
        let parse_each = t.elapsed() / n;

        let shared = FontSet::bundled();
        let m = 200;
        let t2 = Instant::now();
        for _ in 0..m {
            let _ = TerminalRenderer::with_fonts(shared.clone(), 15.0, 1.0, TerminalTheme::dark());
        }
        let shared_each = t2.elapsed() / m;

        eprintln!(
            "B4 per-tab renderer cost: OLD (parse 5 faces) = {parse_each:?}; \
             NEW (with_fonts, shared) = {shared_each:?}"
        );
    }
}

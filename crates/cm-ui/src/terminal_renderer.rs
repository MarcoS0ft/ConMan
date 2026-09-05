//! Glyph-atlas terminal renderer.
//!
//! Rasterizes a [`cm_core::GridSnapshot`] into an RGBA [`slint::SharedPixelBuffer`]
//! using a software grapheme atlas. `cosmic-text` shapes complete cell graphemes and
//! resolves missing glyphs through bundled Symbols Nerd Font and installed system fonts;
//! Swash supplies mask or intrinsic-color glyph pixels. Pure CPU work, headless-testable,
//! with no windowing/GPU dependency.
//!
//! ## Threading (`!Send` boundary)
//! [`TerminalRenderer::render`] returns a `SharedPixelBuffer`, which **is** `Send`. The
//! `slint::Image::from_rgba8` wrap (which yields a `!Send` `Image`) is deliberately *not*
//! done here — it happens on the UI thread. So `render` is callable on the engine
//! thread that owns the (`!Send`) VT engine; only the buffer crosses to the UI thread.
//!
//! ## Fonts (bundled, see `assets/fonts/`)
//! Base: JetBrains Mono Nerd Font Mono (regular/bold/italic/bold-italic), SIL OFL-1.1.
//! Fallback: Symbols Nerd Font Mono, MIT, followed by best-effort installed system fonts.
//! A selected family is preferred rather than exclusive; the primary regular face alone
//! determines terminal geometry.

use std::collections::HashMap;
use std::sync::Arc;

use cm_core::{
    CellAttrs, Color, CursorShape, DEFAULT_TERMINAL_FONT_FAMILY, GridSnapshot, TerminalSize,
};
use slint::{Rgba8Pixel, SharedPixelBuffer};

mod font_backend;
pub use font_backend::TerminalFontSystem;
use font_backend::{FontRequest, FontStyle, GlyphPixels, RasterizedCluster, RasterizedLayer};

const GLYPH_ATLAS_ENTRY_CAP: usize = 2_048;

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

/// A single endpoint of a terminal text selection: a cell position addressed
/// in **absolute buffer-line** coordinates.
///
/// The absolute coordinate model means `row`
/// is now an absolute line index in the same address space as
/// [`cm_core::GridSnapshot::scrollback_len`]/`scroll_offset` (`0` = the
/// oldest retained line; the live tail is always the highest indices). As
/// promised by the seam, the geometry below (`normalized`/`row_span`/
/// `contains`) is unchanged — only what populates/consumes `row` moved:
/// callers convert to/from a viewport-relative row via `abs_top =
/// snap.scrollback_len - snap.scroll_offset` (`cm-ui/src/selection.rs`'s
/// `selected_cells`/`extract_text`, and this module's draw pass, both do
/// this at their read boundary). A selection made while scrolled back now
/// survives further scrolling as long as its rows stay within whatever
/// window is currently displayed; it "clears on new output that scrolls the
/// region" via the existing `invalidate_if_stale` staleness check — once its
/// absolute rows fall outside the displayed window, no cells match, the
/// baseline comparison fails, and it clears (including on a tail-follow jump).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionPoint {
    pub row: u16,
    pub col: u16,
}

/// A mouse-drag text selection over the terminal grid.
///
/// `anchor` is where the drag/click started; `cursor` is the current drag
/// position (word/line selections set both to the expanded word/line bounds
/// instead of tracking a live drag — see `cm-ui/src/selection.rs`). Endpoints
/// are stored in click order, not sorted; use [`Selection::normalized`] for
/// row-major `(start, end)` order regardless of drag direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    pub anchor: SelectionPoint,
    pub cursor: SelectionPoint,
}

impl Selection {
    #[must_use]
    pub fn new(anchor: SelectionPoint, cursor: SelectionPoint) -> Self {
        Self { anchor, cursor }
    }

    /// `(start, end)` in row-major order (`start <= end` as `(row, col)`
    /// tuples), regardless of which endpoint the drag started from.
    #[must_use]
    pub fn normalized(&self) -> (SelectionPoint, SelectionPoint) {
        let a = (self.anchor.row, self.anchor.col);
        let b = (self.cursor.row, self.cursor.col);
        if a <= b {
            (self.anchor, self.cursor)
        } else {
            (self.cursor, self.anchor)
        }
    }

    /// True when both endpoints occupy the same cell. This may be a legitimate
    /// one-cell selection after a same-cell drag or a double-click on a
    /// one-character word; plain clicks are filtered by the selection state
    /// machine before they reach the renderer.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchor == self.cursor
    }

    /// The inclusive `(start_col, end_col)` span selected within `row`, or
    /// `None` if `row` is outside the selection or `cols` is zero. Full
    /// interior rows of a multi-row selection span the whole width;
    /// `cols` clamps the boundary rows to the current grid width (a selection
    /// made at a wider size before a shrink-resize would otherwise report an
    /// out-of-range column — resize also clears the selection at the
    /// controller layer, but this keeps the geometry itself panic-safe).
    #[must_use]
    pub fn row_span(&self, row: u16, cols: u16) -> Option<(u16, u16)> {
        if cols == 0 {
            return None;
        }
        let (start, end) = self.normalized();
        if row < start.row || row > end.row {
            return None;
        }
        let last_col = cols - 1;
        Some(if start.row == end.row {
            (start.col.min(last_col), end.col.min(last_col))
        } else if row == start.row {
            (start.col.min(last_col), last_col)
        } else if row == end.row {
            (0, end.col.min(last_col))
        } else {
            (0, last_col)
        })
    }

    /// Whether `(row, col)` falls inside the selection, given the grid's
    /// current `cols` (needed to resolve the "to end of row" span of a
    /// multi-row selection's boundary rows).
    #[must_use]
    pub fn contains(&self, row: u16, col: u16, cols: u16) -> bool {
        self.row_span(row, cols)
            .is_some_and(|(from, to)| col >= from && col <= to)
    }
}

/// A single search-match span within one row, in the same absolute
/// buffer-line address space as [`SelectionPoint::row`]. `col_start`/`col_end`
/// are inclusive. Produced by `cm-ui`'s search logic (`controller/search.rs`)
/// scanning `TerminalEngine::buffer_text`'s plain-text lines — never by this
/// module, which only draws whatever spans it is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchMatch {
    pub row: u16,
    pub col_start: u16,
    pub col_end: u16,
}

impl SearchMatch {
    #[must_use]
    pub fn contains(&self, row: u16, col: u16) -> bool {
        self.row == row && col >= self.col_start && col <= self.col_end
    }
}

/// Terminal color theme: default fg/bg, the 16 ANSI base colors (extended to 256 via the
/// standard color-cube/grayscale formula), and the cursor color.
///
/// Both [`dark`](Self::dark) and [`light`](Self::light) are selected independently
/// of the application shell theme, so changing the surrounding chrome cannot alter
/// terminal ANSI contrast. Values are literals because Rust cannot read Slint tokens.
#[derive(Debug, Clone)]
pub struct TerminalTheme {
    pub fg: Rgb,
    pub bg: Rgb,
    pub cursor: Rgb,
    /// Background tint painted over a selected cell, instead of its
    /// normal resolved background. Text color is left as-is on top of it.
    pub selection_bg: Rgb,
    /// Background tint for a non-current search match.
    pub search_bg: Rgb,
    /// Background tint for the *current* search match — brighter than
    /// `search_bg` so next/prev navigation is visually obvious.
    pub search_current_bg: Rgb,
    /// Scrollbar track color for the Slint `TerminalScrollbar` overlay
    /// (`ui/app.slint` styles its own rail today; kept here so the palette
    /// stays complete if the overlay ever binds to theme colors).
    pub scrollbar_track: Rgb,
    /// Scrollbar thumb color (see `scrollbar_track`).
    pub scrollbar_thumb: Rgb,
    /// The 16 ANSI colors (0-7 normal, 8-15 bright).
    pub ansi: [Rgb; 16],
}

impl TerminalTheme {
    /// The dark default. fg/bg pinned to `Theme.color-terminal-bg`/`color-terminal-fg`'s
    /// dark values (`#0a0c10`/`#c9ccd1`); the 16-color ANSI cube keeps its original
    /// VS-Code-dark-like values (not a token in `theme.slint` — scope is default
    /// fg/bg, not a full palette redesign).
    #[must_use]
    pub fn dark() -> Self {
        Self {
            fg: (0xc9, 0xcc, 0xd1),
            bg: (0x0a, 0x0c, 0x10),
            cursor: (0xc9, 0xcc, 0xd1),
            // VS Code dark's default editor selection blue.
            selection_bg: (0x26, 0x4f, 0x78),
            // A muted amber for "other matches," a brighter amber for "current."
            search_bg: (0x5a, 0x4a, 0x1a),
            search_current_bg: (0xb8, 0x86, 0x0a),
            // Subtle on dark: a faint lightening of the bg for the track, a
            // clearly visible mid-gray for the thumb.
            scrollbar_track: (0x1a, 0x1d, 0x23),
            scrollbar_thumb: (0x45, 0x4a, 0x54),
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

    /// The light counterpart (/ closes finding V1). fg/bg pinned to
    /// `Theme.color-terminal-bg`/`color-terminal-fg`'s light values (`#ffffff`/`#2b2f36`).
    /// The ANSI cube is a reasonable light-background default (close to VS Code's Light+
    /// terminal palette) — darkened/desaturated versions of the dark palette so text stays
    /// legible on a white background; bright-white in particular is toned down to a mid
    /// gray instead of pure white, which would be invisible on `bg`.
    #[must_use]
    pub fn light() -> Self {
        Self {
            fg: (0x2b, 0x2f, 0x36),
            bg: (0xff, 0xff, 0xff),
            cursor: (0x2b, 0x2f, 0x36),
            // A pale blue selection tint that reads clearly on a white background.
            selection_bg: (0xad, 0xd6, 0xff),
            // A pale yellow for "other matches," a saturated yellow-orange for "current."
            search_bg: (0xfa, 0xf0, 0xb0),
            search_current_bg: (0xf5, 0xb8, 0x2e),
            // Subtle on light: a faint darkening of the bg for the track, a
            // clearly visible mid-gray for the thumb.
            scrollbar_track: (0xe8, 0xe8, 0xe8),
            scrollbar_thumb: (0xa8, 0xa8, 0xa8),
            ansi: [
                (0x00, 0x00, 0x00), // 0 black
                (0xcd, 0x31, 0x31), // 1 red
                (0x00, 0xbc, 0x00), // 2 green
                (0x94, 0x98, 0x00), // 3 yellow
                (0x04, 0x51, 0xa5), // 4 blue
                (0xbc, 0x05, 0xbc), // 5 magenta
                (0x05, 0x98, 0xbc), // 6 cyan
                (0x55, 0x55, 0x55), // 7 white
                (0x66, 0x66, 0x66), // 8 bright black
                (0xcd, 0x31, 0x31), // 9 bright red
                (0x14, 0xce, 0x14), // 10 bright green
                (0xb5, 0xba, 0x00), // 11 bright yellow
                (0x04, 0x51, 0xa5), // 12 bright blue
                (0xbc, 0x05, 0xbc), // 13 bright magenta
                (0x05, 0x98, 0xbc), // 14 bright cyan
                (0xa5, 0xa5, 0xa5), // 15 bright white
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

/// Software glyph-atlas terminal renderer. See module docs.
pub struct TerminalRenderer {
    fonts: Arc<TerminalFontSystem>,
    effective_family: String,
    font_size_px: f32,
    scale_factor: f32,
    metrics: CellMetrics,
    theme: TerminalTheme,
    // One complete-grapheme map per style at the current physical size/family. A borrowed
    // `&str` warm lookup does not allocate; the owned key is created only on insertion.
    cache: [HashMap<String, Arc<RasterizedCluster>>; 4],
    // Size of the most recently rendered snapshot, for `cell_at` clamping.
    last_size: TerminalSize,
}

impl std::fmt::Debug for TerminalRenderer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalRenderer")
            .field("font_size_px", &self.font_size_px)
            .field("scale_factor", &self.scale_factor)
            .field("effective_family", &self.effective_family)
            .field("metrics", &self.metrics)
            .field("cached_glyphs", &self.cache_len())
            .finish()
    }
}

#[inline]
fn font_style(attrs: CellAttrs) -> FontStyle {
    match (attrs.bold(), attrs.italic()) {
        (false, false) => FontStyle::Regular,
        (true, false) => FontStyle::Bold,
        (false, true) => FontStyle::Italic,
        (true, true) => FontStyle::BoldItalic,
    }
}

const fn style_cache_index(style: FontStyle) -> usize {
    match style {
        FontStyle::Regular => 0,
        FontStyle::Bold => 1,
        FontStyle::Italic => 2,
        FontStyle::BoldItalic => 3,
    }
}

impl TerminalRenderer {
    /// Build a renderer from the shared terminal font system and bundled default family.
    #[must_use]
    pub fn new(font_size_px: f32, scale_factor: f32, theme: TerminalTheme) -> Self {
        Self::with_font_system(
            TerminalFontSystem::shared(),
            DEFAULT_TERMINAL_FONT_FAMILY,
            font_size_px,
            scale_factor,
            theme,
        )
    }

    /// Build a renderer over the shared process font system with a preferred primary family.
    #[must_use]
    pub fn with_font_system(
        fonts: Arc<TerminalFontSystem>,
        preferred_family: &str,
        font_size_px: f32,
        scale_factor: f32,
        theme: TerminalTheme,
    ) -> Self {
        let effective_family = fonts.resolve_family(preferred_family);
        let metrics = fonts.primary_metrics(
            &effective_family,
            Self::physical_px(font_size_px, scale_factor),
        );
        Self {
            fonts,
            effective_family,
            font_size_px,
            scale_factor,
            metrics,
            theme,
            cache: std::array::from_fn(|_| HashMap::new()),
            last_size: TerminalSize { rows: 0, cols: 0 },
        }
    }

    fn physical_px(font_size_px: f32, scale_factor: f32) -> f32 {
        (font_size_px * scale_factor).max(1.0)
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

    /// Swap the color theme in place for a future user-selected terminal scheme.
    ///
    /// No cache invalidation is needed: the glyph cache holds only grayscale coverage
    /// bitmaps (`GlyphBitmap`) — color is resolved from `self.theme` at composite time in
    /// `render_to_selected`, never baked into a cached glyph. The very next
    /// `render`/`render_to` call paints with the new palette.
    pub fn set_theme(&mut self, theme: TerminalTheme) {
        self.theme = theme;
    }

    /// Re-set the logical font size / scale factor and re-rasterize the atlas (the glyph
    /// cache is cleared; glyphs are re-baked lazily at the new physical size).
    pub fn set_scale(&mut self, font_size_px: f32, scale_factor: f32) {
        self.font_size_px = font_size_px;
        self.scale_factor = scale_factor;
        self.metrics = self.fonts.primary_metrics(
            &self.effective_family,
            Self::physical_px(font_size_px, scale_factor),
        );
        self.clear_cache();
    }

    /// Switch the preferred primary family live. Missing/unusable requests resolve to the
    /// bundled default. Returns the effective family after recomputing geometry and clearing
    /// the per-renderer atlas.
    pub fn set_preferred_family(&mut self, requested: &str) -> &str {
        self.effective_family = self.fonts.resolve_family(requested);
        self.metrics = self.fonts.primary_metrics(
            &self.effective_family,
            Self::physical_px(self.font_size_px, self.scale_factor),
        );
        self.clear_cache();
        &self.effective_family
    }

    /// The canonical family actually used as this renderer's primary.
    #[must_use]
    pub fn effective_family(&self) -> &str {
        &self.effective_family
    }

    // Ensure a complete grapheme/style is cached at the current size/family; return it.
    fn glyph(&mut self, grapheme: &str, style: FontStyle) -> Arc<RasterizedCluster> {
        let style_index = style_cache_index(style);
        if let Some(cluster) = self.cache[style_index].get(grapheme) {
            return Arc::clone(cluster);
        }

        if self.cache_len() >= GLYPH_ATLAS_ENTRY_CAP {
            self.clear_cache();
        }
        let px = Self::physical_px(self.font_size_px, self.scale_factor);
        let cluster = Arc::new(self.fonts.rasterize(FontRequest {
            grapheme,
            style,
            physical_px: px,
            preferred_family: &self.effective_family,
        }));
        tracing::trace!(grapheme = %grapheme, source = ?cluster.source, "cached terminal grapheme");
        self.cache[style_index].insert(grapheme.to_owned(), Arc::clone(&cluster));
        cluster
    }

    fn cache_len(&self) -> usize {
        self.cache.iter().map(HashMap::len).sum()
    }

    fn clear_cache(&mut self) {
        for cache in &mut self.cache {
            cache.clear();
        }
    }

    /// Rasterize a snapshot into a fresh RGBA pixel buffer of exactly
    /// [`pixel_size`](Self::pixel_size)`(snap.size)` (the grid's natural size).
    pub fn render(&mut self, snap: &GridSnapshot) -> SharedPixelBuffer<Rgba8Pixel> {
        let (w, h) = self.pixel_size(snap.size);
        self.render_to(snap, w, h)
    }

    /// [`render`](Self::render) with an optional text selection tinted
    /// into the draw pass. `None` behaves exactly like `render`.
    pub fn render_selected(
        &mut self,
        snap: &GridSnapshot,
        selection: Option<&Selection>,
    ) -> SharedPixelBuffer<Rgba8Pixel> {
        let (w, h) = self.pixel_size(snap.size);
        self.render_to_selected(snap, w, h, selection)
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
        self.render_to_selected(snap, target_w, target_h, None)
    }

    /// [`render_to`](Self::render_to) with an optional text selection
    /// tinted into the draw pass: selected cells are painted with
    /// [`TerminalTheme::selection_bg`] instead of their resolved background
    /// (glyph/underline/strikethrough still draw in the cell's normal fg on
    /// top, and the cursor still draws over everything — same order as
    /// before). `None` behaves exactly like `render_to`.
    ///
    /// A `Selection` with `anchor == cursor` is a legitimate single-cell
    /// selection (e.g. double-click-to-select-word on a one-character word)
    /// and *will* render — deciding whether a plain, undragged click should
    /// produce a visible selection at all is a `cm-ui/src/selection.rs`
    /// click-state-machine concern (it simply never constructs one in that
    /// case), not something this pure draw pass second-guesses.
    pub fn render_to_selected(
        &mut self,
        snap: &GridSnapshot,
        target_w: u32,
        target_h: u32,
        selection: Option<&Selection>,
    ) -> SharedPixelBuffer<Rgba8Pixel> {
        self.render_to_full(snap, target_w, target_h, selection, &[], None)
    }

    /// [`render_to_selected`](Self::render_to_selected) with search
    /// highlighting: `matches` are tinted with [`TerminalTheme::search_bg`]
    /// (or `search_current_bg` for `matches[current_match]`).
    /// `selection` takes priority over a match
    /// tint on any cell covered by both.
    ///
    /// Scroll position is NOT painted here: the Slint `TerminalScrollbar`
    /// overlay (`ui/app.slint`) renders the interactive 10px rail/thumb from
    /// the same `scrollback_len`/`scroll_offset` fields, so the buffer stays
    /// pure terminal content.
    ///
    /// Callers should pre-filter `matches` to ones visible in the current
    /// viewport window (the row range `snap.scrollback_len -
    /// snap.scroll_offset` through that plus `snap.size.rows`). This pass
    /// does a linear scan per cell and is not sized for the full match list
    /// of a common single-character query across a 10k-line buffer.
    #[allow(clippy::too_many_arguments)]
    pub fn render_to_full(
        &mut self,
        snap: &GridSnapshot,
        target_w: u32,
        target_h: u32,
        selection: Option<&Selection>,
        matches: &[SearchMatch],
        current_match: Option<usize>,
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
        // absolute buffer row of this snapshot's viewport row 0 — see
        // `SelectionPoint`'s doc comment. Saturates to 0 for a earlier
        // snapshot that never set these fields (all-zero is indistinguishable
        // from "at the tail with no scrollback," which is the correct fallback).
        let abs_top = snap.scrollback_len.saturating_sub(snap.scroll_offset);

        // Paint every cell background before any glyph. Glyphs are deliberately clipped only
        // to the framebuffer, not their cell: a later spacer/neighbor background must not
        // erase a wide glyph tail or italic overhang drawn into that neighbor.
        for row in 0..rows {
            let abs_row = u16::try_from(abs_top + row as u32).unwrap_or(u16::MAX);
            for col in 0..cols {
                let idx = row * cols + col;
                let Some(cell) = snap.cells.get(idx) else {
                    continue;
                };
                let col_u16 = col as u16;
                let (_, bg) = self.resolved_cell_colors(
                    cell,
                    abs_row,
                    col_u16,
                    snap.size.cols,
                    selection,
                    matches,
                    current_match,
                );
                let ox = col * cw;
                let oy = row * ch_h;
                fill_rect(bytes, stride, ox, oy, cw, ch_h, bg);
            }
        }

        // Compose glyphs and decorations only after the complete background plane exists.
        for row in 0..rows {
            for col in 0..cols {
                let idx = row * cols + col;
                let Some(cell) = snap.cells.get(idx) else {
                    continue;
                };
                // Selection/search affect only the already-painted background. Resolve the
                // foreground directly here so the glyph pass does not repeat their linear
                // match scan for every cell.
                let fg = if cell.attrs.reverse() {
                    self.theme.resolve(cell.bg, false)
                } else {
                    self.theme.resolve(cell.fg, true)
                };
                let ox = col * cw;
                let oy = row * ch_h;

                if !cell.attrs.hidden() && !cell.grapheme.is_empty() {
                    let style = font_style(cell.attrs);
                    let metrics = self.metrics;
                    let opacity = if cell.attrs.dim() { 128 } else { 255 };
                    let g = self.glyph(&cell.grapheme, style);
                    blit_cluster(
                        bytes,
                        stride,
                        w,
                        h,
                        ox,
                        oy,
                        metrics.baseline,
                        &g,
                        fg,
                        opacity,
                    );
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
    fn resolved_cell_colors(
        &self,
        cell: &cm_core::Cell,
        abs_row: u16,
        col: u16,
        cols: u16,
        selection: Option<&Selection>,
        matches: &[SearchMatch],
        current_match: Option<usize>,
    ) -> (Rgb, Rgb) {
        let mut fg = self.theme.resolve(cell.fg, true);
        let mut bg = self.theme.resolve(cell.bg, false);
        if cell.attrs.reverse() {
            std::mem::swap(&mut fg, &mut bg);
        }
        if let Some(sel) = selection
            && sel.contains(abs_row, col, cols)
        {
            bg = self.theme.selection_bg;
        } else if let Some(match_index) = matches.iter().position(|m| m.contains(abs_row, col)) {
            bg = if current_match == Some(match_index) {
                self.theme.search_current_bg
            } else {
                self.theme.search_bg
            };
        }
        (fg, bg)
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
                    if !cell.attrs.hidden() && !cell.grapheme.is_empty() {
                        let style = font_style(cell.attrs);
                        let metrics = self.metrics;
                        let opacity = if cell.attrs.dim() { 128 } else { 255 };
                        let g = self.glyph(&cell.grapheme, style);
                        blit_cluster(
                            bytes,
                            stride,
                            w,
                            h,
                            ox,
                            oy,
                            metrics.baseline,
                            &g,
                            cell_bg,
                            opacity,
                        );
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
fn blit_cluster(
    bytes: &mut [u8],
    stride: usize,
    w: u32,
    h: u32,
    ox: usize,
    oy: usize,
    baseline: i32,
    cluster: &RasterizedCluster,
    fg: Rgb,
    opacity: u8,
) {
    for layer in &cluster.layers {
        blit_layer(bytes, stride, w, h, ox, oy, baseline, layer, fg, opacity);
    }
}

#[allow(clippy::too_many_arguments)]
fn blit_layer(
    bytes: &mut [u8],
    stride: usize,
    w: u32,
    h: u32,
    ox: usize,
    oy: usize,
    baseline: i32,
    layer: &RasterizedLayer,
    fg: Rgb,
    opacity: u8,
) {
    // Not clipped to the cell: wide glyphs and italic overhang may occupy adjacent cells.
    let gx0 = ox as i32 + layer.left;
    let gy0 = oy as i32 + baseline - layer.top;
    let layer_w = layer.width as usize;
    let layer_h = layer.height as usize;
    for gy in 0..layer_h {
        let py = gy0 + gy as i32;
        if py < 0 || py as u32 >= h {
            continue;
        }
        let row = py as usize * stride;
        for gx in 0..layer_w {
            let px = gx0 + gx as i32;
            if px < 0 || px as u32 >= w {
                continue;
            }
            let pixel = gy * layer_w + gx;
            let (src, alpha) = match &layer.pixels {
                GlyphPixels::Mask(mask) => {
                    let Some(&coverage) = mask.get(pixel) else {
                        continue;
                    };
                    (fg, u32::from(coverage) * u32::from(opacity) / 255)
                }
                GlyphPixels::Color(rgba) => {
                    let i = pixel * 4;
                    let Some(pixel) = rgba.get(i..i + 4) else {
                        continue;
                    };
                    (
                        (pixel[0], pixel[1], pixel[2]),
                        u32::from(pixel[3]) * u32::from(opacity) / 255,
                    )
                }
            };
            if alpha == 0 {
                continue;
            }
            let i = row + px as usize * 4;
            if i + 3 >= bytes.len() {
                continue;
            }
            let inv = 255 - alpha;
            bytes[i] = ((u32::from(src.0) * alpha + u32::from(bytes[i]) * inv) / 255) as u8;
            bytes[i + 1] = ((u32::from(src.1) * alpha + u32::from(bytes[i + 1]) * inv) / 255) as u8;
            bytes[i + 2] = ((u32::from(src.2) * alpha + u32::from(bytes[i + 2]) * inv) / 255) as u8;
            bytes[i + 3] = 0xff;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cm_core::{Cell, CursorState, GridSnapshot, TerminalSize};
    use std::sync::Mutex;

    use super::font_backend::{FontBackend, GlyphSource};

    type RasterCalls = Arc<Mutex<Vec<(String, FontStyle)>>>;

    #[derive(Clone)]
    struct FakeBackend {
        calls: RasterCalls,
    }

    impl FontBackend for FakeBackend {
        fn primary_metrics(
            &mut self,
            _preferred_family: &str,
            physical_px: f32,
        ) -> Result<CellMetrics, String> {
            Ok(CellMetrics {
                cell_w: physical_px.ceil() as u32,
                cell_h: (physical_px * 2.0).ceil() as u32,
                baseline: physical_px.round() as i32,
                ascent: physical_px,
                descent: -physical_px,
            })
        }

        fn rasterize(&mut self, request: FontRequest<'_>) -> Result<RasterizedCluster, String> {
            self.calls
                .lock()
                .unwrap()
                .push((request.grapheme.to_owned(), request.style));
            let (width, pixels) = if request.grapheme == "color" {
                (1, GlyphPixels::Color(vec![240, 30, 80, 255]))
            } else if request.grapheme == "overhang" {
                (9, GlyphPixels::Mask(vec![255; 9]))
            } else if request.grapheme == "empty" {
                (1, GlyphPixels::Mask(vec![0]))
            } else {
                (1, GlyphPixels::Mask(vec![255]))
            };
            Ok(RasterizedCluster {
                layers: vec![RasterizedLayer {
                    width,
                    height: 1,
                    left: 0,
                    top: 0,
                    pixels,
                }],
                source: GlyphSource::BundledBase,
            })
        }
    }

    fn fake_renderer() -> (TerminalRenderer, RasterCalls) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fonts = TerminalFontSystem::with_test_backend(
            FakeBackend {
                calls: calls.clone(),
            },
            vec![DEFAULT_TERMINAL_FONT_FAMILY.to_owned()],
        );
        (
            TerminalRenderer::with_font_system(
                fonts,
                DEFAULT_TERMINAL_FONT_FAMILY,
                8.0,
                1.0,
                TerminalTheme::dark(),
            ),
            calls,
        )
    }

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
            scrollback_len: 0,
            scroll_offset: 0,
            mouse_tracking: false,
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
    fn complete_grapheme_is_one_backend_request_and_cache_key() {
        let (mut renderer, calls) = fake_renderer();
        let grapheme = "e\u{301}";
        let cell = mk(
            grapheme,
            Color::Default,
            Color::Default,
            CellAttrs::empty(),
            1,
        );
        let snapshot = snap(1, 1, vec![cell], blank_cursor());
        let _ = renderer.render(&snapshot);
        let _ = renderer.render(&snapshot);
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            &[(grapheme.to_owned(), FontStyle::Regular)]
        );

        renderer.set_scale(8.0, 2.0);
        let _ = renderer.render(&snapshot);
        assert_eq!(calls.lock().unwrap().len(), 2, "scale clears the atlas");
    }

    #[test]
    fn atlas_warm_hit_does_not_call_the_backend_again() {
        let (mut renderer, calls) = fake_renderer();
        let first = renderer.glyph("warm", FontStyle::Italic);
        let second = renderer.glyph("warm", FontStyle::Italic);
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn atlas_clears_at_the_deterministic_entry_cap() {
        let (mut renderer, calls) = fake_renderer();
        for index in 0..=GLYPH_ATLAS_ENTRY_CAP {
            let grapheme = format!("hostile-{index}");
            let _ = renderer.glyph(&grapheme, FontStyle::Regular);
        }
        assert_eq!(renderer.cache_len(), 1);
        assert_eq!(calls.lock().unwrap().len(), GLYPH_ATLAS_ENTRY_CAP + 1);
    }

    #[test]
    fn cache_distinguishes_complete_graphemes_and_styles() {
        let (mut renderer, calls) = fake_renderer();
        let cells = vec![
            mk("ab", Color::Default, Color::Default, CellAttrs::empty(), 1),
            mk("a", Color::Default, Color::Default, CellAttrs::BOLD, 1),
        ];
        let _ = renderer.render(&snap(1, 2, cells, blank_cursor()));
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            &[
                ("ab".to_owned(), FontStyle::Regular),
                ("a".to_owned(), FontStyle::Bold),
            ]
        );
    }

    #[test]
    fn intrinsic_color_is_not_tinted_by_reverse_and_dim_reduces_alpha() {
        let (mut renderer, _) = fake_renderer();
        let bg = Color::Rgb { r: 0, g: 0, b: 0 };
        let fg = Color::Rgb { r: 0, g: 255, b: 0 };
        let regular = renderer.render(&snap(
            1,
            1,
            vec![mk("color", fg, bg, CellAttrs::REVERSE, 1)],
            blank_cursor(),
        ));
        let baseline = renderer.cell_metrics().baseline as u32;
        assert_eq!(px_at(&regular, 0, baseline), (240, 30, 80));

        let dim = renderer.render(&snap(
            1,
            1,
            vec![mk("color", fg, bg, CellAttrs::DIM, 1)],
            blank_cursor(),
        ));
        let pixel = px_at(&dim, 0, baseline);
        assert!(pixel.0 > pixel.1 && pixel.0 < 240);
    }

    #[test]
    fn missing_requested_family_falls_back_to_bundled_default_live() {
        let (mut renderer, _) = fake_renderer();
        assert_eq!(
            renderer.set_preferred_family("not installed"),
            DEFAULT_TERMINAL_FONT_FAMILY
        );
        assert_eq!(renderer.effective_family(), DEFAULT_TERMINAL_FONT_FAMILY);
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
    fn wide_char_spacer_draws_no_glyph() {
        let (mut r, calls) = fake_renderer();
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
        assert_eq!(
            calls
                .lock()
                .unwrap()
                .iter()
                .map(|(grapheme, _)| grapheme.as_str())
                .collect::<Vec<_>>(),
            ["世", "A"],
            "the empty spacer cell must not request a glyph"
        );
    }

    #[test]
    fn later_cell_background_does_not_erase_a_glyph_overhang() {
        let (mut renderer, _) = fake_renderer();
        let fg = Color::Rgb {
            r: 240,
            g: 30,
            b: 80,
        };
        let first_bg = Color::Rgb { r: 0, g: 0, b: 0 };
        let neighbor_bg = Color::Rgb {
            r: 10,
            g: 40,
            b: 90,
        };
        let cells = vec![
            mk("overhang", fg, first_bg, CellAttrs::empty(), 2),
            mk("", fg, neighbor_bg, CellAttrs::empty(), 1),
        ];
        let buf = renderer.render(&snap(1, 2, cells, blank_cursor()));
        let metrics = renderer.cell_metrics();
        assert_eq!(
            px_at(&buf, metrics.cell_w, metrics.baseline as u32),
            (240, 30, 80),
            "the next cell's background must be behind the preceding glyph tail"
        );
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

    // ──: Selection geometry ─────────────────────────────────────────

    fn pt(row: u16, col: u16) -> SelectionPoint {
        SelectionPoint { row, col }
    }

    #[test]
    fn normalized_is_order_independent_of_drag_direction() {
        // Dragged top-left -> bottom-right.
        let forward = Selection::new(pt(1, 2), pt(3, 4));
        assert_eq!(forward.normalized(), (pt(1, 2), pt(3, 4)));
        // Dragged bottom-right -> top-left: same normalized range.
        let backward = Selection::new(pt(3, 4), pt(1, 2));
        assert_eq!(backward.normalized(), (pt(1, 2), pt(3, 4)));
        // Same row, dragged right -> left.
        let same_row = Selection::new(pt(0, 5), pt(0, 1));
        assert_eq!(same_row.normalized(), (pt(0, 1), pt(0, 5)));
    }

    #[test]
    fn is_empty_true_only_when_anchor_equals_cursor() {
        assert!(Selection::new(pt(2, 2), pt(2, 2)).is_empty());
        assert!(!Selection::new(pt(2, 2), pt(2, 3)).is_empty());
    }

    #[test]
    fn contains_single_row_span() {
        let sel = Selection::new(pt(0, 2), pt(0, 5));
        assert!(!sel.contains(0, 1, 10));
        assert!(sel.contains(0, 2, 10));
        assert!(sel.contains(0, 5, 10));
        assert!(!sel.contains(0, 6, 10));
        // A different row is never in range.
        assert!(!sel.contains(1, 3, 10));
    }

    #[test]
    fn contains_multi_row_first_middle_last() {
        let sel = Selection::new(pt(1, 5), pt(3, 2));
        let cols = 10;
        // First row: from col 5 to end of row.
        assert!(!sel.contains(1, 4, cols));
        assert!(sel.contains(1, 5, cols));
        assert!(sel.contains(1, 9, cols));
        // Middle row: fully covered.
        assert!(sel.contains(2, 0, cols));
        assert!(sel.contains(2, 9, cols));
        // Last row: from start of row to col 2.
        assert!(sel.contains(3, 0, cols));
        assert!(sel.contains(3, 2, cols));
        assert!(!sel.contains(3, 3, cols));
        // Outside the row range entirely.
        assert!(!sel.contains(0, 0, cols));
        assert!(!sel.contains(4, 0, cols));
    }

    #[test]
    fn row_span_clamps_to_grid_width() {
        // A selection made at a wider grid (col 20) queried against a
        // narrower one (cols=10) clamps rather than panicking or returning an
        // out-of-range column — belt-and-suspenders alongside the
        // controller-layer "clear selection on resize" lifecycle rule.
        let sel = Selection::new(pt(0, 0), pt(0, 20));
        assert_eq!(sel.row_span(0, 10), Some((0, 9)));
    }

    #[test]
    fn row_span_none_for_zero_cols_or_out_of_range_row() {
        let sel = Selection::new(pt(0, 0), pt(2, 0));
        assert_eq!(sel.row_span(1, 0), None);
        assert_eq!(sel.row_span(5, 10), None);
    }

    #[test]
    fn no_selection_paints_no_highlight() {
        let mut r = TerminalRenderer::new(14.0, 1.0, TerminalTheme::dark());
        let bg = Color::Rgb {
            r: 10,
            g: 10,
            b: 10,
        };
        let cell = mk("", Color::Default, bg, CellAttrs::empty(), 1);
        let buf = r.render_selected(&snap(1, 1, vec![cell], blank_cursor()), None);
        let (cx, cy) = cell_center(&r, 0, 0);
        assert_eq!(px_at(&buf, cx, cy), (10, 10, 10));
    }

    #[test]
    fn single_cell_selection_tints_only_that_cell() {
        let mut r = TerminalRenderer::new(14.0, 1.0, TerminalTheme::dark());
        let bg = Color::Rgb {
            r: 10,
            g: 10,
            b: 10,
        };
        // Two cells; only cell 0 is selected (anchor == cursor is a legitimate
        // single-cell selection — e.g. double-click on a one-char word).
        let cells = vec![
            mk("", Color::Default, bg, CellAttrs::empty(), 1),
            mk("", Color::Default, bg, CellAttrs::empty(), 1),
        ];
        let sel = Selection::new(pt(0, 0), pt(0, 0));
        let buf = r.render_selected(&snap(1, 2, cells, blank_cursor()), Some(&sel));
        let (c0x, c0y) = cell_center(&r, 0, 0);
        let (c1x, c1y) = cell_center(&r, 0, 1);
        assert_eq!(px_at(&buf, c0x, c0y), TerminalTheme::dark().selection_bg);
        assert_eq!(px_at(&buf, c1x, c1y), (10, 10, 10));
    }

    // ──: search-match highlighting + selection-vs-offset seam ──────────

    #[test]
    fn search_match_tints_only_the_matched_cell() {
        let mut r = TerminalRenderer::new(14.0, 1.0, TerminalTheme::dark());
        let bg = Color::Rgb {
            r: 10,
            g: 10,
            b: 10,
        };
        let cells = vec![
            mk("", Color::Default, bg, CellAttrs::empty(), 1),
            mk("", Color::Default, bg, CellAttrs::empty(), 1),
        ];
        let m = SearchMatch {
            row: 0,
            col_start: 0,
            col_end: 0,
        };
        let s = snap(1, 2, cells, blank_cursor());
        let (w, h) = r.pixel_size(s.size);
        let buf = r.render_to_full(&s, w, h, None, &[m], None);
        let (c0x, c0y) = cell_center(&r, 0, 0);
        let (c1x, c1y) = cell_center(&r, 0, 1);
        assert_eq!(px_at(&buf, c0x, c0y), TerminalTheme::dark().search_bg);
        assert_eq!(px_at(&buf, c1x, c1y), (10, 10, 10));
    }

    #[test]
    fn current_search_match_uses_the_brighter_current_color() {
        let mut r = TerminalRenderer::new(14.0, 1.0, TerminalTheme::dark());
        let bg = Color::Rgb {
            r: 10,
            g: 10,
            b: 10,
        };
        let cells = vec![
            mk("", Color::Default, bg, CellAttrs::empty(), 1),
            mk("", Color::Default, bg, CellAttrs::empty(), 1),
        ];
        let matches = [
            SearchMatch {
                row: 0,
                col_start: 0,
                col_end: 0,
            },
            SearchMatch {
                row: 0,
                col_start: 1,
                col_end: 1,
            },
        ];
        let s = snap(1, 2, cells, blank_cursor());
        let (w, h) = r.pixel_size(s.size);
        let buf = r.render_to_full(&s, w, h, None, &matches, Some(1));
        let (c0x, c0y) = cell_center(&r, 0, 0);
        let (c1x, c1y) = cell_center(&r, 0, 1);
        assert_eq!(px_at(&buf, c0x, c0y), TerminalTheme::dark().search_bg);
        assert_eq!(
            px_at(&buf, c1x, c1y),
            TerminalTheme::dark().search_current_bg
        );
    }

    #[test]
    fn selection_wins_over_a_search_match_on_the_same_cell() {
        let mut r = TerminalRenderer::new(14.0, 1.0, TerminalTheme::dark());
        let bg = Color::Rgb {
            r: 10,
            g: 10,
            b: 10,
        };
        let cell = mk("", Color::Default, bg, CellAttrs::empty(), 1);
        let sel = Selection::new(pt(0, 0), pt(0, 0));
        let m = SearchMatch {
            row: 0,
            col_start: 0,
            col_end: 0,
        };
        let s = snap(1, 1, vec![cell], blank_cursor());
        let (w, h) = r.pixel_size(s.size);
        let buf = r.render_to_full(&s, w, h, Some(&sel), &[m], Some(0));
        let (cx, cy) = cell_center(&r, 0, 0);
        assert_eq!(px_at(&buf, cx, cy), TerminalTheme::dark().selection_bg);
    }

    #[test]
    fn scrollback_translates_selection_row_to_the_right_viewport_row() {
        // A 2-row snapshot, 10 lines of scrollback, scrolled back 8 (so the
        // viewport's absolute top row is 2): a selection stored at absolute
        // row 3 must highlight viewport row 1, not row 0.
        let mut r = TerminalRenderer::new(14.0, 1.0, TerminalTheme::dark());
        let bg = Color::Rgb {
            r: 10,
            g: 10,
            b: 10,
        };
        let cells = vec![
            mk("", Color::Default, bg, CellAttrs::empty(), 1),
            mk("", Color::Default, bg, CellAttrs::empty(), 1),
        ];
        let mut s = snap(2, 1, cells, blank_cursor());
        s.scrollback_len = 10;
        s.scroll_offset = 8;
        let sel = Selection::new(pt(3, 0), pt(3, 0));
        let (w, h) = r.pixel_size(s.size);
        let buf = r.render_to_selected(&s, w, h, Some(&sel));
        let (r0x, r0y) = cell_center(&r, 0, 0);
        let (r1x, r1y) = cell_center(&r, 1, 0);
        assert_eq!(
            px_at(&buf, r0x, r0y),
            (10, 10, 10),
            "row 0 (abs line 2) unselected"
        );
        assert_eq!(
            px_at(&buf, r1x, r1y),
            TerminalTheme::dark().selection_bg,
            "row 1 (abs line 3) is the selected one"
        );
    }

    #[test]
    fn scrollbar_absent_with_no_scrollback() {
        let mut r = TerminalRenderer::new(14.0, 1.0, TerminalTheme::dark());
        let cell = mk("", Color::Default, Color::Default, CellAttrs::empty(), 1);
        let buf = r.render(&snap(4, 20, vec![cell; 80], blank_cursor()));
        let w = buf.width();
        // Rightmost column should be plain background, not the track color.
        assert_eq!(px_at(&buf, w - 1, 0), TerminalTheme::dark().bg);
    }

    #[test]
    fn no_painted_scrollbar_when_scrolled_back() {
        // The interactive overlay scrollbar lives in Slint (`TerminalScrollbar`
        // in `ui/app.slint`); the buffer itself must stay pure terminal
        // content so the overlay is the single scroll indicator.
        let mut r = TerminalRenderer::new(14.0, 1.0, TerminalTheme::dark());
        let cell = mk("", Color::Default, Color::Default, CellAttrs::empty(), 1);
        let mut s = snap(4, 20, vec![cell; 80], blank_cursor());
        s.scrollback_len = 100;
        s.scroll_offset = 50;
        let buf = r.render(&s);
        let w = buf.width();
        // The rightmost column is plain background — no painted track.
        assert_eq!(px_at(&buf, w - 1, 0), TerminalTheme::dark().bg);
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
        let a = TerminalFontSystem::shared();
        let b = TerminalFontSystem::shared();
        assert!(Arc::ptr_eq(&a, &b));
    }

    // ── Available terminal palettes and live scheme switching ───────────────

    #[test]
    fn light_and_dark_themes_have_distinct_default_fg_bg() {
        // Sanity: light remains a genuine alternative scheme even though the
        // application currently selects dark for every new terminal.
        let dark = TerminalTheme::dark();
        let light = TerminalTheme::light();
        assert_eq!(dark.bg, (0x0a, 0x0c, 0x10));
        assert_eq!(dark.fg, (0xc9, 0xcc, 0xd1));
        assert_eq!(light.bg, (0xff, 0xff, 0xff));
        assert_eq!(light.fg, (0x2b, 0x2f, 0x36));
        assert_ne!(dark.bg, light.bg);
        assert_ne!(dark.fg, light.fg);
    }

    #[test]
    fn set_theme_recolors_the_very_next_render() {
        // A future settings control can switch schemes without an additional
        // cache-invalidation step at the call site.
        let mut r = TerminalRenderer::new(16.0, 1.0, TerminalTheme::dark());
        let cells = vec![Cell::default(); 2];
        let before = r.render(&snap(1, 2, cells.clone(), blank_cursor()));
        assert_eq!(px_at(&before, 0, 0), TerminalTheme::dark().bg);

        r.set_theme(TerminalTheme::light());
        let after = r.render(&snap(1, 2, cells, blank_cursor()));
        assert_eq!(px_at(&after, 0, 0), TerminalTheme::light().bg);
    }

    /// profiling aid: a warm 80x24 ASCII grid should reuse the per-renderer atlas.
    #[test]
    #[ignore = "profiling aid; run explicitly with --ignored --nocapture"]
    fn profile_warm_ascii_render() {
        use std::time::Instant;
        let mut renderer = TerminalRenderer::new(15.0, 1.0, TerminalTheme::dark());
        let cells = (0..80 * 24)
            .map(|index| {
                let ch = char::from(b' ' + (index % 95) as u8);
                mk(
                    &ch.to_string(),
                    Color::Default,
                    Color::Default,
                    CellAttrs::empty(),
                    1,
                )
            })
            .collect();
        let snapshot = snap(24, 80, cells, blank_cursor());
        let _ = renderer.render(&snapshot);
        let started = Instant::now();
        let _ = renderer.render(&snapshot);
        eprintln!("warm 80x24 ASCII render: {:?}", started.elapsed());
    }
}

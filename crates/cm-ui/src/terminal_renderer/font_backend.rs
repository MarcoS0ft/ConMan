use std::collections::HashSet;
use std::hash::Hash;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use cm_core::DEFAULT_TERMINAL_FONT_FAMILY;
use cosmic_text::{
    Attrs, Buffer, CacheKey, CacheKeyFlags, Fallback, Family, FontSystem, Metrics,
    PlatformFallback, Shaping, Style, SwashCache, SwashContent, Weight, Wrap, fontdb,
};
use unicode_script::Script;

use super::{CellMetrics, FONT_BOLD, FONT_BOLD_ITALIC, FONT_ITALIC, FONT_REGULAR, FONT_SYMBOLS};

const SYMBOLS_FAMILY: &str = "Symbols Nerd Font Mono";
const PRIMARY_METRICS_SAMPLE: char = 'M';

fn extend_with_new<T: Eq + Hash>(set: &mut HashSet<T>, items: impl IntoIterator<Item = T>) -> bool {
    let before = set.len();
    set.extend(items);
    set.len() != before
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum FontStyle {
    Regular,
    Bold,
    Italic,
    BoldItalic,
}

impl FontStyle {
    fn weight_and_style(self) -> (Weight, Style) {
        match self {
            Self::Regular => (Weight::NORMAL, Style::Normal),
            Self::Bold => (Weight::BOLD, Style::Normal),
            Self::Italic => (Weight::NORMAL, Style::Italic),
            Self::BoldItalic => (Weight::BOLD, Style::Italic),
        }
    }

    fn attrs(self, family: &str) -> Attrs<'_> {
        let (weight, style) = self.weight_and_style();
        Attrs::new()
            .family(Family::Name(family))
            .weight(weight)
            .style(style)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GlyphSource {
    BundledBase,
    BundledSymbols,
    SystemFallback { family: Box<str> },
    Missing,
}

#[derive(Debug, Clone)]
pub(super) enum GlyphPixels {
    Mask(Vec<u8>),
    Color(Vec<u8>),
}

#[derive(Debug, Clone)]
pub(super) struct RasterizedLayer {
    pub width: u32,
    pub height: u32,
    pub left: i32,
    /// Offset above the primary baseline.
    pub top: i32,
    pub pixels: GlyphPixels,
}

#[derive(Debug, Clone)]
pub(super) struct RasterizedCluster {
    pub layers: Vec<RasterizedLayer>,
    pub source: GlyphSource,
}

impl RasterizedCluster {
    fn missing() -> Self {
        Self {
            layers: Vec::new(),
            source: GlyphSource::Missing,
        }
    }

    fn has_ink(&self) -> bool {
        self.layers.iter().any(|layer| match &layer.pixels {
            GlyphPixels::Mask(data) => data.iter().any(|&alpha| alpha != 0),
            GlyphPixels::Color(data) => data
                .chunks_exact(4)
                .any(|rgba| rgba.get(3).is_some_and(|&alpha| alpha != 0)),
        })
    }
}

pub(super) struct FontRequest<'a> {
    pub grapheme: &'a str,
    pub style: FontStyle,
    pub physical_px: f32,
    pub preferred_family: &'a str,
}

pub(super) trait FontBackend: Send {
    fn primary_metrics(
        &mut self,
        preferred_family: &str,
        physical_px: f32,
    ) -> Result<CellMetrics, String>;

    fn rasterize(&mut self, request: FontRequest<'_>) -> Result<RasterizedCluster, String>;
}

/// Process-wide terminal font owner. System enumeration and embedded-face parsing happen once;
/// each renderer keeps only its own bounded grapheme atlas.
pub struct TerminalFontSystem {
    backend: Mutex<Box<dyn FontBackend>>,
    families: Vec<String>,
}

impl std::fmt::Debug for TerminalFontSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalFontSystem")
            .field("families", &self.families)
            .finish_non_exhaustive()
    }
}

impl TerminalFontSystem {
    /// Construct the shared production font system. Cheap after the first call.
    #[must_use]
    pub fn shared() -> Arc<Self> {
        static SHARED: OnceLock<Arc<TerminalFontSystem>> = OnceLock::new();
        SHARED
            .get_or_init(|| {
                let started = Instant::now();
                let mut backend = CosmicTextBackend::new();
                let families = backend.available_monospace_families();
                tracing::info!(
                    elapsed_ms = started.elapsed().as_millis(),
                    family_count = families.len(),
                    "constructed terminal font system"
                );
                Arc::new(Self {
                    backend: Mutex::new(Box::new(backend)),
                    families,
                })
            })
            .clone()
    }

    /// Usable monospace families: bundled default first, all remaining names sorted and
    /// deduplicated case-insensitively.
    #[must_use]
    pub fn available_monospace_families(&self) -> &[String] {
        &self.families
    }

    pub(crate) fn resolve_family(&self, requested: &str) -> String {
        self.families
            .iter()
            .find(|family| family.eq_ignore_ascii_case(requested.trim()))
            .cloned()
            .unwrap_or_else(|| DEFAULT_TERMINAL_FONT_FAMILY.to_owned())
    }

    pub(super) fn primary_metrics(&self, family: &str, px: f32) -> CellMetrics {
        let mut backend = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        backend
            .primary_metrics(family, px)
            .or_else(|_| backend.primary_metrics(DEFAULT_TERMINAL_FONT_FAMILY, px))
            .expect("bundled default font must provide terminal metrics")
    }

    pub(super) fn rasterize(&self, request: FontRequest<'_>) -> RasterizedCluster {
        self.backend
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .rasterize(request)
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "terminal grapheme rasterization failed");
                RasterizedCluster::missing()
            })
    }

    #[cfg(test)]
    pub(super) fn with_test_backend(
        backend: impl FontBackend + 'static,
        families: Vec<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            backend: Mutex::new(Box::new(backend)),
            families,
        })
    }
}

struct TerminalFallback {
    platform: PlatformFallback,
    common: Vec<&'static str>,
}

impl TerminalFallback {
    fn new() -> Self {
        let platform = PlatformFallback;
        let mut common = Vec::with_capacity(platform.common_fallback().len() + 1);
        common.push(SYMBOLS_FAMILY);
        common.extend(
            platform
                .common_fallback()
                .iter()
                .copied()
                .filter(|family| !family.eq_ignore_ascii_case(SYMBOLS_FAMILY)),
        );
        Self { platform, common }
    }
}

impl Fallback for TerminalFallback {
    fn common_fallback(&self) -> &[&'static str] {
        &self.common
    }

    fn forbidden_fallback(&self) -> &[&'static str] {
        self.platform.forbidden_fallback()
    }

    fn script_fallback(&self, script: Script, locale: &str) -> &[&'static str] {
        self.platform.script_fallback(script, locale)
    }
}

struct CosmicTextBackend {
    primary: FontSystem,
    retry: Option<FontSystem>,
    swash: SwashCache,
    bundled_base: HashSet<fontdb::ID>,
    bundled_symbols: HashSet<fontdb::ID>,
    quarantined: HashSet<fontdb::ID>,
    face_bound: usize,
    first_retry_construction: Option<Duration>,
}

impl CosmicTextBackend {
    fn new() -> Self {
        let sources = [
            FONT_REGULAR,
            FONT_BOLD,
            FONT_ITALIC,
            FONT_BOLD_ITALIC,
            FONT_SYMBOLS,
        ]
        .into_iter()
        .map(|bytes| fontdb::Source::Binary(Arc::new(bytes.to_vec())));
        let initial = FontSystem::new_with_fonts(sources);
        let (locale, mut db) = initial.into_locale_and_db();

        let mut bundled_base = HashSet::new();
        let mut bundled_symbols = HashSet::new();
        for face in db.faces() {
            let bundled = matches!(face.source, fontdb::Source::Binary(_));
            if !bundled {
                continue;
            }
            if face
                .families
                .iter()
                .any(|(name, _)| name == DEFAULT_TERMINAL_FONT_FAMILY)
            {
                bundled_base.insert(face.id);
            } else if face.families.iter().any(|(name, _)| name == SYMBOLS_FAMILY) {
                bundled_symbols.insert(face.id);
            }
        }
        // `new_with_fonts` scans the OS before adding supplied binaries. Remove installed
        // duplicates of the two bundled family names so CSS matching cannot put an arbitrary
        // system copy ahead of ConMan's pinned faces.
        let installed_duplicates = db
            .faces()
            .filter(|face| !matches!(face.source, fontdb::Source::Binary(_)))
            .filter(|face| {
                face.families
                    .iter()
                    .any(|(name, _)| name == DEFAULT_TERMINAL_FONT_FAMILY || name == SYMBOLS_FAMILY)
            })
            .map(|face| face.id)
            .collect::<Vec<_>>();
        for id in installed_duplicates {
            db.remove_face(id);
        }
        let face_bound = db.len();
        let primary =
            FontSystem::new_with_locale_and_db_and_fallback(locale, db, TerminalFallback::new());
        Self {
            primary,
            retry: None,
            swash: SwashCache::new(),
            bundled_base,
            bundled_symbols,
            quarantined: HashSet::new(),
            face_bound,
            first_retry_construction: None,
        }
    }

    fn available_monospace_families(&mut self) -> Vec<String> {
        let mut families = self
            .primary
            .db()
            .faces()
            .filter(|face| face.monospaced)
            .flat_map(|face| face.families.iter().map(|(name, _)| name.clone()))
            .filter(|name| !name.trim().is_empty())
            .collect::<Vec<_>>();
        families.sort_by(|a, b| {
            a.to_ascii_lowercase()
                .cmp(&b.to_ascii_lowercase())
                .then_with(|| a.cmp(b))
        });
        families.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        families.retain(|family| Self::metrics_for(&mut self.primary, family, 16.0).is_ok());
        families.retain(|family| !family.eq_ignore_ascii_case(DEFAULT_TERMINAL_FONT_FAMILY));
        families.insert(0, DEFAULT_TERMINAL_FONT_FAMILY.to_owned());
        families
    }

    fn metrics_for(
        system: &mut FontSystem,
        preferred_family: &str,
        physical_px: f32,
    ) -> Result<CellMetrics, String> {
        let family = Family::Name(preferred_family);
        let id = system
            .db()
            .query(&fontdb::Query {
                families: &[family],
                weight: Weight::NORMAL,
                stretch: fontdb::Stretch::Normal,
                style: Style::Normal,
            })
            .ok_or_else(|| format!("font family not found: {preferred_family}"))?;
        let font = system
            .get_font(id, Weight::NORMAL)
            .ok_or_else(|| format!("font face failed to load: {preferred_family}"))?;
        let swash = font.as_swash();
        let metrics = swash.metrics(&[]);
        let units = f32::from(metrics.units_per_em).max(1.0);
        let scale = physical_px / units;
        let glyph_metrics = swash.glyph_metrics(&[]);
        let charmap = swash.charmap();
        let missing = (b' '..=b'~')
            .map(char::from)
            .filter(|&ch| charmap.map(ch) == 0)
            .map(|ch| ch.escape_default().to_string())
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(format!(
                "font family lacks required terminal ASCII glyphs: {preferred_family} ({})",
                missing.join(", ")
            ));
        }
        let sample = charmap.map(PRIMARY_METRICS_SAMPLE);
        debug_assert_ne!(sample, 0, "validated primary metrics glyph must be mapped");
        let advance = glyph_metrics.advance_width(sample) * scale;
        let ascent = metrics.ascent * scale;
        // Swash exposes descent as a positive magnitude, while CellMetrics follows the
        // conventional signed baseline coordinate used by the renderer (below = negative).
        let descent = -(metrics.descent.abs() * scale);
        Ok(CellMetrics {
            cell_w: advance.ceil().max(1.0) as u32,
            cell_h: (ascent - descent).ceil().max(1.0) as u32,
            baseline: ascent.round() as i32,
            ascent,
            descent,
        })
    }

    fn shape_and_rasterize(
        system: &mut FontSystem,
        swash: &mut SwashCache,
        request: &FontRequest<'_>,
        bundled_base: &HashSet<fontdb::ID>,
        bundled_symbols: &HashSet<fontdb::ID>,
    ) -> (RasterizedCluster, HashSet<fontdb::ID>, bool) {
        let metrics = Metrics::new(request.physical_px, request.physical_px * 1.4);
        let mut buffer = Buffer::new_empty(metrics);
        buffer.set_wrap(Wrap::None);
        buffer.set_size(None, Some(metrics.line_height));
        buffer.set_text(
            request.grapheme,
            &request.style.attrs(request.preferred_family),
            Shaping::Advanced,
            None,
        );
        buffer.shape_until_scroll(system, false);

        let glyphs = buffer
            .layout_runs()
            .flat_map(|run| run.glyphs.iter().cloned())
            .collect::<Vec<_>>();
        let has_advance = glyphs.iter().any(|glyph| glyph.w > f32::EPSILON);
        if glyphs.is_empty() || glyphs.iter().any(|glyph| glyph.glyph_id == 0) {
            return (RasterizedCluster::missing(), HashSet::new(), has_advance);
        }

        let mut layers = Vec::new();
        let mut empty_installed = HashSet::new();
        let mut source = GlyphSource::BundledBase;
        for glyph in glyphs {
            let font_id = glyph.font_id;
            let family = system
                .db()
                .face(font_id)
                .and_then(|face| face.families.first().map(|(name, _)| name.clone()))
                .unwrap_or_else(|| "unknown".to_owned());
            let installed = system
                .db()
                .face(font_id)
                .is_some_and(|face| !matches!(face.source, fontdb::Source::Binary(_)));
            if bundled_symbols.contains(&font_id) {
                source = GlyphSource::BundledSymbols;
            } else if !bundled_base.contains(&font_id) {
                source = GlyphSource::SystemFallback {
                    family: family.into_boxed_str(),
                };
            }

            let physical = glyph.physical((0.0, 0.0), 1.0);
            let Some(image) = swash.get_image(system, physical.cache_key).clone() else {
                if installed {
                    empty_installed.insert(font_id);
                }
                continue;
            };
            let pixels = match image.content {
                SwashContent::Mask => GlyphPixels::Mask(image.data),
                SwashContent::Color => GlyphPixels::Color(image.data),
                SwashContent::SubpixelMask => {
                    let mask = image
                        .data
                        .chunks_exact(4)
                        .map(|rgba| rgba.iter().copied().max().unwrap_or(0))
                        .collect();
                    GlyphPixels::Mask(mask)
                }
            };
            let layer = RasterizedLayer {
                width: image.placement.width,
                height: image.placement.height,
                left: physical.x + image.placement.left,
                top: image.placement.top - physical.y,
                pixels,
            };
            let has_ink = match &layer.pixels {
                GlyphPixels::Mask(data) => data.iter().any(|&alpha| alpha != 0),
                GlyphPixels::Color(data) => data
                    .chunks_exact(4)
                    .any(|rgba| rgba.get(3).is_some_and(|&alpha| alpha != 0)),
            };
            if has_ink {
                layers.push(layer);
            } else if installed {
                empty_installed.insert(font_id);
            }
        }
        let cluster = RasterizedCluster { layers, source };
        (cluster, empty_installed, has_advance)
    }

    fn rebuild_retry(&mut self) {
        let started = Instant::now();
        let locale = self.primary.locale().to_owned();
        let mut db = self.primary.db().clone();
        for &id in &self.quarantined {
            db.remove_face(id);
        }
        self.retry = Some(FontSystem::new_with_locale_and_db_and_fallback(
            locale,
            db,
            TerminalFallback::new(),
        ));
        self.swash = SwashCache::new();
        let elapsed = started.elapsed();
        if self.first_retry_construction.is_none() {
            self.first_retry_construction = Some(elapsed);
            tracing::info!(
                elapsed_ms = elapsed.as_millis(),
                quarantined_faces = self.quarantined.len(),
                "constructed terminal font retry system"
            );
        }
    }

    fn notdef(&mut self, request: &FontRequest<'_>) -> RasterizedCluster {
        let (weight, style) = request.style.weight_and_style();
        let family = Family::Name(request.preferred_family);
        let Some(id) = self.primary.db().query(&fontdb::Query {
            families: &[family],
            weight,
            stretch: fontdb::Stretch::Normal,
            style,
        }) else {
            return RasterizedCluster::missing();
        };
        let (key, x, y) = CacheKey::new(
            id,
            0,
            request.physical_px,
            (0.0, 0.0),
            weight,
            CacheKeyFlags::empty(),
        );
        let Some(image) = self.swash.get_image(&mut self.primary, key).clone() else {
            return RasterizedCluster::missing();
        };
        let pixels = match image.content {
            SwashContent::Mask => GlyphPixels::Mask(image.data),
            SwashContent::Color => GlyphPixels::Color(image.data),
            SwashContent::SubpixelMask => return RasterizedCluster::missing(),
        };
        RasterizedCluster {
            layers: vec![RasterizedLayer {
                width: image.placement.width,
                height: image.placement.height,
                left: x + image.placement.left,
                top: image.placement.top - y,
                pixels,
            }],
            source: GlyphSource::Missing,
        }
    }
}

impl FontBackend for CosmicTextBackend {
    fn primary_metrics(
        &mut self,
        preferred_family: &str,
        physical_px: f32,
    ) -> Result<CellMetrics, String> {
        Self::metrics_for(&mut self.primary, preferred_family, physical_px)
    }

    fn rasterize(&mut self, request: FontRequest<'_>) -> Result<RasterizedCluster, String> {
        let whitespace = request.grapheme.chars().all(char::is_whitespace);
        let (cluster, empty_faces, has_advance) = Self::shape_and_rasterize(
            &mut self.primary,
            &mut self.swash,
            &request,
            &self.bundled_base,
            &self.bundled_symbols,
        );
        // Default-ignorable and other zero-advance clusters are successful blanks. They have
        // no visual intent, so an empty raster is not evidence that a selected installed face
        // is broken and must never trigger quarantine/database reconstruction.
        if whitespace || cluster.has_ink() || !has_advance {
            return Ok(cluster);
        }

        let already_quarantined = empty_faces
            .iter()
            .any(|face| self.quarantined.contains(face));
        if extend_with_new(&mut self.quarantined, empty_faces) {
            self.rebuild_retry();
        } else if !already_quarantined || self.retry.is_none() {
            return Ok(self.notdef(&request));
        }

        // Every unsuccessful iteration must quarantine at least one new face. The database is
        // finite, so hostile input cannot loop forever or retry the same face.
        for _ in 0..self.face_bound {
            let retry = self.retry.as_mut().expect("retry system just constructed");
            let (cluster, empty_faces, has_advance) = Self::shape_and_rasterize(
                retry,
                &mut self.swash,
                &request,
                &self.bundled_base,
                &self.bundled_symbols,
            );
            if cluster.has_ink() || !has_advance {
                return Ok(cluster);
            }
            if !extend_with_new(&mut self.quarantined, empty_faces) {
                return Ok(self.notdef(&request));
            }
            self.rebuild_retry();
        }
        Ok(self.notdef(&request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_fallback_puts_symbols_first() {
        let fallback = TerminalFallback::new();
        assert_eq!(fallback.common_fallback().first(), Some(&SYMBOLS_FAMILY));
        assert_eq!(
            &fallback.common_fallback()[1..],
            PlatformFallback.common_fallback()
        );
    }

    #[test]
    fn quarantine_progress_requires_a_new_face() {
        let mut quarantine = HashSet::new();
        assert!(extend_with_new(&mut quarantine, [7_u32]));
        assert!(!extend_with_new(&mut quarantine, [7_u32]));
        assert!(extend_with_new(&mut quarantine, [7_u32, 9_u32]));
        assert_eq!(quarantine, HashSet::from([7, 9]));
    }

    #[test]
    fn standalone_default_ignorables_do_not_quarantine_or_build_a_retry_system() {
        let mut backend = CosmicTextBackend::new();
        for grapheme in ["\u{200d}", "\u{fe0f}"] {
            let before = backend.quarantined.clone();
            let _ = backend
                .rasterize(FontRequest {
                    grapheme,
                    style: FontStyle::Regular,
                    physical_px: 16.0,
                    preferred_family: DEFAULT_TERMINAL_FONT_FAMILY,
                })
                .expect("a zero-advance default-ignorable must be a successful blank");
            assert_eq!(backend.quarantined, before, "{grapheme} quarantined a face");
            assert!(
                backend.retry.is_none(),
                "{grapheme} constructed an unnecessary retry system"
            );
        }
    }

    #[test]
    #[ignore = "profiling aid; run explicitly with --ignored --nocapture"]
    fn profile_font_system_construction() {
        let started = Instant::now();
        let mut backend = CosmicTextBackend::new();
        let families = backend.available_monospace_families();
        eprintln!(
            "cold terminal FontSystem construction: {:?} ({} usable monospace families)",
            started.elapsed(),
            families.len()
        );
    }

    #[test]
    fn family_list_is_default_first_sorted_and_case_insensitively_unique() {
        let mut backend = CosmicTextBackend::new();
        let families = backend.available_monospace_families();
        assert_eq!(
            families.first().map(String::as_str),
            Some(DEFAULT_TERMINAL_FONT_FAMILY)
        );
        assert!(
            families[1..]
                .windows(2)
                .all(|pair| { pair[0].to_ascii_lowercase() <= pair[1].to_ascii_lowercase() })
        );
        assert!(
            families
                .windows(2)
                .all(|pair| !pair[0].eq_ignore_ascii_case(&pair[1]))
        );
    }

    #[test]
    fn symbols_fallback_is_not_offered_as_a_terminal_primary() {
        let mut backend = CosmicTextBackend::new();
        let families = backend.available_monospace_families();
        assert!(
            !families
                .iter()
                .any(|family| family.eq_ignore_ascii_case(SYMBOLS_FAMILY))
        );
    }

    #[test]
    fn bundled_metrics_preserve_the_renderer_negative_descent_contract() {
        let mut backend = CosmicTextBackend::new();
        for (physical_px, expected_height) in [(14.0, 19), (21.0, 28), (28.0, 37)] {
            let metrics = CosmicTextBackend::metrics_for(
                &mut backend.primary,
                DEFAULT_TERMINAL_FONT_FAMILY,
                physical_px,
            )
            .expect("bundled default metrics");

            assert!(
                metrics.descent <= 0.0,
                "CellMetrics descent is a signed offset below the baseline: {metrics:?}"
            );
            assert_eq!(metrics.cell_h, expected_height, "{physical_px}px metrics");
            assert!(
                metrics.baseline < metrics.cell_h as i32,
                "the baseline must remain inside its own row: {metrics:?}"
            );
        }
    }

    #[test]
    fn primary_metrics_rejects_a_face_missing_printable_ascii_coverage() {
        let mut backend = CosmicTextBackend::new();
        let id = backend
            .primary
            .db()
            .query(&fontdb::Query {
                families: &[Family::Name(SYMBOLS_FAMILY)],
                weight: Weight::NORMAL,
                stretch: fontdb::Stretch::Normal,
                style: Style::Normal,
            })
            .expect("bundled symbols face must exist");
        let font = backend
            .primary
            .get_font(id, Weight::NORMAL)
            .expect("bundled symbols face must load");
        let charmap = font.as_swash().charmap();
        assert!(
            (b' '..=b'~').map(char::from).any(|ch| charmap.map(ch) == 0),
            "test fixture must exercise a missing ASCII glyph"
        );
        assert!(
            CosmicTextBackend::metrics_for(&mut backend.primary, SYMBOLS_FAMILY, 16.0).is_err(),
            "primary metrics must never use glyph 0/.notdef"
        );
    }

    #[test]
    #[ignore = "requires installed system fallback fonts"]
    fn system_fallback_prompt_glyphs() {
        let mut backend = CosmicTextBackend::new();
        for grapheme in ["\u{e0a2}", "\u{e0b0}", "🐧", "🏠", "✅"] {
            let cluster = backend
                .rasterize(FontRequest {
                    grapheme,
                    style: FontStyle::Regular,
                    physical_px: 20.0,
                    preferred_family: DEFAULT_TERMINAL_FONT_FAMILY,
                })
                .expect("installed-font smoke must not error");
            eprintln!(
                "{grapheme}: source={:?}, layers={}",
                cluster.source,
                cluster.layers.len()
            );
            assert!(cluster.has_ink(), "{grapheme} produced no visible pixels");
            match grapheme {
                "\u{e0a2}" | "\u{e0b0}" => assert!(matches!(
                    cluster.source,
                    GlyphSource::BundledBase | GlyphSource::BundledSymbols
                )),
                _ => assert!(matches!(cluster.source, GlyphSource::SystemFallback { .. })),
            }
        }
        if let Some(elapsed) = backend.first_retry_construction {
            eprintln!("first retry FontSystem construction: {elapsed:?}");
        }
    }
}

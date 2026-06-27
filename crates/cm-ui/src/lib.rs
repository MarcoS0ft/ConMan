//! `cm-ui` — the Slint user interface for ConMan.
//!
//! Hosts the Slint UI definitions and the controllers/view-models that
//! translate between the core's ports and the widgets. Receives ready-to-draw
//! snapshots and never imports a protocol or storage library directly.

pub mod terminal_renderer;

pub use terminal_renderer::{CellMetrics, GlyphSource, Rgb, TerminalRenderer, TerminalTheme};

pub const NAME: &str = "cm-ui";

//! `cm-ui` — the Slint user interface for ConMan.
//!
//! Hosts the Slint UI definitions, the glyph-atlas terminal renderer (P2.3), and the
//! controllers/view-models that translate between the core's ports and the widgets.
//! Receives ready-to-draw snapshots and never imports a protocol or storage library
//! directly.

mod controller;
mod input;
pub mod terminal_renderer;

// The Slint-generated component types (from `ui/app.slint`). The generated code is
// machine-written and does not follow the workspace lints (it uses `unsafe`, emits
// `unreachable_pub` items, and lacks `Debug` impls), so the whole module opts out.
#[allow(
    unsafe_code,
    unreachable_pub,
    missing_debug_implementations,
    clippy::all,
    clippy::pedantic,
    clippy::nursery
)]
mod generated_ui {
    slint::include_modules!();
}
pub use generated_ui::{AppWindow, TabItem};

pub use controller::run;
pub use terminal_renderer::{CellMetrics, GlyphSource, Rgb, TerminalRenderer, TerminalTheme};

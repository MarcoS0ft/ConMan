//! `cm-ui` — the Slint user interface for ConMan.
//!
//! Hosts the Slint UI definitions, the glyph-atlas terminal renderer (P2.3),
//! and the controllers/view-models that translate between the core's ports and
//! the widgets. Receives ready-to-draw snapshots and never imports a protocol
//! or storage library directly.
//!
//! # P1.4 additions
//!
//! - [`AppConfig`] carries the repository and credential store into [`run`].
//! - [`tree`] module: `ConnectionTree` flattens groups + connections for the
//!   Connections panel.
//! - [`keys`] module: `KeysPanel` flattens credential folders + credentials
//!   for the Keys panel.

use std::sync::Arc;

use cm_core::{ConnectionRepository, CredentialStore};

mod clipboard;
mod controller;
mod input;
pub mod keys;
mod selection;
pub mod terminal_renderer;
pub mod tree;

// The Slint-generated component types (from `ui/app.slint`). The generated
// code is machine-written and does not follow the workspace lints, so the
// whole module opts out.
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

// Re-export the Slint-generated types used by the controller and by
// cm-platform or tests.  `Theme` is internal and not re-exported here;
// appearance is driven via the alias properties on `AppWindow` instead.
pub use generated_ui::{
    AppWindow, ConnRow, CredRow, KbdPromptRow, PaletteAction, RecentItem, TabItem, ToastEntry,
};

pub use controller::run;
pub use terminal_renderer::{
    CellMetrics, FontSet, GlyphSource, Rgb, TerminalRenderer, TerminalTheme,
};

/// Configuration injected by the `conman` binary at startup.
///
/// `repo` and `secrets` are held as `Arc<dyn Trait>` so the controller can
/// share them across closures without lifetime issues.  The binary creates the
/// concrete adapters (`SqliteRepository`, `KeyringStore`) and boxes them here.
pub struct AppConfig {
    /// The SQLite-backed connection and credential repository.
    pub repo: Arc<dyn ConnectionRepository>,
    /// The OS-keychain credential store.
    pub secrets: Arc<dyn CredentialStore>,
    /// P6.16: receives a `()` for every activation request from a second
    /// `conman` launch (delivered by `cm_platform::single_instance`). `run`
    /// spawns a small listener thread that brings the window forward on the
    /// UI thread for each message. `None` when the composition root could not
    /// acquire the single-instance lock (see `AcquireOutcome::Unavailable`) —
    /// the app still starts, it just has no activation channel.
    ///
    /// Deliberately typed as a plain `std::sync::mpsc::Receiver` rather than a
    /// `cm-platform` type so `cm-ui` does not need a dependency on
    /// `cm-platform` for this one hook.
    pub activation_rx: Option<std::sync::mpsc::Receiver<()>>,
    /// P6.14: `true` only on the very first-ever launch (a brand-new DB that
    /// the composition root just seeded with demo data). The first launch
    /// always opens a plain local-shell tab, by established design,
    /// regardless of the "restore last session" setting or the Launchpad
    /// empty-workspace fallback (there is nothing to restore and no recents
    /// to show yet anyway). `false` for every later launch.
    pub first_launch: bool,
}

impl std::fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig").finish_non_exhaustive()
    }
}

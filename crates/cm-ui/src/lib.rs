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

use cm_core::{ConnectionRepository, CredentialStore, SessionProvider};

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
    AppWindow, ConnRow, CredRow, KbdPromptRow, PaletteAction, PaneCell, RecentItem, TabItem,
    ToastEntry,
};

pub use controller::run;
pub use terminal_renderer::{
    CellMetrics, FontSet, GlyphSource, Rgb, TerminalRenderer, TerminalTheme,
};

/// P8.6-B: what the `conman` composition root exposes to the Settings UI
/// (and, once confirmed, the execute-scope launch gate) about the agent-mode
/// scope-enforcement proxy (P8.6-A, `conman/src/agent_mode`). `cm-ui` cannot
/// depend on `conman` (the dependency points the other way — `conman` is the
/// binary crate, `cm-ui` the library it links), so this is a plain,
/// cm-ui-owned mirror of the fields `conman::agent_mode::AgentModeHandle`
/// carries, populated by `main.rs`'s composition root from its own handle.
///
/// Unconditionally defined (not `#[cfg(feature = "agent-mode")]`) so
/// `AppConfig` itself never needs conditional compilation at its call sites —
/// only the *code that acts on* `AppConfig::agent_mode` (the Settings UI
/// wiring, the indicator, the execute-gate) is feature-gated. A build without
/// the `agent-mode` feature simply never constructs a `Some(_)` here.
#[derive(Clone)]
pub struct AgentModeConfig {
    /// The user-facing (agent-connects-here) loopback port the proxy is
    /// bound to. Shown in the Settings UI's connection-details copy.
    pub external_port: u16,
    /// Live-reloadable granted scopes: the Settings UI's scope checkboxes
    /// write into this lock on every change; the proxy (running on its own
    /// thread in `conman`) reads it on every `tools/call` it gates. Shared,
    /// not owned -- this is the exact `Arc` the proxy thread already holds.
    pub scopes: Arc<std::sync::RwLock<cm_core::ScopeSet>>,
    /// The execute-scope launch gate's signal (P8.6-B item 4): a count, not
    /// a bool, of agent-driven **write**-tool calls (`click_element`/
    /// `invoke_accessibility_action`/`dispatch_key_event`) currently in
    /// flight through the proxy. A plain bool would race under concurrent
    /// agent connections -- each accepted connection gets its own proxy
    /// thread, so two overlapping write-tool calls could have one clear the
    /// flag while the other is still in flight, opening a window where its
    /// own triggered click wouldn't be marked. `> 0` means "an agent write
    /// interaction is in progress right now" -- see
    /// [`AgentModeConfig::mcp_interaction_active`].
    ///
    /// Verified (not assumed) that the window this counts actually covers
    /// the launch callback: the vendored Slint MCP server's `click_element`/
    /// etc. handlers run on Slint's own single-threaded event loop and
    /// dispatch the pointer/key event *synchronously* (inline, before their
    /// async handler returns) -- the callback a launch button would fire is
    /// guaranteed to complete before the proxy's blocking `forward()` call
    /// (which brackets the increment/decrement) returns.
    pub mcp_interaction_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl AgentModeConfig {
    /// True while at least one agent-driven write-tool call is in flight.
    /// The execute-scope launch gate refuses a launch when this is true AND
    /// `execute` isn't granted -- see `sessions::agent_mode_execute_blocked`.
    ///
    /// Fail-safe, not fail-open: this can spuriously refuse a **human**
    /// launch that happens to land in the (short, ~tens-of-milliseconds)
    /// window while an unrelated agent write-tool call is in flight --
    /// over-restricting, never under-restricting. Accepted trade-off for
    /// v1 (documented in the P8.6 delivery memo) -- distinguishing human
    /// from agent-injected input within the window would need event
    /// tagging inside Slint itself, out of scope here.
    pub fn mcp_interaction_active(&self) -> bool {
        self.mcp_interaction_count
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0
    }
}

impl std::fmt::Debug for AgentModeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentModeConfig")
            .field("external_port", &self.external_port)
            .finish_non_exhaustive()
    }
}

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
    /// P6.15 (gap 27): establishes live sessions for local/SSH/RDP tabs. The
    /// controller calls this port instead of naming the concrete
    /// `cm_session::{LocalTerminalSession, SshTerminalSession, RdpSession}`
    /// adapters directly — the binary builds `cm_session::
    /// SessionProviderImpl` and injects it here, mirroring `repo`/`secrets`.
    pub session_provider: Arc<dyn SessionProvider>,
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
    /// P8.6-B: `Some(_)` only when `conman` was built with the `agent-mode`
    /// feature AND the user has `automation.enabled` on (the proxy is
    /// actually listening). `None` -- agent-mode off, or not compiled in --
    /// is the default/common case; see [`AgentModeConfig`]'s doc comment for
    /// why this field itself is never behind a `cfg`.
    pub agent_mode: Option<AgentModeConfig>,
}

impl std::fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// P8.2 — in-process element-test harness (dev/test-only public surface)
// ---------------------------------------------------------------------------

/// A hermetically-constructed, non-event-loop-driven `AppWindow` from
/// [`build_for_test`], plus everything that must stay alive for as long as
/// the caller wants the wired callbacks/timers to keep working (the redraw
/// timer, the resize-debounce timer, every Slint list-model handle the
/// controller closed over, ...). That "everything else" is intentionally
/// opaque -- callers only ever need `ui` (to drive/introspect the element
/// tree); the rest exists purely to not be dropped.
///
/// Dropping a `TestHarness` tears the whole wired app down (timers stop,
/// callbacks' captured `Rc`/`Arc` handles release) -- keep it alive for the
/// duration of a test scenario, same as the real `run()` keeps its `Ctx`
/// alive for the duration of the event loop.
#[cfg(any(test, feature = "ui-introspection"))]
pub struct TestHarness {
    /// The live, wired `AppWindow`. Query/drive it with
    /// `i_slint_backend_testing::ElementHandle`/`ElementRoot` the same way
    /// you would the real app's window.
    pub ui: AppWindow,
    _keepalive: Box<dyn std::any::Any>,
}

#[cfg(any(test, feature = "ui-introspection"))]
impl std::fmt::Debug for TestHarness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestHarness").finish_non_exhaustive()
    }
}

/// P8.2 construction seam: builds the real `AppWindow` + controller wiring
/// in-process -- the same model setup and `wire_*()` registration [`run`]
/// does -- without entering the event loop, given already-constructed test
/// doubles in `config` (an in-memory `SqliteRepository`, a mock/loopback
/// `SessionProvider`, `activation_rx: None`). Does not change `run`'s public
/// signature or behavior; this is an additional, test-facing entry point.
///
/// Callers must first initialize `i-slint-backend-testing`'s simulated
/// backend (`i_slint_backend_testing::init_no_event_loop()` for widget-only
/// checks, or `init_integration_test_with_mock_time()` — **once per process**
/// — for anything that needs the redraw timer / mock time to advance). See
/// `crates/cm-ui/tests/` and `docs/devel/tasks/P8.2-element-test-harness.md`.
///
/// # Panics
/// Panics if the underlying `AppWindow::new()` fails (see
/// [`controller::build_for_test`]'s panic doc) -- acceptable for a test-only
/// entry point; a failed harness construction should abort that test loudly.
#[cfg(any(test, feature = "ui-introspection"))]
pub fn build_for_test(config: AppConfig) -> TestHarness {
    let (ui, ctx, redraw) = controller::build_for_test(config);
    TestHarness {
        ui,
        _keepalive: Box::new((ctx, redraw)),
    }
}

//! UI-thread controller: owns per-tab sessions (local or SSH) + renderers + the
//! redraw timer, wires Slint callbacks, and drives the snapshot->render->Image pipeline.
//!
//! P1.4 upgrade: the controller now accepts [`AppConfig`] carrying the repository
//! (P1.1) and credential store (P1.3).  It wires the Connections panel and Keys
//! panel to real persisted data and handles all CRUD operations.
//!
//! Threading (ARCHITECTURE §4 / P0.3):
//! - Sessions run their byte-pump on dedicated threads.
//! - The controller lives entirely on the UI thread.
//! - A `slint::Timer` coalesces snapshots, renders the active tab.
//! - Repository calls are synchronous (SQLite; fast enough for UI responses).
//!
//! P6.1: split from a single 4,525-line `controller.rs` god-module into this
//! `controller/` tree — one file per feature area, each registering its Slint
//! callbacks via a `wire_*(ctx: &Ctx)` function called from [`run`]. Pure code
//! move: no behavior change. See `docs/devel/tasks/P6.1-controller-decomposition.md`.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cm_core::terminal::{GridSnapshot, TerminalSize};
use cm_core::{LocalSettings, SshSettings};
use cm_session::{CertDecision, HostKeyDecision, PaneGroup, Session, SshAuthInput};
use cm_storage::SettingsService;
use slint::{ComponentHandle, Image, ModelRc, Timer, VecModel};

use crate::keys::KeysPanel;
use crate::terminal_renderer::{FontSet, TerminalRenderer, TerminalTheme};
use crate::tree::ConnectionTree;
use crate::{AppConfig, AppWindow, ConnRow, CredRow, PaletteAction, TabItem, ToastEntry};

mod util;

mod keys_ctl;
mod overlays;
mod palette;
mod panes;
#[cfg(feature = "qa-harness")]
mod qa_harness;
mod sessions;
mod settings_ctl;
mod tabs;
mod tree_ctl;

/// Default logical font size used in unit tests (matches `AppSettings::default().font_size`).
#[cfg(test)]
const FONT_SIZE_PX: f32 = 15.0;
/// Redraw cadence (~60 Hz) for coalescing snapshots.
const REDRAW_INTERVAL: Duration = Duration::from_millis(16);
/// Debounce window for committing a resize to the PTY/engine.
const RESIZE_DEBOUNCE: Duration = Duration::from_millis(90);
/// Initial grid size before the surface reports its real dimensions.
const INITIAL_SIZE: TerminalSize = TerminalSize { rows: 24, cols: 80 };

struct SshConnectInfo {
    settings: SshSettings,
    auth: SshAuthInput,
}

/// State for an additional (non-primary) pane within a split tab.
struct ExtraPaneState {
    session: Box<dyn Session>,
    renderer: TerminalRenderer,
    last: Option<GridSnapshot>,
    cols: u16,
    rows: u16,
    scale: f32,
    /// Logical width reported by the last `pane-resized` event for this pane.
    surface_w: f32,
    /// Logical height reported by the last `pane-resized` event for this pane.
    surface_h: f32,
}

/// A session that has been detached from its tab but is still running.
///
/// The tick loop drains the session's output channel to prevent it from
/// filling; `shutdown` is called when the session exits naturally.
struct DetachedEntry {
    session: Box<dyn Session>,
    label: String,
}

struct Tab {
    session: Box<dyn Session>,
    // Terminal tabs:
    renderer: TerminalRenderer,
    last: Option<GridSnapshot>,
    cols: u16,
    rows: u16,
    // RDP tabs (0 / None when terminal):
    last_frame: Option<Image>,
    rdp_w: u16,
    rdp_h: u16,
    /// RDP text clipboard slot: the drive thread writes remote-copied text here;
    /// the tick loop polls it and writes to the OS clipboard (remote→local sync).
    rdp_clipboard: Option<Arc<Mutex<Option<String>>>>,
    // Common:
    scale: f32,
    num: u32,
    /// Present for remote sessions (SSH + RDP) — enables error overlay + SSH reconnect.
    connect_info: Option<SshConnectInfo>,
    /// True for any remote session (SSH or RDP) — drives the error overlay.
    is_remote: bool,
    /// The stored connection profile this tab was launched from (tree-launched
    /// SSH/RDP), if any. `None` for quick-connect and local-shell tabs, which
    /// have no profile to edit. Drives the ErrorOverlay "Edit…" button (P6.9
    /// gap 16): with an id, it opens that profile's editor; without one, it
    /// falls back to quick-connect (the only thing there ever was to edit).
    origin_connection_id: Option<i32>,
    // P5.1: Split-pane support.
    /// Pane layout and focus tracking.
    pane_group: PaneGroup,
    /// Extra panes (beyond the primary pane 0 held in `session`).
    extra_panes: Vec<ExtraPaneState>,
}

struct State {
    tabs: Vec<Tab>,
    active: usize,
    fonts: Arc<FontSet>,
    scale: f32,
    surface_w: f32,
    surface_h: f32,
    conn_tree: ConnectionTree,
    keys_panel: KeysPanel,
    /// OS clipboard handle for RDP CLIPRDR bidirectional sync.
    /// Created lazily on first use; `None` if arboard fails (e.g. no display).
    sys_clipboard: Option<arboard::Clipboard>,
    // P5.1: Detached sessions (still running; drained in tick).
    detached: Vec<DetachedEntry>,
    // P5.2: Persisted terminal font size (logical px), updated live from Settings.
    font_size_px: f32,
    // P5.2: Persisted default local-shell settings, updated live from Settings.
    local_settings: LocalSettings,
    // P5.3b: Current filter text for the connection tree and keys tree.
    conn_filter: String,
    cred_filter: String,
}

impl State {
    fn current_grid(&self) -> TerminalSize {
        if self.surface_w <= 0.0 || self.surface_h <= 0.0 {
            return INITIAL_SIZE;
        }
        let probe = TerminalRenderer::with_fonts(
            self.fonts.clone(),
            self.font_size_px,
            self.scale,
            TerminalTheme::dark(),
        );
        util::grid_for(&probe, self.surface_w, self.surface_h, self.scale)
    }

    fn target_px(&self) -> Option<(u32, u32)> {
        if self.surface_w > 0.0 && self.surface_h > 0.0 {
            Some((
                (self.surface_w * self.scale).round().max(1.0) as u32,
                (self.surface_h * self.scale).round().max(1.0) as u32,
            ))
        } else {
            None
        }
    }
}

/// Per-connection reply queue for the host-key dialog.
///
/// Changed from `Option<Sender>` to `VecDeque<Sender>` (carry-over fix a):
/// concurrent SSH connects each push their own sender; accept/reject pops the
/// front, so no sender is ever clobbered by a subsequent connection.
type HkQueue = Arc<Mutex<std::collections::VecDeque<Sender<HostKeyDecision>>>>;

/// Bundles the handles every `wire_*` setup function needs: the live
/// `AppWindow`, shared `State`, the Slint list models, the storage/secrets
/// adapters, and the pending-decision queues for the host-key/cert dialogs.
///
/// Built once in [`run`] after all models + initial state are constructed,
/// then passed by reference to each feature module's `wire_*` function. Pure
/// parameter bundling — introduced by the P6.1 controller split, no behavior
/// change (CONVENTIONS §3: internal/private, no memo required).
struct Ctx {
    ui: AppWindow,
    state: Rc<RefCell<State>>,
    tab_model: Rc<VecModel<TabItem>>,
    conn_model: Rc<VecModel<ConnRow>>,
    cred_model: Rc<VecModel<CredRow>>,
    palette_model: Rc<VecModel<PaletteAction>>,
    toast_model: Rc<VecModel<ToastEntry>>,
    toast_next_id: Rc<RefCell<i32>>,
    repo: Arc<dyn cm_core::ConnectionRepository>,
    secrets: Arc<dyn cm_core::CredentialStore>,
    hk_pending: HkQueue,
    cert_pending: Arc<Mutex<Option<Sender<CertDecision>>>>,
    resize_debounce: Rc<Timer>,
}

/// Build and run the ConMan application.
///
/// # Errors
/// Returns a [`slint::PlatformError`] if the window/backend cannot be created.
pub fn run(config: AppConfig) -> Result<(), slint::PlatformError> {
    let repo = config.repo;
    let secrets = config.secrets;
    let activation_rx = config.activation_rx;

    let ui = AppWindow::new()?;
    let scale = ui.window().scale_factor();

    let tab_model: Rc<VecModel<TabItem>> = Rc::new(VecModel::default());
    ui.set_tabs(ModelRc::from(tab_model.clone()));

    let conn_model: Rc<VecModel<ConnRow>> = Rc::new(VecModel::default());
    ui.set_connections(ModelRc::from(conn_model.clone()));

    let cred_model: Rc<VecModel<CredRow>> = Rc::new(VecModel::default());
    ui.set_credentials(ModelRc::from(cred_model.clone()));

    let palette_model: Rc<VecModel<PaletteAction>> =
        Rc::new(VecModel::from(palette::initial_palette_actions()));
    ui.set_palette_actions(ModelRc::from(palette_model.clone()));

    // P5.3b: toast model.
    let toast_model: Rc<VecModel<ToastEntry>> = Rc::new(VecModel::default());
    ui.set_toasts(ModelRc::from(toast_model.clone()));
    // Toast counter -- gives each toast a unique id so we can remove it by id.
    let toast_next_id: Rc<RefCell<i32>> = Rc::new(RefCell::new(0));

    // -- Load persisted settings (P5.2) --------------------------------------
    let stored_settings = {
        let svc = SettingsService::new(repo.as_ref());
        match svc.load() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("failed to load settings: {e}");
                cm_storage::AppSettings::default()
            }
        }
    };
    settings_ctl::apply_settings_to_ui(&stored_settings, &ui);
    util::apply_early_env_overrides(&ui);

    // Load initial tree data.
    let conn_tree = match ConnectionTree::load(repo.as_ref()) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("failed to load connections: {e}");
            ConnectionTree::new(vec![], vec![])
        }
    };
    let keys_panel = match KeysPanel::load(repo.as_ref()) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("failed to load credentials: {e}");
            KeysPanel::new(vec![], vec![])
        }
    };

    let state = Rc::new(RefCell::new(State {
        tabs: Vec::new(),
        active: 0,
        fonts: FontSet::bundled(),
        scale,
        surface_w: 0.0,
        surface_h: 0.0,
        conn_tree,
        keys_panel,
        // Created lazily; silently ignored if arboard fails (e.g. no display in CI).
        sys_clipboard: arboard::Clipboard::new().ok(),
        detached: Vec::new(),
        // P5.2: persist terminal rendering font size and local shell defaults.
        font_size_px: stored_settings.font_size as f32,
        local_settings: settings_ctl::local_settings_from_app(&stored_settings),
        // P5.3b: search/filter boxes start empty.
        conn_filter: String::new(),
        cred_filter: String::new(),
    }));

    {
        let st = state.borrow();
        tree_ctl::refresh_conn_model(&st, &conn_model);
        keys_ctl::refresh_cred_model(&st, &cred_model);
        keys_ctl::refresh_cred_name_list(&st, &ui);
        tree_ctl::refresh_group_name_list(&st, &ui);
    }

    let hk_pending: HkQueue = Arc::new(Mutex::new(std::collections::VecDeque::new()));
    let cert_pending: Arc<Mutex<Option<Sender<CertDecision>>>> = Arc::new(Mutex::new(None));
    let resize_debounce = Rc::new(Timer::default());

    tabs::open_local_tab(&state, &tab_model, &ui);

    let ctx = Ctx {
        ui,
        state: state.clone(),
        tab_model: tab_model.clone(),
        conn_model: conn_model.clone(),
        cred_model: cred_model.clone(),
        palette_model: palette_model.clone(),
        toast_model: toast_model.clone(),
        toast_next_id: toast_next_id.clone(),
        repo: repo.clone(),
        secrets: secrets.clone(),
        hk_pending: hk_pending.clone(),
        cert_pending: cert_pending.clone(),
        resize_debounce: resize_debounce.clone(),
    };

    tabs::wire_tabs(&ctx);
    sessions::wire_sessions(&ctx);
    panes::wire_panes(&ctx);
    tree_ctl::wire_tree_ctl(&ctx);
    keys_ctl::wire_keys_ctl(&ctx);
    settings_ctl::wire_settings_ctl(&ctx);
    palette::wire_palette(&ctx);
    overlays::wire_overlays(&ctx);

    // -- Redraw timer ---------------------------------------------------------
    let _redraw = sessions::wire_tick(&ctx);

    // -- Optional headless test hooks -----------------------------------------
    let mut hooks: Vec<Timer> = Vec::new();
    util::wire_env_hooks(&ctx, &mut hooks);

    // -- P6.2b: in-app QA endpoint (feature-gated, off by default) ------------
    #[cfg(feature = "qa-harness")]
    qa_harness::wire_qa_harness(&ctx);

    // P6.16: single-instance activation — a second `conman` launch asked us to
    // come to the foreground. The composition root already validated the
    // handshake (see `cm_platform::single_instance`); here we just react to
    // each `()` on a background thread and hop onto the UI thread to un-
    // minimize and (re)show the window. Actually raising the window above
    // others is best-effort and OS/window-manager dependent — Slint's public
    // `Window` API has no direct "bring to front"/focus primitive, so
    // `set_minimized(false)` + `show()` is the most we can portably do.
    if let Some(rx) = activation_rx {
        let weak = ctx.ui.as_weak();
        std::thread::spawn(move || {
            while rx.recv().is_ok() {
                let weak = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = weak.upgrade() else { return };
                    let win = ui.window();
                    win.set_minimized(false);
                    let _ = win.show();
                });
            }
        });
    }

    ctx.ui.run()
}

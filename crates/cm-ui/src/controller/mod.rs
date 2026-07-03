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
use slint::{ComponentHandle, Image, ModelRc, SharedString, Timer, VecModel};

use crate::clipboard::Clipboard;
use crate::keys::KeysPanel;
use crate::selection::PaneSelectionState;
use crate::terminal_renderer::{FontSet, TerminalRenderer, TerminalTheme};
use crate::tree::ConnectionTree;
use crate::{AppConfig, AppWindow, ConnRow, CredRow, PaletteAction, TabItem, ToastEntry};

mod util;

mod import_export;
mod keys_ctl;
mod launchpad;
mod overlays;
mod palette;
mod panes;
#[cfg(feature = "qa-harness")]
mod qa_harness;
mod search;
mod sessions;
mod settings_ctl;
mod startup;
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

/// Where an SSH tab's auth material comes from, for reconnect (P6.4).
///
/// `Direct` (quick-connect / debug autoinit hooks) caches the typed
/// [`SshAuthInput`] verbatim, exactly as before P6.4 — there is no credential
/// record to re-resolve against. `Credential` (tree-launched, stored-credential
/// connections) caches only the [`cm_core::ConnectionId`]: a reconnect re-runs
/// [`sessions::resolve_ssh_auth`] against the live credential store, so the
/// fetched secret never lingers in `Tab` state longer than one connect attempt
/// (spec: "a reconnect re-fetches rather than caching plaintext").
enum SshAuthSource {
    Direct(SshAuthInput),
    Credential(cm_core::ConnectionId),
}

/// How the caller obtained the `SshAuthInput` passed to [`sessions::open_ssh_tab`]
/// / [`sessions::reconnect_ssh_tab`] — mirrors [`SshAuthSource`] but without an
/// already-resolved `SshAuthInput` payload (the caller still owns that, since it
/// is about to move it into `SshTerminalSession::connect`).
#[derive(Clone, Copy)]
enum AuthProvenance {
    Direct,
    Credential(cm_core::ConnectionId),
}

struct SshConnectInfo {
    settings: SshSettings,
    auth_source: SshAuthSource,
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
    /// P6.5: mouse-drag text selection + multi-click state for this pane.
    sel: PaneSelectionState,
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
    /// P6.5: mouse-drag text selection + multi-click state for the primary pane
    /// (pane 0). Extra panes carry their own in [`ExtraPaneState::sel`].
    sel: PaneSelectionState,
    /// P6.5 lifecycle: the pane index (`PaneGroup::focused()`) observed on the
    /// last tick, so a focus change (Ctrl+Shift+arrow, clicking another pane)
    /// can be detected reactively and clear every pane's stale selection —
    /// see `selection lifecycle` in `docs/devel/tasks/
    /// P6.5-terminal-selection-copy-paste.md`.
    last_focused_pane: usize,
    /// P6.14 (gap 3): `true` for the Launchpad-fronted "home" tab -- a plain
    /// local shell underneath, shown instead of a bare terminal until the
    /// user picks something from the Launchpad. Set on the tab opened for a
    /// non-first-launch empty workspace and for a tab created by closing the
    /// last real tab ("explicitly emptied"); `false` for every real session
    /// tab (never persisted into the restore-last-session snapshot -- see
    /// `startup::persist_session_tabs`).
    is_empty: bool,
    /// P6.7: whole-buffer search overlay state, targeting this tab's primary
    /// pane (`session`) — see `search.rs`'s module doc for the scoping note.
    search: search::SearchState,
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
    /// Shared OS clipboard handle (P6.5: factored out of the RDP-only P4.2
    /// field — used for both RDP CLIPRDR sync and terminal copy/paste). Fails
    /// soft internally if no clipboard is available (e.g. no display).
    sys_clipboard: Clipboard,
    // P5.1: Detached sessions (still running; drained in tick).
    detached: Vec<DetachedEntry>,
    /// P6.5 lifecycle: the active tab index observed on the last tick, so a
    /// tab switch can be detected reactively and clear the outgoing/incoming
    /// tab's stale terminal selection (see `Tab::last_focused_pane` for the
    /// pane-level counterpart).
    last_active_tab: usize,
    // P5.2: Persisted terminal font size (logical px), updated live from Settings.
    font_size_px: f32,
    // P5.2: Persisted default local-shell settings, updated live from Settings.
    local_settings: LocalSettings,
    // P5.3b: Current filter text for the connection tree and keys tree.
    conn_filter: String,
    cred_filter: String,
    // P6.6: repo/secrets + the Slint list-model handles the Import/Export
    // palette actions need. Carried on `State` (not threaded through
    // `dispatch_palette_action`'s parameters) so the QA harness's narrower
    // handle set and the keyboard-dispatch path in `sessions.rs` — both
    // outside this lane this wave — don't need to change. See
    // `import_export.rs`.
    io: import_export::ImportExportHandles,
    /// P6.14: the Slint list-model backing `launchpad-recents`. Lives on
    /// `State` (like `io` above) so both the tab-lifecycle code that shows
    /// the Launchpad (`tabs::open_local_tab_inner`) and the Launchpad's own
    /// callbacks (`launchpad.rs`) can refresh it without widening every
    /// intermediate function signature.
    launchpad_recents_model: Rc<VecModel<crate::RecentItem>>,
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

/// Per-connection reply queue for the keyboard-interactive dialog (P6.13),
/// modeled on [`HkQueue`]: each pending challenge round pushes its own
/// sender; submit/cancel pops the front so no sender is ever clobbered by a
/// subsequent round or connection. `None` means the user cancelled the
/// prompt (aborts that auth attempt); `Some(answers)` carries one [`Secret`]
/// per prompt, in order.
type KbdQueue = Arc<Mutex<std::collections::VecDeque<Sender<Option<Vec<cm_core::Secret>>>>>>;

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
    kbd_pending: KbdQueue,
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
    let first_launch = config.first_launch;

    let ui = AppWindow::new()?;
    let scale = ui.window().scale_factor();

    // P6.8 (gap 10): push the real OS accent into `Theme.os-accent-color` before any
    // persisted settings are applied, so a persisted "OS accent" selection resolves to
    // a live color immediately rather than the compiled-in Slint default.
    util::push_os_accent(&ui, cm_platform::accent::os_accent());

    let tab_model: Rc<VecModel<TabItem>> = Rc::new(VecModel::default());
    ui.set_tabs(ModelRc::from(tab_model.clone()));

    let conn_model: Rc<VecModel<ConnRow>> = Rc::new(VecModel::default());
    ui.set_connections(ModelRc::from(conn_model.clone()));

    let cred_model: Rc<VecModel<CredRow>> = Rc::new(VecModel::default());
    ui.set_credentials(ModelRc::from(cred_model.clone()));

    let palette_model: Rc<VecModel<PaletteAction>> =
        Rc::new(VecModel::from(palette::initial_palette_actions()));
    ui.set_palette_actions(ModelRc::from(palette_model.clone()));

    // P6.14: the Launchpad's recents list.
    let launchpad_recents_model: Rc<VecModel<crate::RecentItem>> = Rc::new(VecModel::default());
    ui.set_launchpad_recents(ModelRc::from(launchpad_recents_model.clone()));
    ui.set_launchpad_greeting(SharedString::from(launchpad::current_greeting()));

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
        // Created lazily; fails soft if arboard has no clipboard (e.g. no display in CI).
        sys_clipboard: Clipboard::new(),
        detached: Vec::new(),
        last_active_tab: 0,
        // P5.2: persist terminal rendering font size and local shell defaults.
        font_size_px: stored_settings.font_size as f32,
        local_settings: settings_ctl::local_settings_from_app(&stored_settings),
        // P5.3b: search/filter boxes start empty.
        conn_filter: String::new(),
        cred_filter: String::new(),
        // P6.6: see the `io` field doc comment.
        io: import_export::ImportExportHandles {
            repo: repo.clone(),
            secrets: secrets.clone(),
            conn_model: conn_model.clone(),
            cred_model: cred_model.clone(),
            toast_model: toast_model.clone(),
            toast_next_id: toast_next_id.clone(),
        },
        // P6.14: see the field doc comment.
        launchpad_recents_model: launchpad_recents_model.clone(),
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
    let kbd_pending: KbdQueue = Arc::new(Mutex::new(std::collections::VecDeque::new()));
    let resize_debounce = Rc::new(Timer::default());

    // -- Initial tab(s) (P6.14: gap 3 empty/launchpad home + gap 4 restore) --
    // The very first-ever launch always opens a plain local shell (nothing to
    // restore, no recents yet) -- established design, unchanged. Otherwise,
    // "restore last session" (when enabled and there is something to
    // restore) takes priority; that needs `ctx` (the credentialed connect
    // path), so it runs just below, after `ctx` exists. A clean start, or a
    // restore attempt with nothing usable to restore, lands on the
    // Launchpad-fronted empty/home tab instead of blindly opening a shell.
    let restore_snapshot = if first_launch {
        None
    } else if stored_settings.startup_behavior == 1 {
        match SettingsService::new(repo.as_ref()).load_session_tabs() {
            Ok(snap) => snap,
            Err(e) => {
                tracing::warn!("failed to load session-tab snapshot: {e}");
                None
            }
        }
    } else {
        None
    };

    if first_launch {
        tabs::open_local_tab(&state, &tab_model, &ui);
    } else if restore_snapshot.is_none() {
        tabs::open_empty_tab(&state, &tab_model, &ui);
    }
    // else: restored below once `ctx` exists.

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
        kbd_pending: kbd_pending.clone(),
        resize_debounce: resize_debounce.clone(),
    };

    tabs::wire_tabs(&ctx);
    sessions::wire_sessions(&ctx);
    search::wire_search(&ctx);
    panes::wire_panes(&ctx);
    tree_ctl::wire_tree_ctl(&ctx);
    keys_ctl::wire_keys_ctl(&ctx);
    settings_ctl::wire_settings_ctl(&ctx);
    palette::wire_palette(&ctx);
    overlays::wire_overlays(&ctx);
    launchpad::wire_launchpad(&ctx);

    // -- Redraw timer ---------------------------------------------------------
    let _redraw = sessions::wire_tick(&ctx);

    if let Some(snap) = restore_snapshot {
        startup::restore_session_tabs(&ctx, snap);
    }

    // -- Optional headless test hooks -----------------------------------------
    let mut hooks: Vec<Timer> = Vec::new();
    util::wire_env_hooks(&ctx, &mut hooks);

    // -- P6.2b: in-app QA endpoint (feature-gated, off by default) ------------
    #[cfg(feature = "qa-harness")]
    qa_harness::wire_qa_harness(&ctx);

    // P6.8 (gap 10): best-effort live OS accent-change watch. `watch_os_accent`
    // is a no-op (returns `false`, spawns nothing) on platforms/desktops with no
    // such signal (Windows in this pass, Linux without a portal) -- `os_accent()`
    // above already covered the startup value for those.
    {
        let weak = ctx.ui.as_weak();
        cm_platform::accent::watch_os_accent(move |color| {
            let weak = weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    util::push_os_accent(&ui, color);
                }
            });
        });
    }

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

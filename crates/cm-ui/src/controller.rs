//! UI-thread controller: owns per-tab sessions (local or SSH) + renderers + the
//! redraw timer, wires Slint callbacks, and drives the snapshot→render→Image pipeline.
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

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cm_core::terminal::{GridSnapshot, Key, KeyEvent, KeyModifiers, TerminalSize};
use cm_core::{
    Connection, ConnectionId, ConnectionKind, ConnectionSettings, Credential, CredentialFolder,
    CredentialFolderId, CredentialId, CredentialKind, CredentialPurpose, CredentialRef, Group,
    GroupId, LocalSettings, RdpSettings, Secret, SshAuthMethod, SshSettings,
};
use cm_session::{
    CertDecision, CertInfo, CertStore, CertVerifier, FailedSession, FrameUpdate, HostKeyDecision,
    HostKeyInfo, HostKeyVerifier, KnownHosts, LocalTerminalSession, PaneGroup, PaneLayout,
    RdpAuthInput, RdpSession, Session, SessionInput, SessionStatus, SshAuthInput,
    SshTerminalSession, Surface,
};
use cm_storage::SettingsService;
use slint::{ComponentHandle, Image, Model, ModelRc, SharedString, Timer, TimerMode, VecModel};

use crate::input;
use crate::keys::KeysPanel;
use crate::terminal_renderer::{FontSet, TerminalRenderer, TerminalTheme};
use crate::tree::{ConnectionTree, build_cred_name_list, cred_name_idx};
use crate::{AppConfig, AppWindow, ConnRow, CredRow, PaletteAction, TabItem, ToastEntry};

// Generated Slint structs for the form editors.
use crate::generated_ui::{ConnProfile, CredFormData, GroupForm};

/// Default logical font size used in unit tests (matches `AppSettings::default().font_size`).
#[cfg(test)]
const FONT_SIZE_PX: f32 = 15.0;
/// Redraw cadence (~60 Hz) for coalescing snapshots.
const REDRAW_INTERVAL: Duration = Duration::from_millis(16);
/// Debounce window for committing a resize to the PTY/engine.
const RESIZE_DEBOUNCE: Duration = Duration::from_millis(90);
/// Initial grid size before the surface reports its real dimensions.
const INITIAL_SIZE: TerminalSize = TerminalSize { rows: 24, cols: 80 };

// ---------------------------------------------------------------------------
// SSH connect info (held for reconnect)
// ---------------------------------------------------------------------------

struct SshConnectInfo {
    settings: SshSettings,
    auth: SshAuthInput,
}

// ---------------------------------------------------------------------------
// P5.1: Extra pane state (pane index 1+)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// P5.1: Detached session entry
// ---------------------------------------------------------------------------

/// A session that has been detached from its tab but is still running.
///
/// The tick loop drains the session's output channel to prevent it from
/// filling; `shutdown` is called when the session exits naturally.
struct DetachedEntry {
    session: Box<dyn Session>,
    label: String,
}

// ---------------------------------------------------------------------------
// Per-tab state
// ---------------------------------------------------------------------------

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
    // P5.1: Split-pane support.
    /// Pane layout and focus tracking.
    pane_group: PaneGroup,
    /// Extra panes (beyond the primary pane 0 held in `session`).
    extra_panes: Vec<ExtraPaneState>,
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

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
        grid_for(&probe, self.surface_w, self.surface_h, self.scale)
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

// ---------------------------------------------------------------------------
// UiHostKeyVerifier
// ---------------------------------------------------------------------------

/// Per-connection reply queue for the host-key dialog.
///
/// Changed from `Option<Sender>` to `VecDeque<Sender>` (carry-over fix a):
/// concurrent SSH connects each push their own sender; accept/reject pops the
/// front, so no sender is ever clobbered by a subsequent connection.
type HkQueue = Arc<Mutex<std::collections::VecDeque<Sender<HostKeyDecision>>>>;

struct UiHostKeyVerifier {
    weak_ui: slint::Weak<AppWindow>,
    pending: HkQueue,
    auto_accept: bool,
}

impl HostKeyVerifier for UiHostKeyVerifier {
    fn decide(&self, info: &HostKeyInfo) -> HostKeyDecision {
        if self.auto_accept {
            return HostKeyDecision::Accept;
        }
        let (tx, rx) = std::sync::mpsc::channel::<HostKeyDecision>();
        if let Ok(mut q) = self.pending.lock() {
            q.push_back(tx);
        }
        let info = info.clone();
        let weak = self.weak_ui.clone();
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = weak.upgrade() else { return };
            let mismatch = matches!(
                info.situation,
                cm_session::HostKeySituation::Mismatch { .. }
            );
            let stored_fp = if let cm_session::HostKeySituation::Mismatch {
                ref stored_fingerprint,
                ..
            } = info.situation
            {
                stored_fingerprint.clone()
            } else {
                String::new()
            };
            ui.set_host_key_mismatch(mismatch);
            ui.set_host_key_host(format!("{}:{}", info.host, info.port).into());
            ui.set_host_key_type(info.algorithm.clone().into());
            ui.set_host_key_fingerprint(info.fingerprint.clone().into());
            ui.set_host_key_stored_fp(stored_fp.into());
            ui.set_host_key_open(true);
        });
        rx.recv().unwrap_or(HostKeyDecision::Reject)
    }
}

// ---------------------------------------------------------------------------
// UiCertVerifier (P4.2)
// ---------------------------------------------------------------------------

/// Shows the cert-accept dialog (P4.2 slint UI) and blocks the RDP connection
/// thread until the user accepts or rejects.
///
/// When `auto_accept` is `true` (set via `CONMAN_RDP_AUTO_ACCEPT_CERTS=1`) the
/// verifier immediately returns `AcceptAndRemember` without showing the dialog —
/// useful for headless CI / screenshot tests.
struct UiCertVerifier {
    weak_ui: slint::Weak<AppWindow>,
    pending: Arc<Mutex<Option<Sender<CertDecision>>>>,
    auto_accept: bool,
}

impl CertVerifier for UiCertVerifier {
    fn decide(&self, info: &CertInfo) -> CertDecision {
        if self.auto_accept {
            return CertDecision::AcceptAndRemember;
        }
        let (tx, rx) = std::sync::mpsc::channel::<CertDecision>();
        if let Ok(mut p) = self.pending.lock() {
            *p = Some(tx);
        }
        let info = info.clone();
        let weak = self.weak_ui.clone();
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = weak.upgrade() else { return };
            let mismatch = matches!(info.situation, cm_session::CertSituation::Mismatch { .. });
            let stored_fp = if let cm_session::CertSituation::Mismatch {
                ref stored_fingerprint,
                ..
            } = info.situation
            {
                stored_fingerprint.clone()
            } else {
                String::new()
            };
            ui.set_cert_dialog_mismatch(mismatch);
            ui.set_cert_dialog_host(format!("{}:{}", info.host, info.port).into());
            ui.set_cert_dialog_subject(info.subject.clone().into());
            ui.set_cert_dialog_fingerprint(info.fingerprint.clone().into());
            ui.set_cert_dialog_stored_fp(stored_fp.into());
            ui.set_cert_dialog_open(true);
        });
        rx.recv().unwrap_or(CertDecision::Reject)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn render_frame(tab: &mut Tab, snap: &GridSnapshot, target: Option<(u32, u32)>) -> Image {
    let buf = match target {
        Some((w, h)) => tab.renderer.render_to(snap, w, h),
        None => tab.renderer.render(snap),
    };
    Image::from_rgba8(buf)
}

fn lowest_free_number(used: &[u32]) -> u32 {
    let mut n = 1;
    while used.contains(&n) {
        n += 1;
    }
    n
}

fn grid_for(r: &TerminalRenderer, logical_w: f32, logical_h: f32, scale: f32) -> TerminalSize {
    let m = r.cell_metrics();
    let phys_w = (logical_w * scale).max(1.0) as u32;
    let phys_h = (logical_h * scale).max(1.0) as u32;
    TerminalSize {
        cols: (phys_w / m.cell_w).max(1) as u16,
        rows: (phys_h / m.cell_h).max(1) as u16,
    }
}

pub(crate) fn drain_latest<T>(rx: &Receiver<T>) -> Option<T> {
    let mut latest = None;
    while let Ok(v) = rx.try_recv() {
        latest = Some(v);
    }
    latest
}

fn trace(args: std::fmt::Arguments) {
    if std::env::var_os("CONMAN_TRACE").is_some() {
        eprintln!("[conman] {args}");
    }
}

// ---------------------------------------------------------------------------
// Settings application helper (P5.2)
// ---------------------------------------------------------------------------

/// Build a [`LocalSettings`] from the persisted [`cm_storage::AppSettings`].
///
/// `shell_path` empty → `None` (OS default shell).
/// `shell_args` non-empty → split on whitespace and pass as a vec.
/// `shell_cwd` empty → `None` (home directory default).
fn local_settings_from_app(s: &cm_storage::AppSettings) -> LocalSettings {
    LocalSettings {
        program: if s.shell_path.is_empty() {
            None
        } else {
            Some(s.shell_path.clone())
        },
        args: if s.shell_args.is_empty() {
            Vec::new()
        } else {
            s.shell_args.split_whitespace().map(String::from).collect()
        },
        working_dir: if s.shell_cwd.is_empty() {
            None
        } else {
            Some(s.shell_cwd.clone())
        },
        env: Vec::new(),
    }
}

/// Push all persisted settings into the live UI globals.
///
/// Called once at startup after `AppWindow` is created.  `Theme.density` and
/// `Theme.dark-mode` are in-out globals in Slint; the aliases on `AppWindow`
/// (`density`, `dark-mode`) are bidirectional bindings, so writing them here
/// updates the Theme global immediately.
///
/// NOTE (P1.5): In the current binary the repository is in-memory, so none of
/// these values survive process restart.  End-to-end persistence will be
/// observable once the disk-backed repository lands in P1.5.
fn apply_settings_to_ui(s: &cm_storage::AppSettings, ui: &AppWindow) {
    ui.set_theme_mode(s.theme_mode);
    ui.set_density(s.density);
    ui.set_accent_index(s.accent_index);
    ui.set_settings_font_size(s.font_size);
    ui.set_settings_shell_path(s.shell_path.as_str().into());
    ui.set_settings_shell_args(s.shell_args.as_str().into());
    ui.set_settings_shell_cwd(s.shell_cwd.as_str().into());
    ui.set_startup_behavior(s.startup_behavior);
    ui.set_active_panel(s.active_panel);
    ui.set_sidebar_collapsed(s.sidebar_collapsed);

    // Apply theme-mode to the live Theme.dark-mode token (system is already the
    // default; dark/light need an explicit override).
    match s.theme_mode {
        0 => ui.set_dark_mode(true),
        1 => ui.set_dark_mode(false),
        _ => {} // 2 (system): leave Theme.dark-mode at its Palette-derived default
    }

    // Restore persisted accent color.  `apply-accent-index` is implemented in
    // Slint as `Theme.accent = Theme.accent-presets[idx]`, so invoking it here
    // ensures the correct color is live immediately, not just the swatch index.
    ui.invoke_apply_accent_index(s.accent_index);
}

// ---------------------------------------------------------------------------
// Panel model refresh helpers
// ---------------------------------------------------------------------------

fn refresh_conn_model(state: &State, conn_model: &Rc<VecModel<ConnRow>>) {
    let flat = state.conn_tree.flat_filtered(&state.conn_filter);
    while conn_model.row_count() > 0 {
        conn_model.remove(0);
    }
    for row in flat {
        conn_model.push(row);
    }
}

fn refresh_cred_model(state: &State, cred_model: &Rc<VecModel<CredRow>>) {
    let flat = state.keys_panel.flat_filtered(&state.cred_filter);
    while cred_model.row_count() > 0 {
        cred_model.remove(0);
    }
    for row in flat {
        cred_model.push(row);
    }
}

fn refresh_cred_name_list(state: &State, ui: &AppWindow) {
    let list = build_cred_name_list(
        state.keys_panel.credentials(),
        state.keys_panel.folders(),
        "Inherit from group",
    );
    let model: Rc<VecModel<SharedString>> = Rc::new(VecModel::from(list));
    ui.set_cred_name_list(ModelRc::from(model));

    let folder_list = KeysPanel::build_folder_name_list(state.keys_panel.folders());
    let fm: Rc<VecModel<SharedString>> = Rc::new(VecModel::from(folder_list));
    ui.set_folder_name_list(ModelRc::from(fm));
}

/// Build the flat group name list for the group/parent pickers in editors.
///
/// Index 0 = "Root (no group)"; subsequent entries are group names in
/// `(sort, id)` order — matching [`ConnectionTree::flat`]'s root iteration.
fn build_group_name_list(groups: &[Group]) -> Vec<SharedString> {
    let mut out = vec![SharedString::from("Root (no group)")];
    let mut sorted: Vec<&Group> = groups.iter().collect();
    sorted.sort_by_key(|g| (g.sort, g.id.get()));
    for g in sorted {
        out.push(SharedString::from(g.name.as_str()));
    }
    out
}

/// Rebuild and push the group name list to the UI.
fn refresh_group_name_list(state: &State, ui: &AppWindow) {
    let list = build_group_name_list(state.conn_tree.groups());
    let model: Rc<VecModel<SharedString>> = Rc::new(VecModel::from(list));
    ui.set_group_name_list(ModelRc::from(model));
}

/// Map a 1-based dropdown index back to the corresponding [`GroupId`].
///
/// Index 0 (the "Root" sentinel) returns `None`.  An out-of-bounds index also
/// returns `None` (safe degradation to root).
fn group_id_from_name_idx(idx: i32, groups: &[Group]) -> Option<GroupId> {
    if idx <= 0 {
        return None;
    }
    let mut sorted: Vec<&Group> = groups.iter().collect();
    sorted.sort_by_key(|g| (g.sort, g.id.get()));
    sorted.get((idx - 1) as usize).map(|g| g.id)
}

/// Find the 1-based dropdown index for a given [`GroupId`] in the name list.
///
/// Returns 0 (the "Root" sentinel) when `group_id` is `None` or not found.
fn group_name_idx(group_id: Option<GroupId>, groups: &[Group]) -> i32 {
    let Some(gid) = group_id else { return 0 };
    let mut sorted: Vec<&Group> = groups.iter().collect();
    sorted.sort_by_key(|g| (g.sort, g.id.get()));
    sorted
        .iter()
        .position(|g| g.id == gid)
        .map(|i| i as i32 + 1)
        .unwrap_or(0)
}

/// Map a 1-based dropdown index back to the corresponding [`CredentialFolderId`].
///
/// Index 0 (the "Root" sentinel) returns `None`.  An out-of-bounds index also
/// returns `None` (safe degradation to root).
fn folder_id_from_name_idx(idx: i32, folders: &[CredentialFolder]) -> Option<CredentialFolderId> {
    if idx <= 0 {
        return None;
    }
    let mut sorted: Vec<&CredentialFolder> = folders.iter().collect();
    sorted.sort_by_key(|f| (f.sort, f.id.get()));
    sorted.get((idx - 1) as usize).map(|f| f.id)
}

/// Find the 1-based dropdown index for a given [`CredentialFolderId`] in the name list.
///
/// Returns 0 (the "Root" sentinel) when `folder_id` is `None` or not found.
fn folder_name_idx(folder_id: Option<CredentialFolderId>, folders: &[CredentialFolder]) -> i32 {
    let Some(fid) = folder_id else { return 0 };
    let mut sorted: Vec<&CredentialFolder> = folders.iter().collect();
    sorted.sort_by_key(|f| (f.sort, f.id.get()));
    sorted
        .iter()
        .position(|f| f.id == fid)
        .map(|i| i as i32 + 1)
        .unwrap_or(0)
}

/// Returns `true` if `target` appears anywhere in the ancestor chain of
/// `candidate_parent` (including `candidate_parent` itself).
///
/// Used in [`on_group_save`] to block descendant-as-parent cycles: the caller
/// should reject any `candidate_parent` for which this returns `true`.
fn is_ancestor_or_self(target: GroupId, candidate_parent: GroupId, groups: &[Group]) -> bool {
    let mut current = Some(candidate_parent);
    let mut depth = 0usize;
    while let Some(id) = current {
        if id == target {
            return true;
        }
        depth += 1;
        if depth > 64 {
            // Cycle already exists in the DB; stop to avoid an infinite loop.
            break;
        }
        current = groups.iter().find(|g| g.id == id).and_then(|g| g.parent_id);
    }
    false
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Build and run the ConMan application.
///
/// # Errors
/// Returns a [`slint::PlatformError`] if the window/backend cannot be created.
pub fn run(config: AppConfig) -> Result<(), slint::PlatformError> {
    let repo = config.repo;
    let secrets = config.secrets;

    let ui = AppWindow::new()?;
    let scale = ui.window().scale_factor();

    let tab_model: Rc<VecModel<TabItem>> = Rc::new(VecModel::default());
    ui.set_tabs(ModelRc::from(tab_model.clone()));

    let conn_model: Rc<VecModel<ConnRow>> = Rc::new(VecModel::default());
    ui.set_connections(ModelRc::from(conn_model.clone()));

    let cred_model: Rc<VecModel<CredRow>> = Rc::new(VecModel::default());
    ui.set_credentials(ModelRc::from(cred_model.clone()));

    let palette_model: Rc<VecModel<PaletteAction>> =
        Rc::new(VecModel::from(initial_palette_actions()));
    ui.set_palette_actions(ModelRc::from(palette_model.clone()));

    // P5.3b: toast model.
    let toast_model: Rc<VecModel<ToastEntry>> = Rc::new(VecModel::default());
    ui.set_toasts(ModelRc::from(toast_model.clone()));
    // Toast counter — gives each toast a unique id so we can remove it by id.
    let toast_next_id: Rc<RefCell<i32>> = Rc::new(RefCell::new(0));

    // ── Load persisted settings (P5.2) ────────────────────────────────────
    let stored_settings = {
        let svc = SettingsService::new(repo.as_ref());
        match svc.load() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("conman: failed to load settings: {e}");
                cm_storage::AppSettings::default()
            }
        }
    };
    apply_settings_to_ui(&stored_settings, &ui);

    // CONMAN_DARK_MODE env-var overrides the persisted theme (dev / CI).
    if let Ok(v) = std::env::var("CONMAN_DARK_MODE") {
        match v.trim() {
            "1" => ui.set_dark_mode(true),
            "0" => ui.set_dark_mode(false),
            _ => {}
        }
    }
    if std::env::var("CONMAN_OPEN_PALETTE").as_deref() == Ok("1") {
        ui.set_palette_open(true);
    }

    // Load initial tree data.
    let conn_tree = match ConnectionTree::load(repo.as_ref()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("conman: failed to load connections: {e}");
            ConnectionTree::new(vec![], vec![])
        }
    };
    let keys_panel = match KeysPanel::load(repo.as_ref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("conman: failed to load credentials: {e}");
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
        local_settings: local_settings_from_app(&stored_settings),
        // P5.3b: search/filter boxes start empty.
        conn_filter: String::new(),
        cred_filter: String::new(),
    }));

    {
        let st = state.borrow();
        refresh_conn_model(&st, &conn_model);
        refresh_cred_model(&st, &cred_model);
        refresh_cred_name_list(&st, &ui);
        refresh_group_name_list(&st, &ui);
    }

    let hk_pending: HkQueue = Arc::new(Mutex::new(std::collections::VecDeque::new()));
    let cert_pending: Arc<Mutex<Option<Sender<CertDecision>>>> = Arc::new(Mutex::new(None));

    open_local_tab(&state, &tab_model, &ui);

    // ── Session tab callbacks ─────────────────────────────────────────────────

    ui.on_new_tab({
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                open_local_tab(&state, &tab_model, &ui);
            }
        }
    });

    ui.on_select_tab({
        let state = state.clone();
        let weak = ui.as_weak();
        move |idx| {
            if let Some(ui) = weak.upgrade() {
                select_tab(&state, &ui, idx);
            }
        }
    });

    ui.on_close_tab({
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        move |idx| {
            if let Some(ui) = weak.upgrade() {
                close_tab(&state, &tab_model, &ui, idx as usize);
            }
        }
    });

    ui.on_key_input({
        let state = state.clone();
        let pal_model_kb = palette_model.clone();
        let tab_model_kb = tab_model.clone();
        let weak_kb = ui.as_weak();
        move |text, special, mods| {
            let Some(ui) = weak_kb.upgrade() else { return };
            if ui.get_palette_open() {
                handle_palette_key(
                    &ui,
                    &state,
                    &tab_model_kb,
                    &pal_model_kb,
                    text,
                    special,
                    mods,
                );
                return;
            }

            // ── P5.1: Ctrl+Shift shortcut layer (reserved by GUI_DESIGN §5) ──
            // These are intercepted before forwarding to the session so they
            // never reach the remote shell.  The terminal FocusScope passes all
            // Ctrl+Shift events to `key-input` (only Ctrl+K is intercepted in
            // Slint); we catch them here.
            let ctrl_shift =
                mods & (input::MOD_CTRL | input::MOD_SHIFT) == (input::MOD_CTRL | input::MOD_SHIFT);
            if ctrl_shift {
                let t = text.as_str();
                match (special, t) {
                    // Ctrl+Shift+\ or Ctrl+Shift+| → H-split.
                    (0, "\\" | "|") => {
                        do_split(&state, &tab_model_kb, &ui, PaneLayout::HSplit);
                        return;
                    }
                    // Ctrl+Shift+- or Ctrl+Shift+_ → V-split.
                    (0, "-" | "_") => {
                        do_split(&state, &tab_model_kb, &ui, PaneLayout::VSplit);
                        return;
                    }
                    // Ctrl+Shift+B → toggle broadcast.
                    (0, "b" | "B") => {
                        ui.set_broadcast_active(!ui.get_broadcast_active());
                        return;
                    }
                    // Ctrl+Shift+Up → focus pane up (prev; intuitive for VSplit).
                    (5, _) => {
                        let new_focus = {
                            let mut st = state.borrow_mut();
                            let active = st.active;
                            if let Some(tab) = st.tabs.get_mut(active) {
                                tab.pane_group.focus_move(-1)
                            } else {
                                return;
                            }
                        };
                        ui.set_active_pane(new_focus as i32);
                        return;
                    }
                    // Ctrl+Shift+Down → focus pane down (next; intuitive for VSplit).
                    (6, _) => {
                        let new_focus = {
                            let mut st = state.borrow_mut();
                            let active = st.active;
                            if let Some(tab) = st.tabs.get_mut(active) {
                                tab.pane_group.focus_move(1)
                            } else {
                                return;
                            }
                        };
                        ui.set_active_pane(new_focus as i32);
                        return;
                    }
                    // Ctrl+Shift+Left → focus pane left (prev; intuitive for HSplit).
                    (7, _) => {
                        let new_focus = {
                            let mut st = state.borrow_mut();
                            let active = st.active;
                            if let Some(tab) = st.tabs.get_mut(active) {
                                tab.pane_group.focus_move(-1)
                            } else {
                                return;
                            }
                        };
                        ui.set_active_pane(new_focus as i32);
                        return;
                    }
                    // Ctrl+Shift+Right → focus pane right (next; intuitive for HSplit).
                    (8, _) => {
                        let new_focus = {
                            let mut st = state.borrow_mut();
                            let active = st.active;
                            if let Some(tab) = st.tabs.get_mut(active) {
                                tab.pane_group.focus_move(1)
                            } else {
                                return;
                            }
                        };
                        ui.set_active_pane(new_focus as i32);
                        return;
                    }
                    // Ctrl+Shift+W → close focused pane (detach = false → shutdown).
                    (0, "w" | "W") => {
                        do_close_pane(&state, &tab_model_kb, &ui, false);
                        return;
                    }
                    // Ctrl+Shift+D → detach session (keep session alive).
                    (0, "d" | "D") => {
                        do_close_pane(&state, &tab_model_kb, &ui, true);
                        return;
                    }
                    _ => {}
                }
            }

            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active) {
                let evs: Vec<SessionInput> = input::map_key(text.as_str(), special, mods)
                    .into_iter()
                    .map(SessionInput::Key)
                    .collect();
                if evs.is_empty() {
                    return;
                }
                // ── Broadcast: fan to ALL pane sessions ──────────────────────
                if ui.get_broadcast_active() {
                    // Send to primary + every extra pane.  The focused pane is
                    // already covered here, so we return to avoid a double-send.
                    for ev in &evs {
                        tab.session.send_input(ev.clone());
                    }
                    for ep in &tab.extra_panes {
                        for ev in &evs {
                            ep.session.send_input(ev.clone());
                        }
                    }
                    return;
                }
                // Not broadcasting — send only to the focused pane.
                let focused = tab.pane_group.focused();
                if focused == 0 {
                    for ev in evs {
                        tab.session.send_input(ev);
                    }
                } else {
                    let ep_idx = focused - 1;
                    if let Some(ep) = tab.extra_panes.get(ep_idx) {
                        for ev in evs {
                            ep.session.send_input(ev);
                        }
                    }
                }
            }
        }
    });

    ui.on_pointer({
        let state = state.clone();
        move |button, kind, x, y, mods| {
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active) {
                let focused = tab.pane_group.focused();
                // Route pointer to the focused pane's session.
                let (session, renderer, scale): (&dyn Session, &TerminalRenderer, f32) =
                    if focused == 0 {
                        (tab.session.as_ref(), &tab.renderer, st.scale)
                    } else {
                        let ep_idx = focused - 1;
                        if let Some(ep) = tab.extra_panes.get(ep_idx) {
                            (ep.session.as_ref(), &ep.renderer, ep.scale)
                        } else {
                            (tab.session.as_ref(), &tab.renderer, st.scale)
                        }
                    };
                match session.surface() {
                    Surface::TerminalGrid(_) => {
                        let (row, col) = renderer.cell_at(x * scale, y * scale);
                        if let Some(ev) = input::map_mouse(button, kind, row, col, mods) {
                            session.send_input(SessionInput::Mouse(ev));
                        }
                    }
                    Surface::Framebuffer(_) => {
                        let w = st.surface_w;
                        let h = st.surface_h;
                        let rdp_w = tab.rdp_w;
                        let rdp_h = tab.rdp_h;
                        let coords = input::RdpCoords {
                            surface_w: w,
                            surface_h: h,
                            rdp_w,
                            rdp_h,
                        };
                        let events = input::map_rdp_mouse(button, kind, x, y, &coords);
                        if !events.is_empty() {
                            session.send_input(SessionInput::Rdp(events));
                        }
                    }
                }
            }
        }
    });

    ui.on_scroll({
        let state = state.clone();
        move |_dx, dy| {
            let st = state.borrow();
            // Terminal scroll only — RDP scroll is handled by on_rdp_scroll (fix c).
            if let Some(tab) = st.tabs.get(st.active)
                && matches!(tab.session.surface(), Surface::TerminalGrid(_))
                && let Some(ev) = input::map_scroll(dy, 0, 0, 0)
            {
                tab.session.send_input(SessionInput::Mouse(ev));
            }
        }
    });

    // RDP scroll with actual pointer coordinates (carry-over fix c).
    ui.on_rdp_scroll({
        let state = state.clone();
        move |x, y, _dx, dy| {
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active)
                && matches!(tab.session.surface(), Surface::Framebuffer(_))
            {
                let w = st.surface_w;
                let h = st.surface_h;
                let rdp_w = tab.rdp_w;
                let rdp_h = tab.rdp_h;
                let coords = input::RdpCoords {
                    surface_w: w,
                    surface_h: h,
                    rdp_w,
                    rdp_h,
                };
                // Use actual pointer position instead of surface centre.
                let events = input::map_rdp_scroll(dy, x, y, &coords);
                if !events.is_empty() {
                    tab.session.send_input(SessionInput::Rdp(events));
                }
            }
        }
    });

    let resize_debounce = Rc::new(Timer::default());
    {
        let state = state.clone();
        let weak = ui.as_weak();
        let debounce = resize_debounce.clone();
        ui.on_surface_resized(move |w, h| {
            if let Some(ui) = weak.upgrade() {
                let mut st = state.borrow_mut();
                st.scale = ui.window().scale_factor();
                st.surface_w = w;
                st.surface_h = h;
                trace(format_args!(
                    "resize event  {w:.0}x{h:.0} logical (debouncing)"
                ));
                render_active(&mut st, &ui);
            }
            let state = state.clone();
            let weak = weak.clone();
            debounce.start(TimerMode::SingleShot, RESIZE_DEBOUNCE, move || {
                if let Some(ui) = weak.upgrade() {
                    apply_settled_resize(&state, &ui);
                }
            });
        });
    }

    // ── Shell / panel callbacks ───────────────────────────────────────────────
    //
    // UNVERIFIED: Persist panel state (active_panel + sidebar_collapsed/width)
    // via a settings facility.  No settings store exists in the merged waves
    // (P1.0–P3.2); persisting theme choices is deferred to P5.2
    // (settings-theming).  Panel state persistence is similarly deferred to
    // P5.2 and will be implemented there once the settings infrastructure
    // lands.  Until then, state resets to defaults on restart.

    ui.on_select_panel({
        let weak = ui.as_weak();
        let repo_sp = repo.clone();
        move |idx| {
            if let Some(ui) = weak.upgrade() {
                ui.set_active_panel(idx);
                let svc = SettingsService::new(repo_sp.as_ref());
                if let Err(e) = svc.save_active_panel(idx) {
                    eprintln!("conman: save active_panel: {e}");
                }
            }
        }
    });

    ui.on_toggle_sidebar({
        let weak = ui.as_weak();
        let repo_ts = repo.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                let new_val = !ui.get_sidebar_collapsed();
                ui.set_sidebar_collapsed(new_val);
                let svc = SettingsService::new(repo_ts.as_ref());
                if let Err(e) = svc.save_sidebar_collapsed(new_val) {
                    eprintln!("conman: save sidebar_collapsed: {e}");
                }
            }
        }
    });

    ui.on_open_palette({
        let weak = ui.as_weak();
        let pal_model = palette_model.clone();
        let tab_model_op = tab_model.clone();
        let state = state.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                let labels: Vec<String> = state
                    .borrow()
                    .detached
                    .iter()
                    .map(|d| d.label.clone())
                    .collect();
                let tabs: Vec<(usize, String)> = (0..tab_model_op.row_count())
                    .filter_map(|i| tab_model_op.row_data(i).map(|t| (i, t.title.to_string())))
                    .collect();
                let q = ui.get_palette_query();
                rebuild_palette_model(&pal_model, &q, &labels, &tabs);
                ui.set_palette_selected(0);
                ui.set_palette_open(true);
            }
        }
    });

    ui.on_quick_connect({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_quick_connect_open(true);
            }
        }
    });

    ui.on_qc_connect({
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        let hk_pending = hk_pending.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let host = ui.get_qc_host().trim().to_owned();
            let port_str = ui.get_qc_port().trim().to_owned();
            let username = ui.get_qc_username().trim().to_owned();
            let auth_method = ui.get_qc_auth_method();
            let secret_raw = ui.get_qc_secret().to_string();
            let pass_raw = ui.get_qc_passphrase().to_string();
            if host.is_empty() || username.is_empty() {
                return;
            }
            let port = port_str.parse::<u16>().unwrap_or(22);
            let auth = match auth_method {
                0 => SshAuthInput::Key {
                    path: PathBuf::from(secret_raw),
                    passphrase: if pass_raw.is_empty() {
                        None
                    } else {
                        Some(Secret::from_string(pass_raw))
                    },
                },
                1 => SshAuthInput::Password(Secret::from_string(secret_raw)),
                _ => SshAuthInput::Agent,
            };
            let settings = SshSettings {
                host,
                port,
                username,
                auth_method: SshAuthMethod::Password,
            };
            ui.set_quick_connect_open(false);
            ui.set_qc_secret(Default::default());
            ui.set_qc_passphrase(Default::default());
            let auto_accept = std::env::var("CONMAN_SSH_AUTO_ACCEPT_KEYS").as_deref() == Ok("1");
            let verifier = Arc::new(UiHostKeyVerifier {
                weak_ui: weak.clone(),
                pending: hk_pending.clone(),
                auto_accept,
            });
            open_ssh_tab(&state, &tab_model, &ui, settings, auth, verifier);
        }
    });

    ui.on_host_key_accept({
        let pending = hk_pending.clone();
        let weak = ui.as_weak();
        move || {
            // Pop the front sender (oldest pending request) — carry-over fix (a).
            if let Ok(mut q) = pending.lock()
                && let Some(tx) = q.pop_front()
            {
                let _ = tx.send(HostKeyDecision::Accept);
            }
            if let Some(ui) = weak.upgrade() {
                ui.set_host_key_open(false);
            }
        }
    });

    ui.on_host_key_reject({
        let pending = hk_pending.clone();
        let weak = ui.as_weak();
        move || {
            // Pop the front sender (oldest pending request) — carry-over fix (a).
            if let Ok(mut q) = pending.lock()
                && let Some(tx) = q.pop_front()
            {
                let _ = tx.send(HostKeyDecision::Reject);
            }
            if let Some(ui) = weak.upgrade() {
                ui.set_host_key_open(false);
            }
        }
    });

    // ── RDP cert dialog callbacks (P4.2) ─────────────────────────────────────

    ui.on_cert_accept({
        let pending = cert_pending.clone();
        let weak = ui.as_weak();
        move || {
            if let Ok(mut p) = pending.lock()
                && let Some(tx) = p.take()
            {
                let _ = tx.send(CertDecision::AcceptAndRemember);
            }
            if let Some(ui) = weak.upgrade() {
                ui.set_cert_dialog_open(false);
            }
        }
    });

    ui.on_cert_reject({
        let pending = cert_pending.clone();
        let weak = ui.as_weak();
        move || {
            if let Ok(mut p) = pending.lock()
                && let Some(tx) = p.take()
            {
                let _ = tx.send(CertDecision::Reject);
            }
            if let Some(ui) = weak.upgrade() {
                ui.set_cert_dialog_open(false);
            }
        }
    });

    // ── RDP key events (P4.2) ────────────────────────────────────────────────

    ui.on_rdp_key_down({
        let state = state.clone();
        move |text, special, mods| {
            // Local→remote clipboard sync: intercept Ctrl+V, announce our clipboard.
            if mods & input::MOD_CTRL != 0 && text.as_str().eq_ignore_ascii_case("v") {
                let paste_text = state
                    .borrow_mut()
                    .sys_clipboard
                    .as_mut()
                    .and_then(|cb| cb.get_text().ok());
                if let Some(text_to_paste) = paste_text {
                    let st = state.borrow();
                    if let Some(tab) = st.tabs.get(st.active) {
                        tab.session
                            .send_input(SessionInput::RdpPaste(text_to_paste));
                    }
                }
                // Fall through: also send the Ctrl+V scancodes so the remote app triggers
                // a clipboard request after we've announced our content.
            }
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active) {
                let events = input::map_rdp_key_down(text.as_str(), special, mods);
                if !events.is_empty() {
                    tab.session.send_input(SessionInput::Rdp(events));
                }
            }
        }
    });

    ui.on_rdp_key_up({
        let state = state.clone();
        move |text, special, mods| {
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active) {
                let events = input::map_rdp_key_up(text.as_str(), special, mods);
                if !events.is_empty() {
                    tab.session.send_input(SessionInput::Rdp(events));
                }
            }
        }
    });

    ui.on_row_activated({
        let state = state.clone();
        let tab_model = tab_model.clone();
        let cert_pending = cert_pending.clone();
        let hk_pending = hk_pending.clone();
        let weak = ui.as_weak();
        move |idx| {
            let Some(ui) = weak.upgrade() else { return };
            let row = {
                let st = state.borrow();
                st.conn_tree.flat().get(idx as usize).cloned()
            };
            let Some(row) = row else { return };
            if row.is_group {
                return; // groups are toggled by on_toggle_conn_row
            }
            // Look up the connection by id.
            let conn = {
                let st = state.borrow();
                st.conn_tree
                    .connections()
                    .iter()
                    .find(|c| c.id.get() as i32 == row.id)
                    .cloned()
            };
            let Some(conn) = conn else {
                open_local_tab(&state, &tab_model, &ui);
                return;
            };
            match conn.settings {
                ConnectionSettings::Local(_) => open_local_tab(&state, &tab_model, &ui),
                ConnectionSettings::Ssh(s) => {
                    let auth = SshAuthInput::Password(Secret::from_string(String::new()));
                    let auto_accept =
                        std::env::var("CONMAN_SSH_AUTO_ACCEPT_KEYS").as_deref() == Ok("1");
                    let verifier = Arc::new(UiHostKeyVerifier {
                        weak_ui: weak.clone(),
                        pending: hk_pending.clone(),
                        auto_accept,
                    });
                    open_ssh_tab(&state, &tab_model, &ui, s, auth, verifier);
                }
                ConnectionSettings::Rdp(s) => {
                    let auto_accept =
                        std::env::var("CONMAN_RDP_AUTO_ACCEPT_CERTS").as_deref() == Ok("1");
                    let verifier = Arc::new(UiCertVerifier {
                        weak_ui: weak.clone(),
                        pending: cert_pending.clone(),
                        auto_accept,
                    });
                    // Use username from settings; password from keychain is out of scope.
                    let auth = RdpAuthInput {
                        username: s.username.clone().unwrap_or_default(),
                        password: cm_core::Secret::from_string(String::new()),
                        domain: None,
                    };
                    open_rdp_tab(&state, &tab_model, &ui, s, auth, verifier);
                }
            }
        }
    });

    ui.on_toggle_broadcast({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_broadcast_active(!ui.get_broadcast_active());
            }
        }
    });

    // ── P5.1: Split-pane callbacks ────────────────────────────────────────────

    ui.on_split_pane_h({
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                do_split(&state, &tab_model, &ui, PaneLayout::HSplit);
            }
        }
    });

    ui.on_split_pane_v({
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                do_split(&state, &tab_model, &ui, PaneLayout::VSplit);
            }
        }
    });

    ui.on_close_pane({
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                do_close_pane(&state, &tab_model, &ui, false);
            }
        }
    });

    ui.on_detach_session({
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                do_close_pane(&state, &tab_model, &ui, true);
            }
        }
    });

    ui.on_pane_focused({
        let state = state.clone();
        let weak = ui.as_weak();
        move |pane_idx| {
            let mut st = state.borrow_mut();
            let active = st.active;
            if let Some(tab) = st.tabs.get_mut(active) {
                tab.pane_group.set_focused(pane_idx as usize);
            }
            if let Some(ui) = weak.upgrade() {
                ui.set_active_pane(pane_idx);
            }
        }
    });

    ui.on_pane_resized({
        let state = state.clone();
        let debounce = resize_debounce.clone();
        let weak = ui.as_weak();
        move |pane_idx, w, h| {
            {
                let mut st = state.borrow_mut();
                let scale = st.scale;
                if pane_idx == 0 {
                    st.surface_w = w;
                    st.surface_h = h;
                    // Update scale from UI if available.
                    if let Some(ui) = weak.upgrade() {
                        st.scale = ui.window().scale_factor();
                    }
                } else {
                    let active = st.active;
                    if let Some(tab) = st.tabs.get_mut(active) {
                        let pidx = pane_idx as usize - 1;
                        if let Some(ep) = tab.extra_panes.get_mut(pidx) {
                            ep.surface_w = w;
                            ep.surface_h = h;
                            ep.scale = scale;
                        }
                    }
                }
            }
            let state = state.clone();
            let weak2 = weak.clone();
            debounce.start(TimerMode::SingleShot, RESIZE_DEBOUNCE, move || {
                if let Some(ui) = weak2.upgrade() {
                    apply_settled_resize(&state, &ui);
                }
            });
        }
    });

    // ── P5.1: Reattach detached session (palette action) ─────────────────────
    // Implemented via `dispatch_palette_action`; no dedicated callback needed.

    ui.on_palette_edited({
        let weak = ui.as_weak();
        let pal_model = palette_model.clone();
        let tab_model_pe = tab_model.clone();
        let state = state.clone();
        move |query| {
            let labels: Vec<String> = state
                .borrow()
                .detached
                .iter()
                .map(|d| d.label.clone())
                .collect();
            let tabs: Vec<(usize, String)> = (0..tab_model_pe.row_count())
                .filter_map(|i| tab_model_pe.row_data(i).map(|t| (i, t.title.to_string())))
                .collect();
            rebuild_palette_model(&pal_model, &query, &labels, &tabs);
            if let Some(ui) = weak.upgrade() {
                ui.set_palette_query(query);
                ui.set_palette_selected(0);
            }
        }
    });

    ui.on_palette_activated({
        let state = state.clone();
        let tab_model = tab_model.clone();
        let pal_model_dispatch = palette_model.clone();
        let weak = ui.as_weak();
        move |idx| {
            if let Some(ui) = weak.upgrade() {
                dispatch_palette_action(&state, &tab_model, &pal_model_dispatch, &ui, idx as usize);
            }
        }
    });

    // ── Settings persistence callbacks (P5.2) ────────────────────────────────

    ui.on_theme_changed({
        let repo_s = repo.clone();
        move |idx| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_theme_mode(idx) {
                eprintln!("conman: save theme_mode: {e}");
            }
        }
    });

    ui.on_density_changed({
        let repo_s = repo.clone();
        move |idx| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_density(idx) {
                eprintln!("conman: save density: {e}");
            }
        }
    });

    ui.on_accent_changed({
        let repo_s = repo.clone();
        move |idx| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_accent_index(idx) {
                eprintln!("conman: save accent_index: {e}");
            }
        }
    });

    ui.on_settings_font_size_changed({
        let repo_s = repo.clone();
        let state_fs = state.clone();
        let weak_fs = ui.as_weak();
        move |v| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_font_size(v) {
                eprintln!("conman: save font_size: {e}");
            }
            // Apply font size change to all live renderers immediately.
            {
                let mut st = state_fs.borrow_mut();
                let new_px = v as f32;
                st.font_size_px = new_px;
                let scale = st.scale;
                for tab in &mut st.tabs {
                    tab.renderer.set_scale(new_px, scale);
                    for ep in &mut tab.extra_panes {
                        ep.renderer.set_scale(new_px, scale);
                    }
                }
                // Drop borrow before calling apply_settled_resize (fix g).
            }
            // Commit new cell dimensions to PTY/engine for all tabs (carry-over fix g).
            if let Some(ui) = weak_fs.upgrade() {
                apply_settled_resize(&state_fs, &ui);
            }
        }
    });

    ui.on_settings_shell_path_changed({
        let repo_s = repo.clone();
        let state_sp = state.clone();
        move |v| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_shell_path(v.as_str()) {
                eprintln!("conman: save shell_path: {e}");
            }
            let mut st = state_sp.borrow_mut();
            st.local_settings.program = if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            };
        }
    });

    ui.on_settings_shell_args_changed({
        let repo_s = repo.clone();
        let state_sa = state.clone();
        move |v| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_shell_args(v.as_str()) {
                eprintln!("conman: save shell_args: {e}");
            }
            let mut st = state_sa.borrow_mut();
            st.local_settings.args = if v.is_empty() {
                Vec::new()
            } else {
                v.split_whitespace().map(String::from).collect()
            };
        }
    });

    ui.on_settings_shell_cwd_changed({
        let repo_s = repo.clone();
        let state_sc = state.clone();
        move |v| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_shell_cwd(v.as_str()) {
                eprintln!("conman: save shell_cwd: {e}");
            }
            let mut st = state_sc.borrow_mut();
            st.local_settings.working_dir = if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            };
        }
    });

    ui.on_startup_behavior_changed({
        let repo_s = repo.clone();
        move |v| {
            let svc = SettingsService::new(repo_s.as_ref());
            if let Err(e) = svc.save_startup_behavior(v) {
                eprintln!("conman: save startup_behavior: {e}");
            }
        }
    });

    ui.on_reconnect({
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        let hk_pending = hk_pending.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let (active_idx, connect_info_opt) = {
                let st = state.borrow();
                let idx = st.active;
                let info = st.tabs.get(idx).and_then(|t| {
                    t.connect_info
                        .as_ref()
                        .map(|c| (c.settings.clone(), c.auth.clone()))
                });
                (idx, info)
            };
            let Some((settings, auth)) = connect_info_opt else {
                return;
            };
            {
                let st = state.borrow();
                if let Some(tab) = st.tabs.get(active_idx) {
                    tab.session.shutdown();
                }
            }
            let auto_accept = std::env::var("CONMAN_SSH_AUTO_ACCEPT_KEYS").as_deref() == Ok("1");
            let verifier = Arc::new(UiHostKeyVerifier {
                weak_ui: weak.clone(),
                pending: hk_pending.clone(),
                auto_accept,
            });
            reconnect_ssh_tab(
                &state, &tab_model, &ui, active_idx, settings, auth, verifier,
            );
        }
    });

    ui.on_launchpad_edited(|_q| {});
    ui.on_open_recent(|_i| {});
    ui.on_open_group_split(|| {});

    // ── P5.3b: Search/filter for connection tree and keys tree ───────────────

    ui.on_conn_filter_changed({
        let state = state.clone();
        let conn_model = conn_model.clone();
        move |q| {
            let mut st = state.borrow_mut();
            st.conn_filter = q.to_string();
            refresh_conn_model(&st, &conn_model);
        }
    });

    ui.on_cred_filter_changed({
        let state = state.clone();
        let cred_model = cred_model.clone();
        move |q| {
            let mut st = state.borrow_mut();
            st.cred_filter = q.to_string();
            refresh_cred_model(&st, &cred_model);
        }
    });

    ui.on_toast_dismissed({
        let toast_model = toast_model.clone();
        move |id| {
            // Find the entry with the given id and remove it.
            let idx = (0..toast_model.row_count())
                .find(|&i| toast_model.row_data(i).map(|e| e.id) == Some(id));
            if let Some(i) = idx {
                toast_model.remove(i);
            }
        }
    });

    // ── P1.4: Connections panel CRUD ─────────────────────────────────────────

    ui.on_toggle_conn_row({
        let state = state.clone();
        let conn_model = conn_model.clone();
        move |idx| {
            let mut st = state.borrow_mut();
            let flat = st.conn_tree.flat();
            if let Some(row) = flat.get(idx as usize)
                && row.is_group
            {
                st.conn_tree.toggle_expand(row.id as i64);
                refresh_conn_model(&st, &conn_model);
            }
        }
    });

    ui.on_new_connection({
        let state = state.clone();
        let weak = ui.as_weak();
        move |group_id| {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.borrow();
            let gid = if group_id == 0 {
                None
            } else {
                Some(GroupId::new(group_id as i64))
            };
            let selected_group_idx = group_name_idx(gid, st.conn_tree.groups());
            let form = ConnProfile {
                id: 0,
                name: SharedString::from("New Connection"),
                group_id,
                kind: 0,
                host: SharedString::from(""),
                port: SharedString::from("22"),
                username: SharedString::from(""),
                auth_method: 1,
                selected_cred_idx: 0,
                effective_cred_name: SharedString::from(""),
                effective_inherited: false,
                selected_group_idx,
            };
            drop(st);
            ui.set_profile_form(form);
            ui.set_profile_editor_open(true);
        }
    });

    ui.on_new_group({
        let state = state.clone();
        let weak = ui.as_weak();
        move |parent_id| {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.borrow();
            let pid = if parent_id == 0 {
                None
            } else {
                Some(GroupId::new(parent_id as i64))
            };
            let selected_parent_idx = group_name_idx(pid, st.conn_tree.groups());
            let form = GroupForm {
                id: 0,
                name: SharedString::from("New Group"),
                parent_id,
                default_cred_idx: 0,
                selected_parent_idx,
            };
            drop(st);
            ui.set_group_form(form);
            ui.set_group_editor_open(true);
        }
    });

    ui.on_edit_conn({
        let state = state.clone();
        let weak = ui.as_weak();
        move |conn_id| {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.borrow();
            let Some(conn) = st.conn_tree.conn_by_id(conn_id as i64) else {
                return;
            };
            let (kind, host, port, username, auth_method) = profile_fields_from_conn(conn);
            let cred_sel_idx = cred_name_idx(
                conn.credential,
                st.keys_panel.credentials(),
                st.keys_panel.folders(),
            );
            let (eff_cred_id, inherited) =
                KeysPanel::resolve_effective(conn.credential, conn.group_id, st.conn_tree.groups());
            let eff_name = KeysPanel::cred_display_name(eff_cred_id, st.keys_panel.credentials());
            let selected_group_idx = group_name_idx(conn.group_id, st.conn_tree.groups());
            let form = ConnProfile {
                id: conn_id,
                name: SharedString::from(conn.name.as_str()),
                group_id: conn.group_id.map(|g| g.get() as i32).unwrap_or(0),
                kind,
                host: SharedString::from(host.as_str()),
                port: SharedString::from(port.as_str()),
                username: SharedString::from(username.as_str()),
                auth_method,
                selected_cred_idx: cred_sel_idx,
                effective_cred_name: SharedString::from(eff_name.as_str()),
                effective_inherited: inherited,
                selected_group_idx,
            };
            drop(st);
            ui.set_profile_form(form);
            ui.set_profile_editor_open(true);
        }
    });

    ui.on_edit_group({
        let state = state.clone();
        let weak = ui.as_weak();
        move |group_id| {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.borrow();
            let Some(group) = st.conn_tree.group_by_id(group_id as i64) else {
                return;
            };
            let default_cred_idx = cred_name_idx(
                group.default_credential,
                st.keys_panel.credentials(),
                st.keys_panel.folders(),
            );
            let selected_parent_idx = group_name_idx(group.parent_id, st.conn_tree.groups());
            let form = GroupForm {
                id: group_id,
                name: SharedString::from(group.name.as_str()),
                parent_id: group.parent_id.map(|g| g.get() as i32).unwrap_or(0),
                default_cred_idx,
                selected_parent_idx,
            };
            drop(st);
            ui.set_group_form(form);
            ui.set_group_editor_open(true);
        }
    });

    ui.on_delete_conn_row({
        let state = state.clone();
        let conn_model = conn_model.clone();
        let repo_del = repo.clone();
        move |id, is_group| {
            let mut st = state.borrow_mut();
            let result = if is_group {
                repo_del.delete_group(GroupId::new(id as i64))
            } else {
                repo_del.delete_connection(ConnectionId::new(id as i64))
            };
            if let Err(e) = result {
                eprintln!("conman: delete failed: {e}");
                return;
            }
            if let Err(e) = st.conn_tree.reload(repo_del.as_ref()) {
                eprintln!("conman: reload after delete failed: {e}");
            }
            refresh_conn_model(&st, &conn_model);
        }
    });

    ui.on_profile_save({
        let state = state.clone();
        let conn_model = conn_model.clone();
        let repo_ps = repo.clone();
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let form = ui.get_profile_form();
            // Resolve group_id from the dropdown index (selected-group-idx).
            // Falls back to the raw form.group_id when the index is out-of-range
            // (e.g. on an older saved form with no group list loaded yet).
            let group_id = {
                let st = state.borrow();
                group_id_from_name_idx(form.selected_group_idx, st.conn_tree.groups())
            };
            let cred_id = {
                let st = state.borrow();
                resolve_cred_from_idx(
                    form.selected_cred_idx,
                    st.keys_panel.credentials(),
                    st.keys_panel.folders(),
                )
            };
            let sort = {
                let st = state.borrow();
                if form.id == 0 {
                    st.conn_tree.next_sort_in_group(group_id)
                } else {
                    st.conn_tree
                        .conn_by_id(form.id as i64)
                        .map(|c| c.sort)
                        .unwrap_or(0)
                }
            };
            let settings = settings_from_form(&form);
            let kind = kind_from_form_int(form.kind);
            let now = crate::tree::now_secs();
            let created_at = {
                let st = state.borrow();
                st.conn_tree
                    .conn_by_id(form.id as i64)
                    .map(|c| c.created_at)
                    .unwrap_or(now)
            };
            let conn = match Connection::new(
                ConnectionId::new(form.id as i64),
                group_id,
                form.name.to_string(),
                kind,
                settings,
                cred_id,
                sort,
                created_at,
                now,
            ) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("conman: profile validation error: {e}");
                    return;
                }
            };
            if let Err(e) = repo_ps.upsert_connection(&conn) {
                eprintln!("conman: upsert connection failed: {e}");
                return;
            }
            ui.set_profile_editor_open(false);
            let mut st = state.borrow_mut();
            if let Err(e) = st.conn_tree.reload(repo_ps.as_ref()) {
                eprintln!("conman: reload after save failed: {e}");
            }
            refresh_conn_model(&st, &conn_model);
            refresh_group_name_list(&st, &ui);
        }
    });

    ui.on_group_save({
        let state = state.clone();
        let conn_model = conn_model.clone();
        let repo_gs = repo.clone();
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let form = ui.get_group_form();
            // Resolve parent_id from the dropdown index (selected-parent-idx).
            // Reject any parent choice that would form a cycle: the chosen parent
            // must not be the group itself AND must not be any of its descendants.
            // (`is_ancestor_or_self` covers both: it returns true when
            //  candidate == self and when candidate is reachable from self.)
            let parent_id = {
                let st = state.borrow();
                let resolved =
                    group_id_from_name_idx(form.selected_parent_idx, st.conn_tree.groups());
                resolved.filter(|&gid| {
                    form.id == 0
                        || !is_ancestor_or_self(
                            GroupId::new(form.id as i64),
                            gid,
                            st.conn_tree.groups(),
                        )
                })
            };
            let default_credential = {
                let st = state.borrow();
                resolve_cred_from_idx(
                    form.default_cred_idx,
                    st.keys_panel.credentials(),
                    st.keys_panel.folders(),
                )
            };
            let sort = {
                let st = state.borrow();
                if form.id == 0 {
                    st.conn_tree.next_group_sort_in_parent(parent_id)
                } else {
                    st.conn_tree
                        .group_by_id(form.id as i64)
                        .map(|g| g.sort)
                        .unwrap_or(0)
                }
            };
            let group = Group {
                id: GroupId::new(form.id as i64),
                parent_id,
                name: form.name.to_string(),
                sort,
                default_credential,
            };
            if let Err(e) = repo_gs.upsert_group(&group) {
                eprintln!("conman: upsert group failed: {e}");
                return;
            }
            ui.set_group_editor_open(false);
            let mut st = state.borrow_mut();
            if let Err(e) = st.conn_tree.reload(repo_gs.as_ref()) {
                eprintln!("conman: reload after group save failed: {e}");
            }
            refresh_conn_model(&st, &conn_model);
            refresh_group_name_list(&st, &ui);
        }
    });

    // ── P1.4: Reorder / move-between-groups ──────────────────────────────────

    ui.on_reorder_conn_row({
        let state = state.clone();
        let conn_model = conn_model.clone();
        let repo_rcr = repo.clone();
        move |conn_id, direction| {
            let mut st = state.borrow_mut();
            let Some(conn) = st.conn_tree.conn_by_id(conn_id as i64).cloned() else {
                return;
            };
            let group_id = conn.group_id;
            // Collect siblings (same parent) sorted by (sort, id).
            let mut siblings: Vec<Connection> = st
                .conn_tree
                .connections()
                .iter()
                .filter(|c| c.group_id == group_id)
                .cloned()
                .collect();
            siblings.sort_by_key(|c| (c.sort, c.id.get()));
            let Some(pos) = siblings.iter().position(|c| c.id == conn.id) else {
                return;
            };
            let target_pos = if direction < 0 {
                if pos == 0 {
                    return;
                }
                pos - 1
            } else {
                if pos + 1 >= siblings.len() {
                    return;
                }
                pos + 1
            };
            // Swap sort values between the two siblings.
            let sort_a = siblings[pos].sort;
            let sort_b = siblings[target_pos].sort;
            let mut a = siblings[pos].clone();
            let mut b = siblings[target_pos].clone();
            if sort_a == sort_b {
                // Equal sorts: nudge them apart without touching the other sibling.
                if direction < 0 {
                    a.sort = sort_a.saturating_sub(1);
                } else {
                    a.sort = sort_a.saturating_add(1);
                }
                if let Err(e) = repo_rcr.upsert_connection(&a) {
                    eprintln!("conman: reorder conn (nudge) failed: {e}");
                    return;
                }
            } else {
                a.sort = sort_b;
                b.sort = sort_a;
                if let Err(e) = repo_rcr.upsert_connection(&b) {
                    eprintln!("conman: reorder conn (swap target) failed: {e}");
                    return;
                }
                if let Err(e) = repo_rcr.upsert_connection(&a) {
                    eprintln!("conman: reorder conn (swap source) failed: {e}");
                    return;
                }
            }
            if let Err(e) = st.conn_tree.reload(repo_rcr.as_ref()) {
                eprintln!("conman: reload after reorder failed: {e}");
            }
            refresh_conn_model(&st, &conn_model);
        }
    });

    ui.on_reorder_group_row({
        let state = state.clone();
        let conn_model = conn_model.clone();
        let repo_rgr = repo.clone();
        let weak_rgr = ui.as_weak();
        move |group_id, direction| {
            let mut st = state.borrow_mut();
            let Some(grp) = st.conn_tree.group_by_id(group_id as i64).cloned() else {
                return;
            };
            let parent_id = grp.parent_id;
            // Collect sibling groups (same parent) sorted by (sort, id).
            let mut siblings: Vec<Group> = st
                .conn_tree
                .groups()
                .iter()
                .filter(|g| g.parent_id == parent_id)
                .cloned()
                .collect();
            siblings.sort_by_key(|g| (g.sort, g.id.get()));
            let Some(pos) = siblings.iter().position(|g| g.id == grp.id) else {
                return;
            };
            let target_pos = if direction < 0 {
                if pos == 0 {
                    return;
                }
                pos - 1
            } else {
                if pos + 1 >= siblings.len() {
                    return;
                }
                pos + 1
            };
            let sort_a = siblings[pos].sort;
            let sort_b = siblings[target_pos].sort;
            let mut a = siblings[pos].clone();
            let mut b = siblings[target_pos].clone();
            if sort_a == sort_b {
                if direction < 0 {
                    a.sort = sort_a.saturating_sub(1);
                } else {
                    a.sort = sort_a.saturating_add(1);
                }
                if let Err(e) = repo_rgr.upsert_group(&a) {
                    eprintln!("conman: reorder group (nudge) failed: {e}");
                    return;
                }
            } else {
                a.sort = sort_b;
                b.sort = sort_a;
                if let Err(e) = repo_rgr.upsert_group(&b) {
                    eprintln!("conman: reorder group (swap target) failed: {e}");
                    return;
                }
                if let Err(e) = repo_rgr.upsert_group(&a) {
                    eprintln!("conman: reorder group (swap source) failed: {e}");
                    return;
                }
            }
            if let Err(e) = st.conn_tree.reload(repo_rgr.as_ref()) {
                eprintln!("conman: reload after group reorder failed: {e}");
            }
            refresh_conn_model(&st, &conn_model);
            if let Some(ui) = weak_rgr.upgrade() {
                refresh_group_name_list(&st, &ui);
            }
        }
    });

    // ── P1.4: Keys panel CRUD ─────────────────────────────────────────────────

    ui.on_toggle_cred_row({
        let state = state.clone();
        let cred_model = cred_model.clone();
        move |idx| {
            let mut st = state.borrow_mut();
            let flat = st.keys_panel.flat();
            if let Some(row) = flat.get(idx as usize)
                && row.is_folder
            {
                st.keys_panel.toggle_expand(row.id as i64);
                refresh_cred_model(&st, &cred_model);
            }
        }
    });

    ui.on_new_cred({
        let state = state.clone();
        let weak = ui.as_weak();
        move |folder_id| {
            let Some(ui) = weak.upgrade() else { return };
            // Resolve the DB folder id to a combo index so the picker
            // pre-selects the folder from which the "New Credential" action
            // was triggered.
            let selected_folder_idx = {
                let st = state.borrow();
                let fid = if folder_id == 0 {
                    None
                } else {
                    Some(CredentialFolderId::new(folder_id as i64))
                };
                folder_name_idx(fid, st.keys_panel.folders())
            };
            let form = CredFormData {
                id: 0,
                name: SharedString::from("New Credential"),
                kind: 0,
                username: SharedString::from(""),
                folder_id,
                selected_folder_idx,
                secret: SharedString::from(""),
                passphrase: SharedString::from(""),
            };
            ui.set_cred_form(form);
            ui.set_cred_editor_open(true);
        }
    });

    ui.on_new_cred_folder({
        let state = state.clone();
        let cred_model = cred_model.clone();
        let repo_ncf = repo.clone();
        let weak = ui.as_weak();
        move |parent_folder_id| {
            let Some(_ui) = weak.upgrade() else { return };
            let fid = if parent_folder_id == 0 {
                None
            } else {
                Some(CredentialFolderId::new(parent_folder_id as i64))
            };
            let sort = {
                let st = state.borrow();
                st.keys_panel
                    .folders()
                    .iter()
                    .filter(|f| f.parent_id == fid)
                    .map(|f| f.sort)
                    .max()
                    .map(|m| m + 1)
                    .unwrap_or(0)
            };
            let folder = CredentialFolder {
                id: CredentialFolderId::UNSAVED,
                parent_id: fid,
                name: "New Folder".to_owned(),
                sort,
            };
            if let Err(e) = repo_ncf.upsert_credential_folder(&folder) {
                eprintln!("conman: create folder failed: {e}");
                return;
            }
            let mut st = state.borrow_mut();
            if let Err(e) = st.keys_panel.reload(repo_ncf.as_ref()) {
                eprintln!("conman: reload after folder create failed: {e}");
            }
            refresh_cred_model(&st, &cred_model);
        }
    });

    ui.on_edit_cred({
        let state = state.clone();
        let weak = ui.as_weak();
        move |cred_id| {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.borrow();
            let Some(cred) = st
                .keys_panel
                .credentials()
                .iter()
                .find(|c| c.id.get() == cred_id as i64)
            else {
                return;
            };
            let kind = match cred.kind {
                CredentialKind::Password => 0,
                CredentialKind::SshKey => 1,
                CredentialKind::SshKeyWithPassphrase => 2,
            };
            let raw_folder_id = cred.folder_id.map(|f| f.get() as i32).unwrap_or(0);
            // Resolve the credential's current folder to a combo-box index so
            // the picker shows the correct folder when the editor opens.
            let selected_folder_idx = folder_name_idx(cred.folder_id, st.keys_panel.folders());
            let form = CredFormData {
                id: cred_id,
                name: SharedString::from(cred.name.as_str()),
                kind,
                username: SharedString::from(cred.username.as_deref().unwrap_or("")),
                folder_id: raw_folder_id,
                selected_folder_idx,
                secret: SharedString::from(""),
                passphrase: SharedString::from(""),
            };
            drop(st);
            ui.set_cred_form(form);
            ui.set_cred_editor_open(true);
        }
    });

    ui.on_delete_cred_row({
        let state = state.clone();
        let cred_model = cred_model.clone();
        let repo_del = repo.clone();
        let weak = ui.as_weak();
        move |id, is_folder| {
            let mut st = state.borrow_mut();
            let result = if is_folder {
                repo_del.delete_credential_folder(CredentialFolderId::new(id as i64))
            } else {
                repo_del.delete_credential(CredentialId::new(id as i64))
            };
            if let Err(e) = result {
                eprintln!("conman: delete cred/folder failed: {e}");
                return;
            }
            if let Err(e) = st.keys_panel.reload(repo_del.as_ref()) {
                eprintln!("conman: reload after cred delete failed: {e}");
            }
            refresh_cred_model(&st, &cred_model);
            let Some(ui) = weak.upgrade() else { return };
            refresh_cred_name_list(&st, &ui);
        }
    });

    ui.on_cred_save({
        let state = state.clone();
        let cred_model = cred_model.clone();
        let repo_cs = repo.clone();
        let secrets_cs = secrets.clone();
        let weak = ui.as_weak();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let mut form = ui.get_cred_form();
            // Resolve folder from the combo index (selected-folder-idx) so that
            // a move-between-folders edit is honoured, not the stale raw folder_id.
            let fid = {
                let st = state.borrow();
                folder_id_from_name_idx(form.selected_folder_idx, st.keys_panel.folders())
            };
            let kind = match form.kind {
                1 => CredentialKind::SshKey,
                2 => CredentialKind::SshKeyWithPassphrase,
                _ => CredentialKind::Password,
            };
            let cred = Credential {
                id: CredentialId::new(form.id as i64),
                name: form.name.to_string(),
                kind,
                folder_id: fid,
                username: {
                    let u = form.username.trim().to_owned();
                    if u.is_empty() { None } else { Some(u) }
                },
            };
            let upserted_id = match repo_cs.upsert_credential(&cred) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("conman: upsert credential failed: {e}");
                    form.secret = SharedString::from("");
                    form.passphrase = SharedString::from("");
                    ui.set_cred_form(form);
                    return;
                }
            };
            // Capture secrets before clearing them.
            let secret_text = form.secret.to_string();
            let passphrase_text = form.passphrase.to_string();
            // SECURITY: clear transient secret fields before any further ops.
            form.secret = SharedString::from("");
            form.passphrase = SharedString::from("");
            ui.set_cred_form(form);

            if !secret_text.is_empty() {
                let purpose = match kind {
                    CredentialKind::Password => CredentialPurpose::Password,
                    _ => CredentialPurpose::SshKey,
                };
                let key_ref = CredentialRef::new(upserted_id, purpose);
                if let Err(e) = secrets_cs.store(&key_ref, &Secret::from_string(secret_text)) {
                    eprintln!("conman: keychain store failed: {e}");
                }
            }
            if kind == CredentialKind::SshKeyWithPassphrase && !passphrase_text.is_empty() {
                let pp_ref = CredentialRef::new(upserted_id, CredentialPurpose::SshPassphrase);
                if let Err(e) = secrets_cs.store(&pp_ref, &Secret::from_string(passphrase_text)) {
                    eprintln!("conman: keychain passphrase store failed: {e}");
                }
            }

            ui.set_cred_editor_open(false);
            let mut st = state.borrow_mut();
            if let Err(e) = st.keys_panel.reload(repo_cs.as_ref()) {
                eprintln!("conman: reload after cred save failed: {e}");
            }
            refresh_cred_model(&st, &cred_model);
            refresh_cred_name_list(&st, &ui);
        }
    });

    // ── Redraw timer ──────────────────────────────────────────────────────────

    let redraw = Timer::default();
    {
        let state = state.clone();
        let tab_model = tab_model.clone();
        let toast_model = toast_model.clone();
        let toast_next_id = toast_next_id.clone();
        let weak = ui.as_weak();
        redraw.start(TimerMode::Repeated, REDRAW_INTERVAL, move || {
            if let Some(ui) = weak.upgrade() {
                tick(&state, &tab_model, &toast_model, &toast_next_id, &ui);
            }
        });
    }

    // ── Optional headless test hooks ──────────────────────────────────────────

    let mut hooks: Vec<Timer> = Vec::new();

    if let Ok(init) = std::env::var("CONMAN_SSH_AUTOINIT") {
        let parts: Vec<&str> = init.splitn(4, ':').collect();
        if parts.len() >= 3 {
            let username = parts[0].to_owned();
            let password = parts[1].to_owned();
            let host = parts[2].to_owned();
            let port = parts
                .get(3)
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(22);
            let settings = SshSettings {
                host,
                port,
                username,
                auth_method: SshAuthMethod::Password,
            };
            let auth = SshAuthInput::Password(Secret::from_string(password));
            let auto_accept = std::env::var("CONMAN_SSH_AUTO_ACCEPT_KEYS").as_deref() == Ok("1");
            let verifier = Arc::new(UiHostKeyVerifier {
                weak_ui: ui.as_weak(),
                pending: hk_pending.clone(),
                auto_accept,
            });
            open_ssh_tab(&state, &tab_model, &ui, settings, auth, verifier);
        }
    }

    // ── CONMAN_RDP_AUTOINIT (P4.2 test hook) ─────────────────────────────────
    // Format: "username:password:host[:port]" — opens an RDP tab immediately on
    // startup without requiring the user to click a connection in the panel.
    if let Ok(init) = std::env::var("CONMAN_RDP_AUTOINIT") {
        let parts: Vec<&str> = init.splitn(4, ':').collect();
        if parts.len() >= 3 {
            let username = parts[0].to_owned();
            let password = parts[1].to_owned();
            let host = parts[2].to_owned();
            let port = parts
                .get(3)
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(3389);
            let auto_accept = std::env::var("CONMAN_RDP_AUTO_ACCEPT_CERTS").as_deref() == Ok("1");
            let verifier = Arc::new(UiCertVerifier {
                weak_ui: ui.as_weak(),
                pending: cert_pending.clone(),
                auto_accept,
            });
            let settings = RdpSettings {
                host,
                port,
                ..RdpSettings::default()
            };
            let auth = RdpAuthInput {
                username,
                password: Secret::from_string(password),
                domain: None,
            };
            open_rdp_tab(&state, &tab_model, &ui, settings, auth, verifier);
        }
    }

    if let Ok(cmd) = std::env::var("CONMAN_AUTODRIVE") {
        let delay = std::env::var("CONMAN_AUTODRIVE_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(800);
        let state = state.clone();
        let t = Timer::default();
        t.start(
            TimerMode::SingleShot,
            Duration::from_millis(delay),
            move || {
                let st = state.borrow();
                if let Some(tab) = st.tabs.get(st.active) {
                    for ch in cmd.chars() {
                        tab.session.send_input(SessionInput::Key(KeyEvent {
                            key: Key::Char(ch),
                            mods: KeyModifiers::default(),
                        }));
                    }
                    tab.session.send_input(SessionInput::Key(KeyEvent {
                        key: Key::Enter,
                        mods: KeyModifiers::default(),
                    }));
                }
            },
        );
        hooks.push(t);
    }

    if let Ok(script) = std::env::var("CONMAN_AUTORESIZE") {
        for step in script.split(';').filter(|s| !s.is_empty()) {
            if let Some((ms, dims)) = step.split_once(':')
                && let (Ok(ms), Some((w, h))) = (
                    ms.parse::<u64>(),
                    dims.split_once('x')
                        .and_then(|(w, h)| Some((w.parse::<u32>().ok()?, h.parse::<u32>().ok()?))),
                )
            {
                let weak = ui.as_weak();
                let t = Timer::default();
                t.start(
                    TimerMode::SingleShot,
                    Duration::from_millis(ms),
                    move || {
                        if let Some(ui) = weak.upgrade() {
                            ui.window().set_size(slint::PhysicalSize::new(w, h));
                        }
                    },
                );
                hooks.push(t);
            }
        }
    }

    if let Some(ms) = std::env::var("CONMAN_AUTOQUIT_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        let t = Timer::default();
        t.start(TimerMode::SingleShot, Duration::from_millis(ms), || {
            let _ = slint::quit_event_loop();
        });
        hooks.push(t);
    }

    if std::env::var("CONMAN_SHOW_KEYS").as_deref() == Ok("1") {
        ui.set_active_panel(1);
    }

    // P5.1: Auto-split hook (headless screenshot tests).
    // CONMAN_AUTOSPLIT=h|v — trigger an H- or V-split after a short delay.
    // CONMAN_AUTOBROADCAST=1 — enable broadcast at startup.
    if let Ok(dir) = std::env::var("CONMAN_AUTOSPLIT") {
        let layout = if dir.trim().eq_ignore_ascii_case("v") {
            PaneLayout::VSplit
        } else {
            PaneLayout::HSplit
        };
        let state_as = state.clone();
        let tab_model_as = tab_model.clone();
        let weak_as = ui.as_weak();
        let delay = std::env::var("CONMAN_AUTOSPLIT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(600);
        let t = Timer::default();
        t.start(
            TimerMode::SingleShot,
            Duration::from_millis(delay),
            move || {
                if let Some(ui) = weak_as.upgrade() {
                    do_split(&state_as, &tab_model_as, &ui, layout);
                }
            },
        );
        hooks.push(t);
    }

    if std::env::var("CONMAN_AUTOBROADCAST").as_deref() == Ok("1") {
        ui.set_broadcast_active(true);
    }

    ui.run()
}

// ---------------------------------------------------------------------------
// Tab management
// ---------------------------------------------------------------------------

struct PushTabArgs {
    session: Box<dyn Session>,
    connect_info: Option<SshConnectInfo>,
    is_remote: bool,
    /// RDP only: Arc to the drive thread's remote-clipboard slot (for CLIPRDR sync).
    rdp_clipboard: Option<Arc<Mutex<Option<String>>>>,
    title: String,
    initial_status: &'static str,
}

fn push_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    args: PushTabArgs,
) {
    let PushTabArgs {
        session,
        connect_info,
        is_remote,
        rdp_clipboard,
        title,
        initial_status,
    } = args;
    let mut st = state.borrow_mut();
    let scale = st.scale;
    let renderer = TerminalRenderer::with_fonts(
        st.fonts.clone(),
        st.font_size_px,
        scale,
        TerminalTheme::dark(),
    );
    let size = if st.surface_w > 0.0 && st.surface_h > 0.0 {
        grid_for(&renderer, st.surface_w, st.surface_h, scale)
    } else {
        INITIAL_SIZE
    };
    let used: Vec<u32> = st.tabs.iter().map(|t| t.num).collect();
    let num = lowest_free_number(&used);
    st.tabs.push(Tab {
        session,
        renderer,
        last: None,
        last_frame: None,
        rdp_w: 0,
        rdp_h: 0,
        rdp_clipboard,
        cols: size.cols,
        rows: size.rows,
        scale,
        num,
        connect_info,
        is_remote,
        pane_group: PaneGroup::single(),
        extra_panes: Vec::new(),
    });
    st.active = st.tabs.len() - 1;
    let active = st.active;
    drop(st);

    tab_model.push(TabItem {
        title: SharedString::from(title),
        id: num as i32,
        status: SharedString::from(initial_status),
        pane_count: 1,
    });
    ui.set_active_tab(active as i32);
    ui.set_session_status(SharedString::from(initial_status));
}

fn open_local_tab(state: &Rc<RefCell<State>>, tab_model: &Rc<VecModel<TabItem>>, ui: &AppWindow) {
    let (size, ls) = {
        let st = state.borrow();
        (st.current_grid(), st.local_settings.clone())
    };
    let session = match LocalTerminalSession::spawn(&ls, size) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("conman: failed to open terminal: {e}");
            return;
        }
    };
    let used: Vec<u32> = state.borrow().tabs.iter().map(|t| t.num).collect();
    let num = lowest_free_number(&used);
    let title = format!("shell {num}");
    let identity = format!("shell {num}");
    push_tab(
        state,
        tab_model,
        ui,
        PushTabArgs {
            session: Box::new(session),
            connect_info: None,
            is_remote: false,
            rdp_clipboard: None,
            title,
            initial_status: "connected",
        },
    );
    ui.set_session_identity(SharedString::from(identity));
    ui.set_overlay_connecting(false);
    ui.set_overlay_error(false);
    ui.set_launchpad_open(false);
    ui.set_rdp_active(false);
}

fn open_ssh_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    settings: SshSettings,
    auth: SshAuthInput,
    verifier: Arc<dyn HostKeyVerifier>,
) {
    let size = state.borrow().current_grid();
    let identity = format!("{}@{}:{}", settings.username, settings.host, settings.port);
    let title = format!("SSH {}", settings.host);
    let auth_for_reconnect = auth.clone();
    match SshTerminalSession::connect(&settings, auth, verifier, KnownHosts::with_defaults(), size)
    {
        Ok(session) => {
            let ci = SshConnectInfo {
                settings,
                auth: auth_for_reconnect,
            };
            push_tab(
                state,
                tab_model,
                ui,
                PushTabArgs {
                    session: Box::new(session),
                    connect_info: Some(ci),
                    is_remote: true,
                    rdp_clipboard: None,
                    title,
                    initial_status: "connecting",
                },
            );
            ui.set_session_identity(SharedString::from(identity));
            ui.set_overlay_connecting(true);
            ui.set_overlay_error(false);
            ui.set_launchpad_open(false);
            ui.set_connecting_step(0);
            ui.set_rdp_active(false);
        }
        Err(e) => {
            // Carry-over fix (b): surface synchronous setup errors as a Failed
            // tab with the error overlay, not just an eprintln!.
            let reason = e.to_string();
            push_tab(
                state,
                tab_model,
                ui,
                PushTabArgs {
                    session: Box::new(FailedSession::new(reason.clone())),
                    connect_info: None,
                    is_remote: true,
                    rdp_clipboard: None,
                    title,
                    initial_status: "error",
                },
            );
            ui.set_session_identity(SharedString::from(identity));
            ui.set_overlay_connecting(false);
            ui.set_overlay_error(true);
            ui.set_launchpad_open(false);
            ui.set_error_reason(SharedString::from(reason));
            ui.set_error_detail(SharedString::from(""));
            ui.set_rdp_active(false);
        }
    }
}

fn open_rdp_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    settings: RdpSettings,
    auth: RdpAuthInput,
    verifier: Arc<dyn CertVerifier>,
) {
    let title = format!("RDP {}", settings.host);
    let identity = format!("{}@{}:{}", auth.username, settings.host, settings.port);
    // Use a persistent cert store in the OS app-data dir so accepted certs survive restarts.
    let cert_store = {
        let path = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("conman")
            .join("cert_trust.json");
        CertStore::new_persistent(path)
    };
    let session = match RdpSession::connect(&settings, auth, verifier, cert_store) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("conman: RDP connect error: {e}");
            return;
        }
    };
    // Retain a reference to the drive thread's clipboard slot for remote→local sync.
    let rdp_clipboard = Some(Arc::clone(&session.remote_clipboard));
    push_tab(
        state,
        tab_model,
        ui,
        PushTabArgs {
            session: Box::new(session),
            connect_info: None,
            is_remote: true,
            rdp_clipboard,
            title,
            initial_status: "connecting",
        },
    );
    ui.set_session_identity(SharedString::from(identity));
    ui.set_overlay_connecting(true);
    ui.set_overlay_error(false);
    ui.set_launchpad_open(false);
    ui.set_connecting_step(0);
    ui.set_rdp_active(true);
}

fn reconnect_ssh_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    tab_idx: usize,
    settings: SshSettings,
    auth: SshAuthInput,
    verifier: Arc<dyn HostKeyVerifier>,
) {
    let size = state.borrow().current_grid();
    let identity = format!("{}@{}:{}", settings.username, settings.host, settings.port);
    let auth_for_reconnect = auth.clone();
    match SshTerminalSession::connect(&settings, auth, verifier, KnownHosts::with_defaults(), size)
    {
        Ok(new_session) => {
            let ci = SshConnectInfo {
                settings,
                auth: auth_for_reconnect,
            };
            {
                let mut st = state.borrow_mut();
                if let Some(tab) = st.tabs.get_mut(tab_idx) {
                    tab.session = Box::new(new_session);
                    tab.connect_info = Some(ci);
                    tab.last = None;
                }
            }
            if let Some(mut item) = tab_model.row_data(tab_idx) {
                item.status = SharedString::from("connecting");
                tab_model.set_row_data(tab_idx, item);
            }
            ui.set_session_identity(SharedString::from(identity));
            ui.set_overlay_connecting(true);
            ui.set_overlay_error(false);
            ui.set_connecting_step(0);
        }
        Err(e) => {
            eprintln!("conman: SSH reconnect error: {e}");
            ui.set_error_reason(SharedString::from(e.to_string()));
        }
    }
}

/// Reattach a previously detached session to a new tab.
///
/// The detached entry is consumed — the session is moved from `State::detached`
/// back into the tab list.  A new `TerminalRenderer` is created for the session
/// since the old one was discarded when the tab was closed.
fn reattach_session(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    entry: DetachedEntry,
) {
    let label = entry.label.clone();
    let session = entry.session;
    // Use a transient renderer; the session will re-render on first tick.
    let (scale, fonts, font_size_px) = {
        let st = state.borrow();
        (st.scale, st.fonts.clone(), st.font_size_px)
    };
    let renderer = TerminalRenderer::with_fonts(fonts, font_size_px, scale, TerminalTheme::dark());
    let status_dot = match session.status() {
        SessionStatus::Connected => "connected",
        SessionStatus::Connecting => "connecting",
        _ => "disconnected",
    };
    let initial_status: &'static str = status_dot;
    let is_remote = !matches!(session.surface(), Surface::TerminalGrid(_))
        || label.starts_with("SSH ")
        || label.starts_with("RDP ");
    {
        let mut st = state.borrow_mut();
        let used: Vec<u32> = st.tabs.iter().map(|t| t.num).collect();
        let num = lowest_free_number(&used);
        st.tabs.push(Tab {
            session,
            renderer,
            last: None,
            last_frame: None,
            rdp_w: 0,
            rdp_h: 0,
            rdp_clipboard: None,
            cols: INITIAL_SIZE.cols,
            rows: INITIAL_SIZE.rows,
            scale,
            num,
            connect_info: None,
            is_remote,
            pane_group: PaneGroup::single(),
            extra_panes: Vec::new(),
        });
        st.active = st.tabs.len() - 1;
        let active = st.active;
        drop(st);

        let tab_title = format!("[r] {label}");
        tab_model.push(TabItem {
            title: SharedString::from(tab_title),
            id: 0,
            status: SharedString::from(initial_status),
            pane_count: 1,
        });
        ui.set_active_tab(active as i32);
        ui.set_pane_layout(0);
        ui.set_active_pane(0);
        ui.set_session_status(SharedString::from(initial_status));
        ui.set_session_identity(SharedString::from(label.as_str()));
        ui.set_overlay_connecting(false);
        ui.set_overlay_error(false);
        ui.set_launchpad_open(false);
        ui.set_rdp_active(false);
    }
    // Update the detached count.
    let count = state.borrow().detached.len();
    ui.set_detached_count(count as i32);
}

fn select_tab(state: &Rc<RefCell<State>>, ui: &AppWindow, idx: i32) {
    let mut st = state.borrow_mut();
    let idx = idx.max(0) as usize;
    if idx >= st.tabs.len() {
        return;
    }
    st.active = idx;
    ui.set_active_tab(idx as i32);
    let pane_layout = st.tabs[idx].pane_group.layout();
    ui.set_pane_layout(layout_to_int(pane_layout));
    ui.set_active_pane(st.tabs[idx].pane_group.focused() as i32);
    let status = st.tabs[idx].session.status();
    let tab = &st.tabs[idx];
    update_overlays_from_status(ui, tab, &status);
    render_active(&mut st, ui);
}

fn close_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    idx: usize,
) {
    let mut st = state.borrow_mut();
    if idx >= st.tabs.len() {
        return;
    }
    let tab = st.tabs.remove(idx);
    let label = tab_model
        .row_data(idx)
        .map(|t| t.title.to_string())
        .unwrap_or_else(|| format!("tab {}", tab.num));
    // P5.1: Detach all sessions in this tab (keep running in the background).
    // Sessions that have already exited or failed are shut down immediately.
    let should_detach = |s: &dyn Session| {
        !matches!(
            s.status(),
            SessionStatus::Exited(_) | SessionStatus::Failed(_)
        )
    };
    if should_detach(tab.session.as_ref()) {
        st.detached.push(DetachedEntry {
            session: tab.session,
            label: label.clone(),
        });
    } else {
        tab.session.shutdown();
    }
    for (i, ep) in tab.extra_panes.into_iter().enumerate() {
        if should_detach(ep.session.as_ref()) {
            st.detached.push(DetachedEntry {
                session: ep.session,
                label: format!("{} [pane {}]", label, i + 2),
            });
        } else {
            ep.session.shutdown();
        }
    }
    tab_model.remove(idx);

    // Update detached count so the palette can show "Reattach" actions.
    ui.set_detached_count(st.detached.len() as i32);

    if st.tabs.is_empty() {
        drop(st);
        let _ = slint::quit_event_loop();
        return;
    }
    if st.active >= idx && st.active > 0 {
        st.active -= 1;
    }
    if st.active >= st.tabs.len() {
        st.active = st.tabs.len() - 1;
    }
    let active = st.active;
    ui.set_active_tab(active as i32);
    // Reset pane layout when switching to a single-pane tab.
    let pane_layout = st.tabs[active].pane_group.layout();
    ui.set_pane_layout(layout_to_int(pane_layout));
    ui.set_active_pane(st.tabs[active].pane_group.focused() as i32);
    let status = st.tabs[active].session.status();
    update_overlays_from_status(ui, &st.tabs[active], &status);
    render_active(&mut st, ui);
}

fn apply_settled_resize(state: &Rc<RefCell<State>>, ui: &AppWindow) {
    let mut st = state.borrow_mut();
    let scale = st.scale;
    let font_size_px = st.font_size_px;
    let (w, h) = (st.surface_w, st.surface_h);
    if w <= 0.0 || h <= 0.0 {
        return;
    }
    for tab in &mut st.tabs {
        if (tab.scale - scale).abs() > f32::EPSILON {
            tab.renderer.set_scale(font_size_px, scale);
            tab.scale = scale;
        }
        match tab.session.surface() {
            Surface::TerminalGrid(_) => {
                let size = grid_for(&tab.renderer, w, h, scale);
                if size.cols != tab.cols || size.rows != tab.rows {
                    tab.session.resize_cells(size.cols, size.rows);
                    tab.cols = size.cols;
                    tab.rows = size.rows;
                    trace(format_args!(
                        "resize commit -> {}x{} cells (settled)",
                        size.cols, size.rows
                    ));
                }
            }
            Surface::Framebuffer(_) => {
                let pw = (w * scale).round().max(1.0) as u32;
                let ph = (h * scale).round().max(1.0) as u32;
                tab.session.resize_px(pw, ph);
            }
        }
        // P5.1: Resize extra panes using their own reported dimensions.
        for ep in &mut tab.extra_panes {
            if ep.surface_w <= 0.0 || ep.surface_h <= 0.0 {
                continue;
            }
            if (ep.scale - scale).abs() > f32::EPSILON {
                ep.renderer.set_scale(font_size_px, scale);
                ep.scale = scale;
            }
            if matches!(ep.session.surface(), Surface::TerminalGrid(_)) {
                let ep_size = grid_for(&ep.renderer, ep.surface_w, ep.surface_h, scale);
                if ep_size.cols != ep.cols || ep_size.rows != ep.rows {
                    ep.session.resize_cells(ep_size.cols, ep_size.rows);
                    ep.cols = ep_size.cols;
                    ep.rows = ep_size.rows;
                }
            }
        }
    }
    render_active(&mut st, ui);
}

// ---------------------------------------------------------------------------
// P5.1: Split-pane + session-detach helpers
// ---------------------------------------------------------------------------

/// Map a [`PaneLayout`] to the integer used by the `pane-layout` Slint property.
fn layout_to_int(layout: PaneLayout) -> i32 {
    match layout {
        PaneLayout::Single => 0,
        PaneLayout::HSplit => 1,
        PaneLayout::VSplit => 2,
    }
}

/// Split the active tab's pane group, spawning a new local terminal in pane 1.
fn do_split(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    layout: PaneLayout,
) {
    let (new_pane_idx, scale, surface_w, surface_h, fonts, font_size_px, ls) = {
        let mut st = state.borrow_mut();
        let active = st.active;
        let Some(tab) = st.tabs.get_mut(active) else {
            return;
        };
        let Some(new_idx) = tab.pane_group.split(layout) else {
            return; // already at max panes
        };
        (
            new_idx,
            st.scale,
            st.surface_w,
            st.surface_h,
            st.fonts.clone(),
            st.font_size_px,
            st.local_settings.clone(),
        )
    };

    // Spawn a new local terminal for the extra pane (half the width for H-split).
    let renderer = TerminalRenderer::with_fonts(fonts, font_size_px, scale, TerminalTheme::dark());
    let pane_w = match layout {
        PaneLayout::HSplit => (surface_w / 2.0).max(1.0),
        PaneLayout::VSplit => surface_w,
        PaneLayout::Single => surface_w,
    };
    let pane_h = match layout {
        PaneLayout::VSplit => (surface_h / 2.0).max(1.0),
        _ => surface_h,
    };
    let size = if pane_w > 0.0 && pane_h > 0.0 {
        grid_for(&renderer, pane_w, pane_h, scale)
    } else {
        INITIAL_SIZE
    };

    let session = match LocalTerminalSession::spawn(&ls, size) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("conman: split pane spawn failed: {e}");
            // Roll back the pane group change.
            let mut st = state.borrow_mut();
            let active = st.active;
            if let Some(tab) = st.tabs.get_mut(active) {
                // The split already happened in pane_group; close it back.
                let _ = tab.pane_group.close_focused();
            }
            return;
        }
    };

    {
        let mut st = state.borrow_mut();
        let active = st.active;
        if let Some(tab) = st.tabs.get_mut(active) {
            let ep = ExtraPaneState {
                session: Box::new(session),
                renderer,
                last: None,
                cols: size.cols,
                rows: size.rows,
                scale,
                surface_w: pane_w,
                surface_h: pane_h,
            };
            // Defensive: only push when the index is contiguous (2-pane case
            // always satisfies this; a future N-pane extension might not).
            if tab.extra_panes.len() <= new_pane_idx {
                tab.extra_panes.push(ep);
            }
        }
    }

    // Update the tab-strip badge.
    {
        let st = state.borrow();
        let active = st.active;
        if let Some(mut item) = tab_model.row_data(active) {
            item.pane_count = st
                .tabs
                .get(active)
                .map(|t| t.pane_group.count() as i32)
                .unwrap_or(1);
            tab_model.set_row_data(active, item);
        }
    }

    ui.set_pane_layout(layout_to_int(layout));
    ui.set_active_pane(new_pane_idx as i32);
}

/// Close the focused pane in the active tab.
///
/// If `detach` is `true`, the closed pane's session is moved to the detached
/// list (kept running).  If `false`, the session is shut down immediately.
fn do_close_pane(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    detach: bool,
) {
    let (closed_idx, new_layout, new_focused, tab_label) = {
        let mut st = state.borrow_mut();
        let active = st.active;
        let Some(tab) = st.tabs.get_mut(active) else {
            return;
        };
        if tab.pane_group.count() <= 1 {
            return; // nothing to close (caller should use close_tab instead)
        }
        let Some(closed) = tab.pane_group.close_focused() else {
            return;
        };
        let new_layout = tab.pane_group.layout();
        let new_focused = tab.pane_group.focused();
        let label = tab_model
            .row_data(active)
            .map(|t| t.title.to_string())
            .unwrap_or_else(|| format!("tab {}", tab.num));
        (closed, new_layout, new_focused, label)
    };

    // Remove the ExtraPaneState for the closed pane (index = closed_idx - 1
    // since extra_panes is 0-based for pane 1+).
    if closed_idx >= 1 {
        let ep_idx = closed_idx - 1;
        let mut st = state.borrow_mut();
        let active = st.active;
        if let Some(tab) = st.tabs.get_mut(active)
            && ep_idx < tab.extra_panes.len()
        {
            let ep = tab.extra_panes.remove(ep_idx);
            if detach
                && !matches!(
                    ep.session.status(),
                    SessionStatus::Exited(_) | SessionStatus::Failed(_)
                )
            {
                st.detached.push(DetachedEntry {
                    session: ep.session,
                    label: format!("{tab_label} [pane {}]", closed_idx + 1),
                });
                ui.set_detached_count(st.detached.len() as i32);
            } else {
                ep.session.shutdown();
            }
        }
    }

    // Update tab strip badge.
    {
        let st = state.borrow();
        let active = st.active;
        if let Some(mut item) = tab_model.row_data(active) {
            item.pane_count = st
                .tabs
                .get(active)
                .map(|t| t.pane_group.count() as i32)
                .unwrap_or(1);
            tab_model.set_row_data(active, item);
        }
    }

    ui.set_pane_layout(layout_to_int(new_layout));
    ui.set_active_pane(new_focused as i32);
    // Re-render the newly focused pane.
    let mut st = state.borrow_mut();
    render_active(&mut st, ui);
}

fn update_overlays_from_status(ui: &AppWindow, tab: &Tab, status: &SessionStatus) {
    match status {
        SessionStatus::Connecting => {
            ui.set_overlay_connecting(true);
            ui.set_overlay_error(false);
            ui.set_launchpad_open(false);
            ui.set_connecting_step(0);
            ui.set_session_status(SharedString::from("connecting"));
        }
        SessionStatus::Connected => {
            ui.set_overlay_connecting(false);
            ui.set_overlay_error(false);
            ui.set_launchpad_open(false);
            ui.set_session_status(SharedString::from("connected"));
        }
        SessionStatus::Failed(reason) => {
            if tab.is_remote {
                ui.set_overlay_connecting(false);
                ui.set_overlay_error(true);
                ui.set_launchpad_open(false);
                ui.set_error_reason(SharedString::from(reason.as_str()));
                ui.set_error_detail(SharedString::from(""));
            }
            ui.set_session_status(SharedString::from("error"));
        }
        SessionStatus::Disconnected => {
            if tab.is_remote {
                ui.set_overlay_connecting(false);
                ui.set_overlay_error(true);
                ui.set_launchpad_open(false);
                ui.set_error_reason(SharedString::from("Session disconnected"));
                ui.set_error_detail(SharedString::from(""));
            }
            ui.set_session_status(SharedString::from("disconnected"));
        }
        SessionStatus::Exited(exit) => {
            if tab.is_remote {
                ui.set_overlay_connecting(false);
                ui.set_overlay_error(true);
                ui.set_launchpad_open(false);
                ui.set_error_reason(SharedString::from("Remote shell exited"));
                ui.set_error_detail(SharedString::from(if exit.success {
                    "Exit code 0"
                } else {
                    "Non-zero exit code"
                }));
            }
            ui.set_session_status(SharedString::from("disconnected"));
        }
    }
}

fn tick(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    toast_model: &Rc<VecModel<ToastEntry>>,
    toast_next_id: &Rc<RefCell<i32>>,
    ui: &AppWindow,
) {
    let mut st = state.borrow_mut();
    let active = st.active;
    let target = st.target_px();
    let mut to_close: Vec<usize> = Vec::new();

    for i in 0..st.tabs.len() {
        // Drain the latest update for this tab's primary surface.
        match st.tabs[i].session.surface() {
            Surface::TerminalGrid(rx) => {
                if let Some(snap) = drain_latest(rx) {
                    if i == active {
                        let img = render_frame(&mut st.tabs[i], &snap, target);
                        ui.set_frame(img);
                    }
                    st.tabs[i].last = Some(snap);
                }
            }
            Surface::Framebuffer(rx) => {
                if let Some(frame) = drain_latest(rx) {
                    let img = frame_to_image(&frame);
                    if i == active {
                        ui.set_rdp_frame(img.clone());
                    }
                    st.tabs[i].last_frame = Some(img);
                    st.tabs[i].rdp_w = frame.width;
                    st.tabs[i].rdp_h = frame.height;
                }
                // Remote→local clipboard sync: poll slot written by the drive thread.
                if let (Some(ref arc), Some(ref mut cb)) =
                    (st.tabs[i].rdp_clipboard.clone(), st.sys_clipboard.as_mut())
                    && let Ok(mut slot) = arc.try_lock()
                    && let Some(text) = slot.take()
                {
                    let _ = cb.set_text(text);
                }
            }
        }

        // P5.1: Drain extra pane surfaces (pane 1+).
        // Carry-over fix (f): collect extra panes that have Exited/Failed for collapse.
        let mut extra_panes_to_close: Vec<usize> = Vec::new();
        for ep_idx in 0..st.tabs[i].extra_panes.len() {
            match st.tabs[i].extra_panes[ep_idx].session.surface() {
                Surface::TerminalGrid(rx) => {
                    if let Some(snap) = drain_latest(rx) {
                        if i == active {
                            // ep_idx 0 = pane 1 → pane-frame-2.
                            if ep_idx == 0 {
                                let ep = &mut st.tabs[i].extra_panes[ep_idx];
                                let ep_target = if ep.surface_w > 0.0 && ep.surface_h > 0.0 {
                                    Some((
                                        (ep.surface_w * ep.scale).round().max(1.0) as u32,
                                        (ep.surface_h * ep.scale).round().max(1.0) as u32,
                                    ))
                                } else {
                                    None
                                };
                                let img = render_frame_ep(ep, &snap, ep_target);
                                ui.set_pane_frame_2(img);
                            }
                        }
                        st.tabs[i].extra_panes[ep_idx].last = Some(snap);
                    }
                }
                Surface::Framebuffer(rx) => {
                    // Drain but discard (RDP-in-pane is an unimplemented edge case; noted).
                    drain_latest(rx);
                }
            }
            // Auto-collapse extra pane when its local shell exits/fails (fix f).
            let ep_status = st.tabs[i].extra_panes[ep_idx].session.status();
            if matches!(
                ep_status,
                SessionStatus::Exited(_) | SessionStatus::Failed(_)
            ) {
                extra_panes_to_close.push(ep_idx);
            }
        }
        // Collapse exited extra panes (process in reverse order to keep indices valid).
        for &ep_idx in extra_panes_to_close.iter().rev() {
            let ep = st.tabs[i].extra_panes.remove(ep_idx);
            ep.session.shutdown();
            // Close the corresponding pane slot in the group tracker.
            // pane index = ep_idx + 1 (extra_panes are panes 1+).
            // PaneGroup::close_focused requires us to focus the pane first.
            st.tabs[i].pane_group.set_focused(ep_idx + 1);
            st.tabs[i].pane_group.close_focused();
        }
        if !extra_panes_to_close.is_empty() {
            // Tab-strip badge update applies to ALL tabs whose pane count changed,
            // not only the active one (fix j: background tabs must sync their badge).
            if let Some(mut item) = tab_model.row_data(i) {
                let new_count = st.tabs[i].pane_group.count() as i32;
                if item.pane_count != new_count {
                    item.pane_count = new_count;
                    tab_model.set_row_data(i, item);
                }
            }
            if i == active {
                let new_layout = st.tabs[i].pane_group.layout();
                let new_focused = st.tabs[i].pane_group.focused();
                ui.set_pane_layout(layout_to_int(new_layout));
                ui.set_active_pane(new_focused as i32);
            }
        }

        let status = st.tabs[i].session.status();
        let dot = match &status {
            SessionStatus::Connecting => "connecting",
            SessionStatus::Connected => "connected",
            SessionStatus::Failed(_) => "error",
            SessionStatus::Disconnected | SessionStatus::Exited(_) => "disconnected",
        };
        if let Some(mut item) = tab_model.row_data(i)
            && item.status.as_str() != dot
        {
            // P5.3b: emit a toast when a background tab disconnects/fails.
            if i != active
                && st.tabs[i].is_remote
                && matches!(
                    status,
                    SessionStatus::Disconnected | SessionStatus::Failed(_)
                )
            {
                let msg = match &status {
                    SessionStatus::Failed(r) => {
                        format!("{}: connection failed – {r}", item.title.as_str())
                    }
                    _ => format!("{}: disconnected", item.title.as_str()),
                };
                let kind: i32 = if matches!(status, SessionStatus::Failed(_)) {
                    3
                } else {
                    2
                };
                let id = {
                    let mut n = toast_next_id.borrow_mut();
                    let id = *n;
                    *n += 1;
                    id
                };
                toast_model.push(ToastEntry {
                    id,
                    message: SharedString::from(msg),
                    kind,
                });
            }
            item.status = SharedString::from(dot);
            tab_model.set_row_data(i, item);
        }

        if i == active {
            update_overlays_from_status(ui, &st.tabs[i], &status);
        }

        if !st.tabs[i].is_remote && matches!(status, SessionStatus::Exited(_)) {
            to_close.push(i);
        }
    }

    // P5.1: Drain detached sessions to prevent channel saturation.
    let mut detached_to_remove: Vec<usize> = Vec::new();
    for (di, d) in st.detached.iter().enumerate() {
        match d.session.surface() {
            Surface::TerminalGrid(rx) => {
                drain_latest(rx); // discard
            }
            Surface::Framebuffer(rx) => {
                drain_latest(rx); // discard
            }
        }
        if matches!(
            d.session.status(),
            SessionStatus::Exited(_) | SessionStatus::Failed(_)
        ) {
            detached_to_remove.push(di);
        }
    }
    for &di in detached_to_remove.iter().rev() {
        let d = st.detached.remove(di);
        d.session.shutdown();
    }
    if !detached_to_remove.is_empty() {
        ui.set_detached_count(st.detached.len() as i32);
    }

    for &i in to_close.iter().rev() {
        let tab = st.tabs.remove(i);
        tab.session.shutdown();
        for ep in tab.extra_panes {
            ep.session.shutdown();
        }
        tab_model.remove(i);
        if i <= st.active && st.active > 0 {
            st.active -= 1;
        }
    }
    if !to_close.is_empty() {
        if st.tabs.is_empty() {
            drop(st);
            let _ = slint::quit_event_loop();
            return;
        }
        if st.active >= st.tabs.len() {
            st.active = st.tabs.len() - 1;
        }
        let active = st.active;
        ui.set_active_tab(active as i32);
        let status = st.tabs[active].session.status();
        update_overlays_from_status(ui, &st.tabs[active], &status);
        render_active(&mut st, ui);
    }
}

fn render_active(st: &mut State, ui: &AppWindow) {
    let active = st.active;
    let target = st.target_px();
    if let Some(tab) = st.tabs.get_mut(active) {
        match &tab.session.surface() {
            Surface::TerminalGrid(_) => {
                if let Some(snap) = tab.last.clone() {
                    let img = render_frame(tab, &snap, target);
                    ui.set_frame(img);
                }
                ui.set_rdp_active(false);
            }
            Surface::Framebuffer(_) => {
                if let Some(img) = tab.last_frame.clone() {
                    ui.set_rdp_frame(img);
                }
                ui.set_rdp_active(true);
            }
        }
        // P5.1: Render extra pane(s).
        for (ep_idx, ep) in tab.extra_panes.iter_mut().enumerate() {
            if ep_idx == 0 {
                // pane 1 → pane-frame-2
                if let Some(snap) = ep.last.clone() {
                    let ep_target = if ep.surface_w > 0.0 && ep.surface_h > 0.0 {
                        Some((
                            (ep.surface_w * ep.scale).round().max(1.0) as u32,
                            (ep.surface_h * ep.scale).round().max(1.0) as u32,
                        ))
                    } else {
                        None
                    };
                    let img = render_frame_ep(ep, &snap, ep_target);
                    ui.set_pane_frame_2(img);
                }
            }
        }
    }
}

/// Render a frame for an [`ExtraPaneState`] (same as `render_frame` but for the
/// extra pane's renderer + snapshot).
fn render_frame_ep(
    ep: &mut ExtraPaneState,
    snap: &GridSnapshot,
    target: Option<(u32, u32)>,
) -> Image {
    let buf = match target {
        Some((w, h)) => ep.renderer.render_to(snap, w, h),
        None => ep.renderer.render(snap),
    };
    Image::from_rgba8(buf)
}

/// Convert a [`FrameUpdate`] into a `slint::Image`.
///
/// Called on the UI thread only; `Image::from_rgba8` is `!Send`.
fn frame_to_image(frame: &FrameUpdate) -> Image {
    use slint::Rgba8Pixel;
    let mut buf =
        slint::SharedPixelBuffer::<Rgba8Pixel>::new(frame.width as u32, frame.height as u32);
    let bytes = buf.make_mut_bytes();
    let copy_len = bytes.len().min(frame.rgba.len());
    bytes[..copy_len].copy_from_slice(&frame.rgba[..copy_len]);
    Image::from_rgba8(buf)
}

// ---------------------------------------------------------------------------
// Profile form ↔ domain helpers
// ---------------------------------------------------------------------------

fn profile_fields_from_conn(conn: &Connection) -> (i32, String, String, String, i32) {
    match &conn.settings {
        ConnectionSettings::Ssh(s) => (
            0,
            s.host.clone(),
            s.port.to_string(),
            s.username.clone(),
            match s.auth_method {
                SshAuthMethod::PublicKey { .. } => 0,
                SshAuthMethod::Password => 1,
                SshAuthMethod::Agent => 2,
            },
        ),
        ConnectionSettings::Rdp(s) => (
            1,
            s.host.clone(),
            s.port.to_string(),
            s.username.clone().unwrap_or_default(),
            1,
        ),
        ConnectionSettings::Local(_) => (2, String::new(), String::new(), String::new(), 1),
    }
}

fn settings_from_form(form: &ConnProfile) -> ConnectionSettings {
    match form.kind {
        1 => ConnectionSettings::Rdp(RdpSettings {
            host: form.host.to_string(),
            port: form.port.as_str().parse::<u16>().unwrap_or(3389),
            domain: None,
            username: {
                let u = form.username.trim().to_owned();
                if u.is_empty() { None } else { Some(u) }
            },
            // width/height/color_depth added by P4.1; default them until the profile
            // editor surfaces resolution/depth fields (later UI enhancement).
            ..RdpSettings::default()
        }),
        2 => ConnectionSettings::Local(LocalSettings::default()),
        _ => ConnectionSettings::Ssh(SshSettings {
            host: form.host.to_string(),
            port: form.port.as_str().parse::<u16>().unwrap_or(22),
            username: form.username.to_string(),
            auth_method: match form.auth_method {
                0 => SshAuthMethod::PublicKey {
                    key_ref: CredentialRef::new(CredentialId::UNSAVED, CredentialPurpose::SshKey),
                },
                2 => SshAuthMethod::Agent,
                _ => SshAuthMethod::Password,
            },
        }),
    }
}

fn kind_from_form_int(n: i32) -> ConnectionKind {
    match n {
        1 => ConnectionKind::Rdp,
        2 => ConnectionKind::LocalTerminal,
        _ => ConnectionKind::Ssh,
    }
}

fn resolve_cred_from_idx(
    idx: i32,
    credentials: &[Credential],
    folders: &[CredentialFolder],
) -> Option<CredentialId> {
    if idx <= 0 {
        return None;
    }
    // Build the same ordered credential sequence that build_cred_name_list
    // produces and index directly by position (idx-1, because index 0 is the
    // "Inherit" sentinel).  This avoids the name-collision bug that arose from
    // splitting on '/' and doing a first-match lookup.
    let mut ordered: Vec<CredentialId> = Vec::new();
    // Root credentials first (no folder), sorted by name.
    let mut root_creds: Vec<&Credential> = credentials
        .iter()
        .filter(|c| c.folder_id.is_none())
        .collect();
    root_creds.sort_by_key(|c| c.name.as_str());
    for c in root_creds {
        ordered.push(c.id);
    }
    // Credentials in each folder, in the same folder iteration order and name-sorted.
    for folder in folders {
        let mut folder_creds: Vec<&Credential> = credentials
            .iter()
            .filter(|c| c.folder_id == Some(folder.id))
            .collect();
        folder_creds.sort_by_key(|c| c.name.as_str());
        for c in folder_creds {
            ordered.push(c.id);
        }
    }
    ordered.get((idx - 1) as usize).copied()
}

// ---------------------------------------------------------------------------
// Command palette helpers
// ---------------------------------------------------------------------------

/// Collect the dynamic context needed to rebuild the palette:
/// returns `(detached_labels, tab_entries)`.
fn collect_palette_context(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
) -> (Vec<String>, Vec<(usize, String)>) {
    let labels: Vec<String> = state
        .borrow()
        .detached
        .iter()
        .map(|d| d.label.clone())
        .collect();
    let tabs: Vec<(usize, String)> = (0..tab_model.row_count())
        .filter_map(|i| tab_model.row_data(i).map(|t| (i, t.title.to_string())))
        .collect();
    (labels, tabs)
}

fn rebuild_palette_model(
    pal_model: &Rc<VecModel<PaletteAction>>,
    query: &SharedString,
    detached_labels: &[String],
    tab_entries: &[(usize, String)],
) {
    let filtered = filter_palette_actions(query.as_str(), detached_labels, tab_entries);
    while pal_model.row_count() > 0 {
        pal_model.remove(0);
    }
    for a in filtered {
        pal_model.push(a);
    }
}

fn handle_palette_key(
    ui: &AppWindow,
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    pal_model: &Rc<VecModel<PaletteAction>>,
    text: SharedString,
    special: i32,
    mods: i32,
) {
    match special {
        4 => {
            ui.set_palette_open(false);
            ui.set_palette_selected(0);
        }
        5 => {
            let cur = ui.get_palette_selected();
            if cur > 0 {
                ui.set_palette_selected(cur - 1);
            }
        }
        6 => {
            let cur = ui.get_palette_selected();
            let max = (pal_model.row_count() as i32).saturating_sub(1);
            if cur < max {
                ui.set_palette_selected(cur + 1);
            }
        }
        1 => {
            let idx = ui.get_palette_selected() as usize;
            ui.set_palette_open(false);
            ui.set_palette_selected(0);
            dispatch_palette_action(state, tab_model, pal_model, ui, idx);
        }
        3 if mods & 0b1001 == 0 => {
            let q = ui.get_palette_query();
            let new_q: String = {
                let mut s = q.as_str().to_owned();
                s.pop();
                s
            };
            let new_q = SharedString::from(new_q.as_str());
            let (labels, tabs) = collect_palette_context(state, tab_model);
            rebuild_palette_model(pal_model, &new_q, &labels, &tabs);
            ui.set_palette_query(new_q);
            ui.set_palette_selected(0);
        }
        0 if mods & 0b1001 == 0 && !text.is_empty() => {
            let q = ui.get_palette_query();
            let new_q = SharedString::from(format!("{}{}", q.as_str(), text.as_str()).as_str());
            let (labels, tabs) = collect_palette_context(state, tab_model);
            rebuild_palette_model(pal_model, &new_q, &labels, &tabs);
            ui.set_palette_query(new_q);
            ui.set_palette_selected(0);
        }
        _ => {}
    }
}

fn dispatch_palette_action(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    palette_model: &Rc<VecModel<PaletteAction>>,
    ui: &AppWindow,
    idx: usize,
) {
    if idx >= palette_model.row_count() {
        return;
    }
    let action = palette_model.row_data(idx).unwrap_or_default();
    match action.label.as_str() {
        // ── ACTIONS ───────────────────────────────────────────────────────────
        "Quick connect\u{2026}" => ui.set_quick_connect_open(true),
        "New local tab" => open_local_tab(state, tab_model, ui),
        "New SSH connection" => {
            // Open the profile editor pre-set for SSH (kind index 0).
            let st = state.borrow();
            let selected_group_idx = group_name_idx(None, st.conn_tree.groups());
            let cred_idx =
                cred_name_idx(None, st.keys_panel.credentials(), st.keys_panel.folders());
            drop(st);
            let form = ConnProfile {
                id: 0,
                name: SharedString::from(""),
                group_id: 0,
                kind: 0, // SSH
                host: SharedString::from(""),
                port: SharedString::from("22"),
                username: SharedString::from(""),
                auth_method: 1,
                selected_cred_idx: cred_idx,
                effective_cred_name: SharedString::from(""),
                effective_inherited: false,
                selected_group_idx,
            };
            ui.set_profile_form(form);
            ui.set_profile_editor_open(true);
        }
        "New RDP connection" => {
            // Open the profile editor pre-set for RDP (kind index 1).
            let st = state.borrow();
            let selected_group_idx = group_name_idx(None, st.conn_tree.groups());
            let cred_idx =
                cred_name_idx(None, st.keys_panel.credentials(), st.keys_panel.folders());
            drop(st);
            let form = ConnProfile {
                id: 0,
                name: SharedString::from(""),
                group_id: 0,
                kind: 1, // RDP
                host: SharedString::from(""),
                port: SharedString::from("3389"),
                username: SharedString::from(""),
                auth_method: 1,
                selected_cred_idx: cred_idx,
                effective_cred_name: SharedString::from(""),
                effective_inherited: false,
                selected_group_idx,
            };
            ui.set_profile_form(form);
            ui.set_profile_editor_open(true);
        }
        "Close current tab" => {
            let active = state.borrow().active;
            close_tab(state, tab_model, ui, active);
        }
        "Toggle sidebar" => ui.set_sidebar_collapsed(!ui.get_sidebar_collapsed()),
        // ── PANELS ────────────────────────────────────────────────────────────
        "Focus Connections" => ui.set_active_panel(0),
        "Focus Keys" => ui.set_active_panel(1),
        "Open Settings" => ui.set_active_panel(2),
        // ── DATA ──────────────────────────────────────────────────────────────
        // BLOCKED: Import / Export requires P1.2 (json-import-export).
        "Import / Export\u{2026}" => {}
        // ── PANES ─────────────────────────────────────────────────────────────
        "Split horizontal" => do_split(state, tab_model, ui, PaneLayout::HSplit),
        "Split vertical" => do_split(state, tab_model, ui, PaneLayout::VSplit),
        "Close pane" => do_close_pane(state, tab_model, ui, false),
        "Detach session" => do_close_pane(state, tab_model, ui, true),
        "Toggle broadcast" => ui.set_broadcast_active(!ui.get_broadcast_active()),
        // ── TABS (dynamic) ────────────────────────────────────────────────────
        // "Switch to: <title>" — find the first tab with the matching title.
        label if label.starts_with("Switch to: ") => {
            let target = label.trim_start_matches("Switch to: ");
            let pos = (0..tab_model.row_count()).find(|&i| {
                tab_model
                    .row_data(i)
                    .map(|t| t.title.as_str() == target)
                    .unwrap_or(false)
            });
            if let Some(idx) = pos {
                select_tab(state, ui, idx as i32);
            }
        }
        // ── SESSIONS (dynamic) ────────────────────────────────────────────────
        // "Reattach: <label>" — find the matching detached entry.
        label if label.starts_with("Reattach: ") => {
            let target_label = label.trim_start_matches("Reattach: ").to_owned();
            let entry = {
                let mut st = state.borrow_mut();
                let pos = st.detached.iter().position(|d| d.label == target_label);
                pos.map(|p| st.detached.remove(p))
            };
            if let Some(d) = entry {
                reattach_session(state, tab_model, ui, d);
            }
        }
        _ => {}
    }
}

fn initial_palette_actions() -> Vec<PaletteAction> {
    vec![
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: true,
            label: SharedString::from("Quick connect\u{2026}"),
            detail: SharedString::from("SSH quick-connect form"),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EB2D}"), // cod-plug
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: false,
            label: SharedString::from("New local tab"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EA60}"), // cod-add
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: false,
            label: SharedString::from("New SSH connection"),
            detail: SharedString::from("Save a new SSH profile"),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{F0317}"), // md-lan
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: false,
            label: SharedString::from("New RDP connection"),
            detail: SharedString::from("Save a new RDP profile"),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EA7A}"), // cod-vm
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: false,
            label: SharedString::from("Close current tab"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EA76}"), // cod-close
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: false,
            label: SharedString::from("Toggle sidebar"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EB6A}"), // cod-three_bars
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("PANELS"),
            first_in_group: true,
            label: SharedString::from("Focus Connections"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{F0317}"), // md-lan
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("PANELS"),
            first_in_group: false,
            label: SharedString::from("Focus Keys"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EB11}"), // cod-key
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("PANELS"),
            first_in_group: false,
            label: SharedString::from("Open Settings"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{F0493}"), // md-cog
            status: SharedString::from(""),
            selected: false,
        },
        // Import / Export — present so the affordance is discoverable; no-op
        // until P1.2 (json-import-export) is merged and wired here.
        PaletteAction {
            category: SharedString::from("DATA"),
            first_in_group: true,
            label: SharedString::from("Import / Export\u{2026}"),
            detail: SharedString::from("Blocked — requires P1.2 (not yet merged)"),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EBAC}"), // cod-export
            status: SharedString::from(""),
            selected: false,
        },
        // Split-pane + broadcast actions (P5.1).
        PaletteAction {
            category: SharedString::from("PANES"),
            first_in_group: true,
            label: SharedString::from("Split horizontal"),
            detail: SharedString::from("Side-by-side panes"),
            shortcut: SharedString::from("Ctrl+Shift+\\"),
            glyph: SharedString::from("\u{EB56}"), // cod-split_horizontal
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("PANES"),
            first_in_group: false,
            label: SharedString::from("Split vertical"),
            detail: SharedString::from("Stacked panes"),
            shortcut: SharedString::from("Ctrl+Shift+-"),
            glyph: SharedString::from("\u{EB57}"), // cod-split_vertical
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("PANES"),
            first_in_group: false,
            label: SharedString::from("Close pane"),
            detail: SharedString::from("Close pane and shut down session"),
            shortcut: SharedString::from("Ctrl+Shift+W"),
            glyph: SharedString::from("\u{EA76}"), // cod-close
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("PANES"),
            first_in_group: false,
            label: SharedString::from("Detach session"),
            detail: SharedString::from("Close pane, keep session running"),
            shortcut: SharedString::from("Ctrl+Shift+D"),
            glyph: SharedString::from("\u{EAD0}"), // cod-debug_disconnect
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("PANES"),
            first_in_group: false,
            label: SharedString::from("Toggle broadcast"),
            detail: SharedString::from("Fan input to all visible panes"),
            shortcut: SharedString::from("Ctrl+Shift+B"),
            glyph: SharedString::from("\u{EAAD}"), // cod-broadcast
            status: SharedString::from(""),
            selected: false,
        },
    ]
}

fn filter_palette_actions(
    query: &str,
    detached_labels: &[String],
    tab_entries: &[(usize, String)],
) -> Vec<PaletteAction> {
    // Build the full list: static actions + TABS + SESSIONS.
    let mut all = initial_palette_actions();
    // One "Switch to: <title>" entry per open tab.
    for (i, (tab_idx, title)) in tab_entries.iter().enumerate() {
        all.push(PaletteAction {
            category: SharedString::from("TABS"),
            first_in_group: i == 0,
            label: SharedString::from(format!("Switch to: {title}").as_str()),
            detail: SharedString::from(format!("tab {}", tab_idx + 1).as_str()),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EBCB}"), // cod-arrow_swap
            status: SharedString::from(""),
            selected: false,
        });
    }
    // One "Reattach: <label>" per detached session.
    for (i, label) in detached_labels.iter().enumerate() {
        all.push(PaletteAction {
            category: SharedString::from("SESSIONS"),
            first_in_group: i == 0,
            label: SharedString::from(format!("Reattach: {label}").as_str()),
            detail: SharedString::from("Restore detached session to a new tab"),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{EB3A}"), // cod-remote
            status: SharedString::from(""),
            selected: false,
        });
    }
    if query.is_empty() {
        return all;
    }
    let q = query.to_lowercase();
    let mut first_in_group = true;
    all.into_iter()
        .filter(|a| a.label.to_lowercase().contains(&q))
        .map(|mut a| {
            a.first_in_group = first_in_group;
            first_in_group = false;
            a
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cm_session::ExitStatus;
    use std::sync::mpsc;

    #[test]
    fn drain_latest_keeps_only_the_last() {
        let (tx, rx) = mpsc::channel::<i32>();
        assert_eq!(drain_latest(&rx), None);
        tx.send(1).unwrap();
        tx.send(2).unwrap();
        tx.send(3).unwrap();
        assert_eq!(drain_latest(&rx), Some(3));
        assert_eq!(drain_latest(&rx), None);
    }

    #[test]
    fn lowest_free_number_reuses_gaps() {
        assert_eq!(lowest_free_number(&[]), 1);
        assert_eq!(lowest_free_number(&[1, 2, 3]), 4);
        assert_eq!(lowest_free_number(&[1, 3]), 2);
        assert_eq!(lowest_free_number(&[3, 1]), 2);
        assert_eq!(lowest_free_number(&[2, 3]), 1);
    }

    #[test]
    fn grid_for_divides_surface_by_cell() {
        let r = TerminalRenderer::new(FONT_SIZE_PX, 1.0, TerminalTheme::dark());
        let m = r.cell_metrics();
        let size = grid_for(&r, (m.cell_w * 40) as f32, (m.cell_h * 12) as f32, 1.0);
        assert_eq!(size.cols, 40);
        assert_eq!(size.rows, 12);
        let tiny = grid_for(&r, 1.0, 1.0, 1.0);
        assert!(tiny.cols >= 1 && tiny.rows >= 1);
    }

    #[test]
    fn palette_filter_empty_query_returns_all() {
        let all = filter_palette_actions("", &[], &[]);
        let initial = initial_palette_actions();
        assert_eq!(all.len(), initial.len());
        for (a, b) in all.iter().zip(initial.iter()) {
            assert_eq!(a.label, b.label);
        }
    }

    #[test]
    fn palette_filter_no_match_returns_empty() {
        let result = filter_palette_actions("xyzzy_no_such_action", &[], &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn palette_contains_new_ssh_connection() {
        let all = initial_palette_actions();
        assert!(all.iter().any(|a| a.label.as_str() == "New SSH connection"));
    }

    #[test]
    fn palette_contains_new_rdp_connection() {
        let all = initial_palette_actions();
        assert!(all.iter().any(|a| a.label.as_str() == "New RDP connection"));
    }

    #[test]
    fn palette_contains_close_current_tab() {
        let all = initial_palette_actions();
        assert!(all.iter().any(|a| a.label.as_str() == "Close current tab"));
    }

    #[test]
    fn palette_contains_quick_connect() {
        let all = initial_palette_actions();
        assert!(
            all.iter()
                .any(|a| a.label.as_str().starts_with("Quick connect"))
        );
    }

    #[test]
    fn palette_filter_narrows_by_label() {
        let result = filter_palette_actions("sidebar", &[], &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].label.as_str(), "Toggle sidebar");
    }

    #[test]
    fn palette_filter_first_row_always_has_group_header() {
        let result = filter_palette_actions("split", &[], &[]);
        assert!(
            !result.is_empty(),
            "expected at least one result for 'split'"
        );
        assert!(result[0].first_in_group);
    }

    #[test]
    fn palette_filter_includes_reattach_entries() {
        let labels = vec!["server1".to_owned(), "server2".to_owned()];
        let all = filter_palette_actions("", &labels, &[]);
        let reattach: Vec<_> = all
            .iter()
            .filter(|a| a.label.as_str().starts_with("Reattach: "))
            .collect();
        assert_eq!(reattach.len(), 2);
        assert_eq!(reattach[0].label.as_str(), "Reattach: server1");
        assert_eq!(reattach[0].category.as_str(), "SESSIONS");
        assert!(reattach[0].first_in_group);
        assert!(!reattach[1].first_in_group);
    }

    #[test]
    fn palette_filter_reattach_matches_query() {
        let labels = vec!["prod-server".to_owned(), "staging".to_owned()];
        let result = filter_palette_actions("prod", &labels, &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].label.as_str(), "Reattach: prod-server");
    }

    #[test]
    fn palette_filter_includes_switch_to_tab_entries() {
        let tabs = vec![
            (0usize, "web-dev-01".to_owned()),
            (1usize, "local".to_owned()),
        ];
        let all = filter_palette_actions("", &[], &tabs);
        let switch: Vec<_> = all
            .iter()
            .filter(|a| a.label.as_str().starts_with("Switch to: "))
            .collect();
        assert_eq!(switch.len(), 2);
        assert_eq!(switch[0].label.as_str(), "Switch to: web-dev-01");
        assert_eq!(switch[0].category.as_str(), "TABS");
        assert!(switch[0].first_in_group);
    }

    #[test]
    fn palette_filter_switch_to_tab_matches_query() {
        let tabs = vec![
            (0usize, "web-dev-01".to_owned()),
            (1usize, "local".to_owned()),
        ];
        let result = filter_palette_actions("web", &[], &tabs);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].label.as_str(), "Switch to: web-dev-01");
    }

    #[test]
    fn rebuild_palette_model_replaces_not_appends() {
        let model: Rc<VecModel<PaletteAction>> = Rc::new(VecModel::default());
        rebuild_palette_model(&model, &SharedString::from(""), &[], &[]);
        let first_count = model.row_count();
        rebuild_palette_model(&model, &SharedString::from(""), &[], &[]);
        assert_eq!(model.row_count(), first_count);
    }

    #[test]
    fn handle_palette_key_mod_bitmask_plain_is_zero() {
        let plain: i32 = 0;
        let ctrl: i32 = 1;
        let meta: i32 = 8;
        assert_eq!(plain & 0b1001, 0);
        assert_ne!(ctrl & 0b1001, 0);
        assert_ne!(meta & 0b1001, 0);
    }

    #[test]
    fn form_to_ssh_auth_password() {
        let auth_method: i32 = 1;
        let secret_raw = "dummy-password".to_owned();
        let pass_raw = String::new();
        let auth = match auth_method {
            0 => SshAuthInput::Key {
                path: PathBuf::from(&secret_raw),
                passphrase: if pass_raw.is_empty() {
                    None
                } else {
                    Some(Secret::from_string(pass_raw))
                },
            },
            1 => SshAuthInput::Password(Secret::from_string(secret_raw)),
            _ => SshAuthInput::Agent,
        };
        assert!(matches!(auth, SshAuthInput::Password(_)));
    }

    #[test]
    fn form_to_ssh_auth_pubkey_no_passphrase() {
        let auth_method: i32 = 0;
        let secret_raw = "/home/user/.ssh/id_ed25519".to_owned();
        let pass_raw = String::new();
        let auth = match auth_method {
            0 => SshAuthInput::Key {
                path: PathBuf::from(&secret_raw),
                passphrase: if pass_raw.is_empty() {
                    None
                } else {
                    Some(Secret::from_string(pass_raw))
                },
            },
            1 => SshAuthInput::Password(Secret::from_string(secret_raw)),
            _ => SshAuthInput::Agent,
        };
        assert!(matches!(
            auth,
            SshAuthInput::Key {
                passphrase: None,
                ..
            }
        ));
    }

    #[test]
    fn form_to_ssh_auth_agent() {
        let auth_method: i32 = 2;
        let secret_raw = String::new();
        let auth = match auth_method {
            0 => SshAuthInput::Key {
                path: PathBuf::from(&secret_raw),
                passphrase: None,
            },
            1 => SshAuthInput::Password(Secret::from_string(secret_raw)),
            _ => SshAuthInput::Agent,
        };
        assert!(matches!(auth, SshAuthInput::Agent));
    }

    #[test]
    fn ssh_settings_default_port() {
        assert_eq!(SshSettings::DEFAULT_PORT, 22);
    }

    #[test]
    fn session_status_dot_all_variants() {
        let cases: Vec<(SessionStatus, &str)> = vec![
            (SessionStatus::Connecting, "connecting"),
            (SessionStatus::Connected, "connected"),
            (SessionStatus::Failed("test".into()), "error"),
            (SessionStatus::Disconnected, "disconnected"),
            (
                SessionStatus::Exited(ExitStatus {
                    success: true,
                    code: 0,
                }),
                "disconnected",
            ),
        ];
        for (status, expected_dot) in cases {
            let dot = match &status {
                SessionStatus::Connecting => "connecting",
                SessionStatus::Connected => "connected",
                SessionStatus::Failed(_) => "error",
                SessionStatus::Disconnected | SessionStatus::Exited(_) => "disconnected",
            };
            assert_eq!(dot, expected_dot, "status {status:?} -> dot {dot}");
        }
    }

    #[test]
    fn kind_from_form_int_all_variants() {
        assert_eq!(kind_from_form_int(0), ConnectionKind::Ssh);
        assert_eq!(kind_from_form_int(1), ConnectionKind::Rdp);
        assert_eq!(kind_from_form_int(2), ConnectionKind::LocalTerminal);
        assert_eq!(kind_from_form_int(99), ConnectionKind::Ssh);
    }

    #[test]
    fn profile_form_mapping_ssh() {
        let form = ConnProfile {
            id: 0,
            name: SharedString::from("Test"),
            group_id: 0,
            kind: 0,
            host: SharedString::from("10.0.0.1"),
            port: SharedString::from("2222"),
            username: SharedString::from("admin"),
            auth_method: 1,
            selected_cred_idx: 0,
            effective_cred_name: SharedString::from(""),
            effective_inherited: false,
            selected_group_idx: 0,
        };
        let settings = settings_from_form(&form);
        assert!(
            matches!(
                settings,
                ConnectionSettings::Ssh(SshSettings { port: 2222, .. })
            ),
            "SSH settings port should be 2222"
        );
    }

    // ── resolve_cred_from_idx ─────────────────────────────────────────────

    fn make_cred(id: i64, folder_id: Option<i64>, name: &str) -> Credential {
        use cm_core::{CredentialFolderId, CredentialId, CredentialKind};
        Credential {
            id: CredentialId::new(id),
            name: name.to_owned(),
            kind: CredentialKind::Password,
            folder_id: folder_id.map(CredentialFolderId::new),
            username: None,
        }
    }

    fn make_folder(id: i64, name: &str) -> CredentialFolder {
        use cm_core::CredentialFolderId;
        CredentialFolder {
            id: CredentialFolderId::new(id),
            parent_id: None,
            name: name.to_owned(),
            sort: 0,
        }
    }

    #[test]
    fn resolve_cred_idx_zero_returns_none() {
        let creds = vec![make_cred(1, None, "alpha")];
        assert!(resolve_cred_from_idx(0, &creds, &[]).is_none());
    }

    #[test]
    fn resolve_cred_idx_negative_returns_none() {
        let creds = vec![make_cred(1, None, "alpha")];
        assert!(resolve_cred_from_idx(-1, &creds, &[]).is_none());
    }

    #[test]
    fn resolve_cred_idx_position_based_not_name_match() {
        // Two creds with the same bare name but in different folders.
        // Idx 1 = root "ops" (alphabetically first among root creds).
        // Idx 2 = "folder/ops" (would be a false match under old name-split logic).
        let creds = vec![make_cred(10, None, "ops"), make_cred(20, Some(99), "ops")];
        let folders = vec![make_folder(99, "folder")];
        let id1 = resolve_cred_from_idx(1, &creds, &folders);
        let id2 = resolve_cred_from_idx(2, &creds, &folders);
        use cm_core::CredentialId;
        assert_eq!(
            id1,
            Some(CredentialId::new(10)),
            "idx 1 must be root ops (id 10)"
        );
        assert_eq!(
            id2,
            Some(CredentialId::new(20)),
            "idx 2 must be folder ops (id 20)"
        );
        // Old name-split logic would return id 10 for both (first-match on "ops").
        assert_ne!(id1, id2, "position-based lookup must distinguish them");
    }

    #[test]
    fn resolve_cred_idx_out_of_bounds_returns_none() {
        let creds = vec![make_cred(1, None, "only")];
        assert!(resolve_cred_from_idx(99, &creds, &[]).is_none());
    }

    // ── group name list helpers ───────────────────────────────────────────

    fn make_group(id: i64, sort: i64, name: &str) -> Group {
        Group {
            id: GroupId::new(id),
            parent_id: None,
            name: name.to_owned(),
            sort,
            default_credential: None,
        }
    }

    #[test]
    fn group_name_list_sentinel_is_root() {
        let list = build_group_name_list(&[]);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].as_str(), "Root (no group)");
    }

    #[test]
    fn group_name_list_sorted_by_sort_then_id() {
        let groups = vec![
            make_group(3, 1, "C"),
            make_group(1, 0, "A"),
            make_group(2, 0, "B"),
        ];
        let list = build_group_name_list(&groups);
        // sentinel + A(sort=0,id=1) + B(sort=0,id=2) + C(sort=1,id=3)
        assert_eq!(list.len(), 4);
        assert_eq!(list[1].as_str(), "A");
        assert_eq!(list[2].as_str(), "B");
        assert_eq!(list[3].as_str(), "C");
    }

    #[test]
    fn group_id_from_name_idx_zero_is_root() {
        let groups = vec![make_group(1, 0, "G1")];
        assert!(group_id_from_name_idx(0, &groups).is_none());
    }

    #[test]
    fn group_id_from_name_idx_one_is_first_sorted_group() {
        let groups = vec![make_group(7, 0, "G7"), make_group(1, 0, "G1")];
        // G1 sort=0,id=1 comes first; G7 sort=0,id=7 comes second.
        let id = group_id_from_name_idx(1, &groups).expect("should resolve");
        assert_eq!(id, GroupId::new(1));
    }

    #[test]
    fn group_name_idx_round_trips() {
        let groups = vec![make_group(5, 0, "Five"), make_group(2, 0, "Two")];
        // sorted: Two(id=2), Five(id=5) → indices 1, 2
        let idx_two = group_name_idx(Some(GroupId::new(2)), &groups);
        let idx_five = group_name_idx(Some(GroupId::new(5)), &groups);
        assert_eq!(idx_two, 1);
        assert_eq!(idx_five, 2);
        // Round-trip: idx → id → idx.
        let recovered = group_id_from_name_idx(idx_two, &groups).expect("should resolve");
        assert_eq!(recovered, GroupId::new(2));
    }

    #[test]
    fn group_name_idx_none_returns_zero() {
        let groups = vec![make_group(1, 0, "G")];
        assert_eq!(group_name_idx(None, &groups), 0);
    }

    #[test]
    fn palette_contains_import_export_blocked_action() {
        let all = initial_palette_actions();
        let entry = all
            .iter()
            .find(|a| a.label.as_str().contains("Import"))
            .expect("Import/Export palette entry must exist");
        assert!(
            entry.detail.as_str().contains("P1.2"),
            "detail must call out P1.2 as the dependency"
        );
    }

    // ── folder name-list helpers ─────────────────────────────────────────────

    fn make_folder_sorted(id: i64, sort: i64, name: &str) -> CredentialFolder {
        CredentialFolder {
            id: CredentialFolderId::new(id),
            parent_id: None,
            name: name.to_owned(),
            sort,
        }
    }

    /// Groups with parent relationships for cycle tests.
    fn make_group_with_parent(id: i64, parent: Option<i64>, sort: i64, name: &str) -> Group {
        Group {
            id: GroupId::new(id),
            parent_id: parent.map(GroupId::new),
            name: name.to_owned(),
            sort,
            default_credential: None,
        }
    }

    #[test]
    fn folder_id_from_name_idx_zero_is_root() {
        let folders = vec![make_folder_sorted(1, 0, "Work")];
        assert!(folder_id_from_name_idx(0, &folders).is_none());
    }

    #[test]
    fn folder_id_from_name_idx_one_is_first_sorted_folder() {
        let folders = vec![make_folder_sorted(7, 0, "Z"), make_folder_sorted(1, 0, "A")];
        // sorted: A(id=1,sort=0) then Z(id=7,sort=0) → index 1 → id 1
        let id = folder_id_from_name_idx(1, &folders).expect("should resolve");
        assert_eq!(id, CredentialFolderId::new(1));
    }

    #[test]
    fn folder_name_idx_round_trips() {
        let folders = vec![
            make_folder_sorted(5, 0, "Five"),
            make_folder_sorted(2, 0, "Two"),
        ];
        // sorted by (sort=0, id): Two(id=2)→1, Five(id=5)→2
        let idx_two = folder_name_idx(Some(CredentialFolderId::new(2)), &folders);
        let idx_five = folder_name_idx(Some(CredentialFolderId::new(5)), &folders);
        assert_eq!(idx_two, 1);
        assert_eq!(idx_five, 2);
        let recovered = folder_id_from_name_idx(idx_two, &folders).expect("should resolve");
        assert_eq!(recovered, CredentialFolderId::new(2));
    }

    #[test]
    fn folder_name_idx_none_returns_zero() {
        let folders = vec![make_folder_sorted(1, 0, "F")];
        assert_eq!(folder_name_idx(None, &folders), 0);
    }

    // ── is_ancestor_or_self ──────────────────────────────────────────────────

    #[test]
    fn ancestor_self_is_detected() {
        let g = make_group_with_parent(1, None, 0, "G");
        assert!(is_ancestor_or_self(GroupId::new(1), GroupId::new(1), &[g]));
    }

    #[test]
    fn ancestor_direct_child_detected() {
        // hierarchy: A(1) → B(2). Moving A under B would create a cycle.
        let groups = vec![
            make_group_with_parent(1, None, 0, "A"),
            make_group_with_parent(2, Some(1), 0, "B"),
        ];
        // B is a descendant of A, so assigning B as A's parent is a cycle.
        assert!(is_ancestor_or_self(
            GroupId::new(1),
            GroupId::new(2),
            &groups
        ));
    }

    #[test]
    fn ancestor_transitive_descendant_detected() {
        // A(1) → B(2) → C(3). Moving A under C is a deeper cycle.
        let groups = vec![
            make_group_with_parent(1, None, 0, "A"),
            make_group_with_parent(2, Some(1), 0, "B"),
            make_group_with_parent(3, Some(2), 0, "C"),
        ];
        assert!(is_ancestor_or_self(
            GroupId::new(1),
            GroupId::new(3),
            &groups
        ));
    }

    #[test]
    fn ancestor_sibling_is_safe() {
        // A(1) and B(2) are siblings under Root. Moving A under B is safe.
        let groups = vec![
            make_group_with_parent(1, None, 0, "A"),
            make_group_with_parent(2, None, 0, "B"),
        ];
        assert!(!is_ancestor_or_self(
            GroupId::new(1),
            GroupId::new(2),
            &groups
        ));
    }

    #[test]
    fn ancestor_unrelated_group_is_safe() {
        // B(2) → C(3). Moving A(1) under C is fine; A is not in B/C's chain.
        let groups = vec![
            make_group_with_parent(1, None, 0, "A"),
            make_group_with_parent(2, None, 0, "B"),
            make_group_with_parent(3, Some(2), 0, "C"),
        ];
        assert!(!is_ancestor_or_self(
            GroupId::new(1),
            GroupId::new(3),
            &groups
        ));
    }
}

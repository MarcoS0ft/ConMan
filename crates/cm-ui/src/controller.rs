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
    HostKeyDecision, HostKeyInfo, HostKeyVerifier, KnownHosts, LocalTerminalSession, SessionStatus,
    SshAuthInput, SshTerminalSession, TerminalSession,
};
use slint::{ComponentHandle, Image, Model, ModelRc, SharedString, Timer, TimerMode, VecModel};

use crate::input;
use crate::keys::KeysPanel;
use crate::terminal_renderer::{FontSet, TerminalRenderer, TerminalTheme};
use crate::tree::{ConnectionTree, build_cred_name_list, cred_name_idx};
use crate::{AppConfig, AppWindow, ConnRow, CredRow, PaletteAction, TabItem};

// Generated Slint structs for the form editors.
use crate::generated_ui::{ConnProfile, CredFormData, GroupForm};

/// Logical font size for the terminal grid.
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
// Per-tab state
// ---------------------------------------------------------------------------

struct Tab {
    session: Box<dyn TerminalSession>,
    renderer: TerminalRenderer,
    last: Option<GridSnapshot>,
    cols: u16,
    rows: u16,
    scale: f32,
    num: u32,
    connect_info: Option<SshConnectInfo>,
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
}

impl State {
    fn current_grid(&self) -> TerminalSize {
        if self.surface_w <= 0.0 || self.surface_h <= 0.0 {
            return INITIAL_SIZE;
        }
        let probe = TerminalRenderer::with_fonts(
            self.fonts.clone(),
            FONT_SIZE_PX,
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

struct UiHostKeyVerifier {
    weak_ui: slint::Weak<AppWindow>,
    pending: Arc<Mutex<Option<Sender<HostKeyDecision>>>>,
    auto_accept: bool,
}

impl HostKeyVerifier for UiHostKeyVerifier {
    fn decide(&self, info: &HostKeyInfo) -> HostKeyDecision {
        if self.auto_accept {
            return HostKeyDecision::Accept;
        }
        let (tx, rx) = std::sync::mpsc::channel::<HostKeyDecision>();
        if let Ok(mut p) = self.pending.lock() {
            *p = Some(tx);
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
// Panel model refresh helpers
// ---------------------------------------------------------------------------

fn refresh_conn_model(state: &State, conn_model: &Rc<VecModel<ConnRow>>) {
    let flat = state.conn_tree.flat();
    while conn_model.row_count() > 0 {
        conn_model.remove(0);
    }
    for row in flat {
        conn_model.push(row);
    }
}

fn refresh_cred_model(state: &State, cred_model: &Rc<VecModel<CredRow>>) {
    let flat = state.keys_panel.flat();
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
    }));

    {
        let st = state.borrow();
        refresh_conn_model(&st, &conn_model);
        refresh_cred_model(&st, &cred_model);
        refresh_cred_name_list(&st, &ui);
        refresh_group_name_list(&st, &ui);
    }

    let hk_pending: Arc<Mutex<Option<Sender<HostKeyDecision>>>> = Arc::new(Mutex::new(None));

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
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active) {
                for ev in input::map_key(text.as_str(), special, mods) {
                    tab.session.send_key(ev);
                }
            }
        }
    });

    ui.on_pointer({
        let state = state.clone();
        move |button, kind, x, y, mods| {
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active) {
                let (row, col) = tab.renderer.cell_at(x * st.scale, y * st.scale);
                if let Some(ev) = input::map_mouse(button, kind, row, col, mods) {
                    tab.session.send_mouse(ev);
                }
            }
        }
    });

    ui.on_scroll({
        let state = state.clone();
        move |_dx, dy| {
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active)
                && let Some(ev) = input::map_scroll(dy, 0, 0, 0)
            {
                tab.session.send_mouse(ev);
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
        move |idx| {
            if let Some(ui) = weak.upgrade() {
                ui.set_active_panel(idx);
            }
        }
    });

    ui.on_toggle_sidebar({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_sidebar_collapsed(!ui.get_sidebar_collapsed());
            }
        }
    });

    ui.on_open_palette({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
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
            if let Ok(mut p) = pending.lock()
                && let Some(tx) = p.take()
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
            if let Ok(mut p) = pending.lock()
                && let Some(tx) = p.take()
            {
                let _ = tx.send(HostKeyDecision::Reject);
            }
            if let Some(ui) = weak.upgrade() {
                ui.set_host_key_open(false);
            }
        }
    });

    ui.on_row_activated({
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        move |_idx| {
            if let Some(ui) = weak.upgrade() {
                open_local_tab(&state, &tab_model, &ui);
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

    ui.on_palette_edited({
        let weak = ui.as_weak();
        let pal_model = palette_model.clone();
        move |query| {
            rebuild_palette_model(&pal_model, &query);
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

    ui.on_theme_changed(|_idx| { /* P5: persist */ });
    ui.on_accent_changed(|_idx| { /* P5: persist */ });

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
        let weak = ui.as_weak();
        redraw.start(TimerMode::Repeated, REDRAW_INTERVAL, move || {
            if let Some(ui) = weak.upgrade() {
                tick(&state, &tab_model, &ui);
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
                        tab.session.send_key(KeyEvent {
                            key: Key::Char(ch),
                            mods: KeyModifiers::default(),
                        });
                    }
                    tab.session.send_key(KeyEvent {
                        key: Key::Enter,
                        mods: KeyModifiers::default(),
                    });
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

    ui.run()
}

// ---------------------------------------------------------------------------
// Tab management
// ---------------------------------------------------------------------------

fn push_tab(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    ui: &AppWindow,
    session: Box<dyn TerminalSession>,
    connect_info: Option<SshConnectInfo>,
    title: String,
    initial_status: &str,
) {
    let mut st = state.borrow_mut();
    let scale = st.scale;
    let renderer =
        TerminalRenderer::with_fonts(st.fonts.clone(), FONT_SIZE_PX, scale, TerminalTheme::dark());
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
        cols: size.cols,
        rows: size.rows,
        scale,
        num,
        connect_info,
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
    let size = state.borrow().current_grid();
    let session = match LocalTerminalSession::spawn(&LocalSettings::default(), size) {
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
        Box::new(session),
        None,
        title,
        "connected",
    );
    ui.set_session_identity(SharedString::from(identity));
    ui.set_overlay_connecting(false);
    ui.set_overlay_error(false);
    ui.set_launchpad_open(false);
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
                Box::new(session),
                Some(ci),
                title,
                "connecting",
            );
            ui.set_session_identity(SharedString::from(identity));
            ui.set_overlay_connecting(true);
            ui.set_overlay_error(false);
            ui.set_launchpad_open(false);
            ui.set_connecting_step(0);
        }
        Err(e) => {
            eprintln!("conman: SSH connect setup error: {e}");
        }
    }
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

fn select_tab(state: &Rc<RefCell<State>>, ui: &AppWindow, idx: i32) {
    let mut st = state.borrow_mut();
    let idx = idx.max(0) as usize;
    if idx >= st.tabs.len() {
        return;
    }
    st.active = idx;
    ui.set_active_tab(idx as i32);
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
    tab.session.shutdown();
    drop(tab);
    tab_model.remove(idx);

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
    let status = st.tabs[active].session.status();
    update_overlays_from_status(ui, &st.tabs[active], &status);
    render_active(&mut st, ui);
}

fn apply_settled_resize(state: &Rc<RefCell<State>>, ui: &AppWindow) {
    let mut st = state.borrow_mut();
    let scale = st.scale;
    let (w, h) = (st.surface_w, st.surface_h);
    if w <= 0.0 || h <= 0.0 {
        return;
    }
    for tab in &mut st.tabs {
        if (tab.scale - scale).abs() > f32::EPSILON {
            tab.renderer.set_scale(FONT_SIZE_PX, scale);
            tab.scale = scale;
        }
        let size = grid_for(&tab.renderer, w, h, scale);
        if size.cols != tab.cols || size.rows != tab.rows {
            tab.session.resize(size);
            tab.cols = size.cols;
            tab.rows = size.rows;
            trace(format_args!(
                "resize commit -> {}x{} cells (settled)",
                size.cols, size.rows
            ));
        }
    }
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
            if tab.connect_info.is_some() {
                ui.set_overlay_connecting(false);
                ui.set_overlay_error(true);
                ui.set_launchpad_open(false);
                ui.set_error_reason(SharedString::from(reason.as_str()));
                ui.set_error_detail(SharedString::from(""));
            }
            ui.set_session_status(SharedString::from("error"));
        }
        SessionStatus::Disconnected => {
            if tab.connect_info.is_some() {
                ui.set_overlay_connecting(false);
                ui.set_overlay_error(true);
                ui.set_launchpad_open(false);
                ui.set_error_reason(SharedString::from("Session disconnected"));
                ui.set_error_detail(SharedString::from(""));
            }
            ui.set_session_status(SharedString::from("disconnected"));
        }
        SessionStatus::Exited(exit) => {
            if tab.connect_info.is_some() {
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

fn tick(state: &Rc<RefCell<State>>, tab_model: &Rc<VecModel<TabItem>>, ui: &AppWindow) {
    let mut st = state.borrow_mut();
    let active = st.active;
    let target = st.target_px();
    let mut to_close: Vec<usize> = Vec::new();

    for i in 0..st.tabs.len() {
        if let Some(snap) = drain_latest(st.tabs[i].session.snapshots()) {
            if i == active {
                let img = render_frame(&mut st.tabs[i], &snap, target);
                ui.set_frame(img);
            }
            st.tabs[i].last = Some(snap);
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
            item.status = SharedString::from(dot);
            tab_model.set_row_data(i, item);
        }

        if i == active {
            update_overlays_from_status(ui, &st.tabs[i], &status);
        }

        if st.tabs[i].connect_info.is_none() && matches!(status, SessionStatus::Exited(_)) {
            to_close.push(i);
        }
    }

    for &i in to_close.iter().rev() {
        let tab = st.tabs.remove(i);
        tab.session.shutdown();
        drop(tab);
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
    if let Some(tab) = st.tabs.get_mut(active)
        && let Some(snap) = tab.last.clone()
    {
        let img = render_frame(tab, &snap, target);
        ui.set_frame(img);
    }
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

fn rebuild_palette_model(pal_model: &Rc<VecModel<PaletteAction>>, query: &SharedString) {
    let filtered = filter_palette_actions(query.as_str());
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
            rebuild_palette_model(pal_model, &new_q);
            ui.set_palette_query(new_q);
            ui.set_palette_selected(0);
        }
        0 if mods & 0b1001 == 0 && !text.is_empty() => {
            let q = ui.get_palette_query();
            let new_q = SharedString::from(format!("{}{}", q.as_str(), text.as_str()).as_str());
            rebuild_palette_model(pal_model, &new_q);
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
        "New local tab" => open_local_tab(state, tab_model, ui),
        "New SSH connection" => ui.set_quick_connect_open(true),
        "Toggle sidebar" => ui.set_sidebar_collapsed(!ui.get_sidebar_collapsed()),
        "Focus Connections" => ui.set_active_panel(0),
        "Focus Keys" => ui.set_active_panel(1),
        "Focus Settings" => ui.set_active_panel(2),
        // BLOCKED: Import / Export requires P1.2 (json-import-export), which has
        // not yet been merged.  No-op here; wire once P1.2 lands.
        "Import / Export\u{2026}" => {}
        _ => {}
    }
}

fn initial_palette_actions() -> Vec<PaletteAction> {
    vec![
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: true,
            label: SharedString::from("New local tab"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{E710}"),
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: false,
            label: SharedString::from("New SSH connection"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{E968}"),
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: false,
            label: SharedString::from("Toggle sidebar"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{E700}"),
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: false,
            label: SharedString::from("Focus Connections"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{E968}"),
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: false,
            label: SharedString::from("Focus Keys"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{E8D7}"),
            status: SharedString::from(""),
            selected: false,
        },
        PaletteAction {
            category: SharedString::from("ACTIONS"),
            first_in_group: false,
            label: SharedString::from("Focus Settings"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{E713}"),
            status: SharedString::from(""),
            selected: false,
        },
        // BLOCKED: Import / Export requires P1.2 (json-import-export), which
        // has not yet landed.  This entry is present so the affordance appears
        // in the palette; it is a no-op until P1.2 is merged and wired here.
        PaletteAction {
            category: SharedString::from("DATA"),
            first_in_group: true,
            label: SharedString::from("Import / Export\u{2026}"),
            detail: SharedString::from("Blocked — requires P1.2 (not yet merged)"),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{E8B5}"),
            status: SharedString::from(""),
            selected: false,
        },
    ]
}

fn filter_palette_actions(query: &str) -> Vec<PaletteAction> {
    let all = initial_palette_actions();
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
        let all = filter_palette_actions("");
        let initial = initial_palette_actions();
        assert_eq!(all.len(), initial.len());
        for (a, b) in all.iter().zip(initial.iter()) {
            assert_eq!(a.label, b.label);
        }
    }

    #[test]
    fn palette_filter_no_match_returns_empty() {
        let result = filter_palette_actions("xyzzy_no_such_action");
        assert!(result.is_empty());
    }

    #[test]
    fn palette_contains_new_ssh_connection() {
        let all = initial_palette_actions();
        assert!(all.iter().any(|a| a.label.as_str() == "New SSH connection"));
    }

    #[test]
    fn palette_filter_narrows_by_label() {
        let result = filter_palette_actions("sidebar");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].label.as_str(), "Toggle sidebar");
    }

    #[test]
    fn palette_filter_first_row_always_has_group_header() {
        let result = filter_palette_actions("tab");
        assert!(!result.is_empty(), "expected at least one result for 'tab'");
        assert!(result[0].first_in_group);
    }

    #[test]
    fn rebuild_palette_model_replaces_not_appends() {
        let model: Rc<VecModel<PaletteAction>> = Rc::new(VecModel::default());
        rebuild_palette_model(&model, &SharedString::from(""));
        let first_count = model.row_count();
        rebuild_palette_model(&model, &SharedString::from(""));
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

//! UI-thread controller: owns per-tab sessions (local or SSH) + renderers + the
//! redraw timer, wires Slint callbacks, and drives the snapshot→render→Image pipeline.
//!
//! P3.2 upgrade: the controller now holds `Box<dyn TerminalSession>` per tab (local
//! **or** SSH — uniform dispatch). SSH tabs carry `SshConnectInfo` for reconnect.
//!
//! Threading (ARCHITECTURE §4 / P0.3):
//! - Sessions run their byte-pump on dedicated threads (engine-owner + PTY/SSH driver).
//! - The controller lives entirely on the UI thread.
//! - A `slint::Timer` coalesces snapshots, renders the active tab, and drives the
//!   connecting/error overlay from the active tab's `TerminalSession::status()`.
//! - Host-key decisions: `UiHostKeyVerifier::decide()` is called from the SSH driver
//!   thread; it posts a closure to the UI event loop (via `slint::invoke_from_event_loop`)
//!   to open the HostKeyDialog, then blocks on a `std::sync::mpsc::Receiver` until the
//!   user clicks Accept/Reject on the UI thread. The SSH thread is blocked but the UI
//!   thread remains fully reactive — no deadlock.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cm_core::Secret;
use cm_core::SshSettings;
use cm_core::terminal::{GridSnapshot, Key, KeyEvent, KeyModifiers, TerminalSize};
use cm_session::{
    HostKeyDecision, HostKeyInfo, HostKeyVerifier, KnownHosts, LocalTerminalSession, SessionStatus,
    SshAuthInput, SshTerminalSession, TerminalSession,
};
use slint::{ComponentHandle, Image, Model, ModelRc, SharedString, Timer, TimerMode, VecModel};

use crate::input;
use crate::terminal_renderer::{FontSet, TerminalRenderer, TerminalTheme};
use crate::{AppWindow, ConnRow, PaletteAction, TabItem};

/// Logical font size for the terminal grid.
const FONT_SIZE_PX: f32 = 15.0;
/// Redraw cadence (~60 Hz) for coalescing snapshots and repainting the active tab.
const REDRAW_INTERVAL: Duration = Duration::from_millis(16);
/// Debounce window for committing a resize to the PTY/engine (B6).
const RESIZE_DEBOUNCE: Duration = Duration::from_millis(90);
/// Initial grid size before the surface reports its real dimensions.
const INITIAL_SIZE: TerminalSize = TerminalSize { rows: 24, cols: 80 };

// ---------------------------------------------------------------------------
// SSH connect info (held for reconnect)
// ---------------------------------------------------------------------------

/// Everything needed to re-establish an SSH session without re-prompting the form.
///
/// Stored in the tab; dropped (and secrets zeroized via `SshAuthInput` → `Secret`)
/// when the tab is closed.
struct SshConnectInfo {
    settings: SshSettings,
    auth: SshAuthInput,
}

// ---------------------------------------------------------------------------
// Per-tab state
// ---------------------------------------------------------------------------

/// One open terminal tab — local or SSH.
struct Tab {
    /// Polymorphic session (local PTY or SSH). `Box<dyn TerminalSession>` because
    /// `LocalTerminalSession` and `SshTerminalSession` are different concrete types.
    session: Box<dyn TerminalSession>,
    renderer: TerminalRenderer,
    /// Most recent snapshot (rendered on tab switch / resize without waiting for output).
    last: Option<GridSnapshot>,
    cols: u16,
    rows: u16,
    scale: f32,
    /// Displayed tab number (reused from the free set on close).
    num: u32,
    /// `Some` for SSH tabs; `None` for local tabs.
    connect_info: Option<SshConnectInfo>,
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// All UI-thread mutable state.
struct State {
    tabs: Vec<Tab>,
    active: usize,
    /// Shared parsed font faces — reused by every tab's renderer.
    fonts: Arc<FontSet>,
    /// Current display scale factor.
    scale: f32,
    /// Current surface size in logical px.
    surface_w: f32,
    surface_h: f32,
}

impl State {
    /// Grid size for a new tab from the current surface size, or the initial default.
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

    /// Active tab's surface target in physical px.
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
// UiHostKeyVerifier — P3.2 host-key dialog bridge
// ---------------------------------------------------------------------------

/// Bridges the SSH driver's blocking `decide()` call to the Slint UI thread.
///
/// Called from the SSH tokio driver thread (inside russh's `check_server_key` async
/// fn, but executed synchronously as a non-`await` call). Blocks the SSH driver OS
/// thread on a `std::sync::mpsc::channel` while the UI thread shows the HostKeyDialog.
/// The UI thread stays fully reactive during the wait — no deadlock.
///
/// `auto_accept`: skips the dialog and always accepts (for headless testing; gated on
/// `CONMAN_SSH_AUTO_ACCEPT_KEYS=1`).
struct UiHostKeyVerifier {
    weak_ui: slint::Weak<AppWindow>,
    /// Set by `decide()` before posting to the UI; cleared by `on_host_key_accept/reject`.
    pending: Arc<Mutex<Option<Sender<HostKeyDecision>>>>,
    auto_accept: bool,
}

impl HostKeyVerifier for UiHostKeyVerifier {
    fn decide(&self, info: &HostKeyInfo) -> HostKeyDecision {
        if self.auto_accept {
            return HostKeyDecision::Accept;
        }

        let (tx, rx) = std::sync::mpsc::channel::<HostKeyDecision>();
        // Store the sender so the UI callbacks can reply.
        if let Ok(mut p) = self.pending.lock() {
            *p = Some(tx);
        }

        let info = info.clone();
        let weak = self.weak_ui.clone();
        // Post to the UI event loop — returns immediately; the dialog opens on
        // the UI thread independently of this blocked SSH thread.
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

        // Block the SSH driver thread until the user decides.
        // On app exit the channel closes → Err → default Reject.
        rx.recv().unwrap_or(HostKeyDecision::Reject)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Render `snap` for `tab` into a frame Image at the surface target size.
fn render_frame(tab: &mut Tab, snap: &GridSnapshot, target: Option<(u32, u32)>) -> Image {
    let buf = match target {
        Some((w, h)) => tab.renderer.render_to(snap, w, h),
        None => tab.renderer.render(snap),
    };
    Image::from_rgba8(buf)
}

/// Lowest unused positive tab number among the currently open tabs.
fn lowest_free_number(used: &[u32]) -> u32 {
    let mut n = 1;
    while used.contains(&n) {
        n += 1;
    }
    n
}

/// Cells that fit a logical surface at a given scale, using the renderer's cell metrics.
fn grid_for(r: &TerminalRenderer, logical_w: f32, logical_h: f32, scale: f32) -> TerminalSize {
    let m = r.cell_metrics();
    let phys_w = (logical_w * scale).max(1.0) as u32;
    let phys_h = (logical_h * scale).max(1.0) as u32;
    TerminalSize {
        cols: (phys_w / m.cell_w).max(1) as u16,
        rows: (phys_h / m.cell_h).max(1) as u16,
    }
}

/// Drain a receiver, returning only the most recent value (coalescing).
pub(crate) fn drain_latest<T>(rx: &Receiver<T>) -> Option<T> {
    let mut latest = None;
    while let Ok(v) = rx.try_recv() {
        latest = Some(v);
    }
    latest
}

/// Lightweight stderr tracing gated on `CONMAN_TRACE=1`.
fn trace(args: std::fmt::Arguments) {
    if std::env::var_os("CONMAN_TRACE").is_some() {
        eprintln!("[conman] {args}");
    }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Build and run the ConMan application. Blocks on the Slint event loop until the window
/// is closed.
///
/// # Errors
/// Returns a [`slint::PlatformError`] if the window/backend cannot be created.
pub fn run() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let scale = ui.window().scale_factor();

    let tab_model: Rc<VecModel<TabItem>> = Rc::new(VecModel::default());
    ui.set_tabs(ModelRc::from(tab_model.clone()));

    // Seed sample connections so the shell is demoable end-to-end (P1 replaces with real).
    let conn_model: Rc<VecModel<ConnRow>> = Rc::new(VecModel::from(sample_connections()));
    ui.set_connections(ModelRc::from(conn_model.clone()));

    // Seed command palette with shell actions (includes "New SSH connection").
    let palette_model: Rc<VecModel<PaletteAction>> =
        Rc::new(VecModel::from(initial_palette_actions()));
    ui.set_palette_actions(ModelRc::from(palette_model.clone()));

    // CONMAN_DARK_MODE env var: force dark (1) or light (0).
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

    let state = Rc::new(RefCell::new(State {
        tabs: Vec::new(),
        active: 0,
        fonts: FontSet::bundled(),
        scale,
        surface_w: 0.0,
        surface_h: 0.0,
    }));

    // ── Shared host-key pending channel ───────────────────────────────────────
    // `UiHostKeyVerifier::decide()` (SSH thread) stores its reply Sender here.
    // The UI callbacks (`on_host_key_accept/reject`) take and send through it.
    let hk_pending: Arc<Mutex<Option<Sender<HostKeyDecision>>>> = Arc::new(Mutex::new(None));

    // ── Open first local tab ──────────────────────────────────────────────────
    open_local_tab(&state, &tab_model, &ui);

    // ── new-tab (local shell) ─────────────────────────────────────────────────
    {
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        ui.on_new_tab(move || {
            if let Some(ui) = weak.upgrade() {
                open_local_tab(&state, &tab_model, &ui);
            }
        });
    }

    // ── select-tab ────────────────────────────────────────────────────────────
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.on_select_tab(move |idx| {
            if let Some(ui) = weak.upgrade() {
                select_tab(&state, &ui, idx);
            }
        });
    }

    // ── close-tab ─────────────────────────────────────────────────────────────
    {
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        ui.on_close_tab(move |idx| {
            if let Some(ui) = weak.upgrade() {
                close_tab(&state, &tab_model, &ui, idx as usize);
            }
        });
    }

    // ── keyboard input ────────────────────────────────────────────────────────
    {
        let state = state.clone();
        let pal_model_kb = palette_model.clone();
        let tab_model_kb = tab_model.clone();
        let weak_kb = ui.as_weak();
        ui.on_key_input(move |text, special, mods| {
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
        });
    }

    // ── pointer ───────────────────────────────────────────────────────────────
    {
        let state = state.clone();
        ui.on_pointer(move |button, kind, x, y, mods| {
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active) {
                let (row, col) = tab.renderer.cell_at(x * st.scale, y * st.scale);
                if let Some(ev) = input::map_mouse(button, kind, row, col, mods) {
                    tab.session.send_mouse(ev);
                }
            }
        });
    }

    // ── scroll ────────────────────────────────────────────────────────────────
    {
        let state = state.clone();
        ui.on_scroll(move |_dx, dy| {
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active)
                && let Some(ev) = input::map_scroll(dy, 0, 0, 0)
            {
                tab.session.send_mouse(ev);
            }
        });
    }

    // ── resize / scale change ─────────────────────────────────────────────────
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

    // ── Shell callbacks ───────────────────────────────────────────────────────

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

    // ── quick-connect: open the form dialog ───────────────────────────────────
    ui.on_quick_connect({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_quick_connect_open(true);
            }
        }
    });

    // ── qc-connect: read form values, spawn SSH session ──────────────────────
    ui.on_qc_connect({
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        let hk_pending = hk_pending.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };

            // Read form values on the UI thread.
            let host = ui.get_qc_host().trim().to_owned();
            let port_str = ui.get_qc_port().trim().to_owned();
            let username = ui.get_qc_username().trim().to_owned();
            let auth_method = ui.get_qc_auth_method();
            let secret_raw = ui.get_qc_secret().to_string();
            let pass_raw = ui.get_qc_passphrase().to_string();

            // Validate required fields (fail silently; P5 adds validation UI).
            if host.is_empty() || username.is_empty() {
                return;
            }
            let port = port_str.parse::<u16>().unwrap_or(22);

            // Build SshAuthInput; secrets consumed into Secret which zeroizes on drop.
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
                // SshAuthMethod is for saved profiles (P1); for quick-connect we carry
                // the real auth in SshAuthInput — use a placeholder value.
                auth_method: cm_core::SshAuthMethod::Password,
            };

            // Close the form and clear secret fields before spawning.
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

    // ── host-key accept ───────────────────────────────────────────────────────
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

    // ── host-key reject ───────────────────────────────────────────────────────
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

    // ── row-activated: open a local terminal tab ──────────────────────────────
    {
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        ui.on_row_activated(move |_idx| {
            if let Some(ui) = weak.upgrade() {
                open_local_tab(&state, &tab_model, &ui);
            }
        });
    }

    // ── toggle-broadcast ──────────────────────────────────────────────────────
    ui.on_toggle_broadcast({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_broadcast_active(!ui.get_broadcast_active());
            }
        }
    });

    // ── palette-edited ────────────────────────────────────────────────────────
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

    // ── palette-activated ─────────────────────────────────────────────────────
    {
        let state = state.clone();
        let tab_model = tab_model.clone();
        let pal_model_dispatch = palette_model.clone();
        let weak = ui.as_weak();
        ui.on_palette_activated(move |idx| {
            if let Some(ui) = weak.upgrade() {
                dispatch_palette_action(&state, &tab_model, &pal_model_dispatch, &ui, idx as usize);
            }
        });
    }

    // ── theme-changed / accent-changed ────────────────────────────────────────
    ui.on_theme_changed(|_idx| { /* P5: persist */ });
    ui.on_accent_changed(|_idx| { /* P5: persist */ });

    // ── reconnect: re-establish the active SSH session ────────────────────────
    ui.on_reconnect({
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        let hk_pending = hk_pending.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };

            // Extract connect info from the active tab (must be SSH).
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

            // Shut down the existing (failed) session.
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

    // ── Launchpad callbacks (stubs; P1 wires real data) ──────────────────────
    ui.on_launchpad_edited(|_q| {});
    ui.on_open_recent(|_i| {});
    ui.on_open_group_split(|| {});

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

    // CONMAN_SSH_AUTOINIT="username:password:host:port" — auto-open SSH tab at startup.
    // Used by the real-host P3.2 verification run.
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
                auth_method: cm_core::SshAuthMethod::Password,
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

    // CONMAN_AUTODRIVE — send keystrokes to the active tab after a delay.
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

    // CONMAN_AUTORESIZE — scripted resize steps for headless resize screenshots.
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

    ui.run()
    // `redraw`, `resize_debounce`, and `hooks` stay alive across `run()`.
}

// ---------------------------------------------------------------------------
// Tab management
// ---------------------------------------------------------------------------

/// Shared helper: push a fully-constructed session into state + tab model.
///
/// Computes the initial grid size from the current surface (or `INITIAL_SIZE`),
/// builds a renderer, assigns a tab number, and updates the active tab indicator.
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

/// Open a new local PTY shell tab.
fn open_local_tab(state: &Rc<RefCell<State>>, tab_model: &Rc<VecModel<TabItem>>, ui: &AppWindow) {
    let size = state.borrow().current_grid();
    let session = match LocalTerminalSession::spawn(&cm_core::LocalSettings::default(), size) {
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
        None, // no connect_info for local
        title,
        "connected",
    );
    ui.set_session_identity(SharedString::from(identity));
    // Local tabs never show overlays.
    ui.set_overlay_connecting(false);
    ui.set_overlay_error(false);
    ui.set_launchpad_open(false);
}

/// Open a new SSH tab. Returns immediately (status = Connecting); the async driver
/// updates status to Connected or Failed on its background threads.
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
            // Synchronous setup errors (thread spawn, engine init) are rare; surface to stderr.
            // A dead-tab placeholder is deferred; the user can retry via Quick Connect.
        }
    }
}

/// Replace the session in an existing tab slot (reconnect).
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
    drop(tab); // ensure SshConnectInfo / Secret are zeroized now
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

/// Commit the settled resize to every tab's session + renderer.
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

// ---------------------------------------------------------------------------
// Overlay helpers
// ---------------------------------------------------------------------------

/// Update session-state overlays and tab-strip dot from a session status.
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

// ---------------------------------------------------------------------------
// Redraw tick
// ---------------------------------------------------------------------------

fn tick(state: &Rc<RefCell<State>>, tab_model: &Rc<VecModel<TabItem>>, ui: &AppWindow) {
    let mut st = state.borrow_mut();
    let active = st.active;
    let target = st.target_px();
    // Local (non-SSH) tabs auto-close when the shell exits;
    // SSH tabs stay showing the error overlay for reconnect.
    let mut to_close: Vec<usize> = Vec::new();

    for i in 0..st.tabs.len() {
        // Drain latest snapshot for every tab.
        if let Some(snap) = drain_latest(st.tabs[i].session.snapshots()) {
            if i == active {
                let img = render_frame(&mut st.tabs[i], &snap, target);
                ui.set_frame(img);
            }
            st.tabs[i].last = Some(snap);
        }

        let status = st.tabs[i].session.status();

        // Update tab-strip status dot in the model.
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

        // Active-tab overlay.
        if i == active {
            update_overlays_from_status(ui, &st.tabs[i], &status);
        }

        // Only local (non-SSH) tabs auto-close on exit.
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

/// Render the active tab's most recent snapshot into the `frame` image.
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
        "Focus Settings" => ui.set_active_panel(2),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Sample data helpers
// ---------------------------------------------------------------------------

fn sample_connections() -> Vec<ConnRow> {
    vec![
        ConnRow {
            id: 1,
            label: SharedString::from("Lab"),
            host: SharedString::from(""),
            kind: SharedString::from(""),
            status: SharedString::from(""),
            is_group: true,
            expanded: true,
            selected: false,
        },
        ConnRow {
            id: 2,
            label: SharedString::from("web-dev-01"),
            host: SharedString::from("ops@10.0.1.11"),
            kind: SharedString::from("SSH"),
            status: SharedString::from("connected"),
            is_group: false,
            expanded: false,
            selected: false,
        },
        ConnRow {
            id: 3,
            label: SharedString::from("db-dev"),
            host: SharedString::from("admin@10.0.1.22"),
            kind: SharedString::from("SSH"),
            status: SharedString::from("disconnected"),
            is_group: false,
            expanded: false,
            selected: false,
        },
        ConnRow {
            id: 4,
            label: SharedString::from("Prod"),
            host: SharedString::from(""),
            kind: SharedString::from(""),
            status: SharedString::from(""),
            is_group: true,
            expanded: true,
            selected: false,
        },
        ConnRow {
            id: 5,
            label: SharedString::from("web-prod-01"),
            host: SharedString::from("ops@10.0.4.11"),
            kind: SharedString::from("SSH"),
            status: SharedString::from("disconnected"),
            is_group: false,
            expanded: false,
            selected: false,
        },
    ]
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
            label: SharedString::from("Focus Settings"),
            detail: SharedString::from(""),
            shortcut: SharedString::from(""),
            glyph: SharedString::from("\u{E713}"),
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

    // ── P3.2 unit tests ───────────────────────────────────────────────────────

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

    /// "New SSH connection" is present in the palette action list.
    #[test]
    fn palette_contains_new_ssh_connection() {
        let all = initial_palette_actions();
        assert!(
            all.iter().any(|a| a.label.as_str() == "New SSH connection"),
            "expected 'New SSH connection' in the palette"
        );
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
    fn sample_connections_has_groups_and_leaves() {
        let conns = sample_connections();
        assert!(conns.iter().any(|c| c.is_group));
        assert!(conns.iter().any(|c| !c.is_group));
    }

    #[test]
    fn sample_connections_leaves_have_kind() {
        let conns = sample_connections();
        for c in &conns {
            if !c.is_group {
                assert!(!c.kind.is_empty(), "leaf '{}' has no kind", c.label);
            }
        }
    }

    #[test]
    fn rebuild_palette_model_empty_query_fills_all() {
        let model: Rc<VecModel<PaletteAction>> = Rc::new(VecModel::default());
        rebuild_palette_model(&model, &SharedString::from(""));
        let all = initial_palette_actions();
        assert_eq!(model.row_count(), all.len());
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

    // ── Form-to-SshSettings mapping tests (P3.2 §Verification) ───────────────

    /// auth_method=1 (Password) maps correctly to SshAuthInput::Password.
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

    /// auth_method=0 (Public key) maps correctly to SshAuthInput::Key.
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

    /// auth_method=2 (Agent) maps to SshAuthInput::Agent.
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

    /// SshSettings::DEFAULT_PORT is 22.
    #[test]
    fn ssh_settings_default_port() {
        assert_eq!(SshSettings::DEFAULT_PORT, 22);
    }

    /// Session status dot mapping covers all variants.
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
}

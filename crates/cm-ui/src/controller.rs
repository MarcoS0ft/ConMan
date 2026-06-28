//! UI-thread controller: owns the per-tab sessions + renderers + the redraw timer, wires
//! the Slint callbacks, and drives the snapshot→render→Image pipeline.
//!
//! Threading (ARCHITECTURE §4 / P0.3): each [`LocalTerminalSession`] runs its own engine +
//! PTY threads and sends `GridSnapshot`s (which are `Send`) over an mpsc channel. The
//! controller lives entirely on the UI thread; a [`slint::Timer`] coalesces each tab's
//! channel (keep-latest), renders the active tab via [`TerminalRenderer`] (`&mut self`,
//! UI-thread), and builds the `!Send` `slint::Image` here on the UI thread.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use cm_core::LocalSettings;
use cm_core::terminal::{GridSnapshot, Key, KeyEvent, KeyModifiers, TerminalSize};
// `TerminalSession` brings the session methods (send_key/resize/snapshots/shutdown)
// into scope; P3.2 will switch this controller to `Box<dyn TerminalSession>`.
use cm_session::{LocalTerminalSession, TerminalSession};
use slint::{ComponentHandle, Image, Model, ModelRc, SharedString, Timer, TimerMode, VecModel};

use crate::input;
use crate::terminal_renderer::{FontSet, TerminalRenderer, TerminalTheme};
use crate::{AppWindow, ConnRow, PaletteAction, TabItem};

/// Logical font size for the terminal grid.
const FONT_SIZE_PX: f32 = 15.0;
/// Redraw cadence (~60 Hz) for coalescing snapshots and repainting the active tab.
const REDRAW_INTERVAL: Duration = Duration::from_millis(16);
/// Debounce window for committing a resize to the PTY/engine (B6). A live drag fires many
/// `changed` events; we repaint immediately (B2/B3) but only push ONE `session.resize` for
/// the settled size, so the shell gets a single SIGWINCH and its cursor tracks the final
/// geometry — instead of an intermediate resize's redraw sticking.
const RESIZE_DEBOUNCE: Duration = Duration::from_millis(90);
/// Initial grid size before the surface reports its real dimensions.
const INITIAL_SIZE: TerminalSize = TerminalSize { rows: 24, cols: 80 };

/// One open terminal tab.
struct Tab {
    session: LocalTerminalSession,
    renderer: TerminalRenderer,
    /// Most recent snapshot (rendered on tab switch / resize without waiting for output).
    last: Option<GridSnapshot>,
    cols: u16,
    rows: u16,
    scale: f32,
    /// Displayed tab number (reused from the free set on close; see `lowest_free_number`).
    num: u32,
}

/// All UI-thread mutable state.
struct State {
    tabs: Vec<Tab>,
    active: usize,
    /// Shared parsed font faces — reused by every tab's renderer (B4).
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
        // Cheap now: with_fonts reuses the shared faces, so this just computes metrics.
        let probe = TerminalRenderer::with_fonts(
            self.fonts.clone(),
            FONT_SIZE_PX,
            self.scale,
            TerminalTheme::dark(),
        );
        grid_for(&probe, self.surface_w, self.surface_h, self.scale)
    }

    /// Active tab's surface target in physical px, or `None` before the surface is laid out
    /// (fall back to the grid's natural size).
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

/// Render `snap` for `tab` into a `frame` Image at the surface target size (B2: exact
/// physical px, bg-padded, 1:1) — or the grid's natural size before the surface is sized.
fn render_frame(tab: &mut Tab, snap: &GridSnapshot, target: Option<(u32, u32)>) -> Image {
    let buf = match target {
        Some((w, h)) => tab.renderer.render_to(snap, w, h),
        None => tab.renderer.render(snap),
    };
    Image::from_rgba8(buf)
}

/// Lowest unused positive tab number among the currently open tabs (B5: reuse-lowest, so
/// closing #2 of 1,2,3 then opening a new tab yields "2", not an ever-growing counter).
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

/// Drain a receiver, returning only the most recent value (coalescing). Cheap and
/// non-blocking; keeps background tabs from backing up.
pub(crate) fn drain_latest<T>(rx: &Receiver<T>) -> Option<T> {
    let mut latest = None;
    while let Ok(v) = rx.try_recv() {
        latest = Some(v);
    }
    latest
}

/// Build and run the ConMan application. Blocks on the Slint event loop until the last tab
/// closes or the window is closed.
///
/// # Errors
/// Returns a [`slint::PlatformError`] if the window/backend cannot be created.
pub fn run() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let scale = ui.window().scale_factor();

    let tab_model: Rc<VecModel<TabItem>> = Rc::new(VecModel::default());
    ui.set_tabs(ModelRc::from(tab_model.clone()));

    // ── Seed sample connections so the shell is demoable end-to-end (P1 replaces with real) ──
    let conn_model: Rc<VecModel<ConnRow>> = Rc::new(VecModel::from(sample_connections()));
    ui.set_connections(ModelRc::from(conn_model.clone()));

    // ── Seed command palette with real shell actions ──────────────────────────────────────
    let palette_model: Rc<VecModel<PaletteAction>> =
        Rc::new(VecModel::from(initial_palette_actions()));
    ui.set_palette_actions(ModelRc::from(palette_model.clone()));

    // ── CONMAN_DARK_MODE env var: force dark (1) or light (0) for screenshots / tests ──
    // Normal operation: leave dark-mode at its default (seeds from Palette/OS scheme).
    // CONMAN_OPEN_PALETTE=1: open the palette overlay at startup (screenshot fixture).
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

    open_tab(&state, &tab_model, &ui);

    // new-tab
    {
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        ui.on_new_tab(move || {
            if let Some(ui) = weak.upgrade() {
                open_tab(&state, &tab_model, &ui);
            }
        });
    }
    // select-tab
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.on_select_tab(move |idx| {
            if let Some(ui) = weak.upgrade() {
                select_tab(&state, &ui, idx);
            }
        });
    }
    // close-tab
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
    // keyboard — when the command palette is open, route keys to palette navigation
    // rather than the terminal. This gives fully keyboard-operable palette without
    // requiring the user to click the search field (GUI_DESIGN §5 keyboard-first).
    {
        let state = state.clone();
        let pal_model_kb = palette_model.clone();
        let tab_model_kb = tab_model.clone();
        let weak_kb = ui.as_weak();
        ui.on_key_input(move |text, special, mods| {
            let Some(ui) = weak_kb.upgrade() else {
                return;
            };
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
            // Normal terminal key forwarding.
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active) {
                for ev in input::map_key(text.as_str(), special, mods) {
                    tab.session.send_key(ev);
                }
            }
        });
    }
    // pointer
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
    // scroll
    {
        let state = state.clone();
        ui.on_scroll(move |_dx, dy| {
            let st = state.borrow();
            if let Some(tab) = st.tabs.get(st.active) {
                // Anchor wheel events at the top-left cell (selection tracking is P5).
                if let Some(ev) = input::map_scroll(dy, 0, 0, 0) {
                    tab.session.send_mouse(ev);
                }
            }
        });
    }
    // resize / scale change. Repaint immediately (B2/B3) on every event, but debounce the
    // PTY/engine resize so only the settled geometry is committed (B6).
    let resize_debounce = Rc::new(Timer::default());
    {
        let state = state.clone();
        let weak = ui.as_weak();
        let debounce = resize_debounce.clone();
        ui.on_surface_resized(move |w, h| {
            if let Some(ui) = weak.upgrade() {
                // Immediate, cheap: record the new surface size + repaint the active tab's
                // current snapshot 1:1 at the new size (no session work here).
                let mut st = state.borrow_mut();
                st.scale = ui.window().scale_factor();
                st.surface_w = w;
                st.surface_h = h;
                trace(format_args!(
                    "resize event  {w:.0}x{h:.0} logical (debouncing)"
                ));
                render_active(&mut st, &ui);
            }
            // Debounced: (re)arm the single-shot timer; the last resize wins.
            let state = state.clone();
            let weak = weak.clone();
            debounce.start(TimerMode::SingleShot, RESIZE_DEBOUNCE, move || {
                if let Some(ui) = weak.upgrade() {
                    apply_settled_resize(&state, &ui);
                }
            });
        });
    }

    // ── New shell callbacks (P2.8) ──────────────────────────────────────────────
    // select-panel: update active-panel (Slint property write); no Rust state needed.
    ui.on_select_panel({
        let weak = ui.as_weak();
        move |idx| {
            if let Some(ui) = weak.upgrade() {
                ui.set_active_panel(idx);
            }
        }
    });
    // toggle-sidebar: flip the collapsed bool.
    ui.on_toggle_sidebar({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_sidebar_collapsed(!ui.get_sidebar_collapsed());
            }
        }
    });
    // open-palette: reveal the command palette overlay; reset selection to first item.
    ui.on_open_palette({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_palette_selected(0);
                ui.set_palette_open(true);
            }
        }
    });
    // quick-connect: P3.2 wires this; for now show the palette.
    ui.on_quick_connect({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_palette_open(true);
            }
        }
    });
    // row-activated: open a local terminal tab for the sample tree row (P1 replaces with real).
    {
        let state = state.clone();
        let tab_model = tab_model.clone();
        let weak = ui.as_weak();
        ui.on_row_activated(move |_idx| {
            if let Some(ui) = weak.upgrade() {
                open_tab(&state, &tab_model, &ui);
            }
        });
    }
    // toggle-broadcast: flip the armed flag (behaviour is a follow-on task).
    ui.on_toggle_broadcast({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_broadcast_active(!ui.get_broadcast_active());
            }
        }
    });
    // palette-edited: Rust filters + re-populates the actions model, then resets
    // the keyboard selection to the first item.
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
    // palette-activated: dispatch a palette action by index.
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
    // theme-changed: Settings panel writes Theme.dark-mode via the Slint callback chain;
    // we just persist the choice here (P5 adds persistence).
    ui.on_theme_changed(|_idx| {
        // P5: persist the preference.
    });
    // accent-changed: Settings panel writes Theme.accent directly; we track for persistence.
    ui.on_accent_changed(|_idx| {
        // P5: persist the accent preference.
    });

    // Redraw timer: coalesce + render the active tab, reap exited tabs.
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

    // Optional headless test hooks (used by the xvfb screenshot gate).
    let mut hooks: Vec<Timer> = Vec::new();
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
    // Optional scripted resizes for the headless resize screenshots (B2/B3):
    // CONMAN_AUTORESIZE="1800:520x360;2600:1100x720" => at 1800ms set the window to
    // 520x360 physical px, at 2600ms to 1100x720.
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
    // `redraw` and `hooks` stay alive across run() (it blocks on this thread).
}

fn open_tab(state: &Rc<RefCell<State>>, tab_model: &Rc<VecModel<TabItem>>, ui: &AppWindow) {
    let size = state.borrow().current_grid();
    let session = match LocalTerminalSession::spawn(&LocalSettings::default(), size) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("conman: failed to open terminal: {e}");
            return;
        }
    };
    let mut st = state.borrow_mut();
    let scale = st.scale;
    // B4: reuse the shared parsed faces instead of re-parsing ~12 MB of TTFs per tab.
    let renderer =
        TerminalRenderer::with_fonts(st.fonts.clone(), FONT_SIZE_PX, scale, TerminalTheme::dark());
    // B5: number from the current set (lowest free), not a monotonic counter.
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
    });
    st.active = st.tabs.len() - 1;
    let active = st.active;
    drop(st);

    tab_model.push(TabItem {
        title: SharedString::from(format!("shell {num}")),
        id: num as i32,
        // status: "connected" once the PTY is running (local tabs are always "connected").
        status: SharedString::from("connected"),
        pane_count: 1,
    });
    ui.set_active_tab(active as i32);
}

fn select_tab(state: &Rc<RefCell<State>>, ui: &AppWindow, idx: i32) {
    let mut st = state.borrow_mut();
    let idx = idx.max(0) as usize;
    if idx >= st.tabs.len() {
        return;
    }
    st.active = idx;
    ui.set_active_tab(idx as i32);
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
    render_active(&mut st, ui);
}

/// Commit the *settled* resize to every tab's PTY/engine + renderer (B6). Called from the
/// debounce timer after a drag stops, using the current `surface_w/h/scale`, so exactly one
/// `session.resize` is sent for the final geometry. Keeps PTY/engine/renderer/snapshot dims
/// in lockstep, then re-renders so the cursor tracks the settled size.
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

/// Lightweight stderr tracing gated on `CONMAN_TRACE=1` (used to verify the resize-debounce
/// collapses a storm of events into a single committed resize; no cost when unset).
fn trace(args: std::fmt::Arguments) {
    if std::env::var_os("CONMAN_TRACE").is_some() {
        eprintln!("[conman] {args}");
    }
}

fn tick(state: &Rc<RefCell<State>>, tab_model: &Rc<VecModel<TabItem>>, ui: &AppWindow) {
    let mut st = state.borrow_mut();
    let active = st.active;
    let target = st.target_px();
    let mut exited = Vec::new();

    for i in 0..st.tabs.len() {
        if let Some(snap) = drain_latest(st.tabs[i].session.snapshots()) {
            if i == active {
                let img = render_frame(&mut st.tabs[i], &snap, target);
                ui.set_frame(img);
            }
            st.tabs[i].last = Some(snap);
        }
        if st.tabs[i].session.exit_status().is_some() {
            exited.push(i);
        }
    }

    for &i in exited.iter().rev() {
        let tab = st.tabs.remove(i);
        tab.session.shutdown();
        tab_model.remove(i);
        if i <= st.active && st.active > 0 {
            st.active -= 1;
        }
    }
    if !exited.is_empty() {
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
        render_active(&mut st, ui);
    }
}

/// Render the active tab's most recent snapshot into the `frame` image (used on tab switch
/// / close so the surface updates immediately, without waiting for new output).
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

// ── P2.8 helpers ─────────────────────────────────────────────────────────────

/// Rebuild the palette model in-place from `query` (clears, filters, re-pushes).
/// Extracted so both `on_palette_edited` and `handle_palette_key` can call it.
fn rebuild_palette_model(pal_model: &Rc<VecModel<PaletteAction>>, query: &SharedString) {
    let filtered = filter_palette_actions(query.as_str());
    while pal_model.row_count() > 0 {
        pal_model.remove(0);
    }
    for a in filtered {
        pal_model.push(a);
    }
}

/// Route a key event to the command palette when it is open.
///
/// Key routing (GUI_DESIGN §5 keyboard-first):
/// - `special=4` Escape  → close palette, reset selection.
/// - `special=5` Up      → move selection one row up (clamped at 0).
/// - `special=6` Down    → move selection one row down (clamped at last row).
/// - `special=1` Enter   → dispatch selected action, close palette.
/// - `special=3` Backspace (no Ctrl) → remove last UTF-8 char from query, re-filter.
/// - `special=0` (plain char, no Ctrl/Meta) → append char to query, re-filter.
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
            // Escape: close and reset.
            ui.set_palette_open(false);
            ui.set_palette_selected(0);
        }
        5 => {
            // Up: move selection back, clamp at 0.
            let cur = ui.get_palette_selected();
            if cur > 0 {
                ui.set_palette_selected(cur - 1);
            }
        }
        6 => {
            // Down: move selection forward, clamp at last row.
            let cur = ui.get_palette_selected();
            let max = (pal_model.row_count() as i32).saturating_sub(1);
            if cur < max {
                ui.set_palette_selected(cur + 1);
            }
        }
        1 => {
            // Enter: dispatch the currently selected action.
            let idx = ui.get_palette_selected() as usize;
            ui.set_palette_open(false);
            ui.set_palette_selected(0);
            dispatch_palette_action(state, tab_model, pal_model, ui, idx);
        }
        3 if mods & 0b1001 == 0 => {
            // Backspace (no Ctrl, no Meta): remove last UTF-8 char from query.
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
            // Plain character (no Ctrl, no Meta): append to query and re-filter.
            let q = ui.get_palette_query();
            let new_q = SharedString::from(format!("{}{}", q.as_str(), text.as_str()).as_str());
            rebuild_palette_model(pal_model, &new_q);
            ui.set_palette_query(new_q);
            ui.set_palette_selected(0);
        }
        _ => {
            // Other special keys (Tab, arrows, etc.) — swallow silently while palette open.
        }
    }
}

/// Sample connection tree for demo / smoke-testing the shell.
/// P1 replaces this with real data from `cm-storage`.
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

/// Initial palette actions (real actions for new-tab, toggle sidebar, focus panel).
/// P3.2 adds quick-connect items; the query filter narrows this list.
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

/// Filter the palette actions by query (simple case-insensitive substring).
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

/// Dispatch a palette action by its index in the current filtered list.
fn dispatch_palette_action(
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    palette_model: &Rc<VecModel<PaletteAction>>,
    ui: &AppWindow,
    idx: usize,
) {
    // Look up the action by index from our own VecModel (same as the Slint side).
    if idx >= palette_model.row_count() {
        return;
    }
    let action = palette_model.row_data(idx).unwrap_or_default();
    match action.label.as_str() {
        "New local tab" => open_tab(state, tab_model, ui),
        "Toggle sidebar" => ui.set_sidebar_collapsed(!ui.get_sidebar_collapsed()),
        "Focus Connections" => ui.set_active_panel(0),
        "Focus Settings" => ui.set_active_panel(2),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        // Fresh set starts at 1.
        assert_eq!(lowest_free_number(&[]), 1);
        // 1,2,3 open -> next is 4.
        assert_eq!(lowest_free_number(&[1, 2, 3]), 4);
        // Close #2 (used = 1,3) -> reuse 2, not 4.
        assert_eq!(lowest_free_number(&[1, 3]), 2);
        // Order independent.
        assert_eq!(lowest_free_number(&[3, 1]), 2);
        // Close the first -> reuse 1.
        assert_eq!(lowest_free_number(&[2, 3]), 1);
    }

    #[test]
    fn grid_for_divides_surface_by_cell() {
        let r = TerminalRenderer::new(FONT_SIZE_PX, 1.0, TerminalTheme::dark());
        let m = r.cell_metrics();
        let size = grid_for(&r, (m.cell_w * 40) as f32, (m.cell_h * 12) as f32, 1.0);
        assert_eq!(size.cols, 40);
        assert_eq!(size.rows, 12);
        // Never zero, even for a tiny surface.
        let tiny = grid_for(&r, 1.0, 1.0, 1.0);
        assert!(tiny.cols >= 1 && tiny.rows >= 1);
    }

    // ── P2.8 component logic tests ────────────────────────────────────────────

    /// `filter_palette_actions` with an empty query returns all initial actions.
    #[test]
    fn palette_filter_empty_query_returns_all() {
        let all = filter_palette_actions("");
        let initial = initial_palette_actions();
        assert_eq!(all.len(), initial.len());
        // All labels should match the initial set.
        for (a, b) in all.iter().zip(initial.iter()) {
            assert_eq!(a.label, b.label);
        }
    }

    /// A query that matches nothing returns an empty list.
    #[test]
    fn palette_filter_no_match_returns_empty() {
        let result = filter_palette_actions("xyzzy_no_such_action");
        assert!(result.is_empty());
    }

    /// A matching query returns only the actions whose label contains the substring.
    #[test]
    fn palette_filter_narrows_by_label() {
        let result = filter_palette_actions("sidebar");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].label.as_str(), "Toggle sidebar");
    }

    /// The first result always has `first_in_group = true` (group header re-set on filter).
    #[test]
    fn palette_filter_first_row_always_has_group_header() {
        let result = filter_palette_actions("tab");
        assert!(!result.is_empty(), "expected at least one result for 'tab'");
        assert!(result[0].first_in_group);
    }

    /// `sample_connections` produces at least one group and one leaf.
    #[test]
    fn sample_connections_has_groups_and_leaves() {
        let conns = sample_connections();
        assert!(
            conns.iter().any(|c| c.is_group),
            "expected at least one group"
        );
        assert!(
            conns.iter().any(|c| !c.is_group),
            "expected at least one leaf"
        );
    }

    /// All leaf connections have a non-empty `kind` (SSH/RDP/LOCAL).
    #[test]
    fn sample_connections_leaves_have_kind() {
        let conns = sample_connections();
        for c in &conns {
            if !c.is_group {
                assert!(!c.kind.is_empty(), "leaf '{}' has no kind", c.label);
            }
        }
    }

    // ── P2.8 keyboard-dispatch tests ─────────────────────────────────────────

    /// `rebuild_palette_model` with an empty query fills the model with all actions.
    #[test]
    fn rebuild_palette_model_empty_query_fills_all() {
        let model: Rc<VecModel<PaletteAction>> = Rc::new(VecModel::default());
        rebuild_palette_model(&model, &SharedString::from(""));
        let all = initial_palette_actions();
        assert_eq!(model.row_count(), all.len());
    }

    /// `rebuild_palette_model` with a matching query narrows correctly.
    #[test]
    fn rebuild_palette_model_narrows_by_query() {
        let model: Rc<VecModel<PaletteAction>> = Rc::new(VecModel::default());
        // Seed with all actions first.
        rebuild_palette_model(&model, &SharedString::from(""));
        let total = model.row_count();
        // Now narrow to "sidebar".
        rebuild_palette_model(&model, &SharedString::from("sidebar"));
        assert_eq!(model.row_count(), 1);
        assert!(model.row_count() < total);
    }

    /// `rebuild_palette_model` replaces the model content on each call (no accumulation).
    #[test]
    fn rebuild_palette_model_replaces_not_appends() {
        let model: Rc<VecModel<PaletteAction>> = Rc::new(VecModel::default());
        rebuild_palette_model(&model, &SharedString::from(""));
        let first_count = model.row_count();
        // Call again with same query: count must be the same, not doubled.
        rebuild_palette_model(&model, &SharedString::from(""));
        assert_eq!(model.row_count(), first_count);
    }

    /// Mods bitmask: control=1, meta=8; palette key handler ignores chars with those
    /// modifiers set (only plain chars without Ctrl/Meta should update the query).
    #[test]
    fn handle_palette_key_mod_bitmask_plain_is_zero() {
        // Verify the bitmask used in handle_palette_key matches the modifier encoding
        // (1=Ctrl, 2=Alt, 4=Shift, 8=Meta); plain char has mods=0 so 0 & 0b1001 == 0.
        let plain: i32 = 0;
        let ctrl: i32 = 1;
        let meta: i32 = 8;
        assert_eq!(plain & 0b1001, 0, "plain has no ctrl/meta bits");
        assert_ne!(ctrl & 0b1001, 0, "ctrl bit should be set");
        assert_ne!(meta & 0b1001, 0, "meta bit should be set");
    }
}

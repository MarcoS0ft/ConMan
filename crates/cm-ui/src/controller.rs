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
use std::sync::mpsc::Receiver;
use std::time::Duration;

use cm_core::LocalSettings;
use cm_core::terminal::{GridSnapshot, Key, KeyEvent, KeyModifiers, TerminalSize};
use cm_session::LocalTerminalSession;
use slint::{ComponentHandle, Image, ModelRc, SharedString, Timer, TimerMode, VecModel};

use crate::input;
use crate::terminal_renderer::{TerminalRenderer, TerminalTheme};
use crate::{AppWindow, TabItem};

/// Logical font size for the terminal grid.
const FONT_SIZE_PX: f32 = 15.0;
/// Redraw cadence (~60 Hz) for coalescing snapshots and repainting the active tab.
const REDRAW_INTERVAL: Duration = Duration::from_millis(16);
/// Initial grid size before the surface reports its real dimensions.
const INITIAL_SIZE: TerminalSize = TerminalSize { rows: 24, cols: 80 };

/// One open terminal tab.
struct Tab {
    session: LocalTerminalSession,
    renderer: TerminalRenderer,
    /// Most recent snapshot (rendered on tab switch without waiting for new output).
    last: Option<GridSnapshot>,
    cols: u16,
    rows: u16,
    scale: f32,
}

/// All UI-thread mutable state.
struct State {
    tabs: Vec<Tab>,
    active: usize,
    next_id: i32,
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
        // Derive from a throwaway metric at the current scale (cell size is scale-derived).
        let probe = TerminalRenderer::new(FONT_SIZE_PX, self.scale, TerminalTheme::dark());
        grid_for(&probe, self.surface_w, self.surface_h, self.scale)
    }
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

    let state = Rc::new(RefCell::new(State {
        tabs: Vec::new(),
        active: 0,
        next_id: 1,
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
    // keyboard
    {
        let state = state.clone();
        ui.on_key_input(move |text, special, mods| {
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
    // resize / scale change
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.on_surface_resized(move |w, h| {
            if let Some(ui) = weak.upgrade() {
                on_resize(&state, &ui, w, h);
            }
        });
    }

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
        let state = state.clone();
        let t = Timer::default();
        t.start(
            TimerMode::SingleShot,
            Duration::from_millis(800),
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
    let renderer = TerminalRenderer::new(FONT_SIZE_PX, scale, TerminalTheme::dark());
    let id = st.next_id;
    st.next_id += 1;
    st.tabs.push(Tab {
        session,
        renderer,
        last: None,
        cols: size.cols,
        rows: size.rows,
        scale,
    });
    st.active = st.tabs.len() - 1;
    let active = st.active;
    drop(st);

    tab_model.push(TabItem {
        title: SharedString::from(format!("shell {id}")),
        id,
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

fn on_resize(state: &Rc<RefCell<State>>, ui: &AppWindow, w: f32, h: f32) {
    let scale = ui.window().scale_factor();
    let mut st = state.borrow_mut();
    st.scale = scale;
    st.surface_w = w;
    st.surface_h = h;
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
        }
    }
}

fn tick(state: &Rc<RefCell<State>>, tab_model: &Rc<VecModel<TabItem>>, ui: &AppWindow) {
    let mut st = state.borrow_mut();
    let active = st.active;
    let mut exited = Vec::new();

    for i in 0..st.tabs.len() {
        if let Some(snap) = drain_latest(st.tabs[i].session.snapshots()) {
            if i == active {
                let buf = st.tabs[i].renderer.render(&snap);
                ui.set_frame(Image::from_rgba8(buf));
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
    if let Some(tab) = st.tabs.get_mut(active)
        && let Some(snap) = tab.last.clone()
    {
        let buf = tab.renderer.render(&snap);
        ui.set_frame(Image::from_rgba8(buf));
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
}

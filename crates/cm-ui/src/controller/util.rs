//! Small shared helpers: the `CONMAN_TRACE` logger, the pixel-grid sizing
//! math, and the CONMAN_* headless test-hook env vars.
use std::sync::Arc;
use std::time::Duration;

use cm_core::terminal::{Key, KeyEvent, KeyModifiers, TerminalSize};
use cm_core::{RdpSettings, Secret, SshAuthMethod, SshSettings};
use cm_session::{PaneLayout, RdpAuthInput, SessionInput, SshAuthInput};
use slint::{ComponentHandle, Timer, TimerMode};

use crate::AppWindow;
use crate::terminal_renderer::TerminalRenderer;

use super::*;

pub(super) fn grid_for(
    r: &TerminalRenderer,
    logical_w: f32,
    logical_h: f32,
    scale: f32,
) -> TerminalSize {
    let m = r.cell_metrics();
    let phys_w = (logical_w * scale).max(1.0) as u32;
    let phys_h = (logical_h * scale).max(1.0) as u32;
    TerminalSize {
        cols: (phys_w / m.cell_w).max(1) as u16,
        rows: (phys_h / m.cell_h).max(1) as u16,
    }
}

pub(super) fn trace(args: std::fmt::Arguments) {
    if std::env::var_os("CONMAN_TRACE").is_some() {
        eprintln!("[conman] {args}");
    }
}

/// Apply the small set of env-var overrides that must take effect before the
/// window is populated (theme + palette visibility) -- read once at startup.
pub(super) fn apply_early_env_overrides(ui: &AppWindow) {
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
}

/// Register every `CONMAN_*` headless test hook. Each hook is independent and
/// gated on its own env var.
pub(super) fn wire_env_hooks(
    ui: &AppWindow,
    state: &Rc<RefCell<State>>,
    tab_model: &Rc<VecModel<TabItem>>,
    hk_pending: &HkQueue,
    cert_pending: &Arc<Mutex<Option<Sender<CertDecision>>>>,
    hooks: &mut Vec<Timer>,
) {
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
            let verifier = Arc::new(sessions::UiHostKeyVerifier {
                weak_ui: ui.as_weak(),
                pending: hk_pending.clone(),
                auto_accept,
            });
            sessions::open_ssh_tab(state, tab_model, ui, settings, auth, verifier);
        }
    }

    // ── CONMAN_RDP_AUTOINIT (P4.2 test hook) ─────────────────────────────
    // Format: "username:password:host[:port]" — opens an RDP tab immediately
    // on startup without requiring the user to click a connection in the panel.
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
            let verifier = Arc::new(sessions::UiCertVerifier {
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
            sessions::open_rdp_tab(state, tab_model, ui, settings, auth, verifier);
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
                    panes::do_split(&state_as, &tab_model_as, &ui, layout);
                }
            },
        );
        hooks.push(t);
    }

    // CONMAN_AUTOBROADCAST=1 — enable broadcast at startup.
    if std::env::var("CONMAN_AUTOBROADCAST").as_deref() == Ok("1") {
        ui.set_broadcast_active(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

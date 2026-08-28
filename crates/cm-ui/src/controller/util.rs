//! Small shared helpers: the pixel-grid sizing math, and the CONMAN_*
//! headless test-hook env vars.
use std::sync::Arc;
use std::time::Duration;

use cm_core::terminal::{Key, KeyEvent, KeyModifiers, TerminalSize};
use cm_core::{RdpSettings, Secret, SshAuthMethod, SshSettings};
use cm_session::{PaneLayout, RdpAuthInput, SessionInput, SshAuthInput};
use slint::{ComponentHandle, Timer, TimerMode};

use crate::AppWindow;
use crate::terminal_renderer::{TerminalRenderer, TerminalTheme};

use super::*;

/// `true` only for an exact `"1"` value — the shared predicate behind both
/// `*_auto_accept_*` hooks below, split out so it is unit-testable without
/// mutating real process env vars (which would race other tests). Compiled
/// in for debug builds (its only caller) and for `cfg(test)` (its unit test
/// below), so a plain release lib build has zero references to it.
#[cfg(any(debug_assertions, test))]
fn is_flag_one(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Debug-only headless test hook: auto-accept SSH host keys without prompting
/// (`CONMAN_SSH_AUTO_ACCEPT_KEYS=1`). P6.3 gap 24: compiled out entirely in
/// release builds -- the `#[cfg(not(debug_assertions))]` variant below never
/// calls `std::env::var` at all, so a release binary cannot be made to skip
/// host-key verification regardless of its environment (verified by
/// inspection of that fn body, plus `is_flag_one`'s unit test below covering
/// the value-matching predicate the debug variant uses). The xvfb/QA
/// automation gates run debug builds, so this is not a regression for them.
#[cfg(debug_assertions)]
pub(super) fn ssh_auto_accept_keys() -> bool {
    is_flag_one(std::env::var("CONMAN_SSH_AUTO_ACCEPT_KEYS").ok().as_deref())
}
#[cfg(not(debug_assertions))]
pub(super) fn ssh_auto_accept_keys() -> bool {
    false
}

/// Debug-only headless test hook: auto-accept RDP TLS certs without prompting
/// (`CONMAN_RDP_AUTO_ACCEPT_CERTS=1`). Same release-inertness rationale as
/// [`ssh_auto_accept_keys`] (P6.3 gap 24).
#[cfg(debug_assertions)]
pub(super) fn rdp_auto_accept_certs() -> bool {
    is_flag_one(
        std::env::var("CONMAN_RDP_AUTO_ACCEPT_CERTS")
            .ok()
            .as_deref(),
    )
}
#[cfg(not(debug_assertions))]
pub(super) fn rdp_auto_accept_certs() -> bool {
    false
}

/// The terminal palette is intentionally independent from the application-shell
/// theme. Until user-visible terminal color schemes land, every terminal uses the
/// established dark palette so switching the surrounding chrome to Light cannot
/// silently change ANSI contrast or turn the terminal canvas white.
pub(super) fn terminal_theme_for(ui: &AppWindow) -> TerminalTheme {
    application_terminal_theme(ui.get_settings_terminal_theme())
}

fn application_terminal_theme(index: i32) -> TerminalTheme {
    if index == 1 {
        TerminalTheme::light()
    } else {
        TerminalTheme::dark()
    }
}

/// Display-only hints for empty local-session settings. Empty values retain their
/// existing semantics; these strings merely describe the default selected by the
/// platform session provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LocalShellPlaceholders {
    pub path_hint: &'static str,
    pub path: &'static str,
    pub args: &'static str,
    pub cwd: &'static str,
}

pub(super) const fn local_shell_placeholders() -> LocalShellPlaceholders {
    #[cfg(windows)]
    {
        LocalShellPlaceholders {
            path_hint: "Executable path — empty uses cmd.exe",
            path: "cmd.exe",
            args: "No arguments",
            cwd: "%USERPROFILE%",
        }
    }
    #[cfg(not(windows))]
    {
        LocalShellPlaceholders {
            path_hint: "Executable path — empty uses $SHELL",
            path: "$SHELL",
            args: "No arguments",
            cwd: "~",
        }
    }
}

pub(super) fn apply_platform_shell_placeholders(ui: &AppWindow) {
    let placeholders = local_shell_placeholders();
    ui.set_settings_shell_path_hint(placeholders.path_hint.into());
    ui.set_settings_shell_path_placeholder(placeholders.path.into());
    ui.set_settings_shell_args_placeholder(placeholders.args.into());
    ui.set_settings_shell_cwd_placeholder(placeholders.cwd.into());
}

/// Push an OS-read accent color (P6.8, gap 10; see `cm_platform::accent`) into
/// the live `Theme.os-accent-color` Slint global via the `set-os-accent`
/// callback — used both at startup and from the best-effort live accent-change
/// watch.
pub(super) fn push_os_accent(ui: &AppWindow, color: cm_platform::accent::AccentColor) {
    ui.invoke_set_os_accent(slint::Color::from_rgb_u8(color.r, color.g, color.b));
}

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

/// Side-panel drag-resize clamps (P6.9 gap 11). Rust-side mirror of the
/// `Theme.side-panel-min-width` / `-max-width` tokens (`cm-ui/ui/theme.slint`)
/// -- the `.slint` drag handle already clamps live while dragging, but every
/// value that reaches the settings table goes through this Rust copy too, so
/// a stale/out-of-range persisted value (e.g. from a future lower minimum)
/// can never restore a sidebar wider/narrower than what the chrome allows.
pub(super) const SIDEBAR_WIDTH_MIN: i32 = 180;
pub(super) const SIDEBAR_WIDTH_MAX: i32 = 480;

/// Clamp a sidebar width (logical px) to `[SIDEBAR_WIDTH_MIN, SIDEBAR_WIDTH_MAX]`.
pub(super) fn clamp_sidebar_width(px: i32) -> i32 {
    px.clamp(SIDEBAR_WIDTH_MIN, SIDEBAR_WIDTH_MAX)
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
/// gated on its own env var; split into one function per hook (P6.1
/// function-size budget) — pure code move, identical logic/order.
pub(super) fn wire_env_hooks(ctx: &Ctx, hooks: &mut Vec<Timer>) {
    wire_ssh_autoinit(ctx);
    wire_rdp_autoinit(ctx);
    wire_open_quickconnect(ctx);
    wire_local_qc_autoconnect(ctx);
    wire_tree_autolaunch(ctx);
    wire_autodrive(ctx, hooks);
    wire_autoresize(ctx, hooks);
    wire_autoquit(hooks);
    wire_show_keys(ctx);
    wire_autosplit(ctx, hooks);
    wire_autobroadcast(ctx);
    wire_autosidebarwidth(ctx);
    wire_autoimport(ctx, hooks);
    wire_autoexport(ctx, hooks);
}

// P6.9 (gap 11) headless test hook: CONMAN_SIDEBAR_WIDTH=<px> — updates the
// live width then fires the exact same `sidebar-width-changed` callback a
// real drag-release does (the `.slint` handle updates `sidebar-width` live
// during the drag and only calls this callback, with the already-current
// value, on release — mirrored here), so an xvfb screenshot scenario can
// exercise "resize, then relaunch and see it restored" without synthesizing
// real OS-level mouse-drag events (out of scope for this generic endpoint,
// same rationale as the other CONMAN_AUTO* hooks above).
fn wire_autosidebarwidth(ctx: &Ctx) {
    if let Ok(px) = std::env::var("CONMAN_SIDEBAR_WIDTH")
        && let Ok(px) = px.trim().parse::<i32>()
    {
        ctx.ui.set_sidebar_width(px);
        ctx.ui.invoke_sidebar_width_changed(px);
    }
}

fn wire_ssh_autoinit(ctx: &Ctx) {
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
            let auto_accept = ssh_auto_accept_keys();
            let verifier = Arc::new(sessions::UiHostKeyVerifier {
                weak_ui: ctx.ui.as_weak(),
                pending: ctx.hk_pending.clone(),
                auto_accept,
            });
            sessions::open_ssh_tab(
                &ctx.state,
                &ctx.tab_model,
                &ctx.ui,
                settings,
                auth,
                AuthProvenance::Direct,
                verifier,
                None,
            );
        }
    }
}

// ── CONMAN_TREE_AUTOLAUNCH (P6.4 QA hook) ────────────────────────────────
// Format: "<connection-id>" — resolves + connects a saved connection through
// the exact same stored-credential path a tree row click uses
// (`sessions::launch_saved_connection`: resolve_effective_credential ->
// keychain fetch -> real SshAuthInput/RdpAuthInput). Lets an xvfb screenshot
// script prove the Keys-panel credential wiring reaches Connected (or the
// auth-error overlay for a credential-less connection) without simulating a
// pixel-precise tree click.
fn wire_tree_autolaunch(ctx: &Ctx) {
    let Ok(raw_id) = std::env::var("CONMAN_TREE_AUTOLAUNCH") else {
        return;
    };
    let Ok(id) = raw_id.trim().parse::<i64>() else {
        tracing::warn!("CONMAN_TREE_AUTOLAUNCH: invalid connection id {raw_id:?}");
        return;
    };
    let conn = {
        let st = ctx.state.borrow();
        st.conn_tree
            .connections()
            .iter()
            .find(|c| c.id.get() == id)
            .cloned()
    };
    let Some(conn) = conn else {
        tracing::warn!("CONMAN_TREE_AUTOLAUNCH: no connection with id {id}");
        return;
    };
    sessions::launch_saved_connection(
        &ctx.state,
        &ctx.tab_model,
        &ctx.ui,
        &ctx.ui.as_weak(),
        &ctx.hk_pending,
        &ctx.cert_pending,
        &ctx.secrets,
        &conn,
    );
}

// ── CONMAN_RDP_AUTOINIT (P4.2 test hook) ─────────────────────────────────
// Format: "username:password:host[:port]" — opens an RDP tab immediately on
// startup without requiring the user to click a connection in the panel.
fn wire_rdp_autoinit(ctx: &Ctx) {
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
            let auto_accept = rdp_auto_accept_certs();
            let verifier = Arc::new(sessions::UiCertVerifier {
                weak_ui: ctx.ui.as_weak(),
                pending: ctx.cert_pending.clone(),
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
            sessions::open_rdp_tab(
                &ctx.state,
                &ctx.tab_model,
                &ctx.ui,
                settings,
                auth,
                AuthProvenance::Direct,
                verifier,
                None,
            );
        }
    }
}

// P6.12 (gap 20) headless test hook: CONMAN_OPEN_QUICKCONNECT=ssh|rdp|local —
// opens the quick-connect dialog pre-set to the given kind, without
// submitting it. No existing hook opens this dialog headlessly (mirrors
// CONMAN_SHOW_KEYS's plain property-set style); exists so the xvfb screenshot
// gate can capture each kind's per-kind fields without synthesizing a
// pixel-precise click on the SegmentedControl.
fn wire_open_quickconnect(ctx: &Ctx) {
    let Ok(kind) = std::env::var("CONMAN_OPEN_QUICKCONNECT") else {
        return;
    };
    let qc_kind = match kind.trim().to_ascii_lowercase().as_str() {
        "rdp" => 1,
        "local" => 2,
        _ => 0,
    };
    ctx.ui.set_qc_kind(qc_kind);
    ctx.ui.set_quick_connect_open(true);
}

// P6.12 (gap 20) headless test hook: CONMAN_LOCAL_QC_AUTOCONNECT=1 — drives
// the quick-connect dialog's Local kind through the exact same
// `sessions::qc_connect_local` dispatch a real "Connect" click uses (reading
// whatever `qc-local-*` fields are already set, empty by default -> the OS
// default shell). Exists so the xvfb screenshot gate can prove "a Local
// quick-connect reaching a live shell" without synthesizing clicks.
fn wire_local_qc_autoconnect(ctx: &Ctx) {
    if std::env::var("CONMAN_LOCAL_QC_AUTOCONNECT").as_deref() == Ok("1") {
        sessions::qc_connect_local(&ctx.state, &ctx.tab_model, &ctx.ui);
    }
}

fn wire_autodrive(ctx: &Ctx, hooks: &mut Vec<Timer>) {
    if let Ok(cmd) = std::env::var("CONMAN_AUTODRIVE") {
        let delay = std::env::var("CONMAN_AUTODRIVE_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(800);
        let state = ctx.state.clone();
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
}

fn wire_autoresize(ctx: &Ctx, hooks: &mut Vec<Timer>) {
    if let Ok(script) = std::env::var("CONMAN_AUTORESIZE") {
        for step in script.split(';').filter(|s| !s.is_empty()) {
            if let Some((ms, dims)) = step.split_once(':')
                && let (Ok(ms), Some((w, h))) = (
                    ms.parse::<u64>(),
                    dims.split_once('x')
                        .and_then(|(w, h)| Some((w.parse::<u32>().ok()?, h.parse::<u32>().ok()?))),
                )
            {
                let weak = ctx.ui.as_weak();
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
}

fn wire_autoquit(hooks: &mut Vec<Timer>) {
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
}

fn wire_show_keys(ctx: &Ctx) {
    if std::env::var("CONMAN_SHOW_KEYS").as_deref() == Ok("1") {
        ctx.ui.set_active_panel(1);
    }
}

// P5.1: Auto-split hook (headless screenshot tests).
// CONMAN_AUTOSPLIT=h|v — trigger an H- or V-split after a short delay.
fn wire_autosplit(ctx: &Ctx, hooks: &mut Vec<Timer>) {
    if let Ok(dir) = std::env::var("CONMAN_AUTOSPLIT") {
        let layout = if dir.trim().eq_ignore_ascii_case("v") {
            PaneLayout::VSplit
        } else {
            PaneLayout::HSplit
        };
        let state_as = ctx.state.clone();
        let tab_model_as = ctx.tab_model.clone();
        let weak_as = ctx.ui.as_weak();
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
}

// CONMAN_AUTOBROADCAST=1 — enable broadcast at startup.
fn wire_autobroadcast(ctx: &Ctx) {
    if std::env::var("CONMAN_AUTOBROADCAST").as_deref() == Ok("1") {
        ctx.ui.set_broadcast_active(true);
    }
}

// P6.6: CONMAN_AUTOIMPORT=<path> — import the given JSON export file shortly
// after startup, bypassing the native file-open dialog
// (`import_export::run_import`, the same dialog-free half
// `import_via_dialog` calls once a path is chosen). Exists so the xvfb
// screenshot gate can produce and capture the real post-import summary
// toast without a display-dependent, blocking native file picker in CI.
fn wire_autoimport(ctx: &Ctx, hooks: &mut Vec<Timer>) {
    if let Ok(path) = std::env::var("CONMAN_AUTOIMPORT") {
        let io = ctx.state.borrow().io.clone();
        let state = ctx.state.clone();
        let weak = ctx.ui.as_weak();
        let delay = std::env::var("CONMAN_AUTOIMPORT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(600);
        let t = Timer::default();
        t.start(
            TimerMode::SingleShot,
            Duration::from_millis(delay),
            move || {
                if let Some(ui) = weak.upgrade() {
                    import_export::run_import(&io, &state, &ui, std::path::Path::new(&path));
                }
            },
        );
        hooks.push(t);
    }
}

// P6.17 finding F3: CONMAN_AUTOEXPORT=<path> — export the current tree to
// the given JSON file shortly after startup, bypassing the native
// file-save dialog (`import_export::run_export`, the same dialog-free half
// `export_via_dialog` calls once a path is chosen). Mirrors
// `CONMAN_AUTOIMPORT` exactly: exists so a headless gate can capture the
// real post-export success/error toast and assert the on-disk JSON (esp.
// secret exclusion) without a display-dependent, blocking native file
// picker in CI (closes the P6.17 J15 gap).
fn wire_autoexport(ctx: &Ctx, hooks: &mut Vec<Timer>) {
    if let Ok(path) = std::env::var("CONMAN_AUTOEXPORT") {
        let io = ctx.state.borrow().io.clone();
        let delay = std::env::var("CONMAN_AUTOEXPORT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(600);
        let t = Timer::default();
        t.start(
            TimerMode::SingleShot,
            Duration::from_millis(delay),
            move || {
                import_export::run_export(&io, std::path::Path::new(&path));
            },
        );
        hooks.push(t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_palette_uses_its_own_setting() {
        let dark = application_terminal_theme(0);
        let light = application_terminal_theme(1);
        assert_eq!(dark.bg, TerminalTheme::dark().bg);
        assert_eq!(light.bg, TerminalTheme::light().bg);
    }

    #[test]
    fn local_shell_hints_name_this_platforms_default() {
        let hints = local_shell_placeholders();
        assert_eq!(hints.args, "No arguments");
        #[cfg(windows)]
        {
            assert_eq!(hints.path, "cmd.exe");
            assert_eq!(hints.cwd, "%USERPROFILE%");
            assert!(!hints.path_hint.contains("/bin/bash"));
        }
        #[cfg(not(windows))]
        {
            assert_eq!(hints.path, "$SHELL");
            assert_eq!(hints.cwd, "~");
        }
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

    // ── gap 24: verification-bypass gating ──────────────────────────────
    //
    // `is_flag_one` is the value-matching predicate both debug-only
    // `*_auto_accept_*` hooks use. The release inertness itself (the
    // `#[cfg(not(debug_assertions))]` variants never calling `std::env::var`
    // at all) is a compile-time structural property verified by
    // code-inspection of `ssh_auto_accept_keys`/`rdp_auto_accept_certs`
    // above, not by this test — see the P6.3 report for the inspection note.

    // ── gap 11: sidebar-width clamp ─────────────────────────────────────

    #[test]
    fn clamp_sidebar_width_passes_through_in_range() {
        assert_eq!(clamp_sidebar_width(252), 252);
        assert_eq!(clamp_sidebar_width(SIDEBAR_WIDTH_MIN), SIDEBAR_WIDTH_MIN);
        assert_eq!(clamp_sidebar_width(SIDEBAR_WIDTH_MAX), SIDEBAR_WIDTH_MAX);
    }

    #[test]
    fn clamp_sidebar_width_clamps_below_min() {
        assert_eq!(clamp_sidebar_width(0), SIDEBAR_WIDTH_MIN);
        assert_eq!(clamp_sidebar_width(-100), SIDEBAR_WIDTH_MIN);
        assert_eq!(
            clamp_sidebar_width(SIDEBAR_WIDTH_MIN - 1),
            SIDEBAR_WIDTH_MIN
        );
    }

    #[test]
    fn clamp_sidebar_width_clamps_above_max() {
        assert_eq!(clamp_sidebar_width(10_000), SIDEBAR_WIDTH_MAX);
        assert_eq!(
            clamp_sidebar_width(SIDEBAR_WIDTH_MAX + 1),
            SIDEBAR_WIDTH_MAX
        );
    }

    #[test]
    fn is_flag_one_requires_exact_1() {
        assert!(is_flag_one(Some("1")));
        assert!(!is_flag_one(Some("true")));
        assert!(!is_flag_one(Some("")));
        assert!(!is_flag_one(Some("0")));
        assert!(!is_flag_one(None));
    }
}

//! P6.2b Part A — in-app QA endpoint.
//!
//! Feature-gated (`qa-harness`, off by default — never compiled into a normal
//! build) loopback JSON-lines socket that lets an agent launch, drive, inspect
//! and screenshot the running app identically on Linux and Windows, closing the
//! human-in-the-loop QA bottleneck. See
//! `docs/devel/tasks/P6.2b-remote-qa-harness.md`.
//!
//! # Design
//!
//! The listener runs on its own OS thread (spawned from [`wire_qa_harness`],
//! itself called on the UI thread during [`super::run`]). It accepts **one
//! client at a time** on `127.0.0.1:<CONMAN_QA_PORT>` (loopback only — never
//! binds `0.0.0.0`) and reads newline-delimited JSON requests.
//!
//! Every command needs the UI thread (Slint's component tree is `!Send` and
//! may only be touched from the thread that owns the event loop), so each
//! parsed request is dispatched via [`slint::invoke_from_event_loop`] — a
//! closure that is itself `Send` (it captures only the request + a reply
//! channel) and, once running on the UI thread, looks up the actual `!Send`
//! handles (the [`Ctx`] pieces it needs) from a thread-local registry set up
//! once in `wire_qa_harness`. The socket thread blocks on the reply channel,
//! so the JSON reply is only written **after** the UI-thread work completes
//! (e.g. a `screenshot` reply is written only once the PNG file exists) —
//! this lets driver scripts sequence commands without sleeping.
//!
//! Malformed JSON / unknown commands never panic: they produce an
//! `{"ok":false,"error":…}` reply (CONVENTIONS §2 — untrusted input never
//! aborts; this listens on loopback only but the input is still
//! agent/script-supplied, not to be trusted blindly).
use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::rc::Rc;
use std::sync::mpsc;
use std::time::Duration;

use slint::{ComponentHandle, Model};

use crate::{AppWindow, PaletteAction, TabItem};

use super::palette;
use super::{Ctx, State};

/// Env var carrying the loopback port to listen on. Absent (the default) means
/// the harness does not start even when the `qa-harness` feature is compiled in
/// — the capability must be explicitly opted into per-launch, never implicit.
const CONMAN_QA_PORT: &str = "CONMAN_QA_PORT";

/// The `!Send` handles a QA command needs, looked up from the UI thread via the
/// thread-local registry below. Deliberately narrow — only what the pinned
/// commands (state/key/text/pointer/palette/screenshot/quit) touch.
struct QaHandles {
    ui: AppWindow,
    state: Rc<RefCell<State>>,
    tab_model: Rc<slint::VecModel<TabItem>>,
    palette_model: Rc<slint::VecModel<PaletteAction>>,
}

thread_local! {
    /// Populated once, on the UI thread, by [`wire_qa_harness`]. Every QA
    /// command runs inside an `invoke_from_event_loop` closure, which is
    /// guaranteed to execute on this same thread, so the `RefCell` is never
    /// contended across threads (Slint's event loop is strictly single-
    /// threaded) — see the module doc for why this indirection exists at all.
    static QA_HANDLES: RefCell<Option<QaHandles>> = const { RefCell::new(None) };
}

/// Register the QA endpoint if `qa-harness` is compiled in and
/// `CONMAN_QA_PORT` is set. No-op otherwise (including: feature compiled in,
/// env var absent — the endpoint is opt-in per launch, not just per build).
pub(super) fn wire_qa_harness(ctx: &Ctx) {
    let Ok(port_str) = std::env::var(CONMAN_QA_PORT) else {
        return;
    };
    let Ok(port) = port_str.trim().parse::<u16>() else {
        tracing::warn!("qa-harness: ignoring invalid {CONMAN_QA_PORT}={port_str:?}");
        return;
    };

    QA_HANDLES.with(|slot| {
        *slot.borrow_mut() = Some(QaHandles {
            ui: ctx.ui.clone_strong(),
            state: ctx.state.clone(),
            tab_model: ctx.tab_model.clone(),
            palette_model: ctx.palette_model.clone(),
        });
    });

    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("qa-harness: failed to bind 127.0.0.1:{port}: {e}");
            return;
        }
    };
    tracing::info!("qa-harness: listening on 127.0.0.1:{port}");

    std::thread::spawn(move || listen_loop(listener));
}

/// Accept connections one at a time; each is fully drained (line by line)
/// before the next `accept()`. Never panics on socket errors — logs and moves
/// on.
fn listen_loop(listener: TcpListener) {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => handle_client(stream),
            Err(e) => tracing::warn!("qa-harness: accept error: {e}"),
        }
    }
}

/// Upper bound on a single QA-command line, in bytes. Generous for any
/// realistic key/text/pointer/palette/screenshot JSON payload, while still
/// bounding memory against a malformed or hostile local client that never
/// sends `\n` (P6.3 Wave-1 advisory).
const MAX_LINE_LEN: usize = 1 << 20; // 1 MiB

/// How long a reply write to the QA client may block before the connection
/// is dropped. Protects against a stalled/dead client whose receive buffer
/// never drains, which would otherwise wedge `write_all` forever — and since
/// the harness serves one client at a time, that would also block every
/// subsequent connection (P6.3 Wave-1 advisory). No read timeout is set: an
/// idle client between commands (normal for a scripted, long-lived session)
/// must not be disconnected.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Reads one `\n`-terminated line from `reader`, capped at [`MAX_LINE_LEN`]
/// bytes. Returns `Ok(None)` on immediate EOF, `Err` on a read error or
/// exceeding the length cap — never buffers past the cap.
fn read_bounded_line(reader: &mut impl Read) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                return Ok(if buf.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(&buf).into_owned())
                });
            }
            Ok(_) if byte[0] == b'\n' => {
                return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
            }
            Ok(_) => {
                buf.push(byte[0]);
                if buf.len() > MAX_LINE_LEN {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "qa-harness line exceeded the length bound",
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

fn handle_client(mut stream: TcpStream) {
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("qa-harness: failed to clone socket: {e}");
            return;
        }
    };
    if writer.set_write_timeout(Some(WRITE_TIMEOUT)).is_err() {
        tracing::warn!("qa-harness: failed to set write timeout; dropping connection");
        return;
    }
    loop {
        let line = match read_bounded_line(&mut stream) {
            Ok(Some(line)) => line,
            Ok(None) => break, // EOF
            Err(e) => {
                tracing::warn!("qa-harness: read error: {e}");
                break;
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let reply = dispatch_line(line);
        if writer.write_all(reply.as_bytes()).is_err() || writer.write_all(b"\n").is_err() {
            break;
        }
        if reply.contains("\"__qa_quit__\":true") {
            break;
        }
    }
}

/// Parse one request line and run it on the UI thread, blocking for the
/// reply. Malformed JSON is rejected here (no UI-thread round-trip needed).
fn dispatch_line(line: &str) -> String {
    let req: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return error_reply(&format!("malformed JSON: {e}")),
    };

    let (reply_tx, reply_rx) = mpsc::channel::<String>();
    let owned = req;
    let invoked = slint::invoke_from_event_loop(move || {
        let reply = QA_HANDLES.with(|slot| match slot.borrow().as_ref() {
            Some(h) => process_command(h, &owned),
            None => error_reply("qa-harness: handles not initialised"),
        });
        // The receiver only goes away if the socket thread already gave up
        // (e.g. client disconnected mid-command); dropping the reply is fine.
        let _ = reply_tx.send(reply);
    });
    if invoked.is_err() {
        return error_reply("qa-harness: UI event loop is not running");
    }
    reply_rx
        .recv()
        .unwrap_or_else(|_| error_reply("qa-harness: UI thread did not reply"))
}

fn error_reply(msg: &str) -> String {
    serde_json::json!({ "ok": false, "error": msg }).to_string()
}

/// Runs entirely on the UI thread (called from inside the
/// `invoke_from_event_loop` closure in [`dispatch_line`]).
fn process_command(h: &QaHandles, req: &serde_json::Value) -> String {
    let Some(cmd) = req.get("cmd").and_then(|v| v.as_str()) else {
        return error_reply("missing \"cmd\"");
    };
    match cmd {
        "state" => cmd_state(h),
        "key" => cmd_key(h, req),
        "text" => cmd_text(h, req),
        "pointer" => cmd_pointer(h, req),
        "palette" => cmd_palette(h, req),
        "screenshot" => cmd_screenshot(h, req),
        "quit" => cmd_quit(),
        other => error_reply(&format!("unknown cmd: {other}")),
    }
}

// ── state ────────────────────────────────────────────────────────────────

fn cmd_state(h: &QaHandles) -> String {
    let ui = &h.ui;
    let active_tab = ui.get_active_tab();
    let tabs_model = ui.get_tabs();
    let mut tabs = Vec::with_capacity(tabs_model.row_count());
    for i in 0..tabs_model.row_count() {
        let Some(t) = tabs_model.row_data(i) else {
            continue;
        };
        tabs.push(serde_json::json!({
            "title": t.title.as_str(),
            "status": t.status.as_str(),
            "pane_count": t.pane_count,
            "active": i as i32 == active_tab,
        }));
    }

    let toasts_model = ui.get_toasts();
    let mut toasts = Vec::with_capacity(toasts_model.row_count());
    for i in 0..toasts_model.row_count() {
        if let Some(t) = toasts_model.row_data(i) {
            toasts.push(t.message.as_str().to_owned());
        }
    }

    // Named overlay/dialog flags currently `true` — never any secret material.
    let overlay_flags: &[(&str, bool)] = &[
        ("palette_open", ui.get_palette_open()),
        ("overlay_connecting", ui.get_overlay_connecting()),
        ("overlay_error", ui.get_overlay_error()),
        ("launchpad_open", ui.get_launchpad_open()),
        ("quick_connect_open", ui.get_quick_connect_open()),
        ("host_key_open", ui.get_host_key_open()),
        ("cert_dialog_open", ui.get_cert_dialog_open()),
        ("profile_editor_open", ui.get_profile_editor_open()),
        ("group_editor_open", ui.get_group_editor_open()),
        ("cred_editor_open", ui.get_cred_editor_open()),
    ];
    let open_overlays: Vec<&str> = overlay_flags
        .iter()
        .filter(|(_, open)| *open)
        .map(|(name, _)| *name)
        .collect();

    serde_json::json!({
        "ok": true,
        "state": {
            "tabs": tabs,
            "active_panel": ui.get_active_panel(),
            "sidebar_collapsed": ui.get_sidebar_collapsed(),
            "open_overlays": open_overlays,
            "broadcast_active": ui.get_broadcast_active(),
            "toasts": toasts,
        }
    })
    .to_string()
}

// ── key / text ───────────────────────────────────────────────────────────

/// Named-key -> the numeric "special" discriminant `.slint` computes against
/// its `Key.*` namespace (see `ui/app.slint`'s `TerminalSurface.key-pressed`
/// and `crate::input::map_key`) — kept in sync with both by hand since the
/// mapping is small and stable (F-keys additionally supported here, matching
/// `input::map_key`, even though the current `.slint` ternary chain does not
/// yet forward them).
fn special_from_code(code: &str) -> Option<i32> {
    Some(match code {
        "Enter" | "Return" => 1,
        "Tab" => 2,
        "Backspace" => 3,
        "Escape" => 4,
        "Up" | "ArrowUp" => 5,
        "Down" | "ArrowDown" => 6,
        "Left" | "ArrowLeft" => 7,
        "Right" | "ArrowRight" => 8,
        "Home" => 9,
        "End" => 10,
        "PageUp" => 11,
        "PageDown" => 12,
        "Insert" => 13,
        "Delete" => 14,
        "F1" => 101,
        "F2" => 102,
        "F3" => 103,
        "F4" => 104,
        "F5" => 105,
        "F6" => 106,
        "F7" => 107,
        "F8" => 108,
        "F9" => 109,
        "F10" => 110,
        "F11" => 111,
        "F12" => 112,
        _ => return None,
    })
}

fn mods_from_names(req: &serde_json::Value) -> i32 {
    let Some(arr) = req.get("modifiers").and_then(|v| v.as_array()) else {
        return 0;
    };
    arr.iter().filter_map(|v| v.as_str()).fold(0, |bits, name| {
        bits | match name.to_ascii_lowercase().as_str() {
            "ctrl" | "control" => crate::input::MOD_CTRL,
            "alt" => crate::input::MOD_ALT,
            "shift" => crate::input::MOD_SHIFT,
            "meta" | "super" | "cmd" | "win" => crate::input::MOD_META,
            _ => 0,
        }
    })
}

/// `{"cmd":"key", "text"|"code":…, "modifiers":[…]}` — injects through the
/// exact same `AppWindow::key-input` callback path the terminal/RDP surfaces
/// use (see `wire_key_input` in `sessions.rs`).
fn cmd_key(h: &QaHandles, req: &serde_json::Value) -> String {
    let mods = mods_from_names(req);
    if let Some(code) = req.get("code").and_then(|v| v.as_str()) {
        let Some(special) = special_from_code(code) else {
            return error_reply(&format!("unknown key code: {code}"));
        };
        h.ui.invoke_key_input(slint::SharedString::new(), special, mods);
        return serde_json::json!({ "ok": true }).to_string();
    }
    if let Some(text) = req.get("text").and_then(|v| v.as_str()) {
        h.ui.invoke_key_input(slint::SharedString::from(text), 0, mods);
        return serde_json::json!({ "ok": true }).to_string();
    }
    error_reply("\"key\" requires \"text\" or \"code\"")
}

/// `{"cmd":"text","text":…}` — same callback as `cmd_key`'s text path;
/// `input::map_key` already fans a multi-character string out into one
/// `KeyEvent` per scalar, so a whole probe string goes through in one call.
fn cmd_text(h: &QaHandles, req: &serde_json::Value) -> String {
    let Some(text) = req.get("text").and_then(|v| v.as_str()) else {
        return error_reply("\"text\" requires a \"text\" field");
    };
    h.ui.invoke_key_input(slint::SharedString::from(text), 0, 0);
    serde_json::json!({ "ok": true }).to_string()
}

// ── pointer ──────────────────────────────────────────────────────────────

fn button_from_name(v: Option<&str>) -> i32 {
    match v.unwrap_or("left").to_ascii_lowercase().as_str() {
        "right" => 2,
        "middle" => 3,
        "none" => 0,
        _ => 1,
    }
}

/// `{"cmd":"pointer","action":"move|press|release|scroll","x":…,"y":…,
/// "dx":…,"dy":…,"button":…,"modifiers":[…]}` (logical px) — injects through
/// `AppWindow::pointer` / `AppWindow::scroll`, the same callbacks the
/// terminal surface's `TouchArea` uses (see `wire_pointer`/`wire_scroll` in
/// `sessions.rs`). RDP-surface-specific routes (`rdp-scroll`) are out of
/// scope for this generic endpoint (spec's "Out": OS-level input injection
/// only lists SendInput/xdotool, but a dedicated RDP scroll route is not one
/// of the pinned commands either — the active tab's own `pointer`/`scroll`
/// wiring already dispatches to RDP vs terminal internally for move/press/
/// release).
fn cmd_pointer(h: &QaHandles, req: &serde_json::Value) -> String {
    let mods = mods_from_names(req);
    let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let f = |key: &str| {
        req.get(key)
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0) as f32
    };
    match action {
        "move" => {
            h.ui.invoke_pointer(0, 3, f("x"), f("y"), mods);
        }
        "press" => {
            let btn = button_from_name(req.get("button").and_then(|v| v.as_str()));
            h.ui.invoke_pointer(btn, 1, f("x"), f("y"), mods);
        }
        "release" => {
            let btn = button_from_name(req.get("button").and_then(|v| v.as_str()));
            h.ui.invoke_pointer(btn, 2, f("x"), f("y"), mods);
        }
        "scroll" => {
            h.ui.invoke_scroll(f("dx"), f("dy"));
        }
        other => return error_reply(&format!("unknown pointer action: {other}")),
    }
    serde_json::json!({ "ok": true }).to_string()
}

// ── palette ──────────────────────────────────────────────────────────────

/// `{"cmd":"palette","action":"<title>"}` — reopens the palette (rebuilding
/// its model against current tab/detached-session context, exactly as
/// `open-palette` does) then invokes the matching row's action through
/// `AppWindow::palette-activated`, the same callback the Enter key uses
/// (mirroring `handle_palette_key`'s `special == 1` branch in `palette.rs`).
fn cmd_palette(h: &QaHandles, req: &serde_json::Value) -> String {
    let Some(title) = req.get("action").and_then(|v| v.as_str()) else {
        return error_reply("\"palette\" requires an \"action\" field");
    };
    h.ui.invoke_open_palette();
    let row_count = h.palette_model.row_count();
    let idx = (0..row_count).find(|&i| {
        h.palette_model
            .row_data(i)
            .is_some_and(|a| a.label.as_str() == title)
    });
    let Some(idx) = idx else {
        h.ui.set_palette_open(false);
        return error_reply(&format!("no palette action titled {title:?}"));
    };
    h.ui.set_palette_open(false);
    h.ui.set_palette_selected(0);
    palette::dispatch_palette_action(&h.state, &h.tab_model, &h.palette_model, &h.ui, idx);
    serde_json::json!({ "ok": true }).to_string()
}

// ── screenshot ───────────────────────────────────────────────────────────

/// `{"cmd":"screenshot","path":…}` — `Window::take_snapshot()` (confirmed
/// working under `SLINT_BACKEND=winit-femtovg` in xvfb once at least one
/// frame has been rendered by the real event loop — see the P6.2b report's
/// spike notes) encoded as PNG at `path`. Replies only after the file is
/// fully written, per the module doc's sequencing contract.
fn cmd_screenshot(h: &QaHandles, req: &serde_json::Value) -> String {
    let Some(path) = req.get("path").and_then(|v| v.as_str()) else {
        return error_reply("\"screenshot\" requires a \"path\" field");
    };
    let buf = match h.ui.window().take_snapshot() {
        Ok(b) => b,
        Err(e) => return error_reply(&format!("take_snapshot failed: {e}")),
    };
    let (width, height) = (buf.width(), buf.height());
    if let Err(e) = write_png(path, width, height, buf.as_bytes()) {
        return error_reply(&format!("failed to write PNG {path}: {e}"));
    }
    serde_json::json!({ "ok": true, "path": path, "width": width, "height": height }).to_string()
}

fn write_png(path: &str, width: u32, height: u32, rgba: &[u8]) -> std::io::Result<()> {
    let file = std::fs::File::create(path)?;
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder
        .write_header()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    writer
        .write_image_data(rgba)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(())
}

// ── quit ─────────────────────────────────────────────────────────────────

fn cmd_quit() -> String {
    let _ = slint::quit_event_loop();
    // A private sentinel key (not part of the documented protocol) that tells
    // `handle_client` to stop reading further lines after this reply — the
    // event loop is going away, so there is no point accepting more commands.
    serde_json::json!({ "ok": true, "__qa_quit__": true }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── special_from_code ───────────────────────────────────────────────

    #[test]
    fn special_from_code_matches_input_map_key_discriminants() {
        // Kept in sync by hand with `crate::input::map_key`'s special-key
        // table (see the doc comment above `special_from_code`).
        assert_eq!(special_from_code("Enter"), Some(1));
        assert_eq!(special_from_code("Return"), Some(1));
        assert_eq!(special_from_code("Tab"), Some(2));
        assert_eq!(special_from_code("Backspace"), Some(3));
        assert_eq!(special_from_code("Escape"), Some(4));
        assert_eq!(special_from_code("Up"), Some(5));
        assert_eq!(special_from_code("ArrowDown"), Some(6));
        assert_eq!(special_from_code("Delete"), Some(14));
        assert_eq!(special_from_code("F1"), Some(101));
        assert_eq!(special_from_code("F12"), Some(112));
    }

    #[test]
    fn special_from_code_unknown_is_none() {
        assert_eq!(special_from_code("NotAKey"), None);
        assert_eq!(special_from_code(""), None);
    }

    // ── mods_from_names ──────────────────────────────────────────────────

    #[test]
    fn mods_from_names_empty_or_missing_is_zero() {
        assert_eq!(mods_from_names(&serde_json::json!({})), 0);
        assert_eq!(mods_from_names(&serde_json::json!({"modifiers": []})), 0);
    }

    #[test]
    fn mods_from_names_combines_bits() {
        let bits = mods_from_names(&serde_json::json!({"modifiers": ["ctrl", "shift"]}));
        assert_eq!(bits, crate::input::MOD_CTRL | crate::input::MOD_SHIFT);
    }

    #[test]
    fn mods_from_names_is_case_insensitive_and_ignores_unknown() {
        let bits = mods_from_names(&serde_json::json!({"modifiers": ["CTRL", "bogus", "Meta"]}));
        assert_eq!(bits, crate::input::MOD_CTRL | crate::input::MOD_META);
    }

    // ── button_from_name ─────────────────────────────────────────────────

    #[test]
    fn button_from_name_defaults_to_left() {
        assert_eq!(button_from_name(None), 1);
    }

    #[test]
    fn button_from_name_all_variants() {
        assert_eq!(button_from_name(Some("left")), 1);
        assert_eq!(button_from_name(Some("Right")), 2);
        assert_eq!(button_from_name(Some("MIDDLE")), 3);
        assert_eq!(button_from_name(Some("none")), 0);
        assert_eq!(button_from_name(Some("garbage")), 1);
    }

    // ── error_reply / dispatch_line ──────────────────────────────────────

    #[test]
    fn error_reply_is_well_formed_json_with_ok_false() {
        let v: serde_json::Value = serde_json::from_str(&error_reply("boom")).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"], "boom");
    }

    #[test]
    fn dispatch_line_malformed_json_never_panics_and_reports_ok_false() {
        let reply = dispatch_line("{not json");
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["ok"], false);
    }

    #[test]
    fn dispatch_line_empty_object_never_panics() {
        // Valid JSON, no "cmd" field: routed towards the UI thread. No
        // `AppWindow` is constructible in this crate's unit tests (`cm-ui`
        // carries no backend/renderer feature on its own — see `Cargo.toml`'s
        // comment on the `slint` dependency), so this exercises the
        // `invoke_from_event_loop` failure path (no event loop running) and
        // proves it fails soft rather than panicking.
        let reply = dispatch_line("{}");
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["ok"], false);
    }

    // ── P6.3 Wave-1 advisory: bounded reads ─────────────────────────────

    #[test]
    fn read_bounded_line_rejects_unterminated_oversized_input() {
        // A byte stream that never sends '\n' -- proves the length bound
        // trips instead of buffering forever.
        let hostile = vec![b'x'; MAX_LINE_LEN + 1];
        let mut cursor = std::io::Cursor::new(hostile);
        assert!(read_bounded_line(&mut cursor).is_err());
    }

    #[test]
    fn read_bounded_line_accepts_line_within_bound() {
        let mut cursor = std::io::Cursor::new(b"{\"cmd\":\"state\"}\n".to_vec());
        assert_eq!(
            read_bounded_line(&mut cursor).unwrap().as_deref(),
            Some("{\"cmd\":\"state\"}")
        );
    }

    #[test]
    fn read_bounded_line_returns_none_on_immediate_eof() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        assert_eq!(read_bounded_line(&mut cursor).unwrap(), None);
    }
}

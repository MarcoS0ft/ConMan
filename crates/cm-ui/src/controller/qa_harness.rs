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
//!
//! # P7.4 — dialog-aware input (the visual-QA gate's enabler)
//!
//! Before P7.4, `key`/`text`/`pointer` only ever reached the active
//! `TerminalSurface`/RDP pane (see `wire_key_input`/`wire_pointer` in
//! `sessions.rs`) — an agent could not focus a quick-connect field, type into
//! the profile editor, or click a dialog's Save/Cancel, so dialogs (where the
//! 2026-07 Windows UI investigation's #1/#2 defects live) were untestable.
//!
//! Rather than simulating real pointer clicks + keystrokes against dialog
//! widgets (which would need per-widget screen geometry that no `.slint` file
//! currently exposes, and this wave's file ownership keeps `qa_harness.rs` as
//! Lane B's only in-scope file — the dialogs' `.slint` sources belong to other
//! lanes), this module drives dialogs at the same level the Rust controller
//! already does: every dialog's fields are plain `in`/`in-out` properties on
//! `AppWindow` (flat, for quick-connect/host-key/cert-dialog) or a struct
//! property (`ConnProfile`/`GroupForm`/`CredFormData`, for the profile/group/
//! credential editors), and every button is wired to either an
//! `AppWindow` callback (`profile-save`, `qc-connect`, `host-key-accept`, …)
//! or a plain `*-open = false` (Cancel, which every dialog wires inline in
//! `app.slint` rather than through a Rust callback). Setting a field's bound
//! property is the exact end-state effect that focusing it and typing would
//! produce (the same property the Rust `on_*_save` handler reads back), and
//! invoking a button's callback is the exact call a real click makes — so the
//! three new commands below (`dialog_field`, `dialog_click`, `dialog_state`)
//! give scripts a faithful, if not literally keystroke-shaped, way to drive
//! and inspect any dialog. See `dialog_field_names` for the per-dialog field
//! catalog (the rubric's per-kind field-manifest check walks this) and
//! `dialog_click` for the button map.
//!
//! One deliberate asymmetry: `dialog_state`'s bulk field dump omits
//! secret-bearing fields (quick-connect's `secret`/`passphrase`, the
//! credential editor's `secret`/`passphrase`, the kbd-interactive dialog's
//! per-row `value`s) — matching `cmd_state`'s "never any secret material"
//! rule for passive/bulk introspection. An agent that already knows a field
//! is secret-bearing can still round-trip it via an explicit
//! `dialog_field`/`get`or `/set` naming that field (needed to actually drive
//! a password/passphrase field end-to-end) — this is a narrow, deliberate
//! read, not a broad dump.
use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::rc::Rc;
use std::sync::mpsc;
use std::time::Duration;

use serde_json::Value;
use slint::{ComponentHandle, Model};

use crate::generated_ui::{ConnProfile, CredFormData, GroupForm};
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
        "dialog_field" => cmd_dialog_field(h, req),
        "dialog_click" => cmd_dialog_click(h, req),
        "dialog_state" => cmd_dialog_state(h, req),
        "pixel" => cmd_pixel(h, req),
        "close_tab" => cmd_close_tab(h, req),
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
        // P7.4: was missing — the P6.13 keyboard-interactive dialog had no
        // flag in this list, so `state` could not see it was open.
        ("kbd_open", ui.get_kbd_open()),
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
            // P7.6: exposes the status bar's "N detached" pill count so a
            // scenario can assert a cancelled/aborted Connecting session
            // never lands in the detached pool (fixes P7.3-b).
            "detached_count": ui.get_detached_count(),
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
/// `sessions.rs`). `"button"` on `"move"` is optional (P6.5: pass it to script
/// a click-drag — see `cmd_pointer`'s `"move"` arm); omitted defaults to no
/// button (a plain hover). RDP-surface-specific routes (`rdp-scroll`) are out
/// of scope for this generic endpoint (spec's "Out": OS-level input injection
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
            // P6.5: an optional "button" simulates a drag-in-progress move
            // (the button stays logically "held", matching how Slint's
            // `TouchArea` reports move events during a real mouse-captured
            // drag) — needed to script click-drag text selection over the
            // JSON protocol. Omitted (the common hover-probe case) preserves
            // the pre-P6.5 button=none behavior.
            let btn = req
                .get("button")
                .and_then(|v| v.as_str())
                .map_or(0, |name| button_from_name(Some(name)));
            h.ui.invoke_pointer(btn, 3, f("x"), f("y"), mods);
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

// ── dialog (P7.4 enabler) ──────────────────────────────────────────────────
//
// See the module doc for the design rationale. `dialog_field`/`dialog_click`/
// `dialog_state` are the three new commands; everything below is their
// per-dialog plumbing.

/// `value` coercion helpers — a malformed `"value"` (wrong JSON type) is a
/// clear protocol error, never a panic (CONVENTIONS §2).
fn need_str(v: &Value) -> Result<slint::SharedString, String> {
    v.as_str()
        .map(slint::SharedString::from)
        .ok_or_else(|| "expected a string \"value\"".to_string())
}
fn need_i32(v: &Value) -> Result<i32, String> {
    v.as_i64()
        .map(|n| n as i32)
        .ok_or_else(|| "expected an integer \"value\"".to_string())
}
fn need_bool(v: &Value) -> Result<bool, String> {
    v.as_bool()
        .ok_or_else(|| "expected a boolean \"value\"".to_string())
}

fn dialog_open(h: &QaHandles, dialog: &str) -> Result<bool, String> {
    Ok(match dialog {
        "quick_connect" => h.ui.get_quick_connect_open(),
        "profile_editor" => h.ui.get_profile_editor_open(),
        "group_editor" => h.ui.get_group_editor_open(),
        "cred_editor" => h.ui.get_cred_editor_open(),
        "host_key" => h.ui.get_host_key_open(),
        "cert_dialog" => h.ui.get_cert_dialog_open(),
        "kbd_interactive" => h.ui.get_kbd_open(),
        other => return Err(format!("unknown dialog: {other}")),
    })
}

/// The field catalog `dialog_state` bulk-dumps for each dialog. Also what the
/// rubric's per-kind field-manifest check walks (e.g. `profile_editor` has no
/// `domain`/`resolution` entries at all — reading them via `dialog_field`
/// returns `unknown field`, which is precisely the P7.2 defect #2 signal).
/// Deliberately excludes secret-bearing fields (see module doc) — those are
/// still reachable one at a time via an explicit `dialog_field` call.
fn dialog_field_names(dialog: &str) -> &'static [&'static str] {
    match dialog {
        "quick_connect" => &[
            "kind",
            "host",
            "port",
            "username",
            "auth_method",
            "rdp_domain",
            "rdp_resolution",
            "local_program",
            "local_args",
            "local_cwd",
        ],
        "profile_editor" => &[
            "id",
            "name",
            "group_id",
            "kind",
            "host",
            "port",
            "username",
            "auth_method",
            "selected_cred_idx",
            "effective_cred_name",
            "effective_cred_username",
            "effective_inherited",
            "selected_group_idx",
            // P9.6-A Phase C: the mode selector + its non-secret Inline flag.
            // `inline_password` is deliberately excluded here (secret-bearing
            // -- see the module doc), same as `quick_connect`'s
            // `secret`/`passphrase`; still reachable one at a time via an
            // explicit `dialog_field` call (see `profile_field_get`/`_set`).
            "cred_mode",
            "inline_has_secret",
        ],
        "group_editor" => &[
            "id",
            "name",
            "parent_id",
            "default_cred_idx",
            "selected_parent_idx",
        ],
        "cred_editor" => &[
            "id",
            "name",
            "kind",
            "username",
            "folder_id",
            "selected_folder_idx",
        ],
        "host_key" => &[
            "mismatch",
            "host",
            "key_type",
            "fingerprint",
            "stored_fingerprint",
        ],
        "cert_dialog" => &[
            "mismatch",
            "host",
            "subject",
            "fingerprint",
            "stored_fingerprint",
        ],
        "kbd_interactive" => &["name", "instructions"],
        _ => &[],
    }
}

fn qc_field_get(h: &QaHandles, field: &str) -> Result<Value, String> {
    Ok(match field {
        "kind" => Value::from(h.ui.get_qc_kind()),
        "host" => Value::from(h.ui.get_qc_host().as_str()),
        "port" => Value::from(h.ui.get_qc_port().as_str()),
        "username" => Value::from(h.ui.get_qc_username().as_str()),
        "auth_method" => Value::from(h.ui.get_qc_auth_method()),
        "secret" => Value::from(h.ui.get_qc_secret().as_str()),
        "passphrase" => Value::from(h.ui.get_qc_passphrase().as_str()),
        "rdp_domain" => Value::from(h.ui.get_qc_rdp_domain().as_str()),
        "rdp_resolution" => Value::from(h.ui.get_qc_rdp_resolution().as_str()),
        "local_program" => Value::from(h.ui.get_qc_local_program().as_str()),
        "local_args" => Value::from(h.ui.get_qc_local_args().as_str()),
        "local_cwd" => Value::from(h.ui.get_qc_local_cwd().as_str()),
        other => return Err(format!("quick_connect: unknown field {other}")),
    })
}

fn qc_field_set(h: &QaHandles, field: &str, value: &Value) -> Result<(), String> {
    match field {
        "kind" => h.ui.set_qc_kind(need_i32(value)?),
        "host" => h.ui.set_qc_host(need_str(value)?),
        "port" => h.ui.set_qc_port(need_str(value)?),
        "username" => h.ui.set_qc_username(need_str(value)?),
        "auth_method" => h.ui.set_qc_auth_method(need_i32(value)?),
        "secret" => h.ui.set_qc_secret(need_str(value)?),
        "passphrase" => h.ui.set_qc_passphrase(need_str(value)?),
        "rdp_domain" => h.ui.set_qc_rdp_domain(need_str(value)?),
        "rdp_resolution" => h.ui.set_qc_rdp_resolution(need_str(value)?),
        "local_program" => h.ui.set_qc_local_program(need_str(value)?),
        "local_args" => h.ui.set_qc_local_args(need_str(value)?),
        "local_cwd" => h.ui.set_qc_local_cwd(need_str(value)?),
        other => return Err(format!("quick_connect: unknown field {other}")),
    }
    Ok(())
}

/// Pure (no `AppWindow` needed) — reads a [`ConnProfile`] snapshot back as
/// JSON. Split out from the `AppWindow` round-trip so it's unit-testable
/// without a live UI (see the tests module).
fn profile_field_get(f: &ConnProfile, field: &str) -> Result<Value, String> {
    Ok(match field {
        "id" => Value::from(f.id),
        "name" => Value::from(f.name.as_str()),
        "group_id" => Value::from(f.group_id),
        "kind" => Value::from(f.kind),
        "host" => Value::from(f.host.as_str()),
        "port" => Value::from(f.port.as_str()),
        "username" => Value::from(f.username.as_str()),
        "auth_method" => Value::from(f.auth_method),
        "selected_cred_idx" => Value::from(f.selected_cred_idx),
        "effective_cred_name" => Value::from(f.effective_cred_name.as_str()),
        "effective_cred_username" => Value::from(f.effective_cred_username.as_str()),
        "effective_inherited" => Value::from(f.effective_inherited),
        "selected_group_idx" => Value::from(f.selected_group_idx),
        "cred_mode" => Value::from(f.cred_mode),
        "inline_has_secret" => Value::from(f.inline_has_secret),
        "inline_password" => Value::from(f.inline_password.as_str()),
        other => return Err(format!("profile_editor: unknown field {other}")),
    })
}

/// Mutates a [`ConnProfile`] in place — pure, unit-testable (see tests).
/// Deliberately has **no** "kind changed -> fix up port" side effect: unlike
/// `QuickConnectForm`'s `changed kind` handler in `dialogs.slint`,
/// `ProfileEditor` has none (that's the P7.2 defect #2 root cause the 2026-07
/// investigation memo found) — this function must not paper over that by
/// adding one here.
fn profile_field_set(f: &mut ConnProfile, field: &str, value: &Value) -> Result<(), String> {
    match field {
        "id" => f.id = need_i32(value)?,
        "name" => f.name = need_str(value)?,
        "group_id" => f.group_id = need_i32(value)?,
        "kind" => f.kind = need_i32(value)?,
        "host" => f.host = need_str(value)?,
        "port" => f.port = need_str(value)?,
        "username" => f.username = need_str(value)?,
        "auth_method" => f.auth_method = need_i32(value)?,
        "selected_cred_idx" => f.selected_cred_idx = need_i32(value)?,
        "effective_cred_name" => f.effective_cred_name = need_str(value)?,
        "effective_cred_username" => f.effective_cred_username = need_str(value)?,
        "effective_inherited" => f.effective_inherited = need_bool(value)?,
        "selected_group_idx" => f.selected_group_idx = need_i32(value)?,
        "cred_mode" => f.cred_mode = need_i32(value)?,
        "inline_has_secret" => f.inline_has_secret = need_bool(value)?,
        "inline_password" => f.inline_password = need_str(value)?,
        other => return Err(format!("profile_editor: unknown field {other}")),
    }
    Ok(())
}

fn group_field_get(f: &GroupForm, field: &str) -> Result<Value, String> {
    Ok(match field {
        "id" => Value::from(f.id),
        "name" => Value::from(f.name.as_str()),
        "parent_id" => Value::from(f.parent_id),
        "default_cred_idx" => Value::from(f.default_cred_idx),
        "selected_parent_idx" => Value::from(f.selected_parent_idx),
        other => return Err(format!("group_editor: unknown field {other}")),
    })
}

fn group_field_set(f: &mut GroupForm, field: &str, value: &Value) -> Result<(), String> {
    match field {
        "id" => f.id = need_i32(value)?,
        "name" => f.name = need_str(value)?,
        "parent_id" => f.parent_id = need_i32(value)?,
        "default_cred_idx" => f.default_cred_idx = need_i32(value)?,
        "selected_parent_idx" => f.selected_parent_idx = need_i32(value)?,
        other => return Err(format!("group_editor: unknown field {other}")),
    }
    Ok(())
}

fn cred_field_get(f: &CredFormData, field: &str) -> Result<Value, String> {
    Ok(match field {
        "id" => Value::from(f.id),
        "name" => Value::from(f.name.as_str()),
        "kind" => Value::from(f.kind),
        "username" => Value::from(f.username.as_str()),
        "folder_id" => Value::from(f.folder_id),
        "selected_folder_idx" => Value::from(f.selected_folder_idx),
        "secret" => Value::from(f.secret.as_str()),
        "passphrase" => Value::from(f.passphrase.as_str()),
        other => return Err(format!("cred_editor: unknown field {other}")),
    })
}

fn cred_field_set(f: &mut CredFormData, field: &str, value: &Value) -> Result<(), String> {
    match field {
        "id" => f.id = need_i32(value)?,
        "name" => f.name = need_str(value)?,
        "kind" => f.kind = need_i32(value)?,
        "username" => f.username = need_str(value)?,
        "folder_id" => f.folder_id = need_i32(value)?,
        "selected_folder_idx" => f.selected_folder_idx = need_i32(value)?,
        "secret" => f.secret = need_str(value)?,
        "passphrase" => f.passphrase = need_str(value)?,
        other => return Err(format!("cred_editor: unknown field {other}")),
    }
    Ok(())
}

fn host_key_field_get(h: &QaHandles, field: &str) -> Result<Value, String> {
    Ok(match field {
        "mismatch" => Value::from(h.ui.get_host_key_mismatch()),
        "host" => Value::from(h.ui.get_host_key_host().as_str()),
        "key_type" => Value::from(h.ui.get_host_key_type().as_str()),
        "fingerprint" => Value::from(h.ui.get_host_key_fingerprint().as_str()),
        "stored_fingerprint" => Value::from(h.ui.get_host_key_stored_fp().as_str()),
        other => return Err(format!("host_key: unknown field {other}")),
    })
}

fn host_key_field_set(h: &QaHandles, field: &str, value: &Value) -> Result<(), String> {
    match field {
        "mismatch" => h.ui.set_host_key_mismatch(need_bool(value)?),
        "host" => h.ui.set_host_key_host(need_str(value)?),
        "key_type" => h.ui.set_host_key_type(need_str(value)?),
        "fingerprint" => h.ui.set_host_key_fingerprint(need_str(value)?),
        "stored_fingerprint" => h.ui.set_host_key_stored_fp(need_str(value)?),
        other => return Err(format!("host_key: unknown field {other}")),
    }
    Ok(())
}

fn cert_dialog_field_get(h: &QaHandles, field: &str) -> Result<Value, String> {
    Ok(match field {
        "mismatch" => Value::from(h.ui.get_cert_dialog_mismatch()),
        "host" => Value::from(h.ui.get_cert_dialog_host().as_str()),
        "subject" => Value::from(h.ui.get_cert_dialog_subject().as_str()),
        "fingerprint" => Value::from(h.ui.get_cert_dialog_fingerprint().as_str()),
        "stored_fingerprint" => Value::from(h.ui.get_cert_dialog_stored_fp().as_str()),
        other => return Err(format!("cert_dialog: unknown field {other}")),
    })
}

fn cert_dialog_field_set(h: &QaHandles, field: &str, value: &Value) -> Result<(), String> {
    match field {
        "mismatch" => h.ui.set_cert_dialog_mismatch(need_bool(value)?),
        "host" => h.ui.set_cert_dialog_host(need_str(value)?),
        "subject" => h.ui.set_cert_dialog_subject(need_str(value)?),
        "fingerprint" => h.ui.set_cert_dialog_fingerprint(need_str(value)?),
        "stored_fingerprint" => h.ui.set_cert_dialog_stored_fp(need_str(value)?),
        other => return Err(format!("cert_dialog: unknown field {other}")),
    }
    Ok(())
}

/// The kbd-interactive dialog has no flat per-field properties — its prompts
/// are a `[KbdPromptRow]` model. `"prompts"` reads the whole array; a single
/// row's `value` is addressed as `"prompt:<idx>"` (get: reads the row; set:
/// fires `AppWindow::kbd-answer-edited(idx, text)`, the exact callback a real
/// keystroke in that row's `FormField` triggers — see `wire_kbd_answer_edited`
/// in `sessions.rs`, which is what actually mutates the model).
fn kbd_field_get(h: &QaHandles, field: &str) -> Result<Value, String> {
    match field {
        "name" => Ok(Value::from(h.ui.get_kbd_name().as_str())),
        "instructions" => Ok(Value::from(h.ui.get_kbd_instructions().as_str())),
        "prompts" => {
            let model = h.ui.get_kbd_prompts();
            let rows: Vec<Value> = (0..model.row_count())
                .filter_map(|i| model.row_data(i))
                .map(|r| {
                    serde_json::json!({
                        "text": r.text.as_str(),
                        "echo": r.echo,
                        "value": r.value.as_str(),
                    })
                })
                .collect();
            Ok(Value::from(rows))
        }
        other => {
            if let Some(idx_str) = other.strip_prefix("prompt:") {
                let idx: usize = idx_str
                    .parse()
                    .map_err(|_| format!("kbd_interactive: bad prompt index {idx_str:?}"))?;
                let model = h.ui.get_kbd_prompts();
                let row = model
                    .row_data(idx)
                    .ok_or_else(|| format!("kbd_interactive: no prompt at index {idx}"))?;
                Ok(serde_json::json!({
                    "text": row.text.as_str(),
                    "echo": row.echo,
                    "value": row.value.as_str(),
                }))
            } else {
                Err(format!("kbd_interactive: unknown field {other}"))
            }
        }
    }
}

fn kbd_field_set(h: &QaHandles, field: &str, value: &Value) -> Result<(), String> {
    let Some(idx_str) = field.strip_prefix("prompt:") else {
        return Err(format!(
            "kbd_interactive: field {field:?} is not settable (only \"prompt:<idx>\")"
        ));
    };
    let idx: i32 = idx_str
        .parse()
        .map_err(|_| format!("kbd_interactive: bad prompt index {idx_str:?}"))?;
    let text = need_str(value)?;
    h.ui.invoke_kbd_answer_edited(idx, text);
    Ok(())
}

fn dialog_field_get(h: &QaHandles, dialog: &str, field: &str) -> Result<Value, String> {
    match dialog {
        "quick_connect" => qc_field_get(h, field),
        "profile_editor" => profile_field_get(&h.ui.get_profile_form(), field),
        "group_editor" => group_field_get(&h.ui.get_group_form(), field),
        "cred_editor" => cred_field_get(&h.ui.get_cred_form(), field),
        "host_key" => host_key_field_get(h, field),
        "cert_dialog" => cert_dialog_field_get(h, field),
        "kbd_interactive" => kbd_field_get(h, field),
        other => Err(format!("unknown dialog: {other}")),
    }
}

fn dialog_field_set(h: &QaHandles, dialog: &str, field: &str, value: &Value) -> Result<(), String> {
    match dialog {
        "quick_connect" => qc_field_set(h, field, value),
        "profile_editor" => {
            let mut f = h.ui.get_profile_form();
            profile_field_set(&mut f, field, value)?;
            h.ui.set_profile_form(f);
            Ok(())
        }
        "group_editor" => {
            let mut f = h.ui.get_group_form();
            group_field_set(&mut f, field, value)?;
            h.ui.set_group_form(f);
            Ok(())
        }
        "cred_editor" => {
            let mut f = h.ui.get_cred_form();
            cred_field_set(&mut f, field, value)?;
            h.ui.set_cred_form(f);
            Ok(())
        }
        "host_key" => host_key_field_set(h, field, value),
        "cert_dialog" => cert_dialog_field_set(h, field, value),
        "kbd_interactive" => kbd_field_set(h, field, value),
        other => Err(format!("unknown dialog: {other}")),
    }
}

/// `{"cmd":"dialog_field","dialog":"<name>","field":"<name>","action":"get"|"set","value":…}`
/// — the enabler's field half. `action` defaults to `"get"`. See the module
/// doc for why a direct property set is the harness's "focus + inject text".
fn cmd_dialog_field(h: &QaHandles, req: &Value) -> String {
    let Some(dialog) = req.get("dialog").and_then(|v| v.as_str()) else {
        return error_reply("\"dialog_field\" requires a \"dialog\" field");
    };
    let Some(field) = req.get("field").and_then(|v| v.as_str()) else {
        return error_reply("\"dialog_field\" requires a \"field\" field");
    };
    let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("get");
    match action {
        "get" => match dialog_field_get(h, dialog, field) {
            Ok(v) => serde_json::json!({ "ok": true, "value": v }).to_string(),
            Err(e) => error_reply(&e),
        },
        "set" => {
            let Some(value) = req.get("value") else {
                return error_reply("\"dialog_field\" set requires a \"value\"");
            };
            match dialog_field_set(h, dialog, field, value) {
                Ok(()) => serde_json::json!({ "ok": true }).to_string(),
                Err(e) => error_reply(&e),
            }
        }
        other => error_reply(&format!("unknown dialog_field action: {other}")),
    }
}

/// Invokes a named dialog's named button. Cancel buttons are not Rust
/// callbacks (every dialog wires `cancel => { root.*-open = false; }` inline
/// in `app.slint`), so those close the flag directly rather than calling an
/// `invoke_*`; every other button matches a real `AppWindow` callback that a
/// click already fires.
fn dialog_click(h: &QaHandles, dialog: &str, button: &str) -> Result<(), String> {
    match (dialog, button) {
        ("quick_connect", "connect") => h.ui.invoke_qc_connect(),
        ("quick_connect", "cancel") => h.ui.set_quick_connect_open(false),
        ("profile_editor", "save") => h.ui.invoke_profile_save(),
        ("profile_editor", "cancel") => h.ui.set_profile_editor_open(false),
        // P7.6: opens the (root-group) GroupEditor -- same `new-group(0)`
        // callback the sidebar's "+"/context-menu "New group" action fires --
        // so a scenario can screenshot it without pixel-hunting tree rows.
        ("group_editor", "new") => h.ui.invoke_new_group(0),
        ("group_editor", "save") => h.ui.invoke_group_save(),
        ("group_editor", "cancel") => h.ui.set_group_editor_open(false),
        ("cred_editor", "save") => h.ui.invoke_cred_save(),
        ("cred_editor", "cancel") => h.ui.set_cred_editor_open(false),
        ("host_key", "accept") => h.ui.invoke_host_key_accept(),
        ("host_key", "reject") => h.ui.invoke_host_key_reject(),
        ("cert_dialog", "accept") => h.ui.invoke_cert_accept(),
        ("cert_dialog", "reject") => h.ui.invoke_cert_reject(),
        ("kbd_interactive", "submit") => h.ui.invoke_kbd_submit(),
        ("kbd_interactive", "cancel") => h.ui.invoke_kbd_cancel(),
        (other_dialog, other_button) => {
            return Err(format!(
                "no such dialog/button: {other_dialog}/{other_button}"
            ));
        }
    }
    Ok(())
}

/// `{"cmd":"dialog_click","dialog":"<name>","button":"<name>"}` — the
/// enabler's button half.
fn cmd_dialog_click(h: &QaHandles, req: &Value) -> String {
    let Some(dialog) = req.get("dialog").and_then(|v| v.as_str()) else {
        return error_reply("\"dialog_click\" requires a \"dialog\" field");
    };
    let Some(button) = req.get("button").and_then(|v| v.as_str()) else {
        return error_reply("\"dialog_click\" requires a \"button\" field");
    };
    match dialog_click(h, dialog, button) {
        Ok(()) => serde_json::json!({ "ok": true }).to_string(),
        Err(e) => error_reply(&e),
    }
}

/// `{"cmd":"dialog_state","dialog":"<name>"}` -> `{"ok":true,"open":bool,
/// "fields":{...}}` — bulk read of [`dialog_field_names`]'s catalog for one
/// dialog, plus its open flag. The rubric's per-kind field-manifest check
/// (RDP ⇒ {Host,Port,Username,Domain,Resolution,…}) is built on this: a field
/// simply absent from the reply (vs. present with a value) is the signal.
fn cmd_dialog_state(h: &QaHandles, req: &Value) -> String {
    let Some(dialog) = req.get("dialog").and_then(|v| v.as_str()) else {
        return error_reply("\"dialog_state\" requires a \"dialog\" field");
    };
    let open = match dialog_open(h, dialog) {
        Ok(o) => o,
        Err(e) => return error_reply(&e),
    };
    let mut fields = serde_json::Map::new();
    for name in dialog_field_names(dialog) {
        if let Ok(v) = dialog_field_get(h, dialog, name) {
            fields.insert((*name).to_string(), v);
        }
    }
    serde_json::json!({ "ok": true, "open": open, "fields": fields }).to_string()
}

// ── pixel (P7.4: opacity/bleed-through + contrast rubric checks) ───────────

/// Bounds on a `pixel` request — same "cap, don't trust" pattern as
/// [`MAX_LINE_LEN`]: a hostile/malformed request must not make this command
/// scan an unbounded number of pixels.
const MAX_PIXEL_REGIONS: usize = 64;
const MAX_PIXEL_REGION_DIM: u64 = 512;

/// `{"cmd":"pixel","regions":[{"name":…,"x":…,"y":…,"w":…,"h":…}, …]}` —
/// takes one fresh `take_snapshot()` (same source as `screenshot`, but
/// returns averaged-region samples inline instead of writing a PNG) so a
/// script can assert e.g. "this dialog gutter pixel equals the panel token,
/// not the launchpad behind it" without a PNG-decode round trip. `w`/`h`
/// default to `1` (a single-pixel sample); omitted `x`/`y` default to `0`.
fn cmd_pixel(h: &QaHandles, req: &Value) -> String {
    let Some(regions) = req.get("regions").and_then(|v| v.as_array()) else {
        return error_reply("\"pixel\" requires a \"regions\" array");
    };
    if regions.is_empty() {
        return error_reply("\"regions\" must be non-empty");
    }
    if regions.len() > MAX_PIXEL_REGIONS {
        return error_reply(&format!("too many regions (max {MAX_PIXEL_REGIONS})"));
    }
    let buf = match h.ui.window().take_snapshot() {
        Ok(b) => b,
        Err(e) => return error_reply(&format!("take_snapshot failed: {e}")),
    };
    let (width, height) = (buf.width(), buf.height());
    let rgba = buf.as_bytes();

    let mut samples = serde_json::Map::new();
    for (i, r) in regions.iter().enumerate() {
        let name = r
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("region{i}"));
        let x = r.get("x").and_then(Value::as_u64).unwrap_or(0);
        let y = r.get("y").and_then(Value::as_u64).unwrap_or(0);
        let w = r
            .get("w")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .clamp(1, MAX_PIXEL_REGION_DIM);
        let hh = r
            .get("h")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .clamp(1, MAX_PIXEL_REGION_DIM);

        if x >= u64::from(width) || y >= u64::from(height) {
            samples.insert(
                name,
                serde_json::json!({ "error": format!(
                    "region origin ({x},{y}) outside {width}x{height}"
                ) }),
            );
            continue;
        }
        let x_end = (x + w).min(u64::from(width));
        let y_end = (y + hh).min(u64::from(height));

        let (mut rs, mut gs, mut bs, mut as_, mut n) = (0u64, 0u64, 0u64, 0u64, 0u64);
        for py in y..y_end {
            for px in x..x_end {
                let idx = ((py * u64::from(width) + px) * 4) as usize;
                if let Some(px_bytes) = rgba.get(idx..idx + 4) {
                    rs += u64::from(px_bytes[0]);
                    gs += u64::from(px_bytes[1]);
                    bs += u64::from(px_bytes[2]);
                    as_ += u64::from(px_bytes[3]);
                    n += 1;
                }
            }
        }
        if n == 0 {
            samples.insert(name, serde_json::json!({ "error": "empty region" }));
            continue;
        }
        let (r8, g8, b8, a8) = (
            (rs / n) as u8,
            (gs / n) as u8,
            (bs / n) as u8,
            (as_ / n) as u8,
        );
        samples.insert(
            name,
            serde_json::json!({
                "r": r8, "g": g8, "b": b8, "a": a8,
                "hex": format!("#{r8:02x}{g8:02x}{b8:02x}"),
                "n": n,
            }),
        );
    }
    serde_json::json!({ "ok": true, "width": width, "height": height, "samples": samples })
        .to_string()
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

// ── close_tab ────────────────────────────────────────────────────────────

/// `{"cmd":"close_tab","idx":N}` — invokes `AppWindow::close-tab(idx)`, the
/// same callback both the tab strip's own ✕ (`Tab.closed`, `app.slint`) and
/// the ConnectingOverlay's Cancel button (`app.slint`'s `cancel =>` handler)
/// route through. Added for P7.6 so a scenario can assert the Cancel/close
/// path aborts (rather than detaches) a session still `Connecting`, without
/// pixel-hunting for the overlay's Cancel button or the tab's ✕ glyph.
fn cmd_close_tab(h: &QaHandles, req: &Value) -> String {
    let Some(idx) = req.get("idx").and_then(Value::as_i64) else {
        return error_reply("\"close_tab\" requires an \"idx\" field");
    };
    h.ui.invoke_close_tab(idx as i32);
    serde_json::json!({ "ok": true }).to_string()
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

    // ── P7.4 dialog enabler: value coercion ─────────────────────────────

    #[test]
    fn need_str_accepts_string_rejects_other() {
        assert_eq!(need_str(&serde_json::json!("hi")).unwrap().as_str(), "hi");
        assert!(need_str(&serde_json::json!(42)).is_err());
    }

    #[test]
    fn need_i32_accepts_integer_rejects_other() {
        assert_eq!(need_i32(&serde_json::json!(7)).unwrap(), 7);
        assert!(need_i32(&serde_json::json!("7")).is_err());
    }

    #[test]
    fn need_bool_accepts_bool_rejects_other() {
        assert!(need_bool(&serde_json::json!(true)).unwrap());
        assert!(need_bool(&serde_json::json!(1)).is_err());
    }

    // ── P7.4 dialog enabler: per-kind field manifest ─────────────────────
    // The rubric's field-manifest check is built directly on
    // `dialog_field_names`: a dialog missing a field entirely (vs. present
    // with a value) is the FAIL signal for P7.2 defect #2.

    #[test]
    fn profile_editor_field_names_omit_rdp_domain_and_resolution() {
        let names = dialog_field_names("profile_editor");
        assert!(!names.contains(&"rdp_domain"));
        assert!(!names.contains(&"rdp_resolution"));
        assert!(!names.contains(&"domain"));
        assert!(!names.contains(&"resolution"));
    }

    #[test]
    fn quick_connect_field_names_include_rdp_domain_and_resolution() {
        let names = dialog_field_names("quick_connect");
        assert!(names.contains(&"rdp_domain"));
        assert!(names.contains(&"rdp_resolution"));
    }

    #[test]
    fn dialog_field_names_excludes_secret_bearing_fields() {
        // Never a broad dump of secret material — matches `cmd_state`'s rule.
        assert!(!dialog_field_names("quick_connect").contains(&"secret"));
        assert!(!dialog_field_names("quick_connect").contains(&"passphrase"));
        assert!(!dialog_field_names("cred_editor").contains(&"secret"));
        assert!(!dialog_field_names("cred_editor").contains(&"passphrase"));
        assert!(!dialog_field_names("kbd_interactive").contains(&"prompts"));
        // P9.6-A Phase C: the Inline mode's transient password field.
        assert!(!dialog_field_names("profile_editor").contains(&"inline_password"));
    }

    #[test]
    fn profile_editor_field_names_include_cred_mode_selector_fields() {
        // P9.6-A Phase C: the non-secret mode-selector fields ARE bulk-dumpable
        // (mirrors `effective_cred_name`/`effective_inherited` above them).
        let names = dialog_field_names("profile_editor");
        assert!(names.contains(&"cred_mode"));
        assert!(names.contains(&"inline_has_secret"));
        assert!(names.contains(&"effective_cred_username"));
    }

    #[test]
    fn profile_field_get_set_round_trip_cred_mode_selector_fields() {
        // Non-secret fields: readable via the bulk-safe path.
        let mut f = sample_profile();
        profile_field_set(&mut f, "cred_mode", &serde_json::json!(1)).unwrap();
        assert_eq!(
            profile_field_get(&f, "cred_mode").unwrap(),
            serde_json::json!(1)
        );
        profile_field_set(&mut f, "inline_has_secret", &serde_json::json!(true)).unwrap();
        assert_eq!(
            profile_field_get(&f, "inline_has_secret").unwrap(),
            serde_json::json!(true)
        );
        profile_field_set(
            &mut f,
            "effective_cred_username",
            &serde_json::json!("alice"),
        )
        .unwrap();
        assert_eq!(
            profile_field_get(&f, "effective_cred_username").unwrap(),
            serde_json::json!("alice")
        );
        // The secret-bearing field is still reachable one at a time (just not
        // bulk-dumped -- see `dialog_field_names_excludes_secret_bearing_fields`).
        profile_field_set(&mut f, "inline_password", &serde_json::json!("hunter2")).unwrap();
        assert_eq!(
            profile_field_get(&f, "inline_password").unwrap(),
            serde_json::json!("hunter2")
        );
    }

    #[test]
    fn dialog_field_names_unknown_dialog_is_empty() {
        let empty: &[&str] = &[];
        assert_eq!(dialog_field_names("no_such_dialog"), empty);
    }

    // ── P7.4 dialog enabler: ConnProfile field get/set (pure, no AppWindow) ──

    fn sample_profile() -> ConnProfile {
        ConnProfile {
            id: 1,
            name: "svc".into(),
            group_id: 0,
            kind: 0,
            host: "h".into(),
            port: "22".into(),
            username: "u".into(),
            auth_method: 1,
            selected_cred_idx: 0,
            effective_cred_name: "".into(),
            effective_cred_username: "".into(),
            effective_inherited: false,
            selected_group_idx: 0,
            rdp_domain: "".into(),
            rdp_resolution: "".into(),
            cred_mode: 0,
            inline_password: "".into(),
            inline_has_secret: false,
        }
    }

    #[test]
    fn profile_field_get_reads_known_fields() {
        let f = sample_profile();
        assert_eq!(
            profile_field_get(&f, "name").unwrap(),
            serde_json::json!("svc")
        );
        assert_eq!(profile_field_get(&f, "kind").unwrap(), serde_json::json!(0));
    }

    #[test]
    fn profile_field_get_unknown_field_errs() {
        // profile_editor's ConnProfile literally has no domain/resolution
        // member — this IS the P7.2 defect #2 signal, not a harness gap.
        let f = sample_profile();
        assert!(profile_field_get(&f, "domain").is_err());
        assert!(profile_field_get(&f, "resolution").is_err());
    }

    #[test]
    fn profile_field_set_kind_does_not_touch_port() {
        // Root cause of defect #2's port half: setting `kind` alone (what
        // switching the SegmentedControl does) must NOT auto-fix `port` —
        // `ProfileEditor` has no `changed kind` reactive glue, unlike
        // `QuickConnectForm`. This test pins that (buggy, pre-P7.2-fix)
        // behavior so a future fix flips it deliberately, not by accident.
        let mut f = sample_profile();
        profile_field_set(&mut f, "kind", &serde_json::json!(1)).unwrap();
        assert_eq!(f.kind, 1);
        assert_eq!(f.port.as_str(), "22");
    }

    #[test]
    fn profile_field_set_unknown_field_errs() {
        let mut f = sample_profile();
        assert!(profile_field_set(&mut f, "bogus", &serde_json::json!("x")).is_err());
    }

    // ── P7.4 dialog enabler: GroupForm / CredFormData ────────────────────

    #[test]
    fn group_field_get_set_round_trip() {
        let mut f = GroupForm {
            id: 0,
            name: "g".into(),
            parent_id: 0,
            default_cred_idx: 0,
            selected_parent_idx: 0,
        };
        group_field_set(&mut f, "name", &serde_json::json!("renamed")).unwrap();
        assert_eq!(
            group_field_get(&f, "name").unwrap(),
            serde_json::json!("renamed")
        );
    }

    #[test]
    fn cred_field_get_set_round_trip_including_secret() {
        let mut f = CredFormData {
            id: 0,
            name: "c".into(),
            kind: 0,
            username: "".into(),
            folder_id: 0,
            selected_folder_idx: 0,
            secret: "".into(),
            passphrase: "".into(),
        };
        cred_field_set(&mut f, "secret", &serde_json::json!("s3cr3t")).unwrap();
        assert_eq!(
            cred_field_get(&f, "secret").unwrap(),
            serde_json::json!("s3cr3t")
        );
    }

    // ── P7.4 dialog enabler: dispatch never panics without an event loop ──
    // Same pattern as `dispatch_line_empty_object_never_panics` above: no
    // `AppWindow` is constructible in this crate's plain unit tests, so these
    // exercise the `invoke_from_event_loop` failure path end-to-end for the
    // new commands and prove they fail soft.

    #[test]
    fn dispatch_line_dialog_field_never_panics() {
        let reply = dispatch_line(
            r#"{"cmd":"dialog_field","dialog":"quick_connect","field":"host","action":"get"}"#,
        );
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["ok"], false);
    }

    #[test]
    fn dispatch_line_dialog_click_never_panics() {
        let reply =
            dispatch_line(r#"{"cmd":"dialog_click","dialog":"quick_connect","button":"connect"}"#);
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["ok"], false);
    }

    #[test]
    fn dispatch_line_dialog_state_never_panics() {
        let reply = dispatch_line(r#"{"cmd":"dialog_state","dialog":"profile_editor"}"#);
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["ok"], false);
    }

    #[test]
    fn dispatch_line_pixel_never_panics() {
        let reply =
            dispatch_line(r#"{"cmd":"pixel","regions":[{"name":"p","x":0,"y":0,"w":1,"h":1}]}"#);
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["ok"], false);
    }

    // P7.6: `close_tab` is new -- same "handles not initialised in a plain
    // unit test" failure-soft path as the dialog commands above.
    #[test]
    fn dispatch_line_close_tab_never_panics() {
        let reply = dispatch_line(r#"{"cmd":"close_tab","idx":0}"#);
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["ok"], false);
    }
}

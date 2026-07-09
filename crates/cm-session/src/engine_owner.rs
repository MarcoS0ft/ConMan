//! Shared byte-pump engine-owner thread (ARCHITECTURE §4).
//!
//! Both the local PTY session and the SSH session drive the **same** `!Send`
//! [`LibghosttyEngine`] from a single owner thread: only raw bytes and owned
//! [`GridSnapshot`]s cross the channel — the engine never moves. The only
//! difference between transports is *where* encoded input/response bytes go and
//! how a resize is applied to the transport; that is captured by [`Transport`].

use std::sync::mpsc::{Receiver, Sender};
use std::time::Instant;

use cm_core::terminal::{GridSnapshot, KeyEvent, MouseEvent, TerminalEngine, TerminalSize};

use crate::libghostty::{EngineError, LibghosttyEngine};

/// Bracketed-paste wire markers (xterm ctlseqs / VT100.net, DECSET 2004).
/// Single source of truth for the escape bytes (CONVENTIONS §2) — shared by
/// [`wrap_paste`] and its tests.
const BRACKETED_PASTE_START: &[u8] = b"\x1b[200~";
const BRACKETED_PASTE_END: &[u8] = b"\x1b[201~";

/// P6.5: wrap `bytes` in the bracketed-paste start/end markers when
/// `bracketed` is true (the app enabled DECSET 2004 — `Msg::Paste`'s handler
/// below queries this via [`TerminalEngine::bracketed_paste_enabled`]);
/// otherwise return them unchanged. This is the "raw otherwise" half of the
/// P6.5 paste contract (`docs/devel/tasks/
/// P6.5-terminal-selection-copy-paste.md`) — deliberately a byte-for-byte
/// passthrough in the non-bracketed case (no newline-to-CR translation or
/// control-byte stripping), matching `paste()`'s pre-P6.5 behavior exactly so
/// existing callers/tests see no change unless the app actually asked for
/// bracketed paste.
pub(crate) fn wrap_paste(bytes: &[u8], bracketed: bool) -> Vec<u8> {
    if !bracketed {
        return bytes.to_vec();
    }
    let mut out =
        Vec::with_capacity(BRACKETED_PASTE_START.len() + bytes.len() + BRACKETED_PASTE_END.len());
    out.extend_from_slice(BRACKETED_PASTE_START);
    out.extend_from_slice(bytes);
    out.extend_from_slice(BRACKETED_PASTE_END);
    out
}

/// Control messages sent to the engine-owner thread. Only `Vec<u8>` byte
/// payloads and small value types cross the channel — never the engine.
pub(crate) enum Msg {
    /// Bytes received from the transport (PTY output / SSH channel data).
    Bytes(Vec<u8>),
    Key(KeyEvent),
    Mouse(MouseEvent),
    Paste(Vec<u8>),
    Resize(TerminalSize),
    /// P6.7: set the viewport's scroll offset (lines above the live tail,
    /// `0` = tail/follow — see [`ScrollState`]). The offset is the caller's
    /// (`cm-ui`'s) best absolute guess computed from the last `GridSnapshot`
    /// it saw; the owner loop clamps/tracks it from here. A fresh snapshot at
    /// the new position is pushed immediately so a scroll action is not
    /// delayed until the next PTY byte.
    SetScroll(u32),
    /// P6.7: request the full retained buffer as plain-text lines (search).
    /// The owner loop replies on `reply` rather than blocking the sender —
    /// see `TerminalEngine::buffer_text`'s "can be expensive" note.
    QueryBuffer(Sender<Vec<String>>),
    Shutdown,
}

/// P6.7 follow-tail / freeze scroll bookkeeping for the engine-owner loop.
///
/// `Tail` always resolves to the live bottom (offset `0`), so new output
/// naturally keeps showing the tail with no compensation needed. `Frozen`
/// pins the view at the buffer growth-point distance it had when the user
/// last scrolled: as more lines are fed, `scrollback_len()` grows by the same
/// amount the tail does, so `offset0 + (scrollback_len_now -
/// scrollback_len0)` keeps the *same absolute content* on screen instead of
/// drifting forward with the tail. See `docs/devel/memos/
/// P6.7-scrollback-port.md` for the trade-off discussion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScrollState {
    Tail,
    Frozen { offset0: u32, scrollback_len0: u32 },
}

impl ScrollState {
    /// The `scroll_offset` to pass to `TerminalEngine::snapshot` right now,
    /// given the engine's current `scrollback_len`.
    fn effective_offset(self, scrollback_len_now: u32) -> u32 {
        match self {
            ScrollState::Tail => 0,
            ScrollState::Frozen {
                offset0,
                scrollback_len0,
            } => offset0.saturating_add(scrollback_len_now.saturating_sub(scrollback_len0)),
        }
    }

    /// Transition on a user-requested absolute offset-from-tail (already
    /// clamped by the caller against `scrollback_len_now`). `0` always means
    /// "resume following the tail," never a `Frozen` pin at distance zero
    /// (which would otherwise drift away from the tail as output arrives).
    fn set(scrollback_len_now: u32, requested: u32) -> Self {
        let clamped = requested.min(scrollback_len_now);
        if clamped == 0 {
            ScrollState::Tail
        } else {
            ScrollState::Frozen {
                offset0: clamped,
                scrollback_len0: scrollback_len_now,
            }
        }
    }
}

/// The transport-specific sink for the engine owner: where encoded input and
/// engine responses are written, and how a resize is propagated.
pub(crate) trait Transport: Send {
    /// Write encoded input / engine response bytes to the transport.
    fn write(&mut self, bytes: &[u8]);
    /// Propagate a grid resize to the transport (PTY `set_size` / SSH
    /// `window_change`). The engine itself is resized by the owner loop.
    fn resize(&mut self, size: TerminalSize);
}

/// Engine-owner loop: construct the engine, report readiness, then process
/// control messages until `Shutdown` / channel close. Identical for every
/// transport; the `transport` parameter is the only variation point.
pub(crate) fn run_engine_owner<T: Transport>(
    size: TerminalSize,
    mut transport: T,
    control_rx: &Receiver<Msg>,
    snapshot_tx: &Sender<GridSnapshot>,
    ready_tx: &Sender<Result<(), EngineError>>,
    start: Instant,
) {
    let mut engine = match LibghosttyEngine::new(size) {
        Ok(engine) => {
            let _ = ready_tx.send(Ok(()));
            engine
        }
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };
    timing(start, "owner: engine ready");
    let mut logged_feed = false;
    let mut logged_nonempty = false;
    // P6.7: scroll position lives here (not on the engine — see `ScrollState`'s
    // doc comment / the port memo) because this loop is the only place that
    // cheaply knows `scrollback_len()` at the moment new bytes are fed.
    let mut scroll = ScrollState::Tail;

    while let Ok(msg) = control_rx.recv() {
        match msg {
            Msg::Bytes(bytes) => {
                if !logged_feed {
                    timing(start, &format!("owner: first feed ({} bytes)", bytes.len()));
                    logged_feed = true;
                }
                engine.feed(&bytes);
                // Forward any replies the engine produced to host queries (e.g. the
                // DSR cursor-position report). ConPTY blocks ~3 s at startup waiting
                // for these (B7); remote shells benefit from the same prompt reply.
                transport.write(&engine.take_responses());
                let offset = scroll.effective_offset(engine.scrollback_len());
                let snap = engine.snapshot(offset);
                if !logged_nonempty && snap.cells.iter().any(|c| !c.grapheme.is_empty()) {
                    timing(start, "owner: first NON-EMPTY snapshot");
                    // P9.8 D4/§5.3: parallel `debug!` (the existing `timing()`
                    // trace line above is untouched -- this promotes the same
                    // event to a level an operator can see without full trace
                    // spam). This loop is shared by local PTY *and* SSH
                    // sessions (both call `run_engine_owner`), so the message
                    // says "terminal", not "local" -- ttfr_ms (time to first
                    // rendered content) is exactly as meaningful for an SSH
                    // shell as a local one, and this is distinct from the
                    // SSH driver's own "ssh: shell ready" connect_ms (channel
                    // opened, before any output has necessarily arrived).
                    tracing::debug!(
                        ttfr_ms = start.elapsed().as_secs_f64() * 1000.0,
                        "terminal: shell ready"
                    );
                    logged_nonempty = true;
                }
                if snapshot_tx.send(snap).is_err() {
                    break; // consumer gone
                }
            }
            Msg::Key(ev) => transport.write(&engine.encode_key(&ev)),
            Msg::Mouse(ev) => transport.write(&engine.encode_mouse(&ev)),
            Msg::Paste(bytes) => {
                let wrapped = wrap_paste(&bytes, engine.bracketed_paste_enabled());
                transport.write(&wrapped);
            }
            Msg::Resize(new_size) => {
                transport.resize(new_size);
                engine.resize(new_size);
                // A pinned pre-resize scroll position has no well-defined
                // meaning against a reflowed grid (same rationale cm-ui uses
                // to clear a selection on resize) — snap back to the tail.
                scroll = ScrollState::Tail;
                let _ = snapshot_tx.send(engine.snapshot(0));
            }
            Msg::SetScroll(requested) => {
                scroll = ScrollState::set(engine.scrollback_len(), requested);
                let offset = scroll.effective_offset(engine.scrollback_len());
                let _ = snapshot_tx.send(engine.snapshot(offset));
            }
            Msg::QueryBuffer(reply) => {
                let _ = reply.send(engine.buffer_text());
            }
            Msg::Shutdown => break,
        }
    }
    // engine + transport dropped here.
}

/// Emit a B7 startup-timing marker at `trace` level (P6.3: replaces the
/// ad-hoc `CONMAN_TIMING` env-var gate — enable with `CONMAN_LOG=trace` or
/// `CONMAN_LOG=cm_session=trace`; no cost when the level is filtered out).
pub(crate) fn timing(start: Instant, stage: &str) {
    tracing::trace!(elapsed_ms = start.elapsed().as_secs_f64() * 1000.0, stage);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // ── wrap_paste (pure) ────────────────────────────────────────────────

    #[test]
    fn wrap_paste_raw_when_not_bracketed() {
        assert_eq!(wrap_paste(b"hello", false), b"hello".to_vec());
    }

    #[test]
    fn wrap_paste_adds_markers_when_bracketed() {
        assert_eq!(
            wrap_paste(b"hello", true),
            b"\x1b[200~hello\x1b[201~".to_vec()
        );
    }

    #[test]
    fn wrap_paste_bracketed_empty_input_still_wraps() {
        assert_eq!(wrap_paste(b"", true), b"\x1b[200~\x1b[201~".to_vec());
    }

    #[test]
    fn wrap_paste_never_wraps_when_not_bracketed_even_with_tilde_bytes() {
        // Raw passthrough must not be confused by content that happens to
        // look like the markers -- "raw otherwise" means byte-for-byte.
        let input = b"\x1b[200~not a real wrap\x1b[201~";
        assert_eq!(wrap_paste(input, false), input.to_vec());
    }

    // ── run_engine_owner: Msg::Paste end-to-end via a fake Transport ───────

    /// Records every byte sequence written to it; ignores resizes (not
    /// exercised by this test).
    #[derive(Clone, Default)]
    struct RecordingTransport {
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl Transport for RecordingTransport {
        fn write(&mut self, bytes: &[u8]) {
            if !bytes.is_empty() {
                self.written.lock().unwrap().extend_from_slice(bytes);
            }
        }
        fn resize(&mut self, _size: TerminalSize) {}
    }

    /// Drives `run_engine_owner` synchronously (on the test thread) with a
    /// scripted message sequence, returning everything the fake transport
    /// received. Used to prove `Msg::Paste` wraps (or doesn't) depending on
    /// whether the engine has DECSET 2004 enabled -- exercising the exact
    /// code path the real byte-pump uses, without any PTY/echo involved.
    fn drive(messages: Vec<Msg>) -> Vec<u8> {
        let (control_tx, control_rx) = std::sync::mpsc::channel();
        let (snapshot_tx, _snapshot_rx) = std::sync::mpsc::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let transport = RecordingTransport::default();
        let written = transport.written.clone();

        for m in messages {
            control_tx.send(m).unwrap();
        }
        control_tx.send(Msg::Shutdown).unwrap();

        run_engine_owner(
            TerminalSize { rows: 24, cols: 80 },
            transport,
            &control_rx,
            &snapshot_tx,
            &ready_tx,
            Instant::now(),
        );
        ready_rx.try_recv().unwrap().expect("engine init");
        written.lock().unwrap().clone()
    }

    #[test]
    fn paste_is_raw_by_default() {
        let out = drive(vec![Msg::Paste(b"echo hi".to_vec())]);
        assert_eq!(out, b"echo hi".to_vec());
    }

    #[test]
    fn paste_is_bracketed_after_decset_2004_enabled() {
        // Feed the DECSET 2004 enable sequence as if the shell/application
        // announced bracketed-paste support, exactly like the existing
        // `encode_mouse_sgr` engine test enables ?1000/?1006.
        let out = drive(vec![
            Msg::Bytes(b"\x1b[?2004h".to_vec()),
            Msg::Paste(b"echo hi".to_vec()),
        ]);
        assert_eq!(out, b"\x1b[200~echo hi\x1b[201~".to_vec());
    }

    #[test]
    fn paste_reverts_to_raw_after_decset_2004_disabled() {
        let out = drive(vec![
            Msg::Bytes(b"\x1b[?2004h".to_vec()),
            Msg::Paste(b"one".to_vec()),
            Msg::Bytes(b"\x1b[?2004l".to_vec()),
            Msg::Paste(b"two".to_vec()),
        ]);
        assert_eq!(out, b"\x1b[200~one\x1b[201~two".to_vec());
    }

    // ── P6.7: Msg::SetScroll / Msg::QueryBuffer via a fresh engine-owner ────

    /// Like `drive`, but on a caller-chosen `rows x cols` grid (small, so
    /// scrollback fills quickly) and returns every [`GridSnapshot`] pushed to
    /// `snapshot_tx`, in order.
    fn drive_snapshots(rows: u16, cols: u16, messages: Vec<Msg>) -> Vec<GridSnapshot> {
        let (control_tx, control_rx) = std::sync::mpsc::channel();
        let (snapshot_tx, snapshot_rx) = std::sync::mpsc::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let transport = RecordingTransport::default();

        for m in messages {
            control_tx.send(m).unwrap();
        }
        control_tx.send(Msg::Shutdown).unwrap();

        run_engine_owner(
            TerminalSize { rows, cols },
            transport,
            &control_rx,
            &snapshot_tx,
            &ready_tx,
            Instant::now(),
        );
        ready_rx.try_recv().unwrap().expect("engine init");
        snapshot_rx.try_iter().collect()
    }

    /// `Msg::Bytes` for 10 numbered lines ("L0".."L9"), each on its own row —
    /// enough to scroll a 4-row grid.
    fn ten_numbered_lines() -> Vec<Msg> {
        (0..10)
            .map(|i| Msg::Bytes(format!("L{i}\r\n").into_bytes()))
            .collect()
    }

    #[test]
    fn set_scroll_pushes_a_snapshot_immediately_at_the_requested_offset() {
        let mut msgs = ten_numbered_lines();
        msgs.push(Msg::SetScroll(3));
        let snaps = drive_snapshots(4, 10, msgs);
        assert_eq!(snaps.last().unwrap().scroll_offset, 3);
    }

    #[test]
    fn set_scroll_zero_resumes_tail_follow() {
        let mut msgs = ten_numbered_lines();
        msgs.push(Msg::SetScroll(3));
        msgs.push(Msg::Bytes(b"more\r\n".to_vec()));
        msgs.push(Msg::SetScroll(0));
        msgs.push(Msg::Bytes(b"tail\r\n".to_vec()));
        let snaps = drive_snapshots(4, 10, msgs);
        assert_eq!(snaps.last().unwrap().scroll_offset, 0);
    }

    #[test]
    fn frozen_scroll_does_not_drift_when_new_output_arrives() {
        // Scroll back (clamped to the max available), then feed one more
        // line: the pinned offset must grow by exactly the scrollback growth
        // so the same absolute content stays on screen (follow-tail semantics
        // are the caller's problem only at offset 0 — see `ScrollState`).
        let mut msgs = ten_numbered_lines();
        msgs.push(Msg::SetScroll(9_999)); // clamps to whatever is available
        let before = drive_snapshots(4, 10, msgs);
        let before_last = before.last().unwrap();

        let mut msgs2 = ten_numbered_lines();
        msgs2.push(Msg::SetScroll(9_999));
        msgs2.push(Msg::Bytes(b"L10\r\n".to_vec()));
        let after = drive_snapshots(4, 10, msgs2);
        let after_last = after.last().unwrap();

        assert_eq!(after_last.scrollback_len, before_last.scrollback_len + 1);
        assert_eq!(
            after_last.scroll_offset,
            before_last.scroll_offset + 1,
            "the pinned view should track buffer growth 1:1, not reset or drift with the tail"
        );
    }

    #[test]
    fn resize_resets_scroll_to_tail() {
        let mut msgs = ten_numbered_lines();
        msgs.push(Msg::SetScroll(3));
        msgs.push(Msg::Resize(TerminalSize { rows: 4, cols: 10 }));
        let snaps = drive_snapshots(4, 10, msgs);
        assert_eq!(snaps.last().unwrap().scroll_offset, 0);
    }

    #[test]
    fn query_buffer_replies_with_the_full_text_oldest_first() {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        let mut msgs: Vec<Msg> = (0..5)
            .map(|i| Msg::Bytes(format!("L{i}\r\n").into_bytes()))
            .collect();
        msgs.push(Msg::QueryBuffer(reply_tx));
        let _ = drive_snapshots(4, 10, msgs);
        let lines = reply_rx.try_recv().expect("buffer reply");
        assert_eq!(lines[0], "L0");
        assert!(lines.iter().any(|l| l == "L4"));
    }

    #[test]
    fn query_buffer_on_empty_terminal_replies_without_blocking() {
        // Empty-input edge case (CONVENTIONS §2): no bytes fed at all.
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        let _ = drive_snapshots(4, 10, vec![Msg::QueryBuffer(reply_tx)]);
        let lines = reply_rx.try_recv().expect("buffer reply");
        assert_eq!(lines.len(), 4);
    }
}

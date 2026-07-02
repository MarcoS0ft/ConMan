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
    Shutdown,
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
                let snap = engine.snapshot();
                if !logged_nonempty && snap.cells.iter().any(|c| !c.grapheme.is_empty()) {
                    timing(start, "owner: first NON-EMPTY snapshot");
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
                let _ = snapshot_tx.send(engine.snapshot());
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
}

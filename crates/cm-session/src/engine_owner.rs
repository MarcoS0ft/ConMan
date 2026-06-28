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
            Msg::Paste(bytes) => transport.write(&bytes),
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

/// Emit a B7 startup-timing marker on stderr when `CONMAN_TIMING` is set (no cost otherwise).
pub(crate) fn timing(start: Instant, stage: &str) {
    if std::env::var_os("CONMAN_TIMING").is_some() {
        eprintln!(
            "[timing] {:>8.1} ms  {stage}",
            start.elapsed().as_secs_f64() * 1000.0
        );
    }
}

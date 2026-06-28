//! Local shell terminal session: a PTY-backed [`cm_core::TerminalEngine`]
//! driver realizing the ARCHITECTURE §4 byte-pump on dedicated OS threads.
//!
//! Two threads back each session:
//! - **PTY reader** — blocking-reads the PTY master and forwards `Vec<u8>`
//!   chunks to the owner thread; exits on EOF (child exit) or error.
//! - **engine owner** — owns the `!Send` [`LibghosttyEngine`] for its whole
//!   life, plus the PTY writer and master handle. It drains a single control
//!   channel: feeds PTY bytes into the engine and publishes a fresh
//!   [`GridSnapshot`]; encodes key/mouse input and writes it to the PTY; writes
//!   pastes; resizes both the PTY and the engine; and stops on `Shutdown`.
//!
//! Only **bytes** and the owned **`GridSnapshot`** cross thread boundaries —
//! the engine itself never moves. Local PTY I/O is blocking, so plain OS
//! threads are used (tokio is reserved for the network transports in P3/P4).
//!
//! This module is gated on the `engine-libghostty` feature: the session is
//! concrete over [`LibghosttyEngine`]. A cross-protocol `SessionProvider`
//! trait is intentionally **not** introduced here — it is generalized in P3
//! once SSH provides a second data point.

use std::io::{Read, Write};
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use cm_core::terminal::{GridSnapshot, KeyEvent, MouseEvent, TerminalEngine, TerminalSize};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};

use crate::libghostty::{EngineError, LibghosttyEngine};
use cm_core::LocalSettings;

/// Read buffer size for the PTY reader thread.
const READ_BUF_LEN: usize = 8192;

/// Errors spawning or driving a [`LocalTerminalSession`].
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The PTY could not be opened or its reader/writer could not be obtained.
    #[error("failed to open pty: {0}")]
    OpenPty(String),
    /// The shell process could not be spawned.
    #[error("failed to spawn shell: {0}")]
    Spawn(String),
    /// An OS thread could not be started.
    #[error("failed to start session thread: {0}")]
    Thread(#[source] std::io::Error),
    /// The terminal engine failed to initialize on its owner thread.
    #[error("terminal engine init failed: {0}")]
    Engine(#[source] EngineError),
    /// The engine-owner thread terminated before reporting readiness.
    #[error("engine owner thread failed to start")]
    EngineStartup,
}

/// The exit status of the session's shell process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    pub success: bool,
    pub code: u32,
}

/// Control messages sent to the engine-owner thread. Only `Vec<u8>` byte
/// payloads and small value types cross the channel — never the engine.
enum Msg {
    PtyBytes(Vec<u8>),
    Key(KeyEvent),
    Mouse(MouseEvent),
    Paste(Vec<u8>),
    Resize(TerminalSize),
    Shutdown,
}

/// A live local shell session: a spawned PTY child plus its byte-pump threads.
///
/// `Send` (it holds only channels, join handles, and the child); the `!Send`
/// engine stays confined to the owner thread.
#[derive(Debug)]
pub struct LocalTerminalSession {
    control_tx: Sender<Msg>,
    snapshot_rx: Receiver<GridSnapshot>,
    owner_handle: Option<JoinHandle<()>>,
    reader_handle: Option<JoinHandle<()>>,
    child: Mutex<Box<dyn Child + Send + Sync>>,
}

impl LocalTerminalSession {
    /// Spawn the shell described by `cfg` (a `None` program means the OS default
    /// shell) at the given initial grid size, wiring up the byte-pump threads.
    ///
    /// # Errors
    /// Returns a [`SessionError`] if the PTY cannot be opened, the shell cannot
    /// be spawned, a thread cannot start, or the engine fails to initialize.
    pub fn spawn(cfg: &LocalSettings, size: TerminalSize) -> Result<Self, SessionError> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(to_pty_size(size))
            .map_err(|e| SessionError::OpenPty(e.to_string()))?;

        let mut child = pair
            .slave
            .spawn_command(build_command(cfg))
            .map_err(|e| SessionError::Spawn(e.to_string()))?;
        // Drop our slave handle so the child is the sole slave owner; the master
        // then sees EOF when the child exits.
        drop(pair.slave);

        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| SessionError::OpenPty(e.to_string()))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| SessionError::OpenPty(e.to_string()))?;
        let master = pair.master;

        let (control_tx, control_rx) = mpsc::channel::<Msg>();
        let (snapshot_tx, snapshot_rx) = mpsc::channel::<GridSnapshot>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), EngineError>>();

        // B7 startup-latency instrumentation (gated on CONMAN_TIMING; see `timing`).
        let start = std::time::Instant::now();

        let reader_tx = control_tx.clone();
        let reader_handle = thread::Builder::new()
            .name("pty-reader".to_owned())
            .spawn(move || reader_loop(reader, &reader_tx, start))
            .map_err(SessionError::Thread)?;

        let owner_handle = thread::Builder::new()
            .name("vt-engine-owner".to_owned())
            .spawn(move || {
                owner_loop(
                    size,
                    master,
                    writer,
                    &control_rx,
                    &snapshot_tx,
                    &ready_tx,
                    start,
                );
            })
            .map_err(SessionError::Thread)?;

        // Wait for the owner thread to construct the engine (or report failure).
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                control_tx,
                snapshot_rx,
                owner_handle: Some(owner_handle),
                reader_handle: Some(reader_handle),
                child: Mutex::new(child),
            }),
            Ok(Err(engine_err)) => {
                // Engine init failed: tear down the child and both threads.
                let _ = child.kill();
                let _ = reader_handle.join();
                let _ = owner_handle.join();
                let _ = child.wait();
                Err(SessionError::Engine(engine_err))
            }
            Err(_) => {
                let _ = child.kill();
                let _ = reader_handle.join();
                let _ = owner_handle.join();
                let _ = child.wait();
                Err(SessionError::EngineStartup)
            }
        }
    }

    /// The stream of viewport snapshots produced as PTY output is processed.
    /// Drain it with `recv`/`recv_timeout`/`try_recv`.
    #[must_use]
    pub fn snapshots(&self) -> &Receiver<GridSnapshot> {
        &self.snapshot_rx
    }

    /// Encode a key event and write it to the PTY. Dropped if the session has
    /// shut down.
    pub fn send_key(&self, ev: KeyEvent) {
        let _ = self.control_tx.send(Msg::Key(ev));
    }

    /// Encode a mouse event and write it to the PTY (subject to the terminal's
    /// active mouse mode). Dropped if the session has shut down.
    pub fn send_mouse(&self, ev: MouseEvent) {
        let _ = self.control_tx.send(Msg::Mouse(ev));
    }

    /// Write raw pasted bytes to the PTY.
    pub fn paste(&self, bytes: Vec<u8>) {
        let _ = self.control_tx.send(Msg::Paste(bytes));
    }

    /// Resize the PTY and the engine grid to `size`.
    pub fn resize(&self, size: TerminalSize) {
        let _ = self.control_tx.send(Msg::Resize(size));
    }

    /// The shell's exit status, or `None` while it is still running.
    #[must_use]
    pub fn exit_status(&self) -> Option<ExitStatus> {
        let mut child = self.child.lock().ok()?;
        match child.try_wait() {
            Ok(Some(status)) => Some(ExitStatus {
                success: status.success(),
                code: status.exit_code(),
            }),
            _ => None,
        }
    }

    /// Signal shutdown, kill the child if still running, and join both threads.
    pub fn shutdown(mut self) {
        // Killing the child closes the PTY, unblocking the reader's read().
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
        }
        let _ = self.control_tx.send(Msg::Shutdown);
        if let Some(h) = self.owner_handle.take() {
            let _ = h.join();
        }
        if let Some(h) = self.reader_handle.take() {
            let _ = h.join();
        }
        if let Ok(mut child) = self.child.lock() {
            let _ = child.wait();
        }
    }
}

impl Drop for LocalTerminalSession {
    fn drop(&mut self) {
        // Best-effort cleanup for a session dropped without `shutdown()`: kill
        // the child and signal the owner so the threads terminate. Threads are
        // detached (not joined) to avoid blocking in `drop`.
        if self.owner_handle.is_none() && self.reader_handle.is_none() {
            return; // already shut down cleanly
        }
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
        }
        let _ = self.control_tx.send(Msg::Shutdown);
    }
}

fn to_pty_size(size: TerminalSize) -> PtySize {
    PtySize {
        rows: size.rows,
        cols: size.cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn build_command(cfg: &LocalSettings) -> CommandBuilder {
    let mut cmd = match &cfg.program {
        Some(program) => CommandBuilder::new(program),
        None => CommandBuilder::new_default_prog(),
    };
    cmd.args(&cfg.args);
    if let Some(dir) = &cfg.working_dir {
        cmd.cwd(dir);
    }
    for (key, value) in &cfg.env {
        cmd.env(key, value);
    }
    cmd
}

/// Emit a B7 startup-timing marker on stderr when `CONMAN_TIMING` is set (no cost otherwise).
fn timing(start: std::time::Instant, stage: &str) {
    if std::env::var_os("CONMAN_TIMING").is_some() {
        eprintln!(
            "[timing] {:>8.1} ms  {stage}",
            start.elapsed().as_secs_f64() * 1000.0
        );
    }
}

/// PTY reader thread: forward output chunks until EOF or error.
fn reader_loop(
    mut reader: Box<dyn Read + Send>,
    control_tx: &Sender<Msg>,
    start: std::time::Instant,
) {
    let mut buf = [0u8; READ_BUF_LEN];
    let mut first = true;
    let dump_raw = std::env::var_os("CONMAN_TIMING_RAW").is_some();
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break, // EOF: child exited / PTY closed
            Ok(n) => {
                if first {
                    timing(start, &format!("reader: first PTY read ({n} bytes)"));
                    first = false;
                }
                if dump_raw {
                    let hex: String = buf[..n.min(64)]
                        .iter()
                        .map(|b| format!("{b:02x} "))
                        .collect();
                    timing(start, &format!("reader chunk ({n} bytes): {hex}"));
                }
                if control_tx.send(Msg::PtyBytes(buf[..n].to_vec())).is_err() {
                    break; // owner gone
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break, // PTY closed or read error
        }
    }
}

/// Engine-owner thread: owns the `!Send` engine, the PTY writer, and the master
/// handle; processes control messages and publishes snapshots.
fn owner_loop(
    size: TerminalSize,
    master: Box<dyn MasterPty + Send>,
    mut writer: Box<dyn Write + Send>,
    control_rx: &Receiver<Msg>,
    snapshot_tx: &Sender<GridSnapshot>,
    ready_tx: &Sender<Result<(), EngineError>>,
    start: std::time::Instant,
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
            Msg::PtyBytes(bytes) => {
                if !logged_feed {
                    timing(start, &format!("owner: first feed ({} bytes)", bytes.len()));
                    logged_feed = true;
                }
                engine.feed(&bytes);
                // Forward any replies the engine produced to host queries (e.g. the
                // DSR cursor-position report). ConPTY/conhost blocks ~3 s at startup
                // waiting for these before emitting the shell prompt (B7).
                write_all(&mut writer, &engine.take_responses());
                let snap = engine.snapshot();
                if !logged_nonempty && snap.cells.iter().any(|c| !c.grapheme.is_empty()) {
                    timing(start, "owner: first NON-EMPTY snapshot");
                    logged_nonempty = true;
                }
                if snapshot_tx.send(snap).is_err() {
                    break; // consumer gone
                }
            }
            Msg::Key(ev) => write_all(&mut writer, &engine.encode_key(&ev)),
            Msg::Mouse(ev) => write_all(&mut writer, &engine.encode_mouse(&ev)),
            Msg::Paste(bytes) => write_all(&mut writer, &bytes),
            Msg::Resize(new_size) => {
                let _ = master.resize(to_pty_size(new_size));
                engine.resize(new_size);
                let _ = snapshot_tx.send(engine.snapshot());
            }
            Msg::Shutdown => break,
        }
    }
    // engine, writer, and master are dropped here, closing the master end.
}

fn write_all(writer: &mut Box<dyn Write + Send>, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let _ = writer.write_all(bytes);
    let _ = writer.flush();
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use cm_core::terminal::Key;
    use std::time::{Duration, Instant};

    fn sh(args: &[&str]) -> LocalSettings {
        LocalSettings {
            program: Some("sh".to_owned()),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            working_dir: None,
            env: Vec::new(),
        }
    }

    fn row_text(snap: &GridSnapshot, row: u16) -> String {
        let cols = usize::from(snap.size.cols);
        let start = usize::from(row) * cols;
        snap.cells[start..start + cols]
            .iter()
            .map(|c| {
                if c.grapheme.is_empty() {
                    " "
                } else {
                    &c.grapheme
                }
            })
            .collect::<String>()
    }

    fn snapshot_contains(snap: &GridSnapshot, needle: &str) -> bool {
        (0..snap.size.rows).any(|r| row_text(snap, r).contains(needle))
    }

    /// Drain snapshots until one contains `needle` or the timeout elapses.
    fn wait_for_text(session: &LocalTerminalSession, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match session.snapshots().recv_timeout(remaining) {
                Ok(snap) => {
                    if snapshot_contains(&snap, needle) {
                        return true;
                    }
                }
                Err(_) => return false,
            }
        }
    }

    #[test]
    fn spawn_and_capture_output() {
        let session = LocalTerminalSession::spawn(
            &sh(&["-c", "printf 'HELLO_PTY\\n'"]),
            TerminalSize { rows: 24, cols: 80 },
        )
        .expect("spawn");
        assert!(
            wait_for_text(&session, "HELLO_PTY", Duration::from_secs(5)),
            "expected shell output in the grid"
        );
        session.shutdown();
    }

    #[test]
    fn key_enter_round_trips_to_shell() {
        // Interactive shell reading from the PTY.
        let session = LocalTerminalSession::spawn(&sh(&[]), TerminalSize { rows: 24, cols: 80 })
            .expect("spawn");
        // Type a command whose OUTPUT differs from the echoed input, so a match
        // proves Enter reached the shell and it executed.
        session.paste(b"echo MARK$((6*7))".to_vec());
        session.send_key(KeyEvent {
            key: Key::Enter,
            mods: cm_core::terminal::KeyModifiers::default(),
        });
        assert!(
            wait_for_text(&session, "MARK42", Duration::from_secs(5)),
            "expected the shell to execute the typed command"
        );
        session.shutdown();
    }

    #[test]
    fn resize_changes_snapshot_dimensions() {
        let session = LocalTerminalSession::spawn(&sh(&[]), TerminalSize { rows: 24, cols: 80 })
            .expect("spawn");
        // Produce an initial snapshot so the stream is flowing.
        session.paste(b"printf 'READY\\n'\n".to_vec());
        assert!(wait_for_text(&session, "READY", Duration::from_secs(5)));

        let new_size = TerminalSize {
            rows: 30,
            cols: 100,
        };
        session.resize(new_size);

        // The resize publishes a snapshot at the new dimensions.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut seen = None;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match session.snapshots().recv_timeout(remaining) {
                Ok(snap) if snap.size == new_size => {
                    seen = Some(snap.size);
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        assert_eq!(seen, Some(new_size), "snapshot should reflect the new size");
        session.shutdown();
    }

    #[test]
    fn exit_status_reports_after_child_exits() {
        let session = LocalTerminalSession::spawn(
            &sh(&["-c", "exit 0"]),
            TerminalSize { rows: 24, cols: 80 },
        )
        .expect("spawn");

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut status = None;
        while Instant::now() < deadline {
            if let Some(s) = session.exit_status() {
                status = Some(s);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            status,
            Some(ExitStatus {
                success: true,
                code: 0
            })
        );
        session.shutdown();
    }

    #[test]
    fn shutdown_does_not_hang() {
        // A shell that never exits on its own; shutdown must kill + join it.
        let session = LocalTerminalSession::spawn(&sh(&[]), TerminalSize { rows: 24, cols: 80 })
            .expect("spawn");

        let (done_tx, done_rx) = mpsc::channel::<()>();
        thread::spawn(move || {
            session.shutdown();
            let _ = done_tx.send(());
        });
        assert!(
            done_rx.recv_timeout(Duration::from_secs(10)).is_ok(),
            "shutdown() hung"
        );
    }
}

#[cfg(all(test, unix))]
mod resize_storm_tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn sh() -> LocalSettings {
        LocalSettings {
            program: Some("sh".to_owned()),
            args: Vec::new(),
            working_dir: None,
            env: Vec::new(),
        }
    }

    /// A burst of resizes with no gaps (a "resize storm") must leave the engine snapshot at
    /// the **last** requested size — confirms the session layer is last-write-wins, so B6's
    /// stale-size symptom is fixed at the controller (resize debouncing), not here.
    #[test]
    fn last_resize_in_a_storm_wins() {
        let s = LocalTerminalSession::spawn(&sh(), TerminalSize { rows: 24, cols: 80 }).unwrap();
        // Fire a burst with no delay between requests.
        for (rows, cols) in [(10, 40), (40, 120), (12, 50), (30, 100)] {
            s.resize(TerminalSize { rows, cols });
        }
        let final_size = TerminalSize {
            rows: 30,
            cols: 100,
        };
        // Drain snapshots for a moment; the last one must reflect the final requested size.
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut last = None;
        while Instant::now() < deadline {
            match s.snapshots().recv_timeout(Duration::from_millis(200)) {
                Ok(snap) => last = Some(snap.size),
                Err(_) => break,
            }
        }
        assert_eq!(
            last,
            Some(final_size),
            "engine grid must settle at the last resize"
        );
        s.shutdown();
    }
}

/// B7 startup-latency profiling (cross-platform: uses the OS default shell so it runs on
/// Windows/ConPTY too). Run explicitly with `--ignored --nocapture`; set `CONMAN_TIMING=1`
/// for the per-stage breakdown. Measures spawn → first non-empty snapshot, isolating the
/// session/PTY layer from the GUI/render path.
#[cfg(test)]
mod startup_timing {
    use super::*;
    use std::time::{Duration, Instant};

    /// Spawn one session and return `(time spawn() returned, time-to-first-non-empty-snapshot,
    /// the live session)`. Both durations are measured from `t0` (set at the call site so the
    /// per-spawn cost is isolated). The session is returned alive so the caller decides when to
    /// shut it down — keeping prior sessions alive reproduces the "pre-warm still running" case.
    /// Build the probe shell config. Defaults to the OS shell, but `CONMAN_PROBE_PROG`
    /// (program) + `CONMAN_PROBE_ARGS` (`;`-separated) override it, so the same timing
    /// harness can localize the ConPTY lag across programs (e.g. interactive `cmd` vs
    /// `cmd /c echo` vs a different shell) without code changes.
    fn probe_settings() -> LocalSettings {
        match std::env::var("CONMAN_PROBE_PROG") {
            Ok(prog) if !prog.is_empty() => LocalSettings {
                program: Some(prog),
                args: std::env::var("CONMAN_PROBE_ARGS")
                    .ok()
                    .map(|a| {
                        a.split(';')
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                working_dir: None,
                env: Vec::new(),
            },
            _ => LocalSettings::default(),
        }
    }

    fn measure_first_nonempty(
        size: TerminalSize,
    ) -> (Duration, Option<Duration>, LocalTerminalSession) {
        let t0 = Instant::now();
        let s = LocalTerminalSession::spawn(&probe_settings(), size).expect("spawn");
        let spawned = t0.elapsed();
        // Diagnostic poke: write to the PTY immediately after spawn to test whether conhost
        // gates its first output flush on input/handshake activity (set CONMAN_PROBE_POKE).
        if std::env::var_os("CONMAN_PROBE_POKE").is_some() {
            s.paste(b"\r".to_vec());
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut first_nonempty = None;
        while Instant::now() < deadline {
            if let Ok(snap) = s.snapshots().recv_timeout(Duration::from_millis(250))
                && snap.cells.iter().any(|c| !c.grapheme.is_empty())
            {
                first_nonempty = Some(t0.elapsed());
                break;
            }
        }
        (spawned, first_nonempty, s)
    }

    fn fmt_ms(d: Option<Duration>) -> String {
        d.map(|d| format!("{:.1} ms", d.as_secs_f64() * 1000.0))
            .unwrap_or_else(|| "NEVER (timed out)".to_string())
    }

    #[test]
    #[ignore = "B7 profiling aid; run with --ignored --nocapture (optionally CONMAN_TIMING=1)"]
    fn time_to_first_nonempty_snapshot() {
        let size = TerminalSize {
            rows: 30,
            cols: 100,
        };
        let (spawned, first_nonempty, s) = measure_first_nonempty(size);
        eprintln!(
            "[B7] spawn() returned at {:.1} ms; first NON-EMPTY snapshot at {}",
            spawned.as_secs_f64() * 1000.0,
            fmt_ms(first_nonempty)
        );
        assert!(first_nonempty.is_some(), "no shell output within 15s");
        s.shutdown();
    }

    /// B7 cold-start-vs-per-spawn determination: spawn several sessions back-to-back **in one
    /// process**, keeping each alive, and report each one's time-to-first-non-empty-snapshot.
    /// On Windows this localizes the ~3 s ConPTY/conhost lag:
    /// - if only spawn #1 is slow and #2.. are fast → a **one-time cold start** (pre-warmable:
    ///   spawn a throwaway session at app launch so the first real tab is instant);
    /// - if every spawn is slow → a **per-spawn** conhost cost (pre-warming a single throwaway
    ///   won't help the 2nd+ tab; see the task report for options).
    #[test]
    #[ignore = "B7 cold-start probe; run with --ignored --nocapture (optionally CONMAN_TIMING=1)"]
    fn back_to_back_spawns_cold_start_vs_per_spawn() {
        let size = TerminalSize {
            rows: 30,
            cols: 100,
        };
        const N: usize = 5;
        let mut sessions = Vec::with_capacity(N);
        let mut firsts = Vec::with_capacity(N);
        for i in 0..N {
            let (spawned, first_nonempty, s) = measure_first_nonempty(size);
            eprintln!(
                "[B7] spawn #{i}: spawn() returned at {:.1} ms; first NON-EMPTY snapshot at {}",
                spawned.as_secs_f64() * 1000.0,
                fmt_ms(first_nonempty)
            );
            firsts.push(first_nonempty);
            sessions.push(s);
        }
        let verdict = match (firsts.first().copied().flatten(), firsts.get(1..)) {
            (Some(first), Some(rest)) if !rest.is_empty() => {
                let rest_max = rest
                    .iter()
                    .filter_map(|d| *d)
                    .fold(Duration::ZERO, Duration::max);
                if first.as_secs_f64() > 0.5 && rest_max.as_secs_f64() * 2.0 < first.as_secs_f64() {
                    "COLD-START (one-time; pre-warmable)"
                } else {
                    "PER-SPAWN (each spawn pays the cost)"
                }
            }
            _ => "INCONCLUSIVE",
        };
        eprintln!("[B7] verdict: {verdict}");
        for s in sessions {
            s.shutdown();
        }
        assert!(
            firsts.iter().all(Option::is_some),
            "some spawn produced no shell output within 15s"
        );
    }
}

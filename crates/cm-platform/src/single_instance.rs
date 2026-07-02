//! Single-instance guard (P6.16).
//!
//! ConMan is a per-user desktop app; only one instance should own the primary
//! window. This is implemented as a **`std`-only, loopback-TCP lock** — no
//! platform-native mutex/socket APIs, so the same code path runs on Windows,
//! Linux, and macOS:
//!
//! - The first launch binds `127.0.0.1:<port>` (see [`DEFAULT_PORT`] /
//!   [`PORT_ENV_VAR`]) and keeps the listener open for the life of the
//!   process. That bound socket *is* the lock.
//! - A second launch fails to bind the same port, so it connects instead and
//!   sends a small fixed, versioned handshake line. If the peer answers
//!   correctly (i.e. it really is a ConMan primary and not an unrelated
//!   process that happens to own the port), the second launch has asked the
//!   primary to activate (raise its window) and exits.
//! - If the port is occupied by something that does *not* speak the
//!   handshake, startup proceeds normally without a lock — a squatted port
//!   must never block the app from launching.
//!
//! Scope: per-user, best-effort. Cross-user/session semantics are explicitly
//! out of scope (a single loopback port is host-wide, not per-user — fine per
//! the P6.16 spec). Bringing an already-visible window fully to the front is
//! best-effort per OS/window-manager; see the P6.16 report for what each
//! platform actually does.

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

/// Environment variable that overrides [`DEFAULT_PORT`]. Used by tests (each
/// test gets its own port so parallel `cargo test` runs never collide) and by
/// power users who intentionally want multiple side-by-side dev instances.
pub const PORT_ENV_VAR: &str = "CONMAN_INSTANCE_PORT";

/// Default loopback port for the single-instance lock. Drawn from the IANA
/// dynamic/private port range (49152-65535) to avoid registered services.
pub const DEFAULT_PORT: u16 = 52734;

/// Fixed, versioned handshake line a candidate second instance sends. Bumping
/// the version on a future incompatible protocol change makes an old/new
/// version mismatch fail safe (treated exactly like a port squatter) instead
/// of misbehaving.
const HANDSHAKE_REQUEST: &str = "CONMAN-SINGLE-INSTANCE-V1 ACTIVATE";

/// Reply the primary sends once it accepts a handshake + activation request.
const HANDSHAKE_REPLY: &str = "CONMAN-SINGLE-INSTANCE-V1 OK";

/// How long the client waits to connect to / hear back from a candidate
/// primary before giving up and treating the port as unusable. Loopback-only,
/// so this is generous rather than tight.
const IO_TIMEOUT: Duration = Duration::from_millis(300);

/// Result of [`acquire`].
#[derive(Debug)]
pub enum AcquireOutcome {
    /// We are the primary instance. Holds the lock; call
    /// [`InstanceGuard::listen`] to start receiving activations from later
    /// launches.
    Acquired(InstanceGuard),
    /// Another ConMan instance is already running and has been asked to
    /// activate. The caller should print a one-line message and exit(0).
    AlreadyRunning,
    /// The lock port could not be acquired *and* whatever is holding it does
    /// not speak the ConMan handshake (a foreign process, or a protocol
    /// mismatch). The caller should log a warning and continue launching
    /// normally — never brick startup on a squatted port.
    Unavailable(String),
}

/// Holds the bound loopback listener that backs the single-instance lock.
///
/// Dropping the guard without calling [`listen`](Self::listen) releases the
/// port (no lock, no activation channel) — callers that acquire the primary
/// role should always call `listen()` and keep the returned receiver alive
/// for the life of the process.
#[derive(Debug)]
pub struct InstanceGuard {
    listener: TcpListener,
}

impl InstanceGuard {
    /// Consumes the guard, spawning a background thread that owns the lock
    /// listener for the remainder of the process and sends `()` on the
    /// returned channel for every validated activation request from a later
    /// launch.
    ///
    /// The listener thread is intentionally never joined — it lives and dies
    /// with the process. If the receiving end is dropped (e.g. the UI shuts
    /// down first), the thread exits on the next send.
    #[must_use]
    pub fn listen(self) -> Receiver<()> {
        let (tx, rx) = mpsc::channel();
        let listener = self.listener;
        let spawned = std::thread::Builder::new()
            .name("cm-platform-single-instance".to_owned())
            .spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    if handle_activation_request(stream) {
                        // Observability for manual/xvfb verification ahead of the P6.3
                        // tracing sweep, which will replace this like the rest of the
                        // codebase's `eprintln!`s.
                        eprintln!(
                            "conman: single-instance: activation received from a second launch"
                        );
                        if tx.send(()).is_err() {
                            // Receiver dropped — nothing left to notify.
                            break;
                        }
                    }
                }
            });
        // Best-effort: if the OS can't spawn a thread we still hold the port
        // (a second launch still can't bind it) but stop short of delivering
        // activations. Rare (thread exhaustion); not worth widening the
        // return type of `listen()` for it.
        if let Err(e) = spawned {
            eprintln!("cm-platform: warning: failed to spawn single-instance listener thread: {e}");
        }
        rx
    }
}

/// Attempts to become the primary ConMan instance.
///
/// See the module docs for the full protocol. Never panics: this runs before
/// the UI exists, and a bad outcome here must degrade to "start normally
/// without a lock", not abort the app.
#[must_use]
pub fn acquire() -> AcquireOutcome {
    acquire_on_port(instance_port())
}

fn instance_port() -> u16 {
    std::env::var(PORT_ENV_VAR)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

fn acquire_on_port(port: u16) -> AcquireOutcome {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    match TcpListener::bind(addr) {
        Ok(listener) => AcquireOutcome::Acquired(InstanceGuard { listener }),
        Err(bind_err) => probe_existing(addr, &bind_err),
    }
}

/// Something already holds `addr`. Connect and run the client side of the
/// handshake to find out whether it is a ConMan primary (in which case this
/// call *is* the activation request) or an unrelated process.
fn probe_existing(addr: SocketAddr, bind_err: &std::io::Error) -> AcquireOutcome {
    let mut stream = match TcpStream::connect_timeout(&addr, IO_TIMEOUT) {
        Ok(s) => s,
        Err(connect_err) => {
            return AcquireOutcome::Unavailable(format!(
                "port {} unavailable (bind: {bind_err}) and not connectable ({connect_err})",
                addr.port()
            ));
        }
    };
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        return AcquireOutcome::Unavailable(format!(
            "port {} occupied; could not configure the probe socket",
            addr.port()
        ));
    }
    if stream
        .write_all(format!("{HANDSHAKE_REQUEST}\n").as_bytes())
        .is_err()
    {
        return AcquireOutcome::Unavailable(format!(
            "port {} occupied; handshake write failed",
            addr.port()
        ));
    }
    let mut reply = String::new();
    let read_result = BufReader::new(&mut stream).read_line(&mut reply);
    match read_result {
        Ok(n) if n > 0 && reply.trim_end() == HANDSHAKE_REPLY => AcquireOutcome::AlreadyRunning,
        _ => AcquireOutcome::Unavailable(format!(
            "port {} occupied by a process that did not answer the ConMan handshake",
            addr.port()
        )),
    }
}

/// Server side of the handshake for one accepted connection. Reads a single
/// line; if (and only if) it matches [`HANDSHAKE_REQUEST`] exactly, replies
/// with [`HANDSHAKE_REPLY`] and reports a validated activation. Any I/O
/// error, timeout, or content mismatch is treated as "not a real activation"
/// and the connection is dropped silently — this reads untrusted bytes off a
/// loopback socket and must never panic (CONVENTIONS §2).
fn handle_activation_request(mut stream: TcpStream) -> bool {
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err() {
        return false;
    }
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&mut stream);
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return false;
        }
    }
    if line.trim_end() != HANDSHAKE_REQUEST {
        return false;
    }
    stream
        .write_all(format!("{HANDSHAKE_REPLY}\n").as_bytes())
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU16, Ordering};

    /// Draws a fresh port per test (well above [`DEFAULT_PORT`]) so parallel
    /// `cargo test` runs never collide with each other or with a real running
    /// instance.
    fn next_test_port() -> u16 {
        static NEXT: AtomicU16 = AtomicU16::new(0);
        58000 + NEXT.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn acquire_twice_is_already_running() {
        let port = next_test_port();
        let AcquireOutcome::Acquired(guard) = acquire_on_port(port) else {
            panic!("expected to acquire the primary lock");
        };
        let _rx = guard.listen();
        std::thread::sleep(Duration::from_millis(50));

        match acquire_on_port(port) {
            AcquireOutcome::AlreadyRunning => {}
            other => panic!("expected AlreadyRunning, got {other:?}"),
        }
    }

    #[test]
    fn activation_is_delivered_on_channel() {
        let port = next_test_port();
        let AcquireOutcome::Acquired(guard) = acquire_on_port(port) else {
            panic!("expected to acquire the primary lock");
        };
        let rx = guard.listen();
        std::thread::sleep(Duration::from_millis(50));

        match acquire_on_port(port) {
            AcquireOutcome::AlreadyRunning => {}
            other => panic!("expected AlreadyRunning, got {other:?}"),
        }

        rx.recv_timeout(Duration::from_secs(2))
            .expect("activation should be delivered to the primary");
    }

    #[test]
    fn squatter_port_reports_unavailable() {
        let port = next_test_port();
        // A listener that does NOT speak the ConMan handshake — stands in for
        // an unrelated process that happens to own the port.
        let squatter = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).expect("bind squatter");
        std::thread::spawn(move || {
            for stream in squatter.incoming() {
                // Accept and hold the connection open without replying, so the
                // probe's connect() succeeds but the handshake read times out.
                let _ = stream;
            }
        });
        std::thread::sleep(Duration::from_millis(50));

        match acquire_on_port(port) {
            AcquireOutcome::Unavailable(reason) => assert!(!reason.is_empty()),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }
}

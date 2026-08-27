//! Default-on TELNET transport integration coverage using only loopback TCP.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use cm_core::TelnetSettings;
use cm_core::terminal::{GridSnapshot, Key, KeyEvent, KeyModifiers, TerminalSize};
use cm_session::{SessionStatus, TelnetTerminalSession, TerminalSession};

const IAC: u8 = 255;
const DO: u8 = 253;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

fn settings(port: u16) -> TelnetSettings {
    TelnetSettings {
        host: "127.0.0.1".to_owned(),
        port,
    }
}

fn size() -> TerminalSize {
    TerminalSize { cols: 80, rows: 24 }
}

fn wait_for_connected(session: &dyn TerminalSession) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match session.status() {
            SessionStatus::Connected => return,
            SessionStatus::Failed(reason) => panic!("TELNET connect failed: {reason}"),
            status if Instant::now() >= deadline => {
                panic!("TELNET did not connect before deadline: {status:?}")
            }
            _ => thread::sleep(Duration::from_millis(5)),
        }
    }
}

fn wait_for_terminal_status(session: &dyn TerminalSession) -> SessionStatus {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let status = session.status();
        if !matches!(status, SessionStatus::Connecting | SessionStatus::Connected) {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "TELNET remained active before deadline: {status:?}"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn snapshot_contains(snapshot: &GridSnapshot, needle: &str) -> bool {
    snapshot
        .cells
        .chunks(usize::from(snapshot.size.cols))
        .any(|row| {
            row.iter()
                .map(|cell| {
                    if cell.grapheme.is_empty() {
                        " "
                    } else {
                        cell.grapheme.as_str()
                    }
                })
                .collect::<String>()
                .contains(needle)
        })
}

fn wait_for_text(session: &dyn TerminalSession, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "terminal did not render {needle:?}");
        match session.snapshots().recv_timeout(remaining) {
            Ok(snapshot) if snapshot_contains(&snapshot, needle) => return,
            Ok(_) => {}
            Err(error) => panic!("snapshot stream closed before rendering {needle:?}: {error}"),
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn read_until(stream: &mut TcpStream, expected: &[&[u8]]) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set server read timeout");
    let mut transcript = Vec::new();
    let mut buffer = [0_u8; 4096];
    while !expected.iter().all(|needle| contains(&transcript, needle)) {
        let count = stream.read(&mut buffer).unwrap_or_else(|error| {
            panic!("read client bytes ({error}); transcript={transcript:?}")
        });
        assert_ne!(
            count, 0,
            "client closed before expected TELNET transcript: {transcript:?}"
        );
        transcript.extend_from_slice(&buffer[..count]);
    }
    transcript
}

#[test]
fn negotiation_render_input_terminal_type_naws_and_eof() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TELNET loopback");
    let port = listener.local_addr().expect("listener address").port();
    let (transcript_tx, transcript_rx) = mpsc::channel();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept TELNET client");
        stream.set_nodelay(true).expect("TCP_NODELAY on server");

        // The seven startup requests are deterministic and sent as one setup
        // record before the session becomes Connected.
        let startup = [
            IAC, WILL, 0, IAC, WILL, 3, IAC, WILL, 24, IAC, WILL, 31, IAC, DO, 0, IAC, DO, 1, IAC,
            DO, 3,
        ];
        let mut received_startup = vec![0_u8; startup.len()];
        stream
            .read_exact(&mut received_startup)
            .expect("read startup negotiation");
        assert_eq!(received_startup, startup);

        // Split every protocol byte into its own socket write. This exercises
        // driver-to-codec integration with negotiation and SB boundaries.
        let script = [
            IAC, DO, 3, // local SGA
            IAC, DO, 24, // local terminal type
            IAC, DO, 31, // local NAWS (triggers initial dimensions)
            IAC, WILL, 1, // remote ECHO
            IAC, WILL, 3, // remote SGA
            IAC, WILL, 42, // unknown remote option (must be refused)
            IAC, SB, 24, 1, IAC, SE, // TERMINAL-TYPE SEND
        ];
        for byte in script {
            stream.write_all(&[byte]).expect("write fragmented byte");
            thread::yield_now();
        }
        stream
            .write_all(b"LOOPBACK_OK\r\n")
            .expect("write application data");

        let initial_naws = [IAC, SB, 31, 0, 80, 0, 24, IAC, SE];
        let resized_naws = [IAC, SB, 31, 0, 100, 0, 40, IAC, SE];
        let terminal_type = [
            IAC, SB, 24, 0, b'x', b't', b'e', b'r', b'm', b'-', b'2', b'5', b'6', b'c', b'o', b'l',
            b'o', b'r', IAC, SE,
        ];
        let refused_unknown = [IAC, 254, 42];
        // Paste mapping, doubled application IAC, semantic Enter (CR LF),
        // literal pasted CR (CR NUL), then a marker from the next input record.
        let encoded_user_input = [
            b'A', b'\r', b'\n', b'B', b'\r', 0, b'C', IAC, IAC, b'\r', b'\n', b'\r', 0, b'Z',
        ];

        let mut transcript = received_startup;
        transcript.extend_from_slice(&read_until(
            &mut stream,
            &[
                &initial_naws,
                &resized_naws,
                &terminal_type,
                &refused_unknown,
                &encoded_user_input,
            ],
        ));
        transcript_tx.send(transcript).expect("send transcript");
        // Drop the socket: client must classify clean EOF as Disconnected.
    });

    let session = TelnetTerminalSession::connect(&settings(port), size()).expect("start session");
    wait_for_connected(&session);
    wait_for_text(&session, "LOOPBACK_OK");

    session.paste(vec![b'A', b'\n', b'B', b'\r', b'C', IAC]);
    session.send_key(KeyEvent {
        key: Key::Enter,
        mods: KeyModifiers::default(),
    });
    session.paste(b"\r".to_vec());
    session.paste(b"Z".to_vec());
    session.resize(TerminalSize {
        cols: 100,
        rows: 40,
    });

    let transcript = transcript_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("server observed full transcript");
    assert!(
        contains(&transcript, &[IAC, IAC, b'\r', b'\n', b'\r', 0, b'Z']),
        "Enter must be CR LF while a literal CR remains CR NUL"
    );
    server.join().expect("TELNET server thread");
    assert!(matches!(
        wait_for_terminal_status(&session),
        SessionStatus::Disconnected
    ));
    session.shutdown();
}

#[test]
fn connection_refusal_surfaces_failed_status() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused port");
    let port = listener.local_addr().expect("listener address").port();
    drop(listener);

    let session = TelnetTerminalSession::connect(&settings(port), size()).expect("start session");
    match wait_for_terminal_status(&session) {
        SessionStatus::Failed(reason) => assert!(reason.contains("connect failed")),
        status => panic!("expected failed connection, got {status:?}"),
    }
    session.shutdown();
}

#[test]
fn oversized_subnegotiation_fails_soft() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TELNET loopback");
    let port = listener.local_addr().expect("listener address").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept TELNET client");
        let mut startup = [0_u8; 21];
        stream.read_exact(&mut startup).expect("read startup");
        stream
            .write_all(&[IAC, SB, 42])
            .expect("start oversized subnegotiation");
        stream
            .write_all(&vec![b'x'; 64 * 1024 + 1])
            .expect("write oversized subnegotiation");
    });

    let session = TelnetTerminalSession::connect(&settings(port), size()).expect("start session");
    match wait_for_terminal_status(&session) {
        SessionStatus::Failed(reason) => assert!(reason.contains("protocol error")),
        status => panic!("expected protocol failure, got {status:?}"),
    }
    server.join().expect("TELNET server thread");
    session.shutdown();
}

#[test]
fn shutdown_while_connected_joins_promptly() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TELNET loopback");
    let port = listener.local_addr().expect("listener address").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept TELNET client");
        let mut startup = [0_u8; 21];
        stream.read_exact(&mut startup).expect("read startup");
        let mut byte = [0_u8; 1];
        assert_eq!(stream.read(&mut byte).expect("wait for client close"), 0);
    });

    let session = TelnetTerminalSession::connect(&settings(port), size()).expect("start session");
    wait_for_connected(&session);
    let started = Instant::now();
    session.shutdown();
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "shutdown took {:?}",
        started.elapsed()
    );
    server.join().expect("TELNET server thread");
    assert!(matches!(session.status(), SessionStatus::Disconnected));
}

#[test]
fn shutdown_interrupts_blocked_socket_write() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TELNET loopback");
    let port = listener.local_addr().expect("listener address").port();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (close_tx, close_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept TELNET client");
        let mut startup = [0_u8; 21];
        stream.read_exact(&mut startup).expect("read startup");
        ready_tx.send(()).expect("announce server ready");
        // Deliberately stop reading. A sufficiently large paste fills the TCP
        // send buffer and leaves the driver's write pending until shutdown.
        close_rx.recv().expect("wait to close server socket");
        drop(stream);
    });

    let session = TelnetTerminalSession::connect(&settings(port), size()).expect("start session");
    wait_for_connected(&session);
    ready_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("server read startup");
    session.paste(vec![b'x'; 16 * 1024 * 1024]);
    // Saturate both bounded bridges behind the pending socket write. Calls
    // remain nonblocking; overflow fails and cancels the session explicitly.
    for _ in 0..4096 {
        session.paste(b"queued".to_vec());
    }
    thread::sleep(Duration::from_millis(100));
    assert!(
        matches!(session.status(), SessionStatus::Failed(reason) if reason.contains("control queue overloaded")),
        "UI overflow must fail closed instead of silently dropping input"
    );

    let started = Instant::now();
    session.shutdown();
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "shutdown did not cancel the pending socket write: {:?}",
        started.elapsed()
    );
    close_tx.send(()).expect("close server");
    server.join().expect("TELNET server thread");
}

#[test]
fn hostile_vt_query_saturation_makes_progress_and_delivers_final_snapshot() {
    const QUERY_COUNT: usize = 32;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TELNET loopback");
    let port = listener.local_addr().expect("listener address").port();
    let (reply_tx, reply_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept TELNET client");
        let mut startup = [0_u8; 21];
        stream.read_exact(&mut startup).expect("read startup");
        for _ in 0..QUERY_COUNT {
            let mut chunk = vec![b'.'; 4096];
            chunk[..4].copy_from_slice(b"\x1b[6n");
            stream.write_all(&chunk).expect("write hostile VT query");
        }
        stream
            .write_all(b"\r\nFINAL_LIVENESS_MARKER\r\n")
            .expect("write final marker");

        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set response timeout");
        let mut responses = Vec::new();
        let mut buffer = [0_u8; 4096];
        while responses.iter().filter(|&&byte| byte == b'R').count() < QUERY_COUNT {
            let count = stream.read(&mut buffer).expect("read VT query responses");
            assert_ne!(count, 0, "client closed before answering VT queries");
            responses.extend_from_slice(&buffer[..count]);
        }
        reply_tx.send(responses).expect("send VT responses");
    });

    let session = TelnetTerminalSession::connect(&settings(port), size()).expect("start session");
    wait_for_connected(&session);
    wait_for_text(&session, "FINAL_LIVENESS_MARKER");
    let responses = reply_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("driver drained VT replies while inbound was backpressured");
    assert!(
        responses.iter().filter(|&&byte| byte == b'R').count() >= QUERY_COUNT,
        "all VT queries must receive replies"
    );
    server.join().expect("TELNET server thread");
    assert!(matches!(
        wait_for_terminal_status(&session),
        SessionStatus::Disconnected
    ));
    session.shutdown();
}

#[test]
fn hostile_vt_query_saturation_shutdown_remains_prompt() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TELNET loopback");
    let port = listener.local_addr().expect("listener address").port();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (close_tx, close_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept TELNET client");
        let mut startup = [0_u8; 21];
        stream.read_exact(&mut startup).expect("read startup");
        for _ in 0..32 {
            let mut chunk = vec![b'.'; 4096];
            chunk[..4].copy_from_slice(b"\x1b[6n");
            stream.write_all(&chunk).expect("write hostile VT query");
        }
        ready_tx.send(()).expect("announce saturation transcript");
        close_rx.recv().expect("keep peer open through shutdown");
    });

    let session = TelnetTerminalSession::connect(&settings(port), size()).expect("start session");
    wait_for_connected(&session);
    ready_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("server wrote saturation transcript");
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    session.shutdown();
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "saturated VT query shutdown took {:?}",
        started.elapsed()
    );
    close_tx.send(()).expect("release server");
    server.join().expect("TELNET server thread");
}

/// Opt-in live interoperability smoke. Endpoint and login material come only
/// from the environment so lab details and credentials never enter source or
/// test output. The command must be harmless and its expected output marker
/// should be stable for the authorized target.
#[test]
#[ignore = "opt-in: set CONMAN_LIVE_TELNET_* for an authorized endpoint"]
fn telnet_live_authorized_smoke() {
    let (host, port, username, password, command, expected) = match (
        std::env::var("CONMAN_LIVE_TELNET_HOST"),
        std::env::var("CONMAN_LIVE_TELNET_PORT"),
        std::env::var("CONMAN_LIVE_TELNET_USER"),
        std::env::var("CONMAN_LIVE_TELNET_PASSWORD"),
        std::env::var("CONMAN_LIVE_TELNET_COMMAND"),
        std::env::var("CONMAN_LIVE_TELNET_EXPECT"),
    ) {
        (Ok(host), Ok(port), Ok(username), Ok(password), Ok(command), Ok(expected)) => (
            host,
            port.parse::<u16>().expect("valid live TELNET port"),
            username,
            password,
            command,
            expected,
        ),
        _ => {
            eprintln!("telnet_live_authorized_smoke: skipping; live environment is incomplete");
            return;
        }
    };
    let timeout = Duration::from_secs(
        std::env::var("CONMAN_LIVE_TELNET_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(15),
    );
    let cfg = TelnetSettings { host, port };

    fn enter(session: &dyn TerminalSession) {
        session.send_key(KeyEvent {
            key: Key::Enter,
            mods: KeyModifiers::default(),
        });
    }

    fn wait_live(session: &dyn TerminalSession, needle: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "live TELNET output marker was not rendered"
            );
            match session.snapshots().recv_timeout(remaining) {
                Ok(snapshot) if snapshot_contains(&snapshot, needle) => return,
                Ok(_) => {}
                Err(error) => panic!("live TELNET snapshot stream closed: {error}"),
            }
        }
    }

    fn login(session: &dyn TerminalSession, username: &str, password: &str, timeout: Duration) {
        enter(session);
        wait_live(session, "login:", timeout);
        session.paste(username.as_bytes().to_vec());
        enter(session);
        wait_live(session, "Password:", timeout);
        session.paste(password.as_bytes().to_vec());
        enter(session);
        // Serial consoles may wait for one more newline before repainting the
        // command prompt after a successful PAM/login transition.
        thread::sleep(Duration::from_millis(250));
        enter(session);
        wait_live(session, "#", timeout);
    }

    for attempt in 0..2 {
        let session = TelnetTerminalSession::connect(&cfg, size()).expect("start live TELNET");
        wait_for_connected(&session);
        login(&session, &username, &password, timeout);

        if attempt == 0 {
            session.resize(TerminalSize {
                cols: 100,
                rows: 30,
            });
        }
        session.paste(command.as_bytes().to_vec());
        enter(&session);
        wait_live(&session, &expected, timeout);

        session.paste(b"exit".to_vec());
        enter(&session);
        wait_live(&session, "login:", timeout);
        session.shutdown();
    }
}

/// Opt-in lifecycle regression for serial-console proxies: explicitly close
/// one live session at the login prompt, then immediately connect again in
/// the same process. Unlike `telnet_live_authorized_smoke`, this deliberately
/// does not send a CLI `exit` before shutting down the first TCP session.
#[test]
#[ignore = "opt-in: set CONMAN_LIVE_TELNET_HOST/PORT for an authorized endpoint"]
fn telnet_live_reconnects_after_explicit_shutdown() {
    let (host, port) = match (
        std::env::var("CONMAN_LIVE_TELNET_HOST"),
        std::env::var("CONMAN_LIVE_TELNET_PORT"),
    ) {
        (Ok(host), Ok(port)) => (host, port.parse::<u16>().expect("valid live TELNET port")),
        _ => {
            eprintln!(
                "telnet_live_reconnects_after_explicit_shutdown: skipping; live endpoint is incomplete"
            );
            return;
        }
    };
    let timeout = Duration::from_secs(
        std::env::var("CONMAN_LIVE_TELNET_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(15),
    );
    let cfg = TelnetSettings { host, port };

    for _ in 0..2 {
        let session = TelnetTerminalSession::connect(&cfg, size()).expect("start live TELNET");
        wait_for_connected(&session);
        session.send_key(KeyEvent {
            key: Key::Enter,
            mods: KeyModifiers::default(),
        });
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "live TELNET login prompt was not rendered"
            );
            match session.snapshots().recv_timeout(remaining) {
                Ok(snapshot) if snapshot_contains(&snapshot, "login:") => break,
                Ok(_) => {}
                Err(error) => panic!("live TELNET snapshot stream closed: {error}"),
            }
        }
        session.shutdown();
    }
}

//! P3.1/P6.2 SSH integration tests.
//!
//! The bulk of this file is a **default-on** loopback harness (P6.2, gap 23):
//! an in-process SSH server (russh's server side — same dependency already in
//! the workspace, no new-dep memo) so the hostile-byte-consuming `drive()`
//! loop in `cm_session::ssh` runs on every plain `cargo test`, no external
//! `sshd` required. Covers: connect; password auth success/failure; publickey
//! auth success/failure; host-key verifier callback paths (Unknown→accept,
//! Unknown→reject aborts, Mismatch→prompt); byte round-trip through the VT
//! engine (echo probe); clean disconnect; server-side abrupt close; and
//! malformed-input (garbage/truncated bytes) at the transport's earliest
//! stage, which must fail soft — never panic.
//!
//! The original real-`sshd` end-to-end proof is kept at the bottom, gated
//! `#[ignore]` as before (needs the `sshd` binary + spawns a real server).
//!
//! `#![cfg(unix)]`: both the harness and the malformed-input tests key
//! host/user credentials off `ssh-keygen` (already assumed available by the
//! pre-existing ignored real-host test in this file). Windows coverage of
//! this file is `UNVERIFIED` — see the P6.2 task report.
#![cfg(unix)]

mod support;

use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cm_core::terminal::{GridSnapshot, Key, KeyEvent, KeyModifiers, TerminalSize};
use cm_core::{Secret, SshSettings};
use cm_session::{
    HostKeyDecision, HostKeyInfo, HostKeySituation, HostKeyVerifier, KnownHostSource, KnownHosts,
    SessionStatus, SshAuthInput, SshTerminalSession, TerminalSession,
};
use russh::keys::known_hosts::learn_known_hosts_path;
use russh::keys::ssh_key::{HashAlg, PublicKey};
use russh::keys::{PrivateKey, load_secret_key};

use support::{LoopbackSshServer, SshServerConfig};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Auto-accept verifier (TOFU happy path).
struct AcceptAll;
impl HostKeyVerifier for AcceptAll {
    fn decide(&self, _: &HostKeyInfo) -> HostKeyDecision {
        HostKeyDecision::Accept
    }
}

/// Programmatic verifier for the loopback tests: always returns the
/// configured decision and records what it was asked about. (Reimplemented
/// here — the equivalent in `ssh.rs`'s `#[cfg(test)]` module is private to
/// that crate and not reachable from this integration-test binary.)
struct FixedVerifier {
    decision: HostKeyDecision,
    seen: Mutex<Vec<HostKeyInfo>>,
}

impl FixedVerifier {
    fn new(decision: HostKeyDecision) -> Arc<Self> {
        Arc::new(Self {
            decision,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen_count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    fn last_situation(&self) -> HostKeySituation {
        self.seen.lock().unwrap().last().unwrap().situation.clone()
    }
}

impl HostKeyVerifier for FixedVerifier {
    fn decide(&self, info: &HostKeyInfo) -> HostKeyDecision {
        self.seen.lock().unwrap().push(info.clone());
        self.decision
    }
}

/// Unique scratch dir per test (keyed by test name + pid; test names are
/// distinct within this file so this never collides across parallel `cargo
/// test` threads).
fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "conman-ssh-loopback-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn keygen(path: &Path) {
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f"])
        .arg(path)
        .status()
        .expect("run ssh-keygen");
    assert!(status.success(), "ssh-keygen failed");
}

/// Generate an ed25519 keypair at `<dir>/<name>`; returns
/// `(private_key_path, PrivateKey, PublicKey)`.
fn gen_keypair(dir: &Path, name: &str) -> (PathBuf, PrivateKey, PublicKey) {
    let path = dir.join(name);
    keygen(&path);
    let private = load_secret_key(&path, None).expect("load generated private key");
    let public_openssh =
        std::fs::read_to_string(path.with_extension("pub")).expect("read generated pubkey file");
    let public = PublicKey::from_openssh(&public_openssh).expect("parse generated pubkey");
    (path, private, public)
}

fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// A port with (by construction) nothing listening on it: bind ephemerally,
/// read back the assigned port, then drop the listener before returning.
fn unused_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().unwrap().port()
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
        .collect()
}

fn snapshot_contains(snap: &GridSnapshot, needle: &str) -> bool {
    (0..snap.size.rows).any(|r| row_text(snap, r).contains(needle))
}

fn wait_for_text(session: &dyn TerminalSession, needle: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match session.snapshots().recv_timeout(remaining) {
            Ok(snap) if snapshot_contains(&snap, needle) => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
}

fn wait_for_connected(session: &dyn TerminalSession, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        match session.status() {
            SessionStatus::Connected => return,
            SessionStatus::Failed(reason) => panic!("SSH connect failed: {reason}"),
            _ if Instant::now() > deadline => {
                panic!("SSH did not reach Connected within {timeout:?}")
            }
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

/// Wait for any *terminal* status (`Failed`/`Disconnected`/`Exited`) — used
/// by the negative-path tests, which must never panic in production code and
/// must reach one of these states rather than hang or crash the test binary.
fn wait_for_terminal_status(session: &dyn TerminalSession, timeout: Duration) -> SessionStatus {
    let deadline = Instant::now() + timeout;
    loop {
        let status = session.status();
        if !matches!(status, SessionStatus::Connecting | SessionStatus::Connected) {
            return status;
        }
        if Instant::now() > deadline {
            panic!(
                "SSH session did not reach a terminal status within {timeout:?} (stuck at {status:?})"
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn default_size() -> TerminalSize {
    TerminalSize { rows: 24, cols: 80 }
}

fn known_hosts_in(dir: &Path) -> KnownHosts {
    KnownHosts::with_paths(dir.join("known_hosts"), None)
}

fn ssh_settings(port: u16, user: &str) -> SshSettings {
    SshSettings {
        host: "127.0.0.1".to_owned(),
        port,
        username: user.to_owned(),
        auth_method: cm_core::SshAuthMethod::Password,
    }
}

// ---------------------------------------------------------------------------
// Happy path: password auth + echo round-trip
// ---------------------------------------------------------------------------

#[test]
fn ssh_password_auth_success_and_echo_round_trip() {
    let dir = scratch_dir("pw-ok");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.accept_password = Some("s3cret".to_owned());
    let server = LoopbackSshServer::spawn(cfg);

    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::Password(Secret::from_string("s3cret".to_owned())),
        Arc::new(AcceptAll),
        known_hosts_in(&dir),
        default_size(),
    )
    .expect("spawn ssh session");

    wait_for_connected(&session, Duration::from_secs(5));

    // The fake server echoes bytes verbatim; a marker with no shell
    // metacharacters proves a genuine transport round trip into the VT
    // engine's rendered grid.
    session.paste(b"LOOPBACK_ECHO_9f3a1".to_vec());
    assert!(
        wait_for_text(&session, "LOOPBACK_ECHO_9f3a1", Duration::from_secs(5)),
        "expected echoed bytes to render in the terminal grid"
    );

    session.shutdown();
    assert!(matches!(
        session.status(),
        SessionStatus::Disconnected | SessionStatus::Exited(_)
    ));
}

#[test]
fn ssh_password_auth_failure_surfaces_failed_status() {
    let dir = scratch_dir("pw-bad");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.accept_password = Some("correct-horse".to_owned());
    let server = LoopbackSshServer::spawn(cfg);

    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::Password(Secret::from_string("wrong-password".to_owned())),
        Arc::new(AcceptAll),
        known_hosts_in(&dir),
        default_size(),
    )
    .expect("spawn ssh session");

    let status = wait_for_terminal_status(&session, Duration::from_secs(5));
    match status {
        SessionStatus::Failed(reason) => {
            assert!(
                reason.to_lowercase().contains("auth"),
                "expected an auth-flavoured reason, got: {reason}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    session.shutdown();
}

// ---------------------------------------------------------------------------
// Publickey auth
// ---------------------------------------------------------------------------

#[test]
fn ssh_publickey_auth_success() {
    let dir = scratch_dir("pk-ok");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");
    let (user_key_path, _user_priv, user_pub) = gen_keypair(&dir, "userkey");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.accept_pubkey_fingerprint = Some(fingerprint(&user_pub));
    let server = LoopbackSshServer::spawn(cfg);

    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::Key {
            path: user_key_path,
            passphrase: None,
        },
        Arc::new(AcceptAll),
        known_hosts_in(&dir),
        default_size(),
    )
    .expect("spawn ssh session");

    wait_for_connected(&session, Duration::from_secs(5));
    session.shutdown();
}

#[test]
fn ssh_publickey_auth_wrong_key_surfaces_failed_status() {
    let dir = scratch_dir("pk-bad");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");
    let (_authorized_path, _authorized_priv, authorized_pub) = gen_keypair(&dir, "authorized");
    let (presented_path, _presented_priv, _presented_pub) = gen_keypair(&dir, "presented");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.accept_pubkey_fingerprint = Some(fingerprint(&authorized_pub));
    let server = LoopbackSshServer::spawn(cfg);

    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::Key {
            path: presented_path,
            passphrase: None,
        },
        Arc::new(AcceptAll),
        known_hosts_in(&dir),
        default_size(),
    )
    .expect("spawn ssh session");

    let status = wait_for_terminal_status(&session, Duration::from_secs(5));
    assert!(
        matches!(status, SessionStatus::Failed(_)),
        "expected Failed, got {status:?}"
    );
    session.shutdown();
}

// ---------------------------------------------------------------------------
// Host-key verifier callback paths
// ---------------------------------------------------------------------------

#[test]
fn ssh_host_key_unknown_accept_stores_via_full_connect() {
    let dir = scratch_dir("hk-unknown-accept");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.accept_password = Some("pw".to_owned());
    let server = LoopbackSshServer::spawn(cfg);

    let verifier = FixedVerifier::new(HostKeyDecision::Accept);
    let known_hosts_path = dir.join("known_hosts");
    assert!(!known_hosts_path.exists());

    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::Password(Secret::from_string("pw".to_owned())),
        verifier.clone(),
        KnownHosts::with_paths(known_hosts_path.clone(), None),
        default_size(),
    )
    .expect("spawn ssh session");

    wait_for_connected(&session, Duration::from_secs(5));
    assert_eq!(verifier.seen_count(), 1, "verifier should be prompted once");
    assert_eq!(verifier.last_situation(), HostKeySituation::Unknown);
    assert!(
        known_hosts_path.exists(),
        "accepted host key must be persisted to the ConMan store"
    );
    session.shutdown();
}

#[test]
fn ssh_host_key_unknown_reject_aborts_connection() {
    let dir = scratch_dir("hk-unknown-reject");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.accept_password = Some("pw".to_owned());
    let server = LoopbackSshServer::spawn(cfg);

    let verifier = FixedVerifier::new(HostKeyDecision::Reject);

    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::Password(Secret::from_string("pw".to_owned())),
        verifier.clone(),
        known_hosts_in(&dir),
        default_size(),
    )
    .expect("spawn ssh session");

    let status = wait_for_terminal_status(&session, Duration::from_secs(5));
    match status {
        SessionStatus::Failed(reason) => {
            assert!(
                reason.to_lowercase().contains("host key")
                    || reason.to_lowercase().contains("trusted"),
                "expected a host-key-flavoured reason, got: {reason}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(verifier.seen_count(), 1);
    assert_eq!(verifier.last_situation(), HostKeySituation::Unknown);
    session.shutdown();
}

#[test]
fn ssh_host_key_mismatch_prompts_verifier_over_full_connect() {
    let dir = scratch_dir("hk-mismatch");
    // Two distinct host identities: the server actually runs key B, but the
    // ConMan store is pre-seeded (as if from a prior connection) with key A
    // for this exact host:port — a textbook TOFU mismatch.
    let (_key_a_path, _key_a_priv, key_a_pub) = gen_keypair(&dir, "hostkey_a");
    let (_key_b_path, key_b_priv, _key_b_pub) = gen_keypair(&dir, "hostkey_b");

    let mut cfg = SshServerConfig::new(key_b_priv);
    cfg.accept_password = Some("pw".to_owned());
    let server = LoopbackSshServer::spawn(cfg);

    let known_hosts_path = dir.join("known_hosts");
    learn_known_hosts_path("127.0.0.1", server.port, &key_a_pub, &known_hosts_path)
        .expect("seed known_hosts with key A");

    let verifier = FixedVerifier::new(HostKeyDecision::Reject);

    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::Password(Secret::from_string("pw".to_owned())),
        verifier.clone(),
        KnownHosts::with_paths(known_hosts_path, None),
        default_size(),
    )
    .expect("spawn ssh session");

    let status = wait_for_terminal_status(&session, Duration::from_secs(5));
    assert!(
        matches!(status, SessionStatus::Failed(_)),
        "expected Failed (rejected mismatch), got {status:?}"
    );
    assert_eq!(verifier.seen_count(), 1);
    match verifier.last_situation() {
        HostKeySituation::Mismatch { source, .. } => {
            assert_eq!(source, KnownHostSource::ConManStore);
        }
        other => panic!("expected Mismatch, got {other:?}"),
    }
    session.shutdown();
}

// ---------------------------------------------------------------------------
// Disconnect paths
// ---------------------------------------------------------------------------

#[test]
fn ssh_clean_disconnect_after_client_shutdown() {
    let dir = scratch_dir("clean-disconnect");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.accept_password = Some("pw".to_owned());
    let server = LoopbackSshServer::spawn(cfg);

    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::Password(Secret::from_string("pw".to_owned())),
        Arc::new(AcceptAll),
        known_hosts_in(&dir),
        default_size(),
    )
    .expect("spawn ssh session");

    wait_for_connected(&session, Duration::from_secs(5));
    session.shutdown();
    assert!(
        matches!(
            session.status(),
            SessionStatus::Disconnected | SessionStatus::Exited(_)
        ),
        "expected a clean terminal status after shutdown, got {:?}",
        session.status()
    );
    // Idempotent: a second shutdown() must not panic or hang.
    session.shutdown();
}

#[test]
fn ssh_server_side_abrupt_close_never_panics() {
    let dir = scratch_dir("abrupt-close");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.accept_password = Some("pw".to_owned());
    cfg.abrupt_close = true;
    let server = LoopbackSshServer::spawn(cfg);

    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::Password(Secret::from_string("pw".to_owned())),
        Arc::new(AcceptAll),
        known_hosts_in(&dir),
        default_size(),
    )
    .expect("spawn ssh session");

    // The server tears the connection down right at shell-request time.
    // Reaching *any* terminal status without the test process aborting is
    // the assertion — a panic on the driver/engine-owner thread would take
    // the whole `cargo test` process down with it.
    let status = wait_for_terminal_status(&session, Duration::from_secs(5));
    assert!(
        matches!(
            status,
            SessionStatus::Failed(_) | SessionStatus::Disconnected
        ),
        "expected Failed or Disconnected, got {status:?}"
    );
    session.shutdown();
}

// ---------------------------------------------------------------------------
// Malformed input at the transport's earliest stage (CONVENTIONS §2):
// truncated/garbage bytes must fail soft — typed error, no panic.
// ---------------------------------------------------------------------------

/// A minimal raw TCP responder (no SSH protocol at all) used to feed garbage
/// / truncated bytes at the point where the client expects an SSH banner.
fn spawn_raw_responder(garbage: Option<&'static [u8]>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept()
            && let Some(bytes) = garbage
        {
            let _ = stream.write_all(bytes);
            let _ = stream.flush();
            // Give the client a beat to read before the socket closes.
            std::thread::sleep(Duration::from_millis(200));
        }
        // Dropping `stream` closes it (immediately if `garbage` was `None`,
        // i.e. an abrupt close with zero bytes sent).
    });
    port
}

#[test]
fn ssh_connect_refused_surfaces_failed_no_panic() {
    let dir = scratch_dir("refused");
    let port = unused_port();

    let session = SshTerminalSession::connect(
        &ssh_settings(port, "tester"),
        SshAuthInput::Password(Secret::from_string("pw".to_owned())),
        Arc::new(AcceptAll),
        known_hosts_in(&dir),
        default_size(),
    )
    .expect("spawn ssh session (connect failure is async)");

    let status = wait_for_terminal_status(&session, Duration::from_secs(5));
    assert!(
        matches!(status, SessionStatus::Failed(_)),
        "expected Failed, got {status:?}"
    );
    session.shutdown();
}

#[test]
fn ssh_garbage_banner_fails_soft_no_panic() {
    let dir = scratch_dir("garbage-banner");
    let port = spawn_raw_responder(Some(b"\x00\x01\x02NOT-AN-SSH-BANNER\xff\xfe\xfd\r\n"));

    let session = SshTerminalSession::connect(
        &ssh_settings(port, "tester"),
        SshAuthInput::Password(Secret::from_string("pw".to_owned())),
        Arc::new(AcceptAll),
        known_hosts_in(&dir),
        default_size(),
    )
    .expect("spawn ssh session");

    let status = wait_for_terminal_status(&session, Duration::from_secs(5));
    assert!(
        matches!(status, SessionStatus::Failed(_)),
        "expected Failed, got {status:?}"
    );
    session.shutdown();
}

#[test]
fn ssh_truncated_connection_fails_soft_no_panic() {
    let dir = scratch_dir("truncated");
    // Accept then close with zero bytes written: the client sent its banner
    // but never got one back before EOF.
    let port = spawn_raw_responder(None);

    let session = SshTerminalSession::connect(
        &ssh_settings(port, "tester"),
        SshAuthInput::Password(Secret::from_string("pw".to_owned())),
        Arc::new(AcceptAll),
        known_hosts_in(&dir),
        default_size(),
    )
    .expect("spawn ssh session");

    let status = wait_for_terminal_status(&session, Duration::from_secs(5));
    assert!(
        matches!(status, SessionStatus::Failed(_)),
        "expected Failed, got {status:?}"
    );
    session.shutdown();
}

// ---------------------------------------------------------------------------
// Real-host integration test (unchanged from P3.1) — needs a local `sshd`.
// ---------------------------------------------------------------------------

/// Kills the spawned sshd and removes the temp dir on drop.
struct TestServer {
    child: Child,
    dir: PathBuf,
    port: u16,
    key_path: PathBuf,
    user: String,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().unwrap().port()
}

fn start_sshd() -> TestServer {
    let sshd = std::env::var("CONMAN_TEST_SSHD").unwrap_or_else(|_| "/usr/sbin/sshd".to_owned());
    let user = std::env::var("USER").expect("USER");
    let dir = std::env::temp_dir().join(format!("conman-ssh-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let host_key = dir.join("hostkey");
    let user_key = dir.join("id");
    keygen(&host_key);
    keygen(&user_key);
    std::fs::copy(dir.join("id.pub"), dir.join("authorized_keys")).unwrap();

    let port = free_port();
    let cfg = dir.join("sshd_config");
    std::fs::write(
        &cfg,
        format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {hk}\n\
             AuthorizedKeysFile {ak}\n\
             PidFile {pid}\n\
             UsePAM no\n\
             StrictModes no\n\
             PermitRootLogin no\n\
             PrintMotd no\n",
            hk = host_key.display(),
            ak = dir.join("authorized_keys").display(),
            pid = dir.join("sshd.pid").display(),
        ),
    )
    .unwrap();

    let log = std::fs::File::create(dir.join("sshd.log")).unwrap();
    let child = Command::new(&sshd)
        .args(["-D", "-e", "-f"])
        .arg(&cfg)
        .stderr(log)
        .spawn()
        .unwrap_or_else(|e| panic!("spawn sshd ({sshd}): {e}"));

    // Wait until it accepts connections.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    TestServer {
        child,
        dir,
        port,
        key_path: user_key,
        user,
    }
}

#[test]
#[ignore = "needs a local sshd; run with --ignored --nocapture"]
fn ssh_publickey_runs_mark42_over_real_sshd() {
    let server = start_sshd();

    let cfg = SshSettings {
        host: "127.0.0.1".to_owned(),
        port: server.port,
        username: server.user.clone(),
        // auth_method is informational here; SshAuthInput carries the material.
        auth_method: cm_core::SshAuthMethod::Password,
    };

    // Throwaway known-hosts in the temp dir; the verifier auto-accepts (TOFU).
    let known_hosts = KnownHosts::with_paths(server.dir.join("conman_known_hosts"), None);
    let auth = SshAuthInput::Key {
        path: server.key_path.clone(),
        passphrase: None,
    };

    let session = SshTerminalSession::connect(
        &cfg,
        auth,
        Arc::new(AcceptAll),
        known_hosts,
        TerminalSize { rows: 24, cols: 80 },
    )
    .expect("spawn ssh session");

    wait_for_connected(&session, Duration::from_secs(10));

    // Type a command whose OUTPUT (MARK42) differs from the echoed input.
    session.paste(b"echo MARK$((6*7))".to_vec());
    session.send_key(KeyEvent {
        key: Key::Enter,
        mods: KeyModifiers::default(),
    });

    assert!(
        wait_for_text(&session, "MARK42", Duration::from_secs(10)),
        "expected the remote shell to execute the command over SSH"
    );

    session.shutdown();
}

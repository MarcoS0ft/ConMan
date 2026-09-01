//! SSH integration tests.
//!
//! The bulk of this file is a **default-on** loopback harness:
//! an in-process SSH server (russh's server side — same dependency already in
//! the workspace, no new dependency) so the hostile-byte-consuming `drive()`
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
//! Live-host coverage is `UNVERIFIED` because it requires a local SSH server.
#![cfg(unix)]

mod support;

use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cm_core::terminal::{GridSnapshot, Key, KeyEvent, KeyModifiers, TerminalSize};
use cm_core::{
    CredentialId, CredentialPurpose, CredentialRef, CredentialStore, Secret, SshSettings,
    TerminalOptions,
};
use cm_session::{
    HostKeyDecision, HostKeyInfo, HostKeySituation, HostKeyVerifier, KbdInteractiveChallenge,
    KbdInteractiveHandler, KnownHostSource, KnownHosts, SessionStatus, SshAuthInput,
    SshTerminalSession as RealSshTerminalSession, TerminalSession,
};
use russh::keys::known_hosts::learn_known_hosts_path;
use russh::keys::ssh_key::{HashAlg, PublicKey};
use russh::keys::{PrivateKey, load_secret_key};

use support::{
    InMemoryCredentialStore, KbdInteractiveTestConfig, KbdRound, LoopbackSshServer, SshServerConfig,
};

/// Preserve concise call sites while making the per-session terminal options
/// explicit at the production constructor boundary.
struct SshTerminalSession;

impl SshTerminalSession {
    fn connect(
        settings: &SshSettings,
        auth: SshAuthInput,
        verifier: Arc<dyn HostKeyVerifier>,
        known_hosts: KnownHosts,
        size: TerminalSize,
    ) -> Result<RealSshTerminalSession, cm_session::SshError> {
        RealSshTerminalSession::connect(
            settings,
            auth,
            verifier,
            known_hosts,
            size,
            TerminalOptions::default(),
        )
    }
}

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

/// A scripted client-side [`KbdInteractiveHandler`] for the loopback tests
/// Returns the next queued round's answers in order, recording every
/// challenge it was shown; returns `None` (abort) once the script is
/// exhausted so a test can never hang waiting on an unscripted round.
struct ScriptedKbdHandler {
    rounds: Mutex<std::collections::VecDeque<Vec<String>>>,
    seen: Mutex<Vec<KbdInteractiveChallenge>>,
}

impl ScriptedKbdHandler {
    fn new(rounds: Vec<Vec<&str>>) -> Arc<Self> {
        Arc::new(Self {
            rounds: Mutex::new(
                rounds
                    .into_iter()
                    .map(|round| round.into_iter().map(str::to_owned).collect())
                    .collect(),
            ),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen_rounds(&self) -> Vec<KbdInteractiveChallenge> {
        self.seen.lock().unwrap().clone()
    }
}

impl KbdInteractiveHandler for ScriptedKbdHandler {
    fn respond(&self, challenge: &KbdInteractiveChallenge) -> Option<Vec<Secret>> {
        self.seen.lock().unwrap().push(challenge.clone());
        let answers = self.rounds.lock().unwrap().pop_front()?;
        Some(answers.into_iter().map(Secret::from_string).collect())
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

/// Generate an RSA keypair (BUG-ssh-rsa-sha2 regression coverage needs an
/// actual RSA key — `ssh-rsa`/`rsa-sha2-*` are RSA-only signature schemes).
fn keygen_rsa(path: &Path) {
    let status = Command::new("ssh-keygen")
        .args(["-t", "rsa", "-b", "3072", "-N", "", "-q", "-f"])
        .arg(path)
        .status()
        .expect("run ssh-keygen -t rsa");
    assert!(status.success(), "ssh-keygen -t rsa failed");
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
// Keyboard-interactive authentication
// ---------------------------------------------------------------------------

#[test]
fn ssh_kbd_interactive_single_round_success() {
    let dir = scratch_dir("kbd-ok");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.kbd_interactive = Some(KbdInteractiveTestConfig {
        name: "Password",
        instructions: "Enter your password",
        rounds: vec![KbdRound {
            prompts: vec![("Password: ", false)],
            expected_answers: vec!["s3cret".to_owned()],
        }],
    });
    let server = LoopbackSshServer::spawn(cfg);

    let handler = ScriptedKbdHandler::new(vec![vec!["s3cret"]]);
    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::KeyboardInteractive {
            handler: handler.clone(),
        },
        Arc::new(AcceptAll),
        known_hosts_in(&dir),
        default_size(),
    )
    .expect("spawn ssh session");

    wait_for_connected(&session, Duration::from_secs(5));

    let seen = handler.seen_rounds();
    assert_eq!(seen.len(), 1, "expected exactly one challenge round");
    assert_eq!(seen[0].prompts.len(), 1);
    assert!(!seen[0].prompts[0].echo, "password prompt must not echo");

    session.shutdown();
}

#[test]
fn ssh_kbd_interactive_wrong_answer_surfaces_failed_status() {
    let dir = scratch_dir("kbd-bad");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.kbd_interactive = Some(KbdInteractiveTestConfig {
        name: "Password",
        instructions: "Enter your password",
        rounds: vec![KbdRound {
            prompts: vec![("Password: ", false)],
            expected_answers: vec!["correct".to_owned()],
        }],
    });
    let server = LoopbackSshServer::spawn(cfg);

    let handler = ScriptedKbdHandler::new(vec![vec!["wrong"]]);
    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::KeyboardInteractive { handler },
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

#[test]
fn ssh_kbd_interactive_multi_prompt_round_success() {
    let dir = scratch_dir("kbd-multi");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.kbd_interactive = Some(KbdInteractiveTestConfig {
        name: "Two-factor",
        instructions: "Enter your password and one-time code",
        // A single round carrying TWO prompts (not two separate rounds).
        rounds: vec![KbdRound {
            prompts: vec![("Password: ", false), ("Code: ", true)],
            expected_answers: vec!["s3cret".to_owned(), "424242".to_owned()],
        }],
    });
    let server = LoopbackSshServer::spawn(cfg);

    let handler = ScriptedKbdHandler::new(vec![vec!["s3cret", "424242"]]);
    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::KeyboardInteractive {
            handler: handler.clone(),
        },
        Arc::new(AcceptAll),
        known_hosts_in(&dir),
        default_size(),
    )
    .expect("spawn ssh session");

    wait_for_connected(&session, Duration::from_secs(5));

    let seen = handler.seen_rounds();
    assert_eq!(seen.len(), 1, "expected a single round with 2 prompts");
    assert_eq!(seen[0].prompts.len(), 2);
    assert!(!seen[0].prompts[0].echo);
    assert!(seen[0].prompts[1].echo);

    session.shutdown();
}

#[test]
fn ssh_kbd_interactive_two_rounds_success() {
    let dir = scratch_dir("kbd-rounds");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.kbd_interactive = Some(KbdInteractiveTestConfig {
        name: "Two-factor",
        instructions: "Enter your password, then your one-time code",
        rounds: vec![
            KbdRound {
                prompts: vec![("Password: ", false)],
                expected_answers: vec!["s3cret".to_owned()],
            },
            KbdRound {
                prompts: vec![("Code: ", true)],
                expected_answers: vec!["424242".to_owned()],
            },
        ],
    });
    let server = LoopbackSshServer::spawn(cfg);

    let handler = ScriptedKbdHandler::new(vec![vec!["s3cret"], vec!["424242"]]);
    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::KeyboardInteractive {
            handler: handler.clone(),
        },
        Arc::new(AcceptAll),
        known_hosts_in(&dir),
        default_size(),
    )
    .expect("spawn ssh session");

    wait_for_connected(&session, Duration::from_secs(5));
    assert_eq!(
        handler.seen_rounds().len(),
        2,
        "expected two separate challenge rounds"
    );

    session.shutdown();
}

/// Malformed/empty challenge: a round with **zero** prompts is a valid (if
/// unusual) server behavior — the client must answer with zero responses and
/// keep going rather than treat it as an error, and it must never panic.
#[test]
fn ssh_kbd_interactive_empty_challenge_round_fails_soft() {
    let dir = scratch_dir("kbd-empty");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.kbd_interactive = Some(KbdInteractiveTestConfig {
        name: "",
        instructions: "",
        rounds: vec![
            KbdRound {
                prompts: vec![],
                expected_answers: vec![],
            },
            KbdRound {
                prompts: vec![("Password: ", false)],
                expected_answers: vec!["s3cret".to_owned()],
            },
        ],
    });
    let server = LoopbackSshServer::spawn(cfg);

    let handler = ScriptedKbdHandler::new(vec![vec![], vec!["s3cret"]]);
    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::KeyboardInteractive {
            handler: handler.clone(),
        },
        Arc::new(AcceptAll),
        known_hosts_in(&dir),
        default_size(),
    )
    .expect("spawn ssh session");

    wait_for_connected(&session, Duration::from_secs(5));
    let seen = handler.seen_rounds();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].prompts.is_empty(), "first round has zero prompts");

    session.shutdown();
}

/// The user dismissing the prompt (`respond` returning `None`) aborts
/// authentication cleanly — `Failed`, never a hang or a panic.
#[test]
fn ssh_kbd_interactive_handler_abort_surfaces_failed_status() {
    let dir = scratch_dir("kbd-abort");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.kbd_interactive = Some(KbdInteractiveTestConfig {
        name: "Password",
        instructions: "Enter your password",
        rounds: vec![KbdRound {
            prompts: vec![("Password: ", false)],
            expected_answers: vec!["s3cret".to_owned()],
        }],
    });
    let server = LoopbackSshServer::spawn(cfg);

    // Empty script: the first `respond()` call finds nothing queued and
    // returns `None` (abort), exactly like a user dismissing the dialog.
    let handler = ScriptedKbdHandler::new(vec![]);
    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::KeyboardInteractive { handler },
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
// Stored-credential resolution -> keychain fetch -> real transport
//
// `resolve_effective_credential` (connection -> nearest-ancestor group
// default) itself is unit-tested in `cm-core`; the cm-ui glue that calls it
// and then fetches from a `CredentialStore` is unit-tested in `cm-ui` with a
// mock store (no network needed there). These loopback tests instead prove
// the other half: that a secret coming out of a real `CredentialStore`
// implementation authenticates against a real SSH transport -- both for a
// stored password and for stored key material via the new
// `SshAuthInput::KeyMaterial` path.
// ---------------------------------------------------------------------------

#[test]
fn ssh_credential_password_auth_success_via_keychain() {
    let dir = scratch_dir("cred-pw-ok");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.accept_password = Some("s3cret".to_owned());
    let server = LoopbackSshServer::spawn(cfg);

    // Store the password under a credential id, exactly as the Keys-panel
    // editor does (`cm-ui/src/controller/keys_ctl.rs`), then fetch it back.
    let store = InMemoryCredentialStore::new();
    let cred_id = CredentialId::new(42);
    store
        .store(
            &CredentialRef::new(cred_id, CredentialPurpose::Password),
            &Secret::from_string("s3cret".to_owned()),
        )
        .expect("store password");
    let fetched = store
        .get(&CredentialRef::new(cred_id, CredentialPurpose::Password))
        .expect("get must succeed")
        .expect("password must be present");

    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::Password(fetched),
        Arc::new(AcceptAll),
        known_hosts_in(&dir),
        default_size(),
    )
    .expect("spawn ssh session");

    wait_for_connected(&session, Duration::from_secs(5));
    session.shutdown();
}

#[test]
fn ssh_credential_key_material_auth_success_via_keychain() {
    let dir = scratch_dir("cred-key-ok");
    let (_hk_path, host_key, _hk_pub) = gen_keypair(&dir, "hostkey");
    let (user_key_path, _user_priv, user_pub) = gen_keypair(&dir, "userkey");
    let key_pem = std::fs::read_to_string(&user_key_path).expect("read generated private key");

    let mut cfg = SshServerConfig::new(host_key);
    cfg.accept_pubkey_fingerprint = Some(fingerprint(&user_pub));
    let server = LoopbackSshServer::spawn(cfg);

    // Store the raw PEM text under `CredentialPurpose::SshKey`, exactly as a
    // pasted SSH-key credential is stored (`cm-ui/src/controller/keys_ctl.rs`),
    // then fetch it back and feed it through `SshAuthInput::KeyMaterial` (no
    // file path for a keychain-stored key).
    let store = InMemoryCredentialStore::new();
    let cred_id = CredentialId::new(43);
    store
        .store(
            &CredentialRef::new(cred_id, CredentialPurpose::SshKey),
            &Secret::from_string(key_pem),
        )
        .expect("store key material");
    let fetched = store
        .get(&CredentialRef::new(cred_id, CredentialPurpose::SshKey))
        .expect("get must succeed")
        .expect("key material must be present");

    let session = SshTerminalSession::connect(
        &ssh_settings(server.port, "tester"),
        SshAuthInput::KeyMaterial {
            key_pem: fetched,
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
fn ssh_credential_missing_never_attempts_connect() {
    // No credential stored at all: the keychain contract itself must return
    // `None` (never an empty-but-`Some` secret) so the cm-ui resolution layer
    // (unit-tested separately with a mock store) can turn this into a typed
    // `AuthResolveError::NotFoundInKeychain` / `NoCredentialAssigned` and show
    // the auth-error overlay -- never a silent empty-password connect attempt.
    let store = InMemoryCredentialStore::new();
    let cred_id = CredentialId::new(44);
    let fetched = store
        .get(&CredentialRef::new(cred_id, CredentialPurpose::Password))
        .expect("get on an absent credential must not error");
    assert!(
        fetched.is_none(),
        "an absent credential must resolve to None, never an empty-but-Some secret"
    );
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
// Real-host integration test — needs a local `sshd`.
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

// ---------------------------------------------------------------------------
// BUG-ssh-rsa-sha2 regression — real `sshd`, SHA-2-only RSA auth.
// ---------------------------------------------------------------------------
//
// `LoopbackSshServer` (the in-process harness above) cannot reproduce this
// bug: its `Handler::auth_publickey` callback fires only *after* russh's own
// server-side signature verification succeeds, with no visibility into which
// signature algorithm name (`ssh-rsa` vs `rsa-sha2-256`/`-512`) the client
// used — so it cannot enforce `PubkeyAcceptedAlgorithms`-style exclusion the
// way real `sshd` does. A real `sshd` is required to prove the fix; it's
// already a test dependency here (`start_sshd`/`ssh_publickey_runs_mark42_over_real_sshd`
// above), so this reuses that pattern with an RSA user key and an explicit
// `PubkeyAcceptedAlgorithms` that excludes `ssh-rsa`.

/// Like [`start_sshd`] but the user key is RSA and `PubkeyAcceptedAlgorithms`
/// is pinned to `rsa-sha2-512,rsa-sha2-256` — legacy `ssh-rsa`/SHA-1 is
/// explicitly excluded, the exact server posture that broke ConMan against
/// win11-target (BUG-ssh-rsa-sha2): before the fix, `authenticate()` always
/// signed RSA keys via `PrivateKeyWithHashAlg::new(key, None)`, which russh
/// maps to legacy `ssh-rsa`, and a server configured this way rejects it.
fn start_sshd_rsa_sha2_only() -> TestServer {
    let sshd = std::env::var("CONMAN_TEST_SSHD").unwrap_or_else(|_| "/usr/sbin/sshd".to_owned());
    let user = std::env::var("USER").expect("USER");
    let dir = std::env::temp_dir().join(format!("conman-ssh-it-rsa-sha2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let host_key = dir.join("hostkey");
    let user_key = dir.join("id_rsa");
    keygen(&host_key); // host-key algorithm is unrelated to user-auth sig algo
    keygen_rsa(&user_key);
    std::fs::copy(dir.join("id_rsa.pub"), dir.join("authorized_keys")).unwrap();

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
             PrintMotd no\n\
             PubkeyAcceptedAlgorithms rsa-sha2-512,rsa-sha2-256\n",
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
fn ssh_publickey_rsa_authenticates_when_server_requires_sha2() {
    let server = start_sshd_rsa_sha2_only();

    let cfg = SshSettings {
        host: "127.0.0.1".to_owned(),
        port: server.port,
        username: server.user.clone(),
        auth_method: cm_core::SshAuthMethod::Password,
    };

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

    // Type a command whose OUTPUT (MARK42) differs from the echoed input —
    // proves a real authenticated shell ran, not just a TCP handshake.
    session.paste(b"echo MARK$((6*7))".to_vec());
    session.send_key(KeyEvent {
        key: Key::Enter,
        mods: KeyModifiers::default(),
    });

    assert!(
        wait_for_text(&session, "MARK42", Duration::from_secs(10)),
        "expected RSA-key publickey auth to succeed against a server whose \
         PubkeyAcceptedAlgorithms requires SHA-2 (excludes ssh-rsa) -- the \
         exact condition BUG-ssh-rsa-sha2 reproduced against win11-target"
    );

    session.shutdown();
}

// ---------------------------------------------------------------------------
// BUG-ssh-rsa-sha2 live re-verify — opt-in, real external host.
// ---------------------------------------------------------------------------

/// Opt-in live proof driven entirely by env vars, so no lab-specific
/// host/user/key path is ever hardcoded in tracked source (this repo keeps
/// infra/host details out of tracked files). No-ops (does not fail) when the
/// env vars are unset, so `cargo test --ignored` elsewhere never fails on
/// missing lab access; only meaningful when explicitly pointed at a host:
///
/// ```text
/// CONMAN_LIVE_SSH_HOST=<ip-or-hostname> CONMAN_LIVE_SSH_USER=<user> \
///   CONMAN_LIVE_SSH_KEY=<path-to-rsa-private-key> \
///   cargo test -p cm-session --test ssh_loopback -- --ignored \
///   ssh_publickey_rsa_live_host_requiring_sha2 --nocapture
/// ```
#[test]
#[ignore = "opt-in: set CONMAN_LIVE_SSH_HOST/_USER/_KEY to run against a real host"]
fn ssh_publickey_rsa_live_host_requiring_sha2() {
    let (host, user, key_path) = match (
        std::env::var("CONMAN_LIVE_SSH_HOST"),
        std::env::var("CONMAN_LIVE_SSH_USER"),
        std::env::var("CONMAN_LIVE_SSH_KEY"),
    ) {
        (Ok(h), Ok(u), Ok(k)) => (h, u, k),
        _ => {
            eprintln!(
                "ssh_publickey_rsa_live_host_requiring_sha2: skipping -- set \
                 CONMAN_LIVE_SSH_HOST/_USER/_KEY to exercise a live host"
            );
            return;
        }
    };

    let dir = scratch_dir("live-rsa-sha2");
    let cfg = SshSettings {
        host,
        port: 22,
        username: user,
        auth_method: cm_core::SshAuthMethod::Password,
    };
    let known_hosts = known_hosts_in(&dir);
    let auth = SshAuthInput::Key {
        path: PathBuf::from(key_path),
        passphrase: None,
    };

    let session =
        SshTerminalSession::connect(&cfg, auth, Arc::new(AcceptAll), known_hosts, default_size())
            .expect("spawn ssh session");

    wait_for_connected(&session, Duration::from_secs(15));

    session.paste(b"echo MARK$((6*7))".to_vec());
    session.send_key(KeyEvent {
        key: Key::Enter,
        mods: KeyModifiers::default(),
    });

    assert!(
        wait_for_text(&session, "MARK42", Duration::from_secs(15)),
        "expected RSA-key publickey auth over cm_session::ssh to succeed against the live host"
    );

    session.shutdown();
}

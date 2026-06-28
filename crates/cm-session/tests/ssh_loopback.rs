//! P3.1 SSH integration proof: stand up a throwaway loopback `sshd`, connect
//! with [`SshTerminalSession`], run `echo MARK$((6*7))`, and assert the grid
//! shows `MARK42` — a real shell command executed over a real SSH transport.
//!
//! Gated `#[ignore]` (needs the `sshd` binary + spawns a server). Run with:
//! ```text
//! CARGO_TARGET_DIR=... PATH=<zig 0.15.2>:$PATH \
//!   cargo test -p cm-session --test ssh_loopback -- --ignored --nocapture
//! ```
//! Override the sshd path with `CONMAN_TEST_SSHD` (default `/usr/sbin/sshd`).
#![cfg(unix)]

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cm_core::SshSettings;
use cm_core::terminal::{GridSnapshot, Key, KeyEvent, KeyModifiers, TerminalSize};
use cm_session::{
    HostKeyDecision, HostKeyInfo, HostKeyVerifier, KnownHosts, SessionStatus, SshAuthInput,
    SshTerminalSession, TerminalSession,
};

/// Auto-accept verifier (TOFU happy path).
struct AcceptAll;
impl HostKeyVerifier for AcceptAll {
    fn decide(&self, _: &HostKeyInfo) -> HostKeyDecision {
        HostKeyDecision::Accept
    }
}

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

fn keygen(path: &Path) {
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f"])
        .arg(path)
        .status()
        .expect("run ssh-keygen");
    assert!(status.success(), "ssh-keygen failed");
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
    while Instant::now() < deadline {
        match session.status() {
            SessionStatus::Connected => return,
            SessionStatus::Failed(reason) => panic!("SSH connect failed: {reason}"),
            _ => std::thread::sleep(Duration::from_millis(25)),
        }
    }
    panic!("SSH did not reach Connected within {timeout:?}");
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

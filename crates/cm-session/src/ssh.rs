//! SSH terminal session over [russh](https://docs.rs/russh) 0.61.
//!
//! Architecture (ARCHITECTURE §4): a **tokio** current-thread runtime on a
//! dedicated OS thread drives russh (connect → host-key verify → auth → PTY +
//! shell → channel IO). Channel bytes are forwarded over an `mpsc` to the
//! **same `!Send` engine-owner thread** the local terminal uses ([`run_engine_owner`]);
//! encoded input + engine responses flow back through a tokio channel to the
//! driver, which writes them to the SSH channel. Only bytes + owned
//! `GridSnapshot`s cross threads — the VT engine never moves.
//!
//! Host-key policy (resolved by the user 2026-06-27): TOFU + accept-prompt, a
//! conscious override on mismatch (warn, never hard-refuse), and a **read-only**
//! consult of the user's OpenSSH `~/.ssh/known_hosts`. See [`KnownHosts`].

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use cm_core::Secret;
use cm_core::terminal::{GridSnapshot, KeyEvent, MouseEvent, TerminalSize};
use russh::keys::known_hosts::{
    check_known_hosts_path, known_host_keys_path, learn_known_hosts_path,
};
use russh::keys::ssh_key::{HashAlg, PublicKey};
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::engine_owner::{Msg, Transport, run_engine_owner};
use crate::libghostty::EngineError;
use crate::session::{ExitStatus, SessionStatus, TerminalSession};
use cm_core::SshSettings;

/// Terminal type advertised to the remote in the PTY request.
const TERM_TYPE: &str = "xterm-256color";

/// Typed SSH session errors. Never carries secret material.
#[derive(Debug, thiserror::Error)]
pub enum SshError {
    /// TCP connect / SSH handshake failed.
    #[error("connect failed: {0}")]
    Connect(String),
    /// The server host key was rejected (unknown/mismatch declined by the verifier).
    #[error("host key rejected: {0}")]
    HostKey(String),
    /// Authentication failed (all configured methods rejected).
    #[error("authentication failed: {0}")]
    Auth(String),
    /// Opening the session channel / requesting a PTY or shell failed.
    #[error("channel error: {0}")]
    Channel(String),
    /// A private key could not be loaded.
    #[error("key load failed: {0}")]
    Key(String),
    /// An OS thread could not be started.
    #[error("failed to start session thread: {0}")]
    Thread(#[source] std::io::Error),
    /// The terminal engine failed to initialize.
    #[error("terminal engine init failed: {0}")]
    Engine(#[source] EngineError),
}

/// MVP inline authentication input (until `cm-secrets`/profile storage lands in P1).
/// Secrets are [`Secret`] (zeroizing) and never logged.
#[derive(Debug)]
pub enum SshAuthInput {
    /// Password authentication.
    Password(Secret),
    /// Public-key authentication from a key file with an optional passphrase.
    Key {
        path: PathBuf,
        passphrase: Option<Secret>,
    },
    /// ssh-agent authentication (uses `SSH_AUTH_SOCK`).
    Agent,
}

// ---------------------------------------------------------------------------
// Host-key verification
// ---------------------------------------------------------------------------

/// Which store a previously-recorded host key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownHostSource {
    /// ConMan's own known-hosts file (writable).
    ConManStore,
    /// The user's OpenSSH `~/.ssh/known_hosts` (consulted read-only).
    UserKnownHosts,
}

/// The situation presented to the verifier for a host key needing a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeySituation {
    /// The host is in neither store.
    Unknown,
    /// The host is known but the presented key differs (possible MITM).
    Mismatch {
        stored_fingerprint: String,
        source: KnownHostSource,
    },
}

/// Details of a host key awaiting a user decision (the prompt UI is P3.2).
#[derive(Debug, Clone)]
pub struct HostKeyInfo {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    /// SHA256 fingerprint of the presented key (`SHA256:...`).
    pub fingerprint: String,
    pub situation: HostKeySituation,
}

/// The user's decision for an unknown or mismatched host key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyDecision {
    /// Accept: on `Unknown` store the key in ConMan's store; on `Mismatch`
    /// replace the ConMan store entry. Never touches `~/.ssh/known_hosts`.
    Accept,
    /// Reject and abort the connection.
    Reject,
}

/// Decides whether to trust an unknown/mismatched host key. In P3.2 this is the
/// prompt UI; in tests it is programmatic (auto-accept / auto-reject).
pub trait HostKeyVerifier: Send + Sync {
    fn decide(&self, info: &HostKeyInfo) -> HostKeyDecision;
}

/// The known-hosts stores consulted on connect: ConMan's own (writable) plus the
/// user's OpenSSH file (read-only — never mutated).
#[derive(Debug, Clone)]
pub struct KnownHosts {
    conman_path: PathBuf,
    user_path: Option<PathBuf>,
}

impl KnownHosts {
    /// ConMan store under the OS data dir; user store at `~/.ssh/known_hosts`.
    #[must_use]
    pub fn with_defaults() -> Self {
        let conman_path = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("conman")
            .join("known_hosts");
        let user_path = dirs::home_dir().map(|h| h.join(".ssh").join("known_hosts"));
        Self {
            conman_path,
            user_path,
        }
    }

    /// Explicit paths (tests pin temp files; pass `None` to skip the user file).
    #[must_use]
    pub fn with_paths(conman_path: PathBuf, user_path: Option<PathBuf>) -> Self {
        Self {
            conman_path,
            user_path,
        }
    }

    /// Run the lookup-order policy and, for unknown/mismatch, consult `verifier`.
    /// Returns whether to accept the key. On accept of an unknown/mismatch, the
    /// key is written to ConMan's store (never to the user file).
    fn verify(
        &self,
        host: &str,
        port: u16,
        key: &PublicKey,
        verifier: &dyn HostKeyVerifier,
    ) -> bool {
        // 1. ConMan store.
        match check_known_hosts_path(host, port, key, &self.conman_path) {
            Ok(true) => return true, // match -> silent accept
            Err(russh::keys::Error::KeyChanged { .. }) => {
                let stored = self.stored_fingerprint(host, port, key, &self.conman_path);
                return self.prompt_and_maybe_store(
                    host,
                    port,
                    key,
                    verifier,
                    HostKeySituation::Mismatch {
                        stored_fingerprint: stored,
                        source: KnownHostSource::ConManStore,
                    },
                );
            }
            _ => {} // not found / unreadable -> continue
        }
        // 2. User ~/.ssh/known_hosts (read-only).
        if let Some(user_path) = &self.user_path {
            match check_known_hosts_path(host, port, key, user_path) {
                Ok(true) => return true,
                Err(russh::keys::Error::KeyChanged { .. }) => {
                    let stored = self.stored_fingerprint(host, port, key, user_path);
                    return self.prompt_and_maybe_store(
                        host,
                        port,
                        key,
                        verifier,
                        HostKeySituation::Mismatch {
                            stored_fingerprint: stored,
                            source: KnownHostSource::UserKnownHosts,
                        },
                    );
                }
                _ => {}
            }
        }
        // 3. Unknown.
        self.prompt_and_maybe_store(host, port, key, verifier, HostKeySituation::Unknown)
    }

    fn prompt_and_maybe_store(
        &self,
        host: &str,
        port: u16,
        key: &PublicKey,
        verifier: &dyn HostKeyVerifier,
        situation: HostKeySituation,
    ) -> bool {
        let info = HostKeyInfo {
            host: host.to_owned(),
            port,
            algorithm: key.algorithm().as_str().to_owned(),
            fingerprint: fingerprint(key),
            situation,
        };
        match verifier.decide(&info) {
            HostKeyDecision::Accept => {
                // Store/replace in ConMan's store only — never the user file.
                let _ = learn_known_hosts_path(host, port, key, &self.conman_path);
                true
            }
            HostKeyDecision::Reject => false,
        }
    }

    /// SHA256 fingerprint of the stored key (same algorithm) for the mismatch
    /// warning, or `"<unknown>"` if it cannot be read.
    fn stored_fingerprint(&self, host: &str, port: u16, key: &PublicKey, path: &PathBuf) -> String {
        known_host_keys_path(host, port, path)
            .ok()
            .and_then(|entries| {
                entries
                    .into_iter()
                    .find(|(_, k)| k.algorithm() == key.algorithm())
                    .map(|(_, k)| fingerprint(&k))
            })
            .unwrap_or_else(|| "<unknown>".to_owned())
    }
}

/// SHA256 fingerprint string (`SHA256:...`).
fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// russh client handler: delegates server-key checking to the [`KnownHosts`]
/// policy + [`HostKeyVerifier`]. Records a rejection reason so the driver can
/// surface [`SshError::HostKey`] specifically.
struct ClientHandler {
    host: String,
    port: u16,
    known_hosts: KnownHosts,
    verifier: Arc<dyn HostKeyVerifier>,
    rejected: Arc<Mutex<Option<String>>>,
}

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        if self
            .known_hosts
            .verify(&self.host, self.port, key, &*self.verifier)
        {
            Ok(true)
        } else {
            *self.rejected.lock().unwrap() = Some(format!(
                "{} key {} not trusted",
                key.algorithm().as_str(),
                fingerprint(key)
            ));
            Ok(false)
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Outbound work for the tokio driver: bytes to write to the channel, or a
/// window resize. (`out_tx` dropping signals shutdown.)
enum Outbound {
    Data(Vec<u8>),
    Resize { cols: u32, rows: u32 },
}

/// SSH-backed [`Transport`]: hands encoded input/responses and resizes to the
/// tokio driver over an unbounded channel.
struct SshTransport {
    out_tx: UnboundedSender<Outbound>,
}

impl Transport for SshTransport {
    fn write(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            let _ = self.out_tx.send(Outbound::Data(bytes.to_vec()));
        }
    }

    fn resize(&mut self, size: TerminalSize) {
        let _ = self.out_tx.send(Outbound::Resize {
            cols: u32::from(size.cols),
            rows: u32::from(size.rows),
        });
    }
}

/// A live SSH terminal session. `Send`; the `!Send` engine is confined to its
/// owner thread.
#[derive(Debug)]
pub struct SshTerminalSession {
    control_tx: Sender<Msg>,
    snapshot_rx: Receiver<GridSnapshot>,
    status: Arc<Mutex<SessionStatus>>,
    owner_handle: Mutex<Option<JoinHandle<()>>>,
    driver_handle: Mutex<Option<JoinHandle<()>>>,
}

impl SshTerminalSession {
    /// Begin connecting. Returns immediately in [`SessionStatus::Connecting`];
    /// the async handshake/auth/shell update [`status`](Self::status) to
    /// `Connected` or `Failed`. Snapshots flow once the remote shell produces
    /// output.
    ///
    /// # Errors
    /// Returns [`SshError`] only for synchronous setup failures (engine init,
    /// thread spawn). Network/auth/host-key failures surface via `status()`.
    pub fn connect(
        cfg: &SshSettings,
        auth: SshAuthInput,
        verifier: Arc<dyn HostKeyVerifier>,
        known_hosts: KnownHosts,
        size: TerminalSize,
    ) -> Result<Self, SshError> {
        let (control_tx, control_rx) = mpsc::channel::<Msg>();
        let (snapshot_tx, snapshot_rx) = mpsc::channel::<GridSnapshot>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), EngineError>>();
        let (out_tx, out_rx) = unbounded_channel::<Outbound>();
        let status = Arc::new(Mutex::new(SessionStatus::Connecting));
        let start = Instant::now();

        // Engine-owner thread (shared byte pump; SSH transport).
        let owner_handle = thread::Builder::new()
            .name("vt-engine-owner".to_owned())
            .spawn({
                let transport = SshTransport { out_tx };
                move || {
                    run_engine_owner(size, transport, &control_rx, &snapshot_tx, &ready_tx, start);
                }
            })
            .map_err(SshError::Thread)?;

        // Surface engine init failure synchronously.
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = owner_handle.join();
                return Err(SshError::Engine(e));
            }
            Err(_) => {
                let _ = owner_handle.join();
                return Err(SshError::Engine(EngineError::Init(
                    "engine owner thread exited".to_owned(),
                )));
            }
        }

        // tokio driver thread.
        let driver_cfg = cfg.clone();
        let driver_control = control_tx.clone();
        let driver_status = Arc::clone(&status);
        let driver_handle = thread::Builder::new()
            .name("ssh-driver".to_owned())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        set_status(
                            &driver_status,
                            SessionStatus::Failed(format!("runtime: {e}")),
                        );
                        return;
                    }
                };
                rt.block_on(drive(
                    driver_cfg,
                    auth,
                    verifier,
                    known_hosts,
                    size,
                    &driver_control,
                    out_rx,
                    &driver_status,
                ));
            })
            .map_err(SshError::Thread)?;

        Ok(Self {
            control_tx,
            snapshot_rx,
            status,
            owner_handle: Mutex::new(Some(owner_handle)),
            driver_handle: Mutex::new(Some(driver_handle)),
        })
    }
}

impl TerminalSession for SshTerminalSession {
    fn snapshots(&self) -> &Receiver<GridSnapshot> {
        &self.snapshot_rx
    }

    fn send_key(&self, ev: KeyEvent) {
        let _ = self.control_tx.send(Msg::Key(ev));
    }

    fn send_mouse(&self, ev: MouseEvent) {
        let _ = self.control_tx.send(Msg::Mouse(ev));
    }

    fn paste(&self, bytes: Vec<u8>) {
        let _ = self.control_tx.send(Msg::Paste(bytes));
    }

    fn resize(&self, size: TerminalSize) {
        let _ = self.control_tx.send(Msg::Resize(size));
    }

    fn status(&self) -> SessionStatus {
        self.status
            .lock()
            .map_or(SessionStatus::Disconnected, |s| s.clone())
    }

    /// Stop the engine owner (dropping `out_tx`, which closes the driver's
    /// receiver), then join both threads. Idempotent.
    fn shutdown(&self) {
        let _ = self.control_tx.send(Msg::Shutdown);
        if let Some(h) = self.owner_handle.lock().ok().and_then(|mut g| g.take()) {
            let _ = h.join();
        }
        if let Some(h) = self.driver_handle.lock().ok().and_then(|mut g| g.take()) {
            let _ = h.join();
        }
        if let Ok(mut s) = self.status.lock()
            && !matches!(*s, SessionStatus::Exited(_) | SessionStatus::Failed(_))
        {
            *s = SessionStatus::Disconnected;
        }
    }
}

impl Drop for SshTerminalSession {
    fn drop(&mut self) {
        let already_done = self
            .owner_handle
            .lock()
            .map(|g| g.is_none())
            .unwrap_or(true);
        if already_done {
            return;
        }
        let _ = self.control_tx.send(Msg::Shutdown);
    }
}

fn set_status(status: &Arc<Mutex<SessionStatus>>, new: SessionStatus) {
    if let Ok(mut s) = status.lock() {
        *s = new;
    }
}

/// The async SSH driver: connect → verify → auth → PTY + shell → byte pump.
#[allow(clippy::too_many_arguments)]
async fn drive(
    cfg: SshSettings,
    auth: SshAuthInput,
    verifier: Arc<dyn HostKeyVerifier>,
    known_hosts: KnownHosts,
    size: TerminalSize,
    control_tx: &Sender<Msg>,
    mut out_rx: UnboundedReceiver<Outbound>,
    status: &Arc<Mutex<SessionStatus>>,
) {
    match drive_inner(
        &cfg,
        auth,
        verifier,
        known_hosts,
        size,
        control_tx,
        &mut out_rx,
        status,
    )
    .await
    {
        Ok(()) => {}
        Err(e) => set_status(status, SessionStatus::Failed(e.to_string())),
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive_inner(
    cfg: &SshSettings,
    auth: SshAuthInput,
    verifier: Arc<dyn HostKeyVerifier>,
    known_hosts: KnownHosts,
    size: TerminalSize,
    control_tx: &Sender<Msg>,
    out_rx: &mut UnboundedReceiver<Outbound>,
    status: &Arc<Mutex<SessionStatus>>,
) -> Result<(), SshError> {
    let config = Arc::new(russh::client::Config::default());
    let rejected = Arc::new(Mutex::new(None::<String>));
    let handler = ClientHandler {
        host: cfg.host.clone(),
        port: cfg.port,
        known_hosts,
        verifier,
        rejected: Arc::clone(&rejected),
    };

    let mut handle =
        match russh::client::connect(config, (cfg.host.as_str(), cfg.port), handler).await {
            Ok(h) => h,
            Err(e) => {
                if let Some(reason) = rejected.lock().unwrap().take() {
                    return Err(SshError::HostKey(reason));
                }
                return Err(SshError::Connect(e.to_string()));
            }
        };

    if !authenticate(&mut handle, &cfg.username, auth).await? {
        return Err(SshError::Auth("all methods rejected".to_owned()));
    }

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| SshError::Channel(e.to_string()))?;
    channel
        .request_pty(
            false,
            TERM_TYPE,
            u32::from(size.cols),
            u32::from(size.rows),
            0,
            0,
            &[],
        )
        .await
        .map_err(|e| SshError::Channel(e.to_string()))?;
    channel
        .request_shell(false)
        .await
        .map_err(|e| SshError::Channel(e.to_string()))?;

    set_status(status, SessionStatus::Connected);

    pump(channel, control_tx, out_rx, status).await;
    Ok(())
}

/// Try the configured authentication method.
async fn authenticate(
    handle: &mut russh::client::Handle<ClientHandler>,
    user: &str,
    auth: SshAuthInput,
) -> Result<bool, SshError> {
    match auth {
        SshAuthInput::Password(secret) => {
            let password = String::from_utf8_lossy(secret.expose()).into_owned();
            let res = handle
                .authenticate_password(user, password)
                .await
                .map_err(|e| SshError::Auth(e.to_string()))?;
            Ok(res.success())
        }
        SshAuthInput::Key { path, passphrase } => {
            let pass = passphrase
                .as_ref()
                .map(|s| String::from_utf8_lossy(s.expose()).into_owned());
            let key = load_secret_key(&path, pass.as_deref())
                .map_err(|e| SshError::Key(e.to_string()))?;
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), None);
            let res = handle
                .authenticate_publickey(user, key)
                .await
                .map_err(|e| SshError::Auth(e.to_string()))?;
            Ok(res.success())
        }
        // ssh-agent is reached via the Unix domain socket in `SSH_AUTH_SOCK`.
        // Windows agents (Pageant / OpenSSH named pipe) use different stream
        // types; that plumbing is deferred (password + public key work on both).
        #[cfg(unix)]
        SshAuthInput::Agent => {
            let mut agent = russh::keys::agent::client::AgentClient::connect_env()
                .await
                .map_err(|e| SshError::Auth(format!("agent: {e}")))?;
            let identities = agent
                .request_identities()
                .await
                .map_err(|e| SshError::Auth(format!("agent identities: {e}")))?;
            for id in identities {
                if let russh::keys::agent::AgentIdentity::PublicKey { key, .. } = id {
                    let res = handle
                        .authenticate_publickey_with(user, key, None, &mut agent)
                        .await
                        .map_err(|e| SshError::Auth(format!("agent auth: {e}")))?;
                    if res.success() {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        #[cfg(not(unix))]
        SshAuthInput::Agent => Err(SshError::Auth(
            "ssh-agent authentication is not yet supported on this platform".to_owned(),
        )),
    }
}

/// Bidirectional pump: channel data → engine owner; outbound → channel.
async fn pump(
    mut channel: russh::Channel<russh::client::Msg>,
    control_tx: &Sender<Msg>,
    out_rx: &mut UnboundedReceiver<Outbound>,
    status: &Arc<Mutex<SessionStatus>>,
) {
    let mut exit_code: Option<u32> = None;
    loop {
        tokio::select! {
            incoming = channel.wait() => match incoming {
                Some(russh::ChannelMsg::Data { data }) => {
                    if control_tx.send(Msg::Bytes(data.to_vec())).is_err() { break; }
                }
                Some(russh::ChannelMsg::ExtendedData { data, .. }) => {
                    if control_tx.send(Msg::Bytes(data.to_vec())).is_err() { break; }
                }
                Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                    exit_code = Some(exit_status);
                }
                Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
            outbound = out_rx.recv() => match outbound {
                Some(Outbound::Data(bytes)) => {
                    if channel.data_bytes(bytes).await.is_err() { break; }
                }
                Some(Outbound::Resize { cols, rows }) => {
                    let _ = channel.window_change(cols, rows, 0, 0).await;
                }
                None => {
                    // Engine owner shut down (out_tx dropped): close the channel.
                    let _ = channel.eof().await;
                    break;
                }
            },
        }
    }

    let final_status = match exit_code {
        Some(code) => SessionStatus::Exited(ExitStatus {
            success: code == 0,
            code,
        }),
        None => SessionStatus::Disconnected,
    };
    if let Ok(mut s) = status.lock()
        && !matches!(*s, SessionStatus::Failed(_))
    {
        *s = final_status;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A programmatic verifier for tests: always returns the configured decision
    /// and records what it was asked about.
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
    }

    impl HostKeyVerifier for FixedVerifier {
        fn decide(&self, info: &HostKeyInfo) -> HostKeyDecision {
            self.seen.lock().unwrap().push(info.clone());
            self.decision
        }
    }

    // Two distinct, valid ed25519 public keys (generated by ssh-keygen; comment
    // stripped — server keys have none, and known_hosts round-trips drop it).
    const PUBKEY_A: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJUY/4JXWLBxpLza/TsG3MKndev7hC98QFUH9ZG8Dykw";
    const PUBKEY_B: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJnchvzC0kIY3cGhATTU9WSu00D0lUSq/uGsIUo+66tM";

    fn pubkey(openssh: &str) -> PublicKey {
        PublicKey::from_openssh(openssh).expect("valid test pubkey")
    }

    #[test]
    fn terminal_session_is_object_safe() {
        fn assert_obj_safe<T: TerminalSession>() {}
        assert_obj_safe::<SshTerminalSession>();
        let _: Option<Box<dyn TerminalSession>> = None;
    }

    #[test]
    fn unknown_host_accept_stores_in_conman_only() {
        let pubkey = pubkey(PUBKEY_A);

        let dir = std::env::temp_dir().join(format!("conman-kh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let conman = dir.join("known_hosts");
        let user = dir.join("user_known_hosts");
        let _ = std::fs::remove_file(&conman);
        let _ = std::fs::write(&user, ""); // empty user store

        let kh = KnownHosts::with_paths(conman.clone(), Some(user.clone()));
        let v = FixedVerifier::new(HostKeyDecision::Accept);

        // Unknown -> prompted, accepted, stored in ConMan store.
        assert!(kh.verify("10.0.0.5", 22, &pubkey, &*v));
        assert_eq!(
            v.seen.lock().unwrap()[0].situation,
            HostKeySituation::Unknown
        );
        assert!(
            conman.exists(),
            "accepted key should be written to ConMan store"
        );
        // User store untouched (still empty).
        assert_eq!(std::fs::read_to_string(&user).unwrap(), "");

        // Now it's a known match -> accepted with NO prompt.
        let v2 = FixedVerifier::new(HostKeyDecision::Reject);
        assert!(kh.verify("10.0.0.5", 22, &pubkey, &*v2));
        assert!(v2.seen.lock().unwrap().is_empty(), "match must not prompt");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mismatch_is_detected_and_can_be_rejected() {
        let key_a = pubkey(PUBKEY_A);
        let key_b = pubkey(PUBKEY_B);

        let dir = std::env::temp_dir().join(format!("conman-kh2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let conman = dir.join("known_hosts");
        let _ = std::fs::remove_file(&conman);

        let kh = KnownHosts::with_paths(conman.clone(), None);
        // Seed ConMan store with key A.
        learn_known_hosts_path("host.test", 22, &key_a, &conman).unwrap();

        // Present key B -> mismatch; reject.
        let v = FixedVerifier::new(HostKeyDecision::Reject);
        assert!(!kh.verify("host.test", 22, &key_b, &*v));
        match &v.seen.lock().unwrap()[0].situation {
            HostKeySituation::Mismatch { source, .. } => {
                assert_eq!(*source, KnownHostSource::ConManStore);
            }
            other => panic!("expected mismatch, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

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
use russh::keys::{PrivateKeyWithHashAlg, decode_secret_key, load_secret_key};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::engine_owner::{Msg, Transport, run_engine_owner};
use crate::libghostty::EngineError;
use crate::session::{ExitStatus, Session, SessionInput, SessionStatus, Surface, TerminalSession};
use cm_core::SshSettings;
// P6.15: the auth-input and host-key-verifier *contract* types moved to
// `cm_core::ssh` (needed by the `SessionProvider` port, which must be
// nameable from `cm-core` without a cm-core -> cm-session dependency). Only
// `KnownHosts` (real file I/O) stays here. Re-exported so external callers
// (`cm-ui`) keep importing them as `cm_session::{...}` unchanged.
pub use cm_core::ssh::{
    HostKeyDecision, HostKeyInfo, HostKeySituation, HostKeyVerifier, KbdInteractiveChallenge,
    KbdInteractiveHandler, KbdInteractivePrompt, KnownHostSource, SshAuthInput,
};

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

/// Hard cap on keyboard-interactive challenge rounds within a single auth
/// attempt — guards against a hostile/broken server looping the client
/// forever (CONVENTIONS §2, parser/loop safety: every loop must be bounded).
const MAX_KBD_INTERACTIVE_ROUNDS: u32 = 16;

/// Pads or truncates `answers` to exactly `expected` entries. Defensive: a
/// misbehaving [`KbdInteractiveHandler`] must never desync the protocol
/// exchange or panic the auth attempt — it just answers empty for any prompt
/// it didn't cover.
fn align_answers(expected: usize, mut answers: Vec<Secret>) -> Vec<Secret> {
    if answers.len() != expected {
        answers.resize_with(expected, || Secret::from_string(String::new()));
    }
    answers
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
        let algorithm = key.algorithm().as_str().to_owned();
        let fp = fingerprint(key);
        let info = HostKeyInfo {
            host: host.to_owned(),
            port,
            algorithm: algorithm.clone(),
            fingerprint: fp.clone(),
            situation: situation.clone(),
        };

        tracing::warn!(
            host,
            port,
            algorithm = %algorithm,
            fingerprint = %fp,
            situation = ?situation,
            "ssh: host key unknown/mismatch, prompting"
        );

        match verifier.decide(&info) {
            HostKeyDecision::Accept => {
                // Store/replace in ConMan's store only — never the user file.
                let _ = learn_known_hosts_path(host, port, key, &self.conman_path);
                tracing::info!(host, port, algorithm = %algorithm, fingerprint = %fp, "ssh: host key accepted and stored");
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
            *self
                .rejected
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(format!(
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
///
/// Implements both [`TerminalSession`] and [`Session`] (unified P4.1 trait).
#[derive(Debug)]
pub struct SshTerminalSession {
    control_tx: Sender<Msg>,
    /// Unified surface — always `Surface::TerminalGrid(_)` for this type.
    surface: Surface,
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
                    start,
                ));
            })
            .map_err(SshError::Thread)?;

        Ok(Self {
            control_tx,
            surface: Surface::TerminalGrid(snapshot_rx),
            status,
            owner_handle: Mutex::new(Some(owner_handle)),
            driver_handle: Mutex::new(Some(driver_handle)),
        })
    }
}

impl TerminalSession for SshTerminalSession {
    fn snapshots(&self) -> &Receiver<GridSnapshot> {
        match &self.surface {
            Surface::TerminalGrid(rx) => rx,
            _ => unreachable!("SshTerminalSession always has TerminalGrid surface"),
        }
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

    fn set_scroll(&self, offset: u32) {
        let _ = self.control_tx.send(Msg::SetScroll(offset));
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

/// Unified [`Session`] implementation for [`SshTerminalSession`].
///
/// `surface()` returns `Surface::TerminalGrid`; `status()` and `shutdown()`
/// delegate to the `TerminalSession` impl; `resize_px()` approximates cell
/// dimensions from pixel dimensions (8×16 font size; precise resize happens
/// via `TerminalSession::resize()` in the UI layer, P4.2).
impl Session for SshTerminalSession {
    fn surface(&self) -> &Surface {
        &self.surface
    }

    fn status(&self) -> SessionStatus {
        <Self as TerminalSession>::status(self)
    }

    fn shutdown(&self) {
        <Self as TerminalSession>::shutdown(self);
    }

    fn resize_px(&self, width: u32, height: u32) {
        // Fallback: approximate 8×16 cell size. Preferred path is resize_cells.
        let cols = u16::try_from(width / 8).unwrap_or(u16::MAX).max(2);
        let rows = u16::try_from(height / 16).unwrap_or(u16::MAX).max(1);
        <Self as TerminalSession>::resize(self, TerminalSize { cols, rows });
    }

    fn resize_cells(&self, cols: u16, rows: u16) {
        <Self as TerminalSession>::resize(self, TerminalSize { cols, rows });
    }

    fn send_input(&self, input: SessionInput) {
        match input {
            SessionInput::Key(ev) => {
                <Self as TerminalSession>::send_key(self, ev);
            }
            SessionInput::Mouse(ev) => {
                <Self as TerminalSession>::send_mouse(self, ev);
            }
            SessionInput::Paste(bytes) => {
                <Self as TerminalSession>::paste(self, bytes);
            }
            SessionInput::Scroll(offset) => {
                <Self as TerminalSession>::set_scroll(self, offset);
            }
            SessionInput::Rdp(_) | SessionInput::RdpPaste(_) => {}
        }
    }

    fn request_search_text(&self, reply: Sender<Vec<String>>) {
        let _ = self.control_tx.send(Msg::QueryBuffer(reply));
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
    start: Instant,
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
        start,
    )
    .await
    {
        Ok(()) => {}
        Err(e) => {
            // P9.8 C16: catch-all so no SshError variant is ever silent --
            // every failure that reaches here gets one WARN line before the
            // status flips to Failed.
            tracing::warn!(host = %cfg.host, error = %e, "ssh: session failed");
            set_status(status, SessionStatus::Failed(e.to_string()));
        }
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
    start: Instant,
) -> Result<(), SshError> {
    tracing::info!(
        host = %cfg.host,
        port = cfg.port,
        username = %cfg.username,
        "ssh: connecting"
    );

    let config = Arc::new(russh::client::Config::default());
    let rejected = Arc::new(Mutex::new(None::<String>));
    let handler = ClientHandler {
        host: cfg.host.clone(),
        port: cfg.port,
        known_hosts,
        verifier,
        rejected: Arc::clone(&rejected),
    };

    let mut handle = match russh::client::connect(config, (cfg.host.as_str(), cfg.port), handler)
        .await
    {
        Ok(h) => h,
        Err(e) => {
            let reason = rejected
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            if let Some(reason) = reason {
                tracing::warn!(host = %cfg.host, port = cfg.port, reason = %reason, "ssh: host key rejected");
                return Err(SshError::HostKey(reason));
            }
            tracing::warn!(host = %cfg.host, port = cfg.port, error = %e, "ssh: TCP/handshake connect failed");
            return Err(SshError::Connect(e.to_string()));
        }
    };

    // fix-connect-credential-logging: debug-build-only diagnostic for the
    // effective username actually handed to SSH auth. NEVER the
    // password/key/passphrase carried in `auth` -- only the username.
    #[cfg(debug_assertions)]
    tracing::info!(
        username = %cfg.username,
        host = %cfg.host,
        port = cfg.port,
        "ssh: authenticating"
    );

    if !authenticate(&mut handle, &cfg.username, auth).await? {
        tracing::warn!(username = %cfg.username, host = %cfg.host, "ssh: all auth methods rejected");
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
    tracing::info!(
        host = %cfg.host,
        username = %cfg.username,
        connect_ms = start.elapsed().as_millis(),
        "ssh: shell ready"
    );

    pump(channel, control_tx, out_rx, status).await;
    Ok(())
}

/// Candidate RSA signature hash algorithms to try, in order, against
/// `handle`'s server (BUG-ssh-rsa-sha2). `PrivateKeyWithHashAlg::new` maps
/// `None` to the legacy `ssh-rsa` (SHA-1) signature algorithm, which modern
/// OpenSSH (8.8+, ~2021 on) rejects outright when `PubkeyAcceptedAlgorithms`
/// excludes it — the exact failure this fixes. Mirrors the OpenSSH client:
/// prefer the server's advertised `server-sig-algs` (RFC 8332) when present;
/// otherwise try SHA-2 first (accepted by all OpenSSH >= 7.2 / ~2016) and
/// fall back to legacy `ssh-rsa` only if the server still wants it.
///
/// Non-RSA keys (Ed25519/ECDSA) always get the single `None` candidate: the
/// hash-alg concept is RSA-only (`PrivateKeyWithHashAlg::new` ignores it for
/// other key types), and skipping the negotiation round-trip avoids the
/// `best_supported_rsa_hash` up-to-1s wait for keys where it can't matter.
async fn rsa_hash_candidates(
    handle: &russh::client::Handle<ClientHandler>,
    algorithm: russh::keys::ssh_key::Algorithm,
) -> Vec<Option<HashAlg>> {
    if !algorithm.is_rsa() {
        return vec![None];
    }
    match handle.best_supported_rsa_hash().await {
        // The server sent `server-sig-algs`: `Some(hash)` is its best
        // SHA-2 variant, `Some(None)` means it advertised the extension but
        // only accepts legacy `ssh-rsa` — either way, trust it and stop.
        Ok(Some(hash)) => vec![hash],
        // No extension info (older/non-conforming server): try SHA-2 first,
        // then fall back to `ssh-rsa` if both are rejected.
        Ok(None) | Err(_) => vec![Some(HashAlg::Sha512), Some(HashAlg::Sha256), None],
    }
}

/// Public-key auth for a locally-held [`russh::keys::PrivateKey`] (the
/// `Key { path }` and `KeyMaterial` arms), retrying across
/// [`rsa_hash_candidates`] until one succeeds or the candidates are
/// exhausted.
async fn authenticate_publickey_negotiated(
    handle: &mut russh::client::Handle<ClientHandler>,
    user: &str,
    key: Arc<russh::keys::PrivateKey>,
) -> Result<bool, SshError> {
    let candidates = rsa_hash_candidates(handle, key.algorithm()).await;
    for hash_alg in candidates {
        let signed = PrivateKeyWithHashAlg::new(Arc::clone(&key), hash_alg);
        let res = handle
            .authenticate_publickey(user, signed)
            .await
            .map_err(|e| SshError::Auth(e.to_string()))?;
        if res.success() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Try the configured authentication method.
async fn authenticate(
    handle: &mut russh::client::Handle<ClientHandler>,
    user: &str,
    auth: SshAuthInput,
) -> Result<bool, SshError> {
    // P9.8 C6: which method is attempted, not any secret material.
    #[cfg(debug_assertions)]
    {
        let method = match &auth {
            SshAuthInput::Password(_) => "password",
            SshAuthInput::Key { .. } => "key",
            SshAuthInput::KeyMaterial { .. } => "key-material",
            SshAuthInput::Agent => "agent",
            SshAuthInput::KeyboardInteractive { .. } => "kbd-interactive",
        };
        tracing::debug!(username = %user, method, "ssh: auth method attempt");
    }

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
            authenticate_publickey_negotiated(handle, user, Arc::new(key)).await
        }
        // P6.4: a stored credential's key material, fetched from the keychain
        // (no path on disk — decode the PEM text directly).
        SshAuthInput::KeyMaterial {
            key_pem,
            passphrase,
        } => {
            let pem = String::from_utf8_lossy(key_pem.expose()).into_owned();
            let pass = passphrase
                .as_ref()
                .map(|s| String::from_utf8_lossy(s.expose()).into_owned());
            let key = decode_secret_key(&pem, pass.as_deref())
                .map_err(|e| SshError::Key(e.to_string()))?;
            authenticate_publickey_negotiated(handle, user, Arc::new(key)).await
        }
        // ssh-agent: Unix reaches it via the domain socket in `SSH_AUTH_SOCK`;
        // Windows (P6.13) via the OpenSSH agent named pipe. Either way, an
        // absent/unreachable agent fails soft to `SshError::Auth` — never a
        // panic — so the caller sees a clear error instead of a hang.
        #[cfg(unix)]
        SshAuthInput::Agent => {
            let mut agent = russh::keys::agent::client::AgentClient::connect_env()
                .await
                .map_err(|e| SshError::Auth(format!("agent: {e}")))?;
            try_agent_identities(handle, user, &mut agent).await
        }
        #[cfg(windows)]
        SshAuthInput::Agent => {
            let mut agent = russh::keys::agent::client::AgentClient::connect_named_pipe(
                WINDOWS_OPENSSH_AGENT_PIPE,
            )
            .await
            .map_err(|e| SshError::Auth(format!("agent: {e}")))?;
            try_agent_identities(handle, user, &mut agent).await
        }
        #[cfg(not(any(unix, windows)))]
        SshAuthInput::Agent => Err(SshError::Auth(
            "ssh-agent authentication is not yet supported on this platform".to_owned(),
        )),
        SshAuthInput::KeyboardInteractive { handler } => {
            keyboard_interactive_auth(handle, user, handler.as_ref()).await
        }
    }
}

/// The Windows OpenSSH agent's well-known named pipe path (P6.13). The
/// service listens here when `ssh-agent` is running (Services.msc /
/// `Set-Service ssh-agent -StartupType Automatic`).
#[cfg(windows)]
const WINDOWS_OPENSSH_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// Walk the agent's identities, trying each against the server in turn.
/// Shared between the Unix (`SSH_AUTH_SOCK`) and Windows (named-pipe)
/// transports — only how `agent` was connected differs.
async fn try_agent_identities<S>(
    handle: &mut russh::client::Handle<ClientHandler>,
    user: &str,
    agent: &mut russh::keys::agent::client::AgentClient<S>,
) -> Result<bool, SshError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let identities = agent
        .request_identities()
        .await
        .map_err(|e| SshError::Auth(format!("agent identities: {e}")))?;
    for id in identities {
        if let russh::keys::agent::AgentIdentity::PublicKey { key, .. } = id {
            // BUG-ssh-rsa-sha2: agent-held RSA keys need the same SHA-2
            // negotiation as local keys. The agent protocol (RFC 8332 /
            // draft-miller-ssh-agent) signs with whatever `hash_alg` we ask
            // for via signature-request flags, so the fix is the same
            // candidate list — just handed to the agent instead of signed
            // in-process.
            let candidates = rsa_hash_candidates(handle, key.algorithm()).await;
            let mut authenticated = false;
            for hash_alg in candidates {
                let res = handle
                    .authenticate_publickey_with(user, key.clone(), hash_alg, agent)
                    .await
                    .map_err(|e| SshError::Auth(format!("agent auth: {e}")))?;
                if res.success() {
                    authenticated = true;
                    break;
                }
            }
            if authenticated {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Drive the keyboard-interactive challenge/response exchange: start the
/// method, then answer each `InfoRequest` round via `handler` until the
/// server reports success/failure or the round cap is hit. A round with zero
/// prompts (a valid but unusual server behavior) is answered with zero
/// responses rather than treated as an error — fail soft, never panic, on
/// malformed/empty challenges (CONVENTIONS §2).
async fn keyboard_interactive_auth(
    handle: &mut russh::client::Handle<ClientHandler>,
    user: &str,
    handler: &dyn KbdInteractiveHandler,
) -> Result<bool, SshError> {
    use russh::client::KeyboardInteractiveAuthResponse as Resp;

    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None)
        .await
        .map_err(|e| SshError::Auth(format!("keyboard-interactive: {e}")))?;

    for round in 0..MAX_KBD_INTERACTIVE_ROUNDS {
        match response {
            Resp::Success => return Ok(true),
            Resp::Failure { .. } => return Ok(false),
            Resp::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                let challenge = KbdInteractiveChallenge {
                    name,
                    instructions,
                    prompts: prompts
                        .into_iter()
                        .map(|p| KbdInteractivePrompt {
                            text: p.prompt,
                            echo: p.echo,
                        })
                        .collect(),
                };
                // P9.8 C10: round/prompt-count/name only -- NEVER the prompt
                // text or the user's answers.
                tracing::debug!(
                    round,
                    prompt_count = challenge.prompts.len(),
                    name = %challenge.name,
                    "ssh: kbd-interactive round"
                );
                let Some(answers) = handler.respond(&challenge) else {
                    // The user aborted the prompt: fail this auth method
                    // cleanly rather than sending a bogus response.
                    return Ok(false);
                };
                let responses: Vec<String> = align_answers(challenge.prompts.len(), answers)
                    .into_iter()
                    .map(|s| String::from_utf8_lossy(s.expose()).into_owned())
                    .collect();
                response = handle
                    .authenticate_keyboard_interactive_respond(responses)
                    .await
                    .map_err(|e| SshError::Auth(format!("keyboard-interactive: {e}")))?;
            }
        }
    }
    Err(SshError::Auth(
        "keyboard-interactive: too many challenge rounds".to_owned(),
    ))
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

    // -- P6.13: keyboard-interactive prompt-collection model ----------------

    /// N prompts (with echo flags preserved) map to N answers, and a
    /// mismatched-length handler response is padded/truncated rather than
    /// desyncing the exchange or panicking.
    #[test]
    fn kbd_interactive_prompts_map_to_one_answer_each() {
        let challenge = KbdInteractiveChallenge {
            name: "Two-factor".to_owned(),
            instructions: "Enter your password and code".to_owned(),
            prompts: vec![
                KbdInteractivePrompt {
                    text: "Password: ".to_owned(),
                    echo: false,
                },
                KbdInteractivePrompt {
                    text: "Verification code: ".to_owned(),
                    echo: true,
                },
            ],
        };
        assert_eq!(challenge.prompts.len(), 2);
        assert!(!challenge.prompts[0].echo, "password prompt must not echo");
        assert!(challenge.prompts[1].echo, "OTP prompt may echo");

        // Exact-length answers pass through unchanged.
        let exact = align_answers(
            challenge.prompts.len(),
            vec![
                Secret::from_string("hunter2".to_owned()),
                Secret::from_string("123456".to_owned()),
            ],
        );
        assert_eq!(exact.len(), 2);

        // A short handler response is padded with empty secrets, never panics.
        let short = align_answers(3, vec![Secret::from_string("only-one".to_owned())]);
        assert_eq!(short.len(), 3);
        assert_eq!(short[1].expose(), b"");
        assert_eq!(short[2].expose(), b"");

        // A long handler response is truncated to the expected count.
        let long = align_answers(
            1,
            vec![
                Secret::from_string("a".to_owned()),
                Secret::from_string("b".to_owned()),
            ],
        );
        assert_eq!(long.len(), 1);

        // Zero prompts (a malformed/empty challenge) map to zero answers,
        // never a panic.
        let empty = align_answers(0, vec![]);
        assert!(empty.is_empty());
    }

    #[test]
    fn ssh_auth_input_debug_never_prints_secret_material() {
        let password = SshAuthInput::Password(Secret::from_string("hunter2".to_owned()));
        assert!(!format!("{password:?}").contains("hunter2"));

        let key_material = SshAuthInput::KeyMaterial {
            key_pem: Secret::from_string("-----BEGIN OPENSSH PRIVATE KEY-----".to_owned()),
            passphrase: None,
        };
        assert!(!format!("{key_material:?}").contains("BEGIN OPENSSH"));
    }
}

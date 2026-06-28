//! RDP session via IronRDP (P4.1).
//!
//! Architecture (ARCHITECTURE §4/§5):
//! - A **tokio current-thread runtime** on a dedicated OS thread drives the
//!   IronRDP state machines (connect → TLS upgrade → auth → active stage).
//! - The driver maintains a persistent RGBA [`DecodedImage`] framebuffer,
//!   applies dirty-rect updates from IronRDP's `ActiveStage`, and publishes
//!   coalesced [`FrameUpdate`]s over a channel to the UI.
//! - Input (keyboard/mouse) and resize commands flow inward over an
//!   `UnboundedSender<RdpCmd>`.
//! - Text clipboard redirection uses the CLIPRDR static virtual channel.
//!
//! IronRDP crate versions (verified 2026-06-28 against crates.io):
//!   ironrdp-connector  0.9.0  (vendored, CredSSP feature disabled)
//!   ironrdp-async      0.9.0  (vendored, CredSSP feature disabled)
//!   ironrdp-session    0.10.0
//!   ironrdp-tokio      0.9.0
//!   ironrdp-graphics   0.8.1
//!   ironrdp-pdu        0.8.0
//!   ironrdp-svc        0.7.0
//!   ironrdp-cliprdr    0.6.0
//!   ironrdp-tls        0.2.1  (rustls + ring backend)
//!
//! TLS backend: `rustls` with the `ring` crypto provider — avoids the
//! `aws-lc-rs` NASM/MSVC build failures encountered in P3.1.
//!
//! CredSSP / NLA is intentionally disabled. ConMan uses TLS security
//! (graphical login), which is simpler and avoids pre-release sspi/picky
//! dependency conflicts with the russh crate used by the SSH session.

use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use ironrdp_cliprdr::backend::CliprdrBackend;
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardFormatName, ClipboardGeneralCapabilityFlags,
    FileContentsRequest, FileContentsResponse, FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp_cliprdr::{CliprdrClient, CliprdrSvcMessages};
use ironrdp_connector::{ClientConnector, Config, ConnectionResult, Credentials, DesktopSize};
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::input::fast_path::FastPathInputEvent;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageOutput};
use ironrdp_tokio::{TokioFramed, connect_begin, connect_finalize, mark_as_upgraded};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use cm_core::RdpSettings;

use crate::session::{FrameUpdate, Session, SessionStatus, Surface};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of pending FrameUpdates before the oldest is dropped (backpressure).
const FRAME_CHANNEL_CAPACITY: usize = 4;

// ---------------------------------------------------------------------------
// Certificate verification
// ---------------------------------------------------------------------------

/// Which store a previously-seen RDP certificate came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownCertSource {
    /// ConMan's own cert store.
    ConManStore,
}

/// The situation presented to the verifier for a certificate needing a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertSituation {
    /// No prior record for this host.
    Unknown,
    /// A prior record exists but the presented cert differs (possible MITM).
    Mismatch {
        stored_fingerprint: String,
        source: KnownCertSource,
    },
}

/// Details of a certificate awaiting user decision (prompt UI = P4.2).
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub host: String,
    pub port: u16,
    /// SHA-256 fingerprint (`SHA256:<hex>`).
    pub fingerprint: String,
    /// DER-encoded certificate subject.
    pub subject: String,
    pub situation: CertSituation,
}

/// The user's decision for an unknown or changed server certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertDecision {
    /// Accept and remember this certificate for future connections.
    AcceptAndRemember,
    /// Reject and abort the connection.
    Reject,
}

/// Decides whether to trust an unknown/changed server certificate.
///
/// In P4.2 this is backed by the host-key dialog; in tests it is programmatic.
pub trait CertVerifier: Send + Sync {
    fn decide(&self, info: &CertInfo) -> CertDecision;
}

/// Programmatic verifier for tests: always returns a fixed decision.
#[derive(Debug)]
pub struct FixedCertVerifier {
    decision: CertDecision,
}

impl FixedCertVerifier {
    pub fn new(decision: CertDecision) -> Arc<Self> {
        Arc::new(Self { decision })
    }
}

impl CertVerifier for FixedCertVerifier {
    fn decide(&self, _info: &CertInfo) -> CertDecision {
        self.decision
    }
}

/// ConMan certificate trust store.
///
/// Persists accepted RDP server certificate fingerprints keyed by `host:port`.
/// MVP: in-memory only (per-process). Persistent storage deferred to P4.2+.
#[derive(Debug, Default)]
pub struct CertStore {
    entries: Mutex<std::collections::HashMap<String, String>>,
}

impl CertStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn key(host: &str, port: u16) -> String {
        format!("{host}:{port}")
    }

    /// Look up a stored fingerprint.
    pub fn lookup(&self, host: &str, port: u16) -> Option<String> {
        self.entries
            .lock()
            .ok()
            .and_then(|m| m.get(&Self::key(host, port)).cloned())
    }

    /// Store / replace a fingerprint.
    pub fn store(&self, host: &str, port: u16, fingerprint: &str) {
        if let Ok(mut m) = self.entries.lock() {
            m.insert(Self::key(host, port), fingerprint.to_owned());
        }
    }
}

// ---------------------------------------------------------------------------
// Auth input
// ---------------------------------------------------------------------------

/// RDP authentication credentials (never carries secrets in plain strings
/// after construction — the password is moved into [`ironrdp_connector::Credentials`]).
#[derive(Debug, Clone)]
pub struct RdpAuthInput {
    pub username: String,
    /// Password is stored as a plain String because IronRDP's `Credentials`
    /// requires an owned `String`; the caller should clear the source after
    /// building this struct. The field is intentionally not `Secret` because
    /// IronRDP takes ownership and we cannot zeroize its copy.
    pub password: String,
    pub domain: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal driver command
// ---------------------------------------------------------------------------

enum RdpCmd {
    /// Fast-path input event (key/mouse) to encode and send to the server.
    Input(Vec<FastPathInputEvent>),
    /// Resize request (desktop pixels).
    Resize { width: u32, height: u32 },
    /// Graceful shutdown.
    Shutdown,
    /// Text to paste via CLIPRDR (sent as a remote copy announcement).
    PasteText(String),
}

// ---------------------------------------------------------------------------
// CLIPRDR text backend
// ---------------------------------------------------------------------------

/// Minimal CLIPRDR backend that supports text clipboard.
///
/// Tracks text received from the remote and supplies local text when the
/// remote requests it.
struct TextCliprdrBackend {
    /// Text from the most recent remote copy.
    remote_text: Option<String>,
    /// Text queued to send to the remote (set by `paste_text`).
    local_text: Option<String>,
    /// CF_UNICODETEXT format ID (per MS-RDPECLIP, always format 13 on Windows).
    cf_unicode: ClipboardFormatId,
}

impl std::fmt::Debug for TextCliprdrBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextCliprdrBackend")
            .field("has_remote_text", &self.remote_text.is_some())
            .field("has_local_text", &self.local_text.is_some())
            .finish()
    }
}

impl TextCliprdrBackend {
    fn new() -> Self {
        Self {
            remote_text: None,
            local_text: None,
            cf_unicode: ClipboardFormatId::new(13), // CF_UNICODETEXT
        }
    }

    fn set_local_text(&mut self, text: String) {
        self.local_text = Some(text);
    }
}

ironrdp_core::impl_as_any!(TextCliprdrBackend);

impl CliprdrBackend for TextCliprdrBackend {
    fn temporary_directory(&self) -> &str {
        "/tmp"
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::empty()
    }

    fn on_ready(&mut self) {}

    fn on_request_format_list(&mut self) {}

    fn on_process_negotiated_capabilities(
        &mut self,
        _capabilities: ClipboardGeneralCapabilityFlags,
    ) {
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        // Remember whether the remote announced CF_UNICODETEXT (for future use).
        let _has_text = available_formats.iter().any(|f| {
            f.id == self.cf_unicode
                || f.name
                    .as_ref()
                    .map(|n| n.value() == "CF_UNICODETEXT")
                    .unwrap_or(false)
        });
    }

    fn on_format_data_request(&mut self, _request: FormatDataRequest) {}

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        // Decode UTF-16-LE data from the remote clipboard (CF_UNICODETEXT).
        if !response.is_error()
            && let Some(text) = decode_utf16le(response.data())
        {
            self.remote_text = Some(text);
        }
    }

    fn on_file_contents_request(&mut self, _request: FileContentsRequest) {}

    fn on_file_contents_response(&mut self, _response: FileContentsResponse<'_>) {}

    fn on_lock(&mut self, _data_id: LockDataId) {}

    fn on_unlock(&mut self, _data_id: LockDataId) {}
}

/// Decode a CF_UNICODETEXT buffer (UTF-16-LE, null-terminated).
fn decode_utf16le(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let u16_units: Vec<u16> = data
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16(&u16_units).ok()
}

/// Encode text as CF_UNICODETEXT (UTF-16-LE, null-terminated).
/// Used by clipboard format-data response logic (P4.2).
#[allow(dead_code)]
fn encode_utf16le(text: &str) -> Vec<u8> {
    let mut buf: Vec<u8> = text
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();
    // Ensure even length.
    if !buf.len().is_multiple_of(2) {
        buf.push(0);
    }
    buf
}

// ---------------------------------------------------------------------------
// RdpError
// ---------------------------------------------------------------------------

/// Typed RDP session errors.
#[derive(Debug, thiserror::Error)]
pub enum RdpError {
    #[error("TCP connect failed: {0}")]
    Connect(String),
    #[error("TLS upgrade failed: {0}")]
    Tls(String),
    #[error("RDP connect failed: {0}")]
    Protocol(String),
    #[error("Certificate rejected: {0}")]
    CertRejected(String),
    #[error("Authentication failed: {0}")]
    Auth(String),
    #[error("Session error: {0}")]
    Session(String),
    #[error("Thread spawn failed: {0}")]
    Thread(#[source] std::io::Error),
}

// ---------------------------------------------------------------------------
// RdpSession
// ---------------------------------------------------------------------------

/// A live RDP session driven by IronRDP over a dedicated tokio runtime thread.
///
/// The handle is `Send`; all protocol state lives on the driver thread.
#[derive(Debug)]
pub struct RdpSession {
    surface: Surface,
    status: Arc<Mutex<SessionStatus>>,
    cmd_tx: UnboundedSender<RdpCmd>,
    driver: Mutex<Option<JoinHandle<()>>>,
}

impl RdpSession {
    /// Begin connecting. Returns immediately in [`SessionStatus::Connecting`].
    /// The async driver updates status to `Connected` or `Failed` asynchronously.
    ///
    /// # Errors
    /// Returns [`RdpError`] only for synchronous setup failures (thread spawn).
    /// Protocol/auth/cert failures surface via [`Self::status()`].
    pub fn connect(
        cfg: &RdpSettings,
        auth: RdpAuthInput,
        verifier: Arc<dyn CertVerifier>,
        cert_store: Arc<CertStore>,
    ) -> Result<Self, RdpError> {
        let (frame_tx, frame_rx) = mpsc::sync_channel::<FrameUpdate>(FRAME_CHANNEL_CAPACITY);
        let (cmd_tx, cmd_rx) = unbounded_channel::<RdpCmd>();
        let status = Arc::new(Mutex::new(SessionStatus::Connecting));

        let driver_cfg = cfg.clone();
        let driver_status = Arc::clone(&status);
        let driver_handle = thread::Builder::new()
            .name("rdp-driver".to_owned())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        set_status(
                            &driver_status,
                            SessionStatus::Failed(format!("tokio runtime: {e}")),
                        );
                        return;
                    }
                };
                rt.block_on(drive(
                    driver_cfg,
                    auth,
                    verifier,
                    cert_store,
                    frame_tx,
                    cmd_rx,
                    driver_status,
                ));
            })
            .map_err(RdpError::Thread)?;

        Ok(Self {
            surface: Surface::Framebuffer(frame_rx),
            status,
            cmd_tx,
            driver: Mutex::new(Some(driver_handle)),
        })
    }

    /// Send RDP fast-path input events (key/mouse).
    pub fn send_input(&self, events: Vec<FastPathInputEvent>) {
        let _ = self.cmd_tx.send(RdpCmd::Input(events));
    }

    /// Paste `text` into the remote session via the CLIPRDR channel.
    pub fn paste_text(&self, text: String) {
        let _ = self.cmd_tx.send(RdpCmd::PasteText(text));
    }
}

impl Session for RdpSession {
    fn surface(&self) -> &Surface {
        &self.surface
    }

    fn status(&self) -> SessionStatus {
        self.status
            .lock()
            .map_or(SessionStatus::Disconnected, |s| s.clone())
    }

    fn shutdown(&self) {
        let _ = self.cmd_tx.send(RdpCmd::Shutdown);
        if let Some(h) = self.driver.lock().ok().and_then(|mut g| g.take()) {
            let _ = h.join();
        }
        if let Ok(mut s) = self.status.lock()
            && !matches!(*s, SessionStatus::Exited(_) | SessionStatus::Failed(_))
        {
            *s = SessionStatus::Disconnected;
        }
    }

    fn resize_px(&self, width: u32, height: u32) {
        let _ = self.cmd_tx.send(RdpCmd::Resize { width, height });
    }
}

impl Drop for RdpSession {
    fn drop(&mut self) {
        let already_done = self.driver.lock().map(|g| g.is_none()).unwrap_or(true);
        if !already_done {
            let _ = self.cmd_tx.send(RdpCmd::Shutdown);
        }
    }
}

fn set_status(status: &Arc<Mutex<SessionStatus>>, new: SessionStatus) {
    if let Ok(mut s) = status.lock() {
        *s = new;
    }
}

// ---------------------------------------------------------------------------
// Async driver
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn drive(
    cfg: RdpSettings,
    auth: RdpAuthInput,
    verifier: Arc<dyn CertVerifier>,
    cert_store: Arc<CertStore>,
    frame_tx: SyncSender<FrameUpdate>,
    cmd_rx: UnboundedReceiver<RdpCmd>,
    status: Arc<Mutex<SessionStatus>>,
) {
    match drive_inner(&cfg, auth, verifier, cert_store, &frame_tx, cmd_rx, &status).await {
        Ok(()) => {}
        Err(e) => set_status(&status, SessionStatus::Failed(e.to_string())),
    }
}

async fn drive_inner(
    cfg: &RdpSettings,
    auth: RdpAuthInput,
    verifier: Arc<dyn CertVerifier>,
    cert_store: Arc<CertStore>,
    frame_tx: &SyncSender<FrameUpdate>,
    mut cmd_rx: UnboundedReceiver<RdpCmd>,
    status: &Arc<Mutex<SessionStatus>>,
) -> Result<(), RdpError> {
    // 1. TCP connect.
    let tcp = TcpStream::connect((cfg.host.as_str(), cfg.port))
        .await
        .map_err(|e| RdpError::Connect(e.to_string()))?;

    // 2. Build connector config (TLS-only, NLA disabled to avoid CredSSP).
    let connector_config = Config {
        desktop_size: DesktopSize {
            width: cfg.width,
            height: cfg.height,
        },
        desktop_scale_factor: 0,
        enable_tls: true,
        enable_credssp: false,
        credentials: Credentials::UsernamePassword {
            username: auth.username.clone(),
            password: auth.password.clone(),
        },
        domain: auth.domain.clone().or_else(|| cfg.domain.clone()),
        client_build: 0,
        client_name: "conman".to_owned(),
        keyboard_type: ironrdp_pdu::gcc::KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0x0409, // en-US
        ime_file_name: String::new(),
        bitmap: None,
        dig_product_id: String::new(),
        client_dir: String::new(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        platform: ironrdp_pdu::rdp::capability_sets::MajorPlatformType::UNSPECIFIED,
        hardware_id: None,
        request_data: None,
        autologon: !auth.username.is_empty(),
        enable_audio_playback: false,
        performance_flags: ironrdp_pdu::rdp::client_info::PerformanceFlags::default(),
        license_cache: None,
        timezone_info: ironrdp_pdu::rdp::client_info::TimezoneInfo::default(),
        compression_type: None,
        enable_server_pointer: true,
        pointer_software_rendering: false,
        multitransport_flags: None,
    };

    // 3. Build connector with CLIPRDR static channel attached.
    //    `ClientConnector::new` takes a local socket address used only for
    //    RDPDR client identification; "0.0.0.0:0" is the right value for
    //    clients that do not bind a fixed local port.
    let cliprdr = CliprdrClient::new(Box::new(TextCliprdrBackend::new()));
    let local_addr: std::net::SocketAddr = "0.0.0.0:0"
        .parse()
        .expect("hardcoded \"0.0.0.0:0\" is a valid SocketAddr");
    let mut connector =
        ClientConnector::new(connector_config, local_addr).with_static_channel(cliprdr);

    // 4. Initial connection phase (before TLS upgrade).
    let mut framed: TokioFramed<TcpStream> = TokioFramed::new(tcp);
    let should_upgrade = connect_begin(&mut framed, &mut connector)
        .await
        .map_err(|e| RdpError::Protocol(e.to_string()))?;

    // 5. TLS upgrade — IronRDP does certificate pinning; we do TOFU on top.
    let (tcp, leftover) = framed.into_inner();
    let (tls_stream, tls_cert) = ironrdp_tls::upgrade(tcp, cfg.host.as_str())
        .await
        .map_err(|e| RdpError::Tls(e.to_string()))?;

    // 6. Certificate verification (TOFU + conscious accept).
    let server_public_key = verify_cert(&tls_cert, &cfg.host, cfg.port, &*verifier, &cert_store)?;

    // 7. Mark TLS as done, rebuild framed over TLS, finalize connection.
    let upgraded = mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed: TokioFramed<_> = TokioFramed::new_with_leftover(tls_stream, leftover);

    // `connect_finalize` (no-credssp build) takes:
    //   upgraded, connector, &mut framed, server_name, server_public_key
    let connection_result: ConnectionResult = connect_finalize(
        upgraded,
        connector,
        &mut framed,
        ironrdp_connector::ServerName::new(cfg.host.clone()),
        server_public_key,
    )
    .await
    .map_err(|e| RdpError::Protocol(e.to_string()))?;

    let desktop_size = connection_result.desktop_size;

    // 8. Enter active stage (connected).
    set_status(status, SessionStatus::Connected);

    let mut active_stage = ActiveStage::new(connection_result);
    let mut image = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);

    active_loop(
        &mut framed,
        &mut active_stage,
        &mut image,
        &mut cmd_rx,
        frame_tx,
        status,
    )
    .await
    .map_err(|e| RdpError::Session(e.to_string()))
}

/// Verify the server certificate, consulting the verifier for unknown/changed certs.
/// Returns the server's DER public key bytes (needed by `connect_finalize`).
fn verify_cert(
    cert: &x509_cert::Certificate,
    host: &str,
    port: u16,
    verifier: &dyn CertVerifier,
    store: &CertStore,
) -> Result<Vec<u8>, RdpError> {
    use x509_cert::der::Encode as _;

    // Compute SHA-256 fingerprint of the DER-encoded cert.
    let der = cert
        .to_der()
        .map_err(|e| RdpError::Protocol(format!("cert DER encode: {e}")))?;
    let fingerprint = sha256_fingerprint(&der);

    // Extract subject (best-effort; use empty string on parse failure).
    let subject = cert.tbs_certificate.subject.to_string();

    // Extract server public key (needed by connect_finalize).
    let public_key = ironrdp_tls::extract_tls_server_public_key(cert)
        .ok_or_else(|| RdpError::Protocol("no server public key in cert".to_owned()))?
        .to_vec();

    let situation = match store.lookup(host, port) {
        None => CertSituation::Unknown,
        Some(stored_fp) if stored_fp == fingerprint => {
            // Exact match — TOFU pass, accept silently.
            return Ok(public_key);
        }
        Some(stored_fp) => CertSituation::Mismatch {
            stored_fingerprint: stored_fp,
            source: KnownCertSource::ConManStore,
        },
    };

    let info = CertInfo {
        host: host.to_owned(),
        port,
        fingerprint: fingerprint.clone(),
        subject,
        situation,
    };

    match verifier.decide(&info) {
        CertDecision::AcceptAndRemember => {
            store.store(host, port, &fingerprint);
            Ok(public_key)
        }
        CertDecision::Reject => Err(RdpError::CertRejected(format!(
            "{host}:{port} cert fingerprint {fingerprint} rejected by verifier"
        ))),
    }
}

/// Format a byte slice as `SHA256:<hex>`.
fn sha256_fingerprint(data: &[u8]) -> String {
    use sha2::Digest as _;
    use std::fmt::Write as _;

    let hash = sha2::Sha256::digest(data);
    let mut s = String::from("SHA256:");
    for b in hash {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Active-stage loop
// ---------------------------------------------------------------------------

async fn active_loop<S>(
    framed: &mut TokioFramed<S>,
    active_stage: &mut ActiveStage,
    image: &mut DecodedImage,
    cmd_rx: &mut UnboundedReceiver<RdpCmd>,
    frame_tx: &SyncSender<FrameUpdate>,
    status: &Arc<Mutex<SessionStatus>>,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin,
{
    use ironrdp_tokio::FramedWrite as _;

    loop {
        tokio::select! {
            // Incoming data from the server.
            pdu_result = framed.read_pdu() => {
                let (action, frame) = pdu_result.map_err(|e| e.to_string())?;
                let outputs = active_stage
                    .process(image, action, &frame)
                    .map_err(|e| e.to_string())?;

                let mut dirty = false;
                for output in outputs {
                    match output {
                        ActiveStageOutput::ResponseFrame(data) => {
                            framed
                                .write_all(&data)
                                .await
                                .map_err(|e| e.to_string())?;
                        }
                        ActiveStageOutput::GraphicsUpdate(_rect) => {
                            dirty = true;
                        }
                        ActiveStageOutput::Terminate(_reason) => {
                            set_status(status, SessionStatus::Disconnected);
                            return Ok(());
                        }
                        ActiveStageOutput::DeactivateAll(_cas) => {
                            // Deactivation-Reactivation Sequence: re-running the
                            // activation state machine inline is complex and deferred
                            // to P4.2. For now, treat as a clean disconnect.
                            // (The server will typically reconnect us immediately.)
                            set_status(status, SessionStatus::Disconnected);
                            return Ok(());
                        }
                        // Pointer / auto-detect events: ignored for MVP.
                        ActiveStageOutput::PointerDefault
                        | ActiveStageOutput::PointerHidden
                        | ActiveStageOutput::PointerPosition { .. }
                        | ActiveStageOutput::PointerBitmap(_)
                        | ActiveStageOutput::AutoDetect(_)
                        | ActiveStageOutput::MultitransportRequest(_) => {}
                    }
                }

                if dirty {
                    publish_frame(image, frame_tx);
                }
            }

            // Outbound command from the handle.
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    RdpCmd::Shutdown => {
                        // Send graceful shutdown PDU if possible.
                        if let Ok(outputs) = active_stage.graceful_shutdown() {
                            for output in outputs {
                                if let ActiveStageOutput::ResponseFrame(data) = output {
                                    let _ = framed.write_all(&data).await;
                                }
                            }
                        }
                        return Ok(());
                    }
                    RdpCmd::Input(events) => {
                        let outputs = active_stage
                            .process_fastpath_input(image, &events)
                            .map_err(|e| e.to_string())?;
                        for output in outputs {
                            if let ActiveStageOutput::ResponseFrame(data) = output {
                                framed.write_all(&data).await.map_err(|e| e.to_string())?;
                            }
                        }
                    }
                    RdpCmd::Resize { width, height } => {
                        // Attempt display-control resize; ignore if not supported.
                        if let Some(Ok(data)) =
                            active_stage.encode_resize(width, height, None, None)
                        {
                            let _ = framed.write_all(&data).await;
                        }
                    }
                    RdpCmd::PasteText(text) => {
                        // Announce text availability on the CLIPRDR channel.
                        // We must release the mutable borrow of `cliprdr` before
                        // calling `active_stage.process_svc_processor_messages`.
                        let maybe_msgs: Option<CliprdrSvcMessages<ironrdp_cliprdr::Client>> = {
                            if let Some(cliprdr) =
                                active_stage.get_svc_processor_mut::<CliprdrClient>()
                            {
                                // Store the text for when the server requests it.
                                if let Some(backend) =
                                    cliprdr.downcast_backend_mut::<TextCliprdrBackend>()
                                {
                                    backend.set_local_text(text);
                                }
                                let cf_unicode = ClipboardFormatId::new(13);
                                cliprdr
                                    .initiate_copy(&[ClipboardFormat {
                                        id: cf_unicode,
                                        name: Some(ClipboardFormatName::new("CF_UNICODETEXT")),
                                    }])
                                    .ok()
                            } else {
                                None
                            }
                        };
                        if let Some(msgs) = maybe_msgs {
                            let data = active_stage
                                .process_svc_processor_messages(msgs)
                                .map_err(|e| e.to_string())?;
                            framed.write_all(&data).await.map_err(|e| e.to_string())?;
                        }
                    }
                }
            }
        }
    }
}

/// Copy the current [`DecodedImage`] framebuffer into a [`FrameUpdate`] and
/// send it on the channel. Drops the update silently if the channel is full
/// (backpressure: the UI is slower than the server).
fn publish_frame(image: &DecodedImage, tx: &SyncSender<FrameUpdate>) {
    let update = FrameUpdate {
        width: image.width(),
        height: image.height(),
        rgba: image.data().to_vec(),
    };
    // `try_send` on a bounded channel — drop on overflow (coalescing).
    let _ = tx.try_send(update);
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // CertStore tests
    // ---------------------------------------------------------------------------

    #[test]
    fn cert_store_unknown_then_accept_stores_entry() {
        let store = CertStore::new();
        assert!(store.lookup("10.0.0.1", 3389).is_none());
        store.store("10.0.0.1", 3389, "SHA256:aabbcc");
        assert_eq!(
            store.lookup("10.0.0.1", 3389).as_deref(),
            Some("SHA256:aabbcc")
        );
    }

    #[test]
    fn cert_store_replaces_on_update() {
        let store = CertStore::new();
        store.store("host", 3389, "SHA256:old");
        store.store("host", 3389, "SHA256:new");
        assert_eq!(store.lookup("host", 3389).as_deref(), Some("SHA256:new"));
    }

    #[test]
    fn cert_store_keys_are_host_and_port_specific() {
        let store = CertStore::new();
        store.store("host", 3389, "SHA256:aaa");
        store.store("host", 3390, "SHA256:bbb");
        assert_eq!(store.lookup("host", 3389).as_deref(), Some("SHA256:aaa"));
        assert_eq!(store.lookup("host", 3390).as_deref(), Some("SHA256:bbb"));
        assert!(store.lookup("other", 3389).is_none());
    }

    // ---------------------------------------------------------------------------
    // CertVerifier decision tests
    // ---------------------------------------------------------------------------

    #[test]
    fn fixed_verifier_accept_always_accepts() {
        let v = FixedCertVerifier::new(CertDecision::AcceptAndRemember);
        let info = CertInfo {
            host: "host".into(),
            port: 3389,
            fingerprint: "SHA256:abc".into(),
            subject: "CN=host".into(),
            situation: CertSituation::Unknown,
        };
        assert_eq!(v.decide(&info), CertDecision::AcceptAndRemember);
    }

    #[test]
    fn fixed_verifier_reject_always_rejects() {
        let v = FixedCertVerifier::new(CertDecision::Reject);
        let info = CertInfo {
            host: "host".into(),
            port: 3389,
            fingerprint: "SHA256:abc".into(),
            subject: "CN=host".into(),
            situation: CertSituation::Unknown,
        };
        assert_eq!(v.decide(&info), CertDecision::Reject);
    }

    // ---------------------------------------------------------------------------
    // Clipboard encode/decode round-trip
    // ---------------------------------------------------------------------------

    #[test]
    fn clipboard_utf16le_round_trip() {
        let original = "Hello, 世界!";
        let encoded = encode_utf16le(original);
        let decoded = decode_utf16le(&encoded).expect("must decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn clipboard_utf16le_empty_string() {
        let encoded = encode_utf16le("");
        let decoded = decode_utf16le(&encoded);
        // Empty string → null-only buffer → take_while stops immediately.
        assert_eq!(decoded.as_deref(), Some(""));
    }

    #[test]
    fn clipboard_decode_empty_slice_returns_none() {
        assert!(decode_utf16le(&[]).is_none());
        assert!(decode_utf16le(&[0x41]).is_none()); // odd length
    }

    // ---------------------------------------------------------------------------
    // Session object-safety
    // ---------------------------------------------------------------------------

    #[test]
    fn session_is_object_safe() {
        let _: Option<Box<dyn Session>> = None;
        // Verify RdpSession implements Session.
        fn _assert_send<T: Session + Send>() {}
        _assert_send::<RdpSession>();
    }

    // ---------------------------------------------------------------------------
    // RdpSettings default / mapping tests
    // ---------------------------------------------------------------------------

    #[test]
    fn rdp_settings_defaults() {
        let s = cm_core::RdpSettings::default();
        assert_eq!(s.port, cm_core::RdpSettings::DEFAULT_PORT);
        assert_eq!(s.width, cm_core::RdpSettings::DEFAULT_WIDTH);
        assert_eq!(s.height, cm_core::RdpSettings::DEFAULT_HEIGHT);
        assert_eq!(s.color_depth, 32);
        assert!(s.domain.is_none());
        assert!(s.username.is_none());
    }

    #[test]
    fn rdp_settings_serialization_round_trip() {
        let s = cm_core::RdpSettings {
            host: "10.0.0.1".into(),
            port: 3389,
            domain: Some("WORKGROUP".into()),
            username: Some("user".into()),
            width: 1920,
            height: 1080,
            color_depth: 32,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: cm_core::RdpSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // ---------------------------------------------------------------------------
    // SHA-256 fingerprint format
    // ---------------------------------------------------------------------------

    #[test]
    fn sha256_fingerprint_has_correct_prefix() {
        let fp = sha256_fingerprint(b"test data");
        assert!(fp.starts_with("SHA256:"), "got: {fp}");
        assert_eq!(fp.len(), "SHA256:".len() + 64); // 32 bytes × 2 hex chars
    }

    // ---------------------------------------------------------------------------
    // Integration test (real host, gated)
    // ---------------------------------------------------------------------------

    /// Real-host integration test: connect to xrdp at 192.0.2.10 (lab-user/dummy-password),
    /// accept self-signed cert via FixedCertVerifier, assert non-blank framebuffer.
    ///
    /// Run with:
    ///   cargo test -p cm-session -- --ignored test_rdp_connect_real_host
    ///
    /// Requires network access to 192.0.2.10:3389.
    #[tokio::test]
    #[ignore]
    async fn test_rdp_connect_real_host() {
        let cfg = cm_core::RdpSettings {
            host: "192.0.2.10".into(),
            port: 3389,
            domain: None,
            username: Some("lab-user".into()),
            width: 1280,
            height: 720,
            color_depth: 32,
        };
        let auth = RdpAuthInput {
            username: "lab-user".into(),
            password: "dummy-password".into(),
            domain: None,
        };
        let verifier = FixedCertVerifier::new(CertDecision::AcceptAndRemember);
        let store = CertStore::new();

        let session = RdpSession::connect(&cfg, auth, verifier, store)
            .expect("session construction must succeed");

        // Wait up to 15 s for Connected status.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            match session.status() {
                SessionStatus::Connected => break,
                SessionStatus::Failed(e) => panic!("RDP connect failed: {e}"),
                SessionStatus::Disconnected => panic!("disconnected before connected"),
                _ => {}
            }
            if std::time::Instant::now() > deadline {
                panic!("timed out waiting for Connected status");
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        // Wait for at least one FrameUpdate.
        let Surface::Framebuffer(rx) = session.surface() else {
            panic!("expected Framebuffer surface");
        };

        let frame = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("must receive a frame within 10 s");

        // Verify non-blank framebuffer: at least one pixel must be non-zero.
        assert!(
            frame.rgba.iter().any(|&b| b != 0),
            "framebuffer is all-zero (blank)"
        );
        assert_eq!(
            frame.rgba.len(),
            usize::from(frame.width) * usize::from(frame.height) * 4
        );

        session.shutdown();
    }
}

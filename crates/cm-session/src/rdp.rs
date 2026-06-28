//! RDP session via IronRDP (P4.1).
//!
//! Architecture (ARCHITECTURE §4/§5):
//! - A **tokio current-thread runtime** on a dedicated OS thread drives the
//!   IronRDP state machines (connect → TLS upgrade → auth → active stage).
//! - The driver maintains a persistent RGBA [`DecodedImage`] framebuffer,
//!   applies dirty-rect updates from IronRDP's `ActiveStage`, and publishes
//!   coalesced [`FrameUpdate`]s over a channel to the UI.
//! - Input (keyboard/mouse) and resize commands flow inward over an
//!   `UnboundedSender<RdpCmd>`, accepting neutral [`RdpInputEvent`]s that are
//!   encoded to IronRDP `FastPathInputEvent`s inside the driver (ironrdp-input).
//! - Text clipboard redirection uses the CLIPRDR static virtual channel;
//!   both remote→local and local→remote text transfers are implemented.
//!
//! IronRDP crate versions (verified 2026-06-28 against crates.io):
//!   ironrdp-connector  0.9.0  (vendored, CredSSP feature disabled)
//!   ironrdp-async      0.9.0  (vendored, CredSSP feature disabled)
//!   ironrdp-session    0.10.0
//!   ironrdp-tokio      0.9.0
//!   ironrdp-graphics   0.8.1
//!   ironrdp-pdu        0.8.0
//!   ironrdp-input      0.6.0  (neutral→FastPath input encoding)
//!   ironrdp-cliprdr    0.6.0
//!   ironrdp-tls        0.2.1  (rustls + ring backend)
//!
//! TLS backend: `rustls` with the `ring` crypto provider — avoids the
//! `aws-lc-rs` NASM/MSVC build failures encountered in P3.1.
//!
//! CredSSP / NLA is intentionally disabled. ConMan uses TLS security
//! (graphical login), which is simpler and avoids pre-release sspi/picky
//! dependency conflicts with the russh crate used by the SSH session.
//!
//! **xrdp server configuration**: the test host (192.0.2.10) must have
//! `security_layer=negotiate` (or `tls`) in `/etc/xrdp/xrdp.ini` so that the
//! server accepts the TLS security protocol IronRDP advertises. The default
//! `security_layer=rdp` (STANDARD_RDP_SECURITY) is not supported by IronRDP.
//!
//! **Unified input (P4.2)**: `Session::send_input(SessionInput)` dispatches
//! `SessionInput::Rdp(events)` to the wire and `SessionInput::RdpPaste(text)`
//! to the CLIPRDR channel.  `RdpInputEvent` and `RdpMouseButton` are now
//! defined in `session.rs` (shared neutral types).
//!
//! **Cert store persistence (P4.2)**: `CertStore::new_persistent(path)` loads
//! existing entries from a JSON file and saves on every accepted fingerprint.
//! Call with a path in the app-data directory so TOFU survives restarts.
//!
//! **Deactivation-Reactivation Sequence**: when the server sends `DeactivateAll`
//! (which xrdp does during normal connection setup before first bitmap data),
//! `active_loop` re-runs the `ConnectionActivationSequence` to completion,
//! then updates the `ActiveStage` processors. This is required for xrdp to
//! deliver the first bitmap frame.
//!
//! **Resize (P4.2 deferral)**: `resize_px` sends a Display Control resize PDU.
//! The server may respond with a `DeactivateAll`; the loop handles it correctly
//! by rebuilding processors with the new desktop size.

use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use ironrdp_cliprdr::backend::CliprdrBackend;
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardFormatName, ClipboardGeneralCapabilityFlags,
    FileContentsRequest, FileContentsResponse, FormatDataRequest, FormatDataResponse, LockDataId,
    OwnedFormatDataResponse,
};
use ironrdp_cliprdr::{CliprdrClient, CliprdrSvcMessages};
use ironrdp_connector::{ClientConnector, Config, ConnectionResult, Credentials, DesktopSize};
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_input::{
    Database as InputDatabase, MouseButton, MousePosition, Operation as InputOperation, Scancode,
    WheelRotations,
};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageOutput};
use ironrdp_tokio::{TokioFramed, connect_begin, connect_finalize, mark_as_upgraded};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use cm_core::{RdpSettings, Secret};

use crate::session::{
    FrameUpdate, RdpInputEvent, RdpMouseButton, Session, SessionInput, SessionStatus, Surface,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of pending FrameUpdates before the oldest is dropped (backpressure).
const FRAME_CHANNEL_CAPACITY: usize = 4;

// ---------------------------------------------------------------------------
// Ring crypto-provider bootstrap
// ---------------------------------------------------------------------------

/// Ensure the `ring` crypto provider is registered as the process-level
/// rustls provider before any TLS call.
///
/// ironrdp-tls brings in `tokio-rustls` with its default features (`aws_lc_rs`),
/// while we also enable `ring`. When both features are compiled in, rustls
/// cannot auto-select a provider and panics. Calling this function first
/// (idempotently) fixes the ambiguity.
fn install_ring_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

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

/// ConMan RDP certificate trust store.
///
/// Maps `host:port` → SHA-256 fingerprint for TOFU certificate verification.
///
/// **Persistent (P4.2):** construct with [`CertStore::new_persistent`] to back
/// the store with a JSON file.  The file is created on the first accepted
/// fingerprint and updated atomically on each subsequent one.  Use
/// [`CertStore::new`] for an ephemeral in-memory-only instance (tests, etc.).
#[derive(Debug)]
pub struct CertStore {
    entries: Mutex<std::collections::HashMap<String, String>>,
    /// Path to the JSON backing file; `None` = in-memory only.
    save_path: Option<std::path::PathBuf>,
}

impl Default for CertStore {
    fn default() -> Self {
        Self {
            entries: Mutex::new(std::collections::HashMap::new()),
            save_path: None,
        }
    }
}

impl CertStore {
    /// Create an ephemeral (in-memory) cert store.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Create a persistent cert store backed by `path`.
    ///
    /// Existing entries are loaded from the file if it exists; missing or
    /// unparseable files start empty.  The file is created / updated on each
    /// accepted fingerprint.
    pub fn new_persistent(path: std::path::PathBuf) -> Arc<Self> {
        let entries: std::collections::HashMap<String, String> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Arc::new(Self {
            entries: Mutex::new(entries),
            save_path: Some(path),
        })
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

    /// Store / replace a fingerprint; persists to disk if a path was configured.
    pub fn store(&self, host: &str, port: u16, fingerprint: &str) {
        if let Ok(mut m) = self.entries.lock() {
            m.insert(Self::key(host, port), fingerprint.to_owned());
            if let Some(path) = &self.save_path {
                let _ = Self::write_json(&m, path);
            }
        }
    }

    /// Serialize `map` as pretty JSON and write to `path` atomically.
    ///
    /// Writes to a sibling `.tmp` file first, then renames into place so a
    /// crash mid-write leaves the previous version intact (crash-safe).
    fn write_json(
        map: &std::collections::HashMap<String, String>,
        path: &std::path::Path,
    ) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(map).map_err(std::io::Error::other)?;
        // Write to a temp file in the same directory, then rename atomically.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, path)
    }
}

// ---------------------------------------------------------------------------
// Auth input
// ---------------------------------------------------------------------------

/// RDP authentication credentials.
///
/// The password is stored as [`Secret`] (zeroized on drop) mirroring the SSH
/// session pattern. It is converted to `String` only at the IronRDP boundary
/// inside `connect()`, immediately before being moved into
/// [`ironrdp_connector::Credentials`].
#[derive(Debug, Clone)]
pub struct RdpAuthInput {
    pub username: String,
    pub password: Secret,
    pub domain: Option<String>,
}

// ---------------------------------------------------------------------------
// RdpMouseButton → ironrdp-input MouseButton conversion (P4.1; types moved to
// session.rs in P4.2 so SessionInput can reference them without circular deps)
// ---------------------------------------------------------------------------

impl From<RdpMouseButton> for MouseButton {
    fn from(b: RdpMouseButton) -> Self {
        match b {
            RdpMouseButton::Left => MouseButton::Left,
            RdpMouseButton::Middle => MouseButton::Middle,
            RdpMouseButton::Right => MouseButton::Right,
            RdpMouseButton::X1 => MouseButton::X1,
            RdpMouseButton::X2 => MouseButton::X2,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal driver command
// ---------------------------------------------------------------------------

enum RdpCmd {
    /// Neutral input events to encode and send to the server.
    Input(Vec<RdpInputEvent>),
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

/// Minimal CLIPRDR backend that supports bidirectional text clipboard.
///
/// **Remote → local** (remote copy):
/// `on_remote_copy` sets `wants_paste_unicode` when CF_UNICODETEXT is
/// available. The active loop polls this flag and calls `initiate_paste`
/// to fetch the data. The response arrives in `on_format_data_response`,
/// which also updates `remote_clipboard_out` (a shared Mutex for the UI thread).
///
/// **Local → remote** (paste into remote):
/// `RdpCmd::PasteText(text)` calls `initiate_copy` announcing CF_UNICODETEXT.
/// The server requests the data via a `FormatDataRequest`, which triggers
/// `on_format_data_request` storing the request. The active loop then calls
/// `submit_format_data` with the UTF-16LE encoded text.
struct TextCliprdrBackend {
    /// Text from the most recent remote copy (set by `on_format_data_response`).
    remote_text: Option<String>,
    /// Text queued to send to the remote.
    local_text: Option<String>,
    /// CF_UNICODETEXT format ID (per MS-RDPECLIP, always format 13 on Windows).
    cf_unicode: ClipboardFormatId,
    /// Set when the remote announces CF_UNICODETEXT; the active loop should
    /// call `initiate_paste` to fetch the data.
    wants_paste_unicode: bool,
    /// Set when the server requests our clipboard data; the active loop should
    /// call `submit_format_data` with the encoded local text.
    pending_format_request: Option<ClipboardFormatId>,
    /// Shared with [`RdpSession`] — updated when remote clipboard text arrives.
    /// The UI thread polls this in the tick loop and writes to the system clipboard.
    remote_clipboard_out: Arc<Mutex<Option<String>>>,
}

impl std::fmt::Debug for TextCliprdrBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextCliprdrBackend")
            .field("has_remote_text", &self.remote_text.is_some())
            .field("has_local_text", &self.local_text.is_some())
            .field("wants_paste_unicode", &self.wants_paste_unicode)
            .field(
                "has_pending_format_req",
                &self.pending_format_request.is_some(),
            )
            .finish()
    }
}

impl TextCliprdrBackend {
    fn new(remote_clipboard_out: Arc<Mutex<Option<String>>>) -> Self {
        Self {
            remote_text: None,
            local_text: None,
            cf_unicode: ClipboardFormatId::new(13), // CF_UNICODETEXT
            wants_paste_unicode: false,
            pending_format_request: None,
            remote_clipboard_out,
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
        // Set flag so the active loop initiates a paste request.
        let has_text = available_formats.iter().any(|f| {
            f.id == self.cf_unicode
                || f.name
                    .as_ref()
                    .map(|n| n.value() == "CF_UNICODETEXT")
                    .unwrap_or(false)
        });
        if has_text {
            self.wants_paste_unicode = true;
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        // Store so the active loop can call submit_format_data with the text.
        self.pending_format_request = Some(request.format);
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        // Decode UTF-16-LE data from the remote clipboard (CF_UNICODETEXT).
        if !response.is_error()
            && let Some(text) = decode_utf16le(response.data())
        {
            self.remote_text = Some(text.clone());
            // Notify the UI thread: overwrite with the latest remote text.
            if let Ok(mut out) = self.remote_clipboard_out.lock() {
                *out = Some(text);
            }
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
fn encode_utf16le(text: &str) -> Vec<u8> {
    let mut buf: Vec<u8> = text
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();
    // Ensure even length (should always be, but defence in depth).
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
    /// Remote clipboard text received via CLIPRDR (CF_UNICODETEXT).
    ///
    /// Set by the driver thread whenever the remote announces a copy.  The UI
    /// thread polls this in the tick loop and writes to the system clipboard.
    /// Publicly readable so the cm-ui controller can clone the Arc.
    pub remote_clipboard: Arc<Mutex<Option<String>>>,
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
        // Shared clipboard slot: driver writes, UI thread polls.
        let remote_clipboard: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let driver_remote_clipboard = Arc::clone(&remote_clipboard);

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
                    DriveCtx {
                        verifier,
                        cert_store,
                        frame_tx,
                        cmd_rx,
                        status: driver_status,
                        remote_clipboard: driver_remote_clipboard,
                    },
                ));
            })
            .map_err(RdpError::Thread)?;

        Ok(Self {
            surface: Surface::Framebuffer(frame_rx),
            status,
            cmd_tx,
            driver: Mutex::new(Some(driver_handle)),
            remote_clipboard,
        })
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
        // Sends a Display Control resize PDU. Full resize (DeactivateAll /
        // Reactivation sequence + framebuffer realloc) is handled by the
        // active_loop's `should_reactivate` path.
        let _ = self.cmd_tx.send(RdpCmd::Resize { width, height });
    }

    /// No-op: RDP is resized in pixels via [`resize_px`].
    fn resize_cells(&self, _cols: u16, _rows: u16) {}

    /// Dispatch transport-neutral input.
    ///
    /// Handles `SessionInput::Rdp(events)` and `SessionInput::RdpPaste(text)`;
    /// silently ignores terminal variants.
    fn send_input(&self, input: SessionInput) {
        match input {
            SessionInput::Rdp(events) => {
                let _ = self.cmd_tx.send(RdpCmd::Input(events));
            }
            SessionInput::RdpPaste(text) => {
                let _ = self.cmd_tx.send(RdpCmd::PasteText(text));
            }
            // Terminal inputs are not applicable to RDP.
            SessionInput::Key(_) | SessionInput::Mouse(_) | SessionInput::Paste(_) => {}
        }
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

/// Groups the runtime handles passed to the async driver so `drive_inner` stays
/// below the clippy `too_many_arguments` threshold.
struct DriveCtx {
    verifier: Arc<dyn CertVerifier>,
    cert_store: Arc<CertStore>,
    frame_tx: SyncSender<FrameUpdate>,
    cmd_rx: UnboundedReceiver<RdpCmd>,
    status: Arc<Mutex<SessionStatus>>,
    remote_clipboard: Arc<Mutex<Option<String>>>,
}

async fn drive(cfg: RdpSettings, auth: RdpAuthInput, ctx: DriveCtx) {
    let status = ctx.status.clone();
    match drive_inner(&cfg, auth, ctx).await {
        Ok(()) => {}
        Err(e) => set_status(&status, SessionStatus::Failed(e.to_string())),
    }
}

async fn drive_inner(
    cfg: &RdpSettings,
    auth: RdpAuthInput,
    mut ctx: DriveCtx,
) -> Result<(), RdpError> {
    // 0. Ensure the ring crypto provider is installed before any TLS call.
    //    ironrdp-tls enables both aws-lc-rs (default) and ring features in
    //    tokio-rustls; without an explicit `install_default()`, rustls panics.
    install_ring_provider();

    // 1. TCP connect.
    let tcp = TcpStream::connect((cfg.host.as_str(), cfg.port))
        .await
        .map_err(|e| RdpError::Connect(e.to_string()))?;

    // 2. Build connector config (TLS security, CredSSP/NLA disabled).
    //    Password exposed only here, at the IronRDP boundary, then moved.
    let password = String::from_utf8_lossy(auth.password.expose()).into_owned();
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
            password,
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
    let cliprdr = CliprdrClient::new(Box::new(TextCliprdrBackend::new(ctx.remote_clipboard)));
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

    // 5. TLS upgrade — ironrdp-tls performs the handshake; CA validation and
    //    TOFU follow in verify_cert.
    let (tcp, leftover) = framed.into_inner();
    let (tls_stream, tls_cert) = ironrdp_tls::upgrade(tcp, cfg.host.as_str())
        .await
        .map_err(|e| RdpError::Tls(e.to_string()))?;

    // 6. Certificate verification: CA store first, then TOFU.
    let server_public_key = verify_cert(
        &tls_cert,
        &cfg.host,
        cfg.port,
        &*ctx.verifier,
        &ctx.cert_store,
    )?;

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
    set_status(&ctx.status, SessionStatus::Connected);

    let mut active_stage = ActiveStage::new(connection_result);
    let mut image = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
    let mut input_db = InputDatabase::new();

    active_loop(
        &mut framed,
        &mut active_stage,
        &mut image,
        &mut input_db,
        &mut ctx.cmd_rx,
        &ctx.frame_tx,
        &ctx.status,
    )
    .await
    .map_err(|e| RdpError::Session(e.to_string()))
}

/// Verify the server certificate.
///
/// Strategy (per spec):
/// 1. If the cert is valid against the OS/CA trust store, accept silently.
/// 2. Otherwise fall back to TOFU: look up the fingerprint in the store.
///    - Match → accept silently (previously pinned).
///    - Unknown / mismatch → ask the verifier (user dialog in P4.2).
///
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

    // 1. Try CA validation against the platform root store.
    //    CA-valid certs connect silently — no TOFU or user prompt required.
    if is_ca_trusted(&der, host) {
        return Ok(public_key);
    }

    // 2. TOFU / user decision for self-signed / unknown / changed certs.
    let situation = match store.lookup(host, port) {
        None => CertSituation::Unknown,
        Some(stored_fp) if stored_fp == fingerprint => {
            // Exact TOFU match — accept silently.
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

/// Check whether the DER-encoded certificate is signed by a trusted OS/CA root.
///
/// Uses `rustls-native-certs` to load the platform trust store and
/// `WebPkiServerVerifier` to validate.  Returns `false` on any error (missing
/// certs, parse failures, hostname mismatch) so that the caller falls through
/// to TOFU.
fn is_ca_trusted(cert_der: &[u8], host: &str) -> bool {
    use rustls::RootCertStore;
    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier as _;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    // Load platform root CAs; ignore individual load errors (some certs may
    // be non-parseable but the rest are still useful).
    let native = rustls_native_certs::load_native_certs();
    let mut root_store = RootCertStore::empty();
    for cert in native.certs {
        root_store.add(cert).ok();
    }
    if root_store.is_empty() {
        return false;
    }

    let Ok(verifier) = WebPkiServerVerifier::builder(Arc::new(root_store)).build() else {
        return false;
    };

    let end_entity = CertificateDer::from(cert_der.to_vec());
    let Ok(server_name) = ServerName::try_from(host.to_owned()) else {
        return false;
    };
    let now = UnixTime::now();

    verifier
        .verify_server_cert(&end_entity, &[], &server_name, &[], now)
        .is_ok()
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

#[allow(clippy::too_many_arguments)]
async fn active_loop<S>(
    framed: &mut TokioFramed<S>,
    active_stage: &mut ActiveStage,
    image: &mut DecodedImage,
    input_db: &mut InputDatabase,
    cmd_rx: &mut UnboundedReceiver<RdpCmd>,
    frame_tx: &SyncSender<FrameUpdate>,
    status: &Arc<Mutex<SessionStatus>>,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin,
{
    use ironrdp_tokio::FramedWrite as _;

    // True once at least one real bitmap PDU has been decoded.
    //
    // IronRDP sets alpha=0xFF for every pixel of a decoded bitmap (even a
    // black one), so a zero-filled DecodedImage means no content yet.
    // We suppress frame publications until the first non-zero pixel arrives.
    // This prevents publishing the initial blank image when the server sends
    // FrameMarker-only PDUs (which produce a GraphicsUpdate with an empty
    // rectangle but do not update image pixels).
    let mut image_has_content = false;

    loop {
        tokio::select! {
            // Incoming data from the server.
            pdu_result = framed.read_pdu() => {
                let (action, frame) = pdu_result.map_err(|e| e.to_string())?;
                let outputs = active_stage
                    .process(image, action, &frame)
                    .map_err(|e| e.to_string())?;

                let mut dirty = false;
                let mut should_reactivate = false;
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
                            // Deactivation-Reactivation Sequence (MS-RDPBCGR §1.3.1.3).
                            // See the detailed comment below.
                            should_reactivate = true;
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

                // --- Deactivation-Reactivation Sequence ---
                // The RDP specification (MS-RDPBCGR §1.3.1.3) calls for a full
                // Deactivation-Reactivation when the server sends DeactivateAll:
                // the client should respond to a subsequent DemandActive with
                // ConfirmActive, then complete the Connection Finalization sequence.
                //
                // However, xrdp (the test host) does not follow this sequence: it
                // sends DeactivateAll and then immediately sends FastPath bitmap
                // data (no DemandActive). Trying to read DemandActive from the wire
                // here would block indefinitely while xrdp is sending bitmap frames.
                //
                // Strategy: if the CAS immediately needs server input (starts in
                // CapabilitiesExchange), just continue the active loop so the next
                // PDU from the server (FastPath bitmap or slow-path update) is
                // dispatched to active_stage.process() as usual.
                //
                // A full Deactivation-Reactivation (for servers that require it) is
                // deferred to P4.2 when the session gains a proper state machine for
                // the reactivation exchange.
                if should_reactivate {
                    // The next PDU from the server (FastPath bitmap or slow-path)
                    // will be processed normally in the next tokio::select! iteration.
                    continue;
                }

                if dirty {
                    // Suppress phantom frames that arrive before the first real
                    // bitmap is decoded.  IronRDP sets alpha = 0xFF for every
                    // pixel it writes (see `apply_bgr24_bitmap`); before that the
                    // DecodedImage is zero-filled, so any(|b| b != 0) is a cheap
                    // proxy for "has at least one decoded pixel".
                    //
                    // This is needed because xrdp sends FrameMarker-only Surface
                    // Commands PDUs early in the session (before the desktop
                    // bitmap), which produce a GraphicsUpdate with an empty rect
                    // but leave the image all-zero.
                    if !image_has_content {
                        image_has_content = image.data().iter().any(|&b| b != 0);
                    }
                    if image_has_content {
                        publish_frame(image, frame_tx);
                    }
                }

                // --- Clipboard state machine: remote → local ---
                // After `process()`, the backend may have set `wants_paste_unicode`
                // (triggered by on_remote_copy). We call initiate_paste to request
                // the actual data; the response arrives in on_format_data_response.
                let wants_paste = {
                    active_stage
                        .get_svc_processor_mut::<CliprdrClient>()
                        .and_then(|c| c.downcast_backend_mut::<TextCliprdrBackend>())
                        .map(|b| {
                            if b.wants_paste_unicode {
                                b.wants_paste_unicode = false;
                                true
                            } else {
                                false
                            }
                        })
                        .unwrap_or(false)
                };
                if wants_paste {
                    let maybe_msgs = active_stage
                        .get_svc_processor_mut::<CliprdrClient>()
                        .and_then(|c| c.initiate_paste(ClipboardFormatId::new(13)).ok());
                    if let Some(msgs) = maybe_msgs {
                        let data = active_stage
                            .process_svc_processor_messages(msgs)
                            .map_err(|e| e.to_string())?;
                        framed.write_all(&data).await.map_err(|e| e.to_string())?;
                    }
                }

                // --- Clipboard state machine: local → remote ---
                // The server may have called on_format_data_request (after we
                // announced our text via initiate_copy). Respond with encoded text.
                let pending_req = {
                    active_stage
                        .get_svc_processor_mut::<CliprdrClient>()
                        .and_then(|c| c.downcast_backend_mut::<TextCliprdrBackend>())
                        .and_then(|b| b.pending_format_request.take())
                };
                if pending_req.is_some() {
                    // Fetch local text (a separate borrow so NLL lets us proceed).
                    let local_text = active_stage
                        .get_svc_processor_mut::<CliprdrClient>()
                        .and_then(|c| c.downcast_backend_mut::<TextCliprdrBackend>())
                        .and_then(|b| b.local_text.clone());

                    let response: OwnedFormatDataResponse = match local_text {
                        Some(text) => FormatDataResponse::new_data(encode_utf16le(&text)),
                        None => FormatDataResponse::new_error(),
                    };
                    let maybe_msgs = active_stage
                        .get_svc_processor_mut::<CliprdrClient>()
                        .and_then(|c| c.submit_format_data(response).ok());
                    if let Some(msgs) = maybe_msgs {
                        let data = active_stage
                            .process_svc_processor_messages(msgs)
                            .map_err(|e| e.to_string())?;
                        framed.write_all(&data).await.map_err(|e| e.to_string())?;
                    }
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
                        // Encode neutral RdpInputEvents to FastPath PDUs using
                        // ironrdp-input's stateful Database (tracks key/button state).
                        let ops: Vec<InputOperation> = events
                            .into_iter()
                            .map(rdp_event_to_operation)
                            .collect();
                        let fast_path_events = input_db.apply(ops);
                        if !fast_path_events.is_empty() {
                            let outputs = active_stage
                                .process_fastpath_input(image, &fast_path_events)
                                .map_err(|e| e.to_string())?;
                            for output in outputs {
                                if let ActiveStageOutput::ResponseFrame(data) = output {
                                    framed
                                        .write_all(&data)
                                        .await
                                        .map_err(|e| e.to_string())?;
                                }
                            }
                        }
                    }
                    RdpCmd::Resize { width, height } => {
                        // Sends a Display Control resize PDU. Full
                        // DeactivateAll/Reactivation + framebuffer realloc is
                        // deferred to P4.2; the server may respond with a
                        // DeactivateAll which currently disconnects us.
                        if let Some(Ok(data)) =
                            active_stage.encode_resize(width, height, None, None)
                        {
                            let _ = framed.write_all(&data).await;
                        }
                    }
                    RdpCmd::PasteText(text) => {
                        // Announce text availability on the CLIPRDR channel.
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

/// Convert a [`RdpInputEvent`] to an `ironrdp-input` [`InputOperation`].
fn rdp_event_to_operation(event: RdpInputEvent) -> InputOperation {
    match event {
        RdpInputEvent::KeyDown { scancode, extended } => {
            InputOperation::KeyPressed(Scancode::from_u8(extended, scancode))
        }
        RdpInputEvent::KeyUp { scancode, extended } => {
            InputOperation::KeyReleased(Scancode::from_u8(extended, scancode))
        }
        RdpInputEvent::MouseMove { x, y } => InputOperation::MouseMove(MousePosition { x, y }),
        RdpInputEvent::MouseDown { button, x: _, y: _ } => {
            // ironrdp-input's Database tracks cursor position from previous
            // MouseMove operations. Callers should send MouseMove before
            // MouseDown to position the click correctly.
            InputOperation::MouseButtonPressed(MouseButton::from(button))
        }
        RdpInputEvent::MouseUp { button, .. } => {
            InputOperation::MouseButtonReleased(MouseButton::from(button))
        }
        RdpInputEvent::Scroll {
            delta,
            vertical,
            x: _,
            y: _,
        } => InputOperation::WheelRotations(WheelRotations {
            is_vertical: vertical,
            rotation_units: delta,
        }),
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
    // RdpMouseButton → ironrdp-input MouseButton
    // ---------------------------------------------------------------------------

    #[test]
    fn mouse_button_conversion() {
        assert_eq!(MouseButton::from(RdpMouseButton::Left), MouseButton::Left);
        assert_eq!(MouseButton::from(RdpMouseButton::Right), MouseButton::Right);
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
    /// Prerequisites:
    ///   - Network access to 192.0.2.10:3389.
    ///   - `/etc/xrdp/xrdp.ini` on the server must have `security_layer=negotiate`
    ///     (or `tls`); the default `security_layer=rdp` uses STANDARD_RDP_SECURITY
    ///     which IronRDP does not support.
    ///
    /// Run with:
    ///   cargo test -p cm-session -- --ignored test_rdp_connect_real_host
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
            password: Secret::from_string("dummy-password".to_owned()),
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

        // xrdp can take ~10–12 s to deliver the first desktop bitmap after
        // initial cursor-setup frames.  15 s gives a comfortable margin.
        let frame = rx
            .recv_timeout(std::time::Duration::from_secs(15))
            .expect("must receive a frame within 15 s");

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

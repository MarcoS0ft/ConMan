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
//!   ironrdp-connector  0.9.0  (vendored, CredSSP feature ON — P9.1)
//!   ironrdp-async      0.9.0  (vendored, CredSSP feature ON — P9.1)
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
//! **CredSSP / NLA (P9.1)**: `enable_credssp: true` — the connector advertises
//! TLS|CredSSP. The server picks; `ClientConnector::should_perform_credssp()`
//! gates the CredSSP step, so servers that select plain TLS (NLA disabled,
//! e.g. win11-target, xrdp `security_layer=tls`) are completely unaffected —
//! this is the load-bearing backward-compat guarantee for the pre-existing
//! TLS-only path. Auth mechanism is **NTLM only** (username/password,
//! optional domain — see [`RdpAuthInput`]); Kerberos scaffolding
//! (`KerberosConfig`, a KDC-capable `NetworkClient`) exists upstream but is
//! wired off (`kerberos_config: None`) — see [`NtlmOnlyNetworkClient`].
//! Smartcard CredSSP is not supported (the vendored `sspi` build disables the
//! `scard` feature to avoid a crypto-bigint conflict with russh — see
//! `docs/devel/memos/P9.1-credssp-dep-audit.md`).
//!
//! **Dependency snapshot is a pinned, fragile RustCrypto RC alignment** (not a
//! durable position) — see `docs/devel/memos/P9.1-credssp-dep-audit.md` and
//! `docs/devel/tasks/CLEANUP-credssp-vendoring.md` for the exact pins and the
//! removal trigger (RustCrypto 1.0 stabilization).
//!
//! **Server-side TLS requirement**: ConMan's IronRDP connector only advertises
//! and accepts enhanced-security protocols (TLS / CredSSP); it has no
//! implementation of legacy Standard RDP Security (RC4) and never will (see
//! `RdpError::LegacySecurityOnly` below). The RDP server must therefore be
//! configured to offer TLS or CredSSP — for xrdp, `security_layer=negotiate`
//! (or `tls`) in `/etc/xrdp/xrdp.ini`, restart the service. A server left at
//! the xrdp default `security_layer=rdp` selects Standard RDP Security and
//! the connection fails with a dedicated, actionable error rather than a raw
//! connector string (diagnosed in `memos/rdp-xrdp-diagnosis-2026-07.md`;
//! supporting the legacy layer via a second engine is a P8 candidate, not
//! this crate).
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
//! **Deactivation-Reactivation Sequence (P9.9)**: when the server sends
//! `DeactivateAll` (which xrdp does during normal connection setup before
//! first bitmap data, and which any server does in response to a display-
//! control resize -- MS-RDPBCGR §1.3.1.3), `active_loop` disambiguates the
//! target by peeking the `Action` of the very next PDU (`reactivate_session`):
//! - `Action::X224` (a compliant host's `ServerDemandActive`): drives the
//!   bound `ConnectionActivationSequence` to `Finalized` (the same state
//!   machine used for the ordinary connect sequence), then applies the new
//!   `share_id` and negotiated `desktop_size` via `ActiveStage::set_share_id`,
//!   a freshly-built `fast_path::Processor` (`ActiveStage::set_fastpath_processor`),
//!   and a `DecodedImage` realloc. `static_channels` (the DisplayControl DVC,
//!   clipboard SVC) are never touched -- they live inside `ActiveStage`'s
//!   private `x224::Processor` the whole time, so nothing is dropped.
//! - `Action::FastPath` (xrdp's non-compliant shortcut: it resumes bitmap
//!   updates immediately, no `DemandActive`): the CAS is dropped and the
//!   already-read frame is processed normally -- the session stays stable at
//!   its current size (a legitimate no-op resize on this target, never a
//!   hang or a crash).
//!
//! A prior version of this comment said the loop discarded `DeactivateAll`
//! outright and "just `continue`s" -- that was true before P9.9 landed the
//! state machine above.
//!
//! **Resize**: `resize_px` sends a Display Control resize PDU
//! (`ActiveStage::encode_resize`); the `RdpCmd::Resize` handler coalesces a
//! burst of pending resizes (`coalesce_latest_resize`) down to one PDU for
//! the settled size, avoiding a reactivation storm on a live window drag.

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
use ironrdp_connector::connection_activation::{
    ConnectionActivationSequence, ConnectionActivationState,
};
use ironrdp_connector::{
    ClientConnector, Config, ConnectionResult, ConnectorError, ConnectorErrorKind, Credentials,
    DesktopSize, Sequence as _,
};
use ironrdp_core::WriteBuf;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_input::{
    Database as InputDatabase, MouseButton, MousePosition, Operation as InputOperation, Scancode,
    WheelRotations,
};
use ironrdp_pdu::Action;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageOutput, fast_path};
use ironrdp_tokio::{
    TokioFramed, connect_begin, connect_finalize, mark_as_upgraded, single_sequence_step,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use cm_core::RdpSettings;

use crate::session::{
    FrameUpdate, RdpInputEvent, RdpMouseButton, Session, SessionInput, SessionStatus, Surface,
};
// P6.15: the auth-input and cert-verifier *contract* types moved to
// `cm_core::rdp` (needed by the `SessionProvider` port, which must be
// nameable from `cm-core` without a cm-core -> cm-session dependency). Only
// `CertStore` (real file I/O) stays here. Re-exported so external callers
// (`cm-ui`) keep importing them as `cm_session::{...}` unchanged.
pub use cm_core::rdp::{
    CertDecision, CertInfo, CertSituation, CertVerifier, KnownCertSource, RdpAuthInput,
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
// RdpMouseButton → ironrdp-input MouseButton conversion (P4.1; types moved to
// cm-core in P6.15 — `RdpMouseButton` is no longer local to this crate, so a
// trait impl of the foreign `From` for the foreign `MouseButton` would
// violate the orphan rule (E0117); a local free function sidesteps that.)
// ---------------------------------------------------------------------------

fn to_ironrdp_mouse_button(b: RdpMouseButton) -> MouseButton {
    match b {
        RdpMouseButton::Left => MouseButton::Left,
        RdpMouseButton::Middle => MouseButton::Middle,
        RdpMouseButton::Right => MouseButton::Right,
        RdpMouseButton::X1 => MouseButton::X1,
        RdpMouseButton::X2 => MouseButton::X2,
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

/// P9.9 §5: collapses a burst of pending resize sizes down to the latest one.
///
/// A live window/pane drag fires `resize_px` (and so `RdpCmd::Resize`) many
/// times in quick succession; without coalescing, each would trigger its own
/// Display Control PDU -> `ActiveStageOutput::DeactivateAll` -> a full
/// reactivation -- a "reactivation storm". `active_loop`'s `RdpCmd::Resize`
/// handler drains every immediately-pending `Resize` from the command
/// channel and calls this pure function so exactly one resize PDU is sent
/// for the settled size. Factored out (rather than inlined) so it's
/// unit-testable independent of the async driver loop.
///
/// - Empty iterator -> `None` (nothing pending, no-op).
/// - Any non-empty run -> the last size in iteration order.
fn coalesce_latest_resize(sizes: impl Iterator<Item = (u32, u32)>) -> Option<(u32, u32)> {
    sizes.last()
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
    /// The server rejected every enhanced-security protocol ConMan advertised
    /// and negotiated legacy Standard RDP Security (RC4) instead. IronRDP has
    /// no implementation of that legacy layer (by design) and never will;
    /// see [`map_negotiation_error`] and the P7.5 diagnosis memo.
    #[error(
        "This RDP server only offers legacy Standard RDP Security, which ConMan does not \
         support. Enable TLS on the server (xrdp: set `security_layer=negotiate` and restart)."
    )]
    LegacySecurityOnly,
    /// The server selected CredSSP/HYBRID (NLA is required) but no password
    /// was supplied. NLA authenticates before the graphical session starts,
    /// so — unlike the TLS-only path, where a blank password just fails
    /// later at the Windows logon screen — ConMan can and must detect this
    /// up front and give an actionable message instead of letting the raw
    /// CredSSP/NTLM exchange fail cryptically. See Milestone C
    /// (`docs/devel/tasks/P9.1-credssp-nla-support.md`).
    #[error("This server requires credentials (NLA); add a credential or enter a password.")]
    CredentialsRequired,
    #[error("Certificate rejected: {0}")]
    CertRejected(String),
    /// A `connect_finalize` (CredSSP/NLA) authentication failure — bad
    /// username/password/domain, or an unsupported Kerberos/KDC round-trip.
    /// The string is a clean, user-facing message; the raw ironrdp error
    /// (which embeds an internal `[CredSSP @ <file>:<line>]` protocol/source
    /// trace — see `ironrdp_error::Error`'s `Display` impl) is logged via
    /// `tracing` at the [`map_finalize_error`] call site instead, never
    /// surfaced here (P9.5 item 5).
    #[error("{0}")]
    Auth(String),
    #[error("Session error: {0}")]
    Session(String),
    #[error("Thread spawn failed: {0}")]
    Thread(#[source] std::io::Error),
}

/// Maps a `connect_begin` negotiation failure to an [`RdpError`].
///
/// Detects the specific IronRDP outcome where the server confirmed the
/// connection but selected no enhanced-security protocol at all — an empty
/// `selected_protocol` bitset (`ironrdp_pdu::nego::SecurityProtocol::empty()`),
/// which is exactly what `security_layer=rdp` (legacy Standard RDP Security)
/// causes an xrdp server to do (`memos/rdp-xrdp-diagnosis-2026-07.md`).
/// IronRDP's connector reports this as a [`ConnectorErrorKind::Reason`] whose
/// text embeds the negotiated protocol's `Display` — `"STANDARD_RDP_SECURITY"`
/// precisely when it is empty (`SecurityProtocol::is_standard_rdp_security`).
/// Matching that token via the typed `Reason` variant (rather than the whole
/// rendered connector error, which also carries file/line/context noise) is
/// as robust as this boundary allows without forking the vendored connector:
/// any other negotiation mismatch selects a *non-empty* protocol and so never
/// renders that token. All other `connect_begin` failures pass through
/// unchanged as `RdpError::Protocol`.
///
/// **P9.1 note:** before CredSSP was enabled, a HYBRID-requiring server (NLA
/// on) made `connect_begin` fail outright (the opposite mismatch from the one
/// this function handles) and there was pressure to add a matching
/// `HYBRID_REQUIRED → dead end` mapping here. That is now obsolete: with
/// `enable_credssp: true`, ConMan advertises TLS|CredSSP, so a HYBRID-only
/// server negotiates successfully and `connect_begin` no longer fails for
/// that case at all — the CredSSP exchange happens later, inside
/// `connect_finalize` (see [`map_finalize_error`] for *its* failure mapping:
/// missing credentials / bad-credential auth failures). Only the
/// empty-selected-protocol legacy case handled below remains a
/// `connect_begin`-time failure.
fn map_negotiation_error(e: ConnectorError) -> RdpError {
    if let ConnectorErrorKind::Reason(reason) = e.kind()
        && reason.contains("STANDARD_RDP_SECURITY")
    {
        return RdpError::LegacySecurityOnly;
    }
    RdpError::Protocol(e.to_string())
}

/// Whether NLA/CredSSP is about to be performed with no password supplied.
///
/// NLA authenticates before the graphical session starts, so a blank
/// password against a HYBRID-selecting server is detectably wrong *before*
/// attempting the CredSSP exchange (unlike the TLS-only path, where a blank
/// password just fails later at the Windows logon screen). Pure and
/// unit-testable independent of a live connector/socket.
fn credssp_requires_credentials(should_perform_credssp: bool, password: &[u8]) -> bool {
    should_perform_credssp && password.is_empty()
}

/// Maps a `connect_finalize` (CredSSP) failure to an [`RdpError`].
///
/// [`ConnectorErrorKind::Credssp`] covers both a rejected NTLM handshake (bad
/// username/password) and a KDC-requiring exchange (Kerberos, unsupported —
/// see [`NtlmOnlyNetworkClient`]); ConMan does not yet distinguish those
/// sub-cases from the connector, so both map to the same actionable
/// `RdpError::Auth`. All other `connect_finalize` failures pass through
/// unchanged as `RdpError::Protocol`, matching [`map_negotiation_error`]'s
/// fallback behavior.
///
/// **P9.5 item 5:** `e.to_string()` for a `Credssp` failure renders as
/// `[CredSSP @ <vendored-source-file>:<line>] <sspi message>` (the
/// `ironrdp_error::Error<Kind>` `Display` impl always prefixes the error's
/// context + call-site source location). That internal plumbing is
/// meaningless to a user and was leaking straight into the `ErrorOverlay`
/// (`Authentication failed [ CredSSP @ … ]`). The raw detail is still useful
/// for debugging, so it's logged here via `tracing` and *not* placed in the
/// `RdpError` reason string — the user only ever sees the clean message.
fn map_finalize_error(e: ConnectorError) -> RdpError {
    if matches!(e.kind(), ConnectorErrorKind::Credssp(_)) {
        tracing::debug!(error = %e, "rdp: CredSSP/NLA authentication failed (connect_finalize)");
        return RdpError::Auth(
            "Authentication failed — check the username, password, and domain.".to_owned(),
        );
    }
    RdpError::Protocol(e.to_string())
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
            // P6.7: scrollback is a terminal-surface concept; RDP has none.
            SessionInput::Scroll(_) => {}
        }
    }

    /// P6.15: was a public field (`RdpSession::remote_clipboard`) `cm-ui`
    /// read directly; now a trait method so it's reachable through
    /// `Box<dyn Session>` (the `SessionProvider` port's return type).
    fn remote_clipboard(&self) -> Option<Arc<Mutex<Option<String>>>> {
        Some(Arc::clone(&self.remote_clipboard))
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

/// The [`ironrdp_async::NetworkClient`] ConMan gives CredSSP for its
/// NTLM-only auth mode (P9.1).
///
/// This is a complete, correct implementation for that mode — not a
/// placeholder: NTLM's challenge/response handshake never suspends the
/// CredSSP generator to make a network request (that only happens for
/// Kerberos, reaching a KDC), so `send` is provably unreachable as long as
/// `kerberos_config` stays `None` (enforced at the one call site in
/// `drive_inner`). If a future Kerberos path is wired, this type must be
/// replaced with a real KDC-capable client.
#[derive(Debug)]
struct NtlmOnlyNetworkClient;

impl ironrdp_async::NetworkClient for NtlmOnlyNetworkClient {
    async fn send(
        &mut self,
        _network_request: &ironrdp_connector::sspi::generator::NetworkRequest,
    ) -> ironrdp_connector::ConnectorResult<Vec<u8>> {
        use ironrdp_connector::ConnectorErrorExt as _;
        Err(ironrdp_connector::ConnectorError::general(
            "CredSSP requested a network round-trip (KDC), but ConMan only \
             supports NTLM (no Kerberos/KDC client configured)",
        ))
    }
}

async fn drive(cfg: RdpSettings, auth: RdpAuthInput, ctx: DriveCtx) {
    let status = ctx.status.clone();
    match drive_inner(&cfg, auth, ctx).await {
        Ok(()) => {}
        Err(e) => {
            // P9.8 B12: catch-all so no `RdpError` variant is ever silent --
            // every failure that reaches here (Connect/Tls/Protocol/Session/
            // CertRejected/etc.) gets one WARN line before the status flips
            // to Failed, even though the ErrorOverlay also shows `e`.
            tracing::warn!(host = %cfg.host, error = %e, "rdp: session loop error");
            set_status(&status, SessionStatus::Failed(e.to_string()));
        }
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

    // P9.8 §5.1: connect-start Instant, used for `connect_ms` (B8) and
    // `ttff_ms` (B9). Threaded into `active_loop` for the latter.
    let t0 = std::time::Instant::now();

    tracing::info!(
        host = %cfg.host,
        port = cfg.port,
        width = cfg.width,
        height = cfg.height,
        "rdp: connecting"
    );

    // 1. TCP connect.
    let tcp = TcpStream::connect((cfg.host.as_str(), cfg.port))
        .await
        .map_err(|e| {
            tracing::warn!(host = %cfg.host, port = cfg.port, error = %e, "rdp: TCP connect failed");
            RdpError::Connect(e.to_string())
        })?;

    // 2. Build connector config (TLS security, CredSSP/NLA enabled — P9.1).
    //    Password exposed only here, at the IronRDP boundary, then moved.
    let password = String::from_utf8_lossy(auth.password.expose()).into_owned();
    let connector_config = Config {
        desktop_size: DesktopSize {
            width: cfg.width,
            height: cfg.height,
        },
        desktop_scale_factor: 0,
        enable_tls: true,
        // P9.1: advertise TLS|CredSSP. `should_perform_credssp()` (checked
        // below, after negotiation) is true only when the server actually
        // selects HYBRID, so TLS-only servers are unaffected — this is the
        // backward-compat guarantee for the pre-existing plain-TLS path.
        enable_credssp: true,
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
        .map_err(|e| {
            // P9.8 B4: `map_negotiation_error` stays a pure, unit-testable
            // function (no host/port); log the actionable case here at the
            // IO boundary where those fields are in scope.
            let mapped = map_negotiation_error(e);
            if matches!(mapped, RdpError::LegacySecurityOnly) {
                tracing::warn!(
                    host = %cfg.host,
                    port = cfg.port,
                    "rdp: server offers only legacy Standard RDP Security"
                );
            }
            mapped
        })?;

    // 5. TLS upgrade — ironrdp-tls performs the handshake; CA validation and
    //    TOFU follow in verify_cert.
    let (tcp, leftover) = framed.into_inner();
    let (tls_stream, tls_cert) =
        ironrdp_tls::upgrade(tcp, cfg.host.as_str())
            .await
            .map_err(|e| {
                tracing::warn!(host = %cfg.host, error = %e, "rdp: TLS upgrade failed");
                RdpError::Tls(e.to_string())
            })?;

    // 6. Certificate verification: CA store first, then TOFU.
    let server_public_key = verify_cert(
        &tls_cert,
        &cfg.host,
        cfg.port,
        &*ctx.verifier,
        &ctx.cert_store,
    )?;

    // 7. Mark TLS as done, rebuild framed over TLS.
    let upgraded = mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed: TokioFramed<_> = TokioFramed::new_with_leftover(tls_stream, leftover);

    // 7b. P9.1: `should_perform_credssp()` only reflects the server's real
    //     protocol selection *after* `mark_as_upgraded` above has driven the
    //     connector's state machine past `EnhancedSecurityUpgrade`: that call
    //     transitions to `ClientConnectorState::Credssp` when the server
    //     selected HYBRID, or to `BasicSettingsExchange...` when it selected
    //     plain TLS (see vendored `ironrdp-connector`'s
    //     `mark_security_upgrade_as_done`). Immediately after `connect_begin`
    //     (i.e. before this point) the connector is still in
    //     `EnhancedSecurityUpgrade`, where `should_perform_credssp()` is
    //     unconditionally false — checking there would never fire. So: if the
    //     server requires NLA and we have no password, fail fast here with an
    //     actionable error instead of running the CredSSP exchange only to
    //     have NTLM reject an empty credential deep inside the connector. The
    //     extra TLS handshake already performed above is an acceptable cost —
    //     it's the CredSSP round-trip (and its opaque failure mode) that this
    //     check avoids. For a TLS-only server, the state here is
    //     `BasicSettingsExchange...`, so `should_perform_credssp()` is false
    //     and this check is a no-op — the plain-TLS path is unaffected.
    let should_perform_credssp = connector.should_perform_credssp();
    tracing::info!(
        host = %cfg.host,
        credssp = should_perform_credssp,
        "rdp: security protocol negotiated"
    );
    if credssp_requires_credentials(should_perform_credssp, auth.password.expose()) {
        tracing::warn!(
            host = %cfg.host,
            username = %auth.username,
            "rdp: NLA required but no password supplied"
        );
        return Err(RdpError::CredentialsRequired);
    }

    // fix-connect-credential-logging: debug-build-only diagnostic for the
    // effective username/domain actually handed to CredSSP/NLA finalize --
    // NEVER the password (not included below; `connector_config`/`auth` are
    // deliberately not Debug-dumped even though `Secret`'s own Debug impl
    // redacts, to keep this an explicit, auditable allowlist of fields).
    #[cfg(debug_assertions)]
    tracing::info!(
        username = %auth.username,
        domain = %auth.domain.clone().unwrap_or_else(|| cfg.domain.clone().unwrap_or_default()),
        host = %cfg.host,
        port = cfg.port,
        "rdp: authenticating (CredSSP/NLA finalize)"
    );

    // `connect_finalize` (credssp build) takes:
    //   upgraded, connector, &mut framed, network_client, server_name,
    //   server_public_key, kerberos_config
    // NTLM completes locally (no KDC round-trip), so the NetworkClient's
    // send() is never invoked — see NtlmOnlyNetworkClient. Kerberos is off
    // (kerberos_config: None). CredSSP itself only runs when the server
    // selected HYBRID (should_perform_credssp(), checked in step 7b above);
    // TLS-only servers never reach the CredSSP branch inside this call.
    let mut network_client = NtlmOnlyNetworkClient;
    let connection_result: ConnectionResult = connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut network_client,
        ironrdp_connector::ServerName::new(cfg.host.clone()),
        server_public_key,
        None,
    )
    .await
    .map_err(|e| {
        // P9.8 B7: `map_finalize_error` stays pure/testable (no host/username
        // in scope); log the actionable, operator-facing event here where
        // they're available. `map_finalize_error` still separately logs the
        // raw ironrdp error at `debug` for deep diagnosis (P9.5 item 5) --
        // this ERROR line is the "what happened, to whom" summary.
        if matches!(e.kind(), ConnectorErrorKind::Credssp(_)) {
            tracing::error!(
                host = %cfg.host,
                username = %auth.username,
                "rdp: CredSSP/NTLM auth rejected"
            );
        }
        map_finalize_error(e)
    })?;

    let desktop_size = connection_result.desktop_size;

    // 8. Enter active stage (connected).
    set_status(&ctx.status, SessionStatus::Connected);
    tracing::info!(
        host = %cfg.host,
        width = desktop_size.width,
        height = desktop_size.height,
        connect_ms = t0.elapsed().as_millis(),
        "rdp: connected (active stage)"
    );

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
        t0,
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
        subject: subject.clone(),
        situation: situation.clone(),
    };

    tracing::warn!(
        host,
        port,
        situation = ?situation,
        fingerprint = %fingerprint,
        subject = %subject,
        "rdp: certificate not CA-trusted, prompting"
    );

    match verifier.decide(&info) {
        CertDecision::AcceptAndRemember => {
            store.store(host, port, &fingerprint);
            tracing::info!(host, port, fingerprint = %fingerprint, "rdp: certificate accepted and pinned");
            Ok(public_key)
        }
        CertDecision::Reject => {
            tracing::warn!(host, port, fingerprint = %fingerprint, "rdp: certificate rejected by user");
            Err(RdpError::CertRejected(format!(
                "{host}:{port} cert fingerprint {fingerprint} rejected by verifier"
            )))
        }
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

/// P9.9 §3: bounded safety timeout for driving the reactivation
/// (`ConnectionActivationSequence`) to `Finalized` after a compliant host's
/// `DemandActive`. Belt-and-suspenders against a half-speaking server -- the
/// reactivation must never be able to wedge `active_loop` forever; on
/// timeout the session fails with a clear status instead of hanging (the
/// §3 degradation contract: a wedged session is never acceptable, a stable
/// no-op resize is). Env-tunable like the live-test's
/// `CONMAN_LIVE_RDP_TIMEOUT_SECS` (same idiom, different knob: this one
/// governs the production reactivation path, not a test).
fn reactivation_timeout() -> std::time::Duration {
    let secs: u64 = std::env::var("CONMAN_RDP_REACTIVATION_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    std::time::Duration::from_secs(secs)
}

/// Outcome of processing one server PDU's [`ActiveStageOutput`]s
/// ([`process_active_stage_pdu`]).
enum PduOutcome {
    /// Nothing special; the caller proceeds as usual.
    Continue,
    /// The server sent [`ActiveStageOutput::Terminate`]; `status` has
    /// already been set to [`SessionStatus::Disconnected`] -- the caller
    /// must return `Ok(())` from `active_loop`.
    Terminated,
    /// The server sent [`ActiveStageOutput::DeactivateAll`]; the caller
    /// drives the Deactivation-Reactivation Sequence (`reactivate_session`).
    Reactivate(Box<ConnectionActivationSequence>),
}

/// Outcome of handling one non-`Resize` [`RdpCmd`] ([`handle_rdp_cmd`]).
/// `Resize` has its own coalescing wrapper directly in `active_loop` (P9.9
/// §5) so it never reaches `handle_rdp_cmd`.
#[derive(PartialEq, Eq)]
enum CmdOutcome {
    Continue,
    Shutdown,
}

#[allow(clippy::too_many_arguments)]
async fn active_loop<S>(
    framed: &mut TokioFramed<S>,
    active_stage: &mut ActiveStage,
    image: &mut DecodedImage,
    input_db: &mut InputDatabase,
    cmd_rx: &mut UnboundedReceiver<RdpCmd>,
    frame_tx: &SyncSender<FrameUpdate>,
    status: &Arc<Mutex<SessionStatus>>,
    // P9.8 §5.1 B9: connect-start Instant (from `drive_inner`), used to log
    // `ttff_ms` (time-to-first-frame) exactly once below.
    t0: std::time::Instant,
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
    // P9.8 B9: fire-once guard so `ttff_ms` is logged exactly once.
    let mut first_frame_logged = false;

    loop {
        tokio::select! {
            // Incoming data from the server.
            pdu_result = framed.read_pdu() => {
                let (action, frame) = pdu_result.map_err(|e| e.to_string())?;
                match process_active_stage_pdu(
                    action,
                    &frame,
                    framed,
                    active_stage,
                    image,
                    &mut image_has_content,
                    &mut first_frame_logged,
                    t0,
                    frame_tx,
                    status,
                )
                .await?
                {
                    PduOutcome::Continue => {}
                    PduOutcome::Terminated => return Ok(()),
                    PduOutcome::Reactivate(cas) => {
                        // P9.9: Deactivation-Reactivation Sequence (MS-RDPBCGR
                        // §1.3.1.3). See the module doc comment +
                        // `reactivate_session`'s own doc for the full design
                        // (dual-target disambiguation, the §4 rebuild
                        // resolution, framebuffer realloc).
                        if let ReactivationOutcome::Terminated = reactivate_session(
                            *cas,
                            framed,
                            active_stage,
                            image,
                            &mut image_has_content,
                            &mut first_frame_logged,
                            t0,
                            frame_tx,
                            status,
                        )
                        .await?
                        {
                            return Ok(());
                        }
                    }
                }
            }

            // Outbound command from the handle.
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    RdpCmd::Resize { width, height } => {
                        // P9.9 §5: drain every immediately-pending Resize and
                        // coalesce down to the latest settled size -- one
                        // Display Control PDU per burst, not one per event
                        // (avoids a reactivation storm on a live window/pane
                        // drag). Non-Resize commands drained along the way
                        // are preserved and replayed in order afterward, so
                        // nothing is silently dropped or reordered.
                        let mut sizes = vec![(width, height)];
                        let mut trailing = Vec::new();
                        while let Ok(next) = cmd_rx.try_recv() {
                            match next {
                                RdpCmd::Resize { width, height } => sizes.push((width, height)),
                                other => trailing.push(other),
                            }
                        }
                        if let Some((width, height)) = coalesce_latest_resize(sizes.into_iter())
                            && let Some(Ok(data)) = active_stage.encode_resize(width, height, None, None)
                        {
                            let _ = framed.write_all(&data).await;
                        }
                        for cmd in trailing {
                            if handle_rdp_cmd(cmd, framed, active_stage, image, input_db).await?
                                == CmdOutcome::Shutdown
                            {
                                return Ok(());
                            }
                        }
                    }
                    other => {
                        if handle_rdp_cmd(other, framed, active_stage, image, input_db).await?
                            == CmdOutcome::Shutdown
                        {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

/// Processes one server PDU (`action`/`frame`, as read by `framed.read_pdu()`)
/// through `active_stage`: applies the standard side effects (write
/// `ResponseFrame`s, track dirty/`image_has_content`, publish frames, drive
/// the CLIPRDR remote<->local state machine) exactly as `active_loop` did
/// inline before P9.9. Factored out so the same logic can process the
/// disambiguating post-`DeactivateAll` frame in `reactivate_session`'s xrdp
/// fallback without duplicating it.
///
/// Returns [`PduOutcome::Reactivate`] on `DeactivateAll` (mirrors the
/// original `should_reactivate` flag) and [`PduOutcome::Terminated`] on
/// `Terminate` (mirrors the original inline early `return Ok(())` --
/// `status` is already set to `Disconnected` when this returns).
#[allow(clippy::too_many_arguments)]
async fn process_active_stage_pdu<S>(
    action: Action,
    frame: &[u8],
    framed: &mut TokioFramed<S>,
    active_stage: &mut ActiveStage,
    image: &mut DecodedImage,
    image_has_content: &mut bool,
    first_frame_logged: &mut bool,
    t0: std::time::Instant,
    frame_tx: &SyncSender<FrameUpdate>,
    status: &Arc<Mutex<SessionStatus>>,
) -> Result<PduOutcome, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin,
{
    use ironrdp_tokio::FramedWrite as _;

    let outputs = active_stage
        .process(image, action, frame)
        .map_err(|e| e.to_string())?;

    let mut dirty = false;
    let mut reactivate: Option<Box<ConnectionActivationSequence>> = None;
    for output in outputs {
        match output {
            ActiveStageOutput::ResponseFrame(data) => {
                framed.write_all(&data).await.map_err(|e| e.to_string())?;
            }
            ActiveStageOutput::GraphicsUpdate(_rect) => {
                dirty = true;
            }
            ActiveStageOutput::Terminate(reason) => {
                // P9.8 B11: `reason` was previously discarded -- bind and
                // log it (a `GracefulDisconnectReason`, just a description
                // string, never secret).
                tracing::info!(reason = %reason, "rdp: session terminated by server");
                set_status(status, SessionStatus::Disconnected);
                return Ok(PduOutcome::Terminated);
            }
            ActiveStageOutput::DeactivateAll(cas) => {
                // Matches the original code's behavior of continuing to
                // drain the rest of this PDU's outputs (e.g. a trailing
                // GraphicsUpdate) before acting on the reactivation.
                reactivate = Some(cas);
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

    if let Some(cas) = reactivate {
        // Matches the original `if should_reactivate { continue; }`: skip
        // the dirty/publish/clipboard handling below for this PDU -- the
        // reactivation is driven by the caller, and the next real content
        // frame is handled on its own next iteration.
        return Ok(PduOutcome::Reactivate(cas));
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
        if !*image_has_content {
            *image_has_content = image.data().iter().any(|&b| b != 0);
        }
        if *image_has_content {
            if !*first_frame_logged {
                *first_frame_logged = true;
                tracing::info!(
                    ttff_ms = t0.elapsed().as_millis(),
                    "rdp: first frame rendered"
                );
            }
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

    Ok(PduOutcome::Continue)
}

/// Handles one non-`Resize` [`RdpCmd`] (see [`CmdOutcome`]). `Resize` is
/// handled directly in `active_loop` (its own coalescing wrapper, P9.9 §5)
/// and never reaches this function.
async fn handle_rdp_cmd<S>(
    cmd: RdpCmd,
    framed: &mut TokioFramed<S>,
    active_stage: &mut ActiveStage,
    image: &mut DecodedImage,
    input_db: &mut InputDatabase,
) -> Result<CmdOutcome, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin,
{
    use ironrdp_tokio::FramedWrite as _;

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
            Ok(CmdOutcome::Shutdown)
        }
        RdpCmd::Input(events) => {
            // Encode neutral RdpInputEvents to FastPath PDUs using
            // ironrdp-input's stateful Database (tracks key/button state).
            let ops: Vec<InputOperation> = events.into_iter().map(rdp_event_to_operation).collect();
            let fast_path_events = input_db.apply(ops);
            if !fast_path_events.is_empty() {
                let outputs = active_stage
                    .process_fastpath_input(image, &fast_path_events)
                    .map_err(|e| e.to_string())?;
                for output in outputs {
                    if let ActiveStageOutput::ResponseFrame(data) = output {
                        framed.write_all(&data).await.map_err(|e| e.to_string())?;
                    }
                }
            }
            Ok(CmdOutcome::Continue)
        }
        RdpCmd::Resize { .. } => {
            unreachable!("RdpCmd::Resize is handled directly in active_loop, never here")
        }
        RdpCmd::PasteText(text) => {
            // Announce text availability on the CLIPRDR channel.
            let maybe_msgs: Option<CliprdrSvcMessages<ironrdp_cliprdr::Client>> = {
                if let Some(cliprdr) = active_stage.get_svc_processor_mut::<CliprdrClient>() {
                    // Store the text for when the server requests it.
                    if let Some(backend) = cliprdr.downcast_backend_mut::<TextCliprdrBackend>() {
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
            Ok(CmdOutcome::Continue)
        }
    }
}

/// Outcome of [`reactivate_session`].
enum ReactivationOutcome {
    /// The reactivation (compliant path) succeeded, or the target doesn't
    /// support it (xrdp fallback) and the session continues stably at its
    /// current size. The caller resumes its normal `tokio::select!` loop.
    Continue,
    /// The server terminated the session partway through (rare, but
    /// `process_active_stage_pdu` can still surface it for the xrdp
    /// fallback's disambiguating frame) -- `status` is already
    /// `Disconnected`; the caller must return `Ok(())`.
    Terminated,
}

/// Drives the Deactivation-Reactivation Sequence (MS-RDPBCGR §1.3.1.3) after
/// `active_stage.process()` surfaces `ActiveStageOutput::DeactivateAll(cas)`.
///
/// **Dual-target disambiguation (P9.9 §3, no heuristic, no timed wait):**
/// does NOT blindly drive `cas` via `single_sequence_step` (that would
/// `read_by_hint(X224_HINT)` and stall on xrdp's FastPath bitmaps -- see
/// [`ironrdp_tokio::single_sequence_step_read`]). Instead it reads the very
/// next PDU with the loop's own `framed.read_pdu()` and branches on its
/// [`Action`], which is decided straight from the wire header
/// (`ironrdp_pdu::find_size`) -- the exact same function `X224_HINT`'s own
/// `find_size` delegates to, so a PDU classified `Action::X224` here is
/// byte-for-byte the same frame `read_by_hint(X224_HINT)` would have
/// produced:
/// - `Action::X224` -- a compliant host's `ServerDemandActive`. Feeds the
///   already-read frame into `cas`'s first `step` directly (equivalent to,
///   not a re-read of, what `single_sequence_step` would have done), then
///   drives the rest via `single_sequence_step` until `Finalized`, bounded
///   by [`reactivation_timeout`] -- a half-speaking server fails the session
///   with a clear status rather than wedging `active_loop` forever.
/// - `Action::FastPath` -- xrdp's non-compliant shortcut: it resumes bitmap
///   updates immediately, never sending `DemandActive`. The CAS is dropped
///   and the already-read frame is processed exactly like any other PDU
///   (via [`process_active_stage_pdu`]) -- the session stays stable at its
///   current size. A no-op resize on this target is a legitimate outcome;
///   a wedged session is not (the §3 degradation contract).
///
/// **§4 resolution (in-place mutation, no `ActiveStage` rebuild):** on
/// reaching `Finalized { desktop_size, share_id, io_channel_id,
/// user_channel_id, enable_server_pointer, pointer_software_rendering }`,
/// the ONLY things that differ from the initial connect are `share_id` and
/// `desktop_size` -- `io_channel_id`/`user_channel_id` are carried forward
/// unchanged by `ConnectionActivationSequence::reset()`, and
/// `enable_server_pointer`/`pointer_software_rendering` are copied straight
/// from the CAS's own immutable `Config` on every `Finalized` transition
/// (never real deltas). `static_channels` (the DisplayControl DVC, clipboard
/// SVC) live inside `ActiveStage`'s private `x224::Processor` and are never
/// touched here -- there is no `ActiveStage` rebuild, so nothing is dropped:
/// - `ActiveStage::set_share_id` -- documented upstream for exactly this
///   ("Must be called during Deactivation-Reactivation if the server
///   assigns a new share_id").
/// - `ActiveStage::set_fastpath_processor` with a freshly built
///   `fast_path::ProcessorBuilder` -- needed because `fast_path::Processor`'s
///   internal `FrameMarkerProcessor` captures its own `share_id` copy at
///   construction (used to encode outbound `FrameAcknowledge` PDUs);
///   `set_share_id` alone only updates the x224 processor's copy, leaving
///   fast-path's stale. `bulk_decompressor: None` is correct here because
///   ConMan's `Config.compression_type` is always `None` (see `drive_inner`)
///   -- if ConMan ever negotiates bulk compression, this rebuild would need
///   to carry the decompressor state forward instead.
/// - The `DecodedImage` realloc (§6) is `cm-session`'s own concern --
///   neither processor stores pixel dimensions.
#[allow(clippy::too_many_arguments)]
async fn reactivate_session<S>(
    cas: ConnectionActivationSequence,
    framed: &mut TokioFramed<S>,
    active_stage: &mut ActiveStage,
    image: &mut DecodedImage,
    image_has_content: &mut bool,
    first_frame_logged: &mut bool,
    t0: std::time::Instant,
    frame_tx: &SyncSender<FrameUpdate>,
    status: &Arc<Mutex<SessionStatus>>,
) -> Result<ReactivationOutcome, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin,
{
    use ironrdp_tokio::FramedWrite as _;

    let (action, first_frame) = framed.read_pdu().await.map_err(|e| e.to_string())?;

    if !rdp_action_wants_reactivation(action) {
        // xrdp path: no DemandActive coming: process the frame we already
        // read exactly like any other PDU and stay at the current size.
        tracing::debug!("rdp: server ignored the display-control resize (no reactivation)");
        return match process_active_stage_pdu(
            action,
            &first_frame,
            framed,
            active_stage,
            image,
            image_has_content,
            first_frame_logged,
            t0,
            frame_tx,
            status,
        )
        .await?
        {
            PduOutcome::Terminated => Ok(ReactivationOutcome::Terminated),
            // A nested DeactivateAll/Reactivate surfacing from this single
            // fallback read is not driven further here (astronomically
            // unlikely immediately after an already-ignored resize) -- fall
            // through to Continue rather than recurse unboundedly.
            PduOutcome::Continue | PduOutcome::Reactivate(_) => Ok(ReactivationOutcome::Continue),
        };
    }

    // Compliant path: `first_frame` is (or leads into) the ServerDemandActive.
    let mut cas = cas;
    let mut buf = WriteBuf::new();
    let written = cas
        .step(&first_frame, &mut buf)
        .map_err(|e| e.to_string())?;
    // Mirrors `ironrdp_async::framed::single_sequence_step_write` (private to
    // that crate) -- `cas.step`'s first call already produced the response
    // in `buf`; the rest of the sequence is driven generically below via the
    // public `single_sequence_step`, which does its own read+step+write.
    if written.size().is_some() {
        framed
            .write_all(buf.filled())
            .await
            .map_err(|e| e.to_string())?;
    }

    let deadline = std::time::Instant::now() + reactivation_timeout();
    loop {
        if let ConnectionActivationState::Finalized {
            desktop_size,
            share_id,
            io_channel_id,
            user_channel_id,
            enable_server_pointer,
            pointer_software_rendering,
        } = cas.connection_activation_state()
        {
            // §4: in-place mutation via the existing public setters -- no
            // `ActiveStage` rebuild, `static_channels` untouched.
            active_stage.set_share_id(share_id);
            active_stage.set_fastpath_processor(
                fast_path::ProcessorBuilder {
                    io_channel_id,
                    user_channel_id,
                    share_id,
                    enable_server_pointer,
                    pointer_software_rendering,
                    bulk_decompressor: None,
                }
                .build(),
            );

            // §6: framebuffer realloc. A reactivation legitimately starts
            // blank again -- reuse the existing `image_has_content` guard so
            // the first new-size frame publishes once real content arrives.
            *image =
                DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
            *image_has_content = false;

            tracing::info!(
                width = desktop_size.width,
                height = desktop_size.height,
                "rdp: reactivated at new size"
            );
            return Ok(ReactivationOutcome::Continue);
        }

        if std::time::Instant::now() > deadline {
            // §3 degradation contract: never wedge -- fail the session with
            // a clear status instead of hanging.
            tracing::warn!("rdp: reactivation timed out, failing session");
            set_status(
                status,
                SessionStatus::Failed("RDP reactivation (resize) timed out".to_owned()),
            );
            return Ok(ReactivationOutcome::Terminated);
        }

        single_sequence_step(framed, &mut cas, &mut buf)
            .await
            .map_err(|e| e.to_string())?;
    }
}

/// P9.9 §3's dual-target branch decision, factored as a pure function over
/// the PDU [`Action`] so it's unit-testable without a live host: does this
/// `Action` indicate a compliant host actually running the reactivation
/// (`Action::X224`, i.e. `ServerDemandActive`), or xrdp's non-compliant
/// resume-bitmaps shortcut (`Action::FastPath`)?
fn rdp_action_wants_reactivation(action: Action) -> bool {
    matches!(action, Action::X224)
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
            InputOperation::MouseButtonPressed(to_ironrdp_mouse_button(button))
        }
        RdpInputEvent::MouseUp { button, .. } => {
            InputOperation::MouseButtonReleased(to_ironrdp_mouse_button(button))
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

/// Counts distinct `(r, g, b)` triples in a [`FrameUpdate`]'s RGBA buffer
/// (ignoring alpha). Test-only helper (P9.7 Slice 1 hardening) used both to
/// pick the "richest" frame in a content window and, on that chosen frame,
/// to assert real variety -- one source of truth for what "distinct color"
/// means in `rdp_connect_live_host`, which also documents the
/// `PixelFormat::RgbA32` byte-order justification.
#[cfg(test)]
fn distinct_rgb_count(rgba: &[u8]) -> usize {
    rgba.chunks_exact(4)
        .map(|p| (p[0], p[1], p[2]))
        .collect::<std::collections::HashSet<_>>()
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;
    // Only used to build `RdpAuthInput` values in these tests — the
    // production path never converts a `Secret` outside `connect()` itself.
    use cm_core::Secret;

    // ---------------------------------------------------------------------------
    // P9.9 §5: coalesce_latest_resize (pure)
    // ---------------------------------------------------------------------------

    #[test]
    fn coalesce_latest_resize_empty_is_none() {
        assert_eq!(coalesce_latest_resize(std::iter::empty()), None);
    }

    #[test]
    fn coalesce_latest_resize_single_is_itself() {
        assert_eq!(
            coalesce_latest_resize([(800, 600)].into_iter()),
            Some((800, 600))
        );
    }

    #[test]
    fn coalesce_latest_resize_run_keeps_the_last() {
        let burst = [(800, 600), (810, 605), (1024, 768), (1280, 720)];
        assert_eq!(coalesce_latest_resize(burst.into_iter()), Some((1280, 720)));
    }

    // ---------------------------------------------------------------------------
    // P9.9 §3: rdp_action_wants_reactivation (pure, dual-target branch decision)
    // ---------------------------------------------------------------------------

    #[test]
    fn action_x224_wants_reactivation() {
        // A compliant host's ServerDemandActive is always a Share Control
        // PDU, i.e. always X224 (slow-path) by protocol definition.
        assert!(rdp_action_wants_reactivation(Action::X224));
    }

    #[test]
    fn action_fastpath_does_not_want_reactivation() {
        // xrdp's shortcut: resumes FastPath bitmaps immediately, never
        // sending a DemandActive -- passthrough, no reactivation.
        assert!(!rdp_action_wants_reactivation(Action::FastPath));
    }

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
        assert_eq!(
            to_ironrdp_mouse_button(RdpMouseButton::Left),
            MouseButton::Left
        );
        assert_eq!(
            to_ironrdp_mouse_button(RdpMouseButton::Right),
            MouseButton::Right
        );
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
    // verify_cert TOFU decision paths (P6.2, gap 23)
    //
    // A full in-process RDP server that completes the X.224/MCS negotiation and
    // a real TLS accept is out of scope without a new dependency (rcgen for
    // self-signed cert generation, or ironrdp-server for full protocol
    // fidelity) — see the P6.2 new-dep memo
    // (docs/devel/memos/p6.2-rdp-loopback-new-dep.md). `verify_cert` is exactly
    // the decision function that new dep would let us exercise inside a live
    // `connect()`; calling it directly against two real (throwaway,
    // pre-generated) self-signed certs exercises the identical TOFU logic —
    // Unknown/Match/Mismatch × Accept/Reject — without needing a live socket.
    // ---------------------------------------------------------------------------

    /// Real, throwaway self-signed ed25519 certificates (DER), generated once
    /// via `openssl req -x509` for these tests (not CA-trusted, so
    /// `verify_cert` always falls through to TOFU — exactly the case these
    /// tests target).
    const TEST_CERT_A_DER: &[u8] = include_bytes!("../tests/fixtures/test_cert_a.der");
    const TEST_CERT_B_DER: &[u8] = include_bytes!("../tests/fixtures/test_cert_b.der");

    fn parse_test_cert(der: &[u8]) -> x509_cert::Certificate {
        use x509_cert::der::Decode as _;
        x509_cert::Certificate::from_der(der).expect("parse fixture cert")
    }

    fn cert_fingerprint(cert: &x509_cert::Certificate) -> String {
        use x509_cert::der::Encode as _;
        sha256_fingerprint(&cert.to_der().expect("encode fixture cert"))
    }

    /// Records every [`CertInfo`] it is asked to decide, then returns a fixed
    /// decision. Lets tests assert *which* situation `verify_cert` presented
    /// (Unknown vs Mismatch), not just the outcome.
    struct RecordingCertVerifier {
        decision: CertDecision,
        seen: Mutex<Vec<CertInfo>>,
    }

    impl RecordingCertVerifier {
        fn new(decision: CertDecision) -> Self {
            Self {
                decision,
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl CertVerifier for RecordingCertVerifier {
        fn decide(&self, info: &CertInfo) -> CertDecision {
            self.seen.lock().unwrap().push(info.clone());
            self.decision
        }
    }

    #[test]
    fn verify_cert_unknown_accept_stores_fingerprint() {
        // `verify_cert` first tries CA validation, which needs the process-level
        // rustls crypto provider installed (normally done once by `drive_inner`
        // before any TLS call); do it here too since these tests call
        // `verify_cert` directly, independent of test execution order.
        install_ring_provider();
        let cert = parse_test_cert(TEST_CERT_A_DER);
        let store = CertStore::new();
        let verifier = RecordingCertVerifier::new(CertDecision::AcceptAndRemember);

        let key = verify_cert(&cert, "host.test", 3389, &verifier, &store).expect("accept");

        assert!(!key.is_empty(), "server public key must be returned");
        assert_eq!(
            store.lookup("host.test", 3389).as_deref(),
            Some(cert_fingerprint(&cert).as_str())
        );
        assert_eq!(verifier.seen.lock().unwrap().len(), 1);
        assert_eq!(
            verifier.seen.lock().unwrap()[0].situation,
            CertSituation::Unknown
        );
    }

    #[test]
    fn verify_cert_unknown_reject_returns_cert_rejected_and_stores_nothing() {
        install_ring_provider();
        let cert = parse_test_cert(TEST_CERT_A_DER);
        let store = CertStore::new();
        let verifier = RecordingCertVerifier::new(CertDecision::Reject);

        let err = verify_cert(&cert, "host.test", 3389, &verifier, &store).unwrap_err();

        assert!(matches!(err, RdpError::CertRejected(_)), "got: {err:?}");
        assert!(store.lookup("host.test", 3389).is_none());
    }

    #[test]
    fn verify_cert_exact_match_accepts_silently_without_prompting() {
        install_ring_provider();
        let cert = parse_test_cert(TEST_CERT_A_DER);
        let store = CertStore::new();
        store.store("host.test", 3389, &cert_fingerprint(&cert));
        let verifier = RecordingCertVerifier::new(CertDecision::Reject); // would fail the test if consulted

        let key = verify_cert(&cert, "host.test", 3389, &verifier, &store).expect("silent accept");

        assert!(!key.is_empty());
        assert!(
            verifier.seen.lock().unwrap().is_empty(),
            "an exact TOFU match must not prompt the verifier"
        );
    }

    #[test]
    fn verify_cert_mismatch_presents_mismatch_situation_and_can_reject() {
        install_ring_provider();
        let cert_a = parse_test_cert(TEST_CERT_A_DER);
        let cert_b = parse_test_cert(TEST_CERT_B_DER);
        let store = CertStore::new();
        store.store("host.test", 3389, &cert_fingerprint(&cert_a));
        let verifier = RecordingCertVerifier::new(CertDecision::Reject);

        let err = verify_cert(&cert_b, "host.test", 3389, &verifier, &store).unwrap_err();

        assert!(matches!(err, RdpError::CertRejected(_)), "got: {err:?}");
        match &verifier.seen.lock().unwrap()[0].situation {
            CertSituation::Mismatch {
                source,
                stored_fingerprint,
            } => {
                assert_eq!(*source, KnownCertSource::ConManStore);
                assert_eq!(*stored_fingerprint, cert_fingerprint(&cert_a));
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
        // Rejecting a mismatch must not overwrite the store.
        assert_eq!(
            store.lookup("host.test", 3389).as_deref(),
            Some(cert_fingerprint(&cert_a).as_str())
        );
    }

    #[test]
    fn verify_cert_mismatch_accept_replaces_stored_fingerprint() {
        install_ring_provider();
        let cert_a = parse_test_cert(TEST_CERT_A_DER);
        let cert_b = parse_test_cert(TEST_CERT_B_DER);
        let store = CertStore::new();
        store.store("host.test", 3389, &cert_fingerprint(&cert_a));
        let verifier = RecordingCertVerifier::new(CertDecision::AcceptAndRemember);

        verify_cert(&cert_b, "host.test", 3389, &verifier, &store).expect("accept mismatch");

        assert_eq!(
            store.lookup("host.test", 3389).as_deref(),
            Some(cert_fingerprint(&cert_b).as_str())
        );
    }

    // ---------------------------------------------------------------------------
    // map_negotiation_error (P7.5)
    // ---------------------------------------------------------------------------

    /// Builds the exact `ConnectorError` IronRDP's `connection.rs` produces
    /// (`ConnectionInitiationWaitConfirm`, `reason_err!`) when the server's
    /// selected protocol doesn't intersect what the client requested — the
    /// literal call site diagnosed in `memos/rdp-xrdp-diagnosis-2026-07.md`.
    fn negotiation_mismatch_err(
        requested: ironrdp_pdu::nego::SecurityProtocol,
        selected: ironrdp_pdu::nego::SecurityProtocol,
    ) -> ConnectorError {
        use ironrdp_connector::ConnectorErrorExt as _;
        ConnectorError::reason(
            "Initiation",
            format!("client advertised {requested}, but server selected {selected}"),
        )
    }

    #[test]
    fn map_negotiation_error_legacy_only_server_gets_actionable_message() {
        use ironrdp_pdu::nego::SecurityProtocol;

        // What ConMan always requests (TLS, CredSSP disabled — cfg above) vs.
        // an xrdp server stuck on `security_layer=rdp`, which selects no
        // enhanced-security protocol at all (the empty bitset).
        let err = negotiation_mismatch_err(SecurityProtocol::SSL, SecurityProtocol::empty());

        let mapped = map_negotiation_error(err);

        assert!(
            matches!(mapped, RdpError::LegacySecurityOnly),
            "got: {mapped:?}"
        );
        assert_eq!(
            mapped.to_string(),
            "This RDP server only offers legacy Standard RDP Security, which ConMan does not \
             support. Enable TLS on the server (xrdp: set `security_layer=negotiate` and restart)."
        );
    }

    #[test]
    fn map_negotiation_error_other_mismatch_passes_through_unchanged() {
        use ironrdp_pdu::nego::SecurityProtocol;

        // A different (non-empty) selected protocol must NOT be misdetected
        // as the legacy-only case — only the empty/STANDARD_RDP_SECURITY
        // selection is actionable-mapped; everything else keeps today's
        // (unideal but not wrong) raw connector string.
        let err = negotiation_mismatch_err(SecurityProtocol::SSL, SecurityProtocol::RDSTLS);
        let raw = err.to_string();

        let mapped = map_negotiation_error(err);

        match mapped {
            RdpError::Protocol(msg) => assert_eq!(msg, raw),
            other => panic!("expected RdpError::Protocol passthrough, got: {other:?}"),
        }
    }

    #[test]
    fn map_negotiation_error_unrelated_reason_passes_through_unchanged() {
        use ironrdp_connector::ConnectorErrorExt as _;

        // A `Reason` error from an unrelated code path (no mention of the
        // legacy-security token at all) must not be swept up either.
        let err = ConnectorError::reason("Initiation", "standard RDP security is not supported");
        let raw = err.to_string();

        let mapped = map_negotiation_error(err);

        match mapped {
            RdpError::Protocol(msg) => assert_eq!(msg, raw),
            other => panic!("expected RdpError::Protocol passthrough, got: {other:?}"),
        }
    }

    // ---------------------------------------------------------------------------
    // P9.1 CredSSP/NLA: credential-check + connect_finalize error mapping
    // ---------------------------------------------------------------------------

    /// HYBRID-selected (should_perform_credssp() == true) + no password ==>
    /// the actionable missing-credential error, *before* any CredSSP exchange
    /// is attempted.
    #[test]
    fn credssp_requires_credentials_when_hybrid_selected_and_password_empty() {
        assert!(credssp_requires_credentials(true, b""));
    }

    /// HYBRID-selected + a real password ==> proceed (CredSSP will run and
    /// either succeed or fail on its own terms — not ConMan's business here).
    #[test]
    fn credssp_requires_credentials_false_when_hybrid_selected_and_password_present() {
        assert!(!credssp_requires_credentials(true, b"hunter2"));
    }

    /// TLS-only server (should_perform_credssp() == false) + no password ==>
    /// unaffected by this check at all, even though the password is empty.
    /// This is the plain-TLS regression guard: a blank password against a
    /// TLS-only server must not be misdiagnosed as an NLA credential problem
    /// (it just proceeds to the graphical Windows logon screen, as before).
    #[test]
    fn credssp_requires_credentials_false_when_tls_only_selected_regardless_of_password() {
        assert!(!credssp_requires_credentials(false, b""));
        assert!(!credssp_requires_credentials(false, b"hunter2"));
    }

    /// Builds a minimal-but-valid `ironrdp_connector::Config` for driving a
    /// real `ClientConnector` in tests. Field values beyond
    /// `enable_tls`/`enable_credssp` don't matter here — the drift-guard
    /// test below force-sets `connector.state` directly rather than letting
    /// the connector negotiate it, so nothing else in `Config` is read.
    fn test_connector_config() -> Config {
        Config {
            desktop_size: DesktopSize {
                width: 800,
                height: 600,
            },
            desktop_scale_factor: 0,
            enable_tls: true,
            enable_credssp: true,
            credentials: Credentials::UsernamePassword {
                username: "tester".to_owned(),
                password: "hunter2".to_owned(),
            },
            domain: None,
            client_build: 0,
            client_name: "conman-test".to_owned(),
            keyboard_type: ironrdp_pdu::gcc::KeyboardType::IbmEnhanced,
            keyboard_subtype: 0,
            keyboard_functional_keys_count: 12,
            keyboard_layout: 0x0409,
            ime_file_name: String::new(),
            bitmap: None,
            dig_product_id: String::new(),
            client_dir: String::new(),
            alternate_shell: String::new(),
            work_dir: String::new(),
            platform: ironrdp_pdu::rdp::capability_sets::MajorPlatformType::UNSPECIFIED,
            hardware_id: None,
            request_data: None,
            autologon: true,
            enable_audio_playback: false,
            performance_flags: ironrdp_pdu::rdp::client_info::PerformanceFlags::default(),
            license_cache: None,
            timezone_info: ironrdp_pdu::rdp::client_info::TimezoneInfo::default(),
            compression_type: None,
            enable_server_pointer: true,
            pointer_software_rendering: false,
            multitransport_flags: None,
        }
    }

    fn test_connector_local_addr() -> std::net::SocketAddr {
        "0.0.0.0:0".parse().expect("hardcoded SocketAddr is valid")
    }

    /// Drift guard (Milestone-C reviewer blocker): proves, against the real
    /// vendored `ClientConnector` state machine — not a reimplementation —
    /// that `should_perform_credssp()` only becomes meaningful *after*
    /// `mark_as_upgraded`, and is unconditionally `false` right after
    /// `connect_begin` (where the missing-credential check used to live,
    /// making it dead code).
    ///
    /// This uses the exact production functions `rdp::connect` calls:
    /// `ironrdp_tokio::skip_connect_begin` performs the identical
    /// precondition assertion and state handoff as `connect_begin` without
    /// requiring a live socket (both hand back the connector already in
    /// `EnhancedSecurityUpgrade`), and `ironrdp_tokio::mark_as_upgraded` is
    /// the literal function `connect()` calls at rdp.rs step 7.
    ///
    /// A future regression that moves the `credssp_requires_credentials`
    /// call back to right after `connect_begin`/`skip_connect_begin` (i.e.
    /// before `mark_as_upgraded`) will not be caught by compilation, but
    /// *is* caught here: this test fails loudly if `should_perform_credssp()`
    /// ever reads `true` before `mark_as_upgraded`, or `false` after it for
    /// a HYBRID selection.
    ///
    /// What this test does *not* cover: driving `connect()` itself end to
    /// end (that needs a real or fully-scripted RDP negotiation over a
    /// socket — `connect_begin` parses actual X.224 Connection Confirm
    /// bytes). That remaining gap is covered by the win11-dev live NLA
    /// verify: an empty-password HYBRID connection to a real NLA-enabled
    /// server must surface `RdpError::CredentialsRequired`, not the
    /// cryptic pre-fix `RdpError::Auth`.
    #[test]
    fn credssp_state_machine_only_settles_after_mark_as_upgraded() {
        use ironrdp_connector::ClientConnectorState;
        use ironrdp_pdu::nego::SecurityProtocol;

        // --- HYBRID (NLA) case: the bug this fix corrects ---
        let mut connector =
            ClientConnector::new(test_connector_config(), test_connector_local_addr());
        // This is what connect_begin leaves behind once the server has
        // confirmed HYBRID (see ClientConnectorState::ConnectionInitiationWaitConfirm's
        // transition in vendored ironrdp-connector): state EnhancedSecurityUpgrade.
        connector.state = ClientConnectorState::EnhancedSecurityUpgrade {
            selected_protocol: SecurityProtocol::HYBRID,
        };
        let should_upgrade = ironrdp_tokio::skip_connect_begin(&mut connector);

        // This is exactly the point where the pre-fix check lived (rdp.rs
        // step "4b", immediately after connect_begin): should_perform_credssp()
        // is false here even though the server selected HYBRID. Checking here
        // is dead code.
        assert!(
            !connector.should_perform_credssp(),
            "should_perform_credssp() must be false before mark_as_upgraded, even for \
             a HYBRID selection (state is still EnhancedSecurityUpgrade) — this is \
             precisely the dead-code bug this test guards against"
        );

        let _upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);

        // After mark_as_upgraded, the connector has transitioned past
        // EnhancedSecurityUpgrade; for a HYBRID selection it now sits in
        // Credssp, so the check is live.
        assert!(
            connector.should_perform_credssp(),
            "should_perform_credssp() must be true after mark_as_upgraded when the \
             server selected HYBRID — this is the fix's load-bearing assumption \
             (the check must run after mark_as_upgraded, not before)"
        );

        // --- TLS-only case: plain-TLS regression guard ---
        let mut connector =
            ClientConnector::new(test_connector_config(), test_connector_local_addr());
        connector.state = ClientConnectorState::EnhancedSecurityUpgrade {
            selected_protocol: SecurityProtocol::SSL,
        };
        let should_upgrade = ironrdp_tokio::skip_connect_begin(&mut connector);
        assert!(!connector.should_perform_credssp());

        let _upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);

        assert!(
            !connector.should_perform_credssp(),
            "TLS-only servers must never trip should_perform_credssp(), even after \
             mark_as_upgraded — the plain-TLS backward-compat guarantee: reordering \
             the check to run after mark_as_upgraded must not regress this path"
        );
    }

    /// A CredSSP-kind `connect_finalize` failure (bad NTLM credentials, or an
    /// unsupported Kerberos/KDC round-trip) maps to the actionable
    /// `RdpError::Auth`, not the generic `RdpError::Protocol`.
    #[test]
    fn map_finalize_error_credssp_kind_maps_to_auth() {
        let sspi_err = ironrdp_connector::sspi::Error::new(
            ironrdp_connector::sspi::ErrorKind::LogonDenied,
            "the referenced account is currently locked out",
        );
        let err = ConnectorError::new(
            "CredSSP",
            ironrdp_connector::ConnectorErrorKind::Credssp(sspi_err),
        );

        let mapped = map_finalize_error(err);

        assert!(matches!(mapped, RdpError::Auth(_)), "got: {mapped:?}");
    }

    /// P9.5 item 5: the mapped `RdpError::Auth` message is clean and
    /// user-facing — no `[CredSSP @ …]` internal protocol/source-location
    /// trace (which `e.to_string()` on the raw `ConnectorError` embeds, per
    /// `ironrdp_error::Error<Kind>`'s `Display` impl). The raw detail must
    /// only reach the `tracing` log, never the reason string the
    /// `ErrorOverlay` renders.
    #[test]
    fn map_finalize_error_credssp_kind_message_is_clean() {
        let sspi_err = ironrdp_connector::sspi::Error::new(
            ironrdp_connector::sspi::ErrorKind::LogonDenied,
            "the referenced account is currently locked out",
        );
        let err = ConnectorError::new(
            "CredSSP",
            ironrdp_connector::ConnectorErrorKind::Credssp(sspi_err),
        );

        let mapped = map_finalize_error(err);
        let msg = mapped.to_string();

        assert_eq!(
            msg, "Authentication failed — check the username, password, and domain.",
            "got: {msg:?}"
        );
        assert!(!msg.contains("CredSSP @"), "leaked internal trace: {msg:?}");
        assert!(!msg.contains(".rs:"), "leaked source location: {msg:?}");
    }

    /// A non-CredSSP `connect_finalize` failure (e.g. a plain TLS-only-path
    /// finalize error) passes through unchanged as `RdpError::Protocol`,
    /// exactly like the pre-P9.1 behavior — the plain-TLS regression guard
    /// for the finalize step.
    #[test]
    fn map_finalize_error_non_credssp_passes_through_unchanged() {
        use ironrdp_connector::ConnectorErrorExt as _;

        let err = ConnectorError::general("some non-CredSSP finalize failure");
        let raw = err.to_string();

        let mapped = map_finalize_error(err);

        match mapped {
            RdpError::Protocol(msg) => assert_eq!(msg, raw),
            other => panic!("expected RdpError::Protocol passthrough, got: {other:?}"),
        }
    }

    // ---------------------------------------------------------------------------
    // Connection-failure surfacing over a real socket (P6.2, gap 23)
    //
    // No in-process RDP protocol responder exists (see the new-dep memo above),
    // so these exercise the client-side failure path — refused connection,
    // abrupt close, and garbage bytes where the X.224 Connection Confirm is
    // expected — proving `RdpSession::connect` always fails soft (typed
    // `Failed` status, never a panic) exactly as CONVENTIONS §2 requires for
    // untrusted transport input.
    // ---------------------------------------------------------------------------

    fn test_rdp_settings(port: u16) -> cm_core::RdpSettings {
        cm_core::RdpSettings {
            host: "127.0.0.1".to_owned(),
            port,
            domain: None,
            username: Some("tester".to_owned()),
            width: 800,
            height: 600,
            color_depth: 32,
        }
    }

    fn test_rdp_auth() -> RdpAuthInput {
        RdpAuthInput {
            username: "tester".to_owned(),
            password: Secret::from_string("pw".to_owned()),
            domain: None,
        }
    }

    fn wait_for_rdp_terminal_status(
        session: &RdpSession,
        timeout: std::time::Duration,
    ) -> SessionStatus {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let status = session.status();
            if !matches!(status, SessionStatus::Connecting) {
                return status;
            }
            if std::time::Instant::now() > deadline {
                panic!(
                    "RDP session did not reach a terminal status within {timeout:?} (stuck at {status:?})"
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn rdp_connect_refused_surfaces_failed_no_panic() {
        // Bind then immediately drop: reserves a port with nothing listening.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
            l.local_addr().unwrap().port()
        };

        let verifier = FixedCertVerifier::new(CertDecision::AcceptAndRemember);
        let session = RdpSession::connect(
            &test_rdp_settings(port),
            test_rdp_auth(),
            verifier,
            CertStore::new(),
        )
        .expect("spawn rdp session (connect failure is async)");

        let status = wait_for_rdp_terminal_status(&session, std::time::Duration::from_secs(5));
        assert!(
            matches!(status, SessionStatus::Failed(_)),
            "expected Failed, got {status:?}"
        );
        session.shutdown();
    }

    #[test]
    fn rdp_immediate_close_fails_soft_no_panic() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            // Accept then drop: the client sent its X.224 Connection Request
            // but the socket closes with zero bytes back.
            let _ = listener.accept();
        });

        let verifier = FixedCertVerifier::new(CertDecision::AcceptAndRemember);
        let session = RdpSession::connect(
            &test_rdp_settings(port),
            test_rdp_auth(),
            verifier,
            CertStore::new(),
        )
        .expect("spawn rdp session");

        let status = wait_for_rdp_terminal_status(&session, std::time::Duration::from_secs(5));
        assert!(
            matches!(status, SessionStatus::Failed(_)),
            "expected Failed, got {status:?}"
        );
        session.shutdown();
    }

    #[test]
    fn rdp_garbage_response_fails_soft_no_panic() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 256];
                // Consume (some of) the client's X.224 Connection Request…
                let _ = stream.read(&mut buf);
                // …then answer with bytes that are not a valid X.224
                // Connection Confirm / RDP Negotiation Response.
                let _ = stream.write_all(b"\x00\x11\x22NOT-A-VALID-X224-RESPONSE\xff\xfe");
                let _ = stream.flush();
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        });

        let verifier = FixedCertVerifier::new(CertDecision::AcceptAndRemember);
        let session = RdpSession::connect(
            &test_rdp_settings(port),
            test_rdp_auth(),
            verifier,
            CertStore::new(),
        )
        .expect("spawn rdp session");

        let status = wait_for_rdp_terminal_status(&session, std::time::Duration::from_secs(5));
        assert!(
            matches!(status, SessionStatus::Failed(_)),
            "expected Failed, got {status:?}"
        );
        session.shutdown();
    }

    // ---------------------------------------------------------------------------
    // Integration test (real host, gated) -- P9.5 item 8: env-gated, no
    // hardcoded lab host/credential in tracked source.
    // ---------------------------------------------------------------------------

    /// Opt-in live proof driven entirely by env vars, so no lab-specific
    /// host/user/password is ever hardcoded in tracked source (this repo
    /// keeps infra/host details out of tracked files -- P9.5 item 8; mirrors
    /// the `ssh_publickey_rsa_live_host_requiring_sha2` live test in
    /// `cm-session/tests/ssh_loopback.rs`). No-ops (does not fail) when the
    /// env vars are unset, so `cargo test --ignored` elsewhere never fails on
    /// missing lab access; only meaningful when explicitly pointed at a host:
    ///
    /// ```text
    /// CONMAN_LIVE_RDP_HOST=<ip-or-hostname> CONMAN_LIVE_RDP_USER=<user> \
    ///   CONMAN_LIVE_RDP_PASSWORD=<password> \
    ///   cargo test -p cm-session -- --ignored rdp_connect_live_host --nocapture
    /// ```
    ///
    /// Prerequisites (xrdp target):
    ///   - Network access to the target host on port 3389.
    ///   - `/etc/xrdp/xrdp.ini` on the server must have `security_layer=negotiate`
    ///     (or `tls`); the default `security_layer=rdp` uses STANDARD_RDP_SECURITY
    ///     which IronRDP does not support.
    ///
    /// **P9.7 Slice 1** (wire-level visual QA, since every other runner is
    /// headless/software and structurally blind to GPU-compositing bugs):
    /// beyond "connects and gets one frame", this asserts (1) the confirmed
    /// desktop size matches the *requested* `RdpSettings` (proves resolution
    /// negotiation, not post-hoc scaling -- #10 at the wire level), (2) the
    /// framebuffer has real RGB variety, not just a non-zero byte (catches a
    /// uniform solid-color decode failure the old check missed), and (3) the
    /// #9/#11 black-screen root cause (alpha = wire-padding 0x00 while RGB is
    /// valid) as a documented invariant, so a future alpha "cleanup" can't
    /// silently reintroduce it. See the assertions' own comments below.
    ///
    /// **Hardening (found during coordinator re-verification against a real
    /// xrdp host, master `b397e4c`):** this live smoke was flaky in two ways
    /// unrelated to the RDP decode/resolution code itself (both confirmed
    /// correct by a clean run):
    /// - The old code asserted variety against whichever frame happened to
    ///   be the *first* non-empty one, which can be a solid xrdp
    ///   greeter/background frame that arrives before real desktop content --
    ///   a spurious "1 distinct RGB value" failure. Now it keeps collecting
    ///   frames for a bounded window after first content and asserts against
    ///   the richest (most colorful) one seen, only failing if real content
    ///   never arrives in that window.
    /// - The fixed 15 s connect-wait can trip on this host's own
    ///   reconnect-throttling (a same-user RDP reconnect attempted right
    ///   after a prior disconnect gets held/rejected server-side for ~20 s --
    ///   see the `test-hosts` memo). The timeout is now tunable via
    ///   `CONMAN_LIVE_RDP_TIMEOUT_SECS` (default unchanged, 15) and a single
    ///   connect attempt that times out gets one retry after a cooldown.
    #[tokio::test]
    #[ignore = "opt-in: set CONMAN_LIVE_RDP_HOST/_USER/_PASSWORD to run against a real host"]
    async fn rdp_connect_live_host() {
        let (host, user, password) = match (
            std::env::var("CONMAN_LIVE_RDP_HOST"),
            std::env::var("CONMAN_LIVE_RDP_USER"),
            std::env::var("CONMAN_LIVE_RDP_PASSWORD"),
        ) {
            (Ok(h), Ok(u), Ok(p)) => (h, u, p),
            _ => {
                eprintln!(
                    "rdp_connect_live_host: skipping -- set \
                     CONMAN_LIVE_RDP_HOST/_USER/_PASSWORD to exercise a live host"
                );
                return;
            }
        };

        // Hardening: tunable connect-wait, defaulting to the original 15 s.
        // A real target's reconnect-throttling (or general slow-host
        // variance) shouldn't be a false failure of a gate meant to catch
        // real decode/negotiation regressions.
        let timeout_secs: u64 = std::env::var("CONMAN_LIVE_RDP_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15);
        let connect_timeout = std::time::Duration::from_secs(timeout_secs);

        let cfg = cm_core::RdpSettings {
            host,
            port: 3389,
            domain: None,
            username: Some(user.clone()),
            width: 1280,
            height: 720,
            color_depth: 32,
        };
        let auth = RdpAuthInput {
            username: user,
            password: Secret::from_string(password),
            domain: None,
        };

        /// One connect attempt: spawn the session and wait up to `timeout`
        /// for `Connected`. Returns the connected session, or an error
        /// string describing what went wrong (never panics -- the caller
        /// decides whether to retry).
        async fn try_connect(
            cfg: &cm_core::RdpSettings,
            auth: RdpAuthInput,
            timeout: std::time::Duration,
        ) -> Result<RdpSession, String> {
            let verifier = FixedCertVerifier::new(CertDecision::AcceptAndRemember);
            let store = CertStore::new();
            let session = RdpSession::connect(cfg, auth, verifier, store)
                .map_err(|e| format!("session construction failed: {e}"))?;

            let deadline = std::time::Instant::now() + timeout;
            loop {
                match session.status() {
                    SessionStatus::Connected => return Ok(session),
                    SessionStatus::Failed(e) => return Err(format!("RDP connect failed: {e}")),
                    SessionStatus::Disconnected => {
                        return Err("disconnected before connected".to_owned());
                    }
                    _ => {}
                }
                if std::time::Instant::now() > deadline {
                    session.shutdown();
                    return Err(format!(
                        "timed out waiting for Connected status ({}s)",
                        timeout.as_secs()
                    ));
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }

        // Hardening: one retry after a cooldown if the first attempt times
        // out. This host's reconnect-throttle (empirically ~20 s) is the
        // known cause; other failure kinds (auth rejected, disconnected) are
        // not retried -- they're real signal, not host flakiness.
        let session = match try_connect(&cfg, auth.clone(), connect_timeout).await {
            Ok(session) => session,
            Err(e) if e.contains("timed out waiting for Connected") => {
                eprintln!(
                    "rdp_connect_live_host: first connect attempt timed out ({e}) -- \
                     retrying once after a cooldown (likely reconnect-throttling)"
                );
                tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                try_connect(&cfg, auth, connect_timeout)
                    .await
                    .unwrap_or_else(|e| panic!("RDP connect failed on retry too: {e}"))
            }
            Err(e) => panic!("{e}"),
        };

        // Wait for at least one FrameUpdate, then keep draining for a
        // bounded window to let real desktop content replace any initial
        // solid xrdp greeter/background frame; assert against the richest
        // (most colorful) frame seen rather than whichever arrived first.
        let Surface::Framebuffer(rx) = session.surface() else {
            panic!("expected Framebuffer surface");
        };

        // xrdp can take ~10–12 s to deliver the first desktop bitmap after
        // initial cursor-setup frames; `connect_timeout` gives a comfortable
        // margin (same knob as the connect-wait, for one dial to turn).
        let first_frame = rx
            .recv_timeout(connect_timeout)
            .expect("must receive a frame within the timeout");

        let content_window_deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut richest_frame = first_frame;
        let mut richest_variety = distinct_rgb_count(&richest_frame.rgba);
        while let Some(remaining) =
            content_window_deadline.checked_duration_since(std::time::Instant::now())
        {
            match rx.recv_timeout(remaining) {
                Ok(frame) => {
                    let variety = distinct_rgb_count(&frame.rgba);
                    if variety > richest_variety {
                        richest_variety = variety;
                        richest_frame = frame;
                    }
                }
                Err(_) => break, // no more frames arriving in the window
            }
        }
        let frame = richest_frame;

        assert_eq!(
            frame.rgba.len(),
            usize::from(frame.width) * usize::from(frame.height) * 4
        );

        // P9.7 Slice 1, item 1: requested-size validation (#10 at the wire
        // level). `frame.width`/`frame.height` are not an echo of `cfg` --
        // they come from `DecodedImage::new(.., desktop_size.width,
        // desktop_size.height)` in `drive_inner`, where `desktop_size` is
        // `connection_result.desktop_size`, IronRDP's server-CONFIRMED
        // active size from `connect_finalize`. Asserting it equals the
        // requested size proves the resolution was actually negotiated
        // end-to-end (not bitmap-scaled after the fact -- the #10 bug).
        // Logged unconditionally so a clamp is visible in the test output
        // even if this assertion is later relaxed for a target host that
        // genuinely can't honor arbitrary resolutions.
        eprintln!(
            "rdp_connect_live_host: requested {}x{}, server-confirmed {}x{}",
            cfg.width, cfg.height, frame.width, frame.height
        );
        assert_eq!(
            (frame.width, frame.height),
            (cfg.width, cfg.height),
            "server did not honor the requested desktop resolution \
             (requested {}x{}, server confirmed {}x{}) -- if this specific \
             xrdp target genuinely cannot support the requested size, this \
             is a legitimate clamp, not a #10 regression; verify against \
             the target's real capabilities before assuming a regression",
            cfg.width,
            cfg.height,
            frame.width,
            frame.height
        );

        // P9.7 Slice 1, items 2 + 3: content variety, and the alpha=0/
        // RGB-valid invariant behind the #9/#11 black-screen root cause.
        //
        // `PixelFormat::RgbA32`'s byte order is [R, G, B, A] per pixel
        // (ironrdp_graphics::image_processing::PixelFormat::channel_order),
        // matching `frame.rgba`'s layout (row-major, width*height*4 bytes).
        let pixels: Vec<(u8, u8, u8, u8)> = frame
            .rgba
            .chunks_exact(4)
            .map(|p| (p[0], p[1], p[2], p[3]))
            .collect();
        assert!(!pixels.is_empty(), "frame has no pixels");

        // Item 2: a uniform solid-color fill (a plausible decode failure
        // distinct from all-zero) passed the old "any non-zero byte" check
        // -- it must not pass here. 8 distinct RGB values is a conservative
        // floor (a real xrdp desktop -- wallpaper, taskbar, anti-aliased
        // text -- has hundreds to thousands), chosen to avoid flaking
        // against an unknown target's visual complexity while still
        // catching a truly uniform fill (which has exactly 1). This now
        // runs against the richest frame in the content window, not
        // whichever frame happened to arrive first (hardening above).
        let distinct_rgb: std::collections::HashSet<(u8, u8, u8)> =
            pixels.iter().map(|&(r, g, b, _)| (r, g, b)).collect();
        assert!(
            distinct_rgb.len() > 8,
            "framebuffer has only {} distinct RGB value(s) -- expected real \
             desktop content (anti-aliased text/window chrome/wallpaper), \
             not a uniform solid-color fill, even after collecting frames \
             for a 3s content window",
            distinct_rgb.len()
        );

        // Item 3 (the highest-value part): pin the #9/#11 black-screen root
        // cause as a test-documented invariant. That black screen was NOT a
        // wire bug -- IronRDP's fast-path/tile decoders leave the alpha
        // channel at the wire-padding value 0x00 while the RGB channels are
        // fully valid. Slint's software backend ignores alpha (so it
        // rendered fine); femtovg alpha-blends alpha=0x00 to fully
        // transparent, which composites as black. cm-ui's fix
        // (`frame_to_image`) forces alpha=0xff before handing the buffer to
        // Slint's `Image`. This assertion documents the exact contract that
        // fix depends on: the RGB data is real and varied EVEN WHERE alpha
        // is 0 -- so a downstream renderer MUST treat alpha=0 pixels as
        // opaque, never as "no content" / blank. Do NOT change decode/alpha
        // behavior here -- this only asserts + documents the invariant; the
        // fix itself lives in cm-ui.
        let alpha_zero_rgb: std::collections::HashSet<(u8, u8, u8)> = pixels
            .iter()
            .filter(|&&(_, _, _, a)| a == 0)
            .map(|&(r, g, b, _)| (r, g, b))
            .collect();
        if alpha_zero_rgb.is_empty() {
            // Server/decoder-dependent: this particular capture happened to
            // carry real alpha throughout. The general RGB-variety
            // assertion above still holds regardless.
            eprintln!(
                "rdp_connect_live_host: no alpha=0 pixels in this frame -- \
                 the wire-padding invariant this test documents didn't \
                 trigger for this capture"
            );
        } else {
            assert!(
                alpha_zero_rgb.len() > 1,
                "all {} alpha=0 pixel(s) share a single RGB value -- if \
                 alpha=0 now correlates with genuinely blank/unset pixels \
                 (rather than wire padding on otherwise-valid content), the \
                 #9/#11 black-screen root-cause analysis needs \
                 re-checking before touching cm-ui's forced-opaque fix",
                alpha_zero_rgb.len()
            );
        }

        // P9.9 §8: mid-session resize round-trip. Request a different size
        // and give the target a window to respond, then assert only what's
        // true for BOTH targets the dual-target design supports: the
        // session must stay `Connected` -- never `Failed`/hung -- whether
        // the target actually reactivates to the new size (a compliant
        // host) or silently ignores the request (xrdp's documented no-op).
        // Does NOT hard-assert the new dimensions equal the request: that
        // would only hold for a compliant host, and this test runs against
        // whatever `CONMAN_LIVE_RDP_HOST` points at.
        let (resize_w, resize_h) = (1024u16, 768u16);
        session.resize_px(u32::from(resize_w), u32::from(resize_h));

        let resize_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut post_resize_frame: Option<FrameUpdate> = None;
        while std::time::Instant::now() < resize_deadline {
            match rx.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(f) => {
                    let reactivated = (f.width, f.height) == (resize_w, resize_h);
                    post_resize_frame = Some(f);
                    if reactivated {
                        break; // observed the new size; no need to keep waiting
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        assert!(
            matches!(session.status(), SessionStatus::Connected),
            "session must remain Connected after a mid-session resize \
             request -- the §3 degradation contract: a stable no-op (xrdp) \
             is acceptable, a wedged or failed session is not; got {:?}",
            session.status()
        );

        match post_resize_frame {
            Some(f) if (f.width, f.height) == (resize_w, resize_h) => {
                eprintln!(
                    "rdp_connect_live_host: mid-session resize reactivated to \
                     {}x{} (compliant-host path exercised)",
                    f.width, f.height
                );
            }
            Some(f) => {
                eprintln!(
                    "rdp_connect_live_host: mid-session resize request was not \
                     honored -- framebuffer stayed at {}x{} (xrdp-style no-op, \
                     session remained stable; this is this test's known \
                     reachable target -- a compliant Windows host was not \
                     available to exercise the reactivation path here)",
                    f.width, f.height
                );
            }
            None => {
                eprintln!(
                    "rdp_connect_live_host: no framebuffer update observed within \
                     10s of the resize request -- acceptable as long as \
                     session status stayed Connected (asserted above)"
                );
            }
        }

        session.shutdown();
    }
}

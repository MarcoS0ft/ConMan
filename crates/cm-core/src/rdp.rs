//! RDP auth-input and certificate-verification contract types.
//!
//! Moved here from `cm-session/src/rdp.rs` — pure data/trait definitions, no
//! I/O, needed by the [`crate::session_ports::SessionProvider`] port and
//! implemented by `cm-ui` (`UiCertVerifier` in `controller/sessions.rs`).
//! `CertStore` — the JSON-file-backed trust store — is *not* moved: it does
//! real file I/O (`std::fs`), which has no place in `cm-core`'s charter
//! (ARCHITECTURE §1: "no I/O"). It stays in `cm-session::rdp`; the
//! `SessionProvider` adapter constructs it internally so callers never need
//! to know it exists.

use crate::credential::Secret;

// Certificate verification

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

/// Details of a certificate awaiting user decision (prompt UI =).
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
/// In this is backed by the host-key dialog; in tests it is programmatic.
pub trait CertVerifier: Send + Sync {
    fn decide(&self, info: &CertInfo) -> CertDecision;
}

// Auth input

/// RDP authentication credentials.
///
/// The password is stored as [`Secret`] (zeroized on drop) mirroring the SSH
/// session pattern. It is converted to `String` only at the IronRDP boundary
/// inside `cm_session::RdpSession::connect`, immediately before being moved
/// into `ironrdp_connector::Credentials`.
#[derive(Debug, Clone)]
pub struct RdpAuthInput {
    pub username: String,
    pub password: Secret,
    pub domain: Option<String>,
}

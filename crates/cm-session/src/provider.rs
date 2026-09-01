//! [`SessionProvider`] adapter.
//!
//! Builds concrete sessions for `cm-ui` and owns per-transport trust-store
//! construction (`KnownHosts`, `CertStore`). Callers therefore do not need to
//! know where either store lives or how it is initialized.

use std::sync::Arc;

use cm_core::rdp::{CertVerifier, RdpAuthInput};
use cm_core::session::Session;
use cm_core::session::SessionEndpointId;
use cm_core::session_ports::{SessionProvider, SessionSetupError, TerminalOptions};
use cm_core::ssh::{HostKeyVerifier, SshAuthInput};
use cm_core::terminal::TerminalSize;
use cm_core::{LocalSettings, RdpSettings, SshSettings, TelnetSettings};

use crate::local::LocalTerminalSession;
use crate::rdp::{CertStore, RdpSession};
use crate::ssh::{KnownHosts, SshTerminalSession};
use crate::telnet::TelnetTerminalSession;

/// Default `cm-session` [`SessionProvider`]. Stateless — every call resolves
/// its own trust-store defaults, matching the `cm-ui` call sites
/// did inline (`KnownHosts::with_defaults`,
/// `CertStore::new_persistent(<app-data dir>/conman/cert_trust.json)`).
#[derive(Debug)]
pub struct SessionProviderImpl {
    clipboard_root: Option<Arc<cm_platform::secure_temp::SecureClipboardRoot>>,
}

impl SessionProviderImpl {
    /// Construct the provider. No setup performed here — trust stores are
    /// resolved per-connect.
    #[must_use]
    pub fn new(clipboard_root: Option<Arc<cm_platform::secure_temp::SecureClipboardRoot>>) -> Self {
        Self { clipboard_root }
    }
}

/// Persistent RDP cert-trust store in the OS app-data dir, so accepted certs
/// survive restarts. Moved here from `cm-ui`'s `default_cert_store`
/// (`controller/sessions.rs`) — same path, same defaults.
fn default_cert_store() -> Arc<CertStore> {
    let path = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("conman")
        .join("cert_trust.json");
    CertStore::new_persistent(path)
}

impl SessionProvider for SessionProviderImpl {
    fn spawn_local(
        &self,
        settings: &LocalSettings,
        size: TerminalSize,
        options: TerminalOptions,
    ) -> Result<Box<dyn Session>, SessionSetupError> {
        LocalTerminalSession::spawn(settings, size, options)
            .map(|s| Box::new(s) as Box<dyn Session>)
            .map_err(|e| SessionSetupError::new(e.to_string()))
    }

    fn connect_ssh(
        &self,
        settings: &SshSettings,
        auth: SshAuthInput,
        verifier: Arc<dyn HostKeyVerifier>,
        size: TerminalSize,
        options: TerminalOptions,
    ) -> Result<Box<dyn Session>, SessionSetupError> {
        SshTerminalSession::connect(
            settings,
            auth,
            verifier,
            KnownHosts::with_defaults(),
            size,
            options,
        )
        .map(|s| Box::new(s) as Box<dyn Session>)
        .map_err(|e| SessionSetupError::new(e.to_string()))
    }

    fn connect_telnet(
        &self,
        settings: &TelnetSettings,
        size: TerminalSize,
        options: TerminalOptions,
    ) -> Result<Box<dyn Session>, SessionSetupError> {
        TelnetTerminalSession::connect(settings, size, options)
            .map(|session| Box::new(session) as Box<dyn Session>)
            .map_err(|error| SessionSetupError::new(error.to_string()))
    }

    fn connect_rdp(
        &self,
        settings: &RdpSettings,
        auth: RdpAuthInput,
        verifier: Arc<dyn CertVerifier>,
        endpoint_id: SessionEndpointId,
    ) -> Result<Box<dyn Session>, SessionSetupError> {
        RdpSession::connect(
            settings,
            auth,
            verifier,
            default_cert_store(),
            endpoint_id,
            self.clipboard_root.clone(),
        )
        .map(|s| Box::new(s) as Box<dyn Session>)
        .map_err(|e| SessionSetupError::new(e.to_string()))
    }
}

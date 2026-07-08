//! A `SessionProvider` double for the P8.2 element-test harness.
//!
//! No real PTY, no real SSH/RDP transport, no threads, no sleeping -- every
//! session this hands out is a [`ScriptedSession`] whose entire lifecycle is
//! a shared `SessionStatus` cell the *test* mutates directly. This is what
//! makes `suite_overlays.rs`'s "connecting overlay holds indefinitely" and
//! "then resolves to failure" scenarios deterministic and instant: nothing
//! ever actually connects, so there is nothing to race or wait on.

use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};

use cm_core::rdp::{CertVerifier, RdpAuthInput};
use cm_core::ssh::{HostKeyVerifier, SshAuthInput};
use cm_core::{
    LocalSettings, RdpSettings, Session, SessionProvider, SessionSetupError, SessionStatus,
    SshSettings, Surface, TerminalSize,
};

/// A [`Session`] whose lifecycle is entirely driven by a shared status cell
/// the test holds a clone of. The surface channel's sender is dropped
/// immediately -- a permanently-empty (and, once dropped, permanently
/// disconnected) `Receiver` is exactly what `drain_latest`/the tick loop
/// already treat "nothing new this tick" as (see
/// `controller/sessions.rs::drain_latest`), so this never errors, it just
/// never renders anything -- fine, since terminal content is out of scope
/// for the element suites (screenshots/`cm-session` own that).
pub(crate) struct ScriptedSession {
    status: Arc<Mutex<SessionStatus>>,
    surface: Surface,
}

impl ScriptedSession {
    pub(crate) fn new(status: Arc<Mutex<SessionStatus>>) -> Self {
        let (_tx, rx) = channel();
        Self {
            status,
            surface: Surface::TerminalGrid(rx),
        }
    }
}

impl Session for ScriptedSession {
    fn surface(&self) -> &Surface {
        &self.surface
    }

    fn status(&self) -> SessionStatus {
        self.status
            .lock()
            .expect("ScriptedSession status mutex poisoned")
            .clone()
    }

    fn shutdown(&self) {}
    fn resize_px(&self, _width: u32, _height: u32) {}
}

/// Hermetic `SessionProvider`:
///
/// - `spawn_local` always returns an immediately-`Connected` [`ScriptedSession`]
///   (own private status cell, never shared) -- satisfies the startup local
///   shell / Launchpad-fronted empty tab without any real PTY.
/// - `connect_ssh`/`connect_rdp` hand out a [`ScriptedSession`] sharing
///   whatever cell [`Self::script_next_remote`] last installed (defaulting to
///   an already-`Connected` cell if a test never calls it) -- install a fresh
///   `Arc<Mutex<SessionStatus::Connecting>>` before driving Connect through
///   the UI to script a specific overlay scenario, then mutate that same
///   `Arc` from the test to move the session through its lifecycle.
pub(crate) struct MockSessionProvider {
    next_remote_status: Mutex<Arc<Mutex<SessionStatus>>>,
}

impl MockSessionProvider {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            next_remote_status: Mutex::new(Arc::new(Mutex::new(SessionStatus::Connected))),
        })
    }

    /// Installs the status cell every subsequent `connect_ssh`/`connect_rdp`
    /// call hands out, until replaced by another call. The test keeps its own
    /// clone of `cell` to mutate the session's reported status afterward.
    pub(crate) fn script_next_remote(&self, cell: Arc<Mutex<SessionStatus>>) {
        *self
            .next_remote_status
            .lock()
            .expect("MockSessionProvider.next_remote_status poisoned") = cell;
    }
}

impl SessionProvider for MockSessionProvider {
    fn spawn_local(
        &self,
        _settings: &LocalSettings,
        _size: TerminalSize,
    ) -> Result<Box<dyn Session>, SessionSetupError> {
        Ok(Box::new(ScriptedSession::new(Arc::new(Mutex::new(
            SessionStatus::Connected,
        )))))
    }

    fn connect_ssh(
        &self,
        _settings: &SshSettings,
        _auth: SshAuthInput,
        _verifier: Arc<dyn HostKeyVerifier>,
        _size: TerminalSize,
    ) -> Result<Box<dyn Session>, SessionSetupError> {
        let cell = self
            .next_remote_status
            .lock()
            .expect("MockSessionProvider.next_remote_status poisoned")
            .clone();
        Ok(Box::new(ScriptedSession::new(cell)))
    }

    fn connect_rdp(
        &self,
        _settings: &RdpSettings,
        _auth: RdpAuthInput,
        _verifier: Arc<dyn CertVerifier>,
    ) -> Result<Box<dyn Session>, SessionSetupError> {
        let cell = self
            .next_remote_status
            .lock()
            .expect("MockSessionProvider.next_remote_status poisoned")
            .clone();
        Ok(Box::new(ScriptedSession::new(cell)))
    }
}

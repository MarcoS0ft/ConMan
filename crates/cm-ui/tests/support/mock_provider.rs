//! A `SessionProvider` double for the P8.2 element-test harness.
//!
//! No real PTY or remote transport, no threads, no sleeping -- every
//! session this hands out is a [`ScriptedSession`] whose entire lifecycle is
//! a shared `SessionStatus` cell the *test* mutates directly. This is what
//! makes `suite_overlays.rs`'s "connecting overlay holds indefinitely" and
//! "then resolves to failure" scenarios deterministic and instant: nothing
//! ever actually connects, so there is nothing to race or wait on.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};

use cm_core::rdp::{CertVerifier, RdpAuthInput};
use cm_core::ssh::{HostKeyVerifier, SshAuthInput};
use cm_core::{
    LocalSettings, RdpSettings, Session, SessionProvider, SessionSetupError, SessionStatus,
    SshSettings, Surface, TelnetSettings, TerminalSize,
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
/// - remote connect methods hand out a [`ScriptedSession`] sharing
///   whatever cell [`Self::script_next_remote`] last installed (defaulting to
///   an already-`Connected` cell if a test never calls it) -- install a fresh
///   `Arc<Mutex<SessionStatus::Connecting>>` before driving Connect through
///   the UI to script a specific overlay scenario, then mutate that same
///   `Arc` from the test to move the session through its lifecycle.
pub(crate) struct MockSessionProvider {
    next_remote_status: Mutex<Arc<Mutex<SessionStatus>>>,
    // P8.6-B (Fable review fixup): the execute-gate tests need to prove a
    // *blocked* reconnect/connect-in-split never dials the provider at all --
    // not just that the resulting tab looks failed (which a normal connect
    // error would also produce). A plain call count is enough; nothing needs
    // the individual call's arguments.
    ssh_connect_calls: AtomicUsize,
    rdp_connect_calls: AtomicUsize,
    telnet_connect_calls: AtomicUsize,
}

impl MockSessionProvider {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            next_remote_status: Mutex::new(Arc::new(Mutex::new(SessionStatus::Connected))),
            ssh_connect_calls: AtomicUsize::new(0),
            rdp_connect_calls: AtomicUsize::new(0),
            telnet_connect_calls: AtomicUsize::new(0),
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

    /// Total `connect_ssh` calls handled so far -- the execute-gate tests'
    /// proof that a blocked reconnect/connect-in-split never reached the
    /// provider.
    pub(crate) fn ssh_connect_count(&self) -> usize {
        self.ssh_connect_calls.load(Ordering::SeqCst)
    }

    /// RDP counterpart to [`Self::ssh_connect_count`].
    pub(crate) fn rdp_connect_count(&self) -> usize {
        self.rdp_connect_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn telnet_connect_count(&self) -> usize {
        self.telnet_connect_calls.load(Ordering::SeqCst)
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
        self.ssh_connect_calls.fetch_add(1, Ordering::SeqCst);
        let cell = self
            .next_remote_status
            .lock()
            .expect("MockSessionProvider.next_remote_status poisoned")
            .clone();
        Ok(Box::new(ScriptedSession::new(cell)))
    }

    fn connect_telnet(
        &self,
        _settings: &TelnetSettings,
        _size: TerminalSize,
    ) -> Result<Box<dyn Session>, SessionSetupError> {
        self.telnet_connect_calls.fetch_add(1, Ordering::SeqCst);
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
        self.rdp_connect_calls.fetch_add(1, Ordering::SeqCst);
        let cell = self
            .next_remote_status
            .lock()
            .expect("MockSessionProvider.next_remote_status poisoned")
            .clone();
        Ok(Box::new(ScriptedSession::new(cell)))
    }
}

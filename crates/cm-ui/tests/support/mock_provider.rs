//! A `SessionProvider` double for the element-test harness.
//!
//! No real PTY or remote transport, no threads, no sleeping -- every
//! session this hands out is a [`ScriptedSession`] whose entire lifecycle is
//! a shared `SessionStatus` cell the *test* mutates directly. This is what
//! makes `suite_overlays.rs`'s "connecting overlay holds indefinitely" and
//! "then resolves to failure" scenarios deterministic and instant: nothing
//! ever actually connects, so there is nothing to race or wait on.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};

use cm_core::rdp::{CertVerifier, RdpAuthInput};
use cm_core::ssh::{HostKeyVerifier, SshAuthInput};
use cm_core::{
    FrameUpdate, GridSnapshot, LocalSettings, MouseEvent, RdpInputEvent, RdpSettings, Session,
    SessionInput, SessionProvider, SessionSetupError, SessionStatus, SshSettings, Surface,
    TelnetSettings, TerminalSize,
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
    shared: ScriptedSessionShared,
    session_id: usize,
}

#[derive(Clone)]
struct ScriptedSessionShared {
    inputs: Arc<Mutex<Vec<SessionInput>>>,
    tagged_inputs: Arc<Mutex<Vec<(usize, SessionInput)>>>,
    search_requests: Arc<AtomicUsize>,
    search_request_sessions: Arc<Mutex<Vec<usize>>>,
    shutdowns: Arc<AtomicUsize>,
}

impl ScriptedSession {
    fn new(
        status: Arc<Mutex<SessionStatus>>,
        terminal_outputs: Arc<Mutex<Vec<Sender<GridSnapshot>>>>,
        session_id: usize,
        shared: ScriptedSessionShared,
    ) -> Self {
        let (tx, rx) = channel();
        terminal_outputs
            .lock()
            .expect("ScriptedSession terminal output mutex poisoned")
            .push(tx);
        Self {
            status,
            surface: Surface::TerminalGrid(rx),
            session_id,
            shared,
        }
    }

    fn new_rdp(
        status: Arc<Mutex<SessionStatus>>,
        rdp_outputs: Arc<Mutex<Vec<Sender<FrameUpdate>>>>,
        session_id: usize,
        shared: ScriptedSessionShared,
    ) -> Self {
        let (tx, rx) = channel::<FrameUpdate>();
        rdp_outputs
            .lock()
            .expect("ScriptedSession RDP output mutex poisoned")
            .push(tx);
        Self {
            status,
            surface: Surface::Framebuffer(rx),
            session_id,
            shared,
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

    fn shutdown(&self) {
        self.shared.shutdowns.fetch_add(1, Ordering::SeqCst);
    }
    fn resize_px(&self, _width: u32, _height: u32) {}

    fn send_input(&self, input: SessionInput) {
        self.shared
            .tagged_inputs
            .lock()
            .expect("ScriptedSession tagged inputs mutex poisoned")
            .push((self.session_id, input.clone()));
        self.shared
            .inputs
            .lock()
            .expect("ScriptedSession inputs mutex poisoned")
            .push(input);
    }

    fn request_search_text(&self, reply: Sender<Vec<String>>) {
        self.shared.search_requests.fetch_add(1, Ordering::SeqCst);
        self.shared
            .search_request_sessions
            .lock()
            .expect("ScriptedSession search request sessions mutex poisoned")
            .push(self.session_id);
        let _ = reply.send(vec!["mock full buffer".to_owned()]);
    }
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
    // The execute-gate tests need to prove a
    // *blocked* reconnect/connect-in-split never dials the provider at all --
    // not just that the resulting tab looks failed (which a normal connect
    // error would also produce). A plain call count is enough; nothing needs
    // the individual call's arguments.
    ssh_connect_calls: AtomicUsize,
    rdp_connect_calls: AtomicUsize,
    telnet_connect_calls: AtomicUsize,
    inputs: Arc<Mutex<Vec<SessionInput>>>,
    shutdowns: Arc<AtomicUsize>,
    terminal_outputs: Arc<Mutex<Vec<Sender<GridSnapshot>>>>,
    rdp_outputs: Arc<Mutex<Vec<Sender<FrameUpdate>>>>,
    next_session_id: AtomicUsize,
    tagged_inputs: Arc<Mutex<Vec<(usize, SessionInput)>>>,
    search_requests: Arc<AtomicUsize>,
    search_request_sessions: Arc<Mutex<Vec<usize>>>,
    ssh_verifiers: Mutex<Vec<Arc<dyn HostKeyVerifier>>>,
    rdp_verifiers: Mutex<Vec<Arc<dyn CertVerifier>>>,
}

impl MockSessionProvider {
    fn scripted_shared(&self) -> ScriptedSessionShared {
        ScriptedSessionShared {
            inputs: self.inputs.clone(),
            tagged_inputs: self.tagged_inputs.clone(),
            search_requests: self.search_requests.clone(),
            search_request_sessions: self.search_request_sessions.clone(),
            shutdowns: self.shutdowns.clone(),
        }
    }

    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            next_remote_status: Mutex::new(Arc::new(Mutex::new(SessionStatus::Connected))),
            ssh_connect_calls: AtomicUsize::new(0),
            rdp_connect_calls: AtomicUsize::new(0),
            telnet_connect_calls: AtomicUsize::new(0),
            inputs: Arc::new(Mutex::new(Vec::new())),
            shutdowns: Arc::new(AtomicUsize::new(0)),
            terminal_outputs: Arc::new(Mutex::new(Vec::new())),
            rdp_outputs: Arc::new(Mutex::new(Vec::new())),
            next_session_id: AtomicUsize::new(0),
            tagged_inputs: Arc::new(Mutex::new(Vec::new())),
            search_requests: Arc::new(AtomicUsize::new(0)),
            search_request_sessions: Arc::new(Mutex::new(Vec::new())),
            ssh_verifiers: Mutex::new(Vec::new()),
            rdp_verifiers: Mutex::new(Vec::new()),
        })
    }

    /// Installs the status cell every subsequent `connect_ssh`/`connect_rdp`
    /// call hands out, until replaced by another call. The test keeps its own
    /// clone of `cell` to mutate the session's status afterward.
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

    pub(crate) fn latest_ssh_verifier(&self) -> Arc<dyn HostKeyVerifier> {
        self.ssh_verifiers
            .lock()
            .expect("MockSessionProvider SSH verifiers poisoned")
            .last()
            .expect("an SSH connection must have supplied a verifier")
            .clone()
    }

    pub(crate) fn latest_rdp_verifier(&self) -> Arc<dyn CertVerifier> {
        self.rdp_verifiers
            .lock()
            .expect("MockSessionProvider RDP verifiers poisoned")
            .last()
            .expect("an RDP connection must have supplied a verifier")
            .clone()
    }

    pub(crate) fn shutdown_count(&self) -> usize {
        self.shutdowns.load(Ordering::SeqCst)
    }

    pub(crate) fn search_request_count(&self) -> usize {
        self.search_requests.load(Ordering::SeqCst)
    }

    pub(crate) fn search_request_sessions(&self) -> Vec<usize> {
        self.search_request_sessions
            .lock()
            .expect("MockSessionProvider search request sessions mutex poisoned")
            .clone()
    }

    /// Terminal mouse inputs delivered through the real controller wiring.
    pub(crate) fn terminal_mouse_events(&self) -> Vec<MouseEvent> {
        self.inputs
            .lock()
            .expect("MockSessionProvider inputs mutex poisoned")
            .iter()
            .filter_map(|input| match input {
                SessionInput::Mouse(event) => Some(*event),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn terminal_key_input_count(&self) -> usize {
        self.inputs
            .lock()
            .expect("MockSessionProvider inputs mutex poisoned")
            .iter()
            .filter(|input| matches!(input, SessionInput::Key(_)))
            .count()
    }

    pub(crate) fn terminal_key_events_for(&self, session_id: usize) -> Vec<cm_core::KeyEvent> {
        self.tagged_inputs
            .lock()
            .expect("MockSessionProvider tagged inputs mutex poisoned")
            .iter()
            .filter(|(id, _)| *id == session_id)
            .filter_map(|(_, input)| match input {
                SessionInput::Key(event) => Some(*event),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn terminal_mouse_events_for(&self, session_id: usize) -> Vec<MouseEvent> {
        self.tagged_inputs
            .lock()
            .expect("MockSessionProvider tagged inputs mutex poisoned")
            .iter()
            .filter(|(id, _)| *id == session_id)
            .filter_map(|(_, input)| match input {
                SessionInput::Mouse(event) => Some(*event),
                _ => None,
            })
            .collect()
    }

    /// Publish a terminal grid to the selected scripted session. Sessions
    /// are indexed in provider creation order; the startup local tab is 0.
    pub(crate) fn publish_terminal_grid(&self, session_index: usize, snapshot: GridSnapshot) {
        self.terminal_outputs
            .lock()
            .expect("MockSessionProvider terminal output mutex poisoned")
            .get(session_index)
            .expect("scripted terminal session index")
            .send(snapshot)
            .expect("scripted terminal receiver must remain live");
    }

    pub(crate) fn publish_rdp_frame(&self, rdp_index: usize, width: u16, height: u16) {
        self.rdp_outputs
            .lock()
            .expect("MockSessionProvider RDP output mutex poisoned")
            .get(rdp_index)
            .expect("scripted RDP session index")
            .send(FrameUpdate {
                width,
                height,
                rgba: vec![0; usize::from(width) * usize::from(height) * 4],
            })
            .expect("scripted RDP receiver must remain live");
    }

    pub(crate) fn rdp_keyboard_events(&self) -> Vec<RdpInputEvent> {
        self.inputs
            .lock()
            .expect("MockSessionProvider inputs mutex poisoned")
            .iter()
            .filter_map(|input| match input {
                SessionInput::Rdp(events) => Some(events.as_slice()),
                _ => None,
            })
            .flatten()
            .filter(|event| {
                matches!(
                    event,
                    RdpInputEvent::KeyDown { .. } | RdpInputEvent::KeyUp { .. }
                )
            })
            .cloned()
            .collect()
    }

    pub(crate) fn rdp_keyboard_events_for(&self, session_id: usize) -> Vec<RdpInputEvent> {
        self.tagged_inputs
            .lock()
            .expect("MockSessionProvider tagged inputs mutex poisoned")
            .iter()
            .filter(|(id, _)| *id == session_id)
            .filter_map(|(_, input)| match input {
                SessionInput::Rdp(events) => Some(events.as_slice()),
                _ => None,
            })
            .flatten()
            .filter(|event| {
                matches!(
                    event,
                    RdpInputEvent::KeyDown { .. } | RdpInputEvent::KeyUp { .. }
                )
            })
            .cloned()
            .collect()
    }

    pub(crate) fn rdp_pointer_events_for(&self, session_id: usize) -> Vec<RdpInputEvent> {
        self.tagged_inputs
            .lock()
            .expect("MockSessionProvider tagged inputs mutex poisoned")
            .iter()
            .filter(|(id, _)| *id == session_id)
            .filter_map(|(_, input)| match input {
                SessionInput::Rdp(events) => Some(events.as_slice()),
                _ => None,
            })
            .flatten()
            .filter(|event| {
                matches!(
                    event,
                    RdpInputEvent::MouseMove { .. }
                        | RdpInputEvent::MouseDown { .. }
                        | RdpInputEvent::MouseUp { .. }
                        | RdpInputEvent::Scroll { .. }
                )
            })
            .cloned()
            .collect()
    }
}

impl SessionProvider for MockSessionProvider {
    fn spawn_local(
        &self,
        _settings: &LocalSettings,
        _size: TerminalSize,
        _options: cm_core::TerminalOptions,
    ) -> Result<Box<dyn Session>, SessionSetupError> {
        let session_id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(ScriptedSession::new(
            Arc::new(Mutex::new(SessionStatus::Connected)),
            self.terminal_outputs.clone(),
            session_id,
            self.scripted_shared(),
        )))
    }

    fn connect_ssh(
        &self,
        _settings: &SshSettings,
        _auth: SshAuthInput,
        verifier: Arc<dyn HostKeyVerifier>,
        _size: TerminalSize,
        _options: cm_core::TerminalOptions,
    ) -> Result<Box<dyn Session>, SessionSetupError> {
        self.ssh_connect_calls.fetch_add(1, Ordering::SeqCst);
        self.ssh_verifiers
            .lock()
            .expect("MockSessionProvider SSH verifiers poisoned")
            .push(verifier);
        let cell = self
            .next_remote_status
            .lock()
            .expect("MockSessionProvider.next_remote_status poisoned")
            .clone();
        let session_id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(ScriptedSession::new(
            cell,
            self.terminal_outputs.clone(),
            session_id,
            self.scripted_shared(),
        )))
    }

    fn connect_telnet(
        &self,
        _settings: &TelnetSettings,
        _size: TerminalSize,
        _options: cm_core::TerminalOptions,
    ) -> Result<Box<dyn Session>, SessionSetupError> {
        self.telnet_connect_calls.fetch_add(1, Ordering::SeqCst);
        let cell = self
            .next_remote_status
            .lock()
            .expect("MockSessionProvider.next_remote_status poisoned")
            .clone();
        let session_id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(ScriptedSession::new(
            cell,
            self.terminal_outputs.clone(),
            session_id,
            self.scripted_shared(),
        )))
    }

    fn connect_rdp(
        &self,
        _settings: &RdpSettings,
        _auth: RdpAuthInput,
        verifier: Arc<dyn CertVerifier>,
        _endpoint_id: cm_core::SessionEndpointId,
    ) -> Result<Box<dyn Session>, SessionSetupError> {
        self.rdp_connect_calls.fetch_add(1, Ordering::SeqCst);
        self.rdp_verifiers
            .lock()
            .expect("MockSessionProvider RDP verifiers poisoned")
            .push(verifier);
        let cell = self
            .next_remote_status
            .lock()
            .expect("MockSessionProvider.next_remote_status poisoned")
            .clone();
        let session_id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(ScriptedSession::new_rdp(
            cell,
            self.rdp_outputs.clone(),
            session_id,
            self.scripted_shared(),
        )))
    }
}

//! P6.2 shared test support: an in-process SSH server (russh server side —
//! same dependency already in the workspace, no new-dep memo needed) used by
//! `tests/ssh_loopback.rs` so the protocol paths in `cm_session::ssh` run
//! against a real transport on every plain `cargo test`, no external `sshd`.
//!
//! Kept in `tests/support/` (a subdirectory) rather than `tests/support.rs` so
//! cargo does not treat it as its own test binary; test files pull it in with
//! `mod support;` / `#[path = "support/mod.rs"] mod support;`.
#![cfg(unix)]

use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use russh::keys::PrivateKey;
use russh::keys::ssh_key::{HashAlg, PublicKey};
use russh::server::{
    Auth, Handler, Msg, RunningServerHandle, Server as ServerTrait, Session as ServerSession,
};
use russh::{ChannelId, Pty};
use tokio::net::TcpListener;

/// Behavior knobs for [`LoopbackSshServer`]. Every test configures exactly the
/// bits it needs; everything else stays at the (rejecting) default so a
/// misconfigured test fails loudly instead of silently accepting.
#[derive(Clone)]
pub(crate) struct SshServerConfig {
    pub host_key: PrivateKey,
    /// `Some(password)` accepts only that password; `None` rejects all password
    /// attempts.
    pub accept_password: Option<String>,
    /// `Some(fingerprint)` (SHA256 form) accepts only a publickey auth whose
    /// presented key has this fingerprint; `None` rejects all publickey
    /// attempts.
    pub accept_pubkey_fingerprint: Option<String>,
    /// When true, the shell request handler aborts the connection instead of
    /// granting a shell — simulates a server-side abrupt close after auth.
    pub abrupt_close: bool,
}

impl SshServerConfig {
    #[must_use]
    pub(crate) fn new(host_key: PrivateKey) -> Self {
        Self {
            host_key,
            accept_password: None,
            accept_pubkey_fingerprint: None,
            abrupt_close: false,
        }
    }
}

/// A running in-process SSH server bound to an ephemeral `127.0.0.1` port.
/// Dropping it requests shutdown and joins the server thread.
pub(crate) struct LoopbackSshServer {
    pub port: u16,
    handle: Option<RunningServerHandle>,
    join: Option<JoinHandle<()>>,
}

impl LoopbackSshServer {
    /// Bind and start serving in a dedicated OS thread. Blocks (briefly) until
    /// the server has bound its socket and reported a control handle back.
    #[must_use]
    pub(crate) fn spawn(cfg: SshServerConfig) -> Self {
        let std_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        std_listener.set_nonblocking(true).expect("set_nonblocking");
        let port = std_listener.local_addr().expect("local_addr").port();

        let (handle_tx, handle_rx) = mpsc::channel();
        let join = thread::Builder::new()
            .name("test-sshd".to_owned())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build tokio runtime");
                rt.block_on(async move {
                    let listener = TcpListener::from_std(std_listener).expect("tokio listener");
                    let config = Arc::new(russh::server::Config {
                        keys: vec![cfg.host_key.clone()],
                        auth_rejection_time: Duration::from_millis(10),
                        auth_rejection_time_initial: Some(Duration::from_millis(0)),
                        inactivity_timeout: Some(Duration::from_secs(30)),
                        ..Default::default()
                    });
                    let mut server = TestServer { cfg };
                    let running = server.run_on_socket(config, &listener);
                    let handle = running.handle();
                    // Best-effort: if the receiver already went away (test
                    // aborted early) there is nothing useful to do.
                    let _ = handle_tx.send(handle);
                    let _ = running.await;
                });
            })
            .expect("spawn test sshd thread");

        let handle = handle_rx.recv_timeout(Duration::from_secs(5)).ok();
        Self {
            port,
            handle,
            join: Some(join),
        }
    }

    /// Ask the server to stop and wait for its thread to exit. Idempotent.
    pub(crate) fn shutdown(&mut self) {
        if let Some(h) = self.handle.take() {
            h.shutdown("test server shutdown".to_owned());
        }
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for LoopbackSshServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Clone)]
struct TestServer {
    cfg: SshServerConfig,
}

impl ServerTrait for TestServer {
    type Handler = TestHandler;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> TestHandler {
        TestHandler {
            cfg: self.cfg.clone(),
        }
    }
}

/// Per-connection handler. No real shell runs; `data` echoes bytes back so
/// the client's VT engine renders real transport round-trip output (the
/// "echo probe").
struct TestHandler {
    cfg: SshServerConfig,
}

impl Handler for TestHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        match &self.cfg.accept_password {
            Some(expected) if expected == password => Ok(Auth::Accept),
            _ => Ok(Auth::reject()),
        }
    }

    async fn auth_publickey(&mut self, _user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        let fp = key.fingerprint(HashAlg::Sha256).to_string();
        match &self.cfg.accept_pubkey_fingerprint {
            Some(expected) if *expected == fp => Ok(Auth::Accept),
            _ => Ok(Auth::reject()),
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<Msg>,
        _session: &mut ServerSession,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        if self.cfg.abrupt_close {
            // Simulate a server crash / hard close right as the shell would
            // start: never reply, just tear the connection down.
            return Err(russh::Error::Disconnect);
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        // Echo probe: bounce received bytes straight back. Proves bytes made
        // a real round trip through the transport and back into the client's
        // VT engine (asserted via the rendered grid in the test).
        session.data(channel, data.to_vec())?;
        Ok(())
    }
}

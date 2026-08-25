//! Interactive TELNET terminal session over a Tokio TCP stream.
//!
//! A dedicated current-thread Tokio runtime owns the socket and the stateful
//! TELNET codec. Only decoded application bytes cross to the libghostty owner
//! thread; negotiation commands and subnegotiations never reach the terminal
//! engine.

mod codec;

use std::future::Future;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use cm_core::TelnetSettings;
use cm_core::terminal::{GridSnapshot, KeyEvent, MouseEvent, TerminalSize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver as TokioReceiver, Sender as TokioSender};
use tokio::sync::watch;

use self::codec::TelnetCodec;
use crate::engine_owner::{Msg, Transport, run_engine_owner};
use crate::libghostty::EngineError;
use crate::session::{Session, SessionInput, SessionStatus, Surface, TerminalSession};

/// Maximum time allowed for opening the TCP connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Bounds user/UI events waiting for the engine owner. On saturation, new
/// UI events are dropped so an input producer cannot block the UI or grow
/// memory. Decoded remote bytes instead await capacity with cancellation.
const CONTROL_QUEUE_CAPACITY: usize = 256;
const CONTROL_RETRY_INTERVAL: Duration = Duration::from_millis(1);
/// Bounds rendered snapshots waiting for the UI. Intermediate snapshots may
/// be dropped; subsequent output or resize supplies a fresh complete snapshot.
const SNAPSHOT_QUEUE_CAPACITY: usize = 8;
/// Bounds encoded terminal records waiting for the socket driver. The engine
/// owner backpressures here until the driver consumes or shutdown drops it.
const OUTBOUND_QUEUE_CAPACITY: usize = 64;
/// Tokio may not be able to cancel an OS resolver's blocking worker. Explicit
/// runtime shutdown bounds the driver join even when such work remains stuck.
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(250);

/// Typed TELNET session errors. Variants never carry terminal payload.
#[derive(Debug, thiserror::Error)]
pub enum TelnetError {
    /// The TCP connection could not be established before the deadline.
    #[error("connect timed out")]
    ConnectTimeout,
    /// The TCP connection could not be established.
    #[error("connect failed: {0}")]
    Connect(String),
    /// Socket I/O failed after connection.
    #[error("I/O failed: {0}")]
    Io(String),
    /// The peer sent an invalid or oversized TELNET protocol frame.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// An OS thread could not be started.
    #[error("failed to start session thread: {0}")]
    Thread(#[source] std::io::Error),
    /// The terminal engine failed to initialize.
    #[error("terminal engine init failed: {0}")]
    Engine(#[source] EngineError),
}

/// Outbound work for the socket driver.
enum Outbound {
    Data(Vec<u8>),
    Newline,
    Resize(TerminalSize),
}

/// TELNET-backed engine transport. Encoding remains in the socket driver so
/// one task owns all parser, negotiation, NVT, and resize state.
struct TelnetTransport {
    out_tx: TokioSender<Outbound>,
}

impl Transport for TelnetTransport {
    fn write(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            let _ = self.out_tx.blocking_send(Outbound::Data(bytes.to_vec()));
        }
    }

    fn write_key(&mut self, bytes: &[u8], newline_intent: bool) {
        if newline_intent {
            let _ = self.out_tx.blocking_send(Outbound::Newline);
        } else {
            self.write(bytes);
        }
    }

    fn resize(&mut self, size: TerminalSize) {
        let _ = self.out_tx.blocking_send(Outbound::Resize(size));
    }
}

/// A live interactive TELNET terminal session.
#[derive(Debug)]
pub struct TelnetTerminalSession {
    control_tx: SyncSender<Msg>,
    surface: Surface,
    status: Arc<Mutex<SessionStatus>>,
    shutdown_tx: watch::Sender<bool>,
    owner_handle: Mutex<Option<JoinHandle<()>>>,
    driver_handle: Mutex<Option<JoinHandle<()>>>,
}

impl TelnetTerminalSession {
    /// Begin connecting and return immediately in [`SessionStatus::Connecting`].
    /// Network and protocol failures are reported asynchronously through
    /// [`TerminalSession::status`].
    ///
    /// # Errors
    /// Returns an error only when synchronous engine or thread setup fails.
    pub fn connect(cfg: &TelnetSettings, size: TerminalSize) -> Result<Self, TelnetError> {
        let (control_tx, control_rx) = mpsc::sync_channel::<Msg>(CONTROL_QUEUE_CAPACITY);
        let (snapshot_tx, snapshot_rx) =
            mpsc::sync_channel::<GridSnapshot>(SNAPSHOT_QUEUE_CAPACITY);
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), EngineError>>();
        let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Outbound>(OUTBOUND_QUEUE_CAPACITY);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let status = Arc::new(Mutex::new(SessionStatus::Connecting));
        let start = Instant::now();

        let owner_handle = thread::Builder::new()
            .name("vt-engine-owner".to_owned())
            .spawn({
                let transport = TelnetTransport { out_tx };
                move || {
                    run_engine_owner(size, transport, &control_rx, &snapshot_tx, &ready_tx, start);
                }
            })
            .map_err(TelnetError::Thread)?;

        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = owner_handle.join();
                return Err(TelnetError::Engine(error));
            }
            Err(_) => {
                let _ = owner_handle.join();
                return Err(TelnetError::Engine(EngineError::Init(
                    "engine owner thread exited".to_owned(),
                )));
            }
        }

        let driver_cfg = cfg.clone();
        let driver_control = control_tx.clone();
        let driver_status = Arc::clone(&status);
        let driver_handle = thread::Builder::new()
            .name("telnet-driver".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        set_status(
                            &driver_status,
                            SessionStatus::Failed(format!("runtime: {error}")),
                        );
                        return;
                    }
                };
                runtime.block_on(drive(
                    driver_cfg,
                    size,
                    &driver_control,
                    out_rx,
                    shutdown_rx,
                    &driver_status,
                    start,
                ));
                shutdown_runtime(runtime);
            })
            .map_err(TelnetError::Thread)?;

        Ok(Self {
            control_tx,
            surface: Surface::TerminalGrid(snapshot_rx),
            status,
            shutdown_tx,
            owner_handle: Mutex::new(Some(owner_handle)),
            driver_handle: Mutex::new(Some(driver_handle)),
        })
    }
}

impl TerminalSession for TelnetTerminalSession {
    fn snapshots(&self) -> &Receiver<GridSnapshot> {
        match &self.surface {
            Surface::TerminalGrid(receiver) => receiver,
            _ => unreachable!("TelnetTerminalSession always has TerminalGrid surface"),
        }
    }

    fn send_key(&self, event: KeyEvent) {
        enqueue_control(&self.control_tx, Msg::Key(event));
    }

    fn send_mouse(&self, event: MouseEvent) {
        enqueue_control(&self.control_tx, Msg::Mouse(event));
    }

    fn paste(&self, bytes: Vec<u8>) {
        enqueue_control(&self.control_tx, Msg::Paste(bytes));
    }

    fn resize(&self, size: TerminalSize) {
        enqueue_control(&self.control_tx, Msg::Resize(size));
    }

    fn set_scroll(&self, offset: u32) {
        enqueue_control(&self.control_tx, Msg::SetScroll(offset));
    }

    fn status(&self) -> SessionStatus {
        self.status
            .lock()
            .map_or(SessionStatus::Disconnected, |status| status.clone())
    }

    fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self
            .driver_handle
            .lock()
            .ok()
            .and_then(|mut guard| guard.take())
        {
            let _ = handle.join();
        }
        // The driver receiver is now dropped, so an engine owner backpressured
        // on the bounded outbound queue is released before this blocking send.
        let _ = self.control_tx.send(Msg::Shutdown);
        if let Some(handle) = self
            .owner_handle
            .lock()
            .ok()
            .and_then(|mut guard| guard.take())
        {
            let _ = handle.join();
        }
        if let Ok(mut status) = self.status.lock()
            && !matches!(*status, SessionStatus::Failed(_))
        {
            *status = SessionStatus::Disconnected;
        }
    }
}

impl Drop for TelnetTerminalSession {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.control_tx.try_send(Msg::Shutdown);
    }
}

impl Session for TelnetTerminalSession {
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
        let cols = u16::try_from(width / 8).unwrap_or(u16::MAX).max(2);
        let rows = u16::try_from(height / 16).unwrap_or(u16::MAX).max(1);
        <Self as TerminalSession>::resize(self, TerminalSize { cols, rows });
    }

    fn resize_cells(&self, cols: u16, rows: u16) {
        <Self as TerminalSession>::resize(self, TerminalSize { cols, rows });
    }

    fn send_input(&self, input: SessionInput) {
        match input {
            SessionInput::Key(event) => <Self as TerminalSession>::send_key(self, event),
            SessionInput::Mouse(event) => <Self as TerminalSession>::send_mouse(self, event),
            SessionInput::Paste(bytes) => <Self as TerminalSession>::paste(self, bytes),
            SessionInput::Scroll(offset) => <Self as TerminalSession>::set_scroll(self, offset),
            SessionInput::Rdp(_) | SessionInput::RdpPaste(_) => {}
        }
    }

    fn request_search_text(&self, reply: Sender<Vec<String>>) {
        match self.control_tx.try_send(Msg::QueryBuffer(reply)) {
            Ok(()) => {}
            Err(TrySendError::Full(Msg::QueryBuffer(reply)))
            | Err(TrySendError::Disconnected(Msg::QueryBuffer(reply))) => {
                let _ = reply.send(Vec::new());
            }
            Err(_) => unreachable!("try_send returns the submitted message"),
        }
    }
}

fn set_status(status: &Arc<Mutex<SessionStatus>>, new_status: SessionStatus) {
    if let Ok(mut status) = status.lock() {
        *status = new_status;
    }
}

/// Nonblocking load shedding at the UI boundary. The terminal input trait has
/// no error return, so saturation is intentionally fail-soft and bounded.
fn enqueue_control(control_tx: &SyncSender<Msg>, message: Msg) {
    let _ = control_tx.try_send(message);
}

fn shutdown_runtime(runtime: tokio::runtime::Runtime) {
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
}

async fn drive(
    cfg: TelnetSettings,
    size: TerminalSize,
    control_tx: &SyncSender<Msg>,
    out_rx: TokioReceiver<Outbound>,
    shutdown_rx: watch::Receiver<bool>,
    status: &Arc<Mutex<SessionStatus>>,
    start: Instant,
) {
    match drive_inner(&cfg, size, control_tx, out_rx, shutdown_rx, status, start).await {
        Ok(()) => {}
        Err(error) => {
            tracing::warn!(
                host = %cfg.host,
                port = cfg.port,
                error = %error,
                "telnet: session failed"
            );
            set_status(status, SessionStatus::Failed(error.to_string()));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive_inner(
    cfg: &TelnetSettings,
    size: TerminalSize,
    control_tx: &SyncSender<Msg>,
    mut out_rx: TokioReceiver<Outbound>,
    mut shutdown_rx: watch::Receiver<bool>,
    status: &Arc<Mutex<SessionStatus>>,
    start: Instant,
) -> Result<(), TelnetError> {
    tracing::info!(host = %cfg.host, port = cfg.port, "telnet: connecting");

    let connect = TcpStream::connect((cfg.host.as_str(), cfg.port));
    let stream = match connect_or_shutdown(connect, &mut shutdown_rx).await? {
        Some(stream) => stream,
        None => {
            set_status(status, SessionStatus::Disconnected);
            return Ok(());
        }
    };
    stream
        .set_nodelay(true)
        .map_err(|error| TelnetError::Io(error.to_string()))?;

    let (mut reader, mut writer) = stream.into_split();
    let mut codec = TelnetCodec::new(size.cols, size.rows);
    let startup = codec.start_negotiation();
    if !write_all_or_shutdown(&mut writer, &startup, &mut shutdown_rx).await? {
        set_status(status, SessionStatus::Disconnected);
        return Ok(());
    }

    set_status(status, SessionStatus::Connected);
    tracing::info!(
        host = %cfg.host,
        port = cfg.port,
        connect_ms = start.elapsed().as_millis(),
        "telnet: connected"
    );

    let result = pump(
        &mut reader,
        &mut writer,
        &mut codec,
        control_tx,
        &mut out_rx,
        &mut shutdown_rx,
        &cfg.host,
        cfg.port,
    )
    .await;

    match result {
        Ok(()) => {
            if !matches!(
                status.lock().ok().as_deref(),
                Some(SessionStatus::Failed(_))
            ) {
                set_status(status, SessionStatus::Disconnected);
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Apply the bounded connect deadline while allowing the session handle to
/// cancel an in-flight OS connection attempt immediately.
async fn connect_or_shutdown<F>(
    connect: F,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<Option<TcpStream>, TelnetError>
where
    F: Future<Output = std::io::Result<TcpStream>>,
{
    if *shutdown_rx.borrow() {
        return Ok(None);
    }
    tokio::select! {
        result = tokio::time::timeout(CONNECT_TIMEOUT, connect) => match result {
            Ok(Ok(stream)) => Ok(Some(stream)),
            Ok(Err(error)) => Err(TelnetError::Connect(error.to_string())),
            Err(_) => Err(TelnetError::ConnectTimeout),
        },
        changed = shutdown_rx.changed() => {
            let _ = changed;
            Ok(None)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn pump(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    codec: &mut TelnetCodec,
    control_tx: &SyncSender<Msg>,
    out_rx: &mut TokioReceiver<Outbound>,
    shutdown_rx: &mut watch::Receiver<bool>,
    host: &str,
    port: u16,
) -> Result<(), TelnetError> {
    let mut buffer = [0_u8; 8192];
    loop {
        tokio::select! {
            read = reader.read(&mut buffer) => {
                let count = read.map_err(|error| TelnetError::Io(error.to_string()))?;
                if count == 0 {
                    let finished = codec.finish();
                    if !finished.application_data.is_empty()
                        && !enqueue_remote_bytes(
                            control_tx,
                            finished.application_data,
                            shutdown_rx,
                        )
                        .await
                    {
                        return Ok(());
                    }
                    tracing::info!(host, port, "telnet: peer closed session");
                    return Ok(());
                }
                let output = codec
                    .receive(&buffer[..count])
                    .map_err(|error| TelnetError::Protocol(error.to_string()))?;
                if output.warn_remote_echo_unavailable {
                    tracing::warn!(
                        host,
                        port,
                        "telnet: remote ECHO unavailable; typed characters may not be visible"
                    );
                }
                if !output.socket_bytes.is_empty()
                    && !write_all_or_shutdown(writer, &output.socket_bytes, shutdown_rx).await?
                {
                    return Ok(());
                }
                if !output.application_data.is_empty()
                    && !enqueue_remote_bytes(control_tx, output.application_data, shutdown_rx).await
                {
                    return Ok(());
                }
            }
            outbound = out_rx.recv() => match outbound {
                Some(Outbound::Data(bytes)) => {
                    let mut encoded = codec.encode_application(&bytes);
                    encoded.extend_from_slice(&codec.flush_outbound());
                    if !encoded.is_empty()
                        && !write_all_or_shutdown(writer, &encoded, shutdown_rx).await?
                    {
                        return Ok(());
                    }
                }
                Some(Outbound::Newline) => {
                    let encoded = codec.encode_newline();
                    if !write_all_or_shutdown(writer, &encoded, shutdown_rx).await? {
                        return Ok(());
                    }
                }
                Some(Outbound::Resize(size)) => {
                    let encoded = codec.resize(size.cols, size.rows);
                    if !encoded.is_empty()
                        && !write_all_or_shutdown(writer, &encoded, shutdown_rx).await?
                    {
                        return Ok(());
                    }
                }
                None => return Ok(()),
            },
            changed = shutdown_rx.changed() => {
                let _ = changed;
                tracing::info!(host, port, "telnet: session shut down");
                return Ok(());
            }
        }
    }
}

/// Hostile remote output shares the fixed control queue with UI events, but is
/// lossless: retain and retry the same complete decoded chunk while the queue
/// is full. Pausing this future backpressures socket reads. Shutdown cancels the
/// wait so a saturated owner can never hold the driver join indefinitely.
async fn enqueue_remote_bytes(
    control_tx: &SyncSender<Msg>,
    bytes: Vec<u8>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> bool {
    let mut message = Msg::Bytes(bytes);
    loop {
        match control_tx.try_send(message) {
            Ok(()) => return true,
            Err(TrySendError::Disconnected(_)) => return false,
            Err(TrySendError::Full(returned)) => message = returned,
        }
        tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                let _ = changed;
                return false;
            }
            () = tokio::time::sleep(CONTROL_RETRY_INTERVAL) => {}
        }
    }
}

/// Write one complete TELNET record while keeping session shutdown
/// responsive even when a peer stops reading and the TCP send buffer fills.
async fn write_all_or_shutdown(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    bytes: &[u8],
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<bool, TelnetError> {
    if *shutdown_rx.borrow() {
        return Ok(false);
    }
    tokio::select! {
        biased;
        changed = shutdown_rx.changed() => {
            let _ = changed;
            Ok(false)
        }
        result = writer.write_all(bytes) => {
            result
                .map(|()| true)
                .map_err(|error| TelnetError::Io(error.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_interrupts_pending_connect() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let sender = tokio::spawn(async move {
            tokio::task::yield_now().await;
            shutdown_tx.send(true).expect("signal shutdown");
        });
        let pending = std::future::pending::<std::io::Result<TcpStream>>();
        let started = Instant::now();
        let result = connect_or_shutdown(pending, &mut shutdown_rx)
            .await
            .expect("shutdown is not a connect error");

        assert!(result.is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
        sender.await.expect("shutdown sender task");
    }

    #[test]
    fn control_queue_is_bounded_and_load_sheds() {
        let (control_tx, control_rx) = mpsc::sync_channel(CONTROL_QUEUE_CAPACITY);
        for offset in 0..CONTROL_QUEUE_CAPACITY + 32 {
            enqueue_control(
                &control_tx,
                Msg::SetScroll(u32::try_from(offset).expect("test offset")),
            );
        }
        assert_eq!(control_rx.try_iter().count(), CONTROL_QUEUE_CAPACITY);
    }

    #[tokio::test]
    async fn remote_output_backpressures_without_losing_the_chunk() {
        let (control_tx, control_rx) = mpsc::sync_channel(1);
        control_tx
            .send(Msg::SetScroll(7))
            .expect("fill control queue");
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let marker = b"lossless-remote-marker".to_vec();
        let enqueue = enqueue_remote_bytes(&control_tx, marker.clone(), &mut shutdown_rx);
        tokio::pin!(enqueue);

        tokio::select! {
            result = &mut enqueue => panic!("remote enqueue did not backpressure: {result}"),
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
        assert!(matches!(control_rx.try_recv(), Ok(Msg::SetScroll(7))));
        assert!(enqueue.await);
        match control_rx.try_recv().expect("retained remote chunk") {
            Msg::Bytes(bytes) => assert_eq!(bytes, marker),
            _ => panic!("unexpected control message"),
        }
    }

    #[tokio::test]
    async fn saturated_remote_enqueue_is_shutdown_cancellable() {
        let (control_tx, _control_rx) = mpsc::sync_channel(1);
        control_tx
            .send(Msg::SetScroll(7))
            .expect("fill control queue");
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let sender = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            shutdown_tx.send(true).expect("signal shutdown");
        });

        let started = Instant::now();
        assert!(
            !enqueue_remote_bytes(&control_tx, vec![b'x'; 8192], &mut shutdown_rx).await,
            "shutdown must cancel the saturated enqueue"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        sender.await.expect("shutdown sender task");
    }

    #[test]
    fn outbound_queue_backpressures_and_receiver_drop_cancels_sender() {
        let (out_tx, out_rx) = tokio::sync::mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
        let (progress_tx, progress_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut transport = TelnetTransport { out_tx };
            for _ in 0..OUTBOUND_QUEUE_CAPACITY + 1 {
                transport.write(b"x");
                progress_tx.send(()).expect("record completed send");
            }
        });

        for _ in 0..OUTBOUND_QUEUE_CAPACITY {
            progress_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("queue capacity should be available");
        }
        assert!(
            progress_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "the send beyond capacity must backpressure"
        );
        drop(out_rx);
        progress_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("receiver drop must release the blocked sender");
        worker.join().expect("outbound producer thread");
    }

    #[test]
    fn runtime_shutdown_is_bounded_with_stuck_blocking_work() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build test runtime");
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        runtime.spawn_blocking(move || {
            started_tx.send(()).expect("announce blocking task");
            let _ = release_rx.recv();
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("blocking task started");

        let started = Instant::now();
        shutdown_runtime(runtime);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "runtime shutdown exceeded its explicit bound: {:?}",
            started.elapsed()
        );
        release_tx.send(()).expect("release detached blocking task");
    }
}

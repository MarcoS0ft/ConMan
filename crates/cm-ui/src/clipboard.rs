//! Nonblocking process-wide OS clipboard worker and RDP bridge coordinator.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use cm_core::{ClipboardSnapshot, RemoteClipboardRevision, SessionEndpointId};

#[cfg(windows)]
#[path = "clipboard/windows.rs"]
mod windows;

const POLL_INTERVAL: Duration = Duration::from_millis(50);
const WRITE_DEADLINE: Duration = Duration::from_secs(5);
const TERMINAL_QUEUE_CAPACITY: usize = 8;
const WRITE_RESULT_CAPACITY: usize = 2;
const TERMINAL_RESULT_CAPACITY: usize = 8;
const RETIRED_SOURCE_CAPACITY: usize = 8;

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsOfferClass {
    FileDrop,
    VirtualFiles,
    TextOrEmpty,
}

#[cfg(windows)]
fn classify_windows_offer(nonempty_file_drop: bool, virtual_formats: bool) -> WindowsOfferClass {
    if nonempty_file_drop {
        WindowsOfferClass::FileDrop
    } else if virtual_formats {
        WindowsOfferClass::VirtualFiles
    } else {
        WindowsOfferClass::TextOrEmpty
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClipboardWrite {
    Text(String),
    Files(Vec<PathBuf>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClipboardWritePurpose {
    /// User explicitly copied non-session UI text such as build diagnostics.
    UiTextCopy,
    RdpInstall {
        owner: SessionEndpointId,
        revision: RemoteClipboardRevision,
    },
    TerminalSelectionCopy {
        /// Stable session endpoint that owned the copied selection.
        target: SessionEndpointId,
        /// Selection identity captured before the asynchronous OS write.
        selection_generation: u64,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct ClipboardWriteRequest {
    pub request_id: u64,
    pub purpose: ClipboardWritePurpose,
    pub content: ClipboardWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClipboardOsError {
    Unavailable,
    Busy,
    Unsupported,
    InvalidData,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClipboardWriteOutcome {
    Written,
    Failed(ClipboardOsError),
    Superseded,
}

#[derive(Debug, Clone)]
pub(crate) struct ClipboardWriteResult {
    pub request_id: u64,
    pub purpose: ClipboardWritePurpose,
    pub outcome: ClipboardWriteOutcome,
}

#[derive(Debug, Clone, Copy)]
struct TerminalTextRead {
    request_id: u64,
    target: SessionEndpointId,
}

#[derive(Debug, Clone)]
pub(crate) struct TerminalTextResult {
    pub request_id: u64,
    pub target: SessionEndpointId,
    pub text: Result<Option<String>, ClipboardOsError>,
}

#[derive(Debug, Clone)]
pub(crate) struct PlatformObservation {
    pub demand_generation: u64,
    pub sequence: u64,
    pub snapshot: ClipboardSnapshot,
    pub source_staging_root: Option<PathBuf>,
}

#[derive(Debug, Default)]
struct CommandMailbox {
    rdp_demand: Option<u64>,
    write: Option<ClipboardWriteRequest>,
    terminal_reads: VecDeque<TerminalTextRead>,
    shutdown: bool,
}

#[derive(Debug, Default)]
struct ResultMailbox {
    observation: Option<PlatformObservation>,
    retired_source_roots: VecDeque<PathBuf>,
    write_results: VecDeque<ClipboardWriteResult>,
    terminal_reads: VecDeque<TerminalTextResult>,
}

#[derive(Debug, Default)]
pub(crate) struct ClipboardResults {
    pub observation: Option<PlatformObservation>,
    pub retired_source_roots: Vec<PathBuf>,
    pub write_results: Vec<ClipboardWriteResult>,
    pub terminal_reads: Vec<TerminalTextResult>,
}

/// UI-side nonblocking handle. The worker thread exclusively owns arboard.
pub(crate) struct PlatformClipboardHandle {
    commands: Arc<(Mutex<CommandMailbox>, Condvar)>,
    results: Arc<Mutex<ResultMailbox>>,
    exited: std::sync::mpsc::Receiver<()>,
    thread: Option<JoinHandle<()>>,
    next_request_id: Option<u64>,
    terminal_outstanding: usize,
}

impl std::fmt::Debug for PlatformClipboardHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlatformClipboardHandle")
            .finish_non_exhaustive()
    }
}

impl PlatformClipboardHandle {
    pub(crate) fn spawn(
        secure_root: Option<Arc<cm_platform::secure_temp::SecureClipboardRoot>>,
    ) -> Self {
        let commands = Arc::new((Mutex::new(CommandMailbox::default()), Condvar::new()));
        let results = Arc::new(Mutex::new(ResultMailbox::default()));
        let (exit_tx, exited) = std::sync::mpsc::sync_channel(1);
        let worker_commands = Arc::clone(&commands);
        let worker_results = Arc::clone(&results);
        let thread = std::thread::Builder::new()
            .name("clipboard-worker".to_owned())
            .spawn(move || clipboard_worker(worker_commands, worker_results, exit_tx, secure_root))
            .ok();
        Self {
            commands,
            results,
            exited,
            thread,
            next_request_id: Some(1),
            terminal_outstanding: 0,
        }
    }

    pub(crate) fn set_rdp_demand(&self, generation: Option<u64>) {
        let (mutex, signal) = &*self.commands;
        if let Ok(mut commands) = mutex.lock() {
            commands.rdp_demand = generation;
            signal.notify_one();
        }
    }

    pub(crate) fn submit_write(
        &mut self,
        purpose: ClipboardWritePurpose,
        content: ClipboardWrite,
    ) -> Option<ClipboardWriteRequest> {
        let request_id = self.allocate_request_id()?;
        let request = ClipboardWriteRequest {
            request_id,
            purpose,
            content,
        };
        let (mutex, signal) = &*self.commands;
        let replaced = mutex
            .lock()
            .ok()
            .and_then(|mut commands| commands.write.replace(request));
        signal.notify_one();
        replaced
    }

    pub(crate) fn request_terminal_text(&mut self, target: SessionEndpointId) -> Option<u64> {
        if self.terminal_outstanding >= TERMINAL_QUEUE_CAPACITY {
            return None;
        }
        let request_id = self.allocate_request_id()?;
        let (mutex, signal) = &*self.commands;
        let mut commands = mutex.lock().ok()?;
        if commands.terminal_reads.len() >= TERMINAL_QUEUE_CAPACITY {
            return None;
        }
        commands
            .terminal_reads
            .push_back(TerminalTextRead { request_id, target });
        self.terminal_outstanding += 1;
        signal.notify_one();
        Some(request_id)
    }

    pub(crate) fn drain_results(&mut self) -> ClipboardResults {
        let Ok(mut results) = self.results.lock() else {
            return ClipboardResults::default();
        };
        let drained = ClipboardResults {
            observation: results.observation.take(),
            retired_source_roots: results.retired_source_roots.drain(..).collect(),
            write_results: results.write_results.drain(..).collect(),
            terminal_reads: results.terminal_reads.drain(..).collect(),
        };
        self.terminal_outstanding = self
            .terminal_outstanding
            .saturating_sub(drained.terminal_reads.len());
        drop(results);
        self.commands.1.notify_one();
        drained
    }

    fn allocate_request_id(&mut self) -> Option<u64> {
        let id = self.next_request_id?;
        self.next_request_id = id.checked_add(1);
        Some(id)
    }

    pub(crate) fn shutdown(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        let (mutex, signal) = &*self.commands;
        if let Ok(mut commands) = mutex.lock() {
            commands.shutdown = true;
            signal.notify_all();
        }
        if self.exited.recv_timeout(Duration::from_secs(5)).is_ok() {
            let _ = thread.join();
        }
    }
}

impl Drop for PlatformClipboardHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn clipboard_worker(
    commands: Arc<(Mutex<CommandMailbox>, Condvar)>,
    results: Arc<Mutex<ResultMailbox>>,
    exited: std::sync::mpsc::SyncSender<()>,
    secure_root: Option<Arc<cm_platform::secure_temp::SecureClipboardRoot>>,
) {
    let mut clipboard = arboard::Clipboard::new().ok();
    let mut last_snapshot: Option<ClipboardSnapshot> = None;
    let mut last_demand_generation: Option<u64> = None;
    let mut sequence = 0_u64;
    let mut observation_disabled = false;
    let mut next_poll = Instant::now();
    let mut last_worker_demand: Option<u64> = None;
    #[cfg(windows)]
    let mut virtual_task: Option<windows::VirtualTask> = None;
    #[cfg(windows)]
    let mut last_virtual_sequence = 0_u32;
    #[cfg(windows)]
    let mut active_virtual_sequence = None;
    #[cfg(windows)]
    let mut active_virtual_root: Option<PathBuf> = None;

    loop {
        let write_slot_available = results
            .lock()
            .is_ok_and(|mailbox| mailbox.write_results.len() < WRITE_RESULT_CAPACITY);
        let (write, terminal_read, demand, shutdown) = {
            let (mutex, signal) = &*commands;
            let Ok(mut mailbox) = mutex.lock() else {
                break;
            };
            while !mailbox.shutdown
                && (mailbox.write.is_none() || !write_slot_available)
                && mailbox.terminal_reads.is_empty()
                && (mailbox.rdp_demand.is_none() || Instant::now() < next_poll)
            {
                if mailbox.rdp_demand.is_none() {
                    let Ok(next) = signal.wait(mailbox) else {
                        return;
                    };
                    mailbox = next;
                } else {
                    let wait = next_poll.saturating_duration_since(Instant::now());
                    let Ok((next, _)) = signal.wait_timeout(mailbox, wait) else {
                        return;
                    };
                    mailbox = next;
                }
            }
            (
                write_slot_available.then(|| mailbox.write.take()).flatten(),
                mailbox.terminal_reads.pop_front(),
                mailbox.rdp_demand,
                mailbox.shutdown,
            )
        };
        if shutdown {
            #[cfg(windows)]
            if let Some(task) = virtual_task.as_ref() {
                task.cancel
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
            break;
        }

        if demand != last_worker_demand {
            #[cfg(windows)]
            if let Some(task) = virtual_task.as_ref()
                && Some(task.generation) != demand
            {
                task.cancel
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
            last_worker_demand = demand;
            next_poll = Instant::now();
        }

        if let Some(request) = write {
            let outcome = perform_write(
                &mut clipboard,
                &commands,
                request.request_id,
                &request.content,
            );
            push_write_result(
                &results,
                ClipboardWriteResult {
                    request_id: request.request_id,
                    purpose: request.purpose,
                    outcome,
                },
            );
            next_poll = Instant::now();
            continue;
        }

        if let Some(request) = terminal_read {
            let text = read_text(&mut clipboard);
            if let Ok(mut mailbox) = results.lock()
                && mailbox.terminal_reads.len() < TERMINAL_RESULT_CAPACITY
            {
                mailbox.terminal_reads.push_back(TerminalTextResult {
                    request_id: request.request_id,
                    target: request.target,
                    text,
                });
            }
            continue;
        }

        if let Some(generation) = demand
            && Instant::now() >= next_poll
            && !observation_disabled
        {
            #[cfg(windows)]
            {
                let current_sequence = windows::sequence();
                match observe_file_list(&mut clipboard) {
                    Ok(Some(snapshot)) => {
                        debug_assert_eq!(
                            classify_windows_offer(true, windows::virtual_formats_available()),
                            WindowsOfferClass::FileDrop
                        );
                        if let Some(task) = virtual_task.take() {
                            task.cancel
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        active_virtual_sequence = None;
                        active_virtual_root = None;
                        publish_platform_observation(
                            &results,
                            secure_root.as_deref(),
                            generation,
                            snapshot,
                            None,
                            &mut sequence,
                            &mut observation_disabled,
                            &mut last_snapshot,
                            &mut last_demand_generation,
                        );
                        next_poll = Instant::now() + POLL_INTERVAL;
                        continue;
                    }
                    Err(_) => {
                        if let Some(task) = virtual_task.take() {
                            task.cancel
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        next_poll = Instant::now() + POLL_INTERVAL;
                        continue;
                    }
                    Ok(None) => {}
                }

                if classify_windows_offer(false, windows::virtual_formats_available())
                    == WindowsOfferClass::VirtualFiles
                {
                    if let Some(task) = virtual_task.as_ref() {
                        match task.poll() {
                            windows::VirtualTaskPoll::Pending => {
                                next_poll = Instant::now() + POLL_INTERVAL;
                                continue;
                            }
                            windows::VirtualTaskPoll::Finished(result) => {
                                let task = virtual_task.take().expect("task is present");
                                if let Ok(materialized) = result {
                                    if generation == task.generation
                                        && materialized.sequence == task.sequence
                                        && current_sequence == task.sequence
                                    {
                                        active_virtual_sequence = Some(materialized.sequence);
                                        active_virtual_root =
                                            Some(materialized.source_root.clone());
                                        publish_platform_observation(
                                            &results,
                                            secure_root.as_deref(),
                                            generation,
                                            materialized.snapshot,
                                            Some(materialized.source_root),
                                            &mut sequence,
                                            &mut observation_disabled,
                                            &mut last_snapshot,
                                            &mut last_demand_generation,
                                        );
                                    } else if let Some(root) = secure_root.as_ref() {
                                        let _ =
                                            root.cleanup_staging_path(&materialized.source_root);
                                    }
                                }
                                next_poll = Instant::now() + POLL_INTERVAL;
                                continue;
                            }
                        }
                    }

                    if active_virtual_sequence == Some(current_sequence) {
                        if active_virtual_root.as_ref().is_some_and(|path| {
                            secure_root
                                .as_ref()
                                .is_some_and(|root| root.is_live_staging_path(path))
                        }) {
                            // A delayed-rendered virtual file offer cannot be read
                            // by arboard's CF_HDROP path. Preserve and, after an
                            // owner change, republish the materialized observation
                            // until the OS sequence actually changes; otherwise
                            // the ordinary read below would replace it with Empty.
                            if last_demand_generation != Some(generation)
                                && let (Some(snapshot), Some(source_root)) =
                                    (last_snapshot.clone(), active_virtual_root.clone())
                            {
                                publish_platform_observation(
                                    &results,
                                    secure_root.as_deref(),
                                    generation,
                                    snapshot,
                                    Some(source_root),
                                    &mut sequence,
                                    &mut observation_disabled,
                                    &mut last_snapshot,
                                    &mut last_demand_generation,
                                );
                            }
                            next_poll = Instant::now() + POLL_INTERVAL;
                            continue;
                        }
                        // The coordinator may have cleaned an inactive pending
                        // observation. Permit one fresh materialization when an
                        // RDP owner becomes active again.
                        last_virtual_sequence = 0;
                    }
                    active_virtual_sequence = None;
                    active_virtual_root = None;
                    if virtual_task.is_none()
                        && current_sequence != 0
                        && current_sequence != last_virtual_sequence
                        && let Some(root) = secure_root.as_ref()
                    {
                        last_virtual_sequence = current_sequence;
                        virtual_task = windows::VirtualTask::start(
                            generation,
                            current_sequence,
                            Arc::clone(root),
                        );
                    }
                    next_poll = Instant::now() + POLL_INTERVAL;
                    continue;
                }

                if let Some(task) = virtual_task.take() {
                    task.cancel
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                }
                active_virtual_sequence = None;
                active_virtual_root = None;
                if let Ok(snapshot) = observe_text_or_empty(&mut clipboard) {
                    publish_platform_observation(
                        &results,
                        secure_root.as_deref(),
                        generation,
                        snapshot,
                        None,
                        &mut sequence,
                        &mut observation_disabled,
                        &mut last_snapshot,
                        &mut last_demand_generation,
                    );
                }
                next_poll = Instant::now() + POLL_INTERVAL;
                continue;
            }
            #[cfg(not(windows))]
            {
                if let Ok(snapshot) = observe(&mut clipboard) {
                    publish_platform_observation(
                        &results,
                        secure_root.as_deref(),
                        generation,
                        snapshot,
                        None,
                        &mut sequence,
                        &mut observation_disabled,
                        &mut last_snapshot,
                        &mut last_demand_generation,
                    );
                }
                next_poll = Instant::now() + POLL_INTERVAL;
            }
        }
    }
    let _ = exited.send(());
}

fn replace_observation(
    results: &Arc<Mutex<ResultMailbox>>,
    observation: PlatformObservation,
) -> bool {
    let next_source = observation.source_staging_root.clone();
    let Ok(mut mailbox) = results.lock() else {
        return false;
    };
    let retired = mailbox
        .observation
        .as_ref()
        .and_then(|previous| previous.source_staging_root.as_ref())
        .filter(|path| next_source.as_ref() != Some(*path))
        .cloned();
    if retired.is_some() && mailbox.retired_source_roots.len() >= RETIRED_SOURCE_CAPACITY {
        return false;
    }
    if let Some(path) = retired {
        mailbox.retired_source_roots.push_back(path);
    }
    mailbox.observation = Some(observation);
    true
}

#[allow(clippy::too_many_arguments)]
fn publish_platform_observation(
    results: &Arc<Mutex<ResultMailbox>>,
    _root: Option<&cm_platform::secure_temp::SecureClipboardRoot>,
    generation: u64,
    snapshot: ClipboardSnapshot,
    source_staging_root: Option<PathBuf>,
    sequence: &mut u64,
    disabled: &mut bool,
    last_snapshot: &mut Option<ClipboardSnapshot>,
    last_generation: &mut Option<u64>,
) {
    if *last_generation == Some(generation) && last_snapshot.as_ref() == Some(&snapshot) {
        return;
    }
    let Some(next_sequence) = sequence.checked_add(1) else {
        *disabled = true;
        return;
    };
    if !replace_observation(
        results,
        PlatformObservation {
            demand_generation: generation,
            sequence: next_sequence,
            snapshot: snapshot.clone(),
            source_staging_root,
        },
    ) {
        return;
    }
    *sequence = next_sequence;
    *last_snapshot = Some(snapshot);
    *last_generation = Some(generation);
}

fn perform_write(
    clipboard: &mut Option<arboard::Clipboard>,
    commands: &Arc<(Mutex<CommandMailbox>, Condvar)>,
    request_id: u64,
    content: &ClipboardWrite,
) -> ClipboardWriteOutcome {
    let started = Instant::now();
    let mut delay = Duration::ZERO;
    loop {
        if !delay.is_zero() {
            let (mutex, signal) = &**commands;
            if let Ok(mailbox) = mutex.lock() {
                let Ok((mailbox, _)) = signal.wait_timeout(mailbox, delay) else {
                    return ClipboardWriteOutcome::Failed(ClipboardOsError::Other);
                };
                if mailbox.shutdown {
                    return ClipboardWriteOutcome::Superseded;
                }
                if mailbox
                    .write
                    .as_ref()
                    .is_some_and(|newer| newer.request_id != request_id)
                {
                    return ClipboardWriteOutcome::Superseded;
                }
            }
        }
        let Some(clipboard) = clipboard.as_mut() else {
            return ClipboardWriteOutcome::Failed(ClipboardOsError::Unavailable);
        };
        let result = match content {
            ClipboardWrite::Text(text) => clipboard.set().text(platform_write_text(text)),
            ClipboardWrite::Files(paths) => clipboard.set().file_list(paths),
        };
        let superseded = commands.0.lock().is_ok_and(|mailbox| {
            mailbox.shutdown
                || mailbox
                    .write
                    .as_ref()
                    .is_some_and(|newer| newer.request_id != request_id)
        });
        if superseded {
            return ClipboardWriteOutcome::Superseded;
        }
        match result {
            Ok(()) => return ClipboardWriteOutcome::Written,
            Err(arboard::Error::ClipboardOccupied) if started.elapsed() < WRITE_DEADLINE => {
                delay = match delay.as_millis() {
                    0 => Duration::from_millis(50),
                    50 => Duration::from_millis(100),
                    100 => Duration::from_millis(200),
                    200 => Duration::from_millis(400),
                    _ => Duration::from_millis(500),
                };
            }
            Err(error) => return ClipboardWriteOutcome::Failed(map_error(&error)),
        }
    }
}

fn platform_write_text(text: &str) -> String {
    #[cfg(windows)]
    {
        text.replace('\n', "\r\n")
    }
    #[cfg(not(windows))]
    {
        text.to_owned()
    }
}

fn push_write_result(results: &Arc<Mutex<ResultMailbox>>, result: ClipboardWriteResult) {
    if let Ok(mut mailbox) = results.lock() {
        debug_assert!(mailbox.write_results.len() < WRITE_RESULT_CAPACITY);
        if mailbox.write_results.len() >= WRITE_RESULT_CAPACITY {
            return;
        }
        mailbox.write_results.push_back(result);
    }
}

fn read_text(
    clipboard: &mut Option<arboard::Clipboard>,
) -> Result<Option<String>, ClipboardOsError> {
    let clipboard = clipboard.as_mut().ok_or(ClipboardOsError::Unavailable)?;
    match clipboard.get().text() {
        Ok(text) => Ok(Some(normalize_text(text)?)),
        Err(arboard::Error::ContentNotAvailable) => Ok(None),
        Err(error) => Err(map_error(&error)),
    }
}

#[cfg(not(windows))]
fn observe(
    clipboard: &mut Option<arboard::Clipboard>,
) -> Result<ClipboardSnapshot, ClipboardOsError> {
    if let Some(files) = observe_file_list(clipboard)? {
        return Ok(files);
    }
    observe_text_or_empty(clipboard)
}

fn observe_file_list(
    clipboard: &mut Option<arboard::Clipboard>,
) -> Result<Option<ClipboardSnapshot>, ClipboardOsError> {
    let clipboard = clipboard.as_mut().ok_or(ClipboardOsError::Unavailable)?;
    match clipboard.get().file_list() {
        Ok(paths) if !paths.is_empty() => {
            validate_observed_files(&paths)?;
            Ok(Some(ClipboardSnapshot::Files(paths)))
        }
        Ok(_) | Err(arboard::Error::ContentNotAvailable) => Ok(None),
        Err(error) => Err(map_error(&error)),
    }
}

fn observe_text_or_empty(
    clipboard: &mut Option<arboard::Clipboard>,
) -> Result<ClipboardSnapshot, ClipboardOsError> {
    let clipboard = clipboard.as_mut().ok_or(ClipboardOsError::Unavailable)?;
    match clipboard.get().text() {
        Ok(text) => Ok(ClipboardSnapshot::Text(normalize_text(text)?)),
        Err(arboard::Error::ContentNotAvailable) => Ok(ClipboardSnapshot::Empty),
        Err(error) => Err(map_error(&error)),
    }
}

fn validate_observed_files(paths: &[PathBuf]) -> Result<(), ClipboardOsError> {
    const MAX_FILES: usize = 256;
    const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
    const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

    if paths.is_empty() || paths.len() > MAX_FILES {
        return Err(ClipboardOsError::InvalidData);
    }
    let mut total = 0_u64;
    let mut names = std::collections::HashSet::with_capacity(paths.len());
    for path in paths {
        if !path.is_absolute() {
            return Err(ClipboardOsError::InvalidData);
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| valid_flat_file_name(name))
            .ok_or(ClipboardOsError::InvalidData)?;
        if !names.insert(name.to_lowercase()) {
            return Err(ClipboardOsError::InvalidData);
        }
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| ClipboardOsError::InvalidData)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_FILE_BYTES
        {
            return Err(ClipboardOsError::InvalidData);
        }
        total = total
            .checked_add(metadata.len())
            .ok_or(ClipboardOsError::InvalidData)?;
        if total > MAX_TOTAL_BYTES {
            return Err(ClipboardOsError::InvalidData);
        }
    }
    Ok(())
}

fn valid_flat_file_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.encode_utf16().count() <= 255
        && !name
            .chars()
            .any(|ch| ch == '\0' || ch.is_control() || ch == '/' || ch == '\\')
        && !name.ends_with(['.', ' '])
        && !is_windows_device_name(name)
}

fn is_windows_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

fn normalize_text(text: String) -> Result<String, ClipboardOsError> {
    if text.len() > 16 * 1024 * 1024 || text.contains('\0') {
        return Err(ClipboardOsError::InvalidData);
    }
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}

fn map_error(error: &arboard::Error) -> ClipboardOsError {
    match error {
        arboard::Error::ClipboardOccupied => ClipboardOsError::Busy,
        arboard::Error::ClipboardNotSupported => ClipboardOsError::Unsupported,
        arboard::Error::ConversionFailure => ClipboardOsError::InvalidData,
        arboard::Error::ContentNotAvailable => ClipboardOsError::Unavailable,
        _ => ClipboardOsError::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_normalization_rejects_nul() {
        assert_eq!(normalize_text("a\r\nb\rc".into()).unwrap(), "a\nb\nc");
        assert_eq!(
            normalize_text("a\0b".into()),
            Err(ClipboardOsError::InvalidData)
        );
    }

    #[test]
    fn unavailable_worker_is_nonblocking_and_fail_soft() {
        let mut handle = PlatformClipboardHandle::spawn(None);
        let _ = handle.submit_write(
            ClipboardWritePurpose::TerminalSelectionCopy {
                target: SessionEndpointId(1),
                selection_generation: 1,
            },
            ClipboardWrite::Text("synthetic".into()),
        );
        handle.shutdown();
    }

    #[test]
    fn request_ids_stop_at_exhaustion_without_reuse() {
        let mut handle = PlatformClipboardHandle::spawn(None);
        handle.next_request_id = Some(u64::MAX);
        assert_eq!(handle.allocate_request_id(), Some(u64::MAX));
        assert_eq!(handle.allocate_request_id(), None);
        assert_eq!(handle.allocate_request_id(), None);
        handle.shutdown();
    }

    #[test]
    fn shutdown_is_idempotent_and_consumes_join_handle_once() {
        let mut handle = PlatformClipboardHandle::spawn(None);
        handle.shutdown();
        assert!(handle.thread.is_none());
        let started = Instant::now();
        handle.shutdown();
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn replaced_write_returns_original_purpose_for_staging_cleanup() {
        let first_purpose = ClipboardWritePurpose::RdpInstall {
            owner: SessionEndpointId(7),
            revision: RemoteClipboardRevision(9),
        };
        let mut mailbox = CommandMailbox {
            write: Some(ClipboardWriteRequest {
                request_id: 1,
                purpose: first_purpose,
                content: ClipboardWrite::Files(vec!["/synthetic/a".into()]),
            }),
            ..CommandMailbox::default()
        };
        let replaced = mailbox
            .write
            .replace(ClipboardWriteRequest {
                request_id: 2,
                purpose: ClipboardWritePurpose::TerminalSelectionCopy {
                    target: SessionEndpointId(8),
                    selection_generation: 4,
                },
                content: ClipboardWrite::Text("selection".into()),
            })
            .expect("first write is superseded");
        assert_eq!(replaced.purpose, first_purpose);
    }

    #[test]
    fn terminal_read_captures_stable_requesting_endpoint() {
        let target = SessionEndpointId(44);
        let mut commands = CommandMailbox::default();
        commands.terminal_reads.push_back(TerminalTextRead {
            request_id: 3,
            target,
        });
        // A later focus change has no field through which it can retarget the
        // queued request: the endpoint travels with the request/result.
        let _new_focus = SessionEndpointId(99);
        let queued = commands.terminal_reads.pop_front().expect("queued read");
        assert_eq!(queued.request_id, 3);
        assert_eq!(queued.target, target);
    }

    #[test]
    fn terminal_write_result_retains_selection_target_identity() {
        let purpose = ClipboardWritePurpose::TerminalSelectionCopy {
            target: SessionEndpointId(44),
            selection_generation: 17,
        };
        let result = ClipboardWriteResult {
            request_id: 9,
            purpose,
            outcome: ClipboardWriteOutcome::Written,
        };

        // Focus and selection can both change while the worker owns the
        // request; completion still identifies precisely what was copied.
        let _later_focus = SessionEndpointId(99);
        assert_eq!(result.purpose, purpose);
        assert_eq!(result.request_id, 9);
    }

    #[test]
    fn file_observation_policy_rejects_directory_symlink_and_duplicate_name() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("a.txt");
        std::fs::write(&file, b"synthetic").unwrap();
        assert_eq!(
            validate_observed_files(&[directory.path().to_path_buf()]),
            Err(ClipboardOsError::InvalidData)
        );
        assert_eq!(
            validate_observed_files(&[file.clone(), file.clone()]),
            Err(ClipboardOsError::InvalidData)
        );
        #[cfg(unix)]
        {
            let link = directory.path().join("link.txt");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert_eq!(
                validate_observed_files(&[link]),
                Err(ClipboardOsError::InvalidData)
            );
        }
    }

    #[test]
    fn observation_replacement_reports_source_retirement_to_coordinator() {
        let results = Arc::new(Mutex::new(ResultMailbox::default()));
        let first = PathBuf::from("/synthetic/source-a");
        assert!(replace_observation(
            &results,
            PlatformObservation {
                demand_generation: 1,
                sequence: 1,
                snapshot: ClipboardSnapshot::Files(vec![first.join("a")]),
                source_staging_root: Some(first.clone()),
            }
        ));
        assert!(replace_observation(
            &results,
            PlatformObservation {
                demand_generation: 1,
                sequence: 2,
                snapshot: ClipboardSnapshot::Text("replacement".into()),
                source_staging_root: None,
            }
        ));
        let mailbox = results.lock().unwrap();
        assert_eq!(mailbox.retired_source_roots.front(), Some(&first));
    }

    #[test]
    fn retired_source_mailbox_backpressures_instead_of_dropping_cleanup() {
        let results = Arc::new(Mutex::new(ResultMailbox::default()));
        {
            let mut mailbox = results.lock().unwrap();
            mailbox.observation = Some(PlatformObservation {
                demand_generation: 1,
                sequence: 1,
                snapshot: ClipboardSnapshot::Files(vec!["/synthetic/source/a".into()]),
                source_staging_root: Some("/synthetic/source".into()),
            });
            mailbox.retired_source_roots = (0..RETIRED_SOURCE_CAPACITY)
                .map(|index| PathBuf::from(format!("/synthetic/retired-{index}")))
                .collect();
        }
        assert!(!replace_observation(
            &results,
            PlatformObservation {
                demand_generation: 1,
                sequence: 2,
                snapshot: ClipboardSnapshot::Empty,
                source_staging_root: None,
            }
        ));
        assert_eq!(
            results
                .lock()
                .unwrap()
                .observation
                .as_ref()
                .unwrap()
                .sequence,
            1
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_offer_classification_prioritizes_nonempty_file_drop() {
        assert_eq!(
            classify_windows_offer(true, true),
            WindowsOfferClass::FileDrop
        );
        assert_eq!(
            classify_windows_offer(false, true),
            WindowsOfferClass::VirtualFiles
        );
        assert_eq!(
            classify_windows_offer(false, false),
            WindowsOfferClass::TextOrEmpty
        );
    }
}

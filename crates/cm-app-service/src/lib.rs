//! Native-only runtime for the neutral, bounded `cm_core::application` port.
//!
//! This crate owns no HTTP, Slint, wire, or database implementation. Its
//! event-loop-local facade pumps owned commands across bounded standard
//! channels to one serialized native worker.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::Path;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};

use cm_core::application::{
    AppCommand, AppError, AppEvent, AppNotification, AppResult, Application,
    ApplicationFailureKind, ApplicationMailbox, RequestId, ResultClass, SubmitError,
};
use cm_platform::{WorkspaceGuard, WorkspaceLockError};

const CHANNEL_CAPACITY: usize = 64;
const PUMP_BUDGET: usize = 64;

/// Backend implemented by a native command executor.
///
/// The runtime selects the C1 result class before dispatch. Implementations
/// must return bounded results matching the C1 command/result table.
pub trait NativeCommandBackend: Send + 'static {
    /// Execute one accepted command on the serialized native worker.
    ///
    /// `request_id` is local C1 correlation and is available for the
    /// service-epoch outcome map. It is never a wire UUID.
    fn execute(
        &mut self,
        request_id: RequestId,
        command: AppCommand,
    ) -> Result<AppResult, AppError>;
}

/// Error reported while constructing a backend after acquiring workspace
/// ownership.
#[derive(Debug)]
pub struct BackendInitError {
    message: String,
}

impl BackendInitError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for BackendInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for BackendInitError {}

/// Failure to construct the native service.
#[derive(Debug)]
pub enum ServiceStartError {
    Workspace(WorkspaceLockError),
    Backend(BackendInitError),
    Worker(io::Error),
}

impl fmt::Display for ServiceStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workspace(error) => write!(formatter, "workspace ownership failed: {error}"),
            Self::Backend(error) => {
                write!(formatter, "native backend initialization failed: {error}")
            }
            Self::Worker(error) => write!(formatter, "native worker start failed: {error}"),
        }
    }
}

impl std::error::Error for ServiceStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Workspace(error) => Some(error),
            Self::Backend(error) => Some(error),
            Self::Worker(error) => Some(error),
        }
    }
}

/// State returned by a nonblocking shutdown poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownProgress {
    Running,
    WorkerFinished,
    Finished,
}

/// Failure while finalizing a native service shutdown.
#[derive(Debug)]
pub enum ShutdownError {
    NotStarted,
    WorkerNotFinished,
    WorkerPanicked,
}

impl fmt::Display for ShutdownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotStarted => formatter.write_str("shutdown has not started"),
            Self::WorkerNotFinished => formatter.write_str("native worker is still running"),
            Self::WorkerPanicked => formatter.write_str("native worker panicked"),
        }
    }
}

impl std::error::Error for ShutdownError {}

/// Cloneable event-loop-local handle implementing the frozen core port.
#[derive(Clone, Debug)]
pub struct NativeApplication {
    shared: Rc<RefCell<Shared>>,
}

impl Application for NativeApplication {
    fn submit(&self, command: AppCommand) -> Result<RequestId, SubmitError> {
        let mut shared = self.shared.borrow_mut();
        if shared.closed {
            return Err(SubmitError::Closed);
        }
        let request_id = shared.mailbox.accept(command)?;
        let previous = shared.requests.insert(request_id, DispatchState::Queued);
        debug_assert!(previous.is_none());
        Ok(request_id)
    }

    fn try_recv(&self) -> Option<AppEvent> {
        let mut shared = self.shared.borrow_mut();
        let event = shared.mailbox.try_recv()?;
        if let AppEvent::Completed { request_id, .. } = &event {
            shared.requests.remove(request_id);
        }
        Some(event)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchState {
    Queued,
    Dispatched,
    Completed,
}

#[derive(Debug)]
struct Shared {
    mailbox: ApplicationMailbox,
    requests: HashMap<RequestId, DispatchState>,
    closed: bool,
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            mailbox: ApplicationMailbox::default(),
            requests: HashMap::with_capacity(CHANNEL_CAPACITY),
            closed: false,
        }
    }
}

#[derive(Debug)]
struct WorkItem {
    request_id: RequestId,
    result_class: ResultClass,
    command: AppCommand,
}

#[derive(Debug)]
struct Completion {
    request_id: RequestId,
    result: Result<AppResult, AppError>,
}

/// Owner-thread service facade. Call `pump` from the owning event loop.
#[derive(Debug)]
pub struct NativeApplicationService {
    shared: Rc<RefCell<Shared>>,
    dispatch_tx: Option<SyncSender<WorkItem>>,
    completion_rx: Receiver<Completion>,
    worker: Option<JoinHandle<()>>,
    stopping: bool,
    failure_handled: bool,
    finalized: bool,
}

impl NativeApplicationService {
    /// Acquire the canonical workspace before invoking the backend factory.
    pub fn start<B, F>(workspace: &Path, backend_factory: F) -> Result<Self, ServiceStartError>
    where
        B: NativeCommandBackend,
        F: FnOnce() -> Result<B, BackendInitError>,
    {
        let workspace_guard =
            WorkspaceGuard::acquire(workspace).map_err(ServiceStartError::Workspace)?;
        let backend = backend_factory().map_err(ServiceStartError::Backend)?;

        let (dispatch_tx, dispatch_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let (completion_tx, completion_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let worker = thread::Builder::new()
            .name("conman-app-service".to_owned())
            .spawn(move || worker_main(backend, workspace_guard, dispatch_rx, completion_tx))
            .map_err(ServiceStartError::Worker)?;

        Ok(Self {
            shared: Rc::new(RefCell::new(Shared::default())),
            dispatch_tx: Some(dispatch_tx),
            completion_rx,
            worker: Some(worker),
            stopping: false,
            failure_handled: false,
            finalized: false,
        })
    }

    /// Return a cloneable, local handle for the C1 application port.
    #[must_use]
    pub fn application(&self) -> NativeApplication {
        NativeApplication {
            shared: Rc::clone(&self.shared),
        }
    }

    /// Pump at most 64 accepted commands and worker completions combined.
    pub fn pump(&mut self) -> PumpReport {
        if self.finalized {
            return PumpReport::default();
        }

        let mut report = PumpReport::default();
        let mut budget = PUMP_BUDGET;
        if self.drain_worker_completions(&mut budget, &mut report) {
            report.closed = true;
            if !self.stopping {
                self.fail_service();
            }
            return report;
        }

        if self.dispatch_tx.is_some() {
            while budget > 0 {
                let next = self.shared.borrow_mut().mailbox.take_command();
                let Some((request_id, command)) = next else {
                    break;
                };
                budget -= 1;
                let result_class = result_class_for(&command);
                let reservation = self
                    .shared
                    .borrow_mut()
                    .mailbox
                    .reserve_result(request_id, result_class);
                if reservation.is_err() {
                    self.enqueue_completion(request_id, Err(AppError::ResourceLimit));
                    report.completed += 1;
                    continue;
                }

                let work = WorkItem {
                    request_id,
                    result_class,
                    command,
                };
                match self
                    .dispatch_tx
                    .as_ref()
                    .expect("checked above")
                    .try_send(work)
                {
                    Ok(()) => {
                        self.set_dispatch_state(request_id, DispatchState::Dispatched);
                        report.dispatched += 1;
                    }
                    Err(TrySendError::Full(work)) => {
                        // With one bounded slot per C1 accepted-request credit,
                        // Full is unreachable unless the accounting invariant
                        // has been broken. The taken request is still tracked.
                        self.set_dispatch_state(request_id, DispatchState::Queued);
                        drop(work);
                        let disconnected = self.drain_worker_completions(&mut budget, &mut report);
                        report.closed |= disconnected;
                        self.fail_service();
                        report.closed = true;
                        break;
                    }
                    Err(TrySendError::Disconnected(work)) => {
                        self.set_dispatch_state(request_id, DispatchState::Queued);
                        drop(work);
                        let disconnected = self.drain_worker_completions(&mut budget, &mut report);
                        report.closed |= disconnected;
                        self.fail_service();
                        report.closed = true;
                        break;
                    }
                }
            }
        }

        if self.stopping && self.dispatch_tx.is_some() {
            // C1 has at most 64 accepted requests total. The loop above has
            // therefore taken every queued command before reaching this point.
            self.dispatch_tx.take();
        }

        let disconnected = self.drain_worker_completions(&mut budget, &mut report);
        if disconnected {
            if !self.stopping {
                self.fail_service();
            }
            report.closed = true;
        }
        report
    }

    /// Close new submissions. Continue calling `pump` until shutdown finishes.
    pub fn begin_shutdown(&mut self) {
        if self.finalized || self.stopping {
            return;
        }
        self.stopping = true;
        self.shared.borrow_mut().closed = true;
    }

    /// Pump pending work and report whether the worker exited. Never blocks.
    pub fn poll_shutdown(&mut self) -> ShutdownProgress {
        if self.finalized {
            return ShutdownProgress::Finished;
        }
        if !self.stopping {
            return ShutdownProgress::Running;
        }
        let _ = self.pump();
        if self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            ShutdownProgress::WorkerFinished
        } else {
            ShutdownProgress::Running
        }
    }

    /// Join and finalize after `poll_shutdown` reports `WorkerFinished`.
    /// Returns immediately with `WorkerNotFinished` if the join would block.
    pub fn finish_shutdown(&mut self) -> Result<(), ShutdownError> {
        if self.finalized {
            return Ok(());
        }
        if !self.stopping {
            return Err(ShutdownError::NotStarted);
        }
        if !self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            return Err(ShutdownError::WorkerNotFinished);
        }

        // Drain worker completions before joining, preserving their successful
        // results rather than replacing them with shutdown uncertainty.
        let _ = self.pump();
        let worker = self.worker.take().expect("worker exists until finalized");
        let join = worker.join();
        self.dispatch_tx.take();
        match join {
            Ok(()) => {
                self.finalized = true;
                Ok(())
            }
            Err(_) => {
                self.fail_service();
                self.finalized = true;
                Err(ShutdownError::WorkerPanicked)
            }
        }
    }

    fn enqueue_completion(&mut self, request_id: RequestId, result: Result<AppResult, AppError>) {
        let mut shared = self.shared.borrow_mut();
        let enqueue = shared.mailbox.enqueue_completion(request_id, result);
        debug_assert!(enqueue.is_ok(), "C1 reserved completion must enqueue");
        if enqueue.is_ok() {
            shared.requests.insert(request_id, DispatchState::Completed);
        }
    }

    /// Drain at most the remaining per-pump budget. `true` means the worker
    /// sender has disconnected and its buffered completions have been drained.
    fn drain_worker_completions(&mut self, budget: &mut usize, report: &mut PumpReport) -> bool {
        while *budget > 0 {
            match self.completion_rx.try_recv() {
                Ok(completion) => {
                    *budget -= 1;
                    report.completed += 1;
                    // After emergency settlement, a still-running worker may
                    // produce a late result for an ID already completed as
                    // uncertain/stopping. Drop it to preserve exactly-once C1
                    // completion semantics.
                    if !self.failure_handled {
                        self.enqueue_completion(completion.request_id, completion.result);
                    }
                }
                Err(TryRecvError::Empty) => return false,
                Err(TryRecvError::Disconnected) => return true,
            }
        }
        false
    }

    fn set_dispatch_state(&mut self, request_id: RequestId, state: DispatchState) {
        if let Some(current) = self.shared.borrow_mut().requests.get_mut(&request_id) {
            *current = state;
        }
    }

    fn fail_service(&mut self) {
        if self.finalized || self.failure_handled {
            return;
        }
        self.failure_handled = true;
        self.stopping = true;
        let mut shared = self.shared.borrow_mut();
        shared.closed = true;

        // Discard commands still owned by the event-loop mailbox. The bounded
        // state map retains their IDs and C1 has already reserved each error.
        while shared.mailbox.take_command().is_some() {}

        let unsettled = shared
            .requests
            .iter()
            .map(|(id, state)| (*id, *state))
            .collect::<Vec<_>>();
        for (request_id, state) in unsettled {
            let error = match state {
                DispatchState::Queued => AppError::ServiceStopping,
                DispatchState::Dispatched => AppError::TransportUncertain { request_id },
                DispatchState::Completed => continue,
            };
            let enqueue = shared.mailbox.enqueue_completion(request_id, Err(error));
            debug_assert!(enqueue.is_ok(), "C1 reserved completion must enqueue");
            if enqueue.is_ok() {
                shared.requests.insert(request_id, DispatchState::Completed);
            }
        }

        let _ = shared
            .mailbox
            .enqueue_notification(AppNotification::ApplicationFailure {
                reason: ApplicationFailureKind::ServiceStopping,
            });
        self.dispatch_tx.take();
    }
}

impl Drop for NativeApplicationService {
    fn drop(&mut self) {
        if !self.finalized {
            // Emergency shutdown never blocks the owner thread. The worker
            // closure retains WorkspaceGuard through backend teardown.
            let mut budget = PUMP_BUDGET;
            let mut report = PumpReport::default();
            let _ = self.drain_worker_completions(&mut budget, &mut report);
            self.fail_service();
        }
    }
}

/// Per-pump work performed by the owner event loop.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PumpReport {
    pub dispatched: usize,
    pub completed: usize,
    pub closed: bool,
}

struct WorkerResources<B> {
    backend: Option<B>,
    workspace_guard: Option<WorkspaceGuard>,
}

impl<B> Drop for WorkerResources<B> {
    fn drop(&mut self) {
        // Explicit order makes the lock outlive backend teardown on return or
        // unwind. If backend Drop panics, remaining fields still drop with the
        // resource object.
        drop(self.backend.take());
        drop(self.workspace_guard.take());
    }
}

fn worker_main<B: NativeCommandBackend>(
    backend: B,
    workspace_guard: WorkspaceGuard,
    dispatch_rx: Receiver<WorkItem>,
    completion_tx: SyncSender<Completion>,
) {
    let mut resources = WorkerResources {
        backend: Some(backend),
        workspace_guard: Some(workspace_guard),
    };
    while let Ok(work) = dispatch_rx.recv() {
        debug_assert_eq!(work.result_class, result_class_for(&work.command));
        let result = resources
            .backend
            .as_mut()
            .expect("backend lives through worker loop")
            .execute(work.request_id, work.command);
        let completion = Completion {
            request_id: work.request_id,
            result,
        };
        if completion_tx.send(completion).is_err() {
            break;
        }
    }
    drop(resources);
}

fn result_class_for(command: &AppCommand) -> ResultClass {
    match command {
        AppCommand::Bootstrap | AppCommand::ListWorkspace | AppCommand::ExportSecretFree => {
            ResultClass::Workspace
        }
        AppCommand::ImportPreview { .. } => ResultClass::ImportPreview,
        AppCommand::SearchTerminal { .. } => ResultClass::Search,
        AppCommand::QueryOutcome { .. }
        | AppCommand::RequestControl
        | AppCommand::Mutate { .. }
        | AppCommand::OpenSession { .. }
        | AppCommand::CloseSession { .. }
        | AppCommand::DetachSession { .. }
        | AppCommand::AttachSession { .. }
        | AppCommand::SessionInput { .. }
        | AppCommand::ResizeSession { .. }
        | AppCommand::SetViewport { .. }
        | AppCommand::ClipboardPasteText { .. }
        | AppCommand::RespondChallenge { .. } => ResultClass::Standard,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cm_core::application::{
        Capability, ImportFormat, SearchCursor, SearchDirection, SessionId,
    };
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::{Duration, Instant};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    type CompletionEvents = Vec<(RequestId, Result<AppResult, AppError>)>;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("cm-app-service-test-{}-{id}", std::process::id()));
            std::fs::create_dir(&path).expect("unique temporary directory");
            Self(path)
        }

        fn canonical(&self) -> PathBuf {
            std::fs::canonicalize(&self.0).unwrap()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Debug)]
    struct FailureBackend;

    impl NativeCommandBackend for FailureBackend {
        fn execute(
            &mut self,
            _request_id: RequestId,
            _command: AppCommand,
        ) -> Result<AppResult, AppError> {
            Err(AppError::CapabilityUnavailable {
                capability: Capability::ControlTransfer,
            })
        }
    }

    fn start_failure_service(workspace: &Path) -> NativeApplicationService {
        NativeApplicationService::start(workspace, || Ok(FailureBackend)).unwrap()
    }

    fn request_control() -> AppCommand {
        AppCommand::RequestControl
    }

    fn collect_completions(
        app: &NativeApplication,
        expected: usize,
        timeout: Duration,
    ) -> (CompletionEvents, bool) {
        let deadline = Instant::now() + timeout;
        let mut completions = Vec::with_capacity(expected);
        let mut service_stopping = false;
        while completions.len() < expected && Instant::now() < deadline {
            match app.try_recv() {
                Some(AppEvent::Completed { request_id, result }) => {
                    completions.push((request_id, result));
                }
                Some(AppEvent::Notification(AppNotification::ApplicationFailure {
                    reason: ApplicationFailureKind::ServiceStopping,
                })) => service_stopping = true,
                Some(AppEvent::Notification(_)) | None => {}
            }
            if completions.len() < expected {
                thread::sleep(Duration::from_millis(1));
            }
        }
        if !service_stopping {
            for _ in 0..cm_core::application::EVENT_CAPACITY {
                match app.try_recv() {
                    Some(AppEvent::Notification(AppNotification::ApplicationFailure {
                        reason: ApplicationFailureKind::ServiceStopping,
                    })) => service_stopping = true,
                    Some(_) => {}
                    None => break,
                }
            }
        }
        (completions, service_stopping)
    }

    fn pump_until_completed(
        service: &mut NativeApplicationService,
        expected: usize,
        timeout: Duration,
    ) {
        let deadline = Instant::now() + timeout;
        while service.shared.borrow().mailbox.queued_event_count() < expected
            && Instant::now() < deadline
        {
            service.pump();
            thread::sleep(Duration::from_millis(1));
        }
        assert!(service.shared.borrow().mailbox.queued_event_count() >= expected);
    }

    #[test]
    fn startup_acquires_guard_before_calling_backend_factory() {
        let workspace = TempDir::new();
        let canonical = workspace.canonical();
        let mut invoked = false;
        let service = NativeApplicationService::start(&canonical, || {
            invoked = true;
            Ok(FailureBackend)
        })
        .unwrap();
        assert!(invoked);

        let mut second_factory_called = false;
        let second = NativeApplicationService::start(&canonical, || {
            second_factory_called = true;
            Ok(FailureBackend)
        });
        assert!(matches!(
            second,
            Err(ServiceStartError::Workspace(
                WorkspaceLockError::AlreadyOwned
            ))
        ));
        assert!(!second_factory_called);
        drop(service);
    }

    #[test]
    fn result_class_mapping_matches_frozen_c1_table() {
        assert_eq!(
            result_class_for(&AppCommand::Bootstrap),
            ResultClass::Workspace
        );
        assert_eq!(
            result_class_for(&AppCommand::ListWorkspace),
            ResultClass::Workspace
        );
        assert_eq!(
            result_class_for(&AppCommand::ExportSecretFree),
            ResultClass::Workspace
        );
        assert_eq!(
            result_class_for(&AppCommand::ImportPreview {
                format: ImportFormat::ConManJson,
                filename: String::new(),
                bytes: Vec::new(),
            }),
            ResultClass::ImportPreview
        );
        assert_eq!(
            result_class_for(&AppCommand::SearchTerminal {
                session_id: SessionId(1),
                session_generation: 1,
                query: String::new(),
                direction: SearchDirection::Forward,
                from: SearchCursor {
                    row: 0,
                    column: 0,
                    surface_sequence: 0,
                },
            }),
            ResultClass::Search
        );
        assert_eq!(
            result_class_for(&AppCommand::RequestControl),
            ResultClass::Standard
        );
    }

    #[test]
    fn result_reservations_happen_before_worker_dispatch() {
        let workspace = TempDir::new();
        let mut service = start_failure_service(&workspace.canonical());
        let app = service.application();
        let _first = app.submit(AppCommand::Bootstrap).unwrap();
        let second = app.submit(AppCommand::Bootstrap).unwrap();

        let report = service.pump();
        assert_eq!(report.dispatched, 1);
        assert!(report.completed >= 1);
        pump_until_completed(&mut service, 2, Duration::from_secs(2));
        let (completions, _) = collect_completions(&app, 2, Duration::from_secs(2));
        assert_eq!(completions.len(), 2);
        assert!(
            completions
                .iter()
                .any(|(id, result)| *id == second && *result == Err(AppError::ResourceLimit))
        );

        service.begin_shutdown();
        wait_for_shutdown(&mut service);
        service.finish_shutdown().unwrap();
    }

    #[test]
    fn sixty_four_requests_complete_and_release_c1_credit() {
        let workspace = TempDir::new();
        let mut service = start_failure_service(&workspace.canonical());
        let app = service.application();
        let mut ids = Vec::with_capacity(CHANNEL_CAPACITY);
        for _ in 0..CHANNEL_CAPACITY {
            ids.push(app.submit(request_control()).unwrap());
        }
        assert_eq!(app.submit(request_control()), Err(SubmitError::QueueFull));

        service.pump();
        pump_until_completed(&mut service, CHANNEL_CAPACITY, Duration::from_secs(3));
        let (completions, _) = collect_completions(&app, CHANNEL_CAPACITY, Duration::from_secs(1));
        assert_eq!(completions.len(), CHANNEL_CAPACITY);
        let mut got = completions
            .iter()
            .map(|(request_id, _)| *request_id)
            .collect::<Vec<_>>();
        got.sort_unstable();
        ids.sort_unstable();
        assert_eq!(got, ids);
        assert_eq!(service.shared.borrow().mailbox.accepted_count(), 0);

        service.begin_shutdown();
        wait_for_shutdown(&mut service);
        service.finish_shutdown().unwrap();
    }

    #[test]
    fn emergency_drop_settles_queued_work_for_retained_handle() {
        let workspace = TempDir::new();
        let service = start_failure_service(&workspace.canonical());
        let app = service.application();
        for _ in 0..CHANNEL_CAPACITY {
            app.submit(request_control()).unwrap();
        }

        drop(service);
        let (completions, service_stopping) =
            collect_completions(&app, CHANNEL_CAPACITY, Duration::from_secs(1));
        assert_eq!(completions.len(), CHANNEL_CAPACITY);
        assert!(
            completions
                .iter()
                .all(|(_, result)| *result == Err(AppError::ServiceStopping))
        );
        assert!(service_stopping);
        assert_eq!(app.submit(request_control()), Err(SubmitError::Closed));
        assert_eq!(app.shared.borrow().mailbox.accepted_count(), 0);
    }

    #[test]
    fn emergency_drop_preserves_completion_already_queued_for_ui() {
        let workspace = TempDir::new();
        let mut service = start_failure_service(&workspace.canonical());
        let app = service.application();
        let request_id = app.submit(request_control()).unwrap();
        service.pump();
        pump_until_completed(&mut service, 1, Duration::from_secs(2));

        drop(service);
        let (completions, service_stopping) = collect_completions(&app, 1, Duration::from_secs(1));
        assert_eq!(
            completions,
            vec![(
                request_id,
                Err(AppError::CapabilityUnavailable {
                    capability: Capability::ControlTransfer,
                })
            )]
        );
        assert!(service_stopping);
    }

    #[derive(Debug)]
    struct PanicBackend;

    impl NativeCommandBackend for PanicBackend {
        fn execute(
            &mut self,
            _request_id: RequestId,
            _command: AppCommand,
        ) -> Result<AppResult, AppError> {
            panic!("intentional worker failure test");
        }
    }

    #[test]
    fn worker_panic_settles_dispatched_work_as_uncertain() {
        let workspace = TempDir::new();
        let mut service =
            NativeApplicationService::start(&workspace.canonical(), || Ok(PanicBackend)).unwrap();
        let app = service.application();
        for _ in 0..CHANNEL_CAPACITY {
            app.submit(request_control()).unwrap();
        }
        service.pump();

        let deadline = Instant::now() + Duration::from_secs(3);
        while !service.worker.as_ref().unwrap().is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(service.worker.as_ref().unwrap().is_finished());
        service.pump();

        let (completions, service_stopping) =
            collect_completions(&app, CHANNEL_CAPACITY, Duration::from_secs(1));
        assert_eq!(completions.len(), CHANNEL_CAPACITY);
        assert!(completions.iter().all(|(id, result)| {
            matches!(
                result,
                Err(AppError::TransportUncertain { request_id }) if request_id == id
            ) || *result == Err(AppError::ServiceStopping)
        }));
        assert!(
            completions
                .iter()
                .any(|(_, result)| matches!(result, Err(AppError::TransportUncertain { .. })))
        );
        assert!(service_stopping);
        assert_eq!(service.shared.borrow().mailbox.accepted_count(), 0);
        assert_eq!(service.poll_shutdown(), ShutdownProgress::WorkerFinished);
        assert!(matches!(
            service.finish_shutdown(),
            Err(ShutdownError::WorkerPanicked)
        ));
    }

    #[derive(Debug)]
    struct SuccessThenPanicBackend {
        calls: usize,
        entered_tx: mpsc::SyncSender<()>,
        release: Arc<Barrier>,
    }

    impl NativeCommandBackend for SuccessThenPanicBackend {
        fn execute(
            &mut self,
            _request_id: RequestId,
            _command: AppCommand,
        ) -> Result<AppResult, AppError> {
            self.calls += 1;
            if self.calls == 1 {
                let _ = self.entered_tx.send(());
                self.release.wait();
                Ok(AppResult::SessionClosed)
            } else {
                panic!("intentional panic after successful completion");
            }
        }
    }

    #[test]
    fn worker_failure_preserves_queued_success_before_settling_other_requests() {
        let workspace = TempDir::new();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let release = Arc::new(Barrier::new(2));
        let worker_release = Arc::clone(&release);
        let mut service = NativeApplicationService::start(&workspace.canonical(), || {
            Ok(SuccessThenPanicBackend {
                calls: 0,
                entered_tx,
                release: worker_release,
            })
        })
        .unwrap();
        let app = service.application();
        let succeeded_id = app.submit(request_control()).unwrap();
        let uncertain_id = app.submit(request_control()).unwrap();
        service.pump();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        release.wait();

        let deadline = Instant::now() + Duration::from_secs(2);
        while !service.worker.as_ref().unwrap().is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(service.worker.as_ref().unwrap().is_finished());
        let never_dispatched_id = app.submit(request_control()).unwrap();

        let report = service.pump();
        assert!(report.closed);
        assert!(report.dispatched + report.completed <= PUMP_BUDGET);
        let (completions, service_stopping) = collect_completions(&app, 3, Duration::from_secs(1));
        assert_eq!(completions.len(), 3);
        assert_eq!(
            completions
                .iter()
                .find(|(id, _)| *id == succeeded_id)
                .map(|(_, result)| result),
            Some(&Ok(AppResult::SessionClosed))
        );
        assert_eq!(
            completions
                .iter()
                .find(|(id, _)| *id == uncertain_id)
                .map(|(_, result)| result),
            Some(&Err(AppError::TransportUncertain {
                request_id: uncertain_id,
            }))
        );
        assert_eq!(
            completions
                .iter()
                .find(|(id, _)| *id == never_dispatched_id)
                .map(|(_, result)| result),
            Some(&Err(AppError::ServiceStopping))
        );
        assert!(service_stopping);
        assert_eq!(app.shared.borrow().mailbox.accepted_count(), 0);
        assert!(!matches!(app.try_recv(), Some(AppEvent::Completed { .. })));
        assert_eq!(report.completed, 1);
    }

    #[derive(Debug)]
    struct BlockingBackend {
        entered_tx: mpsc::SyncSender<()>,
        release: Arc<Barrier>,
        dropped_tx: mpsc::SyncSender<()>,
    }

    impl NativeCommandBackend for BlockingBackend {
        fn execute(
            &mut self,
            _request_id: RequestId,
            _command: AppCommand,
        ) -> Result<AppResult, AppError> {
            let _ = self.entered_tx.send(());
            self.release.wait();
            Err(AppError::PersistenceFailed)
        }
    }

    impl Drop for BlockingBackend {
        fn drop(&mut self) {
            let _ = self.dropped_tx.send(());
        }
    }

    #[test]
    fn worker_retains_workspace_lock_until_backend_teardown_after_facade_drop() {
        let workspace = TempDir::new();
        let canonical = workspace.canonical();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (dropped_tx, dropped_rx) = mpsc::sync_channel(1);
        let release = Arc::new(Barrier::new(2));
        let worker_release = Arc::clone(&release);
        let mut service = NativeApplicationService::start(&canonical, move || {
            Ok(BlockingBackend {
                entered_tx,
                release: worker_release,
                dropped_tx,
            })
        })
        .unwrap();
        let app = service.application();
        for _ in 0..CHANNEL_CAPACITY {
            app.submit(request_control()).unwrap();
        }
        service.pump();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        drop(service);
        let (completions, service_stopping) =
            collect_completions(&app, CHANNEL_CAPACITY, Duration::from_secs(1));
        assert_eq!(completions.len(), CHANNEL_CAPACITY);
        assert!(completions.iter().all(|(id, result)| {
            *result == Err(AppError::TransportUncertain { request_id: *id })
        }));
        assert!(service_stopping);

        let mut factory_called = false;
        assert!(matches!(
            NativeApplicationService::start(&canonical, || {
                factory_called = true;
                Ok(FailureBackend)
            }),
            Err(ServiceStartError::Workspace(
                WorkspaceLockError::AlreadyOwned
            ))
        ));
        assert!(!factory_called);

        release.wait();
        dropped_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match WorkspaceGuard::acquire(&canonical) {
                Ok(guard) => {
                    drop(guard);
                    break;
                }
                Err(WorkspaceLockError::AlreadyOwned) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("workspace guard release failed: {error}"),
            }
        }
    }

    #[test]
    fn late_worker_result_after_emergency_settlement_is_discarded() {
        let workspace = TempDir::new();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (dropped_tx, dropped_rx) = mpsc::sync_channel(1);
        let release = Arc::new(Barrier::new(2));
        let worker_release = Arc::clone(&release);
        let mut service = NativeApplicationService::start(&workspace.canonical(), move || {
            Ok(BlockingBackend {
                entered_tx,
                release: worker_release,
                dropped_tx,
            })
        })
        .unwrap();
        let app = service.application();
        let request_id = app.submit(request_control()).unwrap();
        service.pump();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        // Simulate a fail-closed invariant error while native work is already
        // executing. Its eventual result must not follow the uncertainty event.
        service.fail_service();
        let (completions, service_stopping) = collect_completions(&app, 1, Duration::from_secs(1));
        assert_eq!(
            completions,
            vec![(request_id, Err(AppError::TransportUncertain { request_id }))]
        );
        assert!(service_stopping);

        release.wait();
        dropped_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let report = service.pump();
        assert_eq!(report.completed, 1);
        assert!(!matches!(app.try_recv(), Some(AppEvent::Completed { .. })));
        assert_eq!(app.shared.borrow().mailbox.accepted_count(), 0);
        wait_for_shutdown(&mut service);
        assert_eq!(service.poll_shutdown(), ShutdownProgress::WorkerFinished);
        service.finish_shutdown().unwrap();
    }

    #[test]
    fn normal_shutdown_poll_and_finish_do_not_block_on_running_backend() {
        let workspace = TempDir::new();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (dropped_tx, dropped_rx) = mpsc::sync_channel(1);
        let release = Arc::new(Barrier::new(2));
        let worker_release = Arc::clone(&release);
        let mut service = NativeApplicationService::start(&workspace.canonical(), move || {
            Ok(BlockingBackend {
                entered_tx,
                release: worker_release,
                dropped_tx,
            })
        })
        .unwrap();
        let app = service.application();
        let request_id = app.submit(request_control()).unwrap();
        service.pump();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        service.begin_shutdown();
        assert_eq!(service.poll_shutdown(), ShutdownProgress::Running);
        assert!(matches!(
            service.finish_shutdown(),
            Err(ShutdownError::WorkerNotFinished)
        ));

        release.wait();
        dropped_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        wait_for_shutdown(&mut service);
        service.finish_shutdown().unwrap();
        let (completions, _) = collect_completions(&app, 1, Duration::from_secs(1));
        assert_eq!(
            completions,
            vec![(request_id, Err(AppError::PersistenceFailed))]
        );
    }

    fn wait_for_shutdown(service: &mut NativeApplicationService) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match service.poll_shutdown() {
                ShutdownProgress::WorkerFinished | ShutdownProgress::Finished => return,
                ShutdownProgress::Running if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(1));
                }
                ShutdownProgress::Running => panic!("worker did not stop before deadline"),
            }
        }
    }
}

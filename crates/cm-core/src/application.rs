//! Neutral, event-loop-local application port and its bounded mailbox types.
//!
//! This module contains no runtime, wire protocol, storage, or platform code.
mod snapshot;
pub use snapshot::{
    MAX_WORKSPACE_RECORDS, MAX_WORKSPACE_ROW_DECODE_BYTES, RowDecodePermit, WorkspaceRecordCounts,
    WorkspaceResultOverhead, WorkspaceSnapshotBuilder,
};
use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
    num::NonZeroU64,
    rc::Rc,
    sync::Arc,
};

use crate::{
    AccentColor, Connection, ConnectionId, ConnectionKind, ConnectionSettings, Credential,
    CredentialFolder, CredentialFolderId, CredentialId, CredentialPurpose, CredentialSource,
    Density, ExitStatus, FrameUpdate, GridSnapshot, Group, GroupId, Secret, SessionInput,
    TerminalSize, TerminalTheme, ThemeMode,
};

pub const MAX_ACCEPTED_REQUESTS: usize = 64;
pub const EVENT_CAPACITY: usize = 256;
pub const COMPLETION_RESERVATIONS: usize = 64;
pub const INGRESS_BYTES: usize = 32 * 1024 * 1024;
pub const NOTIFICATION_BYTES: usize = 128 * 1024 * 1024;
const ERROR_RESERVATION: usize = 4 * 1024;
const EVENT_RING_BYTES: usize = EVENT_CAPACITY * size_of::<QueuedEvent>();
const COMMAND_RING_BYTES: usize = MAX_ACCEPTED_REQUESTS * size_of::<(RequestId, AppCommand)>();
const REQUEST_TABLE_BYTES: usize =
    2 * MAX_ACCEPTED_REQUESTS * size_of::<(RequestId, RequestState)>();
const INGRESS_BASE_BYTES: usize =
    EVENT_RING_BYTES + COMMAND_RING_BYTES + REQUEST_TABLE_BYTES + size_of::<ApplicationMailbox>();
const NOTIFICATION_FIXED_BYTES: usize =
    16 * size_of::<(SessionId, MarkerSlot)>() + 512 * size_of::<(usize, (usize, usize))>();

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(NonZeroU64);
impl RequestId {
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkspaceRevision(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChallengeId(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PreviewId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutationMeta {
    pub expected_revision: WorkspaceRevision,
}

pub trait Application {
    fn submit(&self, command: AppCommand) -> Result<RequestId, SubmitError>;
    fn try_recv(&self) -> Option<AppEvent>;
}

#[derive(Debug)]
pub enum AppCommand {
    Bootstrap,
    ListWorkspace,
    QueryOutcome {
        original_request_id: RequestId,
    },
    RequestControl,
    Mutate {
        meta: MutationMeta,
        operation: WorkspaceMutation,
    },
    ImportPreview {
        format: ImportFormat,
        filename: String,
        bytes: Vec<u8>,
    },
    ExportSecretFree,
    OpenSession {
        target: SessionTarget,
        size: TerminalSize,
    },
    CloseSession {
        session_id: SessionId,
        session_generation: u64,
    },
    DetachSession {
        session_id: SessionId,
        session_generation: u64,
    },
    AttachSession {
        session_id: SessionId,
        session_generation: u64,
    },
    SessionInput {
        session_id: SessionId,
        session_generation: u64,
        sequence: u64,
        input: SessionInput,
    },
    ResizeSession {
        session_id: SessionId,
        session_generation: u64,
        cols: u16,
        rows: u16,
    },
    SetViewport {
        session_id: SessionId,
        session_generation: u64,
        offset: u32,
    },
    SearchTerminal {
        session_id: SessionId,
        session_generation: u64,
        query: String,
        direction: SearchDirection,
        from: SearchCursor,
    },
    ClipboardPasteText {
        session_id: SessionId,
        session_generation: u64,
        text: String,
    },
    RespondChallenge {
        session_id: SessionId,
        session_generation: u64,
        challenge_id: ChallengeId,
        response: ChallengeResponse,
    },
}
impl AppCommand {
    /// Return the shared reservation class for this command.
    ///
    /// Native runtimes and transport bridges must derive this from the owned
    /// command before reserving output; callers cannot override the policy.
    #[must_use]
    pub const fn result_class(&self) -> ResultClass {
        match self {
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
}

#[derive(Debug)]
pub enum WorkspaceMutation {
    UpsertConnection {
        value: Connection,
        secret_intent: InlineSecretIntent,
    },
    DeleteConnection {
        id: ConnectionId,
    },
    MoveConnection {
        id: ConnectionId,
        group_id: Option<GroupId>,
        sort: i64,
    },
    UpsertGroup {
        value: Group,
    },
    DeleteGroup {
        id: GroupId,
    },
    MoveGroup {
        id: GroupId,
        parent_id: Option<GroupId>,
        sort: i64,
    },
    UpsertCredential {
        value: Credential,
        secret_intent: CredentialSecretIntent,
    },
    DeleteCredential {
        id: CredentialId,
    },
    UpsertCredentialFolder {
        value: CredentialFolder,
    },
    DeleteCredentialFolder {
        id: CredentialFolderId,
    },
    MoveCredentialFolder {
        id: CredentialFolderId,
        parent_id: Option<CredentialFolderId>,
        sort: i64,
    },
    SetPreferences {
        value: GatewayPreferences,
    },
    ImportCommit {
        preview_id: PreviewId,
        preview_revision: u64,
    },
}
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // Frozen API owns the quick-connect profile directly.
pub enum SessionTarget {
    Saved(ConnectionId),
    QuickConnect(Connection),
    GatewayTerminal,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    ConManJson,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportWarningCode {
    UnsupportedCredential,
    InvalidEntry,
    DuplicateEntry,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundledFont {
    JetBrainsMonoNerdFontMono,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchDirection {
    Forward,
    Backward,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchCursor {
    pub row: u16,
    pub column: u16,
    pub surface_sequence: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchMatch {
    pub start_row: u16,
    pub start_col: u16,
    pub end_row: u16,
    pub end_col: u16,
    pub absolute_line: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResultsDto {
    pub matches: Vec<SearchMatch>,
    pub next_cursor: Option<SearchCursor>,
    pub truncated: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportCounts {
    pub connections: u32,
    pub groups: u32,
    pub credentials: u32,
    pub credential_folders: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportWarningDto {
    pub code: ImportWarningCode,
    pub count: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportPreviewDto {
    pub preview_id: PreviewId,
    pub revision: u64,
    pub format: ImportFormat,
    pub profile_counts: ImportCounts,
    pub warnings: Vec<ImportWarningDto>,
    pub contains_secrets: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportStatsDto {
    pub counts: ImportCounts,
    pub secrets_imported: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportDto {
    pub filename: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayPreferences {
    pub theme: ThemeMode,
    pub accent_color: AccentColor,
    pub density: Density,
    pub terminal_theme: TerminalTheme,
    pub bundled_font: BundledFont,
    pub font_size: u8,
    pub scrollback_limit: u32,
    pub always_show_scrollbar: bool,
    pub plain_copy_paste_shortcuts: bool,
    pub copy_on_select: bool,
    pub confirm_close_active_tab: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveLimits {
    pub max_sessions: u8,
    pub max_rdp_sessions: u8,
    pub max_rdp_width: u16,
    pub max_rdp_height: u16,
    pub max_rdp_aggregate_pixels: u64,
    pub max_terminal_cols: u16,
    pub max_terminal_rows: u16,
    pub max_terminal_history_bytes: u64,
    pub max_import_bytes: u64,
    pub max_clipboard_bytes: u32,
    pub max_secret_bytes: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDto {
    pub id: SessionId,
    pub generation: u64,
    pub kind: ConnectionKind,
    pub status: ApplicationSessionStatus,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceDto {
    pub revision: WorkspaceRevision,
    pub connections: Vec<Connection>,
    pub groups: Vec<Group>,
    pub credentials: Vec<Credential>,
    pub credential_folders: Vec<CredentialFolder>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapDto {
    pub workspace_revision: WorkspaceRevision,
    pub capabilities: Vec<Capability>,
    pub workspace: WorkspaceDto,
    pub preferences: GatewayPreferences,
    pub sessions: Vec<SessionDto>,
    pub limits: EffectiveLimits,
}

#[derive(Debug)]
pub enum InlineSecretIntent {
    Keep,
    Replace(Secret),
    Clear,
}
#[derive(Debug)]
pub enum SecretChange {
    Keep,
    Replace(Secret),
    Clear,
}
#[derive(Debug)]
pub struct CredentialSecretIntent {
    pub password: SecretChange,
    pub ssh_key: SecretChange,
    pub ssh_passphrase: SecretChange,
}
#[derive(Debug)]
pub enum ChallengeResponse {
    AcceptSshHostKey,
    RejectSshHostKey,
    AcceptRdpCertificate,
    RejectRdpCertificate,
    Password(Secret),
    PrivateKey {
        key: Secret,
        passphrase: Option<Secret>,
    },
    KeyboardInteractive(Vec<Secret>),
    Cancel,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionFailureKind {
    Setup,
    Authentication,
    TrustRejected,
    DestinationDenied,
    Timeout,
    Disconnected,
    ResourceLimit,
    Cancelled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationSessionStatus {
    Connecting,
    Connected,
    Disconnected,
    Exited(ExitStatus),
    Failed(SessionFailureKind),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    Ssh,
    Telnet,
    Rdp,
    GatewayTerminal,
    SavedCredentials,
    Import,
    Export,
    TextClipboard,
    Search,
    ControlTransfer,
    SecretStore,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppField {
    Name,
    Host,
    Port,
    Username,
    Domain,
    Group,
    Credential,
    Preference,
    Import,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownOutcomeReason {
    CacheExpired,
    GatewayEpochChanged,
    NotRetained,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationResult {
    ConnectionId(ConnectionId),
    GroupId(GroupId),
    CredentialId(CredentialId),
    CredentialFolderId(CredentialFolderId),
    Deleted,
    Preferences(GatewayPreferences),
    ImportCommitted(ImportStatsDto),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationOutcome {
    Committed {
        revision: WorkspaceRevision,
        result: MutationResult,
    },
    Failed {
        current_revision: WorkspaceRevision,
        error: AppError,
    },
    InProgress,
    Unknown {
        current_revision: WorkspaceRevision,
        reason: UnknownOutcomeReason,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppResult {
    Bootstrap(BootstrapDto),
    Workspace(WorkspaceDto),
    ImportPreview(ImportPreviewDto),
    Export(ExportDto),
    SessionOpened(SessionDto),
    SessionClosed,
    SessionDetached,
    SessionAttached(SessionDto),
    SessionInputAccepted {
        sequence: u64,
    },
    SessionResized {
        cols: u16,
        rows: u16,
    },
    ViewportSet,
    Search(SearchResultsDto),
    ClipboardAccepted {
        sequence: u64,
    },
    ChallengeResponded,
    ControlTransferRequested,
    MutationCommitted {
        revision: WorkspaceRevision,
        result: MutationResult,
    },
    MutationOutcome(MutationOutcome),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppError {
    ResourceLimit,
    RevisionConflict {
        current_revision: WorkspaceRevision,
    },
    NotFound,
    Validation {
        field: AppField,
    },
    CapabilityUnavailable {
        capability: Capability,
    },
    PersistenceFailed,
    SecretStoreUnavailable,
    SecretMutationFailed,
    PartialRequiresReconcile {
        metadata_committed: bool,
        current_revision: WorkspaceRevision,
        affected: Box<[SecretRefId]>,
        affected_total: u32,
        affected_truncated: bool,
    },
    SessionFailed {
        reason: SessionFailureKind,
    },
    /// Accepted work that the service can prove was never dispatched.
    ServiceStopping,
    TransportUncertain {
        request_id: RequestId,
    },
    RevisionExhausted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitError {
    QueueFull,
    Closed,
    RequestIdsExhausted,
    ResourceLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationError {
    ResourceLimit,
    CriticalOverflow(CriticalOverflow),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultClass {
    Standard,
    Workspace,
    ImportPreview,
    Search,
}

impl ResultClass {
    /// Maximum owned C1 completion capacity, including its inline baseline.
    ///
    /// This is not a serialized JSON or wire-message byte limit.
    #[must_use]
    pub const fn limit(self) -> usize {
        match self {
            Self::Standard => ERROR_RESERVATION,
            Self::Workspace => 16 * 1024 * 1024,
            Self::ImportPreview => 768 * 1024,
            Self::Search => 256 * 1024,
        }
    }
}
#[derive(Debug, Clone)]
pub enum AppNotification {
    SessionChanged {
        session_id: SessionId,
        session_generation: u64,
        status: ApplicationSessionStatus,
    },
    TerminalSurface {
        session_id: SessionId,
        session_generation: u64,
        surface: Arc<GridSnapshot>,
    },
    RdpFrame {
        session_id: SessionId,
        session_generation: u64,
        frame: Arc<FrameUpdate>,
    },
    SurfaceResyncRequired {
        session_id: SessionId,
        session_generation: u64,
    },
    ChallengeIssued {
        challenge: ChallengeDto,
    },
    ChallengeCancelled {
        session_id: SessionId,
        session_generation: u64,
        challenge_id: ChallengeId,
    },
    SessionFailed {
        session_id: SessionId,
        session_generation: u64,
        reason: SessionFailureKind,
    },
    ApplicationFailure {
        reason: ApplicationFailureKind,
    },
    ControlTransferred,
    RemoteClipboardOfferedText {
        session_id: SessionId,
        session_generation: u64,
        revision: u64,
        text: String,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeDto {
    pub challenge_id: ChallengeId,
    pub session_id: SessionId,
    pub session_generation: u64,
    pub expires_at_ms: u64,
    pub kind: ChallengeKind,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeKind {
    SshHost {
        host: String,
        fingerprint: String,
        changed: bool,
    },
    RdpCertificate {
        host: String,
        fingerprint: String,
        changed: bool,
    },
    Password,
    PrivateKey,
    KeyboardInteractive(Vec<String>),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationFailureKind {
    NotificationOverflow,
    ServiceStopping,
}
#[derive(Debug, Clone)]
pub enum AppEvent {
    Completed {
        request_id: RequestId,
        result: Result<AppResult, AppError>,
    },
    Notification(AppNotification),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OverflowAction {
    CancelChallenge,
    CancelSession,
    ResyncSurface,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CriticalOverflow {
    pub session_id: SessionId,
    pub generation: u64,
    pub action: OverflowAction,
}

/// Non-secret identity used by bounded reconciliation reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretRefId {
    Connection {
        id: ConnectionId,
        purpose: CredentialPurpose,
    },
    Credential {
        id: CredentialId,
        purpose: CredentialPurpose,
    },
}

/// Event returned from the application port.
#[derive(Debug)]
pub struct ApplicationMailbox {
    next_request: Option<NonZeroU64>,
    accepted: HashMap<RequestId, RequestState>,
    commands: VecDeque<(RequestId, AppCommand)>,
    events: VecDeque<QueuedEvent>,
    notification_bytes: usize,
    shared_allocations: HashMap<usize, (usize, usize)>,
    markers: HashMap<SessionId, MarkerSlot>,
    global_failure: Option<ApplicationFailureKind>,
    _main_thread: PhantomData<Rc<()>>,
}
#[derive(Debug, Clone, Copy)]
struct RequestState {
    command_bytes: usize,
    result_reservation: usize,
    completion_bytes: Option<usize>,
    import_pending: bool,
}
#[derive(Debug)]
struct QueuedEvent {
    event: AppEvent,
    unique_bytes: usize,
    arc: Option<(usize, usize)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Marker {
    generation: u64,
    action: OverflowAction,
}
#[derive(Debug, Clone, Copy)]
struct MarkerSlot {
    marker: Option<Marker>,
    retiring: bool,
}
impl Default for ApplicationMailbox {
    fn default() -> Self {
        Self {
            next_request: NonZeroU64::new(1),
            accepted: HashMap::with_capacity(MAX_ACCEPTED_REQUESTS),
            commands: VecDeque::with_capacity(MAX_ACCEPTED_REQUESTS),
            events: VecDeque::with_capacity(EVENT_CAPACITY),
            notification_bytes: NOTIFICATION_FIXED_BYTES,
            shared_allocations: HashMap::with_capacity(EVENT_CAPACITY),
            markers: HashMap::with_capacity(8),
            global_failure: None,
            _main_thread: PhantomData,
        }
    }
}
impl ApplicationMailbox {
    /// Atomically account and accept an owned command before assigning its ID.
    pub fn accept(&mut self, command: AppCommand) -> Result<RequestId, SubmitError> {
        if self.accepted.len() >= MAX_ACCEPTED_REQUESTS {
            return Err(SubmitError::QueueFull);
        }
        let is_import = matches!(&command, AppCommand::ImportPreview { .. });
        if is_import && self.accepted.values().any(|state| state.import_pending) {
            return Err(SubmitError::ResourceLimit);
        }
        let command_bytes = command_capacity(&command)?;
        let used = self.ingress_bytes()?;
        if used
            .checked_add(command_bytes)
            .and_then(|n| n.checked_add(ERROR_RESERVATION))
            .filter(|n| *n <= INGRESS_BYTES)
            .is_none()
        {
            return Err(SubmitError::ResourceLimit);
        }
        let n = self.next_request.ok_or(SubmitError::RequestIdsExhausted)?;
        self.next_request = n.get().checked_add(1).and_then(NonZeroU64::new);
        let id = RequestId(n);
        self.accepted.insert(
            id,
            RequestState {
                command_bytes,
                result_reservation: 0,
                completion_bytes: None,
                import_pending: is_import,
            },
        );
        self.commands.push_back((id, command));
        Ok(id)
    }
    fn ingress_bytes(&self) -> Result<usize, SubmitError> {
        self.accepted
            .values()
            .try_fold(INGRESS_BASE_BYTES, |sum, state| {
                sum.checked_add(state.command_bytes)?
                    .checked_add(if state.completion_bytes.is_none() {
                        ERROR_RESERVATION
                    } else {
                        0
                    })?
                    .checked_add(state.result_reservation)?
                    .checked_add(state.completion_bytes.unwrap_or(0))
            })
            .ok_or(SubmitError::ResourceLimit)
    }
    /// Transfer an accepted command to its worker. Its bytes remain charged
    /// until the worker completes it.
    pub fn take_command(&mut self) -> Option<(RequestId, AppCommand)> {
        self.commands.pop_front()
    }
    /// Reserve the result class bound before constructing the success result.
    pub fn reserve_result(&mut self, id: RequestId, class: ResultClass) -> Result<(), SubmitError> {
        let state = self.accepted.get(&id).ok_or(SubmitError::Closed)?;
        if state.completion_bytes.is_some() || state.result_reservation != 0 {
            return Err(SubmitError::Closed);
        }
        if self
            .ingress_bytes()?
            .checked_add(class.limit())
            .filter(|n| *n <= INGRESS_BYTES)
            .is_none()
        {
            return Err(SubmitError::ResourceLimit);
        }
        self.accepted
            .get_mut(&id)
            .expect("checked above")
            .result_reservation = class.limit();
        Ok(())
    }
    pub fn enqueue_completion(
        &mut self,
        id: RequestId,
        result: Result<AppResult, AppError>,
    ) -> Result<(), SubmitError> {
        let Some(mut state) = self.accepted.get(&id).copied() else {
            return Err(SubmitError::Closed);
        };
        if state.completion_bytes.is_some() {
            return Err(SubmitError::Closed);
        }
        if self.events.len() >= EVENT_CAPACITY {
            return Err(SubmitError::QueueFull);
        }
        let (result, bytes) = match result {
            Err(error) => match error_capacity(&error) {
                Ok(bytes) if bytes <= ERROR_RESERVATION => (Err(error), bytes),
                _ => (Err(AppError::ResourceLimit), ERROR_RESERVATION),
            },
            Ok(value) => match result_capacity(&value) {
                Ok(bytes) if state.result_reservation != 0 && bytes <= state.result_reservation => {
                    (Ok(value), bytes)
                }
                _ => (Err(AppError::ResourceLimit), ERROR_RESERVATION),
            },
        };
        if let Some(index) = self
            .commands
            .iter()
            .position(|(request_id, _)| *request_id == id)
        {
            self.commands.remove(index);
        }
        state.command_bytes = 0;
        state.result_reservation = 0;
        state.completion_bytes = Some(bytes);
        state.import_pending = false;
        self.accepted.insert(id, state);
        self.events.push_back(QueuedEvent {
            event: AppEvent::Completed {
                request_id: id,
                result,
            },
            unique_bytes: 0,
            arc: None,
        });
        Ok(())
    }
    pub fn enqueue_notification(
        &mut self,
        event: AppNotification,
    ) -> Result<(), NotificationError> {
        let key = notification_key(&event);
        let replace = key.and_then(|key| {
            self.events.iter().position(|queued| match &queued.event {
                AppEvent::Notification(existing) => notification_key(existing) == Some(key),
                AppEvent::Completed { .. } => false,
            })
        });
        let critical = critical_overflow_for(&event);
        let global_reason = match &event {
            AppNotification::ApplicationFailure { reason } => Some(*reason),
            AppNotification::ControlTransferred => {
                Some(ApplicationFailureKind::NotificationOverflow)
            }
            _ => None,
        };
        let critical_count = self.events.iter().filter(|queued| matches!(&queued.event, AppEvent::Notification(v) if critical_overflow_for(v).is_some())).count();
        if replace.is_none() && self.events.len() >= EVENT_CAPACITY - COMPLETION_RESERVATIONS {
            return Err(self.reject_notification_overflow(critical, global_reason));
        }
        if replace.is_none() && critical.is_some() && critical_count >= 64 {
            return Err(self.reject_notification_overflow(critical, global_reason));
        }
        let previous =
            replace.and_then(|index| self.events.remove(index).map(|queued| (index, queued)));
        if let Some((_, queued)) = &previous {
            self.release_queued(queued);
        }
        let prepared = self.account_notification(event);
        match prepared {
            Ok(queued) => {
                if let Some((index, _)) = previous {
                    self.events.insert(index, queued);
                } else {
                    self.events.push_back(queued);
                }
                Ok(())
            }
            Err(_error) => {
                if let Some((index, queued)) = previous {
                    self.restore_queued(&queued);
                    self.events.insert(index, queued);
                }
                if critical.is_some() || global_reason.is_some() {
                    Err(self.reject_notification_overflow(critical, global_reason))
                } else {
                    Err(NotificationError::ResourceLimit)
                }
            }
        }
    }
    fn reject_notification_overflow(
        &mut self,
        critical: Option<CriticalOverflow>,
        global_reason: Option<ApplicationFailureKind>,
    ) -> NotificationError {
        if let Some(overflow) = critical {
            if self.latch_overflow(overflow).is_err() {
                self.global_failure = Some(ApplicationFailureKind::NotificationOverflow);
            }
            NotificationError::CriticalOverflow(overflow)
        } else {
            if let Some(reason) = global_reason {
                self.global_failure = Some(reason);
            }
            NotificationError::ResourceLimit
        }
    }
    fn account_notification(&mut self, event: AppNotification) -> Result<QueuedEvent, SubmitError> {
        let (owned, arc) = notification_cost(&event)?;
        let arc_bytes = arc.map_or(0, |(_, bytes)| bytes);
        let new_arc = arc.is_some_and(|(ptr, _)| !self.shared_allocations.contains_key(&ptr));
        let added = owned
            .checked_add(if new_arc { arc_bytes } else { 0 })
            .ok_or(SubmitError::ResourceLimit)?;
        if self
            .notification_bytes
            .checked_add(added)
            .filter(|n| *n <= NOTIFICATION_BYTES)
            .is_none()
        {
            return Err(SubmitError::ResourceLimit);
        }
        self.notification_bytes += added;
        if let Some((ptr, bytes)) = arc {
            self.shared_allocations
                .entry(ptr)
                .and_modify(|entry| entry.0 += 1)
                .or_insert((1, bytes));
        }
        Ok(QueuedEvent {
            event: AppEvent::Notification(event),
            unique_bytes: owned,
            arc,
        })
    }
    fn release_queued(&mut self, queued: &QueuedEvent) {
        self.notification_bytes = self.notification_bytes.saturating_sub(queued.unique_bytes);
        if let Some((ptr, _)) = queued.arc
            && let Some((refs, bytes)) = self.shared_allocations.get_mut(&ptr)
        {
            *refs -= 1;
            if *refs == 0 {
                self.notification_bytes = self.notification_bytes.saturating_sub(*bytes);
                self.shared_allocations.remove(&ptr);
            }
        }
    }
    fn restore_queued(&mut self, queued: &QueuedEvent) {
        self.notification_bytes += queued.unique_bytes;
        if let Some((ptr, bytes)) = queued.arc {
            self.shared_allocations
                .entry(ptr)
                .and_modify(|entry| entry.0 += 1)
                .or_insert((1, bytes));
            if self
                .shared_allocations
                .get(&ptr)
                .is_some_and(|entry| entry.0 == 1)
            {
                self.notification_bytes += bytes;
            }
        }
    }
    pub fn try_recv(&mut self) -> Option<AppEvent> {
        let marker_id = self
            .markers
            .iter()
            .filter(|(_, slot)| slot.marker.is_some())
            .map(|(id, _)| *id)
            .min_by_key(|id| id.0);
        if let Some(id) = marker_id {
            let slot = self.markers.get_mut(&id)?;
            let marker = slot.marker.take()?;
            if slot.retiring {
                self.markers.remove(&id);
            }
            return Some(AppEvent::Notification(match marker.action {
                OverflowAction::CancelChallenge => AppNotification::SessionFailed {
                    session_id: id,
                    session_generation: marker.generation,
                    reason: SessionFailureKind::Cancelled,
                },
                OverflowAction::CancelSession => AppNotification::SessionFailed {
                    session_id: id,
                    session_generation: marker.generation,
                    reason: SessionFailureKind::ResourceLimit,
                },
                OverflowAction::ResyncSurface => AppNotification::SurfaceResyncRequired {
                    session_id: id,
                    session_generation: marker.generation,
                },
            }));
        }
        if let Some(reason) = self.global_failure.take() {
            return Some(AppEvent::Notification(
                AppNotification::ApplicationFailure { reason },
            ));
        }
        let queued = self.events.pop_front()?;
        if matches!(queued.event, AppEvent::Notification(_)) {
            self.release_queued(&queued);
        }
        if let AppEvent::Completed { request_id, .. } = &queued.event {
            self.accepted.remove(request_id);
        }
        Some(queued.event)
    }
    pub fn latch_overflow(&mut self, overflow: CriticalOverflow) -> Result<(), CriticalOverflow> {
        let Some(slot) = self.markers.get_mut(&overflow.session_id) else {
            return Err(overflow);
        };
        let incoming = Marker {
            generation: overflow.generation,
            action: overflow.action,
        };
        if slot.retiring {
            return Err(overflow);
        }
        match &slot.marker {
            Some(current) if incoming.generation > current.generation => {
                slot.marker = Some(incoming)
            }
            Some(current)
                if incoming.generation == current.generation
                    && overflow_severity(incoming.action) > overflow_severity(current.action) =>
            {
                slot.marker = Some(incoming)
            }
            Some(_) => {}
            None => slot.marker = Some(incoming),
        }
        Ok(())
    }
    /// Reserve one of the eight fixed overflow-delivery slots before opening a session.
    pub fn register_session_marker(&mut self, id: SessionId) -> Result<(), SubmitError> {
        if let Some(slot) = self.markers.get(&id) {
            return if slot.retiring {
                Err(SubmitError::ResourceLimit)
            } else {
                Ok(())
            };
        }
        if self.markers.len() >= 8 {
            return Err(SubmitError::ResourceLimit);
        }
        self.markers.insert(
            id,
            MarkerSlot {
                marker: None,
                retiring: false,
            },
        );
        Ok(())
    }
    pub fn unregister_session_marker(&mut self, id: SessionId) {
        if let Some(slot) = self.markers.get_mut(&id) {
            if slot.marker.is_some() {
                slot.retiring = true;
            } else {
                self.markers.remove(&id);
            }
        }
    }
    pub fn accepted_count(&self) -> usize {
        self.accepted.len()
    }
    pub fn queued_event_count(&self) -> usize {
        self.events.len()
    }
    pub fn notification_bytes(&self) -> usize {
        self.notification_bytes
    }
}

pub(super) fn add_cap(total: &mut usize, bytes: usize) -> Result<(), SubmitError> {
    *total = total.checked_add(bytes).ok_or(SubmitError::ResourceLimit)?;
    Ok(())
}
pub(super) fn add_vec<T>(total: &mut usize, value: &Vec<T>) -> Result<(), SubmitError> {
    add_cap(
        total,
        value
            .capacity()
            .checked_mul(size_of::<T>())
            .ok_or(SubmitError::ResourceLimit)?,
    )
}
pub(super) fn add_string(total: &mut usize, value: &String) -> Result<(), SubmitError> {
    add_cap(total, value.capacity())
}
fn add_path(total: &mut usize, value: &std::path::PathBuf) -> Result<(), SubmitError> {
    add_cap(total, value.capacity())
}
fn add_secret(total: &mut usize, value: &Secret) -> Result<(), SubmitError> {
    if value.expose().len() > 64 * 1024 {
        return Err(SubmitError::ResourceLimit);
    }
    add_cap(total, value.allocated_bytes())
}
fn add_credential_secret_intent(
    total: &mut usize,
    value: &CredentialSecretIntent,
) -> Result<(), SubmitError> {
    let changes = [&value.password, &value.ssh_key, &value.ssh_passphrase];
    if changes
        .iter()
        .filter(|change| !matches!(change, SecretChange::Keep))
        .count()
        > 2
    {
        return Err(SubmitError::ResourceLimit);
    }
    for change in changes {
        match change {
            SecretChange::Replace(secret) => add_secret(total, secret)?,
            SecretChange::Keep | SecretChange::Clear => {}
        }
    }
    Ok(())
}

fn add_connection_settings(
    total: &mut usize,
    settings: &ConnectionSettings,
) -> Result<(), SubmitError> {
    match settings {
        ConnectionSettings::Rdp(v) => {
            add_string(total, &v.host)?;
            if let Some(x) = &v.domain {
                add_string(total, x)?
            }
            if let Some(x) = &v.username {
                add_string(total, x)?
            }
        }
        ConnectionSettings::Ssh(v) => {
            add_string(total, &v.host)?;
            add_string(total, &v.username)?;
            match &v.auth_method {
                crate::SshAuthMethod::PublicKey { key_ref } => {
                    add_cap(total, key_ref.allocated_bytes())?
                }
                crate::SshAuthMethod::Password | crate::SshAuthMethod::Agent => {}
            }
        }
        ConnectionSettings::Telnet(v) => add_string(total, &v.host)?,
        ConnectionSettings::Local(v) => {
            if let Some(x) = &v.program {
                add_string(total, x)?
            }
            if let Some(x) = &v.working_dir {
                add_string(total, x)?
            }
            add_vec(total, &v.args)?;
            for x in &v.args {
                add_string(total, x)?
            }
            add_vec(total, &v.env)?;
            for (k, v) in &v.env {
                add_string(total, k)?;
                add_string(total, v)?
            }
        }
    }
    Ok(())
}
pub(super) fn add_connection(total: &mut usize, value: &Connection) -> Result<(), SubmitError> {
    add_string(total, &value.name)?;
    add_connection_settings(total, &value.settings)?;
    match &value.credential_source {
        Some(CredentialSource::Inline {
            username, domain, ..
        }) => {
            add_string(total, username)?;
            if let Some(x) = domain {
                add_string(total, x)?;
            }
        }
        None | Some(CredentialSource::Object(_)) | Some(CredentialSource::Prompt) => {}
    }
    Ok(())
}
pub(super) fn add_group(total: &mut usize, value: &Group) -> Result<(), SubmitError> {
    add_string(total, &value.name)
}
pub(super) fn add_credential(total: &mut usize, value: &Credential) -> Result<(), SubmitError> {
    add_string(total, &value.name)?;
    if let Some(x) = &value.username {
        add_string(total, x)?
    }
    Ok(())
}
pub(super) fn add_folder(total: &mut usize, value: &CredentialFolder) -> Result<(), SubmitError> {
    add_string(total, &value.name)
}
fn add_mutation_result(_total: &mut usize, value: &MutationResult) -> Result<(), SubmitError> {
    match value {
        MutationResult::ConnectionId(_)
        | MutationResult::GroupId(_)
        | MutationResult::CredentialId(_)
        | MutationResult::CredentialFolderId(_)
        | MutationResult::Deleted => {}
        MutationResult::Preferences(_) => {}
        MutationResult::ImportCommitted(_) => {}
    }
    Ok(())
}
fn add_app_error(total: &mut usize, value: &AppError) -> Result<(), SubmitError> {
    match value {
        AppError::PartialRequiresReconcile { affected, .. } => add_cap(
            total,
            affected
                .len()
                .checked_mul(size_of::<SecretRefId>())
                .ok_or(SubmitError::ResourceLimit)?,
        )?,
        AppError::ResourceLimit
        | AppError::RevisionConflict { .. }
        | AppError::NotFound
        | AppError::Validation { .. }
        | AppError::CapabilityUnavailable { .. }
        | AppError::PersistenceFailed
        | AppError::SecretStoreUnavailable
        | AppError::SecretMutationFailed
        | AppError::SessionFailed { .. }
        | AppError::ServiceStopping
        | AppError::TransportUncertain { .. }
        | AppError::RevisionExhausted => {}
    }
    Ok(())
}
fn add_mutation_outcome(total: &mut usize, value: &MutationOutcome) -> Result<(), SubmitError> {
    match value {
        MutationOutcome::Committed { result, .. } => add_mutation_result(total, result)?,
        MutationOutcome::Failed { error, .. } => add_app_error(total, error)?,
        MutationOutcome::InProgress | MutationOutcome::Unknown { .. } => {}
    }
    Ok(())
}
fn add_workspace(total: &mut usize, value: &WorkspaceDto) -> Result<(), SubmitError> {
    add_vec(total, &value.connections)?;
    for v in &value.connections {
        add_connection(total, v)?
    }
    add_vec(total, &value.groups)?;
    for v in &value.groups {
        add_group(total, v)?
    }
    add_vec(total, &value.credentials)?;
    for v in &value.credentials {
        add_credential(total, v)?
    }
    add_vec(total, &value.credential_folders)?;
    for v in &value.credential_folders {
        add_folder(total, v)?
    }
    Ok(())
}
fn add_session_target(total: &mut usize, value: &SessionTarget) -> Result<(), SubmitError> {
    match value {
        SessionTarget::QuickConnect(v) => add_connection(total, v)?,
        SessionTarget::Saved(_) | SessionTarget::GatewayTerminal => {}
    }
    Ok(())
}
fn add_session_input(total: &mut usize, value: &SessionInput) -> Result<(), SubmitError> {
    match value {
        SessionInput::Paste(v) => add_vec(total, v)?,
        SessionInput::Rdp(v) => add_vec(total, v)?,
        SessionInput::RdpClipboard(crate::RdpClipboardCommand::PublishLocal {
            snapshot, ..
        }) => match snapshot {
            crate::ClipboardSnapshot::Text(v) => add_string(total, v)?,
            crate::ClipboardSnapshot::Files(paths) => {
                add_vec(total, paths)?;
                for p in paths {
                    add_path(total, p)?
                }
            }
            crate::ClipboardSnapshot::Empty => {}
        },
        SessionInput::Key(_) | SessionInput::Mouse(_) | SessionInput::Scroll(_) => {}
        SessionInput::RdpClipboard(crate::RdpClipboardCommand::SetActive(_)) => {}
    }
    Ok(())
}
fn add_challenge_response(total: &mut usize, value: &ChallengeResponse) -> Result<(), SubmitError> {
    match value {
        ChallengeResponse::Password(v) => add_secret(total, v)?,
        ChallengeResponse::PrivateKey { key, passphrase } => {
            add_secret(total, key)?;
            if let Some(v) = passphrase {
                add_secret(total, v)?
            }
        }
        ChallengeResponse::KeyboardInteractive(v) => {
            add_vec(total, v)?;
            for s in v {
                add_secret(total, s)?
            }
        }
        ChallengeResponse::AcceptSshHostKey
        | ChallengeResponse::RejectSshHostKey
        | ChallengeResponse::AcceptRdpCertificate
        | ChallengeResponse::RejectRdpCertificate
        | ChallengeResponse::Cancel => {}
    }
    Ok(())
}
fn command_capacity(value: &AppCommand) -> Result<usize, SubmitError> {
    let mut n = size_of::<AppCommand>();
    match value {
        AppCommand::ImportPreview {
            filename, bytes, ..
        } => {
            if bytes.len() > 16 * 1024 * 1024 {
                return Err(SubmitError::ResourceLimit);
            }
            add_string(&mut n, filename)?;
            add_vec(&mut n, bytes)?
        }
        AppCommand::Mutate { operation, .. } => match operation {
            WorkspaceMutation::UpsertConnection {
                value,
                secret_intent,
            } => {
                add_connection(&mut n, value)?;
                match secret_intent {
                    InlineSecretIntent::Replace(s) => add_secret(&mut n, s)?,
                    InlineSecretIntent::Keep | InlineSecretIntent::Clear => {}
                }
            }
            WorkspaceMutation::UpsertGroup { value } => add_group(&mut n, value)?,
            WorkspaceMutation::UpsertCredential {
                value,
                secret_intent,
            } => {
                add_credential(&mut n, value)?;
                add_credential_secret_intent(&mut n, secret_intent)?;
            }
            WorkspaceMutation::UpsertCredentialFolder { value } => add_folder(&mut n, value)?,
            WorkspaceMutation::DeleteConnection { .. }
            | WorkspaceMutation::MoveConnection { .. }
            | WorkspaceMutation::DeleteGroup { .. }
            | WorkspaceMutation::MoveGroup { .. }
            | WorkspaceMutation::DeleteCredential { .. }
            | WorkspaceMutation::DeleteCredentialFolder { .. }
            | WorkspaceMutation::MoveCredentialFolder { .. }
            | WorkspaceMutation::SetPreferences { .. }
            | WorkspaceMutation::ImportCommit { .. } => {}
        },
        AppCommand::OpenSession { target, .. } => add_session_target(&mut n, target)?,
        AppCommand::SessionInput { input, .. } => add_session_input(&mut n, input)?,
        AppCommand::SearchTerminal { query, .. } => {
            if query.len() > 4 * 1024 {
                return Err(SubmitError::ResourceLimit);
            }
            add_string(&mut n, query)?;
        }
        AppCommand::ClipboardPasteText { text, .. } => {
            if text.len() > 1024 * 1024 {
                return Err(SubmitError::ResourceLimit);
            }
            add_string(&mut n, text)?;
        }
        AppCommand::RespondChallenge { response, .. } => add_challenge_response(&mut n, response)?,
        AppCommand::Bootstrap
        | AppCommand::ListWorkspace
        | AppCommand::QueryOutcome { .. }
        | AppCommand::RequestControl
        | AppCommand::ExportSecretFree
        | AppCommand::CloseSession { .. }
        | AppCommand::DetachSession { .. }
        | AppCommand::AttachSession { .. }
        | AppCommand::ResizeSession { .. }
        | AppCommand::SetViewport { .. } => {}
    }
    Ok(n)
}
fn result_capacity(value: &AppResult) -> Result<usize, SubmitError> {
    let mut n = size_of::<AppEvent>();
    match value {
        AppResult::Bootstrap(v) => {
            add_vec(&mut n, &v.capabilities)?;
            add_workspace(&mut n, &v.workspace)?;
            add_vec(&mut n, &v.sessions)?
        }
        AppResult::Workspace(v) => add_workspace(&mut n, v)?,
        AppResult::ImportPreview(v) => add_vec(&mut n, &v.warnings)?,
        AppResult::Export(v) => {
            add_string(&mut n, &v.filename)?;
            add_string(&mut n, &v.content_type)?;
            add_vec(&mut n, &v.bytes)?
        }
        AppResult::SessionOpened(_)
        | AppResult::SessionAttached(_)
        | AppResult::SessionClosed
        | AppResult::SessionDetached
        | AppResult::SessionInputAccepted { .. }
        | AppResult::SessionResized { .. }
        | AppResult::ViewportSet
        | AppResult::ClipboardAccepted { .. }
        | AppResult::ChallengeResponded
        | AppResult::ControlTransferRequested => {}
        AppResult::Search(v) => add_vec(&mut n, &v.matches)?,
        AppResult::MutationCommitted { result, .. } => add_mutation_result(&mut n, result)?,
        AppResult::MutationOutcome(v) => add_mutation_outcome(&mut n, v)?,
    }
    Ok(n)
}
fn error_capacity(value: &AppError) -> Result<usize, SubmitError> {
    let mut n = size_of::<AppEvent>();
    if let AppError::PartialRequiresReconcile {
        affected,
        affected_total,
        affected_truncated,
        ..
    } = value
        && (affected.len() > 32
            || (*affected_total as usize) < affected.len()
            || *affected_truncated != (*affected_total as usize > affected.len()))
    {
        return Err(SubmitError::ResourceLimit);
    }
    add_app_error(&mut n, value)?;
    Ok(n)
}

fn critical_overflow_for(event: &AppNotification) -> Option<CriticalOverflow> {
    let (session_id, generation, action) = match event {
        AppNotification::SessionChanged {
            session_id,
            session_generation,
            ..
        } => (
            *session_id,
            *session_generation,
            OverflowAction::CancelSession,
        ),
        AppNotification::ChallengeIssued { challenge } => (
            challenge.session_id,
            challenge.session_generation,
            OverflowAction::CancelChallenge,
        ),
        AppNotification::ChallengeCancelled {
            session_id,
            session_generation,
            ..
        } => (
            *session_id,
            *session_generation,
            OverflowAction::CancelChallenge,
        ),
        AppNotification::SessionFailed {
            session_id,
            session_generation,
            ..
        } => (
            *session_id,
            *session_generation,
            OverflowAction::CancelSession,
        ),
        AppNotification::SurfaceResyncRequired {
            session_id,
            session_generation,
        } => (
            *session_id,
            *session_generation,
            OverflowAction::ResyncSurface,
        ),
        AppNotification::ApplicationFailure { .. }
        | AppNotification::ControlTransferred
        | AppNotification::TerminalSurface { .. }
        | AppNotification::RdpFrame { .. }
        | AppNotification::RemoteClipboardOfferedText { .. } => return None,
    };
    Some(CriticalOverflow {
        session_id,
        generation,
        action,
    })
}

const fn overflow_severity(action: OverflowAction) -> u8 {
    match action {
        OverflowAction::ResyncSurface => 1,
        OverflowAction::CancelChallenge => 2,
        OverflowAction::CancelSession => 3,
    }
}

fn notification_key(event: &AppNotification) -> Option<(SessionId, u64, u8)> {
    match event {
        AppNotification::TerminalSurface {
            session_id,
            session_generation,
            ..
        } => Some((*session_id, *session_generation, 0)),
        AppNotification::RdpFrame {
            session_id,
            session_generation,
            ..
        } => Some((*session_id, *session_generation, 1)),
        AppNotification::RemoteClipboardOfferedText {
            session_id,
            session_generation,
            ..
        } => Some((*session_id, *session_generation, 2)),
        AppNotification::SessionChanged { .. }
        | AppNotification::SurfaceResyncRequired { .. }
        | AppNotification::ChallengeIssued { .. }
        | AppNotification::ChallengeCancelled { .. }
        | AppNotification::SessionFailed { .. }
        | AppNotification::ApplicationFailure { .. }
        | AppNotification::ControlTransferred => None,
    }
}

fn notification_cost(
    event: &AppNotification,
) -> Result<(usize, Option<(usize, usize)>), SubmitError> {
    let mut bytes = size_of::<AppNotification>();
    let mut arc = None;
    let mut add = |n: usize| -> Result<(), SubmitError> {
        bytes = bytes.checked_add(n).ok_or(SubmitError::ResourceLimit)?;
        Ok(())
    };
    match event {
        AppNotification::RemoteClipboardOfferedText { text, .. } => {
            if text.len() > 1024 * 1024 {
                return Err(SubmitError::ResourceLimit);
            }
            add(text.capacity())?;
        }
        AppNotification::ChallengeIssued { challenge } => match &challenge.kind {
            ChallengeKind::SshHost {
                host, fingerprint, ..
            }
            | ChallengeKind::RdpCertificate {
                host, fingerprint, ..
            } => {
                add(host.capacity())?;
                add(fingerprint.capacity())?;
            }
            ChallengeKind::KeyboardInteractive(prompts) => {
                add(prompts
                    .capacity()
                    .checked_mul(size_of::<String>())
                    .ok_or(SubmitError::ResourceLimit)?)?;
                for prompt in prompts {
                    add(prompt.capacity())?;
                }
            }
            ChallengeKind::Password | ChallengeKind::PrivateKey => {}
        },
        AppNotification::TerminalSurface { surface, .. } => {
            let ptr = Arc::as_ptr(surface) as usize;
            let mut n = size_of::<GridSnapshot>()
                .checked_add(2 * size_of::<usize>())
                .ok_or(SubmitError::ResourceLimit)?;
            n = n
                .checked_add(
                    surface
                        .cells
                        .capacity()
                        .checked_mul(size_of::<crate::Cell>())
                        .ok_or(SubmitError::ResourceLimit)?,
                )
                .ok_or(SubmitError::ResourceLimit)?;
            for cell in &surface.cells {
                n = n
                    .checked_add(cell.grapheme.capacity())
                    .ok_or(SubmitError::ResourceLimit)?;
            }
            arc = Some((ptr, n));
        }
        AppNotification::RdpFrame { frame, .. } => {
            let ptr = Arc::as_ptr(frame) as usize;
            let n = size_of::<FrameUpdate>()
                .checked_add(2 * size_of::<usize>())
                .and_then(|n| n.checked_add(frame.rgba.capacity()))
                .ok_or(SubmitError::ResourceLimit)?;
            arc = Some((ptr, n));
        }
        AppNotification::SessionChanged { .. }
        | AppNotification::SurfaceResyncRequired { .. }
        | AppNotification::ChallengeCancelled { .. }
        | AppNotification::SessionFailed { .. }
        | AppNotification::ApplicationFailure { .. }
        | AppNotification::ControlTransferred => {}
    }
    Ok((bytes, arc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cell, CellAttrs, Color, CredentialRef, CursorShape, CursorState, TerminalSize};

    fn empty_grid() -> GridSnapshot {
        GridSnapshot {
            size: TerminalSize { rows: 1, cols: 1 },
            cells: vec![Cell {
                grapheme: String::with_capacity(40),
                fg: Color::Default,
                bg: Color::Default,
                attrs: CellAttrs::empty(),
                width: 1,
            }],
            cursor: CursorState {
                row: 0,
                col: 0,
                visible: false,
                shape: CursorShape::Block,
            },
            scrollback_len: 0,
            scroll_offset: 0,
            mouse_tracking: false,
        }
    }

    fn accepted(mailbox: &mut ApplicationMailbox) -> RequestId {
        let id = mailbox.accept(AppCommand::Bootstrap).unwrap();
        let (taken, _command) = mailbox
            .take_command()
            .expect("accepted commands are queued");
        assert_eq!(id, taken);
        id
    }

    #[test]
    fn completion_credit_is_held_until_completion_is_consumed() {
        let mut mailbox = ApplicationMailbox::default();
        let ids: Vec<_> = (0..64).map(|_| accepted(&mut mailbox)).collect();
        assert_eq!(
            mailbox.accept(AppCommand::Bootstrap),
            Err(SubmitError::QueueFull)
        );
        mailbox
            .enqueue_completion(ids[0], Err(AppError::ResourceLimit))
            .unwrap();
        assert_eq!(
            mailbox.accept(AppCommand::Bootstrap),
            Err(SubmitError::QueueFull)
        );
        assert!(
            matches!(mailbox.try_recv(), Some(AppEvent::Completed { request_id, .. }) if request_id == ids[0])
        );
        assert_eq!(mailbox.accept(AppCommand::Bootstrap).unwrap().get(), 65);
    }

    #[test]
    fn service_stopping_completes_accepted_undispatched_work_from_reserved_credit() {
        let mut mailbox = ApplicationMailbox::default();
        let ids: Vec<_> = (0..MAX_ACCEPTED_REQUESTS)
            .map(|_| mailbox.accept(AppCommand::Bootstrap).unwrap())
            .collect();
        assert_eq!(mailbox.commands.len(), MAX_ACCEPTED_REQUESTS);

        for id in &ids {
            mailbox
                .enqueue_completion(*id, Err(AppError::ServiceStopping))
                .expect("every accepted request reserved its error completion");
        }
        assert!(mailbox.commands.is_empty());
        assert_eq!(mailbox.events.len(), MAX_ACCEPTED_REQUESTS);
        for id in ids {
            assert!(matches!(
                mailbox.try_recv(),
                Some(AppEvent::Completed {
                    request_id,
                    result: Err(AppError::ServiceStopping),
                }) if request_id == id
            ));
        }
        assert_eq!(mailbox.accept(AppCommand::Bootstrap).unwrap().get(), 65);
    }

    #[test]
    fn oversized_completion_falls_back_to_its_pre_reserved_resource_limit() {
        let mut mailbox = ApplicationMailbox::default();
        let id = accepted(&mut mailbox);
        mailbox.reserve_result(id, ResultClass::Standard).unwrap();
        let oversized = AppResult::Export(ExportDto {
            filename: String::new(),
            content_type: String::new(),
            bytes: Vec::with_capacity(ERROR_RESERVATION + 32),
        });
        mailbox.enqueue_completion(id, Ok(oversized)).unwrap();
        assert!(matches!(
            mailbox.try_recv(),
            Some(AppEvent::Completed {
                result: Err(AppError::ResourceLimit),
                ..
            })
        ));
    }

    #[test]
    fn request_ids_never_wrap_and_failed_acceptance_does_not_consume_one() {
        let mut mailbox = ApplicationMailbox::default();
        let too_large = AppCommand::ImportPreview {
            format: ImportFormat::ConManJson,
            filename: String::new(),
            bytes: vec![0; INGRESS_BYTES],
        };
        assert_eq!(mailbox.accept(too_large), Err(SubmitError::ResourceLimit));
        assert_eq!(mailbox.accept(AppCommand::Bootstrap).unwrap().get(), 1);
        let mut exhausted = ApplicationMailbox {
            next_request: NonZeroU64::new(u64::MAX),
            ..ApplicationMailbox::default()
        };
        assert_eq!(
            exhausted.accept(AppCommand::Bootstrap).unwrap().get(),
            u64::MAX
        );
        assert_eq!(
            exhausted.accept(AppCommand::Bootstrap),
            Err(SubmitError::RequestIdsExhausted)
        );
    }

    #[test]
    fn oversized_partial_reconciliation_report_falls_back_to_bounded_error() {
        let mut mailbox = ApplicationMailbox::default();
        let id = accepted(&mut mailbox);
        let affected: Box<[SecretRefId]> = vec![
            SecretRefId::Credential {
                id: CredentialId::new(1),
                purpose: CredentialPurpose::Password
            };
            33
        ]
        .into_boxed_slice();
        let error = AppError::PartialRequiresReconcile {
            metadata_committed: false,
            current_revision: WorkspaceRevision(1),
            affected,
            affected_total: 33,
            affected_truncated: true,
        };
        mailbox.enqueue_completion(id, Err(error)).unwrap();
        assert!(matches!(
            mailbox.try_recv(),
            Some(AppEvent::Completed {
                result: Err(AppError::ResourceLimit),
                ..
            })
        ));
    }

    #[test]
    fn failure_completion_is_always_reserved_and_notifications_respect_completion_slots() {
        let mut mailbox = ApplicationMailbox::default();
        let id = accepted(&mut mailbox);
        mailbox
            .enqueue_completion(id, Err(AppError::ResourceLimit))
            .unwrap();
        assert!(matches!(
            mailbox.try_recv(),
            Some(AppEvent::Completed {
                result: Err(AppError::ResourceLimit),
                ..
            })
        ));
        for _ in 0..(EVENT_CAPACITY - COMPLETION_RESERVATIONS) {
            mailbox
                .enqueue_notification(AppNotification::ControlTransferred)
                .unwrap();
        }
        assert_eq!(
            mailbox.enqueue_notification(AppNotification::ControlTransferred),
            Err(NotificationError::ResourceLimit)
        );
    }

    #[test]
    fn critical_overflow_uses_out_of_band_marker_before_normal_events() {
        let mut mailbox = ApplicationMailbox::default();
        mailbox
            .enqueue_notification(AppNotification::ControlTransferred)
            .unwrap();
        mailbox.register_session_marker(SessionId(9)).unwrap();
        let marker = CriticalOverflow {
            session_id: SessionId(9),
            generation: 4,
            action: OverflowAction::ResyncSurface,
        };
        mailbox.latch_overflow(marker).unwrap();
        assert!(matches!(
            mailbox.try_recv(),
            Some(AppEvent::Notification(
                AppNotification::SurfaceResyncRequired {
                    session_id: SessionId(9),
                    session_generation: 4
                }
            ))
        ));
        assert!(matches!(
            mailbox.try_recv(),
            Some(AppEvent::Notification(AppNotification::ControlTransferred))
        ));
    }

    #[test]
    fn marker_registry_is_bounded_and_critical_overflow_is_typed_and_visible() {
        let mut mailbox = ApplicationMailbox::default();
        for raw in 0..8 {
            mailbox.register_session_marker(SessionId(raw)).unwrap();
        }
        assert_eq!(
            mailbox.register_session_marker(SessionId(8)),
            Err(SubmitError::ResourceLimit)
        );
        for _ in 0..64 {
            mailbox
                .enqueue_notification(AppNotification::SessionChanged {
                    session_id: SessionId(0),
                    session_generation: 3,
                    status: ApplicationSessionStatus::Connected,
                })
                .unwrap();
        }
        assert!(matches!(
            mailbox.enqueue_notification(AppNotification::SessionChanged {
                session_id: SessionId(0),
                session_generation: 3,
                status: ApplicationSessionStatus::Disconnected
            }),
            Err(NotificationError::CriticalOverflow(CriticalOverflow {
                action: OverflowAction::CancelSession,
                ..
            }))
        ));
        assert!(matches!(
            mailbox.try_recv(),
            Some(AppEvent::Notification(AppNotification::SessionFailed {
                reason: SessionFailureKind::ResourceLimit,
                ..
            }))
        ));
    }

    #[test]
    fn newer_generation_replaces_stale_overflow_marker() {
        let mut mailbox = ApplicationMailbox::default();
        mailbox.register_session_marker(SessionId(3)).unwrap();
        mailbox
            .latch_overflow(CriticalOverflow {
                session_id: SessionId(3),
                generation: 1,
                action: OverflowAction::CancelSession,
            })
            .unwrap();
        mailbox
            .latch_overflow(CriticalOverflow {
                session_id: SessionId(3),
                generation: 2,
                action: OverflowAction::ResyncSurface,
            })
            .unwrap();
        assert!(matches!(
            mailbox.try_recv(),
            Some(AppEvent::Notification(
                AppNotification::SurfaceResyncRequired {
                    session_id: SessionId(3),
                    session_generation: 2,
                }
            ))
        ));
    }

    #[test]
    fn unregister_retires_pending_markers_until_visible_failure_is_consumed() {
        let mut mailbox = ApplicationMailbox::default();
        for raw in 0..8 {
            let session_id = SessionId(raw);
            mailbox.register_session_marker(session_id).unwrap();
            mailbox
                .latch_overflow(CriticalOverflow {
                    session_id,
                    generation: raw + 10,
                    action: OverflowAction::CancelChallenge,
                })
                .unwrap();
            mailbox.unregister_session_marker(session_id);
            assert_eq!(
                mailbox.register_session_marker(session_id),
                Err(SubmitError::ResourceLimit)
            );
        }
        for raw in 0..8 {
            assert!(matches!(
                mailbox.try_recv(),
                Some(AppEvent::Notification(AppNotification::SessionFailed {
                    session_id: SessionId(id),
                    session_generation,
                    reason: SessionFailureKind::Cancelled,
                })) if id == raw && session_generation == raw + 10
            ));
        }
        assert!(mailbox.try_recv().is_none());
        for raw in 0..8 {
            mailbox.register_session_marker(SessionId(raw)).unwrap();
        }
    }

    #[test]
    fn nested_grid_capacities_are_available_for_recursive_accounting() {
        let grid = Arc::new(empty_grid());
        assert!(grid.cells.capacity() >= 1);
        assert!(grid.cells[0].grapheme.capacity() >= 40);
        assert!(Arc::ptr_eq(&grid, &grid.clone()));
    }

    #[test]
    fn aliased_surface_allocations_are_counted_once_until_last_mailbox_reference() {
        let mut mailbox = ApplicationMailbox::default();
        let grid = Arc::new(empty_grid());
        let surface = |surface| AppNotification::TerminalSurface {
            session_id: SessionId(1),
            session_generation: 2,
            surface,
        };
        mailbox.enqueue_notification(surface(grid.clone())).unwrap();
        let once = mailbox.notification_bytes();
        mailbox
            .enqueue_notification(AppNotification::TerminalSurface {
                session_id: SessionId(2),
                session_generation: 2,
                surface: grid,
            })
            .unwrap();
        assert_eq!(
            mailbox.notification_bytes(),
            once + size_of::<AppNotification>()
        );
        let _ = mailbox.try_recv();
        assert!(mailbox.notification_bytes() > 0);
        let _ = mailbox.try_recv();
        assert_eq!(mailbox.notification_bytes(), NOTIFICATION_FIXED_BYTES);
    }

    #[test]
    fn surface_updates_replace_the_undelivered_value_for_the_same_generation() {
        let mut mailbox = ApplicationMailbox::default();
        let first = Arc::new(empty_grid());
        let second = Arc::new(empty_grid());
        mailbox
            .enqueue_notification(AppNotification::TerminalSurface {
                session_id: SessionId(4),
                session_generation: 8,
                surface: first,
            })
            .unwrap();
        mailbox
            .enqueue_notification(AppNotification::TerminalSurface {
                session_id: SessionId(4),
                session_generation: 8,
                surface: second.clone(),
            })
            .unwrap();
        assert_eq!(mailbox.queued_event_count(), 1);
        assert!(
            matches!(mailbox.try_recv(), Some(AppEvent::Notification(AppNotification::TerminalSurface { surface, .. })) if Arc::ptr_eq(&surface, &second))
        );
    }

    #[test]
    fn command_capacity_recurses_through_settings_auth_and_secret_spare_capacity() {
        let host = String::with_capacity(72);
        let host_bytes = host.capacity();
        let username = String::with_capacity(33);
        let username_bytes = username.capacity();
        let name = String::with_capacity(41);
        let name_bytes = name.capacity();
        let key_ref = CredentialRef::new(CredentialId::new(5), CredentialPurpose::SshKey);
        let ref_bytes = key_ref.allocated_bytes();
        let value = Connection::new(
            ConnectionId::UNSAVED,
            None,
            name,
            ConnectionKind::Ssh,
            ConnectionSettings::Ssh(crate::SshSettings {
                host,
                port: 22,
                username,
                auth_method: crate::SshAuthMethod::PublicKey { key_ref },
            }),
            None,
            0,
            0,
            0,
        )
        .unwrap();
        let secret = Secret::new(Vec::with_capacity(91));
        let secret_bytes = secret.allocated_bytes();
        let command = AppCommand::Mutate {
            meta: MutationMeta {
                expected_revision: WorkspaceRevision(0),
            },
            operation: WorkspaceMutation::UpsertConnection {
                value,
                secret_intent: InlineSecretIntent::Replace(secret),
            },
        };
        let expected = size_of::<AppCommand>()
            + name_bytes
            + host_bytes
            + username_bytes
            + ref_bytes
            + secret_bytes;
        assert_eq!(command_capacity(&command).unwrap(), expected);
    }

    #[test]
    fn rdp_settings_capacity_counts_host_domain_and_username_once_each() {
        let host = String::with_capacity(71);
        let host_bytes = host.capacity();
        let domain = String::with_capacity(29);
        let domain_bytes = domain.capacity();
        let username = String::with_capacity(37);
        let username_bytes = username.capacity();
        let name = String::with_capacity(43);
        let name_bytes = name.capacity();
        let connection = Connection::new(
            ConnectionId::UNSAVED,
            None,
            name,
            ConnectionKind::Rdp,
            ConnectionSettings::Rdp(crate::RdpSettings {
                host,
                port: 3389,
                domain: Some(domain),
                username: Some(username),
                width: 1280,
                height: 720,
                color_depth: 32,
            }),
            None,
            0,
            0,
            0,
        )
        .unwrap();
        let command = AppCommand::Mutate {
            meta: MutationMeta {
                expected_revision: WorkspaceRevision(0),
            },
            operation: WorkspaceMutation::UpsertConnection {
                value: connection,
                secret_intent: InlineSecretIntent::Keep,
            },
        };
        assert_eq!(
            command_capacity(&command).unwrap(),
            size_of::<AppCommand>() + name_bytes + host_bytes + domain_bytes + username_bytes
        );
    }

    #[test]
    fn session_clipboard_paths_and_interactive_secret_vectors_are_recursive() {
        let mut path = std::path::PathBuf::with_capacity(128);
        path.push("x");
        let path_bytes = path.capacity();
        let mut paths = Vec::with_capacity(4);
        paths.push(path);
        let path_vec_bytes = paths.capacity() * size_of::<std::path::PathBuf>();
        let command = AppCommand::SessionInput {
            session_id: SessionId(1),
            session_generation: 2,
            sequence: 3,
            input: SessionInput::RdpClipboard(crate::RdpClipboardCommand::PublishLocal {
                revision: crate::LocalClipboardRevision(1),
                snapshot: crate::ClipboardSnapshot::Files(paths),
            }),
        };
        assert_eq!(
            command_capacity(&command).unwrap(),
            size_of::<AppCommand>() + path_bytes + path_vec_bytes
        );

        let mut secret_bytes = vec![0; 8];
        secret_bytes.reserve(96);
        let secret_capacity = secret_bytes.capacity();
        let mut secrets = Vec::with_capacity(3);
        secrets.push(Secret::new(secret_bytes));
        let vector_capacity = secrets.capacity() * size_of::<Secret>();
        let challenge = AppCommand::RespondChallenge {
            session_id: SessionId(1),
            session_generation: 2,
            challenge_id: ChallengeId(7),
            response: ChallengeResponse::KeyboardInteractive(secrets),
        };
        assert_eq!(
            command_capacity(&challenge).unwrap(),
            size_of::<AppCommand>() + vector_capacity + secret_capacity
        );
    }

    #[test]
    fn failed_large_result_reservation_still_has_resource_limit_completion() {
        let mut mailbox = ApplicationMailbox::default();
        let first = accepted(&mut mailbox);
        let second = accepted(&mut mailbox);
        mailbox
            .reserve_result(first, ResultClass::Workspace)
            .unwrap();
        assert_eq!(
            mailbox.reserve_result(second, ResultClass::Workspace),
            Err(SubmitError::ResourceLimit)
        );
        mailbox
            .enqueue_completion(second, Err(AppError::ResourceLimit))
            .unwrap();
        assert!(
            matches!(mailbox.try_recv(), Some(AppEvent::Completed { request_id, result: Err(AppError::ResourceLimit) }) if request_id == second)
        );
    }

    #[test]
    fn only_one_import_preview_can_be_accepted_at_once() {
        let mut mailbox = ApplicationMailbox::default();
        let import = || AppCommand::ImportPreview {
            format: ImportFormat::ConManJson,
            filename: String::new(),
            bytes: Vec::new(),
        };
        let first = mailbox.accept(import()).unwrap();
        assert_eq!(mailbox.accept(import()), Err(SubmitError::ResourceLimit));
        let _ = mailbox.take_command().unwrap();
        mailbox
            .reserve_result(first, ResultClass::ImportPreview)
            .unwrap();
        mailbox
            .enqueue_completion(
                first,
                Ok(AppResult::ImportPreview(ImportPreviewDto {
                    preview_id: PreviewId(1),
                    revision: 0,
                    format: ImportFormat::ConManJson,
                    profile_counts: ImportCounts {
                        connections: 0,
                        groups: 0,
                        credentials: 0,
                        credential_folders: 0,
                    },
                    warnings: Vec::new(),
                    contains_secrets: false,
                })),
            )
            .unwrap();
        let _ = mailbox.try_recv();
        assert_eq!(mailbox.accept(import()).unwrap().get(), 2);
    }

    #[test]
    fn result_capacity_uses_vector_capacity_and_nested_payload_capacity() {
        let mut bytes = vec![0; 4096];
        bytes.reserve(4096);
        let bytes_cap = bytes.capacity();
        let name = String::with_capacity(80);
        let name_cap = name.capacity();
        let content_type = String::with_capacity(48);
        let content_type_cap = content_type.capacity();
        let result = AppResult::Export(ExportDto {
            filename: name,
            content_type,
            bytes,
        });
        assert_eq!(
            result_capacity(&result).unwrap(),
            size_of::<AppEvent>() + bytes_cap + name_cap + content_type_cap
        );
    }

    #[test]
    fn secret_accessor_reports_capacity_not_length() {
        let secret = Secret::new(Vec::with_capacity(64));
        assert!(secret.allocated_bytes() >= 64);
    }
}

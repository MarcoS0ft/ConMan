use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cm_core::{
    ClipboardPublishResult, ClipboardSnapshot, LocalClipboardRevision, RdpClipboardEvent,
    RemoteClipboardContent, RemoteClipboardRevision,
};
use ironrdp_cliprdr::backend::CliprdrBackend;
use ironrdp_cliprdr::pdu::{
    ClipboardFileAttributes, ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags,
    FileContentsFlags, FileContentsRequest, FileContentsResponse, FileDescriptor,
    FormatDataRequest, FormatDataResponse, LockDataId, OwnedFormatDataResponse,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

const CF_UNICODETEXT: ClipboardFormatId = ClipboardFormatId(13);
const MAX_TEXT_BYTES: usize = 16 * 1024 * 1024;
const ACK_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_FILES: usize = 256;
const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TOTAL_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_FILE_CHUNK: u32 = 1024 * 1024;
const MAX_LOCKED_CATALOGS: usize = 100;
const MAX_PENDING_FORMAT_REQUESTS: usize = 32;

#[derive(Debug, Default)]
struct EventSlots {
    advertised: Option<RdpClipboardEvent>,
    remote: Option<RdpClipboardEvent>,
}

#[derive(Debug)]
pub(crate) struct ClipboardEventMailbox {
    slots: Mutex<EventSlots>,
    secure_root: Option<Arc<cm_platform::secure_temp::SecureClipboardRoot>>,
}

impl ClipboardEventMailbox {
    pub(crate) fn new(
        secure_root: Option<Arc<cm_platform::secure_temp::SecureClipboardRoot>>,
    ) -> Self {
        Self {
            slots: Mutex::new(EventSlots::default()),
            secure_root,
        }
    }

    pub(crate) fn drain(&self) -> Vec<RdpClipboardEvent> {
        let Ok(mut slots) = self.slots.lock() else {
            return Vec::new();
        };
        let mut events = Vec::with_capacity(2);
        if let Some(event) = slots.advertised.take() {
            events.push(event);
        }
        if let Some(event) = slots.remote.take() {
            events.push(event);
        }
        events
    }

    fn advertise_result(
        &self,
        revision: LocalClipboardRevision,
        result: ClipboardPublishResult,
    ) -> bool {
        let Ok(mut slots) = self.slots.lock() else {
            return false;
        };
        if slots.advertised.is_some() {
            return false;
        }
        slots.advertised = Some(RdpClipboardEvent::LocalAdvertiseResult { revision, result });
        true
    }

    fn remote_text(&self, revision: RemoteClipboardRevision, text: String) {
        if let Ok(mut slots) = self.slots.lock() {
            cleanup_replaced_remote_event(self.secure_root.as_deref(), slots.remote.take());
            slots.remote = Some(RdpClipboardEvent::RemoteContent {
                revision,
                content: RemoteClipboardContent::Text(text),
            });
        }
    }

    fn remote_files(
        &self,
        revision: RemoteClipboardRevision,
        staging_root: PathBuf,
        paths: Vec<PathBuf>,
    ) {
        if let Ok(mut slots) = self.slots.lock() {
            cleanup_replaced_remote_event(self.secure_root.as_deref(), slots.remote.take());
            slots.remote = Some(RdpClipboardEvent::RemoteContent {
                revision,
                content: RemoteClipboardContent::Files {
                    staging_root,
                    paths,
                },
            });
        }
    }
}

impl Default for ClipboardEventMailbox {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Drop for ClipboardEventMailbox {
    fn drop(&mut self) {
        let slots = self
            .slots
            .get_mut()
            .unwrap_or_else(|poison| poison.into_inner());
        cleanup_replaced_remote_event(self.secure_root.as_deref(), slots.remote.take());
    }
}

fn cleanup_replaced_remote_event(
    root: Option<&cm_platform::secure_temp::SecureClipboardRoot>,
    event: Option<RdpClipboardEvent>,
) {
    if let (
        Some(root),
        Some(RdpClipboardEvent::RemoteContent {
            content: RemoteClipboardContent::Files { staging_root, .. },
            ..
        }),
    ) = (root, event)
    {
        let _ = root.cleanup_staging_path(&staging_root);
    }
}

#[derive(Debug)]
pub(crate) struct LocalFileEntry {
    name: String,
    size: u64,
    modified: Option<std::time::SystemTime>,
    file: tokio::sync::Mutex<tokio::fs::File>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    identity: cm_platform::secure_temp::WindowsFileIdentity,
}

#[derive(Debug)]
pub(crate) struct LocalFileCatalog {
    revision: LocalClipboardRevision,
    entries: Vec<Arc<LocalFileEntry>>,
}

impl LocalFileCatalog {
    pub(crate) fn descriptors(&self) -> Vec<FileDescriptor> {
        self.entries
            .iter()
            .map(|entry| {
                FileDescriptor::new(entry.name.clone())
                    .with_attributes(ClipboardFileAttributes::NORMAL)
                    .with_file_size(entry.size)
            })
            .collect()
    }
}

#[derive(Debug)]
pub(crate) struct RemoteFileEntry {
    name: String,
    partial_name: String,
    size: u64,
    file: tokio::sync::Mutex<Option<tokio::fs::File>>,
}

#[derive(Debug)]
pub(crate) struct RemoteDownload {
    revision: RemoteClipboardRevision,
    root: Arc<cm_platform::secure_temp::SecureClipboardRoot>,
    pub(crate) directory: Arc<cm_platform::secure_temp::SecureStagingDirectory>,
    entries: Vec<Arc<RemoteFileEntry>>,
    paths: Vec<PathBuf>,
    clip_data_id: Option<u32>,
    file_index: usize,
    offset: u64,
    phase: RemoteFilePhase,
    started: Instant,
    last_activity: Instant,
    adopted: bool,
}

impl Drop for RemoteDownload {
    fn drop(&mut self) {
        if !self.adopted {
            let _ = self.root.cleanup_staging_path(self.directory.path());
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum RemoteFilePhase {
    NeedSize,
    NeedRange,
    AwaitingSize { stream_id: u32 },
    AwaitingRange { stream_id: u32, requested: u32 },
    Storing { last: bool },
}

#[derive(Debug)]
pub(crate) enum ClipboardWork {
    InitiateCopy {
        kind: AdvertiseKind,
        formats: Vec<ClipboardFormat>,
    },
    PrepareFileCopy {
        kind: AdvertiseKind,
        revision: LocalClipboardRevision,
        paths: Vec<PathBuf>,
    },
    InitiateFileCopy {
        kind: AdvertiseKind,
        catalog: Arc<LocalFileCatalog>,
    },
    InitiatePaste(ClipboardFormatId),
    SubmitFormatData(OwnedFormatDataResponse),
    ServeFile {
        request: FileContentsRequest,
        entry: Option<Arc<LocalFileEntry>>,
    },
    PrepareRemoteFiles {
        revision: RemoteClipboardRevision,
        root: Arc<cm_platform::secure_temp::SecureClipboardRoot>,
        endpoint: cm_core::SessionEndpointId,
        descriptors: Vec<FileDescriptor>,
        clip_data_id: Option<u32>,
    },
    RequestRemoteFile(FileContentsRequest),
    StoreRemoteChunk {
        download: Arc<Mutex<RemoteDownload>>,
        entry: Arc<RemoteFileEntry>,
        offset: u64,
        data: Vec<u8>,
        last: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdvertiseKind {
    Initial,
    Local(LocalClipboardRevision),
}

#[derive(Debug)]
pub(crate) struct ClipboardBackend {
    temporary_directory: String,
    events: Arc<ClipboardEventMailbox>,
    active: bool,
    ready: bool,
    queued_advertise: Option<(AdvertiseKind, u8, Instant)>,
    emitting_ack: Option<(AdvertiseKind, u8)>,
    pending_ack: Option<(AdvertiseKind, u8, Instant)>,
    channel_disabled: bool,
    tx_disabled: bool,
    local: Option<(LocalClipboardRevision, ClipboardSnapshot)>,
    publish_after_ready: bool,
    remote_request: Option<(RemoteClipboardRevision, ClipboardFormatId)>,
    remote_rx: RemoteRxState,
    pending_format_requests: VecDeque<ClipboardFormatId>,
    pending_format_failure: bool,
    format_serve_disabled: bool,
    next_remote_revision: u64,
    files_available: bool,
    negotiated_capabilities: ClipboardGeneralCapabilityFlags,
    local_catalog: Option<Arc<LocalFileCatalog>>,
    locked_catalogs: HashMap<u32, Arc<LocalFileCatalog>>,
    pending_file_requests: VecDeque<FileContentsRequest>,
    pending_file_failure: Option<FileContentsRequest>,
    file_serve_disabled: bool,
    secure_root: Option<Arc<cm_platform::secure_temp::SecureClipboardRoot>>,
    endpoint_id: cm_core::SessionEndpointId,
    pending_remote_prepare: Option<(RemoteClipboardRevision, Vec<FileDescriptor>, Option<u32>)>,
    preparing_remote_revision: Option<RemoteClipboardRevision>,
    remote_download: Option<Arc<Mutex<RemoteDownload>>>,
    pending_remote_store: Option<(u64, Vec<u8>, bool)>,
    next_stream_id: u32,
}

#[derive(Debug)]
enum RemoteRxState {
    Idle,
    Awaiting {
        revision: RemoteClipboardRevision,
        format: ClipboardFormatId,
        deadline: Instant,
    },
    Draining {
        latest: Option<(RemoteClipboardRevision, ClipboardFormatId)>,
        deadline: Instant,
        resume_allowed: bool,
    },
    Disabled,
}

impl ClipboardBackend {
    pub(crate) fn new(
        events: Arc<ClipboardEventMailbox>,
        secure_root: Option<Arc<cm_platform::secure_temp::SecureClipboardRoot>>,
        endpoint_id: cm_core::SessionEndpointId,
    ) -> Self {
        let temporary_directory = secure_root
            .as_ref()
            .and_then(|root| root.path().to_str())
            .filter(|path| path.encode_utf16().count() <= 259)
            .unwrap_or("")
            .to_owned();
        let files_available = secure_root.is_some() && !temporary_directory.is_empty();
        Self {
            temporary_directory,
            events,
            active: false,
            ready: false,
            queued_advertise: None,
            emitting_ack: None,
            pending_ack: None,
            channel_disabled: false,
            tx_disabled: false,
            local: None,
            publish_after_ready: false,
            remote_request: None,
            remote_rx: RemoteRxState::Idle,
            pending_format_requests: VecDeque::new(),
            pending_format_failure: false,
            format_serve_disabled: false,
            next_remote_revision: 1,
            files_available,
            negotiated_capabilities: ClipboardGeneralCapabilityFlags::empty(),
            local_catalog: None,
            locked_catalogs: HashMap::new(),
            pending_file_requests: VecDeque::new(),
            pending_file_failure: None,
            file_serve_disabled: false,
            secure_root,
            endpoint_id,
            pending_remote_prepare: None,
            preparing_remote_revision: None,
            remote_download: None,
            pending_remote_store: None,
            next_stream_id: 1,
        }
    }

    pub(crate) fn set_active(&mut self, active: bool) {
        self.active = active;
        if !active {
            self.remote_request = None;
            self.pending_remote_prepare = None;
            self.preparing_remote_revision = None;
            self.pending_remote_store = None;
            self.remote_download = None;
            if let RemoteRxState::Awaiting { deadline, .. } = self.remote_rx {
                self.remote_rx = RemoteRxState::Draining {
                    latest: None,
                    deadline,
                    resume_allowed: false,
                };
            }
        }
    }

    pub(crate) fn publish_local(
        &mut self,
        revision: LocalClipboardRevision,
        snapshot: ClipboardSnapshot,
    ) {
        if self.channel_disabled
            || self.tx_disabled
            || !valid_snapshot(&snapshot)
            || (matches!(snapshot, ClipboardSnapshot::Files(_))
                && (!self.files_available || (self.ready && !self.file_transfer_enabled())))
        {
            self.emit_advertise_result(revision, ClipboardPublishResult::Rejected);
            return;
        }
        self.local = Some((revision, snapshot));
        self.publish_after_ready = true;
    }

    pub(crate) fn take_work(&mut self) -> Option<ClipboardWork> {
        self.tick();
        if self.pending_ack.is_none()
            && self.emitting_ack.is_none()
            && let Some((kind, attempt, due)) = self.queued_advertise
            && Instant::now() >= due
        {
            self.queued_advertise = None;
            let formats = match kind {
                AdvertiseKind::Initial => Vec::new(),
                AdvertiseKind::Local(revision) => self
                    .local
                    .as_ref()
                    .filter(|(current, _)| *current == revision)
                    .map_or_else(Vec::new, |(_, snapshot)| formats_for(snapshot)),
            };
            if let AdvertiseKind::Local(revision) = kind
                && let Some((_, ClipboardSnapshot::Files(paths))) = self
                    .local
                    .as_ref()
                    .filter(|(current, _)| *current == revision)
            {
                if let Some(catalog) = self
                    .local_catalog
                    .as_ref()
                    .filter(|catalog| catalog.revision == revision)
                {
                    self.emitting_ack = Some((kind, attempt));
                    return Some(ClipboardWork::InitiateFileCopy {
                        kind,
                        catalog: Arc::clone(catalog),
                    });
                }
                self.emitting_ack = Some((kind, attempt));
                return Some(ClipboardWork::PrepareFileCopy {
                    kind,
                    revision,
                    paths: paths.clone(),
                });
            }
            // Reserve response ownership before returning the work. The ACK
            // deadline starts only after IronRDP emitted and the driver wrote
            // the FormatList successfully.
            self.emitting_ack = Some((kind, attempt));
            return Some(ClipboardWork::InitiateCopy { kind, formats });
        }
        if self.ready
            && !self.tx_disabled
            && self.publish_after_ready
            && self.pending_ack.is_none()
            && self.emitting_ack.is_none()
        {
            self.publish_after_ready = false;
            if let Some((revision, snapshot)) = &self.local {
                if let ClipboardSnapshot::Files(paths) = snapshot {
                    if !self.file_transfer_enabled() {
                        self.emit_advertise_result(*revision, ClipboardPublishResult::Rejected);
                        return None;
                    }
                    let kind = AdvertiseKind::Local(*revision);
                    self.emitting_ack = Some((kind, 1));
                    return Some(ClipboardWork::PrepareFileCopy {
                        kind,
                        revision: *revision,
                        paths: paths.clone(),
                    });
                }
                let formats = formats_for(snapshot);
                let kind = AdvertiseKind::Local(*revision);
                self.emitting_ack = Some((kind, 1));
                return Some(ClipboardWork::InitiateCopy { kind, formats });
            }
        }
        if let Some((revision, format)) = self.remote_request.take() {
            self.remote_rx = RemoteRxState::Awaiting {
                revision,
                format,
                deadline: Instant::now() + ACK_TIMEOUT,
            };
            return Some(ClipboardWork::InitiatePaste(format));
        }
        if let Some(format) = self.pending_format_requests.pop_front() {
            let response = if format == CF_UNICODETEXT {
                match self.local.as_ref().map(|(_, snapshot)| snapshot) {
                    Some(ClipboardSnapshot::Text(text)) => {
                        OwnedFormatDataResponse::new_unicode_string(&to_windows_lines(text))
                    }
                    _ => OwnedFormatDataResponse::new_error(),
                }
            } else {
                OwnedFormatDataResponse::new_error()
            };
            return Some(ClipboardWork::SubmitFormatData(response));
        }
        if self.pending_format_failure {
            self.pending_format_failure = false;
            return Some(ClipboardWork::SubmitFormatData(
                OwnedFormatDataResponse::new_error(),
            ));
        }
        if let Some(request) = self.pending_file_requests.pop_front() {
            let entry = self.catalog_for_request(&request).and_then(|catalog| {
                usize::try_from(request.index)
                    .ok()
                    .and_then(|index| catalog.entries.get(index).cloned())
            });
            return Some(ClipboardWork::ServeFile { request, entry });
        }
        if let Some(request) = self.pending_file_failure.take() {
            return Some(ClipboardWork::ServeFile {
                request,
                entry: None,
            });
        }
        if let Some((revision, descriptors, clip_data_id)) = self.pending_remote_prepare.take()
            && let Some(root) = self.secure_root.as_ref()
        {
            self.preparing_remote_revision = Some(revision);
            return Some(ClipboardWork::PrepareRemoteFiles {
                revision,
                root: Arc::clone(root),
                endpoint: self.endpoint_id,
                descriptors,
                clip_data_id,
            });
        }
        if let Some((offset, data, last)) = self.pending_remote_store.take()
            && let Some(download) = self.remote_download.as_ref()
            && let Ok(guard) = download.lock()
            && let Some(entry) = guard.entries.get(guard.file_index).cloned()
        {
            drop(guard);
            return Some(ClipboardWork::StoreRemoteChunk {
                download: Arc::clone(download),
                entry,
                offset,
                data,
                last,
            });
        }
        if let Some(download) = self.remote_download.as_ref()
            && let Ok(mut download) = download.lock()
        {
            let stream_id = self.next_stream_id;
            let Some(next_stream_id) = self.next_stream_id.checked_add(1) else {
                self.remote_rx = RemoteRxState::Disabled;
                return None;
            };
            let request = match download.phase {
                RemoteFilePhase::NeedSize => {
                    download.phase = RemoteFilePhase::AwaitingSize { stream_id };
                    Some(FileContentsRequest {
                        stream_id,
                        index: download.file_index as i32,
                        flags: FileContentsFlags::SIZE,
                        position: 0,
                        requested_size: 8,
                        data_id: download.clip_data_id,
                    })
                }
                RemoteFilePhase::NeedRange => {
                    let remaining = download.entries[download.file_index]
                        .size
                        .saturating_sub(download.offset);
                    let requested = remaining.min(u64::from(MAX_FILE_CHUNK)) as u32;
                    download.phase = RemoteFilePhase::AwaitingRange {
                        stream_id,
                        requested,
                    };
                    Some(FileContentsRequest {
                        stream_id,
                        index: download.file_index as i32,
                        flags: FileContentsFlags::RANGE,
                        position: download.offset,
                        requested_size: requested,
                        data_id: download.clip_data_id,
                    })
                }
                RemoteFilePhase::AwaitingSize { .. }
                | RemoteFilePhase::AwaitingRange { .. }
                | RemoteFilePhase::Storing { .. } => None,
            };
            if let Some(request) = request {
                self.next_stream_id = next_stream_id;
                return Some(ClipboardWork::RequestRemoteFile(request));
            }
        }
        None
    }

    pub(crate) fn install_local_catalog(
        &mut self,
        revision: LocalClipboardRevision,
        catalog: Arc<LocalFileCatalog>,
    ) -> bool {
        if self
            .local
            .as_ref()
            .is_some_and(|(current, _)| *current == revision)
            && self
                .emitting_ack
                .is_some_and(|(kind, _)| kind == AdvertiseKind::Local(revision))
        {
            self.local_catalog = Some(catalog);
            true
        } else {
            false
        }
    }

    pub(crate) fn install_remote_download(&mut self, download: Arc<Mutex<RemoteDownload>>) {
        let revision = download.lock().ok().map(|state| state.revision);
        if revision.is_none()
            || revision != self.preparing_remote_revision.take()
            || !self.active
            || !matches!(self.remote_rx, RemoteRxState::Idle)
        {
            return;
        }
        self.remote_download = Some(download);
    }

    pub(crate) fn remote_store_completed(
        &mut self,
        expected: &Arc<Mutex<RemoteDownload>>,
        succeeded: bool,
        written: u64,
    ) {
        let Some(download) = self
            .remote_download
            .as_ref()
            .filter(|current| Arc::ptr_eq(current, expected))
            .cloned()
        else {
            return;
        };
        let Ok(mut state) = download.lock() else {
            self.remote_download = None;
            return;
        };
        let RemoteFilePhase::Storing { last } = state.phase else {
            return;
        };
        if !succeeded {
            drop(state);
            self.remote_download = None;
            return;
        }
        state.last_activity = Instant::now();
        state.offset = state.offset.saturating_add(written);
        if last {
            state.file_index += 1;
            state.offset = 0;
            if state.file_index == state.entries.len() {
                let revision = state.revision;
                let root = state.directory.path().to_path_buf();
                let paths = state.paths.clone();
                state.adopted = true;
                drop(state);
                self.remote_download = None;
                self.events.remote_files(revision, root, paths);
                return;
            }
            state.phase = RemoteFilePhase::NeedSize;
        } else {
            state.phase = RemoteFilePhase::NeedRange;
        }
    }

    pub(crate) fn work_succeeded(&mut self, work: &ClipboardWork) {
        let kind = match work {
            ClipboardWork::InitiateCopy { kind, .. }
            | ClipboardWork::PrepareFileCopy { kind, .. }
            | ClipboardWork::InitiateFileCopy { kind, .. } => *kind,
            ClipboardWork::InitiatePaste(_)
            | ClipboardWork::SubmitFormatData(_)
            | ClipboardWork::ServeFile { .. }
            | ClipboardWork::PrepareRemoteFiles { .. }
            | ClipboardWork::RequestRemoteFile(_)
            | ClipboardWork::StoreRemoteChunk { .. } => return,
        };
        if self
            .emitting_ack
            .is_some_and(|(emitted, _)| emitted == kind)
            && let Some((_, attempt)) = self.emitting_ack.take()
        {
            self.pending_ack = Some((kind, attempt, Instant::now() + ACK_TIMEOUT));
        }
    }

    fn catalog_for_request(&self, request: &FileContentsRequest) -> Option<&Arc<LocalFileCatalog>> {
        match request.data_id {
            Some(id) => self.locked_catalogs.get(&id),
            None => self.current_local_catalog(),
        }
    }

    fn current_local_catalog(&self) -> Option<&Arc<LocalFileCatalog>> {
        self.local_catalog.as_ref().filter(|catalog| {
            self.local.as_ref().is_some_and(|(revision, snapshot)| {
                *revision == catalog.revision && matches!(snapshot, ClipboardSnapshot::Files(_))
            })
        })
    }

    fn file_transfer_enabled(&self) -> bool {
        self.files_available
            && self.negotiated_capabilities.contains(
                ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
                    | ClipboardGeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS,
            )
    }

    pub(crate) fn work_failed(&mut self, work: &ClipboardWork) {
        match work {
            ClipboardWork::InitiateCopy { kind, .. } => {
                self.emitting_ack = None;
                self.pending_ack = None;
                self.reject_unsent_advertisement(*kind);
            }
            ClipboardWork::PrepareFileCopy { kind, .. }
            | ClipboardWork::InitiateFileCopy { kind, .. } => {
                self.emitting_ack = None;
                self.pending_ack = None;
                self.reject_unsent_advertisement(*kind);
            }
            ClipboardWork::InitiatePaste(_) => {
                self.remote_rx = RemoteRxState::Idle;
            }
            ClipboardWork::SubmitFormatData(_) | ClipboardWork::ServeFile { .. } => {}
            ClipboardWork::PrepareRemoteFiles { revision, .. } => {
                if self.preparing_remote_revision == Some(*revision) {
                    self.preparing_remote_revision = None;
                }
            }
            ClipboardWork::StoreRemoteChunk { download, .. } => {
                self.remote_store_completed(download, false, 0);
            }
            ClipboardWork::RequestRemoteFile(_) => {
                self.remote_download = None;
                self.pending_remote_store = None;
            }
        }
    }

    pub(crate) fn local_prepare_failed(&mut self, kind: AdvertiseKind) {
        self.emitting_ack = None;
        self.pending_ack = None;
        self.reject_unsent_advertisement(kind);
    }

    pub(crate) fn remote_prepare_failed(&mut self, revision: RemoteClipboardRevision) {
        if self.preparing_remote_revision == Some(revision) {
            self.preparing_remote_revision = None;
        }
    }

    pub(crate) fn tick(&mut self) {
        if self
            .pending_ack
            .as_ref()
            .is_some_and(|(_, _, deadline)| Instant::now() >= *deadline)
            && let Some((kind, _, _)) = self.pending_ack.take()
        {
            // FormatListResponse has no request ID. After a timeout any late
            // response makes future ownership ambiguous, so never retransmit.
            self.disable_advertisement(kind);
        }
        let rx_expired = match self.remote_rx {
            RemoteRxState::Awaiting { deadline, .. } | RemoteRxState::Draining { deadline, .. } => {
                Instant::now() >= deadline
            }
            RemoteRxState::Idle | RemoteRxState::Disabled => false,
        };
        if rx_expired {
            self.remote_request = None;
            self.remote_rx = RemoteRxState::Disabled;
        }
        let download_expired = self.remote_download.as_ref().is_some_and(|download| {
            download.lock().is_ok_and(|state| {
                state.started.elapsed() >= Duration::from_secs(30 * 60)
                    || state.last_activity.elapsed() >= Duration::from_secs(60)
            })
        });
        if download_expired {
            self.remote_download = None;
            self.pending_remote_store = None;
        }
    }

    fn disable_advertisement(&mut self, kind: AdvertiseKind) {
        match kind {
            AdvertiseKind::Initial => {
                self.channel_disabled = true;
                self.queued_advertise = None;
                if let Some((revision, _)) = self.local.take() {
                    self.emit_advertise_result(revision, ClipboardPublishResult::Rejected);
                }
            }
            AdvertiseKind::Local(revision) => {
                self.tx_disabled = true;
                self.publish_after_ready = false;
                self.emit_advertise_result(revision, ClipboardPublishResult::Rejected);
            }
        }
    }

    fn reject_unsent_advertisement(&mut self, kind: AdvertiseKind) {
        match kind {
            AdvertiseKind::Initial => self.disable_advertisement(kind),
            AdvertiseKind::Local(revision) => {
                self.publish_after_ready = false;
                self.emit_advertise_result(revision, ClipboardPublishResult::Rejected);
            }
        }
    }

    fn emit_advertise_result(
        &mut self,
        revision: LocalClipboardRevision,
        result: ClipboardPublishResult,
    ) {
        if !self.events.advertise_result(revision, result) {
            // A FormatListResponse has no wire correlation. Losing a result
            // would let the controller advance while this backend still owns
            // an older response, so fail the publishing direction closed.
            self.tx_disabled = true;
            self.publish_after_ready = false;
        }
    }
}

ironrdp_core::impl_as_any!(ClipboardBackend);

impl CliprdrBackend for ClipboardBackend {
    fn temporary_directory(&self) -> &str {
        &self.temporary_directory
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        if self.files_available {
            ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
                | ClipboardGeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS
                | ClipboardGeneralCapabilityFlags::CAN_LOCK_CLIPDATA
        } else {
            ClipboardGeneralCapabilityFlags::empty()
        }
    }

    fn on_ready(&mut self) {
        self.ready = true;
    }

    fn on_request_format_list(&mut self) {
        if !self.channel_disabled {
            self.queued_advertise = Some((AdvertiseKind::Initial, 1, Instant::now()));
        }
    }

    fn on_format_list_response(&mut self, ok: bool) {
        let Some((kind, attempt, _)) = self.pending_ack.take() else {
            return;
        };
        if ok {
            if let AdvertiseKind::Local(revision) = kind {
                self.emit_advertise_result(revision, ClipboardPublishResult::Advertised);
            }
            return;
        }
        if attempt < 4 {
            let delay = match attempt {
                1 => Duration::from_millis(100),
                2 => Duration::from_millis(250),
                _ => Duration::from_millis(500),
            };
            self.queued_advertise = Some((kind, attempt + 1, Instant::now() + delay));
        } else {
            self.disable_advertisement(kind);
        }
    }

    fn on_process_negotiated_capabilities(
        &mut self,
        capabilities: ClipboardGeneralCapabilityFlags,
    ) {
        self.negotiated_capabilities = capabilities;
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        let revision = RemoteClipboardRevision(self.next_remote_revision);
        let Some(next) = self.next_remote_revision.checked_add(1) else {
            self.remote_request = None;
            self.remote_rx = RemoteRxState::Disabled;
            return;
        };
        self.next_remote_revision = next;
        let file_offer = self.file_transfer_enabled().then(|| {
            available_formats.iter().find_map(|format| {
                format
                    .name()
                    .is_some_and(|name| name.value() == ironrdp_cliprdr::pdu::FORMAT_NAME_FILE_LIST)
                    .then_some((revision, format.id))
            })
        });
        let text_offer = available_formats
            .iter()
            .any(|format| format.id == CF_UNICODETEXT)
            .then_some((revision, CF_UNICODETEXT));
        let offer = file_offer.flatten().or(text_offer);
        self.remote_download = None;
        self.pending_remote_prepare = None;
        self.preparing_remote_revision = None;
        self.pending_remote_store = None;
        match &mut self.remote_rx {
            RemoteRxState::Awaiting { deadline, .. } => {
                self.remote_request = None;
                self.remote_rx = RemoteRxState::Draining {
                    latest: self.active.then_some(offer).flatten(),
                    deadline: *deadline,
                    resume_allowed: self.active,
                };
            }
            RemoteRxState::Draining {
                latest,
                resume_allowed,
                ..
            } => {
                *latest = (*resume_allowed && self.active).then_some(offer).flatten();
            }
            RemoteRxState::Idle if !self.channel_disabled && self.active => {
                self.remote_request = offer;
            }
            RemoteRxState::Idle | RemoteRxState::Disabled => {}
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        if self.format_serve_disabled {
            return;
        }
        if self.pending_format_requests.len() < MAX_PENDING_FORMAT_REQUESTS {
            self.pending_format_requests.push_back(request.format);
        } else {
            // The response has no correlation ID, so fail the triggering
            // request in FIFO order and close this serving direction rather
            // than silently overwrite or grow without bound.
            self.pending_format_failure = true;
            self.format_serve_disabled = true;
        }
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        let state = std::mem::replace(&mut self.remote_rx, RemoteRxState::Idle);
        let (revision, format) = match state {
            RemoteRxState::Awaiting {
                revision, format, ..
            } => (revision, format),
            RemoteRxState::Draining {
                latest,
                resume_allowed,
                ..
            } => {
                if resume_allowed && self.active {
                    self.remote_request = latest;
                }
                return;
            }
            RemoteRxState::Idle => return,
            RemoteRxState::Disabled => {
                self.remote_rx = RemoteRxState::Disabled;
                return;
            }
        };
        if response.is_error() {
            return;
        }
        if format == CF_UNICODETEXT
            && let Some(text) = decode_remote_text(response.data())
        {
            self.events.remote_text(revision, text);
        }
    }

    fn on_file_contents_request(&mut self, request: FileContentsRequest) {
        if self.file_serve_disabled {
            return;
        }
        if self.pending_file_requests.len() < MAX_FILES {
            self.pending_file_requests.push_back(request);
        } else {
            // FILECONTENTS responses carry stream_id, so the triggering
            // overflow receives an explicit error after queued work drains.
            // Then fail this serving direction closed to keep memory bounded.
            self.pending_file_failure = Some(request);
            self.file_serve_disabled = true;
        }
    }
    fn on_file_contents_response(&mut self, response: FileContentsResponse<'_>) {
        let Some(download) = self.remote_download.as_ref() else {
            return;
        };
        let Ok(mut state) = download.lock() else {
            return;
        };
        if response.is_error() {
            drop(state);
            self.remote_download = None;
            return;
        }
        match state.phase {
            RemoteFilePhase::AwaitingSize { stream_id } if stream_id == response.stream_id() => {
                let Ok(size) = response.data_as_size() else {
                    drop(state);
                    self.remote_download = None;
                    return;
                };
                if size != state.entries[state.file_index].size {
                    drop(state);
                    self.remote_download = None;
                    return;
                }
                state.last_activity = Instant::now();
                if size == 0 {
                    state.phase = RemoteFilePhase::Storing { last: true };
                    self.pending_remote_store = Some((0, Vec::new(), true));
                } else {
                    state.phase = RemoteFilePhase::NeedRange;
                }
            }
            RemoteFilePhase::AwaitingRange {
                stream_id,
                requested,
            } if stream_id == response.stream_id()
                && response.data().len() == requested as usize =>
            {
                let offset = state.offset;
                let last = offset + u64::from(requested) == state.entries[state.file_index].size;
                state.phase = RemoteFilePhase::Storing { last };
                self.pending_remote_store = Some((offset, response.data().to_vec(), last));
            }
            _ => {}
        }
    }
    fn on_lock(&mut self, data_id: LockDataId) {
        if self.locked_catalogs.len() < MAX_LOCKED_CATALOGS
            && let Some(catalog) = self.current_local_catalog()
        {
            self.locked_catalogs.insert(data_id.0, Arc::clone(catalog));
        }
    }
    fn on_unlock(&mut self, data_id: LockDataId) {
        self.locked_catalogs.remove(&data_id.0);
    }

    fn on_remote_file_list(&mut self, files: &[FileDescriptor], clip_data_id: Option<u32>) {
        let state = std::mem::replace(&mut self.remote_rx, RemoteRxState::Idle);
        let revision = match state {
            RemoteRxState::Awaiting { revision, .. } => revision,
            RemoteRxState::Draining {
                latest,
                resume_allowed,
                ..
            } => {
                if resume_allowed && self.active {
                    self.remote_request = latest;
                }
                return;
            }
            RemoteRxState::Idle => return,
            RemoteRxState::Disabled => {
                self.remote_rx = RemoteRxState::Disabled;
                return;
            }
        };
        if self.active && self.file_transfer_enabled() {
            self.pending_remote_prepare = Some((revision, files.to_vec(), clip_data_id));
        }
    }
}

fn formats_for(snapshot: &ClipboardSnapshot) -> Vec<ClipboardFormat> {
    match snapshot {
        ClipboardSnapshot::Text(_) => vec![ClipboardFormat {
            id: CF_UNICODETEXT,
            name: None,
        }],
        ClipboardSnapshot::Empty | ClipboardSnapshot::Files(_) => Vec::new(),
    }
}

fn valid_snapshot(snapshot: &ClipboardSnapshot) -> bool {
    match snapshot {
        ClipboardSnapshot::Text(text) => text.len() <= MAX_TEXT_BYTES && !text.contains('\0'),
        ClipboardSnapshot::Empty => true,
        ClipboardSnapshot::Files(paths) => !paths.is_empty() && paths.len() <= MAX_FILES,
    }
}

pub(crate) async fn prepare_local_catalog(
    revision: LocalClipboardRevision,
    paths: &[PathBuf],
) -> Result<Arc<LocalFileCatalog>, ()> {
    if paths.is_empty() || paths.len() > MAX_FILES {
        return Err(());
    }
    let mut entries = Vec::with_capacity(paths.len());
    let mut names = std::collections::HashSet::with_capacity(paths.len());
    let mut total = 0_u64;
    for path in paths {
        if !path.is_absolute() {
            return Err(());
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| valid_flat_file_name(name))
            .ok_or(())?
            .to_owned();
        if !names.insert(name.to_lowercase()) {
            return Err(());
        }
        let symlink_metadata = tokio::fs::symlink_metadata(path).await.map_err(|_| ())?;
        if symlink_metadata.file_type().is_symlink() || !symlink_metadata.is_file() {
            return Err(());
        }
        let file = open_local_no_follow(path).await?;
        let metadata = file.metadata().await.map_err(|_| ())?;
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
            return Err(());
        }
        total = total.checked_add(metadata.len()).ok_or(())?;
        if total > MAX_TOTAL_FILE_BYTES {
            return Err(());
        }
        #[cfg(windows)]
        let identity = cm_platform::secure_temp::windows_file_identity(&file).map_err(|_| ())?;
        entries.push(Arc::new(LocalFileEntry {
            name,
            size: metadata.len(),
            modified: metadata.modified().ok(),
            file: tokio::sync::Mutex::new(file),
            #[cfg(unix)]
            device: std::os::unix::fs::MetadataExt::dev(&metadata),
            #[cfg(unix)]
            inode: std::os::unix::fs::MetadataExt::ino(&metadata),
            #[cfg(windows)]
            identity,
        }));
    }
    Ok(Arc::new(LocalFileCatalog { revision, entries }))
}

async fn open_local_no_follow(path: &std::path::Path) -> Result<tokio::fs::File, ()> {
    let path = path.to_path_buf();
    let file = tokio::task::spawn_blocking(move || {
        cm_platform::secure_temp::open_regular_file_nofollow(&path)
    })
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    Ok(tokio::fs::File::from_std(file))
}

pub(crate) async fn serve_local_file(
    entry: &Option<Arc<LocalFileEntry>>,
    request: &FileContentsRequest,
) -> FileContentsResponse<'static> {
    let Some(entry) = entry else {
        return FileContentsResponse::new_error(request.stream_id);
    };
    let mut file = entry.file.lock().await;
    let Ok(metadata) = file.metadata().await else {
        return FileContentsResponse::new_error(request.stream_id);
    };
    #[cfg(unix)]
    if std::os::unix::fs::MetadataExt::dev(&metadata) != entry.device
        || std::os::unix::fs::MetadataExt::ino(&metadata) != entry.inode
    {
        return FileContentsResponse::new_error(request.stream_id);
    }
    #[cfg(windows)]
    if !matches!(
        cm_platform::secure_temp::windows_file_identity(&*file),
        Ok(identity) if identity == entry.identity
    ) {
        return FileContentsResponse::new_error(request.stream_id);
    }
    if !metadata.is_file()
        || metadata.len() != entry.size
        || metadata.modified().ok() != entry.modified
    {
        return FileContentsResponse::new_error(request.stream_id);
    }
    if request.flags.contains(FileContentsFlags::SIZE) {
        return FileContentsResponse::new_size_response(request.stream_id, entry.size);
    }
    if !request.flags.contains(FileContentsFlags::RANGE)
        || request.requested_size == 0
        || request.requested_size > MAX_FILE_CHUNK
        || request
            .position
            .checked_add(u64::from(request.requested_size))
            .is_none_or(|end| end > entry.size)
    {
        return FileContentsResponse::new_error(request.stream_id);
    }
    let mut data = vec![0; request.requested_size as usize];
    if file
        .seek(std::io::SeekFrom::Start(request.position))
        .await
        .is_err()
        || file.read_exact(&mut data).await.is_err()
    {
        return FileContentsResponse::new_error(request.stream_id);
    }
    FileContentsResponse::new_data_response(request.stream_id, data)
}

pub(crate) async fn prepare_remote_download(
    root: Arc<cm_platform::secure_temp::SecureClipboardRoot>,
    endpoint: cm_core::SessionEndpointId,
    revision: RemoteClipboardRevision,
    descriptors: &[FileDescriptor],
    clip_data_id: Option<u32>,
) -> Result<Arc<Mutex<RemoteDownload>>, ()> {
    if descriptors.is_empty() || descriptors.len() > MAX_FILES {
        return Err(());
    }
    let mut names = std::collections::HashSet::with_capacity(descriptors.len());
    let mut total = 0_u64;
    for descriptor in descriptors {
        if descriptor.relative_path.is_some()
            || descriptor
                .attributes
                .is_some_and(|attributes| attributes.contains(ClipboardFileAttributes::DIRECTORY))
            || !valid_flat_file_name(&descriptor.name)
            || !names.insert(descriptor.name.to_lowercase())
        {
            return Err(());
        }
        let size = descriptor.file_size.ok_or(())?;
        if size > MAX_FILE_BYTES {
            return Err(());
        }
        total = total.checked_add(size).ok_or(())?;
        if total > MAX_TOTAL_FILE_BYTES {
            return Err(());
        }
    }
    let directory = Arc::new(
        root.create_transfer_directory(endpoint.0, revision.0)
            .map_err(|_| ())?,
    );
    let mut entries = Vec::with_capacity(descriptors.len());
    let mut paths = Vec::with_capacity(descriptors.len());
    for (index, descriptor) in descriptors.iter().enumerate() {
        let partial_name = format!("{index}.partial");
        let file = match directory.create_new_file(&partial_name) {
            Ok(file) => file,
            Err(_) => {
                let _ = root.cleanup_staging_path(directory.path());
                return Err(());
            }
        };
        paths.push(directory.path().join(&descriptor.name));
        entries.push(Arc::new(RemoteFileEntry {
            name: descriptor.name.clone(),
            partial_name,
            size: descriptor.file_size.ok_or(())?,
            file: tokio::sync::Mutex::new(Some(tokio::fs::File::from_std(file))),
        }));
    }
    let now = Instant::now();
    Ok(Arc::new(Mutex::new(RemoteDownload {
        revision,
        root,
        directory,
        entries,
        paths,
        clip_data_id,
        file_index: 0,
        offset: 0,
        phase: RemoteFilePhase::NeedSize,
        started: now,
        last_activity: now,
        adopted: false,
    })))
}

pub(crate) async fn store_remote_chunk(
    entry: &Arc<RemoteFileEntry>,
    directory: &Arc<cm_platform::secure_temp::SecureStagingDirectory>,
    offset: u64,
    data: &[u8],
    last: bool,
) -> Result<(), ()> {
    let mut slot = entry.file.lock().await;
    let file = slot.as_mut().ok_or(())?;
    file.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|_| ())?;
    file.write_all(data).await.map_err(|_| ())?;
    if last {
        file.flush().await.map_err(|_| ())?;
        file.sync_all().await.map_err(|_| ())?;
        let closed = slot.take();
        drop(closed);
        directory
            .rename_leaf(&entry.partial_name, &entry.name)
            .map_err(|_| ())?;
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
        && !ironrdp_cliprdr::is_windows_device_name(name)
        && !name.ends_with(['.', ' '])
}

fn to_windows_lines(text: &str) -> String {
    normalize_lines(text).replace('\n', "\r\n")
}

fn normalize_lines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

fn decode_remote_text(data: &[u8]) -> Option<String> {
    if data.len() < 2 || !data.len().is_multiple_of(2) || data.len() > MAX_TEXT_BYTES * 2 + 2 {
        return None;
    }
    let units = data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let terminator = units.iter().position(|unit| *unit == 0)?;
    if units[terminator + 1..].iter().any(|unit| *unit != 0) {
        return None;
    }
    let text = String::from_utf16(&units[..terminator]).ok()?;
    let text = normalize_lines(&text);
    (text.len() <= MAX_TEXT_BYTES && !text.contains('\0')).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_backend(events: Arc<ClipboardEventMailbox>) -> ClipboardBackend {
        ClipboardBackend::new(events, None, cm_core::SessionEndpointId(1))
    }

    #[test]
    fn remote_unicode_text_is_normalized_and_bounded() {
        let bytes = "one\r\ntwo\rthree"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            decode_remote_text(&bytes).as_deref(),
            Some("one\ntwo\nthree")
        );
        assert!(decode_remote_text(&[1]).is_none());
    }

    #[test]
    fn advertised_is_distinct_from_content_transfer() {
        let events = Arc::new(ClipboardEventMailbox::default());
        let mut backend = text_backend(events.clone());
        backend.ready = true;
        backend.publish_local(
            LocalClipboardRevision(7),
            ClipboardSnapshot::Text("value".into()),
        );
        let work = backend.take_work().unwrap();
        assert!(matches!(work, ClipboardWork::InitiateCopy { .. }));
        backend.work_succeeded(&work);
        backend.on_format_list_response(true);
        assert!(matches!(
            events.drain().as_slice(),
            [RdpClipboardEvent::LocalAdvertiseResult {
                revision: LocalClipboardRevision(7),
                result: ClipboardPublishResult::Advertised
            }]
        ));
    }

    #[test]
    fn advertise_deadline_starts_only_after_driver_reports_success() {
        let events = Arc::new(ClipboardEventMailbox::default());
        let mut backend = text_backend(events);
        backend.ready = true;
        backend.publish_local(
            LocalClipboardRevision(8),
            ClipboardSnapshot::Text("value".into()),
        );
        let work = backend.take_work().unwrap();
        assert!(backend.pending_ack.is_none());
        assert!(backend.emitting_ack.is_some());
        backend.tick();
        assert!(!backend.tx_disabled);
        backend.work_succeeded(&work);
        assert!(backend.pending_ack.is_some());
    }

    #[test]
    fn full_result_mailbox_disables_future_publication() {
        let events = Arc::new(ClipboardEventMailbox::default());
        assert!(
            events.advertise_result(LocalClipboardRevision(1), ClipboardPublishResult::Rejected)
        );
        let mut backend = text_backend(events);
        backend.ready = true;
        backend.publish_local(
            LocalClipboardRevision(2),
            ClipboardSnapshot::Text("value".into()),
        );
        let work = backend.take_work().unwrap();
        backend.work_succeeded(&work);
        backend.on_format_list_response(true);
        assert!(backend.tx_disabled);
        backend.publish_local(
            LocalClipboardRevision(3),
            ClipboardSnapshot::Text("later".into()),
        );
        assert!(backend.take_work().is_none());
    }

    #[test]
    fn explicit_fail_retries_but_ack_timeout_disables_tx_and_late_ok_is_ignored() {
        let events = Arc::new(ClipboardEventMailbox::default());
        let mut backend = text_backend(events.clone());
        backend.ready = true;
        backend.publish_local(
            LocalClipboardRevision(9),
            ClipboardSnapshot::Text("value".into()),
        );
        let work = backend.take_work().unwrap();
        assert!(matches!(work, ClipboardWork::InitiateCopy { .. }));
        backend.work_succeeded(&work);
        backend.on_format_list_response(false);
        assert!(backend.queued_advertise.is_some());
        backend.queued_advertise.as_mut().unwrap().2 = Instant::now();
        let work = backend.take_work().unwrap();
        assert!(matches!(work, ClipboardWork::InitiateCopy { .. }));
        backend.work_succeeded(&work);
        backend.pending_ack.as_mut().unwrap().2 = Instant::now() - Duration::from_millis(1);
        backend.tick();
        assert!(backend.tx_disabled);
        backend.on_format_list_response(true);
        assert!(matches!(
            events.drain().as_slice(),
            [RdpClipboardEvent::LocalAdvertiseResult {
                revision: LocalClipboardRevision(9),
                result: ClipboardPublishResult::Rejected
            }]
        ));
        backend.publish_local(
            LocalClipboardRevision(10),
            ClipboardSnapshot::Text("new".into()),
        );
        assert!(backend.take_work().is_none());
    }

    #[test]
    fn new_offer_drains_uncorrelated_old_format_response_before_requesting_latest() {
        let events = Arc::new(ClipboardEventMailbox::default());
        let mut backend = text_backend(events);
        backend.active = true;
        backend.ready = true;
        let text = ClipboardFormat {
            id: CF_UNICODETEXT,
            name: None,
        };
        backend.on_remote_copy(std::slice::from_ref(&text));
        assert!(matches!(
            backend.take_work(),
            Some(ClipboardWork::InitiatePaste(_))
        ));
        backend.on_remote_copy(std::slice::from_ref(&text));
        assert!(matches!(backend.remote_rx, RemoteRxState::Draining { .. }));
        let old = "old"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        backend.on_format_data_response(FormatDataResponse::new_data(old));
        assert!(matches!(backend.remote_rx, RemoteRxState::Idle));
        assert!(matches!(
            backend.take_work(),
            Some(ClipboardWork::InitiatePaste(_))
        ));
    }

    #[test]
    fn absent_drained_format_response_disables_remote_direction() {
        let events = Arc::new(ClipboardEventMailbox::default());
        let mut backend = text_backend(events);
        backend.active = true;
        backend.ready = true;
        let text = ClipboardFormat {
            id: CF_UNICODETEXT,
            name: None,
        };
        backend.on_remote_copy(std::slice::from_ref(&text));
        assert!(matches!(
            backend.take_work(),
            Some(ClipboardWork::InitiatePaste(_))
        ));
        backend.on_remote_copy(std::slice::from_ref(&text));
        let RemoteRxState::Draining { deadline, .. } = &mut backend.remote_rx else {
            panic!("expected an uncorrelated-response drain");
        };
        *deadline = Instant::now() - Duration::from_millis(1);
        backend.tick();
        assert!(matches!(backend.remote_rx, RemoteRxState::Disabled));

        let late = "old"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        backend.on_format_data_response(FormatDataResponse::new_data(late));
        assert!(backend.take_work().is_none());
    }

    #[test]
    fn flat_file_policy_counts_utf16_and_rejects_windows_hazards() {
        assert!(valid_flat_file_name("report.txt"));
        assert!(!valid_flat_file_name("../report.txt"));
        assert!(!valid_flat_file_name("NUL.txt"));
        assert!(!valid_flat_file_name("trailing. "));
        assert!(!valid_flat_file_name(&"a".repeat(256)));
        assert!(!valid_flat_file_name(&"😀".repeat(128)));
    }

    #[test]
    fn pipelined_format_requests_are_served_fifo_without_overwrite() {
        let events = Arc::new(ClipboardEventMailbox::default());
        let mut backend = text_backend(events);
        backend.local = Some((
            LocalClipboardRevision(1),
            ClipboardSnapshot::Text("synthetic".into()),
        ));
        backend.on_format_data_request(FormatDataRequest {
            format: CF_UNICODETEXT,
        });
        backend.on_format_data_request(FormatDataRequest {
            format: ClipboardFormatId(999),
        });
        assert!(matches!(
            backend.take_work(),
            Some(ClipboardWork::SubmitFormatData(_))
        ));
        assert!(matches!(
            backend.take_work(),
            Some(ClipboardWork::SubmitFormatData(_))
        ));
        assert!(backend.take_work().is_none());
    }

    #[test]
    fn format_request_overflow_is_bounded_and_schedules_explicit_failure() {
        let events = Arc::new(ClipboardEventMailbox::default());
        let mut backend = text_backend(events);
        for _ in 0..MAX_PENDING_FORMAT_REQUESTS {
            backend.on_format_data_request(FormatDataRequest {
                format: CF_UNICODETEXT,
            });
        }
        backend.on_format_data_request(FormatDataRequest {
            format: CF_UNICODETEXT,
        });
        assert!(backend.format_serve_disabled);
        assert_eq!(
            backend.pending_format_requests.len(),
            MAX_PENDING_FORMAT_REQUESTS
        );
        for _ in 0..MAX_PENDING_FORMAT_REQUESTS {
            assert!(matches!(
                backend.take_work(),
                Some(ClipboardWork::SubmitFormatData(_))
            ));
        }
        assert!(backend.pending_format_failure);
        assert!(matches!(
            backend.take_work(),
            Some(ClipboardWork::SubmitFormatData(_))
        ));
        assert!(!backend.pending_format_failure);
    }

    fn file_request(stream_id: u32) -> FileContentsRequest {
        FileContentsRequest {
            stream_id,
            index: 0,
            flags: FileContentsFlags::SIZE,
            position: 0,
            requested_size: 8,
            data_id: None,
        }
    }

    #[test]
    fn file_request_overflow_returns_correlated_failure_and_fails_closed() {
        let events = Arc::new(ClipboardEventMailbox::default());
        let mut backend = text_backend(events);
        for stream_id in 0..MAX_FILES as u32 {
            backend.on_file_contents_request(file_request(stream_id));
        }
        backend.on_file_contents_request(file_request(999));
        assert!(backend.file_serve_disabled);
        assert_eq!(backend.pending_file_requests.len(), MAX_FILES);
        for expected in 0..MAX_FILES as u32 {
            let Some(ClipboardWork::ServeFile { request, .. }) = backend.take_work() else {
                panic!("queued file request missing");
            };
            assert_eq!(request.stream_id, expected);
        }
        let Some(ClipboardWork::ServeFile { request, entry }) = backend.take_work() else {
            panic!("overflow failure missing");
        };
        assert_eq!(request.stream_id, 999);
        assert!(entry.is_none());
    }

    #[test]
    fn prepared_catalog_serves_exact_bounded_ranges() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("synthetic.bin");
        std::fs::write(&path, b"0123456789").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let catalog = prepare_local_catalog(LocalClipboardRevision(3), &[path])
                .await
                .unwrap();
            assert_eq!(catalog.descriptors()[0].file_size, Some(10));
            let entry = Some(Arc::clone(&catalog.entries[0]));
            let size = serve_local_file(
                &entry,
                &FileContentsRequest {
                    stream_id: 1,
                    index: 0,
                    flags: FileContentsFlags::SIZE,
                    position: 0,
                    requested_size: 8,
                    data_id: None,
                },
            )
            .await;
            assert_eq!(size.data_as_size().unwrap(), 10);
            let range = serve_local_file(
                &entry,
                &FileContentsRequest {
                    stream_id: 2,
                    index: 0,
                    flags: FileContentsFlags::RANGE,
                    position: 3,
                    requested_size: 4,
                    data_id: None,
                },
            )
            .await;
            assert_eq!(range.data(), b"3456");
        });
    }

    #[test]
    fn remote_file_is_staged_then_atomically_exposed() {
        let root = Arc::new(
            cm_platform::secure_temp::SecureClipboardRoot::bootstrap().expect("secure root"),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let descriptor = FileDescriptor::new("received.bin")
                .with_attributes(ClipboardFileAttributes::NORMAL)
                .with_file_size(6);
            let download = prepare_remote_download(
                Arc::clone(&root),
                cm_core::SessionEndpointId(77),
                RemoteClipboardRevision(4),
                &[descriptor],
                Some(9),
            )
            .await
            .unwrap();
            let (entry, directory, final_path) = {
                let state = download.lock().unwrap();
                (
                    Arc::clone(&state.entries[0]),
                    Arc::clone(&state.directory),
                    state.paths[0].clone(),
                )
            };
            store_remote_chunk(&entry, &directory, 0, b"abcdef", true)
                .await
                .unwrap();
            assert_eq!(tokio::fs::read(&final_path).await.unwrap(), b"abcdef");
            drop(download);
            assert!(!final_path.exists());
        });
    }

    #[test]
    fn remote_file_descriptor_rejects_paths_and_declared_oversize() {
        let root = Arc::new(
            cm_platform::secure_temp::SecureClipboardRoot::bootstrap().expect("secure root"),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let nested = FileDescriptor::new("file.txt")
                .with_relative_path("folder")
                .with_file_size(1);
            assert!(
                prepare_remote_download(
                    Arc::clone(&root),
                    cm_core::SessionEndpointId(78),
                    RemoteClipboardRevision(5),
                    &[nested],
                    None,
                )
                .await
                .is_err()
            );
            let huge = FileDescriptor::new("huge.bin").with_file_size(MAX_FILE_BYTES + 1);
            assert!(
                prepare_remote_download(
                    root,
                    cm_core::SessionEndpointId(78),
                    RemoteClipboardRevision(6),
                    &[huge],
                    None,
                )
                .await
                .is_err()
            );
        });
    }

    #[test]
    fn undrained_mailbox_drop_cleans_adopted_file_staging() {
        let root = Arc::new(
            cm_platform::secure_temp::SecureClipboardRoot::bootstrap().expect("secure root"),
        );
        let directory = root
            .create_transfer_directory(91, 7)
            .expect("transfer directory");
        let staging_root = directory.path().to_path_buf();
        let path = staging_root.join("received.bin");
        std::fs::write(&path, b"synthetic").expect("fixture");
        drop(directory);

        let mailbox = ClipboardEventMailbox::new(Some(Arc::clone(&root)));
        mailbox.remote_files(RemoteClipboardRevision(7), staging_root.clone(), vec![path]);
        drop(mailbox);

        assert!(!staging_root.exists());
    }

    #[test]
    fn stale_remote_prepare_completion_cannot_revive_after_deactivation() {
        let root = Arc::new(
            cm_platform::secure_temp::SecureClipboardRoot::bootstrap().expect("secure root"),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let revision = RemoteClipboardRevision(20);
            let descriptor = FileDescriptor::new("stale.bin").with_file_size(0);
            let download = prepare_remote_download(
                Arc::clone(&root),
                cm_core::SessionEndpointId(92),
                revision,
                &[descriptor],
                None,
            )
            .await
            .unwrap();
            let path = download.lock().unwrap().directory.path().to_path_buf();
            let events = Arc::new(ClipboardEventMailbox::new(Some(Arc::clone(&root))));
            let mut backend = ClipboardBackend::new(
                events,
                Some(Arc::clone(&root)),
                cm_core::SessionEndpointId(92),
            );
            backend.active = true;
            backend.preparing_remote_revision = Some(revision);
            backend.set_active(false);
            backend.install_remote_download(download);
            assert!(backend.remote_download.is_none());
            assert!(!path.exists());
        });
    }

    #[test]
    fn stale_store_completion_cannot_advance_a_newer_download() {
        let root = Arc::new(
            cm_platform::secure_temp::SecureClipboardRoot::bootstrap().expect("secure root"),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let make = |revision| {
                let root = Arc::clone(&root);
                async move {
                    let descriptors =
                        vec![FileDescriptor::new(format!("{revision:?}.bin")).with_file_size(1)];
                    prepare_remote_download(
                        root,
                        cm_core::SessionEndpointId(93),
                        revision,
                        &descriptors,
                        None,
                    )
                    .await
                }
            };
            let old = make(RemoteClipboardRevision(1)).await.unwrap();
            let current = make(RemoteClipboardRevision(2)).await.unwrap();
            current.lock().unwrap().phase = RemoteFilePhase::Storing { last: true };
            let events = Arc::new(ClipboardEventMailbox::new(Some(Arc::clone(&root))));
            let mut backend =
                ClipboardBackend::new(events, Some(root), cm_core::SessionEndpointId(93));
            backend.remote_download = Some(Arc::clone(&current));
            backend.remote_store_completed(&old, true, 1);
            assert!(
                backend
                    .remote_download
                    .as_ref()
                    .is_some_and(|download| Arc::ptr_eq(download, &current))
            );
            assert_eq!(current.lock().unwrap().offset, 0);
        });
    }
}

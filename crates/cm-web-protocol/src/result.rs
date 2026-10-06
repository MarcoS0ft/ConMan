use serde::{Deserialize, Serialize};

use crate::{
    BuildId, CanonicalUuid, DecimalI64, DecimalU64, RequiredNullable,
    command::{
        ConnectionDto, CredentialDto, CredentialFolderDto, EffectiveLimitsDto,
        GatewayPreferencesDto, GroupDto,
    },
    deserialize_required_nullable,
    error::ErrorDto,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResultDto {
    Bootstrap {
        value: BootstrapResultDto,
    },
    Workspace {
        transfer_id: CanonicalUuid,
        revision: DecimalU64,
    },
    ImportPreview {
        value: crate::command::ImportPreviewDto,
    },
    Export {
        filename: String,
        content_type: String,
        transfer_id: CanonicalUuid,
    },
    SessionOpened {
        value: SessionDto,
    },
    SessionClosed {},
    SessionDetached {},
    SessionAttached {
        value: SessionDto,
    },
    SessionInputAccepted {
        sequence: DecimalU64,
    },
    SessionResized {
        cols: u16,
        rows: u16,
    },
    ViewportSet {},
    Search {
        value: crate::command::SearchResultsDto,
    },
    ClipboardAccepted {
        sequence: DecimalU64,
    },
    ChallengeResponded {},
    ControlTransferRequested {},
    MutationCommitted {
        revision: DecimalU64,
        result: MutationResultDto,
    },
    MutationOutcome {
        value: MutationOutcomeDto,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapResultDto {
    pub build_id: BuildId,
    pub schema: u32,
    pub gateway_epoch: CanonicalUuid,
    pub lease_generation: DecimalU64,
    pub workspace_revision: DecimalU64,
    pub capabilities: Vec<CapabilityDto>,
    pub workspace_transfer_id: CanonicalUuid,
    pub preferences: GatewayPreferencesDto,
    pub sessions: Vec<SessionDto>,
    pub limits: EffectiveLimitsDto,
    pub control_state: ControlStateDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotPayload {
    pub workspace: WorkspaceDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceDto {
    pub revision: DecimalU64,
    pub connections: Vec<ConnectionDto>,
    pub groups: Vec<GroupDto>,
    pub credentials: Vec<CredentialDto>,
    pub credential_folders: Vec<CredentialFolderDto>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStateDto {
    Available,
    ControlledByThisBrowser,
    ReadOnlyOtherBrowser,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionDto {
    pub id: CanonicalUuid,
    pub generation: DecimalU64,
    pub kind: SessionKindDto,
    pub status: SessionStatusDto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKindDto {
    Rdp,
    Ssh,
    Telnet,
    GatewayTerminal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionStatusDto {
    Connecting {},
    Connected {},
    Disconnected {},
    Exited { success: bool, code: u32 },
    Failed { reason: SessionFailureKindDto },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionFailureKindDto {
    Setup,
    Authentication,
    TrustRejected,
    DestinationDenied,
    Timeout,
    Disconnected,
    ResourceLimit,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum NotificationDto {
    SessionChanged {
        session_id: CanonicalUuid,
        session_generation: DecimalU64,
        status: SessionStatusDto,
    },
    SurfaceResyncRequired {
        session_id: CanonicalUuid,
        session_generation: DecimalU64,
    },
    ChallengeIssued {
        challenge: ChallengeDto,
    },
    ChallengeCancelled {
        session_id: CanonicalUuid,
        session_generation: DecimalU64,
        challenge_id: CanonicalUuid,
    },
    SessionFailed {
        session_id: CanonicalUuid,
        session_generation: DecimalU64,
        reason: SessionFailureKindDto,
    },
    ApplicationFailure {
        reason: ApplicationFailureKindDto,
    },
    ControlTransferred {},
    RemoteClipboardOfferedText {
        session_id: CanonicalUuid,
        session_generation: DecimalU64,
        revision: DecimalU64,
        transfer_id: CanonicalUuid,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeDto {
    pub challenge_id: CanonicalUuid,
    pub session_id: CanonicalUuid,
    pub session_generation: DecimalU64,
    pub expires_at_ms: DecimalU64,
    pub kind: ChallengeKindDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChallengeKindDto {
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
    Password {},
    PrivateKey {},
    KeyboardInteractive {
        prompts: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationFailureKindDto {
    NotificationOverflow,
    ServiceStopping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityDto {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MutationResultDto {
    ConnectionId {
        id: DecimalI64,
    },
    GroupId {
        id: DecimalI64,
    },
    CredentialId {
        id: DecimalI64,
    },
    CredentialFolderId {
        id: DecimalI64,
    },
    Deleted {},
    Preferences {
        value: GatewayPreferencesDto,
    },
    ImportCommitted {
        value: crate::command::ImportStatsDto,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MutationOutcomeDto {
    Committed {
        revision: DecimalU64,
        result: MutationResultDto,
    },
    Failed {
        current_revision: DecimalU64,
        error: ErrorDto,
    },
    InProgress {},
    Unknown {
        current_revision: DecimalU64,
        reason: UnknownOutcomeReasonDto,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownOutcomeReasonDto {
    CacheExpired,
    GatewayEpochChanged,
    NotRetained,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyEnvelope {
    pub request_id: CanonicalUuid,
    pub gateway_epoch: CanonicalUuid,
    pub lease_generation: DecimalU64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub result: RequiredNullable<ResultDto>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub error: RequiredNullable<ErrorDto>,
}

impl ReplyEnvelope {
    pub fn validate(&self) -> Result<(), crate::ProtocolError> {
        if self.result.0.is_some() == self.error.0.is_some() {
            return Err(crate::ProtocolError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationEnvelope {
    pub gateway_epoch: CanonicalUuid,
    pub lease_generation: DecimalU64,
    pub notification: NotificationDto,
}

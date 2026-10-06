use serde::{Deserialize, Serialize};

use crate::command::CredentialRefDto;
use crate::result::{CapabilityDto, SessionFailureKindDto};
use crate::{CanonicalUuid, DecimalU64, RequiredNullable, deserialize_required_nullable};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorDto {
    pub code: WireErrorCode,
    pub message: String,
    pub retry: RetryHint,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub details: RequiredNullable<ErrorDetailsDto>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryHint {
    Never,
    AfterRefresh,
    QueryOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireErrorCode {
    InvalidRequest,
    UnsupportedSchema,
    BuildMismatch,
    AuthFailed,
    Unauthenticated,
    OriginDenied,
    CsrfDenied,
    TicketInvalid,
    RateLimited,
    LeaseRevoked,
    StaleEpoch,
    StaleSession,
    RevisionConflict,
    DuplicateOperationMismatch,
    OperationCacheFull,
    OutcomeUnknown,
    NotFound,
    ValidationFailed,
    PolicyDenied,
    CapabilityUnavailable,
    PersistenceFailed,
    SecretStoreUnavailable,
    SecretWriteFailed,
    SecretCompensationFailed,
    ImportTooLarge,
    ImportInvalid,
    PreviewExpired,
    QueueFull,
    ResourceLimit,
    ChallengeExpired,
    ChallengeAlreadyAnswered,
    SessionFailed,
    ServiceStopping,
    TransportLost,
    RevisionExhausted,
    InternalContractError,
    InternalError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppFieldDto {
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

pub type SecretReferenceDto = CredentialRefDto;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ErrorDetailsDto {
    RevisionConflict {
        current_revision: DecimalU64,
    },
    Validation {
        field: AppFieldDto,
    },
    CapabilityUnavailable {
        capability: CapabilityDto,
    },
    SessionFailed {
        reason: SessionFailureKindDto,
    },
    TransportUncertain {
        original_request_id: CanonicalUuid,
    },
    PartialRequiresReconcile {
        metadata_committed: bool,
        current_revision: DecimalU64,
        affected: Vec<SecretReferenceDto>,
        affected_total: u32,
        affected_truncated: bool,
    },
}

impl ErrorDto {
    pub fn validate(&self) -> Result<(), crate::ProtocolError> {
        if self.retry != self.code.retry_hint() {
            return Err(crate::ProtocolError::InvalidRequest);
        }
        if self.message.len() > 256 {
            return Err(crate::ProtocolError::ResourceLimit);
        }
        if let Some(ErrorDetailsDto::PartialRequiresReconcile {
            affected,
            affected_total,
            affected_truncated,
            ..
        }) = &self.details.0
            && (affected.len() > 32
                || (*affected_total as usize) < affected.len()
                || *affected_truncated != (*affected_total as usize > affected.len()))
        {
            return Err(crate::ProtocolError::InvalidRequest);
        }
        Ok(())
    }
}

impl WireErrorCode {
    pub const fn retry_hint(self) -> RetryHint {
        match self {
            Self::RevisionConflict | Self::StaleEpoch | Self::StaleSession | Self::LeaseRevoked => {
                RetryHint::AfterRefresh
            }
            Self::TransportLost => RetryHint::QueryOutcome,
            Self::InvalidRequest
            | Self::UnsupportedSchema
            | Self::BuildMismatch
            | Self::AuthFailed
            | Self::Unauthenticated
            | Self::OriginDenied
            | Self::CsrfDenied
            | Self::TicketInvalid
            | Self::RateLimited
            | Self::DuplicateOperationMismatch
            | Self::OperationCacheFull
            | Self::OutcomeUnknown
            | Self::NotFound
            | Self::ValidationFailed
            | Self::PolicyDenied
            | Self::CapabilityUnavailable
            | Self::PersistenceFailed
            | Self::SecretStoreUnavailable
            | Self::SecretWriteFailed
            | Self::SecretCompensationFailed
            | Self::ImportTooLarge
            | Self::ImportInvalid
            | Self::PreviewExpired
            | Self::QueueFull
            | Self::ResourceLimit
            | Self::ChallengeExpired
            | Self::ChallengeAlreadyAnswered
            | Self::SessionFailed
            | Self::ServiceStopping
            | Self::RevisionExhausted
            | Self::InternalContractError
            | Self::InternalError => RetryHint::Never,
        }
    }
}

use serde::de::DeserializeOwned;

use crate::{
    AuthenticatedDto, CanonicalUuid, CommandDto, CommandEnvelope, LoginRequestDto,
    NotificationEnvelope, ReplyEnvelope, WsAuthenticateDto,
    auth::{AssetManifestDto, WsTicketRequestDto},
    command::{ConnectionDto, CredentialDto, SearchResultsDto},
    result::{
        BootstrapResultDto, ChallengeKindDto, MutationOutcomeDto, NotificationDto, ResultDto,
        WorkspaceDto,
    },
};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_CONTROL_JSON_BYTES: usize = 1024 * 1024;
pub const MAX_JSON_NESTING: usize = 32;
pub const MAX_STRING_BYTES: usize = 64 * 1024;
pub const MAX_ARRAY_ITEMS: usize = 4096;
pub const MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION: usize = 64;
pub const MAX_IMPORT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SECRET_BYTES: usize = 64 * 1024;
pub const MAX_CLIPBOARD_TEXT_BYTES: usize = 1024 * 1024;
pub const MAX_SEARCH_QUERY_BYTES: usize = 4096;
pub const MAX_SEARCH_MATCHES: usize = 200;
pub const MAX_KEYBOARD_PROMPTS: usize = 32;
pub const MAX_RDP_INPUT_EVENTS: usize = 512;
pub const MAX_PARTIAL_SECRET_REFS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidUtf8,
    MalformedJson,
    MessageTooLarge,
    NestingTooDeep,
    InvalidRequest,
    UnsupportedSchema,
    BuildMismatch,
    StaleEpoch,
    LeaseRevoked,
    ResourceLimit,
    AuthFailed,
}

pub fn parse_strict<T: DeserializeOwned>(input: &[u8]) -> Result<T, ProtocolError> {
    if input.len() > MAX_CONTROL_JSON_BYTES {
        return Err(ProtocolError::MessageTooLarge);
    }
    std::str::from_utf8(input).map_err(|_| ProtocolError::InvalidUtf8)?;
    if nesting_exceeds_limit(input, MAX_JSON_NESTING) {
        return Err(ProtocolError::NestingTooDeep);
    }
    serde_json::from_slice(input).map_err(|_| ProtocolError::MalformedJson)
}

pub fn parse_command(input: &[u8]) -> Result<CommandEnvelope, ProtocolError> {
    let command: CommandEnvelope = parse_strict(input)?;
    command.validate()?;
    Ok(command)
}

pub fn parse_login(
    input: &[u8],
    expected_build: &crate::BuildId,
) -> Result<LoginRequestDto, ProtocolError> {
    if input.len() > 1024 {
        return Err(ProtocolError::MessageTooLarge);
    }
    let request: LoginRequestDto = parse_strict(input)?;
    validate_schema(request.schema)?;
    validate_build_id(&request.build_id, expected_build)?;
    Ok(request)
}

pub fn parse_ws_ticket_request(
    input: &[u8],
    expected_build: &crate::BuildId,
) -> Result<WsTicketRequestDto, ProtocolError> {
    let request: WsTicketRequestDto = parse_strict(input)?;
    validate_schema(request.schema)?;
    validate_build_id(&request.build_id, expected_build)?;
    Ok(request)
}

pub fn parse_ws_authenticate(
    input: &[u8],
    expected_build: &crate::BuildId,
) -> Result<WsAuthenticateDto, ProtocolError> {
    let request: WsAuthenticateDto = parse_strict(input)?;
    validate_schema(request.schema)?;
    validate_build_id(&request.build_id, expected_build)?;
    Ok(request)
}

pub fn parse_command_and_authorize(
    input: &[u8],
    expected_epoch: &CanonicalUuid,
    current_lease_generation: u64,
    has_owner_lease: bool,
) -> Result<CommandEnvelope, ProtocolError> {
    let command = parse_command(input)?;
    validate_command_authority(
        &command,
        expected_epoch,
        current_lease_generation,
        has_owner_lease,
    )?;
    Ok(command)
}

pub fn parse_reply(input: &[u8]) -> Result<ReplyEnvelope, ProtocolError> {
    let reply: ReplyEnvelope = parse_strict(input)?;
    reply.validate()?;
    if let Some(error) = &reply.error.0 {
        error.validate()?;
    }
    if let Some(result) = &reply.result.0 {
        validate_result(result)?;
    }
    Ok(reply)
}

pub fn parse_notification(input: &[u8]) -> Result<NotificationEnvelope, ProtocolError> {
    let envelope: NotificationEnvelope = parse_strict(input)?;
    validate_notification(&envelope.notification)?;
    Ok(envelope)
}

pub fn parse_authenticated(input: &[u8]) -> Result<AuthenticatedDto, ProtocolError> {
    let response: AuthenticatedDto = parse_strict(input)?;
    validate_bootstrap(&response.bootstrap)?;
    Ok(response)
}

pub fn parse_asset_manifest(input: &[u8]) -> Result<AssetManifestDto, ProtocolError> {
    let manifest: AssetManifestDto = parse_strict(input)?;
    validate_schema(manifest.schema)?;
    check_array(&manifest.asset_hashes, MAX_ARRAY_ITEMS)?;
    Ok(manifest)
}

pub fn serialize_control<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ProtocolError::InvalidRequest)?;
    if bytes.len() > MAX_CONTROL_JSON_BYTES {
        return Err(ProtocolError::MessageTooLarge);
    }
    Ok(bytes)
}

pub fn validate_result(value: &ResultDto) -> Result<(), ProtocolError> {
    match value {
        ResultDto::Bootstrap { value } => validate_bootstrap(value),
        ResultDto::ImportPreview { value } => {
            check_array(&value.warnings, 256)?;
            Ok(())
        }
        ResultDto::Export {
            filename,
            content_type,
            ..
        } => {
            check_string(filename, 255)?;
            check_string(content_type, 256)
        }
        ResultDto::SessionOpened { value } | ResultDto::SessionAttached { value } => {
            validate_session(value)
        }
        ResultDto::Search { value } => validate_search(value),
        ResultDto::MutationCommitted { result, .. } => match result {
            crate::result::MutationResultDto::Preferences { .. }
            | crate::result::MutationResultDto::ConnectionId { .. }
            | crate::result::MutationResultDto::GroupId { .. }
            | crate::result::MutationResultDto::CredentialId { .. }
            | crate::result::MutationResultDto::CredentialFolderId { .. }
            | crate::result::MutationResultDto::Deleted {} => Ok(()),
            crate::result::MutationResultDto::ImportCommitted { .. } => Ok(()),
        },
        ResultDto::MutationOutcome {
            value: MutationOutcomeDto::Failed { error, .. },
        } => error.validate(),
        _ => Ok(()),
    }
}

pub fn validate_notification(value: &NotificationDto) -> Result<(), ProtocolError> {
    match value {
        NotificationDto::ChallengeIssued { challenge } => match &challenge.kind {
            ChallengeKindDto::SshHost {
                host, fingerprint, ..
            }
            | ChallengeKindDto::RdpCertificate {
                host, fingerprint, ..
            } => {
                check_string(host, 253)?;
                check_string(fingerprint, 4096)
            }
            ChallengeKindDto::KeyboardInteractive { prompts } => {
                check_array(prompts, MAX_KEYBOARD_PROMPTS)?;
                for prompt in prompts {
                    check_string(prompt, 256)?;
                }
                Ok(())
            }
            ChallengeKindDto::Password {} | ChallengeKindDto::PrivateKey {} => Ok(()),
        },
        _ => Ok(()),
    }
}

fn validate_bootstrap(value: &BootstrapResultDto) -> Result<(), ProtocolError> {
    validate_schema(value.schema)?;
    check_array(&value.capabilities, 64)?;
    check_array(&value.sessions, value.limits.max_sessions as usize)?;
    for session in &value.sessions {
        validate_session(session)?;
    }
    Ok(())
}

fn validate_session(value: &crate::result::SessionDto) -> Result<(), ProtocolError> {
    let _ = value;
    Ok(())
}

fn validate_search(value: &SearchResultsDto) -> Result<(), ProtocolError> {
    check_array(&value.matches, MAX_SEARCH_MATCHES)
}

pub fn validate_workspace(value: &WorkspaceDto) -> Result<(), ProtocolError> {
    check_array(&value.connections, MAX_ARRAY_ITEMS)?;
    check_array(&value.groups, MAX_ARRAY_ITEMS)?;
    check_array(&value.credentials, MAX_ARRAY_ITEMS)?;
    check_array(&value.credential_folders, MAX_ARRAY_ITEMS)?;
    for connection in &value.connections {
        validate_connection(connection)?;
    }
    for group in &value.groups {
        check_string(&group.name, 256)?;
    }
    for credential in &value.credentials {
        validate_credential(credential)?;
    }
    for folder in &value.credential_folders {
        check_string(&folder.name, 256)?;
    }
    Ok(())
}

fn validate_credential(value: &CredentialDto) -> Result<(), ProtocolError> {
    check_string(&value.name, 256)?;
    if let Some(username) = &value.username.0 {
        check_string(username, 256)?;
    }
    Ok(())
}

fn validate_connection(value: &ConnectionDto) -> Result<(), ProtocolError> {
    crate::command::validate_connection(value)
}

fn check_string(value: &str, max: usize) -> Result<(), ProtocolError> {
    if value.len() > max {
        Err(ProtocolError::ResourceLimit)
    } else {
        Ok(())
    }
}

fn check_array<T>(values: &[T], max: usize) -> Result<(), ProtocolError> {
    if values.len() > max {
        Err(ProtocolError::ResourceLimit)
    } else {
        Ok(())
    }
}

pub fn validate_schema(schema: u32) -> Result<(), ProtocolError> {
    if schema == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedSchema)
    }
}

pub fn validate_build_id(
    actual: &crate::BuildId,
    expected: &crate::BuildId,
) -> Result<(), ProtocolError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ProtocolError::BuildMismatch)
    }
}

pub fn validate_command_authority(
    command: &CommandEnvelope,
    expected_epoch: &CanonicalUuid,
    current_lease_generation: u64,
    has_owner_lease: bool,
) -> Result<(), ProtocolError> {
    if &command.gateway_epoch != expected_epoch {
        return Err(ProtocolError::StaleEpoch);
    }
    if command_requires_owner(&command.command)
        && (!has_owner_lease || command.lease_generation.0 != current_lease_generation)
    {
        return Err(ProtocolError::LeaseRevoked);
    }
    Ok(())
}

pub fn command_requires_owner(command: &CommandDto) -> bool {
    !matches!(
        command,
        CommandDto::Bootstrap {}
            | CommandDto::ListWorkspace {}
            | CommandDto::QueryOutcome { .. }
            | CommandDto::RequestControl {}
    )
}

fn nesting_exceeds_limit(input: &[u8], maximum: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in input {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > maximum {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

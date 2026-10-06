use serde::{Deserialize, Serialize};

use crate::{
    CanonicalUuid, DecimalI64, DecimalU64, RequiredNullable, deserialize_required_nullable,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandEnvelope {
    pub request_id: CanonicalUuid,
    pub gateway_epoch: CanonicalUuid,
    pub lease_generation: DecimalU64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub session_id: RequiredNullable<CanonicalUuid>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub session_generation: RequiredNullable<DecimalU64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub expected_revision: RequiredNullable<DecimalU64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub idempotency_id: RequiredNullable<CanonicalUuid>,
    pub command: CommandDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandDto {
    Bootstrap {},
    ListWorkspace {},
    QueryOutcome {
        idempotency_id: CanonicalUuid,
    },
    RequestControl {},
    Mutate {
        operation: WorkspaceMutationDto,
    },
    ImportPreview {
        format: ImportFormatDto,
        filename: String,
        transfer_id: CanonicalUuid,
    },
    ExportSecretFree {},
    OpenSession {
        target: SessionTargetDto,
        size: TerminalSizeDto,
    },
    CloseSession {},
    DetachSession {},
    AttachSession {},
    SessionInput {
        sequence: DecimalU64,
        input: SessionInputDto,
    },
    ResizeSession {
        cols: u16,
        rows: u16,
    },
    SetViewport {
        offset: u32,
    },
    SearchTerminal {
        query: String,
        direction: SearchDirectionDto,
        from: SearchCursorDto,
    },
    ClipboardPasteText {
        transfer_id: CanonicalUuid,
    },
    RespondChallenge {
        challenge_id: CanonicalUuid,
        response: ChallengeResponseDto,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkspaceMutationDto {
    UpsertConnection {
        value: ConnectionDto,
        secret_intent: InlineSecretIntentDto,
    },
    DeleteConnection {
        id: DecimalI64,
    },
    MoveConnection {
        id: DecimalI64,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        group_id: RequiredNullable<DecimalI64>,
        sort: DecimalI64,
    },
    UpsertGroup {
        value: GroupDto,
    },
    DeleteGroup {
        id: DecimalI64,
    },
    MoveGroup {
        id: DecimalI64,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        parent_id: RequiredNullable<DecimalI64>,
        sort: DecimalI64,
    },
    UpsertCredential {
        value: CredentialDto,
        secret_intent: CredentialSecretIntentDto,
    },
    DeleteCredential {
        id: DecimalI64,
    },
    UpsertCredentialFolder {
        value: CredentialFolderDto,
    },
    DeleteCredentialFolder {
        id: DecimalI64,
    },
    MoveCredentialFolder {
        id: DecimalI64,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        parent_id: RequiredNullable<DecimalI64>,
        sort: DecimalI64,
    },
    SetPreferences {
        value: GatewayPreferencesDto,
    },
    ImportCommit {
        preview_id: CanonicalUuid,
        preview_revision: DecimalU64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFormatDto {
    ConManJson,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionKindDto {
    Rdp,
    Ssh,
    Telnet,
    Local,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKindDto {
    Password,
    SshKey,
    SshKeyWithPassphrase,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportWarningCodeDto {
    UnsupportedCredential,
    InvalidEntry,
    DuplicateEntry,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchDirectionDto {
    Forward,
    Backward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalSizeDto {
    pub rows: u16,
    pub cols: u16,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchCursorDto {
    pub row: u16,
    pub column: u16,
    pub surface_sequence: DecimalU64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyModifiersDto {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    pub sup: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyDto {
    Char { value: char },
    Enter {},
    Tab {},
    Backspace {},
    Escape {},
    Up {},
    Down {},
    Left {},
    Right {},
    Home {},
    End {},
    PageUp {},
    PageDown {},
    Insert {},
    Delete {},
    F { value: u8 },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEventDto {
    pub key: KeyDto,
    pub mods: KeyModifiersDto,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseButtonDto {
    Left,
    Middle,
    Right,
    ScrollUp,
    ScrollDown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseActionDto {
    Press,
    Release,
    Move,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MouseEventDto {
    pub button: MouseButtonDto,
    pub action: MouseActionDto,
    pub row: u16,
    pub col: u16,
    pub mods: KeyModifiersDto,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RdpInputEventDto {
    KeyDown {
        scancode: u8,
        extended: bool,
    },
    KeyUp {
        scancode: u8,
        extended: bool,
    },
    MouseMove {
        x: u16,
        y: u16,
    },
    MouseDown {
        button: RdpMouseButtonDto,
        x: u16,
        y: u16,
    },
    MouseUp {
        button: RdpMouseButtonDto,
        x: u16,
        y: u16,
    },
    Scroll {
        delta: i16,
        vertical: bool,
        x: u16,
        y: u16,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RdpMouseButtonDto {
    Left,
    Middle,
    Right,
    X1,
    X2,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RdpClipboardCommandDto {
    SetActive {
        active: bool,
    },
    PublishLocal {
        revision: DecimalU64,
        snapshot: RdpClipboardSnapshotDto,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RdpClipboardSnapshotDto {
    Empty {},
    Text { transfer_id: CanonicalUuid },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)] // Preserve the direct typed DTO shape; wire size is independently capped.
pub enum SessionTargetDto {
    Saved { connection_id: DecimalI64 },
    QuickConnect { connection: ConnectionDto },
    GatewayTerminal {},
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionInputDto {
    Key { event: KeyEventDto },
    Mouse { event: MouseEventDto },
    Paste { transfer_id: CanonicalUuid },
    Scroll { offset: u32 },
    Rdp { events: Vec<RdpInputEventDto> },
    RdpClipboard { command: RdpClipboardCommandDto },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChallengeResponseDto {
    AcceptSshHostKey {},
    RejectSshHostKey {},
    AcceptRdpCertificate {},
    RejectRdpCertificate {},
    Password {
        transfer_id: CanonicalUuid,
    },
    PrivateKey {
        key_transfer_id: CanonicalUuid,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        passphrase_transfer_id: RequiredNullable<CanonicalUuid>,
    },
    KeyboardInteractive {
        transfer_ids: Vec<CanonicalUuid>,
    },
    Cancel {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum InlineSecretIntentDto {
    Keep {},
    Replace { transfer_id: CanonicalUuid },
    Clear {},
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretChangeDto {
    Keep {},
    Replace { transfer_id: CanonicalUuid },
    Clear {},
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSecretIntentDto {
    pub password: SecretChangeDto,
    pub ssh_key: SecretChangeDto,
    pub ssh_passphrase: SecretChangeDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionDto {
    pub id: DecimalI64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub group_id: RequiredNullable<DecimalI64>,
    pub name: String,
    pub kind: ConnectionKindDto,
    pub settings: ConnectionSettingsDto,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub credential_source: RequiredNullable<CredentialSourceDto>,
    pub sort: DecimalI64,
    pub created_at: DecimalI64,
    pub updated_at: DecimalI64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupDto {
    pub id: DecimalI64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub parent_id: RequiredNullable<DecimalI64>,
    pub name: String,
    pub sort: DecimalI64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub default_credential: RequiredNullable<DecimalI64>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialDto {
    pub id: DecimalI64,
    pub name: String,
    pub kind: CredentialKindDto,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub folder_id: RequiredNullable<DecimalI64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub username: RequiredNullable<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialFolderDto {
    pub id: DecimalI64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub parent_id: RequiredNullable<DecimalI64>,
    pub name: String,
    pub sort: DecimalI64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ConnectionSettingsDto {
    Rdp(RdpSettingsDto),
    Ssh(SshSettingsDto),
    Telnet(TelnetSettingsDto),
    Local(LocalSettingsDto),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSettingsDto {}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RdpSettingsDto {
    pub host: String,
    pub port: u16,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub domain: RequiredNullable<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub username: RequiredNullable<String>,
    pub width: u16,
    pub height: u16,
    pub color_depth: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshSettingsDto {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: SshAuthMethodDto,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum SshAuthMethodDto {
    Password {},
    PublicKey { key_ref: CredentialRefDto },
    Agent {},
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretOwnerDto {
    Connection,
    Credential,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretPurposeDto {
    Password,
    SshKey,
    SshPassphrase,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRefDto {
    pub owner: SecretOwnerDto,
    pub entity_id: DecimalI64,
    pub purpose: SecretPurposeDto,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelnetSettingsDto {
    pub host: String,
    pub port: u16,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CredentialSourceDto {
    Object(DecimalI64),
    Inline(InlineCredentialDto),
    Prompt,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InlineCredentialDto {
    pub username: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub domain: RequiredNullable<String>,
    pub has_secret: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayPreferencesDto {
    pub theme: ThemeModeDto,
    pub accent_color: AccentColorDto,
    pub density: DensityDto,
    pub terminal_theme: TerminalThemeDto,
    pub bundled_font: BundledFontDto,
    pub font_size: u8,
    pub scrollback_limit: u32,
    pub always_show_scrollbar: bool,
    pub plain_copy_paste_shortcuts: bool,
    pub copy_on_select: bool,
    pub confirm_close_active_tab: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeModeDto {
    System,
    Dark,
    Light,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccentColorDto {
    Blue,
    Teal,
    Green,
    Purple,
    System,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DensityDto {
    Compact,
    Cosy,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalThemeDto {
    Dark,
    Light,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundledFontDto {
    JetBrainsMonoNerdFontMono,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportWarningCodeValue {
    UnsupportedCredential,
    InvalidEntry,
    DuplicateEntry,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveLimitsDto {
    pub max_sessions: u8,
    pub max_rdp_sessions: u8,
    pub max_rdp_width: u16,
    pub max_rdp_height: u16,
    pub max_rdp_aggregate_pixels: DecimalU64,
    pub max_terminal_cols: u16,
    pub max_terminal_rows: u16,
    pub max_terminal_history_bytes: DecimalU64,
    pub max_import_bytes: DecimalU64,
    pub max_clipboard_bytes: u32,
    pub max_secret_bytes: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportWarningCodeValueDto {
    UnsupportedCredential,
    InvalidEntry,
    DuplicateEntry,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchDirectionValueDto {
    Forward,
    Backward,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportCountsDto {
    pub connections: u32,
    pub groups: u32,
    pub credentials: u32,
    pub credential_folders: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportWarningDto {
    pub code: ImportWarningCodeDto,
    pub count: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportPreviewDto {
    pub preview_id: CanonicalUuid,
    pub revision: DecimalU64,
    pub format: ImportFormatDto,
    pub profile_counts: ImportCountsDto,
    pub warnings: Vec<ImportWarningDto>,
    pub contains_secrets: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportStatsDto {
    pub counts: ImportCountsDto,
    pub secrets_imported: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchResultsDto {
    pub matches: Vec<SearchMatchDto>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub next_cursor: RequiredNullable<SearchCursorDto>,
    pub truncated: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchMatchDto {
    pub start_row: u16,
    pub start_col: u16,
    pub end_row: u16,
    pub end_col: u16,
    pub absolute_line: DecimalU64,
}

impl CommandEnvelope {
    pub fn validate(&self) -> Result<(), crate::ProtocolError> {
        use CommandDto as C;
        let session_scope = self.session_id.0.is_some() && self.session_generation.0.is_some();
        if self.session_id.0.is_some() != self.session_generation.0.is_some() {
            return Err(crate::ProtocolError::InvalidRequest);
        }
        let (needs_session, needs_revision, needs_idempotency) = match &self.command {
            C::Bootstrap {}
            | C::ListWorkspace {}
            | C::QueryOutcome { .. }
            | C::RequestControl {}
            | C::ImportPreview { .. }
            | C::ExportSecretFree {}
            | C::OpenSession { .. } => (false, false, false),
            C::Mutate { .. } => (false, true, true),
            C::CloseSession {}
            | C::DetachSession {}
            | C::AttachSession {}
            | C::SessionInput { .. }
            | C::ResizeSession { .. }
            | C::SetViewport { .. }
            | C::SearchTerminal { .. }
            | C::ClipboardPasteText { .. }
            | C::RespondChallenge { .. } => (true, false, false),
        };
        if needs_session != session_scope
            || needs_revision != self.expected_revision.0.is_some()
            || needs_idempotency != self.idempotency_id.0.is_some()
        {
            return Err(crate::ProtocolError::InvalidRequest);
        }
        if let C::QueryOutcome { idempotency_id } = &self.command {
            if self.idempotency_id.0.is_some() || self.expected_revision.0.is_some() {
                return Err(crate::ProtocolError::InvalidRequest);
            }
            if idempotency_id == &self.request_id {
                return Err(crate::ProtocolError::InvalidRequest);
            }
        }
        if matches!(&self.command, C::Mutate { .. })
            && self.idempotency_id.0.as_ref() == Some(&self.request_id)
        {
            return Err(crate::ProtocolError::InvalidRequest);
        }
        validate_command(&self.command)
    }
}

fn check_string(value: &str, max: usize) -> Result<(), crate::ProtocolError> {
    if value.len() > max {
        Err(crate::ProtocolError::ResourceLimit)
    } else {
        Ok(())
    }
}
fn check_array<T>(values: &[T], max: usize) -> Result<(), crate::ProtocolError> {
    if values.len() > max {
        Err(crate::ProtocolError::ResourceLimit)
    } else {
        Ok(())
    }
}

fn validate_command(command: &CommandDto) -> Result<(), crate::ProtocolError> {
    use CommandDto as C;
    match command {
        C::Mutate { operation } => validate_mutation(operation),
        C::ImportPreview { filename, .. } => check_string(filename, 255),
        C::OpenSession {
            target: SessionTargetDto::QuickConnect { connection },
            ..
        } => validate_connection(connection),
        C::SessionInput { input, .. } => validate_session_input(input),
        C::SearchTerminal { query, .. } => check_string(query, 4096),
        C::RespondChallenge {
            response: ChallengeResponseDto::KeyboardInteractive { transfer_ids },
            ..
        } => check_array(transfer_ids, 32),
        _ => Ok(()),
    }
}

fn validate_mutation(value: &WorkspaceMutationDto) -> Result<(), crate::ProtocolError> {
    match value {
        WorkspaceMutationDto::UpsertConnection {
            value,
            secret_intent,
        } => {
            validate_connection(value)?;
            if !matches!(secret_intent, InlineSecretIntentDto::Keep {})
                && !matches!(
                    &value.credential_source.0,
                    Some(CredentialSourceDto::Inline(_))
                )
            {
                return Err(crate::ProtocolError::InvalidRequest);
            }
            Ok(())
        }
        WorkspaceMutationDto::UpsertGroup { value } => check_string(&value.name, 256),
        WorkspaceMutationDto::UpsertCredential {
            value,
            secret_intent,
        } => {
            check_string(&value.name, 256)?;
            if let Some(username) = &value.username.0 {
                check_string(username, 256)?;
            }
            let changed = [
                &secret_intent.password,
                &secret_intent.ssh_key,
                &secret_intent.ssh_passphrase,
            ]
            .into_iter()
            .filter(|value| !matches!(value, SecretChangeDto::Keep {}))
            .count();
            if changed > 2 {
                return Err(crate::ProtocolError::ResourceLimit);
            }
            let no_replace =
                |value: &SecretChangeDto| !matches!(value, SecretChangeDto::Replace { .. });
            let kind_valid = match value.kind {
                CredentialKindDto::Password => {
                    no_replace(&secret_intent.ssh_key) && no_replace(&secret_intent.ssh_passphrase)
                }
                CredentialKindDto::SshKey => {
                    no_replace(&secret_intent.password) && no_replace(&secret_intent.ssh_passphrase)
                }
                CredentialKindDto::SshKeyWithPassphrase => no_replace(&secret_intent.password),
            };
            if !kind_valid {
                return Err(crate::ProtocolError::InvalidRequest);
            }
            Ok(())
        }
        WorkspaceMutationDto::UpsertCredentialFolder { value } => check_string(&value.name, 256),
        WorkspaceMutationDto::SetPreferences { .. } => Ok(()),
        _ => Ok(()),
    }
}

pub(crate) fn validate_connection(value: &ConnectionDto) -> Result<(), crate::ProtocolError> {
    check_string(&value.name, 256)?;
    let kind_matches = matches!(
        (&value.kind, &value.settings),
        (ConnectionKindDto::Rdp, ConnectionSettingsDto::Rdp(_))
            | (ConnectionKindDto::Ssh, ConnectionSettingsDto::Ssh(_))
            | (ConnectionKindDto::Telnet, ConnectionSettingsDto::Telnet(_))
            | (ConnectionKindDto::Local, ConnectionSettingsDto::Local(_))
    );
    if !kind_matches {
        return Err(crate::ProtocolError::InvalidRequest);
    }
    match &value.settings {
        ConnectionSettingsDto::Rdp(settings) => {
            check_string(&settings.host, 253)?;
            if let Some(domain) = &settings.domain.0 {
                check_string(domain, 256)?;
            }
            if let Some(username) = &settings.username.0 {
                check_string(username, 256)?;
            }
        }
        ConnectionSettingsDto::Ssh(settings) => {
            check_string(&settings.host, 253)?;
            check_string(&settings.username, 256)?;
            if let SshAuthMethodDto::PublicKey { key_ref } = &settings.auth_method
                && key_ref.purpose != SecretPurposeDto::SshKey
            {
                return Err(crate::ProtocolError::InvalidRequest);
            }
        }
        ConnectionSettingsDto::Telnet(settings) => check_string(&settings.host, 253)?,
        ConnectionSettingsDto::Local(_) => {}
    }
    if let Some(CredentialSourceDto::Inline(inline)) = &value.credential_source.0 {
        check_string(&inline.username, 256)?;
        if let Some(domain) = &inline.domain.0 {
            check_string(domain, 256)?;
        }
    }
    Ok(())
}

fn validate_session_input(value: &SessionInputDto) -> Result<(), crate::ProtocolError> {
    match value {
        SessionInputDto::Rdp { events } => check_array(events, 512),
        SessionInputDto::Key { event } => {
            if matches!(&event.key, KeyDto::F { value } if !(1..=24).contains(value)) {
                return Err(crate::ProtocolError::InvalidRequest);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::CanonicalUuid;

pub const BINARY_RECORD_HEADER_BYTES: usize = 60;
pub const MAX_BINARY_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_BINARY_PAYLOAD_BYTES: usize = 256 * 1024;
pub const MAX_TRANSFER_CHUNKS: u32 = 64;
const BINARY_MAGIC: [u8; 4] = *b"CMW2";
const FLAG_DATA_NON_FINAL: u8 = 0x00;
const FLAG_DATA_FINAL: u8 = 0x01;
const FLAG_CANCEL: u8 = 0x02;
const FLAG_ACK: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferKindDto {
    Import,
    Export,
    ClipboardText,
    SecretPassword,
    SecretSshKey,
    SecretSshPassphrase,
    WorkspaceSnapshot,
}

impl TransferKindDto {
    pub const fn max_total_bytes(self) -> usize {
        match self {
            Self::Import | Self::Export | Self::WorkspaceSnapshot => 16 * 1024 * 1024,
            Self::ClipboardText => 1024 * 1024,
            Self::SecretPassword | Self::SecretSshKey | Self::SecretSshPassphrase => 64 * 1024,
        }
    }

    const fn wire_value(self) -> u8 {
        match self {
            Self::Import => 0x01,
            Self::Export => 0x02,
            Self::ClipboardText => 0x03,
            Self::SecretPassword => 0x04,
            Self::SecretSshKey => 0x05,
            Self::SecretSshPassphrase => 0x06,
            Self::WorkspaceSnapshot => 0x07,
        }
    }

    fn from_wire_value(value: u8) -> Result<Self, BinaryRecordError> {
        match value {
            0x01 => Ok(Self::Import),
            0x02 => Ok(Self::Export),
            0x03 => Ok(Self::ClipboardText),
            0x04 => Ok(Self::SecretPassword),
            0x05 => Ok(Self::SecretSshKey),
            0x06 => Ok(Self::SecretSshPassphrase),
            0x07 => Ok(Self::WorkspaceSnapshot),
            _ => Err(BinaryRecordError::UnknownKind),
        }
    }

    const fn allows_empty(self) -> bool {
        matches!(
            self,
            Self::Import | Self::ClipboardText | Self::SecretPassword | Self::SecretSshPassphrase
        )
    }

    const fn allows_upload(self) -> bool {
        matches!(
            self,
            Self::Import | Self::SecretPassword | Self::SecretSshKey | Self::SecretSshPassphrase
        )
    }

    const fn allows_download(self) -> bool {
        matches!(self, Self::Export | Self::WorkspaceSnapshot)
    }
}

/// Direction of DATA bytes relative to the gateway. ACK and CANCEL direction is
/// checked by the stateful permit owner because it depends on the named transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    BrowserToGateway,
    GatewayToBrowser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryRecordType {
    Data { final_chunk: bool },
    Cancel,
    Ack,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryRecordHeader {
    pub kind: TransferKindDto,
    pub record_type: BinaryRecordType,
    pub record_seq: u32,
    pub gateway_epoch: CanonicalUuid,
    pub transfer_id: CanonicalUuid,
    pub chunk_index: u32,
    pub chunk_count: u32,
    pub total_bytes: u32,
}

/// One validated CMW2 record. Payload bytes borrow from the input message and
/// are intentionally omitted from diagnostic formatting.
pub struct BinaryRecord<'a> {
    pub header: BinaryRecordHeader,
    payload: &'a [u8],
}

impl<'a> BinaryRecord<'a> {
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

impl fmt::Debug for BinaryRecord<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BinaryRecord")
            .field("header", &self.header)
            .field(
                "payload",
                &format_args!("<redacted: {} bytes>", self.payload.len()),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryRecordError {
    TooShort,
    MessageTooLarge,
    InvalidMagic,
    UnknownKind,
    InvalidFlags,
    InvalidHeaderLength,
    PayloadLengthMismatch,
    InvalidChunkCount,
    InvalidChunkIndex,
    InvalidTotalBytes,
    InvalidPayloadLength,
    InvalidDirection,
    InvalidControlRecord,
}

/// Parses and structurally validates one complete CMW2 binary message.
/// Connection sequence, authentication, transfer permit, and authority checks
/// are deliberately left to the stateful caller.
pub fn parse_binary_record(
    message: &[u8],
    direction: TransferDirection,
) -> Result<BinaryRecord<'_>, BinaryRecordError> {
    if message.len() < BINARY_RECORD_HEADER_BYTES {
        return Err(BinaryRecordError::TooShort);
    }
    if message.len() > MAX_BINARY_MESSAGE_BYTES {
        return Err(BinaryRecordError::MessageTooLarge);
    }

    let header = &message[..BINARY_RECORD_HEADER_BYTES];
    if header[..4] != BINARY_MAGIC {
        return Err(BinaryRecordError::InvalidMagic);
    }
    let kind = TransferKindDto::from_wire_value(header[4])?;
    let record_type = match header[5] {
        FLAG_DATA_NON_FINAL => BinaryRecordType::Data { final_chunk: false },
        FLAG_DATA_FINAL => BinaryRecordType::Data { final_chunk: true },
        FLAG_CANCEL => BinaryRecordType::Cancel,
        FLAG_ACK => BinaryRecordType::Ack,
        _ => return Err(BinaryRecordError::InvalidFlags),
    };
    if read_u16(header, 6) != BINARY_RECORD_HEADER_BYTES as u16 {
        return Err(BinaryRecordError::InvalidHeaderLength);
    }

    let payload_len = read_u32(header, 8) as usize;
    if payload_len > MAX_BINARY_PAYLOAD_BYTES {
        return Err(BinaryRecordError::InvalidPayloadLength);
    }
    let expected_message_len = BINARY_RECORD_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(BinaryRecordError::PayloadLengthMismatch)?;
    if expected_message_len != message.len() {
        return Err(BinaryRecordError::PayloadLengthMismatch);
    }

    let parsed = BinaryRecordHeader {
        kind,
        record_type,
        record_seq: read_u32(header, 12),
        gateway_epoch: CanonicalUuid(Uuid::from_bytes(header[16..32].try_into().unwrap())),
        transfer_id: CanonicalUuid(Uuid::from_bytes(header[32..48].try_into().unwrap())),
        chunk_index: read_u32(header, 48),
        chunk_count: read_u32(header, 52),
        total_bytes: read_u32(header, 56),
    };
    let payload = &message[BINARY_RECORD_HEADER_BYTES..];
    validate_record(&parsed, payload.len(), direction)?;

    Ok(BinaryRecord {
        header: parsed,
        payload,
    })
}

/// Encodes the fixed 60-byte header for a record. The caller appends `payload`
/// to the returned header without introducing an intermediate owned buffer.
pub fn encode_binary_record_header(
    header: &BinaryRecordHeader,
    payload: &[u8],
    direction: TransferDirection,
) -> Result<[u8; BINARY_RECORD_HEADER_BYTES], BinaryRecordError> {
    validate_record(header, payload.len(), direction)?;
    let mut encoded = [0_u8; BINARY_RECORD_HEADER_BYTES];
    encoded[..4].copy_from_slice(&BINARY_MAGIC);
    encoded[4] = header.kind.wire_value();
    encoded[5] = match header.record_type {
        BinaryRecordType::Data { final_chunk: false } => FLAG_DATA_NON_FINAL,
        BinaryRecordType::Data { final_chunk: true } => FLAG_DATA_FINAL,
        BinaryRecordType::Cancel => FLAG_CANCEL,
        BinaryRecordType::Ack => FLAG_ACK,
    };
    write_u16(&mut encoded, 6, BINARY_RECORD_HEADER_BYTES as u16);
    write_u32(&mut encoded, 8, payload.len() as u32);
    write_u32(&mut encoded, 12, header.record_seq);
    encoded[16..32].copy_from_slice(header.gateway_epoch.0.as_bytes());
    encoded[32..48].copy_from_slice(header.transfer_id.0.as_bytes());
    write_u32(&mut encoded, 48, header.chunk_index);
    write_u32(&mut encoded, 52, header.chunk_count);
    write_u32(&mut encoded, 56, header.total_bytes);
    Ok(encoded)
}

fn validate_record(
    header: &BinaryRecordHeader,
    payload_len: usize,
    direction: TransferDirection,
) -> Result<(), BinaryRecordError> {
    if payload_len > MAX_BINARY_PAYLOAD_BYTES {
        return Err(BinaryRecordError::InvalidPayloadLength);
    }
    match header.record_type {
        BinaryRecordType::Data { final_chunk } => {
            validate_direction(header.kind, direction)?;
            if header.chunk_count == 0 || header.chunk_count > MAX_TRANSFER_CHUNKS {
                return Err(BinaryRecordError::InvalidChunkCount);
            }
            if header.chunk_index >= header.chunk_count {
                return Err(BinaryRecordError::InvalidChunkIndex);
            }
            let total = header.total_bytes as usize;
            if total > header.kind.max_total_bytes() || (total == 0 && !header.kind.allows_empty())
            {
                return Err(BinaryRecordError::InvalidTotalBytes);
            }
            let expected_count = total.div_ceil(MAX_BINARY_PAYLOAD_BYTES).max(1);
            if expected_count != header.chunk_count as usize {
                return Err(BinaryRecordError::InvalidChunkCount);
            }
            let should_be_final = header.chunk_index + 1 == header.chunk_count;
            if final_chunk != should_be_final {
                return Err(BinaryRecordError::InvalidFlags);
            }
            let expected_len = if should_be_final {
                total - MAX_BINARY_PAYLOAD_BYTES * (header.chunk_count as usize - 1)
            } else {
                MAX_BINARY_PAYLOAD_BYTES
            };
            if expected_len != payload_len {
                return Err(BinaryRecordError::InvalidPayloadLength);
            }
        }
        BinaryRecordType::Cancel | BinaryRecordType::Ack => {
            if payload_len != 0
                || header.chunk_index != 0
                || header.chunk_count != 0
                || header.total_bytes != 0
            {
                return Err(BinaryRecordError::InvalidControlRecord);
            }
        }
    }
    Ok(())
}

fn validate_direction(
    kind: TransferKindDto,
    direction: TransferDirection,
) -> Result<(), BinaryRecordError> {
    let valid = match direction {
        TransferDirection::BrowserToGateway => {
            kind.allows_upload() || kind == TransferKindDto::ClipboardText
        }
        TransferDirection::GatewayToBrowser => {
            kind.allows_download() || kind == TransferKindDto::ClipboardText
        }
    };
    if valid {
        Ok(())
    } else {
        Err(BinaryRecordError::InvalidDirection)
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

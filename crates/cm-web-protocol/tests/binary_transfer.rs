use cm_web_protocol::CanonicalUuid;
use cm_web_protocol::transfer::{
    BINARY_RECORD_HEADER_BYTES, BinaryRecordError, BinaryRecordHeader, BinaryRecordType,
    MAX_BINARY_PAYLOAD_BYTES, TransferDirection, TransferKindDto, encode_binary_record_header,
    parse_binary_record,
};
use uuid::Uuid;

const EPOCH: &str = "49d2f963-2bc2-4b47-95f0-7dce77e973f0";
const TRANSFER: &str = "00000000-0000-4000-8000-000000000001";

fn uuid(value: &str) -> CanonicalUuid {
    CanonicalUuid(Uuid::parse_str(value).unwrap())
}

fn from_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let byte = |digit| match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                _ => panic!("invalid fixture hex"),
            };
            byte(pair[0]) * 16 + byte(pair[1])
        })
        .collect()
}

fn to_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn header(
    kind: TransferKindDto,
    record_type: BinaryRecordType,
    record_seq: u32,
    chunk_index: u32,
    chunk_count: u32,
    total_bytes: u32,
) -> BinaryRecordHeader {
    BinaryRecordHeader {
        kind,
        record_type,
        record_seq,
        gateway_epoch: uuid(EPOCH),
        transfer_id: uuid(TRANSFER),
        chunk_index,
        chunk_count,
        total_bytes,
    }
}

#[test]
fn seven_frozen_binary_goldens_parse_and_encode_exactly() {
    // Exact complete-record hex from P13.1-WIRE2-transfer-framing-proposal.md.
    let vectors = [
        (
            TransferDirection::BrowserToGateway,
            "434d573201013c00710000000000000049d2f9632bc24b4795f07dce77e973f0000000000000400080000000000000010000000001000000710000007b22636f6d6d616e5f6578706f72745f76657273696f6e223a312c226578706f727465645f6174223a302c2263726564656e7469616c5f666f6c64657273223a5b5d2c2263726564656e7469616c73223a5b5d2c2267726f757073223a5b5d2c22636f6e6e656374696f6e73223a5b5d7d",
        ),
        (
            TransferDirection::GatewayToBrowser,
            "434d573202013c00710000000100000049d2f9632bc24b4795f07dce77e973f0000000000000400080000000000000020000000001000000710000007b22636f6d6d616e5f6578706f72745f76657273696f6e223a312c226578706f727465645f6174223a302c2263726564656e7469616c5f666f6c64657273223a5b5d2c2263726564656e7469616c73223a5b5d2c2267726f757073223a5b5d2c22636f6e6e656374696f6e73223a5b5d7d",
        ),
        (
            TransferDirection::BrowserToGateway,
            "434d573203013c000a0000000200000049d2f9632bc24b4795f07dce77e973f00000000000004000800000000000000300000000010000000a00000068656c6c6f20f09f8c8d",
        ),
        (
            TransferDirection::BrowserToGateway,
            "434d573204013c00020000000300000049d2f9632bc24b4795f07dce77e973f0000000000000400080000000000000040000000001000000020000007077",
        ),
        (
            TransferDirection::BrowserToGateway,
            "434d573205013c00030000000400000049d2f9632bc24b4795f07dce77e973f0000000000000400080000000000000050000000001000000030000004b4559",
        ),
        (
            TransferDirection::BrowserToGateway,
            "434d573206013c00060000000500000049d2f9632bc24b4795f07dce77e973f000000000000040008000000000000006000000000100000006000000706872617365",
        ),
        (
            TransferDirection::GatewayToBrowser,
            "434d573207013c00640000000600000049d2f9632bc24b4795f07dce77e973f0000000000000400080000000000000070000000001000000640000007b22776f726b7370616365223a7b227265766973696f6e223a2230222c22636f6e6e656374696f6e73223a5b5d2c2267726f757073223a5b5d2c2263726564656e7469616c73223a5b5d2c2263726564656e7469616c5f666f6c64657273223a5b5d7d7d",
        ),
    ];

    for (direction, hex) in vectors {
        let bytes = from_hex(hex);
        let record = parse_binary_record(&bytes, direction).unwrap();
        assert_eq!(
            record.payload().len(),
            bytes.len() - BINARY_RECORD_HEADER_BYTES
        );
        let encoded =
            encode_binary_record_header(&record.header, record.payload(), direction).unwrap();
        let mut round_trip = encoded.to_vec();
        round_trip.extend_from_slice(record.payload());
        assert_eq!(to_hex(&round_trip), hex);
    }
}

#[test]
fn allowed_empty_data_kinds_are_one_final_record_and_disallowed_kinds_fail() {
    let allowed = [
        TransferKindDto::Import,
        TransferKindDto::ClipboardText,
        TransferKindDto::SecretPassword,
        TransferKindDto::SecretSshPassphrase,
    ];
    for kind in allowed {
        let header = header(
            kind,
            BinaryRecordType::Data { final_chunk: true },
            9,
            0,
            1,
            0,
        );
        let encoded =
            encode_binary_record_header(&header, &[], TransferDirection::BrowserToGateway).unwrap();
        let record = parse_binary_record(&encoded, TransferDirection::BrowserToGateway).unwrap();
        assert!(record.payload().is_empty());
        assert_eq!(record.header.kind, kind);
    }

    for kind in [
        TransferKindDto::Export,
        TransferKindDto::WorkspaceSnapshot,
        TransferKindDto::SecretSshKey,
    ] {
        let direction = match kind {
            TransferKindDto::Export | TransferKindDto::WorkspaceSnapshot => {
                TransferDirection::GatewayToBrowser
            }
            _ => TransferDirection::BrowserToGateway,
        };
        let header = header(
            kind,
            BinaryRecordType::Data { final_chunk: true },
            9,
            0,
            1,
            0,
        );
        assert_eq!(
            encode_binary_record_header(&header, &[], direction),
            Err(BinaryRecordError::InvalidTotalBytes)
        );
    }
}

#[test]
fn control_records_require_the_exact_empty_control_shape() {
    for (record_type, flag) in [
        (BinaryRecordType::Cancel, 0x02),
        (BinaryRecordType::Ack, 0x04),
    ] {
        let header = header(TransferKindDto::ClipboardText, record_type, 7, 0, 0, 0);
        let encoded =
            encode_binary_record_header(&header, &[], TransferDirection::BrowserToGateway).unwrap();
        assert_eq!(encoded[5], flag);
        assert!(parse_binary_record(&encoded, TransferDirection::BrowserToGateway).is_ok());
    }
    let malformed = header(
        TransferKindDto::Import,
        BinaryRecordType::Cancel,
        7,
        0,
        1,
        0,
    );
    assert_eq!(
        encode_binary_record_header(&malformed, &[], TransferDirection::BrowserToGateway),
        Err(BinaryRecordError::InvalidControlRecord)
    );
}

#[test]
fn boundary_transfer_uses_full_non_final_chunk_then_exact_one_byte_final_chunk() {
    let first_payload = vec![0x41; MAX_BINARY_PAYLOAD_BYTES];
    let first_header = header(
        TransferKindDto::Import,
        BinaryRecordType::Data { final_chunk: false },
        20,
        0,
        2,
        MAX_BINARY_PAYLOAD_BYTES as u32 + 1,
    );
    let first_encoded = encode_binary_record_header(
        &first_header,
        &first_payload,
        TransferDirection::BrowserToGateway,
    )
    .unwrap();
    let first_record = parse_binary_record(&first_encoded, TransferDirection::BrowserToGateway);
    assert!(first_record.is_err());
    let mut first_message = first_encoded.to_vec();
    first_message.extend_from_slice(&first_payload);
    let first_record =
        parse_binary_record(&first_message, TransferDirection::BrowserToGateway).unwrap();
    assert_eq!(first_record.payload().len(), MAX_BINARY_PAYLOAD_BYTES);
    assert_eq!(first_record.header.chunk_index, 0);
    assert_eq!(first_record.header.record_seq, 20);

    let final_header = header(
        TransferKindDto::Import,
        BinaryRecordType::Data { final_chunk: true },
        21,
        1,
        2,
        MAX_BINARY_PAYLOAD_BYTES as u32 + 1,
    );
    let final_encoded =
        encode_binary_record_header(&final_header, &[0x42], TransferDirection::BrowserToGateway)
            .unwrap();
    let mut final_message = final_encoded.to_vec();
    final_message.push(0x42);
    let final_record =
        parse_binary_record(&final_message, TransferDirection::BrowserToGateway).unwrap();
    assert_eq!(final_record.payload(), &[0x42]);
    assert_eq!(final_record.header.chunk_index, 1);
    assert_eq!(final_record.header.record_seq, 21);
}

#[test]
fn malformed_headers_and_chunk_shapes_fail_without_exposing_payload() {
    let valid_header = header(
        TransferKindDto::SecretPassword,
        BinaryRecordType::Data { final_chunk: true },
        0,
        0,
        1,
        2,
    );
    let encoded =
        encode_binary_record_header(&valid_header, b"pw", TransferDirection::BrowserToGateway)
            .unwrap();
    let mut message = encoded.to_vec();
    message.extend_from_slice(b"pw");

    let mut unknown_kind = message.clone();
    unknown_kind[4] = 0xff;
    assert_eq!(
        parse_binary_record(&unknown_kind, TransferDirection::BrowserToGateway).unwrap_err(),
        BinaryRecordError::UnknownKind
    );
    let mut invalid_flags = message.clone();
    invalid_flags[5] = 0x03;
    assert_eq!(
        parse_binary_record(&invalid_flags, TransferDirection::BrowserToGateway).unwrap_err(),
        BinaryRecordError::InvalidFlags
    );
    let mut bad_header_len = message.clone();
    bad_header_len[6] = 0x3b;
    assert_eq!(
        parse_binary_record(&bad_header_len, TransferDirection::BrowserToGateway).unwrap_err(),
        BinaryRecordError::InvalidHeaderLength
    );
    assert_eq!(
        parse_binary_record(
            &message[..message.len() - 1],
            TransferDirection::BrowserToGateway
        )
        .unwrap_err(),
        BinaryRecordError::PayloadLengthMismatch
    );
    let mut too_large_payload = message.clone();
    too_large_payload[8..12]
        .copy_from_slice(&((MAX_BINARY_PAYLOAD_BYTES as u32) + 1).to_le_bytes());
    assert_eq!(
        parse_binary_record(&too_large_payload, TransferDirection::BrowserToGateway).unwrap_err(),
        BinaryRecordError::InvalidPayloadLength
    );

    let wrong_count = header(
        TransferKindDto::SecretPassword,
        BinaryRecordType::Data { final_chunk: true },
        0,
        0,
        2,
        2,
    );
    assert_eq!(
        encode_binary_record_header(&wrong_count, b"pw", TransferDirection::BrowserToGateway),
        Err(BinaryRecordError::InvalidChunkCount)
    );
    let wrong_direction = header(
        TransferKindDto::Import,
        BinaryRecordType::Data { final_chunk: true },
        0,
        0,
        1,
        2,
    );
    assert_eq!(
        encode_binary_record_header(&wrong_direction, b"{}", TransferDirection::GatewayToBrowser),
        Err(BinaryRecordError::InvalidDirection)
    );

    let too_many_chunks = header(
        TransferKindDto::Import,
        BinaryRecordType::Data { final_chunk: false },
        0,
        0,
        65,
        65 * MAX_BINARY_PAYLOAD_BYTES as u32,
    );
    assert_eq!(
        encode_binary_record_header(
            &too_many_chunks,
            &vec![0; MAX_BINARY_PAYLOAD_BYTES],
            TransferDirection::BrowserToGateway,
        ),
        Err(BinaryRecordError::InvalidChunkCount)
    );
    let out_of_range = header(
        TransferKindDto::Import,
        BinaryRecordType::Data { final_chunk: true },
        0,
        1,
        1,
        1,
    );
    assert_eq!(
        encode_binary_record_header(&out_of_range, &[0], TransferDirection::BrowserToGateway),
        Err(BinaryRecordError::InvalidChunkIndex)
    );
    let excessive_total = header(
        TransferKindDto::SecretPassword,
        BinaryRecordType::Data { final_chunk: true },
        0,
        0,
        1,
        u32::MAX,
    );
    assert_eq!(
        encode_binary_record_header(&excessive_total, &[], TransferDirection::BrowserToGateway),
        Err(BinaryRecordError::InvalidTotalBytes)
    );
    let short_interior = header(
        TransferKindDto::Import,
        BinaryRecordType::Data { final_chunk: false },
        0,
        0,
        2,
        MAX_BINARY_PAYLOAD_BYTES as u32 + 1,
    );
    assert_eq!(
        encode_binary_record_header(
            &short_interior,
            &vec![0; MAX_BINARY_PAYLOAD_BYTES - 1],
            TransferDirection::BrowserToGateway,
        ),
        Err(BinaryRecordError::InvalidPayloadLength)
    );

    let over_transport_cap = vec![0; 1024 * 1024 + 1];
    assert_eq!(
        parse_binary_record(&over_transport_cap, TransferDirection::BrowserToGateway).unwrap_err(),
        BinaryRecordError::MessageTooLarge
    );
}

#[test]
fn record_debug_redacts_payload_and_header_uses_network_order_uuid_bytes() {
    let header = header(
        TransferKindDto::SecretPassword,
        BinaryRecordType::Data { final_chunk: true },
        0,
        0,
        1,
        2,
    );
    let encoded =
        encode_binary_record_header(&header, b"pw", TransferDirection::BrowserToGateway).unwrap();
    assert_eq!(&encoded[16..32], uuid(EPOCH).0.as_bytes());
    let mut message = encoded.to_vec();
    message.extend_from_slice(b"pw");
    let debug = format!(
        "{:?}",
        parse_binary_record(&message, TransferDirection::BrowserToGateway).unwrap()
    );
    assert!(!debug.contains("pw"));
    assert!(debug.contains("redacted: 2 bytes"));
}

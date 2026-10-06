use cm_web_protocol::{
    CanonicalUuid, ProtocolError, command_requires_owner, parse_command, parse_strict,
    validate_command_authority,
};

const EPOCH: &str = "49d2f963-2bc2-4b47-95f0-7dce77e973f0";
const REQUEST: &str = "00000000-0000-4000-8000-000000000001";

fn command(command: &str) -> String {
    format!(
        r#"{{"request_id":"{REQUEST}","gateway_epoch":"{EPOCH}","lease_generation":"2","session_id":null,"session_generation":null,"expected_revision":null,"idempotency_id":null,"command":{command}}}"#
    )
}

#[test]
fn required_nullable_distinguishes_absence_from_explicit_null() {
    let absent = command(r#"{"type":"bootstrap"}"#).replace("\"session_id\":null,", "");
    assert!(parse_command(absent.as_bytes()).is_err());

    let present = parse_command(command(r#"{"type":"bootstrap"}"#).as_bytes())
        .expect("all nullable envelope fields are explicitly present");
    assert!(present.session_id.0.is_none());
}

#[test]
fn canonical_primitives_reject_alternate_spellings() {
    assert!(parse_strict::<cm_web_protocol::DecimalU64>(br#""01""#).is_err());
    assert!(parse_strict::<cm_web_protocol::DecimalI64>(br#""-0""#).is_err());
    assert!(parse_strict::<CanonicalUuid>(br#""49D2F963-2BC2-4B47-95F0-7DCE77E973F0""#).is_err());
}

#[test]
fn owner_authority_is_only_required_for_mutating_and_session_commands() {
    let readonly = parse_command(command(r#"{"type":"bootstrap"}"#).as_bytes()).unwrap();
    let epoch = CanonicalUuid(uuid::Uuid::parse_str(EPOCH).unwrap());
    assert!(!command_requires_owner(&readonly.command));
    validate_command_authority(&readonly, &epoch, 2, false).unwrap();

    let write = parse_command(command(r#"{"type":"request_control"}"#).as_bytes()).unwrap();
    assert!(!command_requires_owner(&write.command));
    validate_command_authority(&write, &epoch, 2, false).unwrap();

    let mutation = parse_command(command(r#"{"type":"export_secret_free"}"#).as_bytes()).unwrap();
    assert!(command_requires_owner(&mutation.command));
    assert_eq!(
        validate_command_authority(&mutation, &epoch, 2, false),
        Err(ProtocolError::LeaseRevoked)
    );
}

#[test]
fn set_viewport_requires_session_scope() {
    let valid = format!(
        r#"{{"request_id":"{REQUEST}","gateway_epoch":"{EPOCH}","lease_generation":"2","session_id":"b4204de7-4dcb-4dd9-8f36-9117e42a18ac","session_generation":"1","expected_revision":null,"idempotency_id":null,"command":{{"type":"set_viewport","offset":0}}}}"#
    );
    let decoded: cm_web_protocol::CommandEnvelope = serde_json::from_str(&valid).unwrap();
    decoded.validate().unwrap();
}

#[test]
fn authentication_secrets_have_redacted_debug_and_strict_token_shape() {
    let login: cm_web_protocol::LoginRequestDto = serde_json::from_str(
        r#"{"build_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema":1,"password":"correct-horse-test"}"#,
    )
    .unwrap();
    let debug = format!("{login:?}");
    assert!(!debug.contains("correct-horse-test"));
    assert!(debug.contains("redacted"));

    let ticket: cm_web_protocol::WsTicketResponseDto = serde_json::from_str(
        r#"{"ticket":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","expires_in_seconds":30}"#,
    )
    .unwrap();
    let debug = format!("{ticket:?}");
    assert!(!debug.contains("cccccccccccccccc"));
    assert!(debug.contains("redacted"));
    assert!(serde_json::from_str::<cm_web_protocol::WsTicketResponseDto>(
        r#"{"ticket":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC","expires_in_seconds":30}"#
    )
    .is_err());
}

#[test]
fn login_handshake_binds_exact_build_and_schema() {
    let build: cm_web_protocol::BuildId =
        serde_json::from_str(&format!("\"{}\"", "a".repeat(64))).unwrap();
    let valid = br#"{"build_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema":1,"password":"correct-horse-test"}"#;
    cm_web_protocol::parse_login(valid, &build).unwrap();

    let different_build: cm_web_protocol::BuildId =
        serde_json::from_str(&format!("\"{}\"", "b".repeat(64))).unwrap();
    assert_eq!(
        cm_web_protocol::parse_login(valid, &different_build).unwrap_err(),
        ProtocolError::BuildMismatch
    );
    let wrong_schema = br#"{"build_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema":2,"password":"correct-horse-test"}"#;
    assert_eq!(
        cm_web_protocol::parse_login(wrong_schema, &build).unwrap_err(),
        ProtocolError::UnsupportedSchema
    );
}

#[test]
fn parser_enforces_control_message_and_nesting_limits() {
    let too_large = vec![b' '; cm_web_protocol::MAX_CONTROL_JSON_BYTES + 1];
    assert_eq!(
        parse_command(&too_large),
        Err(ProtocolError::MessageTooLarge)
    );

    let too_deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
    assert_eq!(
        parse_strict::<u32>(too_deep.as_bytes()),
        Err(ProtocolError::NestingTooDeep)
    );
}

#[test]
fn frozen_non_stream_command_goldens_parse_and_serialize_canonically() {
    for (line_number, line) in include_str!("fixtures/valid_commands.jsonl")
        .lines()
        .enumerate()
    {
        let command = parse_command(line.as_bytes())
            .unwrap_or_else(|error| panic!("golden {} rejected: {error:?}", line_number + 1));
        let encoded = cm_web_protocol::serialize_control(&command).unwrap();
        assert_eq!(
            encoded,
            line.as_bytes(),
            "golden {} changed",
            line_number + 1
        );
    }

    for (line_number, line) in include_str!("fixtures/invalid_commands.jsonl")
        .lines()
        .enumerate()
    {
        assert!(
            parse_command(line.as_bytes()).is_err(),
            "invalid golden {} was accepted",
            line_number + 1
        );
    }
}

#[test]
fn frozen_reply_and_notification_goldens_parse_and_serialize_canonically() {
    for line in include_str!("fixtures/valid_replies_notifications.jsonl").lines() {
        let encoded = if line.contains("\"notification\":") {
            let value = cm_web_protocol::parse_notification(line.as_bytes()).unwrap();
            cm_web_protocol::serialize_control(&value).unwrap()
        } else {
            let value = cm_web_protocol::parse_reply(line.as_bytes()).unwrap();
            cm_web_protocol::serialize_control(&value).unwrap()
        };
        assert_eq!(encoded, line.as_bytes());
    }

    for line in include_str!("fixtures/invalid_replies_notifications.jsonl").lines() {
        let accepted = if line.contains("\"notification\":") {
            cm_web_protocol::parse_notification(line.as_bytes()).is_ok()
        } else {
            cm_web_protocol::parse_reply(line.as_bytes()).is_ok()
        };
        assert!(!accepted, "invalid reply/notification golden was accepted");
    }
}

#[test]
fn error_code_retry_hints_are_exact_and_enforced() {
    use cm_web_protocol::{ErrorDto, RequiredNullable, RetryHint, WireErrorCode as C};

    let cases = [
        (C::InvalidRequest, RetryHint::Never),
        (C::UnsupportedSchema, RetryHint::Never),
        (C::BuildMismatch, RetryHint::Never),
        (C::AuthFailed, RetryHint::Never),
        (C::Unauthenticated, RetryHint::Never),
        (C::OriginDenied, RetryHint::Never),
        (C::CsrfDenied, RetryHint::Never),
        (C::TicketInvalid, RetryHint::Never),
        (C::RateLimited, RetryHint::Never),
        (C::LeaseRevoked, RetryHint::AfterRefresh),
        (C::StaleEpoch, RetryHint::AfterRefresh),
        (C::StaleSession, RetryHint::AfterRefresh),
        (C::RevisionConflict, RetryHint::AfterRefresh),
        (C::DuplicateOperationMismatch, RetryHint::Never),
        (C::OperationCacheFull, RetryHint::Never),
        (C::OutcomeUnknown, RetryHint::Never),
        (C::NotFound, RetryHint::Never),
        (C::ValidationFailed, RetryHint::Never),
        (C::PolicyDenied, RetryHint::Never),
        (C::CapabilityUnavailable, RetryHint::Never),
        (C::PersistenceFailed, RetryHint::Never),
        (C::SecretStoreUnavailable, RetryHint::Never),
        (C::SecretWriteFailed, RetryHint::Never),
        (C::SecretCompensationFailed, RetryHint::Never),
        (C::ImportTooLarge, RetryHint::Never),
        (C::ImportInvalid, RetryHint::Never),
        (C::PreviewExpired, RetryHint::Never),
        (C::QueueFull, RetryHint::Never),
        (C::ResourceLimit, RetryHint::Never),
        (C::ChallengeExpired, RetryHint::Never),
        (C::ChallengeAlreadyAnswered, RetryHint::Never),
        (C::SessionFailed, RetryHint::Never),
        (C::ServiceStopping, RetryHint::Never),
        (C::TransportLost, RetryHint::QueryOutcome),
        (C::RevisionExhausted, RetryHint::Never),
        (C::InternalContractError, RetryHint::Never),
        (C::InternalError, RetryHint::Never),
    ];
    let all_hints = [
        RetryHint::Never,
        RetryHint::AfterRefresh,
        RetryHint::QueryOutcome,
    ];
    for (code, expected) in cases {
        assert_eq!(code.retry_hint(), expected);
        for retry in all_hints {
            let error = ErrorDto {
                code,
                message: "safe".into(),
                retry,
                details: RequiredNullable(None),
            };
            assert_eq!(
                error.validate().is_ok(),
                retry == expected,
                "{code:?}/{retry:?}"
            );
        }
    }
}

#[test]
fn failed_mutation_outcome_enforces_retry_mapping_too() {
    let valid = format!(
        r#"{{"request_id":"{REQUEST}","gateway_epoch":"{EPOCH}","lease_generation":"2","result":{{"type":"mutation_outcome","value":{{"type":"failed","current_revision":"0","error":{{"code":"transport_lost","message":"uncertain","retry":"query_outcome","details":{{"type":"transport_uncertain","original_request_id":"00000000-0000-4000-8000-000000000002"}}}}}}}},"error":null}}"#
    );
    cm_web_protocol::parse_reply(valid.as_bytes()).unwrap();

    let invalid = valid.replace("query_outcome", "never");
    assert!(cm_web_protocol::parse_reply(invalid.as_bytes()).is_err());
}

#[test]
fn service_stopping_wire_error_is_never_retry_with_explicit_null_details() {
    let valid = format!(
        r#"{{"request_id":"{REQUEST}","gateway_epoch":"{EPOCH}","lease_generation":"2","result":null,"error":{{"code":"service_stopping","message":"The service is stopping.","retry":"never","details":null}}}}"#
    );
    cm_web_protocol::parse_reply(valid.as_bytes()).unwrap();

    let wrong_retry = valid.replace("\"retry\":\"never\"", "\"retry\":\"after_refresh\"");
    assert!(cm_web_protocol::parse_reply(wrong_retry.as_bytes()).is_err());
    let missing_details = valid.replace(",\"details\":null", "");
    assert!(cm_web_protocol::parse_reply(missing_details.as_bytes()).is_err());
}

#[test]
fn gateway_local_session_kind_has_only_the_canonical_spelling() {
    assert_eq!(
        serde_json::from_str::<cm_web_protocol::SessionKindDto>("\"gateway_terminal\"").unwrap(),
        cm_web_protocol::SessionKindDto::GatewayTerminal
    );
    assert!(serde_json::from_str::<cm_web_protocol::SessionKindDto>("\"local_terminal\"").is_err());
}

#[test]
fn transfer_kind_exposes_only_typed_size_policy() {
    use cm_web_protocol::TransferKindDto as K;

    assert_eq!(K::Import.max_total_bytes(), 16 * 1024 * 1024);
    assert_eq!(K::Export.max_total_bytes(), 16 * 1024 * 1024);
    assert_eq!(K::ClipboardText.max_total_bytes(), 1024 * 1024);
    assert_eq!(K::SecretPassword.max_total_bytes(), 64 * 1024);
    assert_eq!(K::SecretSshKey.max_total_bytes(), 64 * 1024);
    assert_eq!(K::SecretSshPassphrase.max_total_bytes(), 64 * 1024);
}

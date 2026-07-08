use ironrdp_core::{WriteBuf, other_err};
use ironrdp_pdu::{PduHint, nego};
// P9.1: `picky` itself is no longer referenced directly (only via
// picky-asn1-x509/picky-asn1-der) now that the SmartCard match arm below was
// stubbed out, but it stays a declared dependency (credssp feature parity
// with the audited dep snapshot); mark it explicitly used to satisfy this
// crate's `unused_crate_dependencies` lint.
use picky as _;
use picky_asn1_x509::{Certificate, ExtensionView, GeneralName, oids};
use sspi::credssp::{self, ClientState, CredSspClient};
use sspi::generator::{Generator, NetworkRequest};
use sspi::Username;
use tracing::debug;

use crate::{
    ConnectorError, ConnectorErrorKind, ConnectorResult, Credentials, ServerName, Written, custom_err, general_err,
};

#[derive(Debug, Clone)]
pub struct KerberosConfig {
    pub kdc_proxy_url: Option<url::Url>,
    pub hostname: String,
}

impl KerberosConfig {
    pub fn new(kdc_proxy_url: Option<String>, hostname: String) -> ConnectorResult<Self> {
        let kdc_proxy_url = kdc_proxy_url
            .map(|url| url::Url::parse(&url))
            .transpose()
            .map_err(|e| custom_err!("invalid KDC URL", e))?;
        Ok(Self {
            kdc_proxy_url,
            hostname,
        })
    }
}

impl From<KerberosConfig> for sspi::KerberosConfig {
    fn from(val: KerberosConfig) -> Self {
        sspi::KerberosConfig {
            kdc_url: val.kdc_proxy_url,
            client_computer_name: val.hostname,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct CredsspTsRequestHint;

const CREDSSP_TS_REQUEST_HINT: CredsspTsRequestHint = CredsspTsRequestHint;

impl PduHint for CredsspTsRequestHint {
    fn find_size(&self, bytes: &[u8]) -> ironrdp_core::DecodeResult<Option<(bool, usize)>> {
        match credssp::TsRequest::read_length(bytes) {
            Ok(length) => Ok(Some((true, length))),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(other_err!("CredsspTsRequestHint", source: e)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct CredsspEarlyUserAuthResultHint;

const CREDSSP_EARLY_USER_AUTH_RESULT_HINT: CredsspEarlyUserAuthResultHint = CredsspEarlyUserAuthResultHint;

impl PduHint for CredsspEarlyUserAuthResultHint {
    fn find_size(&self, _: &[u8]) -> ironrdp_core::DecodeResult<Option<(bool, usize)>> {
        Ok(Some((true, credssp::EARLY_USER_AUTH_RESULT_PDU_SIZE)))
    }
}

pub type CredsspProcessGenerator<'a> = Generator<'a, NetworkRequest, sspi::Result<Vec<u8>>, sspi::Result<ClientState>>;

#[derive(Debug)]
pub struct CredsspSequence {
    client: CredSspClient,
    state: CredsspState,
    selected_protocol: nego::SecurityProtocol,
}

#[derive(Debug, PartialEq)]
pub(crate) enum CredsspState {
    Ongoing,
    EarlyUserAuthResult,
    Finished,
}

impl CredsspSequence {
    pub fn next_pdu_hint(&self) -> Option<&dyn PduHint> {
        match self.state {
            CredsspState::Ongoing => Some(&CREDSSP_TS_REQUEST_HINT),
            CredsspState::EarlyUserAuthResult => Some(&CREDSSP_EARLY_USER_AUTH_RESULT_HINT),
            CredsspState::Finished => None,
        }
    }

    /// `server_name` must be the actual target server hostname (as opposed to the proxy)
    pub fn init(
        credentials: Credentials,
        domain: Option<&str>,
        protocol: nego::SecurityProtocol,
        server_name: ServerName,
        server_public_key: Vec<u8>,
        kerberos_config: Option<KerberosConfig>,
    ) -> ConnectorResult<(Self, credssp::TsRequest)> {
        let credentials: sspi::Credentials = match &credentials {
            Credentials::UsernamePassword { username, password } => {
                let username = Username::new(username, domain).map_err(|e| custom_err!("invalid username", e))?;

                sspi::AuthIdentity {
                    username,
                    password: password.to_owned().into(),
                }
                .into()
            }
            // P9.1: smart-card CredSSP requires sspi's `scard` feature, which
            // pulls `winscard` -> `crypto-bigint =0.7.0-rc.18`, conflicting
            // with russh 0.61.2's `crypto-bigint ^0.7.3`. ConMan only performs
            // NTLM username/password NLA, so the scard feature is disabled and
            // this arm is unreachable in practice. Return an error rather than
            // reference the (now feature-gated) sspi smart-card types.
            Credentials::SmartCard { .. } => {
                return Err(general_err!(
                    "smart card CredSSP is not supported in this build (sspi `scard` feature disabled)"
                ));
            }
        };

        let server_name = server_name.into_inner();

        let service_principal_name = format!("TERMSRV/{}", &server_name);

        let client_mode = match kerberos_config {
            Some(ref krb_config) => {
                let credssp_config = Box::new(Into::<sspi::KerberosConfig>::into(krb_config.clone()));
                debug!(?credssp_config);
                credssp::ClientMode::Negotiate(sspi::NegotiateConfig {
                    protocol_config: credssp_config,
                    package_list: None,
                    client_computer_name: server_name,
                })
            }
            None => credssp::ClientMode::Ntlm(sspi::ntlm::NtlmConfig::default()),
        };

        let client = CredSspClient::new(
            server_public_key,
            credentials,
            credssp::CredSspMode::WithCredentials,
            client_mode,
            service_principal_name,
        )
        .map_err(|e| ConnectorError::new("CredSSP", ConnectorErrorKind::Credssp(e)))?;

        let sequence = Self {
            client,
            state: CredsspState::Ongoing,
            selected_protocol: protocol,
        };

        let initial_request = credssp::TsRequest::default();

        Ok((sequence, initial_request))
    }

    /// Returns Some(ts_request) when a TS request is received from server,
    /// and None when an early user auth result PDU is received instead.
    pub fn decode_server_message(&mut self, input: &[u8]) -> ConnectorResult<Option<credssp::TsRequest>> {
        match self.state {
            CredsspState::Ongoing => {
                let message = credssp::TsRequest::from_buffer(input).map_err(|e| custom_err!("TsRequest", e))?;
                debug!(?message, "Received");
                Ok(Some(message))
            }
            CredsspState::EarlyUserAuthResult => {
                let early_user_auth_result = credssp::EarlyUserAuthResult::from_buffer(input)
                    .map_err(|e| custom_err!("EarlyUserAuthResult", e))?;

                debug!(message = ?early_user_auth_result, "Received");

                match early_user_auth_result {
                    credssp::EarlyUserAuthResult::Success => {
                        self.state = CredsspState::Finished;
                        Ok(None)
                    }
                    credssp::EarlyUserAuthResult::AccessDenied => {
                        Err(ConnectorError::new("CredSSP", ConnectorErrorKind::AccessDenied))
                    }
                }
            }
            _ => Err(general_err!(
                "attempted to feed server request to CredSSP sequence in an unexpected state"
            )),
        }
    }

    pub fn process_ts_request(&mut self, request: credssp::TsRequest) -> CredsspProcessGenerator<'_> {
        self.client.process(request)
    }

    pub fn handle_process_result(&mut self, result: ClientState, output: &mut WriteBuf) -> ConnectorResult<Written> {
        let (size, next_state) = match self.state {
            CredsspState::Ongoing => {
                let (ts_request_from_client, next_state) = match result {
                    ClientState::ReplyNeeded(ts_request) => (ts_request, CredsspState::Ongoing),
                    ClientState::FinalMessage(ts_request) => (
                        ts_request,
                        if self.selected_protocol.contains(nego::SecurityProtocol::HYBRID_EX) {
                            CredsspState::EarlyUserAuthResult
                        } else {
                            CredsspState::Finished
                        },
                    ),
                };

                debug!(message = ?ts_request_from_client, "Send");

                let written = write_credssp_request(ts_request_from_client, output)?;

                Ok((Written::from_size(written)?, next_state))
            }
            CredsspState::EarlyUserAuthResult => Ok((Written::Nothing, CredsspState::Finished)),
            CredsspState::Finished => Err(general_err!("CredSSP sequence is already done")),
        }?;

        self.state = next_state;

        Ok(size)
    }
}

// P9.1: unreachable now that the SmartCard match arm above (which was their
// only caller) returns an error instead of parsing the certificate. Kept
// (rather than deleted) so a future smartcard-CredSSP reactivation (once the
// `scard` sspi feature no longer conflicts with russh's crypto-bigint pin)
// doesn't have to rewrite them from scratch; `#[allow(dead_code)]` silences
// the lint in the meantime.
#[allow(dead_code)]
fn extract_user_name(cert: &Certificate) -> Option<String> {
    cert.tbs_certificate.subject.find_common_name().map(ToString::to_string)
}

#[allow(dead_code)]
fn extract_user_principal_name(cert: &Certificate) -> Option<String> {
    cert.extensions()
        .iter()
        .find(|ext| ext.extn_id().0 == oids::subject_alternative_name())
        .iter()
        .flat_map(|ext| match ext.extn_value() {
            ExtensionView::SubjectAltName(names) => names.0,
            _ => vec![],
        })
        .find_map(|name| match name {
            GeneralName::OtherName(name) if name.type_id.0 == oids::user_principal_name() => Some(name.value),
            _ => None,
        })
        .and_then(|asn1| picky_asn1_der::from_bytes(&asn1.0.0).ok())
}

fn write_credssp_request(ts_request: credssp::TsRequest, output: &mut WriteBuf) -> ConnectorResult<usize> {
    let length = usize::from(ts_request.buffer_len());

    let unfilled_buffer = output.unfilled_to(length);

    ts_request
        .encode_ts_request(unfilled_buffer)
        .map_err(|e| custom_err!("TsRequest", e))?;

    output.advance(length);

    Ok(length)
}

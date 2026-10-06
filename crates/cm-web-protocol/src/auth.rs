use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{BuildId, Sha256Hex};

#[derive(Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct SecretText(String);

impl SecretText {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SecretText {
    type Error = AuthDtoValidationError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() > 256 {
            Err(AuthDtoValidationError)
        } else {
            Ok(Self(value))
        }
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretText(<redacted>)")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct SensitiveHexToken(String);

impl SensitiveHexToken {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SensitiveHexToken {
    type Error = AuthDtoValidationError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(AuthDtoValidationError)
        }
    }
}

impl fmt::Debug for SensitiveHexToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveHexToken(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthDtoValidationError;

impl fmt::Display for AuthDtoValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid authentication value")
    }
}

impl std::error::Error for AuthDtoValidationError {}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequestDto {
    pub build_id: BuildId,
    pub schema: u32,
    pub password: SecretText,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoginResponseDto {
    pub csrf_token: SensitiveHexToken,
    pub build_id: BuildId,
    pub schema: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogoutResponseDto {
    pub logged_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WsTicketRequestDto {
    pub build_id: BuildId,
    pub schema: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WsTicketResponseDto {
    pub ticket: SensitiveHexToken,
    pub expires_in_seconds: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetManifestDto {
    pub build_id: BuildId,
    pub schema: u32,
    pub asset_hashes: Vec<Sha256Hex>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatusDto {
    Ok,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthDto {
    pub status: HealthStatusDto,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WsAuthenticateDto {
    pub ticket: SensitiveHexToken,
    pub build_id: BuildId,
    pub schema: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedDto {
    pub bootstrap: crate::result::BootstrapResultDto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthFailureCodeDto {
    AuthFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthFailureDto {
    pub code: AuthFailureCodeDto,
}

use serde::{Deserialize, Serialize};

use crate::credential::CredentialRef;
use crate::kind::ConnectionKind;

/// Kind-specific connection settings. Exactly one variant per
/// [`ConnectionKind`]; the variant must agree with the connection's declared
/// kind (enforced by [`crate::Connection::new`] / [`crate::Connection::validate`]).
///
/// Serialized externally tagged with stable lowercase tags (`"rdp"`, `"ssh"`,
/// `"local"`) to mirror [`ConnectionKind`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionSettings {
    Rdp(RdpSettings),
    Ssh(SshSettings),
    Local(LocalSettings),
}

impl ConnectionSettings {
    /// The [`ConnectionKind`] implied by this settings variant.
    pub fn kind(&self) -> ConnectionKind {
        match self {
            ConnectionSettings::Rdp(_) => ConnectionKind::Rdp,
            ConnectionSettings::Ssh(_) => ConnectionKind::Ssh,
            ConnectionSettings::Local(_) => ConnectionKind::LocalTerminal,
        }
    }
}

/// RDP connection settings (P4 — extended with resolution and color-depth).
///
/// `username` is the Windows/xrdp login name; if `None`, the server shows a
/// graphical login screen (TLS-only security). `domain` may be omitted for
/// workgroup machines. Resolution defaults to 1280 × 720; color depth to 32.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdpSettings {
    pub host: String,
    pub port: u16,
    pub domain: Option<String>,
    pub username: Option<String>,
    /// Requested desktop width in pixels.
    #[serde(default = "RdpSettings::default_width")]
    pub width: u16,
    /// Requested desktop height in pixels.
    #[serde(default = "RdpSettings::default_height")]
    pub height: u16,
    /// Colour depth in bits per pixel (32 recommended).
    #[serde(default = "RdpSettings::default_color_depth")]
    pub color_depth: u32,
}

impl RdpSettings {
    /// Default RDP port.
    pub const DEFAULT_PORT: u16 = 3389;
    /// Default desktop width used when not specified.
    pub const DEFAULT_WIDTH: u16 = 1280;
    /// Default desktop height used when not specified.
    pub const DEFAULT_HEIGHT: u16 = 720;

    fn default_width() -> u16 {
        Self::DEFAULT_WIDTH
    }

    fn default_height() -> u16 {
        Self::DEFAULT_HEIGHT
    }

    fn default_color_depth() -> u32 {
        32
    }
}

impl Default for RdpSettings {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: Self::DEFAULT_PORT,
            domain: None,
            username: None,
            width: Self::DEFAULT_WIDTH,
            height: Self::DEFAULT_HEIGHT,
            color_depth: 32,
        }
    }
}

/// SSH connection settings (host-key policy lives in the session layer, P3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshSettings {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: SshAuthMethod,
}

impl SshSettings {
    /// Default SSH port.
    pub const DEFAULT_PORT: u16 = 22;
}

/// How an SSH session authenticates.
///
/// Internally tagged on the `method` field with stable tags (`"password"`,
/// `"public_key"`, `"agent"`) — a wire/format contract for JSON import/export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum SshAuthMethod {
    Password,
    PublicKey { key_ref: CredentialRef },
    Agent,
}

/// Local-terminal settings. `program == None` means the OS default shell.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LocalSettings {
    pub program: Option<String>,
    pub args: Vec<String>,
    pub working_dir: Option<String>,
    pub env: Vec<(String, String)>,
}

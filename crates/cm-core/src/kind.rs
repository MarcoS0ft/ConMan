use serde::{Deserialize, Serialize};

/// The kind of remote session a [`crate::Connection`] describes.
///
/// The serde string tags (`"rdp"`, `"ssh"`, `"local"`) are a wire/format
/// contract for JSON import/export — pin them, do not churn them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionKind {
    #[serde(rename = "rdp")]
    Rdp,
    #[serde(rename = "ssh")]
    Ssh,
    #[serde(rename = "local")]
    LocalTerminal,
}

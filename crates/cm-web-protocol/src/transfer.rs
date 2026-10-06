use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferKindDto {
    Import,
    Export,
    ClipboardText,
    SecretPassword,
    SecretSshKey,
    SecretSshPassphrase,
}

impl TransferKindDto {
    pub const fn max_total_bytes(self) -> usize {
        match self {
            Self::Import | Self::Export => 16 * 1024 * 1024,
            Self::ClipboardText => 1024 * 1024,
            Self::SecretPassword | Self::SecretSshKey | Self::SecretSshPassphrase => 64 * 1024,
        }
    }
}

#![forbid(unsafe_code)]
//! Shared, platform-neutral automatic update domain for ConMan.
//!
//! This crate deliberately stops at the platform boundary. It validates and
//! selects signed release metadata, reduces backend facts into one stable UI
//! state, and provides bounded command/event queues. Sparkle, Velopack, and
//! package-manager integration belong to platform adapters.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::{Display, Formatter};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use cm_core::{AppStateRepository, UpdateChannel};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use semver::Version;
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

pub const PRODUCT: &str = "conman";
pub const REPOSITORY: &str = "MarcoS0ft/ConMan";
pub const MANIFEST_ASSET_NAME: &str = "conman-update.json";
pub const SIGNATURE_ASSET_NAME: &str = "conman-update.json.sig";
pub const DEFAULT_MANIFEST_KEY_ID: &str = "conman-release-update-v1";
pub const MAX_API_BODY: u64 = 1024 * 1024;
pub const MAX_MANIFEST_BODY: u64 = 256 * 1024;
pub const MAX_SIGNATURE_BODY: u64 = 8 * 1024;
pub const MAX_PACKAGE_SIZE: u64 = 512 * 1024 * 1024;
pub const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn verify_package(bytes: &[u8], asset: &ManifestAsset) -> Result<(), UpdateError> {
    if bytes.len() as u64 != asset.byte_length {
        return Err(UpdateError::Metadata(
            "downloaded size differs from signed size".to_owned(),
        ));
    }
    if sha256_hex(bytes) != asset.sha256 {
        return Err(UpdateError::Signature(
            "downloaded package hash differs from signed hash".to_owned(),
        ));
    }
    Ok(())
}

/// Operating-system target used in release metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Macos,
    Windows,
    Linux,
}

impl Display for Platform {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
        })
    }
}

impl std::str::FromStr for Platform {
    type Err = UpdateError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "macos" => Ok(Self::Macos),
            "windows" => Ok(Self::Windows),
            "linux" => Ok(Self::Linux),
            _ => Err(UpdateError::Metadata("unsupported platform".to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}

impl Display for Architecture {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        })
    }
}

impl std::str::FromStr for Architecture {
    type Err = UpdateError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "x86_64" => Ok(Self::X86_64),
            "aarch64" => Ok(Self::Aarch64),
            _ => Err(UpdateError::Metadata("unsupported architecture".to_owned())),
        }
    }
}

/// Installation ownership known to the composition root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstallContext {
    Installed,
    AppImage,
    Package,
    Portable,
    Unknown,
}

/// Identity embedded in the current executable and used by the common
/// candidate ordering policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentBuild {
    pub version: Version,
    pub commit: Option<[u8; 20]>,
    pub revision: Option<u64>,
    pub dirty: bool,
    pub platform: Platform,
    pub architecture: Architecture,
    pub install: InstallContext,
}

impl CurrentBuild {
    #[must_use]
    pub fn default_channel(&self) -> UpdateChannel {
        if self
            .version
            .pre
            .as_str()
            .split('.')
            .any(|part| part == "dev")
        {
            UpdateChannel::Dev
        } else {
            UpdateChannel::Stable
        }
    }

    /// Official packages need enough identity to make a downloaded artifact
    /// unambiguous. Check-only builds can still display candidates.
    #[must_use]
    pub fn may_auto_download(&self) -> bool {
        !self.dirty
            && self.commit.is_some()
            && self.revision.is_some()
            && !matches!(
                self.install,
                InstallContext::Unknown | InstallContext::Portable
            )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    MacosDmg,
    WindowsVelopack,
    WindowsZip,
    LinuxAppimage,
    LinuxDeb,
    LinuxRpm,
    LinuxTar,
    LinuxStaticTar,
}

impl Display for AssetKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MacosDmg => "macos-dmg",
            Self::WindowsVelopack => "windows-velopack",
            Self::WindowsZip => "windows-zip",
            Self::LinuxAppimage => "linux-appimage",
            Self::LinuxDeb => "linux-deb",
            Self::LinuxRpm => "linux-rpm",
            Self::LinuxTar => "linux-tar",
            Self::LinuxStaticTar => "linux-static-tar",
        })
    }
}

impl std::str::FromStr for AssetKind {
    type Err = UpdateError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "macos-dmg" => Ok(Self::MacosDmg),
            "windows-velopack" => Ok(Self::WindowsVelopack),
            "windows-zip" => Ok(Self::WindowsZip),
            "linux-appimage" => Ok(Self::LinuxAppimage),
            "linux-deb" => Ok(Self::LinuxDeb),
            "linux-rpm" => Ok(Self::LinuxRpm),
            "linux-tar" => Ok(Self::LinuxTar),
            "linux-static-tar" => Ok(Self::LinuxStaticTar),
            _ => Err(UpdateError::Metadata("unsupported asset kind".to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestAsset {
    pub platform: Platform,
    pub architecture: Architecture,
    pub kind: AssetKind,
    pub asset_name: String,
    pub byte_length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateManifest {
    pub schema: u8,
    pub product: String,
    pub repository: String,
    pub channel: UpdateChannel,
    pub release_tag: String,
    pub version: String,
    pub revision: u64,
    pub commit: String,
    pub published_at: String,
    pub minimum_updater_version: String,
    pub assets: Vec<ManifestAsset>,
}

/// The small, strict subset of a GitHub release response consumed by the
/// updater. Keeping this type in the shared crate prevents adapters from
/// independently selecting a release or concatenating an untrusted asset
/// URL. The API response is decoded into this small typed subset; unknown
/// fields are ignored because GitHub adds response fields without a client-
/// visible schema version. Manifest and signature parsing remain strict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub prerelease: bool,
    pub html_url: String,
    pub assets: Vec<GitHubReleaseAsset>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}

impl GitHubRelease {
    pub fn parse(bytes: &[u8]) -> Result<Self, UpdateError> {
        if bytes.len() as u64 > MAX_API_BODY {
            return Err(UpdateError::Metadata(
                "GitHub response exceeds 1 MiB".to_owned(),
            ));
        }
        let release: Self = parse_strict_json(bytes)?;
        release.validate()
    }

    pub fn validate(&self) -> Result<Self, UpdateError> {
        if self.tag_name.is_empty() || self.assets.is_empty() {
            return Err(UpdateError::Metadata(
                "GitHub release has no tag or assets".to_owned(),
            ));
        }
        validate_github_url(&self.html_url, false)?;
        let mut names = HashSet::new();
        for asset in &self.assets {
            if !valid_asset_name(&asset.name) || asset.size == 0 {
                return Err(UpdateError::Metadata(
                    "GitHub release contains an invalid asset".to_owned(),
                ));
            }
            validate_github_url(&asset.browser_download_url, false)?;
            if !names.insert(asset.name.as_str()) {
                return Err(UpdateError::Metadata(
                    "GitHub release contains duplicate asset names".to_owned(),
                ));
            }
        }
        let manifest_count = names.contains(MANIFEST_ASSET_NAME);
        let signature_count = names.contains(SIGNATURE_ASSET_NAME);
        if !manifest_count || !signature_count {
            return Err(UpdateError::Metadata(
                "GitHub release is missing its manifest or signature".to_owned(),
            ));
        }
        Ok(self.clone())
    }

    #[must_use]
    pub fn is_channel(&self, channel: UpdateChannel) -> bool {
        match channel {
            UpdateChannel::Stable => !self.prerelease && self.tag_name.starts_with('v'),
            UpdateChannel::Dev => self.tag_name == "dev",
        }
    }

    pub fn asset(&self, name: &str) -> Result<&GitHubReleaseAsset, UpdateError> {
        self.assets
            .iter()
            .find(|asset| asset.name == name)
            .ok_or(UpdateError::NoMatchingAsset)
    }

    pub fn validate_channel(&self, channel: UpdateChannel) -> Result<(), UpdateError> {
        if self.is_channel(channel) {
            Ok(())
        } else {
            Err(UpdateError::Metadata(
                "GitHub release does not match the selected channel".to_owned(),
            ))
        }
    }
}

/// Endpoints are intentionally fixed; release tags and URLs are never built
/// from user or server-controlled strings.
#[must_use]
pub const fn github_release_endpoint(channel: UpdateChannel) -> &'static str {
    match channel {
        UpdateChannel::Stable => "https://api.github.com/repos/MarcoS0ft/ConMan/releases/latest",
        UpdateChannel::Dev => "https://api.github.com/repos/MarcoS0ft/ConMan/releases/tags/dev",
    }
}

pub fn validate_github_release(
    release: &GitHubRelease,
    manifest: &UpdateManifest,
    channel: UpdateChannel,
) -> Result<(), UpdateError> {
    release.validate_channel(channel)?;
    if manifest.channel != channel
        || manifest.release_tag != release.tag_name
        || manifest.release_tag.is_empty()
    {
        return Err(UpdateError::Metadata(
            "release and manifest identity disagree".to_owned(),
        ));
    }
    if channel == UpdateChannel::Stable && release.tag_name != format!("v{}", manifest.version) {
        return Err(UpdateError::Metadata(
            "stable release tag does not match manifest version".to_owned(),
        ));
    }
    Ok(())
}

/// Finalized package facts consumed by the release metadata generator. The
/// generator hashes bytes supplied by packaging, so a manifest can never be
/// emitted with a caller-provided or stale checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseArtifact {
    pub platform: Platform,
    pub architecture: Architecture,
    pub kind: AssetKind,
    pub asset_name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseIdentity {
    pub channel: UpdateChannel,
    pub release_tag: String,
    pub version: Version,
    pub revision: u64,
    pub commit: [u8; 20],
    pub published_at: String,
    pub minimum_updater_version: Version,
}

impl ReleaseIdentity {
    pub fn validate(&self) -> Result<(), UpdateError> {
        if self.release_tag.is_empty() || self.published_at.is_empty() {
            return Err(UpdateError::Metadata(
                "release identity is missing tag or publication time".to_owned(),
            ));
        }
        if self.commit == [0; 20] {
            return Err(UpdateError::Metadata(
                "release identity requires a full commit".to_owned(),
            ));
        }
        match self.channel {
            UpdateChannel::Stable
                if self.version.pre.is_empty()
                    && self.release_tag == format!("v{}", self.version) => {}
            UpdateChannel::Dev if self.release_tag == "dev" => {}
            _ => {
                return Err(UpdateError::Metadata(
                    "release tag, channel, and version disagree".to_owned(),
                ));
            }
        }
        if self.minimum_updater_version > self.version {
            return Err(UpdateError::Unsupported(
                "minimum updater version exceeds the release version".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEntry {
    pub key_id: String,
    pub ed25519: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub schema: u8,
    pub signatures: Vec<SignatureEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub key_id: String,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedManifest {
    pub manifest: UpdateManifest,
    pub manifest_bytes: Vec<u8>,
}

/// Metadata selected for the running platform and install context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateCandidate {
    pub version: Version,
    pub revision: u64,
    pub commit: [u8; 20],
    pub channel: UpdateChannel,
    pub release_tag: String,
    pub minimum_updater_version: Version,
    pub asset: ManifestAsset,
    pub release_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedUpdate {
    pub candidate: UpdateCandidate,
    pub byte_length: u64,
    pub sha256: String,
    /// Opaque platform token (for example a Sparkle or Velopack staging id).
    pub platform_token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompletionAction {
    RestartToApply,
    FinishInSystemInstaller,
    OpenDownloadedArtifact,
    OpenReleasePage,
    ManagedExternally,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateState {
    Idle,
    Checking {
        manual: bool,
    },
    Available {
        candidate: UpdateCandidate,
    },
    Downloading {
        candidate: UpdateCandidate,
        received: u64,
        total: u64,
    },
    Preparing {
        candidate: UpdateCandidate,
    },
    Ready {
        staged: StagedUpdate,
        action: CompletionAction,
    },
    Installing {
        candidate: UpdateCandidate,
    },
    UpToDate {
        checked_at: SystemTime,
    },
    Error {
        operation: UpdateOperation,
        error: UpdateErrorSummary,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateOperation {
    Check,
    Download,
    Prepare,
    Install,
    Recover,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateErrorSummary {
    pub category: UpdateErrorCategory,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateErrorCategory {
    Network,
    RateLimited,
    Metadata,
    Signature,
    Version,
    Unsupported,
    NoMatchingAsset,
    Storage,
    Cancelled,
    Platform,
    Privilege,
    Relaunch,
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpdateError {
    #[error("network error: {0}")]
    Network(String),
    #[error("GitHub rate limit reached")]
    RateLimited,
    #[error("invalid update metadata: {0}")]
    Metadata(String),
    #[error("update signature verification failed: {0}")]
    Signature(String),
    #[error("update version rejected: {0}")]
    Version(String),
    #[error("unsupported update: {0}")]
    Unsupported(String),
    #[error("no matching update asset")]
    NoMatchingAsset,
    #[error("update storage error: {0}")]
    Storage(String),
    #[error("update cancelled")]
    Cancelled,
    #[error("platform update error: {0}")]
    Platform(String),
    #[error("privilege or installer handoff failed: {0}")]
    Privilege(String),
    #[error("relaunch failed: {0}")]
    Relaunch(String),
    #[error("update recovery failed: {0}")]
    Recovery(String),
}

impl UpdateError {
    #[must_use]
    pub fn category(&self) -> UpdateErrorCategory {
        match self {
            Self::Network(_) => UpdateErrorCategory::Network,
            Self::RateLimited => UpdateErrorCategory::RateLimited,
            Self::Metadata(_) => UpdateErrorCategory::Metadata,
            Self::Signature(_) => UpdateErrorCategory::Signature,
            Self::Version(_) => UpdateErrorCategory::Version,
            Self::Unsupported(_) => UpdateErrorCategory::Unsupported,
            Self::NoMatchingAsset => UpdateErrorCategory::NoMatchingAsset,
            Self::Storage(_) => UpdateErrorCategory::Storage,
            Self::Cancelled => UpdateErrorCategory::Cancelled,
            Self::Platform(_) => UpdateErrorCategory::Platform,
            Self::Privilege(_) => UpdateErrorCategory::Privilege,
            Self::Relaunch(_) => UpdateErrorCategory::Relaunch,
            Self::Recovery(_) => UpdateErrorCategory::Recovery,
        }
    }

    #[must_use]
    pub fn summary(&self) -> UpdateErrorSummary {
        UpdateErrorSummary {
            category: self.category(),
            message: self.category().user_message().to_owned(),
        }
    }
}

impl UpdateErrorCategory {
    /// Bounded, non-server-derived copy suitable for Settings and the update
    /// capsule. Backend details remain in typed logs; arbitrary response
    /// bodies, URLs, and local paths never reach UI state.
    #[must_use]
    pub const fn user_message(self) -> &'static str {
        match self {
            Self::Network => "Could not reach the update service",
            Self::RateLimited => "The update service is rate-limiting requests",
            Self::Metadata => "The update metadata is invalid",
            Self::Signature => "The update signature could not be verified",
            Self::Version => "The update version is not supported",
            Self::Unsupported => "This installation cannot apply the update",
            Self::NoMatchingAsset => "No update package matches this installation",
            Self::Storage => "Update state could not be saved",
            Self::Cancelled => "Update cancelled",
            Self::Platform => "The platform updater reported an error",
            Self::Privilege => "The platform installer needs permission",
            Self::Relaunch => "ConMan could not be relaunched after updating",
            Self::Recovery => "The previous update could not be recovered",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum StrictValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<StrictValue>),
    Object(serde_json::Map<String, serde_json::Value>),
}

impl StrictValue {
    fn into_json(self) -> serde_json::Value {
        match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(value) => serde_json::Value::Bool(value),
            Self::Number(value) => serde_json::Value::Number(value),
            Self::String(value) => serde_json::Value::String(value),
            Self::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(StrictValue::into_json).collect())
            }
            Self::Object(values) => serde_json::Value::Object(values),
        }
    }
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ValueVisitor;
        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue::Null)
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue::Number(value.into()))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue::Number(value.into()))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(StrictValue::Number)
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue::String(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue::String(value))
            }

            fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = access.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue::Array(values))
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                while let Some((key, value)) = access.next_entry::<String, StrictValue>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!(
                            "duplicate JSON object key `{key}`"
                        )));
                    }
                    values.insert(key, value.into_json());
                }
                Ok(StrictValue::Object(values))
            }
        }

        deserializer.deserialize_any(ValueVisitor)
    }
}

fn parse_strict_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, UpdateError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| UpdateError::Metadata(format!("invalid JSON: {error}")))?;
    deserializer
        .end()
        .map_err(|error| UpdateError::Metadata(format!("trailing JSON data: {error}")))?;
    serde_json::from_value(value.into_json())
        .map_err(|error| UpdateError::Metadata(format!("invalid update schema: {error}")))
}

fn parse_hex<const N: usize>(value: &str, what: &'static str) -> Result<[u8; N], UpdateError> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(UpdateError::Metadata(format!(
            "{what} must be lowercase hexadecimal"
        )));
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(UpdateError::Metadata(format!(
            "{what} must be lowercase hexadecimal"
        )));
    }
    let mut output = [0u8; N];
    for (idx, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[idx] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8, UpdateError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(UpdateError::Metadata("invalid hexadecimal".to_owned())),
    }
}

fn valid_asset_name(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('.')
        // Release assets are deliberately restricted to an ASCII basename.
        // This excludes path separators, control bytes, Windows device names,
        // and shell metacharacters while retaining the punctuation used by
        // package names (`.`, `_`, `-`, `+`).
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
        })
}

impl UpdateManifest {
    /// Parse, deny unknown/duplicate JSON fields, and validate all schema
    /// invariants. The exact input bytes are retained for detached signature
    /// verification.
    pub fn parse(bytes: &[u8]) -> Result<Self, UpdateError> {
        if bytes.len() as u64 > MAX_MANIFEST_BODY {
            return Err(UpdateError::Metadata("manifest exceeds 256 KiB".to_owned()));
        }
        let manifest: Self = parse_strict_json(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), UpdateError> {
        if self.schema != 1 {
            return Err(UpdateError::Metadata(
                "unsupported manifest schema".to_owned(),
            ));
        }
        if self.product != PRODUCT || self.repository != REPOSITORY {
            return Err(UpdateError::Metadata(
                "manifest product or repository mismatch".to_owned(),
            ));
        }
        let version = Version::parse(&self.version)
            .map_err(|_| UpdateError::Version("manifest version is not SemVer".to_owned()))?;
        Version::parse(&self.minimum_updater_version).map_err(|_| {
            UpdateError::Version("minimum updater version is not SemVer".to_owned())
        })?;
        parse_hex::<20>(&self.commit, "commit")?;
        if self.release_tag.is_empty() || self.published_at.is_empty() {
            return Err(UpdateError::Metadata(
                "release tag and publication time are required".to_owned(),
            ));
        }
        if self.channel == UpdateChannel::Stable
            && (!version.pre.is_empty() || self.release_tag != format!("v{version}"))
        {
            return Err(UpdateError::Metadata(
                "stable manifest tag/version mismatch".to_owned(),
            ));
        }
        if self.channel == UpdateChannel::Dev && self.release_tag != "dev" {
            return Err(UpdateError::Metadata(
                "dev manifest must use the rolling dev tag".to_owned(),
            ));
        }
        if self.assets.is_empty() {
            return Err(UpdateError::Metadata("manifest has no assets".to_owned()));
        }
        let mut identities = HashSet::new();
        for asset in &self.assets {
            if !valid_asset_name(&asset.asset_name) {
                return Err(UpdateError::Metadata(
                    "asset name is not a safe basename".to_owned(),
                ));
            }
            if asset.byte_length == 0 || asset.byte_length > MAX_PACKAGE_SIZE {
                return Err(UpdateError::Metadata(
                    "asset size is outside the supported limit".to_owned(),
                ));
            }
            if asset.sha256.len() != 64
                || !asset.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                || asset.sha256.bytes().any(|byte| byte.is_ascii_uppercase())
            {
                return Err(UpdateError::Metadata(
                    "asset sha256 must be 64 lowercase hex characters".to_owned(),
                ));
            }
            if !identities.insert((asset.platform, asset.architecture, asset.kind)) {
                return Err(UpdateError::Metadata(
                    "duplicate platform/architecture/kind asset".to_owned(),
                ));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn version(&self) -> Option<Version> {
        Version::parse(&self.version).ok()
    }
}

pub fn generate_manifest(
    identity: &ReleaseIdentity,
    artifacts: &[ReleaseArtifact],
) -> Result<Vec<u8>, UpdateError> {
    identity.validate()?;
    if artifacts.is_empty() {
        return Err(UpdateError::Metadata(
            "release has no finalized artifacts".to_owned(),
        ));
    }
    let mut seen = HashSet::new();
    let assets = artifacts
        .iter()
        .map(|artifact| {
            if !seen.insert((artifact.platform, artifact.architecture, artifact.kind)) {
                return Err(UpdateError::Metadata(
                    "duplicate release artifact identity".to_owned(),
                ));
            }
            Ok(ManifestAsset {
                platform: artifact.platform,
                architecture: artifact.architecture,
                kind: artifact.kind,
                asset_name: artifact.asset_name.clone(),
                byte_length: artifact.bytes.len() as u64,
                sha256: sha256_hex(&artifact.bytes),
            })
        })
        .collect::<Result<Vec<_>, UpdateError>>()?;
    let manifest = UpdateManifest {
        schema: 1,
        product: PRODUCT.to_owned(),
        repository: REPOSITORY.to_owned(),
        channel: identity.channel,
        release_tag: identity.release_tag.clone(),
        version: identity.version.to_string(),
        revision: identity.revision,
        commit: identity
            .commit
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        published_at: identity.published_at.clone(),
        minimum_updater_version: identity.minimum_updater_version.to_string(),
        assets,
    };
    manifest.validate()?;
    serde_json::to_vec(&manifest)
        .map_err(|error| UpdateError::Metadata(format!("could not serialize manifest: {error}")))
}

impl SignatureEnvelope {
    pub fn parse(bytes: &[u8]) -> Result<Self, UpdateError> {
        if bytes.len() as u64 > MAX_SIGNATURE_BODY {
            return Err(UpdateError::Signature(
                "signature envelope exceeds 8 KiB".to_owned(),
            ));
        }
        let envelope: Self =
            parse_strict_json(bytes).map_err(|error| UpdateError::Signature(error.to_string()))?;
        if envelope.schema != 1 || envelope.signatures.is_empty() {
            return Err(UpdateError::Signature(
                "signature envelope is empty or unsupported".to_owned(),
            ));
        }
        let mut keys = HashSet::new();
        for signature in &envelope.signatures {
            if signature.key_id.is_empty() || !keys.insert(signature.key_id.as_str()) {
                return Err(UpdateError::Signature(
                    "duplicate or empty signature key id".to_owned(),
                ));
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&signature.ed25519)
                .map_err(|_| UpdateError::Signature("signature is not valid base64".to_owned()))?;
            if decoded.len() != 64 {
                return Err(UpdateError::Signature(
                    "Ed25519 signature must be 64 bytes".to_owned(),
                ));
            }
        }
        Ok(envelope)
    }
}

pub fn verify_manifest(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    trusted_keys: &[TrustedKey],
) -> Result<VerifiedManifest, UpdateError> {
    let manifest = UpdateManifest::parse(manifest_bytes)?;
    let envelope = SignatureEnvelope::parse(signature_bytes)?;
    let trusted = trusted_keys
        .iter()
        .map(|key| (key.key_id.as_str(), key.public_key))
        .collect::<HashMap<_, _>>();
    let mut valid = false;
    for entry in envelope.signatures {
        let Some(public_key) = trusted.get(entry.key_id.as_str()) else {
            continue;
        };
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(entry.ed25519)
            .map_err(|_| UpdateError::Signature("signature is not valid base64".to_owned()))?;
        let signature = Signature::try_from(decoded.as_slice())
            .map_err(|_| UpdateError::Signature("malformed Ed25519 signature".to_owned()))?;
        let key = VerifyingKey::from_bytes(public_key)
            .map_err(|_| UpdateError::Signature("invalid trusted public key".to_owned()))?;
        if key.verify(manifest_bytes, &signature).is_ok() {
            valid = true;
            break;
        }
    }
    if !valid {
        return Err(UpdateError::Signature(
            "no trusted signature matched".to_owned(),
        ));
    }
    Ok(VerifiedManifest {
        manifest,
        manifest_bytes: manifest_bytes.to_owned(),
    })
}

/// Build the detached signature envelope for a manifest. Release tooling may
/// use this helper; private key bytes never enter a runtime update state.
pub fn sign_manifest(
    manifest_bytes: &[u8],
    key_id: impl Into<String>,
    secret_key: [u8; 32],
) -> String {
    use ed25519_dalek::{Signer, SigningKey};
    let signing_key = SigningKey::from_bytes(&secret_key);
    let signature = signing_key.sign(manifest_bytes);
    let encoded = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    serde_json::to_string(&SignatureEnvelope {
        schema: 1,
        signatures: vec![SignatureEntry {
            key_id: key_id.into(),
            ed25519: encoded,
        }],
    })
    .expect("signature envelope is always serializable")
}

fn candidate_asset_kind_allowed(
    channel: UpdateChannel,
    platform: Platform,
    kind: AssetKind,
) -> bool {
    matches!(
        (platform, channel, kind),
        (Platform::Macos, _, AssetKind::MacosDmg)
            | (Platform::Windows, _, AssetKind::WindowsVelopack)
            | (Platform::Windows, _, AssetKind::WindowsZip)
            | (Platform::Linux, _, AssetKind::LinuxAppimage)
            | (Platform::Linux, _, AssetKind::LinuxDeb)
            | (Platform::Linux, _, AssetKind::LinuxRpm)
            | (Platform::Linux, _, AssetKind::LinuxTar)
            | (Platform::Linux, _, AssetKind::LinuxStaticTar)
    )
}

/// Select the exact release asset and apply the pinned channel/version rules.
pub fn select_candidate(
    verified: &VerifiedManifest,
    current: &CurrentBuild,
    channel: UpdateChannel,
    release_url: impl Into<String>,
    updater_version: &Version,
) -> Result<Option<UpdateCandidate>, UpdateError> {
    let release_url = release_url.into();
    validate_github_url(&release_url, false)?;
    let manifest = &verified.manifest;
    if manifest.channel != channel {
        return Err(UpdateError::Metadata(
            "manifest channel disagrees with selected channel".to_owned(),
        ));
    }
    let version = manifest
        .version()
        .ok_or_else(|| UpdateError::Version("manifest version is not SemVer".to_owned()))?;
    let commit = parse_hex::<20>(&manifest.commit, "commit")?;
    let minimum = Version::parse(&manifest.minimum_updater_version)
        .map_err(|_| UpdateError::Version("minimum updater version is not SemVer".to_owned()))?;
    if minimum > *updater_version {
        return Err(UpdateError::Unsupported(
            "minimum updater version is newer than ConMan".to_owned(),
        ));
    }
    let actionable = match channel {
        UpdateChannel::Stable => version > current.version && version.pre.is_empty(),
        UpdateChannel::Dev => current
            .revision
            .is_some_and(|revision| manifest.revision > revision),
    };
    if !actionable {
        return Ok(None);
    }
    let asset = manifest
        .assets
        .iter()
        .find(|asset| {
            asset.platform == current.platform
                && asset.architecture == current.architecture
                && candidate_asset_kind_allowed(channel, current.platform, asset.kind)
        })
        .cloned()
        .ok_or(UpdateError::NoMatchingAsset)?;
    Ok(Some(UpdateCandidate {
        version,
        revision: manifest.revision,
        commit,
        channel,
        release_tag: manifest.release_tag.clone(),
        minimum_updater_version: minimum,
        asset,
        release_url,
    }))
}

/// A URL is only accepted after a redirect/final response has been checked by
/// this policy. Keeping it as a pure function makes hostile redirect tests
/// deterministic and keeps URL handling out of the UI.
pub fn validate_github_url(url: &str, initial_api_request: bool) -> Result<(), UpdateError> {
    let parsed = parse_simple_url(url)?;
    if parsed.scheme != "https" || parsed.userinfo || parsed.port.is_some_and(|port| port != 443) {
        return Err(UpdateError::Network(
            "update endpoint must use HTTPS without credentials".to_owned(),
        ));
    }
    let allowed = parsed.host == "github.com"
        || parsed.host == "api.github.com"
        || parsed.host.ends_with(".githubusercontent.com");
    if !allowed {
        return Err(UpdateError::Network(
            "redirected to an untrusted host".to_owned(),
        ));
    }
    if initial_api_request && parsed.host != "api.github.com" {
        return Err(UpdateError::Network(
            "GitHub API request must start at api.github.com".to_owned(),
        ));
    }
    Ok(())
}

/// Validate every URL in an HTTP redirect chain, including the initial API
/// request. A client must call this before following a redirect and again for
/// the final response; checking only the first URL is insufficient because a
/// GitHub asset may redirect to a CDN host.
pub fn validate_redirect_chain(urls: &[&str]) -> Result<(), UpdateError> {
    if urls.is_empty() {
        return Err(UpdateError::Network(
            "empty update redirect chain".to_owned(),
        ));
    }
    if urls.len().saturating_sub(1) > HttpPolicy::default().max_redirects as usize {
        return Err(UpdateError::Network("too many update redirects".to_owned()));
    }
    for (index, url) in urls.iter().enumerate() {
        validate_github_url(url, index == 0)?;
    }
    Ok(())
}

/// Classify an HTTP response without copying or surfacing its body. GitHub's
/// rate-limit response is deliberately distinct from a missing release so a
/// client can apply the retry schedule rather than suppressing the update.
pub fn classify_http_status(
    status: u16,
    rate_limit_remaining: Option<&str>,
) -> Result<(), UpdateError> {
    match status {
        200..=299 => Ok(()),
        403 if rate_limit_remaining.is_some_and(|value| value.trim() == "0") => {
            Err(UpdateError::RateLimited)
        }
        408 | 425 | 429 | 500..=599 => Err(UpdateError::Network(
            "update service returned a retryable response".to_owned(),
        )),
        404 => Err(UpdateError::NoMatchingAsset),
        _ => Err(UpdateError::Network(
            "update service returned an unexpected response".to_owned(),
        )),
    }
}

/// Incremental package verifier used by every platform download adapter.
/// Callers can feed bounded chunks directly from their HTTP body; no package
/// bytes are retained in this crate and a length overflow fails immediately.
#[derive(Debug)]
pub struct PackageVerifier {
    expected_length: u64,
    expected_sha256: String,
    received: u64,
    hasher: Sha256,
}

impl PackageVerifier {
    pub fn new(asset: &ManifestAsset) -> Result<Self, UpdateError> {
        if asset.byte_length == 0 || asset.byte_length > MAX_PACKAGE_SIZE {
            return Err(UpdateError::Metadata(
                "asset size is outside the supported limit".to_owned(),
            ));
        }
        // Reuse manifest validation rules without constructing an entire
        // manifest; this catches accidental uppercase or truncated hashes in
        // platform adapters before any staging file is created.
        if asset.sha256.len() != 64
            || !asset.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || asset.sha256.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(UpdateError::Metadata("asset sha256 is invalid".to_owned()));
        }
        Ok(Self {
            expected_length: asset.byte_length,
            expected_sha256: asset.sha256.clone(),
            received: 0,
            hasher: Sha256::new(),
        })
    }

    pub fn update(&mut self, chunk: &[u8]) -> Result<u64, UpdateError> {
        let chunk_len = u64::try_from(chunk.len())
            .map_err(|_| UpdateError::Metadata("download chunk is too large".to_owned()))?;
        let next = self
            .received
            .checked_add(chunk_len)
            .ok_or_else(|| UpdateError::Metadata("download length overflow".to_owned()))?;
        if next > self.expected_length {
            return Err(UpdateError::Metadata(
                "download exceeds signed size".to_owned(),
            ));
        }
        self.hasher.update(chunk);
        self.received = next;
        Ok(next)
    }

    pub fn finish(self) -> Result<(), UpdateError> {
        if self.received != self.expected_length {
            return Err(UpdateError::Metadata(
                "download ended before the signed size".to_owned(),
            ));
        }
        let digest = self.hasher.finalize();
        let actual = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if actual != self.expected_sha256 {
            return Err(UpdateError::Signature(
                "downloaded package hash differs from signed hash".to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn received(&self) -> u64 {
        self.received
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SimpleUrl<'a> {
    scheme: &'a str,
    host: String,
    port: Option<u16>,
    userinfo: bool,
}

fn parse_simple_url(url: &str) -> Result<SimpleUrl<'_>, UpdateError> {
    let (scheme, remainder) = url
        .split_once("://")
        .ok_or_else(|| UpdateError::Network("malformed update URL".to_owned()))?;
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    let userinfo = authority.contains('@');
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let (host, port) = if host_port.starts_with('[') {
        return Err(UpdateError::Network(
            "IPv6 update hosts are not allowed".to_owned(),
        ));
    } else if let Some((host, port)) = host_port.rsplit_once(':') {
        (
            host,
            Some(
                port.parse::<u16>()
                    .map_err(|_| UpdateError::Network("invalid URL port".to_owned()))?,
            ),
        )
    } else {
        (host_port, None)
    };
    if host.is_empty() {
        return Err(UpdateError::Network("update URL has no host".to_owned()));
    }
    Ok(SimpleUrl {
        scheme,
        host: host.to_ascii_lowercase(),
        port,
        userinfo,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpPolicy {
    pub connect_timeout: Duration,
    pub read_idle_timeout: Duration,
    pub check_deadline: Duration,
    pub package_deadline: Duration,
    pub max_redirects: u8,
}

impl Default for HttpPolicy {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            read_idle_timeout: Duration::from_secs(30),
            check_deadline: Duration::from_secs(30),
            package_deadline: Duration::from_secs(15 * 60),
            max_redirects: 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCapabilities {
    pub can_download: bool,
    pub can_install: bool,
    pub completion: CompletionAction,
}

impl Default for BackendCapabilities {
    fn default() -> Self {
        Self {
            can_download: false,
            can_install: false,
            completion: CompletionAction::OpenReleasePage,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendCommand {
    Check {
        generation: u64,
        channel: UpdateChannel,
    },
    Download {
        generation: u64,
        candidate: UpdateCandidate,
    },
    Cancel {
        generation: u64,
    },
    BeginCompletion {
        generation: u64,
        staged: StagedUpdate,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendEvent {
    NoUpdate {
        generation: u64,
    },
    Candidate {
        generation: u64,
        candidate: UpdateCandidate,
    },
    DownloadProgress {
        generation: u64,
        received: u64,
        total: u64,
    },
    Preparing {
        generation: u64,
    },
    Ready {
        generation: u64,
        staged: StagedUpdate,
    },
    CompletionHandoffStarted {
        generation: u64,
    },
    RelaunchRequested {
        generation: u64,
    },
    Error {
        generation: u64,
        operation: UpdateOperation,
        error: UpdateError,
    },
}

pub trait UpdateBackend: Send {
    fn capabilities(&self) -> BackendCapabilities;
    fn submit(&mut self, command: BackendCommand) -> Result<(), UpdateError>;
    fn drain_events(&mut self) -> Vec<BackendEvent>;
    fn shutdown(&mut self, deadline: Instant);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePreferences {
    pub auto_check: bool,
    pub auto_download: bool,
    pub channel: Option<UpdateChannel>,
}

impl Default for UpdatePreferences {
    fn default() -> Self {
        Self {
            auto_check: true,
            auto_download: true,
            channel: None,
        }
    }
}

impl UpdatePreferences {
    #[must_use]
    pub fn effective_channel(&self, build: &CurrentBuild) -> UpdateChannel {
        self.channel.unwrap_or_else(|| build.default_channel())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSnapshot {
    pub state: UpdateState,
    pub channel: UpdateChannel,
    pub auto_check: bool,
    pub auto_download: bool,
    pub capabilities: BackendCapabilities,
    pub last_successful_check: Option<SystemTime>,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateCommand {
    StartAutomatic,
    CheckNow,
    DownloadAvailable,
    Cancel,
    DiscardStaged,
    BeginCompletion,
    PreferencesChanged(UpdatePreferences),
    Shutdown,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateEvent {
    Snapshot(UpdateSnapshot),
    CompletionHandoffStarted,
    RelaunchRequested,
}

#[derive(Debug)]
pub struct UpdateController<B> {
    backend: B,
    current_build: CurrentBuild,
    updater_version: Version,
    preferences: UpdatePreferences,
    state: UpdateState,
    generation: u64,
    exhausted: bool,
    current_candidate: Option<UpdateCandidate>,
    manual_operation: bool,
    automatic_download: bool,
    schedule: ScheduleState,
    last_error: Option<UpdateErrorSummary>,
    last_successful_check: Option<SystemTime>,
    events: VecDeque<UpdateEvent>,
}

impl<B: UpdateBackend> UpdateController<B> {
    #[must_use]
    pub fn new(
        backend: B,
        current_build: CurrentBuild,
        updater_version: Version,
        preferences: UpdatePreferences,
    ) -> Self {
        let channel = preferences.effective_channel(&current_build);
        let capabilities = backend.capabilities();
        Self {
            backend,
            current_build,
            updater_version,
            preferences,
            state: UpdateState::Idle,
            generation: 0,
            exhausted: false,
            current_candidate: None,
            manual_operation: false,
            automatic_download: false,
            schedule: ScheduleState::default(),
            last_error: None,
            last_successful_check: None,
            events: VecDeque::new(),
        }
        .with_snapshot(channel, capabilities)
    }

    fn with_snapshot(
        mut self,
        _channel: UpdateChannel,
        _capabilities: BackendCapabilities,
    ) -> Self {
        self.emit_snapshot();
        self
    }

    #[must_use]
    pub fn state(&self) -> &UpdateState {
        &self.state
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn preferences(&self) -> &UpdatePreferences {
        &self.preferences
    }

    #[must_use]
    pub fn updater_version(&self) -> &Version {
        &self.updater_version
    }

    #[must_use]
    pub fn snapshot(&self) -> UpdateSnapshot {
        self.snapshot_value()
    }

    /// Attach persisted machine-local scheduling state before the worker is
    /// started. The builder form keeps deterministic tests independent of the
    /// wall clock while production can load the state through
    /// [`UpdateMachineState`].
    #[must_use]
    pub fn with_schedule(mut self, schedule: ScheduleState) -> Self {
        self.schedule = schedule;
        self
    }

    #[must_use]
    pub fn schedule(&self) -> &ScheduleState {
        &self.schedule
    }

    /// Dispatch using an explicit timestamp. Production callers use
    /// [`Self::dispatch`], while tests and state-storage recovery can make the
    /// interval/backoff policy deterministic.
    pub fn dispatch_at(
        &mut self,
        command: UpdateCommand,
        now: SystemTime,
    ) -> Result<(), UpdateError> {
        self.dispatch_inner(command, now)
    }

    pub fn dispatch(&mut self, command: UpdateCommand) -> Result<(), UpdateError> {
        self.dispatch_at(command, SystemTime::now())
    }

    fn dispatch_inner(
        &mut self,
        command: UpdateCommand,
        now: SystemTime,
    ) -> Result<(), UpdateError> {
        match command {
            UpdateCommand::StartAutomatic => {
                if self.preferences.auto_check {
                    self.start_check(false, now)?;
                }
            }
            UpdateCommand::CheckNow => self.start_check(true, now)?,
            UpdateCommand::DownloadAvailable => self.start_download(false)?,
            UpdateCommand::Cancel => self.cancel_current()?,
            UpdateCommand::DiscardStaged => self.discard_staged()?,
            UpdateCommand::BeginCompletion => self.begin_completion()?,
            UpdateCommand::PreferencesChanged(preferences) => {
                self.preferences_changed(preferences, now)?;
            }
            UpdateCommand::Shutdown => {
                self.backend
                    .shutdown(Instant::now() + Duration::from_secs(5));
            }
        }
        Ok(())
    }

    /// Drain backend facts and reduce each one. Backends cannot publish a
    /// user-visible state directly; all accepted events pass through here.
    pub fn poll_backend(&mut self) {
        let events = self.backend.drain_events();
        for event in events {
            if let Err(error) = self.reduce_backend_event(event) {
                self.fail(UpdateOperation::Check, error);
            }
        }
    }

    pub fn drain_events(&mut self, limit: usize) -> Vec<UpdateEvent> {
        self.events.drain(..self.events.len().min(limit)).collect()
    }

    fn start_check(&mut self, manual: bool, now: SystemTime) -> Result<(), UpdateError> {
        if self.exhausted {
            return Err(UpdateError::Unsupported(
                "update generation exhausted".to_owned(),
            ));
        }
        if matches!(self.state, UpdateState::Checking { .. }) {
            // Repeated manual checks coalesce to the current operation.
            if manual {
                self.manual_operation = true;
            }
            return Ok(());
        }
        let channel = self.preferences.effective_channel(&self.current_build);
        if !manual && !self.schedule.eligible(channel, now) {
            return Ok(());
        }
        let generation = self.bump_generation()?;
        self.manual_operation = manual;
        self.automatic_download = false;
        self.last_error = None;
        self.schedule.record_attempt(channel, now);
        self.state = UpdateState::Checking { manual };
        if let Err(error) = self.backend.submit(BackendCommand::Check {
            generation,
            channel,
        }) {
            self.fail(UpdateOperation::Check, error);
            return Ok(());
        }
        self.emit_snapshot();
        Ok(())
    }

    fn start_download(&mut self, automatic: bool) -> Result<(), UpdateError> {
        let Some(candidate) = self.current_candidate.clone() else {
            return self.illegal("download requested without an available candidate");
        };
        if !matches!(self.state, UpdateState::Available { .. }) {
            return self.illegal("download requested outside Available state");
        }
        if !self.backend.capabilities().can_download {
            return self.illegal("backend cannot download updates");
        }
        let generation = self.bump_generation()?;
        self.automatic_download = automatic;
        self.state = UpdateState::Downloading {
            total: candidate.asset.byte_length,
            received: 0,
            candidate: candidate.clone(),
        };
        self.backend
            .submit(BackendCommand::Download {
                generation,
                candidate,
            })
            .inspect_err(|error| {
                self.fail(UpdateOperation::Download, error.clone());
            })?;
        self.emit_snapshot();
        Ok(())
    }

    fn cancel_current(&mut self) -> Result<(), UpdateError> {
        if !matches!(
            self.state,
            UpdateState::Checking { .. }
                | UpdateState::Downloading { .. }
                | UpdateState::Preparing { .. }
                | UpdateState::Installing { .. }
        ) {
            return Ok(());
        }
        let old_generation = self.generation;
        self.backend.submit(BackendCommand::Cancel {
            generation: old_generation,
        })?;
        self.bump_generation()?;
        let candidate = self.current_candidate.clone();
        self.state = candidate.map_or(UpdateState::Idle, |candidate| UpdateState::Available {
            candidate,
        });
        self.automatic_download = false;
        self.emit_snapshot();
        Ok(())
    }

    fn begin_completion(&mut self) -> Result<(), UpdateError> {
        // The close coordinator may race with a second activation of the
        // capsule while the first handoff is in flight. A repeated request
        // must not submit a second install.
        if matches!(self.state, UpdateState::Installing { .. }) {
            return Ok(());
        }
        let UpdateState::Ready { staged, .. } = self.state.clone() else {
            return self.illegal("completion requested before an update is Ready");
        };
        if !self.backend.capabilities().can_install {
            return self.illegal("backend cannot complete updates");
        }
        let generation = self.bump_generation()?;
        let candidate = staged.candidate.clone();
        self.state = UpdateState::Installing {
            candidate: candidate.clone(),
        };
        self.backend
            .submit(BackendCommand::BeginCompletion { generation, staged })
            .inspect_err(|error| {
                self.fail(UpdateOperation::Install, error.clone());
            })?;
        self.emit_snapshot();
        Ok(())
    }

    fn discard_staged(&mut self) -> Result<(), UpdateError> {
        if !matches!(self.state, UpdateState::Ready { .. }) {
            return Ok(());
        }
        let generation = self.generation;
        self.backend.submit(BackendCommand::Cancel { generation })?;
        self.bump_generation()?;
        self.state = UpdateState::Idle;
        self.current_candidate = None;
        self.automatic_download = false;
        self.emit_snapshot();
        Ok(())
    }

    fn preferences_changed(
        &mut self,
        preferences: UpdatePreferences,
        now: SystemTime,
    ) -> Result<(), UpdateError> {
        let old_channel = self.preferences.effective_channel(&self.current_build);
        let new_channel = preferences.effective_channel(&self.current_build);
        let channel_changed = old_channel != new_channel;
        let download_disabled = self.preferences.auto_download && !preferences.auto_download;
        let check_disabled = self.preferences.auto_check && !preferences.auto_check;
        self.preferences = preferences;
        let automatic_checking = matches!(self.state, UpdateState::Checking { manual: false });
        let automatic_work = automatic_checking
            || (self.automatic_download
                && matches!(
                    self.state,
                    UpdateState::Downloading { .. } | UpdateState::Preparing { .. }
                ));
        let should_cancel = channel_changed
            || (download_disabled && self.automatic_download)
            || (check_disabled && automatic_work);
        if should_cancel
            && matches!(
                self.state,
                UpdateState::Checking { .. }
                    | UpdateState::Downloading { .. }
                    | UpdateState::Preparing { .. }
                    | UpdateState::Installing { .. }
            )
        {
            let _ = self.cancel_current();
        }
        if channel_changed {
            // A channel switch invalidates any staged package from the old
            // channel. Ordinary UI cancellation never reaches Ready and keeps
            // that completed staged update intact.
            if matches!(self.state, UpdateState::Ready { .. }) {
                let _ = self.backend.submit(BackendCommand::Cancel {
                    generation: self.generation,
                });
            }
            self.current_candidate = None;
            self.last_error = None;
            self.schedule.force_check(new_channel);
            self.bump_generation()?;
            self.state = UpdateState::Idle;
            self.emit_snapshot();
            if self.preferences.auto_check {
                self.start_check(false, now)?;
            }
        } else if (download_disabled || check_disabled)
            && matches!(self.state, UpdateState::Available { .. })
        {
            self.emit_snapshot();
        }
        Ok(())
    }

    fn reduce_backend_event(&mut self, event: BackendEvent) -> Result<(), UpdateError> {
        let event_generation = match &event {
            BackendEvent::NoUpdate { generation }
            | BackendEvent::Candidate { generation, .. }
            | BackendEvent::DownloadProgress { generation, .. }
            | BackendEvent::Preparing { generation }
            | BackendEvent::Ready { generation, .. }
            | BackendEvent::CompletionHandoffStarted { generation }
            | BackendEvent::RelaunchRequested { generation }
            | BackendEvent::Error { generation, .. } => *generation,
        };
        if event_generation != self.generation || event_generation == 0 {
            return Ok(());
        }
        match event {
            BackendEvent::NoUpdate { .. } => {
                self.current_candidate = None;
                let checked_at = SystemTime::now();
                let channel = self.preferences.effective_channel(&self.current_build);
                self.schedule.record_success(channel, checked_at);
                self.last_successful_check = Some(checked_at);
                self.last_error = None;
                self.state = if self.manual_operation {
                    UpdateState::UpToDate { checked_at }
                } else {
                    UpdateState::Idle
                };
                self.emit_snapshot();
            }
            BackendEvent::Candidate { candidate, .. } => {
                self.validate_candidate(&candidate)?;
                self.current_candidate = Some(candidate.clone());
                let checked_at = SystemTime::now();
                self.schedule.record_success(candidate.channel, checked_at);
                self.last_successful_check = Some(checked_at);
                self.last_error = None;
                self.state = UpdateState::Available {
                    candidate: candidate.clone(),
                };
                let may_download = self.preferences.auto_download
                    && self.backend.capabilities().can_download
                    && self.current_build.may_auto_download();
                if may_download {
                    self.start_download(true)?;
                } else {
                    self.emit_snapshot();
                }
            }
            BackendEvent::DownloadProgress {
                received, total, ..
            } => {
                let UpdateState::Downloading { candidate, .. } = &self.state else {
                    return self.illegal("download progress outside Downloading state");
                };
                if total == 0 || received > total || total != candidate.asset.byte_length {
                    return self.fail_and_error(
                        UpdateOperation::Download,
                        UpdateError::Metadata("invalid download progress".to_owned()),
                    );
                }
                self.state = UpdateState::Downloading {
                    candidate: candidate.clone(),
                    received,
                    total,
                };
                self.emit_snapshot();
            }
            BackendEvent::Preparing { .. } => {
                let UpdateState::Downloading { candidate, .. } = &self.state else {
                    return self.illegal("preparing outside Downloading state");
                };
                self.state = UpdateState::Preparing {
                    candidate: candidate.clone(),
                };
                self.emit_snapshot();
            }
            BackendEvent::Ready { staged, .. } => {
                if !matches!(
                    self.state,
                    UpdateState::Downloading { .. } | UpdateState::Preparing { .. }
                ) {
                    return self.illegal("ready outside download/preparing state");
                }
                if staged.byte_length != staged.candidate.asset.byte_length
                    || staged.sha256 != staged.candidate.asset.sha256
                    || staged.platform_token.is_empty()
                {
                    return self.fail_and_error(
                        UpdateOperation::Prepare,
                        UpdateError::Recovery("staged update identity is invalid".to_owned()),
                    );
                }
                self.current_candidate = Some(staged.candidate.clone());
                self.state = UpdateState::Ready {
                    staged,
                    action: self.backend.capabilities().completion,
                };
                self.emit_snapshot();
            }
            BackendEvent::CompletionHandoffStarted { .. } => {
                self.events.push_back(UpdateEvent::CompletionHandoffStarted);
            }
            BackendEvent::RelaunchRequested { .. } => {
                self.events.push_back(UpdateEvent::RelaunchRequested);
            }
            BackendEvent::Error {
                operation, error, ..
            } => self.fail(operation, error),
        }
        Ok(())
    }

    fn bump_generation(&mut self) -> Result<u64, UpdateError> {
        if self.exhausted {
            return Err(UpdateError::Unsupported(
                "update generation exhausted".to_owned(),
            ));
        }
        let next = self.generation.checked_add(1).filter(|value| *value != 0);
        match next {
            Some(value) => {
                self.generation = value;
                Ok(value)
            }
            None => {
                self.exhausted = true;
                Err(UpdateError::Unsupported(
                    "update generation exhausted".to_owned(),
                ))
            }
        }
    }

    fn validate_candidate(&self, candidate: &UpdateCandidate) -> Result<(), UpdateError> {
        let channel = self.preferences.effective_channel(&self.current_build);
        if candidate.channel != channel
            || candidate.asset.platform != self.current_build.platform
            || candidate.asset.architecture != self.current_build.architecture
        {
            return Err(UpdateError::Metadata(
                "backend candidate does not match the running installation".to_owned(),
            ));
        }
        let actionable = match channel {
            UpdateChannel::Stable => {
                candidate.version > self.current_build.version && candidate.version.pre.is_empty()
            }
            UpdateChannel::Dev => self
                .current_build
                .revision
                .is_some_and(|revision| candidate.revision > revision),
        };
        if !actionable {
            return Err(UpdateError::Version(
                "backend candidate is not newer than the running build".to_owned(),
            ));
        }
        Ok(())
    }

    fn illegal<T>(&mut self, message: &str) -> Result<T, UpdateError> {
        Err(UpdateError::Platform(format!(
            "illegal update transition: {message}"
        )))
    }

    fn fail_and_error(
        &mut self,
        operation: UpdateOperation,
        error: UpdateError,
    ) -> Result<(), UpdateError> {
        self.fail(operation, error.clone());
        Err(error)
    }

    fn fail(&mut self, operation: UpdateOperation, error: UpdateError) {
        let summary = error.summary();
        self.last_error = Some(summary.clone());
        if !self.manual_operation {
            let channel = self.preferences.effective_channel(&self.current_build);
            self.schedule.record_failure(channel, SystemTime::now());
            self.state = UpdateState::Idle;
        } else {
            self.state = UpdateState::Error {
                operation,
                error: summary,
            };
        }
        self.emit_snapshot();
    }

    fn snapshot_value(&self) -> UpdateSnapshot {
        let channel = self.preferences.effective_channel(&self.current_build);
        UpdateSnapshot {
            state: self.state.clone(),
            channel,
            auto_check: self.preferences.auto_check,
            auto_download: self.preferences.auto_download,
            capabilities: self.backend.capabilities(),
            last_successful_check: self.last_successful_check,
            status: if matches!(self.state, UpdateState::Idle) && self.last_error.is_some() {
                self.last_error
                    .as_ref()
                    .map_or_else(|| state_status(&self.state), |error| error.message.clone())
            } else {
                state_status(&self.state)
            },
        }
    }

    fn emit_snapshot(&mut self) {
        self.events
            .push_back(UpdateEvent::Snapshot(self.snapshot_value()));
        while self.events.len() > 128 {
            self.events.pop_front();
        }
    }
}

fn state_status(state: &UpdateState) -> String {
    match state {
        UpdateState::Idle => "Updates are idle".to_owned(),
        UpdateState::Checking { manual: true } => "Checking for updates…".to_owned(),
        UpdateState::Checking { manual: false } => {
            "Checking for updates in the background".to_owned()
        }
        UpdateState::Available { candidate } => {
            format!("Version {} is available", candidate.version)
        }
        UpdateState::Downloading {
            received, total, ..
        } => format!("Downloading update ({received} of {total} bytes)"),
        UpdateState::Preparing { .. } => "Preparing update".to_owned(),
        UpdateState::Ready { action, .. } => match action {
            CompletionAction::RestartToApply => "Restart to complete update".to_owned(),
            CompletionAction::FinishInSystemInstaller => {
                "Finish update in system installer".to_owned()
            }
            CompletionAction::OpenDownloadedArtifact => "Downloaded update is ready".to_owned(),
            CompletionAction::OpenReleasePage => "Open release page to update".to_owned(),
            CompletionAction::ManagedExternally => "Update is managed externally".to_owned(),
        },
        UpdateState::Installing { .. } => "Completing update".to_owned(),
        UpdateState::UpToDate { .. } => "ConMan is up to date".to_owned(),
        UpdateState::Error { error, .. } => error.message.clone(),
    }
}

pub const STATE_LAST_SUCCESS_STABLE: &str = "updates.v1.last-success.stable";
pub const STATE_LAST_SUCCESS_DEV: &str = "updates.v1.last-success.dev";
pub const STATE_LAST_ATTEMPT_STABLE: &str = "updates.v1.last-attempt.stable";
pub const STATE_LAST_ATTEMPT_DEV: &str = "updates.v1.last-attempt.dev";
pub const STATE_BACKOFF_STABLE: &str = "updates.v1.backoff.stable";
pub const STATE_BACKOFF_DEV: &str = "updates.v1.backoff.dev";
pub const STATE_HTTP_STABLE: &str = "updates.v1.http.stable";
pub const STATE_HTTP_DEV: &str = "updates.v1.http.dev";
pub const STATE_STAGED: &str = "updates.v1.staged";
pub const STATE_LAST_RESULT: &str = "updates.v1.last-result";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpValidators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// The durable part of a staged update.  In particular, this record contains
/// no release notes, URL, local path, or credential.  The platform token is
/// opaque to the shared core and must be independently validated by the
/// adapter before installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedUpdateRecord {
    pub channel: UpdateChannel,
    pub version: String,
    pub revision: u64,
    pub commit: String,
    pub platform: Platform,
    pub architecture: Architecture,
    pub kind: AssetKind,
    pub byte_length: u64,
    pub sha256: String,
    pub platform_token: String,
}

impl StagedUpdateRecord {
    pub fn from_staged(staged: &StagedUpdate) -> Result<Self, UpdateError> {
        if staged.byte_length == 0
            || staged.byte_length > MAX_PACKAGE_SIZE
            || staged.byte_length != staged.candidate.asset.byte_length
            || staged.sha256 != staged.candidate.asset.sha256
            || !valid_sha256(&staged.sha256)
            || !candidate_asset_kind_allowed(
                staged.candidate.channel,
                staged.candidate.asset.platform,
                staged.candidate.asset.kind,
            )
            || staged.platform_token.is_empty()
            || staged.platform_token.len() > 4096
        {
            return Err(UpdateError::Storage(
                "staged update identity is invalid".to_owned(),
            ));
        }
        let commit = staged
            .candidate
            .commit
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        parse_hex::<20>(&commit, "commit")?;
        Ok(Self {
            channel: staged.candidate.channel,
            version: staged.candidate.version.to_string(),
            revision: staged.candidate.revision,
            commit,
            platform: staged.candidate.asset.platform,
            architecture: staged.candidate.asset.architecture,
            kind: staged.candidate.asset.kind,
            byte_length: staged.byte_length,
            sha256: staged.sha256.clone(),
            platform_token: staged.platform_token.clone(),
        })
    }

    pub fn validate(&self) -> Result<(), UpdateError> {
        Version::parse(&self.version)
            .map_err(|_| UpdateError::Recovery("staged version is invalid".to_owned()))?;
        parse_hex::<20>(&self.commit, "staged commit")?;
        if !candidate_asset_kind_allowed(self.channel, self.platform, self.kind) {
            return Err(UpdateError::Recovery(
                "staged package kind does not match its platform".to_owned(),
            ));
        }
        if self.byte_length == 0 || self.byte_length > MAX_PACKAGE_SIZE {
            return Err(UpdateError::Recovery("staged size is invalid".to_owned()));
        }
        if !valid_sha256(&self.sha256)
            || self.platform_token.is_empty()
            || self.platform_token.len() > 4096
        {
            return Err(UpdateError::Recovery(
                "staged identity is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateMachineState {
    pub schedule: ScheduleState,
    pub http: HashMap<UpdateChannel, HttpValidators>,
    pub staged: Option<StagedUpdateRecord>,
    pub last_result: Option<UpdateErrorSummary>,
}

impl UpdateMachineState {
    pub fn load(repository: &dyn AppStateRepository) -> Result<Self, UpdateError> {
        let schedule = ScheduleState::load(repository)?;
        let mut http = HashMap::new();
        for channel in [UpdateChannel::Stable, UpdateChannel::Dev] {
            let suffix = channel.as_str();
            let key = format!("updates.v1.http.{suffix}");
            let Some(raw) = repository
                .get_state(&key)
                .map_err(|error| UpdateError::Storage(error.to_string()))?
            else {
                continue;
            };
            match parse_strict_json::<HttpValidators>(raw.as_bytes()) {
                Ok(value) if validators_are_safe(&value) => {
                    http.insert(channel, value);
                }
                _ => {
                    repository
                        .delete_state(&key)
                        .map_err(|error| UpdateError::Storage(error.to_string()))?;
                }
            }
        }
        let staged = load_json_state(repository, STATE_STAGED, |raw| {
            let value = parse_strict_json::<StagedUpdateRecord>(raw.as_bytes())?;
            value.validate()?;
            Ok(value)
        })?;
        let last_result = load_json_state(repository, STATE_LAST_RESULT, |raw| {
            let value = parse_strict_json::<UpdateErrorSummary>(raw.as_bytes())?;
            if value.message.len() > 256 || value.message.chars().any(char::is_control) {
                return Err(UpdateError::Recovery(
                    "last update result is invalid".to_owned(),
                ));
            }
            Ok(value)
        })?;
        Ok(Self {
            schedule,
            http,
            staged,
            last_result,
        })
    }

    pub fn persist(&self, repository: &dyn AppStateRepository) -> Result<(), UpdateError> {
        if let Some(staged) = self.staged.as_ref() {
            staged.validate()?;
        }
        if let Some(result) = self.last_result.as_ref()
            && (result.message.len() > 256 || result.message.chars().any(char::is_control))
        {
            return Err(UpdateError::Storage(
                "last update result is invalid".to_owned(),
            ));
        }
        self.schedule.persist(repository)?;
        for channel in [UpdateChannel::Stable, UpdateChannel::Dev] {
            let key = format!("updates.v1.http.{}", channel.as_str());
            match self.http.get(&channel) {
                Some(value) if validators_are_safe(value) => {
                    let json = serde_json::to_string(value)
                        .map_err(|error| UpdateError::Storage(error.to_string()))?;
                    repository
                        .set_state(&key, &json)
                        .map_err(|error| UpdateError::Storage(error.to_string()))?;
                }
                _ => repository
                    .delete_state(&key)
                    .map_err(|error| UpdateError::Storage(error.to_string()))?,
            }
        }
        persist_json_state(repository, STATE_STAGED, self.staged.as_ref())?;
        persist_json_state(repository, STATE_LAST_RESULT, self.last_result.as_ref())?;
        Ok(())
    }

    pub fn clear_staged(&mut self, repository: &dyn AppStateRepository) -> Result<(), UpdateError> {
        self.staged = None;
        repository
            .delete_state(STATE_STAGED)
            .map_err(|error| UpdateError::Storage(error.to_string()))
    }
}

fn validators_are_safe(value: &HttpValidators) -> bool {
    value.etag.as_deref().is_none_or(valid_header_value)
        && value
            .last_modified
            .as_deref()
            .is_none_or(valid_header_value)
}

fn valid_header_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

fn load_json_state<T>(
    repository: &dyn AppStateRepository,
    key: &str,
    parse: impl FnOnce(&str) -> Result<T, UpdateError>,
) -> Result<Option<T>, UpdateError> {
    let Some(raw) = repository
        .get_state(key)
        .map_err(|error| UpdateError::Storage(error.to_string()))?
    else {
        return Ok(None);
    };
    match parse(&raw) {
        Ok(value) => Ok(Some(value)),
        Err(_) => {
            repository
                .delete_state(key)
                .map_err(|error| UpdateError::Storage(error.to_string()))?;
            Ok(None)
        }
    }
}

fn persist_json_state<T: Serialize>(
    repository: &dyn AppStateRepository,
    key: &str,
    value: Option<&T>,
) -> Result<(), UpdateError> {
    if let Some(value) = value {
        let json = serde_json::to_string(value)
            .map_err(|error| UpdateError::Storage(error.to_string()))?;
        repository
            .set_state(key, &json)
            .map_err(|error| UpdateError::Storage(error.to_string()))
    } else {
        repository
            .delete_state(key)
            .map_err(|error| UpdateError::Storage(error.to_string()))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScheduleState {
    pub last_success: HashMap<UpdateChannel, SystemTime>,
    pub last_attempt: HashMap<UpdateChannel, SystemTime>,
    pub backoff_step: HashMap<UpdateChannel, u8>,
    /// A channel change bypasses the previous channel's 24-hour result even
    /// when the same channel was used earlier in the process lifetime.
    pub forced: HashSet<UpdateChannel>,
}

impl ScheduleState {
    pub fn load(repository: &dyn AppStateRepository) -> Result<Self, UpdateError> {
        let mut state = Self::default();
        for channel in [UpdateChannel::Stable, UpdateChannel::Dev] {
            let suffix = match channel {
                UpdateChannel::Stable => "stable",
                UpdateChannel::Dev => "dev",
            };
            if let Some(value) =
                read_u64_state(repository, &format!("updates.v1.last-success.{suffix}"))?
            {
                if let Some(timestamp) = UNIX_EPOCH.checked_add(Duration::from_secs(value)) {
                    state.last_success.insert(channel, timestamp);
                } else {
                    repository
                        .delete_state(&format!("updates.v1.last-success.{suffix}"))
                        .map_err(|error| UpdateError::Storage(error.to_string()))?;
                }
            }
            if let Some(value) =
                read_u64_state(repository, &format!("updates.v1.last-attempt.{suffix}"))?
            {
                if let Some(timestamp) = UNIX_EPOCH.checked_add(Duration::from_secs(value)) {
                    state.last_attempt.insert(channel, timestamp);
                } else {
                    repository
                        .delete_state(&format!("updates.v1.last-attempt.{suffix}"))
                        .map_err(|error| UpdateError::Storage(error.to_string()))?;
                }
            }
            if let Some(value) =
                read_u64_state(repository, &format!("updates.v1.backoff.{suffix}"))?
            {
                if value <= 5 {
                    state.backoff_step.insert(channel, value as u8);
                } else {
                    repository
                        .delete_state(&format!("updates.v1.backoff.{suffix}"))
                        .map_err(|error| UpdateError::Storage(error.to_string()))?;
                }
            }
        }
        Ok(state)
    }

    pub fn persist(&self, repository: &dyn AppStateRepository) -> Result<(), UpdateError> {
        for channel in [UpdateChannel::Stable, UpdateChannel::Dev] {
            let suffix = match channel {
                UpdateChannel::Stable => "stable",
                UpdateChannel::Dev => "dev",
            };
            persist_optional_time(
                repository,
                &format!("updates.v1.last-success.{suffix}"),
                self.last_success.get(&channel),
            )?;
            persist_optional_time(
                repository,
                &format!("updates.v1.last-attempt.{suffix}"),
                self.last_attempt.get(&channel),
            )?;
            let step = self.backoff_step.get(&channel).copied().unwrap_or(0);
            if step > 5 {
                return Err(UpdateError::Storage(
                    "update backoff step is outside the supported range".to_owned(),
                ));
            }
            repository
                .set_state(&format!("updates.v1.backoff.{suffix}"), &step.to_string())
                .map_err(|error| UpdateError::Storage(error.to_string()))?;
        }
        Ok(())
    }

    #[must_use]
    pub fn eligible(&self, channel: UpdateChannel, now: SystemTime) -> bool {
        if self.forced.contains(&channel) {
            return true;
        }
        let step = self.backoff_step.get(&channel).copied().unwrap_or(0);
        if self.last_attempt.get(&channel).is_some_and(|attempt| {
            now.duration_since(*attempt).unwrap_or_default() < retry_delay(step)
        }) {
            return false;
        }
        let Some(last_success) = self.last_success.get(&channel) else {
            return true;
        };
        let age = now.duration_since(*last_success).unwrap_or_default();
        age >= CHECK_INTERVAL
    }

    pub fn record_attempt(&mut self, channel: UpdateChannel, at: SystemTime) {
        self.last_attempt.insert(channel, at);
    }

    pub fn record_success(&mut self, channel: UpdateChannel, at: SystemTime) {
        self.last_success.insert(channel, at);
        self.backoff_step.insert(channel, 0);
        self.forced.remove(&channel);
    }

    pub fn record_failure(&mut self, channel: UpdateChannel, at: SystemTime) {
        self.last_attempt.insert(channel, at);
        let step = self.backoff_step.get(&channel).copied().unwrap_or(0);
        self.backoff_step
            .insert(channel, step.saturating_add(1).min(5));
    }

    pub fn force_check(&mut self, channel: UpdateChannel) {
        self.forced.insert(channel);
    }
}

fn read_u64_state(
    repository: &dyn AppStateRepository,
    key: &str,
) -> Result<Option<u64>, UpdateError> {
    let value = repository
        .get_state(key)
        .map_err(|error| UpdateError::Storage(error.to_string()))?;
    let Some(value) = value else { return Ok(None) };
    match value.parse::<u64>() {
        Ok(value) => Ok(Some(value)),
        Err(_) => {
            repository
                .delete_state(key)
                .map_err(|error| UpdateError::Storage(error.to_string()))?;
            Ok(None)
        }
    }
}

fn persist_optional_time(
    repository: &dyn AppStateRepository,
    key: &str,
    value: Option<&SystemTime>,
) -> Result<(), UpdateError> {
    if let Some(value) = value {
        let seconds = value
            .duration_since(UNIX_EPOCH)
            .map_err(|_| UpdateError::Storage("timestamp predates Unix epoch".to_owned()))?
            .as_secs();
        repository
            .set_state(key, &seconds.to_string())
            .map_err(|error| UpdateError::Storage(error.to_string()))?;
    } else {
        repository
            .delete_state(key)
            .map_err(|error| UpdateError::Storage(error.to_string()))?;
    }
    Ok(())
}

fn retry_delay(step: u8) -> Duration {
    match step {
        0 => Duration::ZERO,
        1 => Duration::from_secs(60 * 60),
        2 => Duration::from_secs(2 * 60 * 60),
        3 => Duration::from_secs(4 * 60 * 60),
        4 => Duration::from_secs(8 * 60 * 60),
        _ => CHECK_INTERVAL,
    }
}

#[derive(Debug)]
pub struct UpdateHandle {
    commands: SyncSender<UpdateCommand>,
    events: Arc<Mutex<Receiver<UpdateEvent>>>,
}

impl Clone for UpdateHandle {
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
            events: Arc::clone(&self.events),
        }
    }
}

impl UpdateHandle {
    pub fn try_submit(&self, command: UpdateCommand) -> Result<(), UpdateError> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                TrySendError::Full(_) => {
                    UpdateError::Platform("update command queue is full".to_owned())
                }
                TrySendError::Disconnected(_) => {
                    UpdateError::Platform("update worker is stopped".to_owned())
                }
            })
    }

    pub fn try_check_now(&self) -> Result<(), UpdateError> {
        self.try_submit(UpdateCommand::CheckNow)
    }

    pub fn drain(&self, limit: usize) -> Vec<UpdateEvent> {
        let Ok(receiver) = self.events.lock() else {
            return Vec::new();
        };
        let mut events = Vec::new();
        for _ in 0..limit {
            match receiver.try_recv() {
                Ok(event) => events.push(event),
                Err(_) => break,
            }
        }
        events
    }
}

pub struct UpdateWorker {
    command: Option<SyncSender<UpdateCommand>>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for UpdateWorker {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UpdateWorker")
            .finish_non_exhaustive()
    }
}

impl UpdateWorker {
    pub fn spawn<B: UpdateBackend + 'static>(
        mut controller: UpdateController<B>,
    ) -> (UpdateHandle, Self) {
        let (command_tx, command_rx) = mpsc::sync_channel::<UpdateCommand>(64);
        let worker_command = command_tx.clone();
        let (event_tx, event_rx) = mpsc::sync_channel::<UpdateEvent>(128);
        let join = std::thread::Builder::new()
            .name("conman-update".to_owned())
            .spawn(move || {
                for initial in controller.drain_events(usize::MAX) {
                    let _ = event_tx.try_send(initial);
                }
                loop {
                    match command_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(UpdateCommand::Shutdown) => {
                            let _ = controller.dispatch(UpdateCommand::Shutdown);
                            break;
                        }
                        Ok(command) => {
                            let _ = controller.dispatch(command);
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                    controller.poll_backend();
                    for event in controller.drain_events(64) {
                        let _ = event_tx.try_send(event);
                    }
                }
            })
            .expect("failed to spawn update worker");
        (
            UpdateHandle {
                commands: command_tx,
                events: Arc::new(Mutex::new(event_rx)),
            },
            Self {
                command: Some(worker_command),
                join: Some(join),
            },
        )
    }
}

impl Drop for UpdateWorker {
    fn drop(&mut self) {
        if let Some(command) = self.command.take() {
            // Drop is the owner of the worker join. A blocking send here is
            // bounded by the 64-entry queue and lets the worker drain before
            // its join; a failed `try_send` would otherwise leave recv_timeout
            // looping forever while the worker's sender remains alive.
            let _ = command.send(UpdateCommand::Shutdown);
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Deterministic backend used by unit/UI tests and as a small contract
/// fixture for platform adapters.
#[derive(Debug, Default)]
pub struct FakeUpdateBackend {
    pub capabilities: BackendCapabilities,
    pub commands: Vec<BackendCommand>,
    events: VecDeque<BackendEvent>,
}

impl FakeUpdateBackend {
    #[must_use]
    pub fn new(capabilities: BackendCapabilities) -> Self {
        Self {
            capabilities,
            commands: Vec::new(),
            events: VecDeque::new(),
        }
    }

    pub fn push_event(&mut self, event: BackendEvent) {
        self.events.push_back(event);
    }
}

impl UpdateBackend for FakeUpdateBackend {
    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities
    }

    fn submit(&mut self, command: BackendCommand) -> Result<(), UpdateError> {
        self.commands.push(command);
        Ok(())
    }

    fn drain_events(&mut self) -> Vec<BackendEvent> {
        self.events.drain(..).collect()
    }

    fn shutdown(&mut self, _deadline: Instant) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct MemoryState(Mutex<HashMap<String, String>>);

    impl AppStateRepository for MemoryState {
        fn get_state(&self, key: &str) -> Result<Option<String>, cm_core::RepositoryError> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }

        fn set_state(&self, key: &str, value: &str) -> Result<(), cm_core::RepositoryError> {
            self.0
                .lock()
                .unwrap()
                .insert(key.to_owned(), value.to_owned());
            Ok(())
        }

        fn delete_state(&self, key: &str) -> Result<(), cm_core::RepositoryError> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
    }

    use ed25519_dalek::{Signer, SigningKey};

    const SECRET: [u8; 32] = [7; 32];

    fn manifest_json() -> Vec<u8> {
        serde_json::to_vec(&UpdateManifest {
            schema: 1,
            product: PRODUCT.to_owned(),
            repository: REPOSITORY.to_owned(),
            channel: UpdateChannel::Dev,
            release_tag: "dev".to_owned(),
            version: "0.1.0-dev.5+g0123456789".to_owned(),
            revision: 5,
            commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            published_at: "2026-09-01T12:00:00Z".to_owned(),
            minimum_updater_version: "0.1.0".to_owned(),
            assets: vec![ManifestAsset {
                platform: Platform::Linux,
                architecture: Architecture::X86_64,
                kind: AssetKind::LinuxAppimage,
                asset_name: "ConMan.AppImage".to_owned(),
                byte_length: 1,
                sha256: sha256_hex(&[0]),
            }],
        })
        .unwrap()
    }

    fn build() -> CurrentBuild {
        CurrentBuild {
            version: Version::parse("0.1.0-dev.4+g0000000000").unwrap(),
            commit: Some([0; 20]),
            revision: Some(4),
            dirty: false,
            platform: Platform::Linux,
            architecture: Architecture::X86_64,
            install: InstallContext::AppImage,
        }
    }

    #[test]
    fn manifest_rejects_duplicate_fields_and_unsafe_assets() {
        let duplicate = br#"{"schema":1,"schema":1}"#;
        assert!(UpdateManifest::parse(duplicate).is_err());
        let mut invalid = manifest_json();
        invalid = String::from_utf8(invalid)
            .unwrap()
            .replace("ConMan.AppImage", "../ConMan.AppImage")
            .into_bytes();
        assert!(UpdateManifest::parse(&invalid).is_err());
    }

    #[test]
    fn exact_manifest_bytes_are_signed_and_verified() {
        let bytes = manifest_json();
        let envelope = sign_manifest(&bytes, DEFAULT_MANIFEST_KEY_ID, SECRET);
        let key = SigningKey::from_bytes(&SECRET).verifying_key();
        let verified = verify_manifest(
            &bytes,
            envelope.as_bytes(),
            &[TrustedKey {
                key_id: DEFAULT_MANIFEST_KEY_ID.to_owned(),
                public_key: key.to_bytes(),
            }],
        )
        .unwrap();
        assert_eq!(verified.manifest_bytes, bytes);
        let mut altered = bytes.clone();
        altered.push(b' ');
        assert!(
            verify_manifest(
                &altered,
                envelope.as_bytes(),
                &[TrustedKey {
                    key_id: DEFAULT_MANIFEST_KEY_ID.to_owned(),
                    public_key: key.to_bytes(),
                }]
            )
            .is_err()
        );
    }

    #[test]
    fn candidate_ordering_uses_channel_rules() {
        let bytes = manifest_json();
        let manifest = UpdateManifest::parse(&bytes).unwrap();
        let verified = VerifiedManifest {
            manifest,
            manifest_bytes: bytes,
        };
        let candidate = select_candidate(
            &verified,
            &build(),
            UpdateChannel::Dev,
            "https://github.com/MarcoS0ft/ConMan/releases/tag/dev",
            &Version::parse("0.1.0").unwrap(),
        )
        .unwrap();
        assert_eq!(candidate.unwrap().revision, 5);
        assert!(
            select_candidate(
                &verified,
                &CurrentBuild {
                    revision: Some(5),
                    ..build()
                },
                UpdateChannel::Dev,
                "https://github.com/MarcoS0ft/ConMan/releases/tag/dev",
                &Version::parse("0.1.0").unwrap(),
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn stale_backend_events_are_ignored() {
        let backend = FakeUpdateBackend::new(BackendCapabilities {
            can_download: true,
            can_install: true,
            completion: CompletionAction::RestartToApply,
        });
        let mut controller = UpdateController::new(
            backend,
            build(),
            Version::parse("0.1.0").unwrap(),
            UpdatePreferences::default(),
        );
        let _ = controller.drain_events(usize::MAX);
        controller.dispatch(UpdateCommand::CheckNow).unwrap();
        controller.poll_backend();
        let candidate = UpdateCandidate {
            version: Version::parse("0.1.0-dev.5").unwrap(),
            revision: 5,
            commit: [1; 20],
            channel: UpdateChannel::Dev,
            release_tag: "dev".to_owned(),
            minimum_updater_version: Version::parse("0.1.0").unwrap(),
            asset: UpdateManifest::parse(&manifest_json())
                .unwrap()
                .assets
                .remove(0),
            release_url: "https://github.com/MarcoS0ft/ConMan".to_owned(),
        };
        controller
            .reduce_backend_event(BackendEvent::Candidate {
                generation: controller.generation(),
                candidate: candidate.clone(),
            })
            .unwrap();
        let state = controller.state().clone();
        controller
            .reduce_backend_event(BackendEvent::NoUpdate {
                generation: controller.generation().saturating_sub(1),
            })
            .unwrap();
        assert_eq!(*controller.state(), state);
    }

    #[test]
    fn github_url_policy_rejects_credentials_and_untrusted_redirects() {
        assert!(validate_github_url("https://api.github.com/repos/MarcoS0ft/ConMan", true).is_ok());
        assert!(validate_github_url("https://evil.example/file", false).is_err());
        assert!(validate_github_url("https://github.com@evil.example/file", false).is_err());
    }

    #[test]
    fn package_hash_and_length_are_pinned() {
        let mut manifest = UpdateManifest::parse(&manifest_json()).unwrap();
        let asset = manifest.assets.remove(0);
        assert!(verify_package(&[0], &asset).is_ok());
        assert!(verify_package(&[1], &asset).is_err());
        let mut verifier = PackageVerifier::new(&asset).unwrap();
        assert_eq!(verifier.update(&[]).unwrap(), 0);
        assert_eq!(verifier.update(&[0]).unwrap(), 1);
        assert!(verifier.finish().is_ok());
        let signature = SigningKey::from_bytes(&SECRET).sign(b"unused");
        assert_eq!(signature.to_bytes().len(), 64);
    }

    #[test]
    fn schedule_enforces_interval_and_exponential_retry() {
        let now = UNIX_EPOCH + Duration::from_secs(10_000);
        let mut schedule = ScheduleState::default();
        assert!(schedule.eligible(UpdateChannel::Stable, now));
        schedule.record_success(UpdateChannel::Stable, now);
        assert!(!schedule.eligible(
            UpdateChannel::Stable,
            now + CHECK_INTERVAL - Duration::from_secs(1)
        ));
        assert!(schedule.eligible(UpdateChannel::Stable, now + CHECK_INTERVAL));
        schedule.record_failure(UpdateChannel::Stable, now + CHECK_INTERVAL);
        assert_eq!(schedule.backoff_step[&UpdateChannel::Stable], 1);
        assert!(!schedule.eligible(
            UpdateChannel::Stable,
            now + CHECK_INTERVAL + Duration::from_secs(60 * 59)
        ));
        assert!(schedule.eligible(
            UpdateChannel::Stable,
            now + CHECK_INTERVAL + Duration::from_secs(60 * 60)
        ));
        schedule.force_check(UpdateChannel::Stable);
        assert!(schedule.eligible(UpdateChannel::Stable, now));
    }

    #[test]
    fn github_release_parser_ignores_unversioned_api_fields() {
        let json = br#"{
            "tag_name":"dev",
            "prerelease":true,
            "html_url":"https://github.com/MarcoS0ft/ConMan/releases/tag/dev",
            "assets":[
                {"name":"conman-update.json","browser_download_url":"https://github.com/MarcoS0ft/ConMan/releases/download/dev/conman-update.json","size":10,"id":1},
                {"name":"conman-update.json.sig","browser_download_url":"https://github.com/MarcoS0ft/ConMan/releases/download/dev/conman-update.json.sig","size":10,"uploader":{"login":"bot"}}
            ],
            "id":123,
            "target_commitish":"main"
        }"#;
        let release = GitHubRelease::parse(json).unwrap();
        assert!(release.is_channel(UpdateChannel::Dev));
        assert_eq!(release.asset(MANIFEST_ASSET_NAME).unwrap().size, 10);
    }

    #[test]
    fn machine_state_roundtrips_and_deletes_corrupt_staged_data() {
        let repository = MemoryState::default();
        let timestamp = UNIX_EPOCH + Duration::from_secs(10_000);
        let mut schedule = ScheduleState::default();
        schedule.record_success(UpdateChannel::Dev, timestamp);
        let state = UpdateMachineState {
            schedule,
            http: HashMap::from([(
                UpdateChannel::Dev,
                HttpValidators {
                    etag: Some("\"dev-1\"".to_owned()),
                    last_modified: None,
                },
            )]),
            staged: None,
            last_result: Some(UpdateError::Network("private detail".to_owned()).summary()),
        };
        state.persist(&repository).unwrap();
        let loaded = UpdateMachineState::load(&repository).unwrap();
        assert_eq!(loaded.schedule.last_success, state.schedule.last_success);
        assert_eq!(loaded.http, state.http);
        assert_eq!(loaded.last_result, state.last_result);

        repository
            .set_state(STATE_STAGED, r#"{"unexpected":true}"#)
            .unwrap();
        let recovered = UpdateMachineState::load(&repository).unwrap();
        assert!(recovered.staged.is_none());
        assert!(repository.get_state(STATE_STAGED).unwrap().is_none());
    }
}

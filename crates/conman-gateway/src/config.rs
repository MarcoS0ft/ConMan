use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;
use url::Url;

pub const CONFIG_VERSION: u32 = 1;
pub const DEFAULT_LISTEN_ADDRESSES: [&str; 2] = ["127.0.0.1:39080", "[::1]:39080"];
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
pub const MAX_PUBLIC_ASSETS: usize = 512;
pub const MAX_PUBLIC_ASSET_PATH_BYTES: usize = 1024;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration file is unavailable or unreadable")]
    Io(#[from] std::io::Error),
    #[error("configuration is malformed or contains unsupported fields")]
    Toml(#[from] toml::de::Error),
    #[error("configuration is invalid: {0}")]
    Invalid(&'static str),
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PublicAssetPolicyError {
    #[error("asset manifest exceeds its entry limit")]
    TooManyAssets,
    #[error("asset manifest contains a duplicate or invalid route path")]
    InvalidPath,
}

/// An exact public-route allowlist supplied by the later browser packaging slice.
/// This type validates policy only; it does not read or serve files.
#[derive(Debug, Clone)]
pub struct PublicAssetManifest {
    paths: HashSet<String>,
}

impl PublicAssetManifest {
    pub fn new<I, S>(paths: I) -> Result<Self, PublicAssetPolicyError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut allowed = HashSet::new();
        for item in paths {
            if allowed.len() >= MAX_PUBLIC_ASSETS {
                return Err(PublicAssetPolicyError::TooManyAssets);
            }
            let path = item.into();
            if !valid_asset_route_path(&path) || !allowed.insert(path) {
                return Err(PublicAssetPolicyError::InvalidPath);
            }
        }
        Ok(Self { paths: allowed })
    }

    pub fn allows_exact_path(&self, path: &str) -> bool {
        self.paths.contains(path)
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

fn valid_asset_route_path(path: &str) -> bool {
    if path.len() > MAX_PUBLIC_ASSET_PATH_BYTES || !path.starts_with('/') {
        return false;
    }
    if path == "/" {
        return true;
    }
    if path.bytes().any(|byte| {
        !(byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'~'))
    }) {
        return false;
    }
    path.split('/')
        .skip(1)
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    gateway_config_version: u32,
    workspace_dir: PathBuf,
    #[serde(default = "default_listen_addresses")]
    listen_addresses: Vec<String>,
    external_origin: String,
    owner_verifier_file: PathBuf,
}

fn default_listen_addresses() -> Vec<String> {
    DEFAULT_LISTEN_ADDRESSES
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub workspace_dir: PathBuf,
    pub listen_addresses: Vec<SocketAddr>,
    pub external_origin: String,
    pub external_authority: String,
    pub owner_verifier_file: PathBuf,
}

impl GatewayConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let metadata = fs::metadata(path)?;
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Invalid("config file exceeds size limit"));
        }
        let input = fs::read_to_string(path)?;
        Self::parse(&input)
    }

    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        if input.len() > MAX_CONFIG_BYTES as usize {
            return Err(ConfigError::Invalid("config file exceeds size limit"));
        }
        let raw: RawConfig = toml::from_str(input)?;
        if raw.gateway_config_version != CONFIG_VERSION {
            return Err(ConfigError::Invalid("unsupported config version"));
        }

        let workspace_dir = canonical_directory(&raw.workspace_dir)?;
        let owner_verifier_file = canonical_file(&raw.owner_verifier_file)?;
        validate_owner_only_file(&owner_verifier_file)?;

        let mut listen_addresses = Vec::with_capacity(raw.listen_addresses.len());
        let mut unique = HashSet::with_capacity(raw.listen_addresses.len());
        for candidate in raw.listen_addresses {
            let address = candidate
                .parse::<SocketAddr>()
                .map_err(|_| ConfigError::Invalid("listener must be a socket address"))?;
            if !address.ip().is_loopback() {
                return Err(ConfigError::Invalid(
                    "listeners must bind loopback addresses only",
                ));
            }
            if !unique.insert(address) {
                return Err(ConfigError::Invalid("duplicate listener address"));
            }
            listen_addresses.push(address);
        }
        if listen_addresses.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one loopback listener is required",
            ));
        }

        let (external_origin, external_authority) = canonical_https_origin(&raw.external_origin)?;
        Ok(Self {
            workspace_dir,
            listen_addresses,
            external_origin,
            external_authority,
            owner_verifier_file,
        })
    }

    pub fn host_is_allowed(&self, host: Option<&str>) -> bool {
        host == Some(self.external_authority.as_str())
    }

    pub fn origin_is_allowed(&self, origin: Option<&str>) -> bool {
        origin == Some(self.external_origin.as_str())
    }
}

fn canonical_directory(path: &Path) -> Result<PathBuf, ConfigError> {
    validate_absolute_normal_path(path)?;
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_dir() {
        return Err(ConfigError::Invalid("workspace_dir must be a directory"));
    }
    Ok(canonical)
}

fn canonical_file(path: &Path) -> Result<PathBuf, ConfigError> {
    validate_absolute_normal_path(path)?;
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_file() {
        return Err(ConfigError::Invalid(
            "owner_verifier_file must be a regular file",
        ));
    }
    Ok(canonical)
}

fn validate_absolute_normal_path(path: &Path) -> Result<(), ConfigError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(ConfigError::Invalid(
            "configured paths must be absolute and normalized",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_owner_only_file(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 || mode & 0o400 == 0 {
        return Err(ConfigError::Invalid(
            "verifier file must be owner-readable only",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_only_file(_path: &Path) -> Result<(), ConfigError> {
    // Platform ACL validation belongs to the packaging/platform adapter. The
    // helper still refuses non-file paths and never relaxes auth verification.
    Ok(())
}

fn canonical_https_origin(value: &str) -> Result<(String, String), ConfigError> {
    let parsed =
        Url::parse(value).map_err(|_| ConfigError::Invalid("external_origin is invalid"))?;
    if parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfigError::Invalid(
            "external_origin must be a root HTTPS origin",
        ));
    }
    let origin = parsed.origin().ascii_serialization();
    if origin != value {
        return Err(ConfigError::Invalid(
            "external_origin must use canonical origin spelling",
        ));
    }
    let authority = origin
        .strip_prefix("https://")
        .ok_or(ConfigError::Invalid("external_origin must be HTTPS"))?
        .to_owned();
    Ok((origin, authority))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: PathBuf,
        workspace: PathBuf,
        verifier: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!("conman-gateway-config-{id}"));
            let workspace = root.join("workspace");
            fs::create_dir_all(&workspace).expect("test fixture directory");
            let verifier = root.join("owner-verifier");
            fs::write(&verifier, "unused test verifier\n").expect("test verifier");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&verifier, fs::Permissions::from_mode(0o600))
                    .expect("test verifier permissions");
            }
            Self {
                root,
                workspace,
                verifier,
            }
        }

        fn config(&self, extra: &str) -> String {
            format!(
                r#"gateway_config_version = 1
workspace_dir = {:?}
external_origin = "https://connections.example.invalid"
owner_verifier_file = {:?}
{extra}"#,
                self.workspace, self.verifier
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn defaults_to_dual_loopback_and_exact_origin_authority() {
        let fixture = Fixture::new();
        let config = GatewayConfig::parse(&fixture.config("")).expect("valid config");
        assert_eq!(config.listen_addresses.len(), 2);
        assert!(
            config
                .listen_addresses
                .iter()
                .all(|addr| addr.ip().is_loopback())
        );
        assert_eq!(
            config.external_origin,
            "https://connections.example.invalid"
        );
        assert_eq!(config.external_authority, "connections.example.invalid");
        assert!(config.host_is_allowed(Some("connections.example.invalid")));
        assert!(!config.host_is_allowed(Some("evil.example.invalid")));
        assert!(config.origin_is_allowed(Some("https://connections.example.invalid")));
        assert!(!config.origin_is_allowed(Some("https://connections.example.invalid/")));
    }

    #[test]
    fn rejects_unknown_fields_wrong_version_empty_or_public_listeners() {
        let fixture = Fixture::new();
        assert!(GatewayConfig::parse(&fixture.config("unknown = true\n")).is_err());
        assert!(
            GatewayConfig::parse(
                &fixture
                    .config("")
                    .replace("gateway_config_version = 1", "gateway_config_version = 2")
            )
            .is_err()
        );
        assert!(GatewayConfig::parse(&fixture.config("listen_addresses = []\n")).is_err());
        assert!(
            GatewayConfig::parse(&fixture.config("listen_addresses = [\"0.0.0.0:39080\"]\n"))
                .is_err()
        );
    }

    #[test]
    fn public_assets_are_finite_exact_manifest_paths_without_fallback() {
        let manifest = PublicAssetManifest::new(["/", "/pkg/login.js", "/pkg/snippets/inline0.js"])
            .expect("safe allowlist");
        assert!(manifest.allows_exact_path("/pkg/login.js"));
        assert!(!manifest.allows_exact_path("/pkg/other.js"));
        assert!(!manifest.allows_exact_path("/pkg/"));
        for path in [
            "/../secret",
            "/pkg/../secret",
            "/pkg/%2e%2e/secret",
            "/pkg//file",
            "/pkg/a?x=1",
            "/pkg\\secret",
        ] {
            assert!(
                matches!(
                    PublicAssetManifest::new([path]),
                    Err(PublicAssetPolicyError::InvalidPath)
                ),
                "accepted {path}"
            );
        }
        let too_many = (0..=MAX_PUBLIC_ASSETS).map(|index| format!("/asset{index}.js"));
        assert!(matches!(
            PublicAssetManifest::new(too_many),
            Err(PublicAssetPolicyError::TooManyAssets)
        ));
    }

    #[test]
    fn rejects_noncanonical_origins_and_insecure_or_nonroot_urls() {
        let fixture = Fixture::new();
        for origin in [
            "http://connections.example.invalid",
            "https://CONNECTIONS.example.invalid",
            "https://connections.example.invalid/",
            "https://user@connections.example.invalid",
            "https://connections.example.invalid/path",
            "https://connections.example.invalid?x=1",
        ] {
            let input = fixture
                .config("")
                .replace("https://connections.example.invalid", origin);
            assert!(GatewayConfig::parse(&input).is_err(), "accepted {origin}");
        }
    }
}

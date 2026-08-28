//! Deterministic build identity for ConMan executables.
//!
//! The package build script derives the user-facing version from the Cargo
//! version and Git state. Consumers use [`BuildInfo::current`] rather than
//! duplicating Git or environment handling.

#[cfg(test)]
mod derive;

/// Identity embedded in the current executable at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildInfo {
    /// Canonical user-facing version.
    pub version: &'static str,
    /// Full Git object ID, absent when built outside a Git checkout.
    pub git_sha: Option<&'static str>,
    /// Monotonic commit count, absent when built outside a Git checkout.
    pub revision_count: Option<u64>,
    /// Whether tracked files differed from `HEAD` when the build ran.
    pub dirty: bool,
    /// Rust target triple used to compile this artifact.
    pub target: &'static str,
    /// Cargo profile used to compile this artifact.
    pub profile: &'static str,
}

impl BuildInfo {
    /// Returns the identity embedded by this crate's build script.
    #[must_use]
    pub fn current() -> Self {
        Self {
            version: env!("CONMAN_BUILD_VERSION"),
            git_sha: non_empty(option_env!("CONMAN_BUILD_GIT_SHA")),
            revision_count: parse_optional_u64(option_env!("CONMAN_BUILD_COMMIT_COUNT")),
            dirty: matches!(option_env!("CONMAN_BUILD_DIRTY"), Some("true")),
            target: env!("CONMAN_BUILD_TARGET"),
            profile: env!("CONMAN_BUILD_PROFILE"),
        }
    }
}

/// Returns the canonical version embedded in this build.
#[must_use]
pub const fn version() -> &'static str {
    env!("CONMAN_BUILD_VERSION")
}

fn non_empty(value: Option<&'static str>) -> Option<&'static str> {
    match value {
        Some("") | None => None,
        Some(value) => Some(value),
    }
}

fn parse_optional_u64(value: Option<&'static str>) -> Option<u64> {
    non_empty(value).and_then(|value| value.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_identity_is_internally_consistent() {
        let build = BuildInfo::current();
        assert_eq!(build.version, version());
        assert!(!build.version.is_empty());
        assert!(!build.target.is_empty());
        assert!(!build.profile.is_empty());
        assert_eq!(build.git_sha.is_some(), build.revision_count.is_some());
        if let Some(sha) = build.git_sha {
            assert_eq!(sha.len(), 40);
            assert!(sha.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
    }
}

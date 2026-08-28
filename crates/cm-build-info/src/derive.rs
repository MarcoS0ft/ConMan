//! Pure build-version derivation shared by the build script and its tests.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VersionInputs {
    pub(crate) base_version: String,
    pub(crate) override_version: Option<String>,
    pub(crate) full_sha: Option<String>,
    pub(crate) revision_count: Option<u64>,
    pub(crate) dirty: bool,
    pub(crate) tags_at_head: Vec<String>,
    pub(crate) release_profile: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedVersion {
    pub(crate) canonical: String,
    pub(crate) full_sha: Option<String>,
    pub(crate) revision_count: Option<u64>,
    pub(crate) dirty: bool,
}

pub(crate) fn resolve(inputs: VersionInputs) -> Result<ResolvedVersion, String> {
    if let Some(override_version) = inputs.override_version.as_deref()
        && !valid_semver(override_version)
    {
        return Err(
            "CONMAN_BUILD_VERSION must be one exact, single-line SemVer value (for example, \
             0.1.0 or 0.1.0-dev.312+gabc123)"
                .to_owned(),
        );
    }

    let semantic_tags = inputs
        .tags_at_head
        .iter()
        .filter_map(|tag| semantic_tag_version(tag))
        .collect::<Vec<_>>();

    if inputs.release_profile
        && semantic_tags
            .iter()
            .any(|version| *version != inputs.base_version)
    {
        return Err(format!(
            "release tag does not match Cargo package version {} (tags at HEAD: {})",
            inputs.base_version,
            semantic_tags.join(", ")
        ));
    }

    if let Some(override_version) = inputs.override_version.as_deref() {
        return Ok(ResolvedVersion {
            canonical: override_version.to_owned(),
            full_sha: inputs.full_sha,
            revision_count: inputs.revision_count,
            dirty: inputs.dirty,
        });
    }

    let is_exact_release = !inputs.dirty && semantic_tags.contains(&inputs.base_version);
    let canonical = if is_exact_release {
        inputs.base_version
    } else if let (Some(full_sha), Some(revision_count)) =
        (inputs.full_sha.as_deref(), inputs.revision_count)
    {
        let short_sha = &full_sha[..full_sha.len().min(10)];
        let dirty_suffix = if inputs.dirty { ".dirty" } else { "" };
        format!(
            "{}-dev.{revision_count}+g{short_sha}{dirty_suffix}",
            inputs.base_version
        )
    } else {
        format!("{}-dev.unknown", inputs.base_version)
    };

    Ok(ResolvedVersion {
        canonical,
        full_sha: inputs.full_sha,
        revision_count: inputs.revision_count,
        dirty: inputs.dirty,
    })
}

/// Validates the SemVer 2.0.0 grammar without normalizing the supplied value.
/// The exact validated string is embedded in the executable.
fn valid_semver(version: &str) -> bool {
    let (version_and_pre, build) = match version.split_once('+') {
        Some((left, right)) => (left, Some(right)),
        None => (version, None),
    };
    if build.is_some_and(|identifiers| !valid_identifiers(identifiers, true)) {
        return false;
    }

    let (core, pre) = match version_and_pre.split_once('-') {
        Some((left, right)) => (left, Some(right)),
        None => (version_and_pre, None),
    };
    if pre.is_some_and(|identifiers| !valid_identifiers(identifiers, false)) {
        return false;
    }

    let mut components = core.split('.');
    let Some(major) = components.next() else {
        return false;
    };
    let Some(minor) = components.next() else {
        return false;
    };
    let Some(patch) = components.next() else {
        return false;
    };
    components.next().is_none()
        && valid_numeric_component(major)
        && valid_numeric_component(minor)
        && valid_numeric_component(patch)
}

fn valid_identifiers(identifiers: &str, allow_numeric_leading_zeroes: bool) -> bool {
    identifiers.split('.').all(|identifier| {
        !identifier.is_empty()
            && identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && (allow_numeric_leading_zeroes
                || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                || valid_numeric_component(identifier))
    })
}

fn semantic_tag_version(tag: &str) -> Option<String> {
    let version = tag.strip_prefix('v')?;
    let mut parts = version.split('.');
    let major = parts.next()?;
    let minor = parts.next()?;
    let patch = parts.next()?;
    if parts.next().is_some()
        || !valid_numeric_component(major)
        || !valid_numeric_component(minor)
        || !valid_numeric_component(patch)
    {
        return None;
    }
    Some(version.to_owned())
}

fn valid_numeric_component(component: &str) -> bool {
    !component.is_empty()
        && component.bytes().all(|byte| byte.is_ascii_digit())
        && (component == "0" || !component.starts_with('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> VersionInputs {
        VersionInputs {
            base_version: "0.1.0".to_owned(),
            override_version: None,
            full_sha: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            revision_count: Some(311),
            dirty: false,
            tags_at_head: Vec::new(),
            release_profile: false,
        }
    }

    #[test]
    fn clean_matching_semver_tag_is_the_release_version() {
        let mut case = inputs();
        case.tags_at_head = vec!["dev".to_owned(), "v0.1.0".to_owned()];
        assert_eq!(resolve(case).unwrap().canonical, "0.1.0");
    }

    #[test]
    fn rolling_dev_and_non_semver_tags_are_ignored() {
        let mut case = inputs();
        case.tags_at_head = vec!["dev".to_owned(), "nightly".to_owned()];
        assert_eq!(
            resolve(case).unwrap().canonical,
            "0.1.0-dev.311+g0123456789"
        );
    }

    #[test]
    fn dirty_exact_tag_is_a_development_version() {
        let mut case = inputs();
        case.tags_at_head = vec!["v0.1.0".to_owned()];
        case.dirty = true;
        assert_eq!(
            resolve(case).unwrap().canonical,
            "0.1.0-dev.311+g0123456789.dirty"
        );
    }

    #[test]
    fn source_archive_without_git_has_an_unknown_revision() {
        let mut case = inputs();
        case.full_sha = None;
        case.revision_count = None;
        assert_eq!(resolve(case).unwrap().canonical, "0.1.0-dev.unknown");
    }

    #[test]
    fn explicit_override_wins_version_derivation() {
        let mut case = inputs();
        case.override_version = Some("1.2.3-rc.1+packager.004".to_owned());
        assert_eq!(resolve(case).unwrap().canonical, "1.2.3-rc.1+packager.004");
    }

    #[test]
    fn override_must_be_exact_single_line_semver() {
        for invalid in [
            "",
            " 1.2.3",
            "1.2.3 ",
            "v1.2.3",
            "01.2.3",
            "1.2.3-01",
            "1.2.3-",
            "1.2.3+",
            "1.2.3\ncargo:warning=injected",
        ] {
            let mut case = inputs();
            case.override_version = Some(invalid.to_owned());
            assert!(
                resolve(case).is_err(),
                "override {invalid:?} must be rejected"
            );
        }
    }

    #[test]
    fn release_profile_rejects_a_mismatched_semver_tag() {
        let mut case = inputs();
        case.release_profile = true;
        case.tags_at_head = vec!["v0.2.0".to_owned()];
        assert_eq!(
            resolve(case).unwrap_err(),
            "release tag does not match Cargo package version 0.1.0 (tags at HEAD: 0.2.0)"
        );
    }

    #[test]
    fn semver_like_prerelease_tag_is_not_a_release_tag() {
        let mut case = inputs();
        case.tags_at_head = vec!["v0.1.0-rc.1".to_owned()];
        assert_eq!(
            resolve(case).unwrap().canonical,
            "0.1.0-dev.311+g0123456789"
        );
    }
}

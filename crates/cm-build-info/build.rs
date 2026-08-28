mod build_support;
#[path = "src/derive.rs"]
mod derive;

use std::path::{Path, PathBuf};

use build_support::RepositorySnapshot;
use derive::{ResolvedVersion, VersionInputs};

const VERSION_OVERRIDE_ENV: &str = "CONMAN_BUILD_VERSION";

fn main() {
    println!("cargo:rerun-if-env-changed={VERSION_OVERRIDE_ENV}");

    let manifest_dir = PathBuf::from(required_env("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir
        .ancestors()
        .nth(2)
        .expect("cm-build-info must remain under <workspace>/crates")
        .to_path_buf();
    register_git_inputs(&workspace);

    let repository = RepositorySnapshot::read(&workspace);

    let resolved = derive::resolve(VersionInputs {
        base_version: required_env("CARGO_PKG_VERSION"),
        override_version: std::env::var(VERSION_OVERRIDE_ENV).ok(),
        full_sha: repository.full_sha,
        revision_count: repository.revision_count,
        dirty: repository.dirty,
        tags_at_head: repository.tags_at_head,
        release_profile: required_env("PROFILE") == "release",
    })
    .unwrap_or_else(|error| panic!("invalid ConMan build identity: {error}"));

    emit_metadata(&resolved, &required_env("TARGET"), &required_env("PROFILE"));
}

fn register_git_inputs(workspace: &Path) {
    for path in build_support::rerun_paths(workspace) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn emit_metadata(resolved: &ResolvedVersion, target: &str, profile: &str) {
    println!(
        "cargo:rustc-env=CONMAN_BUILD_VERSION={}",
        resolved.canonical
    );
    println!(
        "cargo:rustc-env=CONMAN_BUILD_GIT_SHA={}",
        resolved.full_sha.as_deref().unwrap_or_default()
    );
    println!(
        "cargo:rustc-env=CONMAN_BUILD_COMMIT_COUNT={}",
        resolved
            .revision_count
            .map(|count| count.to_string())
            .unwrap_or_default()
    );
    println!("cargo:rustc-env=CONMAN_BUILD_DIRTY={}", resolved.dirty);
    println!("cargo:rustc-env=CONMAN_BUILD_TARGET={target}");
    println!("cargo:rustc-env=CONMAN_BUILD_PROFILE={profile}");
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("Cargo did not set {name}"))
}

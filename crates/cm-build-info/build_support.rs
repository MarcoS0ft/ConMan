//! Git repository inspection used exclusively while compiling `cm-build-info`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Workspace roots that can gain new product inputs without modifying an
/// already-tracked file. Watching the directories makes Cargo rerun the build
/// script when, for example, a new icon or Rust module is created.
///
/// `target`, `tmp`, `.zig`, and `docs/devel` are intentionally absent. Git's
/// exclude rules remain the source of truth for whether a repository is dirty.
const PRODUCT_INPUT_ROOTS: &[&str] = &[
    ".cargo",
    ".github",
    "crates",
    "resources",
    "scripts",
    "vendor",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepositorySnapshot {
    pub(crate) full_sha: Option<String>,
    pub(crate) revision_count: Option<u64>,
    pub(crate) dirty: bool,
    pub(crate) tags_at_head: Vec<String>,
}

impl RepositorySnapshot {
    pub(crate) fn read(workspace: &Path) -> Self {
        Self {
            full_sha: git_text(workspace, &["rev-parse", "HEAD"]),
            revision_count: git_text(workspace, &["rev-list", "--count", "HEAD"])
                .and_then(|count| count.parse().ok()),
            // Git status includes untracked, non-ignored files by default. This
            // is important for newly added product resources while naturally
            // excluding target/ and docs/devel/ via .gitignore.
            dirty: git_text(
                workspace,
                &["status", "--porcelain=v1", "--untracked-files=normal"],
            )
            .is_some_and(|status| !status.is_empty()),
            tags_at_head: git_text(workspace, &["tag", "--points-at", "HEAD"])
                .map(|tags| tags.lines().map(str::to_owned).collect())
                .unwrap_or_default(),
        }
    }
}

/// Files and directories whose changes can alter the embedded build identity.
pub(crate) fn rerun_paths(workspace: &Path) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    paths.insert(workspace.join("Cargo.toml"));
    paths.insert(workspace.join("Cargo.lock"));

    // Every currently tracked or untracked-but-not-ignored file is watched
    // explicitly. This catches ordinary unstaged edits, deletions, and changes
    // outside the cm-build-info package itself.
    if let Some(files) = git_bytes(
        workspace,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    ) {
        for relative in files
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
        {
            paths.insert(workspace.join(String::from_utf8_lossy(relative).as_ref()));
        }
    }

    // Directory watches detect brand-new files which were not present when
    // the previous build-script fingerprint was generated.
    for root in PRODUCT_INPUT_ROOTS {
        let path = workspace.join(root);
        if path.is_dir() {
            paths.insert(path);
        }
    }

    // `--git-path` accounts for both the per-worktree Git directory (HEAD,
    // index) and the common Git directory (branches, tags, packed refs).
    // Watching refs/tags is what makes `git tag vX.Y.Z` turn an already-built
    // development artifact into an exact release build on the next Cargo run.
    for relative in ["HEAD", "index", "packed-refs", "refs", "refs/tags"] {
        if let Some(path) = git_path(workspace, relative)
            && path.exists()
        {
            paths.insert(path);
        }
    }
    if let Some(symbolic_head) = git_text(workspace, &["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git_path(workspace, &symbolic_head)
        && path.exists()
    {
        paths.insert(path);
    }

    paths.into_iter().collect()
}

fn git_path(workspace: &Path, relative: &str) -> Option<PathBuf> {
    let path = PathBuf::from(git_text(
        workspace,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            relative,
        ],
    )?);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(workspace.join(path))
    }
}

fn git_text(workspace: &Path, args: &[&str]) -> Option<String> {
    let output = git_bytes(workspace, args)?;
    String::from_utf8(output)
        .ok()
        .map(|value| value.trim().to_owned())
}

fn git_bytes(workspace: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let output = Command::new("git")
        .args(args)
        .current_dir(workspace)
        .output()
        .ok()?;
    output.status.success().then_some(output.stdout)
}

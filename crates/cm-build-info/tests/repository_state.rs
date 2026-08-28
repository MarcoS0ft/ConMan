#[path = "../build_support.rs"]
mod build_support;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use build_support::RepositorySnapshot;

#[test]
fn git_dirty_state_and_rerun_inputs_include_untracked_product_files() {
    let repo = TempRepository::new();
    repo.write(".gitignore", "/target/\ndocs/devel/\n");
    repo.write("crates/example/src/lib.rs", "pub fn value() -> u8 { 1 }\n");
    fs::create_dir_all(repo.path().join("resources")).expect("create resources directory");
    repo.git(&["add", "."]);
    repo.git(&["commit", "-qm", "initial"]);

    assert!(!RepositorySnapshot::read(repo.path()).dirty);

    repo.write("crates/example/src/lib.rs", "pub fn value() -> u8 { 2 }\n");
    assert!(RepositorySnapshot::read(repo.path()).dirty);
    repo.git(&["restore", "crates/example/src/lib.rs"]);

    // Ignored development/build artifacts never mark the embedded identity as
    // dirty, even though they exist in the workspace.
    repo.write("target/debug/artifact", "build output");
    repo.write("docs/devel/private-note.md", "ignored note");
    assert!(!RepositorySnapshot::read(repo.path()).dirty);

    // A new, non-ignored product resource does mark the repository dirty. The
    // resource root is itself watched, so creating this file invalidates the
    // previous Cargo build-script fingerprint.
    repo.write("resources/new-icon.ico", "icon bytes");
    assert!(RepositorySnapshot::read(repo.path()).dirty);
    let watched = build_support::rerun_paths(repo.path());
    assert!(watched.contains(&repo.path().join("resources")));
    assert!(watched.contains(&repo.path().join("resources/new-icon.ico")));
    assert!(!watched.contains(&repo.path().join("target/debug/artifact")));
    assert!(!watched.contains(&repo.path().join("docs/devel/private-note.md")));
}

#[test]
fn cargo_reembeds_dirty_state_after_tracked_and_new_resource_changes() {
    let repo = TempRepository::new();
    repo.write(".gitignore", "/target/\ndocs/devel/\n");
    repo.write(
        "Cargo.toml",
        "[workspace]\nresolver = \"3\"\nmembers = [\"app\", \"crates/cm-build-info\"]\n\
         [workspace.package]\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    );
    repo.write(
        "crates/cm-build-info/Cargo.toml",
        "[package]\nname = \"cm-build-info\"\nversion.workspace = true\n\
         edition.workspace = true\nbuild = \"build.rs\"\n",
    );
    repo.write("crates/cm-build-info/build.rs", include_str!("../build.rs"));
    repo.write(
        "crates/cm-build-info/build_support.rs",
        include_str!("../build_support.rs"),
    );
    repo.write(
        "crates/cm-build-info/src/derive.rs",
        include_str!("../src/derive.rs"),
    );
    repo.write(
        "crates/cm-build-info/src/lib.rs",
        "pub const fn version() -> &'static str { env!(\"CONMAN_BUILD_VERSION\") }\n",
    );
    repo.write(
        "app/Cargo.toml",
        "[package]\nname = \"fixture-app\"\nversion.workspace = true\n\
         edition.workspace = true\n[dependencies]\ncm-build-info = { path = \"../crates/cm-build-info\" }\n",
    );
    repo.write(
        "app/src/main.rs",
        "fn main() { println!(\"{}\", cm_build_info::version()); }\n",
    );
    repo.write("resources/brand.txt", "tracked brand\n");
    repo.cargo(&["generate-lockfile"]);
    repo.git(&["add", "."]);
    repo.git(&["commit", "-qm", "fixture"]);

    let clean = repo.cargo(&["run", "-q", "-p", "fixture-app"]);
    assert!(clean.starts_with("0.1.0-dev.1+g"), "{clean}");
    assert!(!clean.contains(".dirty"), "{clean}");

    // Creating an exact release tag changes no source or index file. The Git
    // tag-ref watcher must nevertheless rerun the build script and replace the
    // already-built development identity.
    repo.git(&["tag", "v0.1.0"]);
    let tagged = repo.cargo(&["run", "-q", "-p", "fixture-app"]);
    assert_eq!(tagged, "0.1.0");
    repo.git(&["tag", "-d", "v0.1.0"]);
    let untagged = repo.cargo(&["run", "-q", "-p", "fixture-app"]);
    assert!(untagged.starts_with("0.1.0-dev.1+g"), "{untagged}");

    repo.write("resources/brand.txt", "modified tracked brand\n");
    let tracked_dirty = repo.cargo(&["run", "-q", "-p", "fixture-app"]);
    assert!(tracked_dirty.ends_with(".dirty"), "{tracked_dirty}");

    repo.git(&["restore", "resources/brand.txt"]);
    let restored = repo.cargo(&["run", "-q", "-p", "fixture-app"]);
    assert!(!restored.contains(".dirty"), "{restored}");

    repo.write("resources/new-icon.ico", "new untracked product input");
    let untracked_dirty = repo.cargo(&["run", "-q", "-p", "fixture-app"]);
    assert!(untracked_dirty.ends_with(".dirty"), "{untracked_dirty}");
}

#[test]
fn linked_worktree_watches_per_worktree_and_common_git_paths() {
    let repo = TempRepository::new();
    repo.write(".gitignore", "/target/\n");
    repo.write("crates/example/src/lib.rs", "pub fn value() {}\n");
    repo.git(&["add", "."]);
    repo.git(&["commit", "-qm", "initial"]);
    repo.git(&["tag", "v0.1.0"]);

    let linked = LinkedWorktree::add(&repo);
    let watched = build_support::rerun_paths(linked.path());
    let linked_head = linked.git_path("HEAD");
    let linked_index = linked.git_path("index");
    let common_tags = linked.git_path("refs/tags");
    let common_refs = linked.git_path("refs");
    let linked_branch = linked.git_path("refs/heads/conman-build-info-linked");
    let canonical_common_git =
        fs::canonicalize(repo.path().join(".git")).expect("canonicalize common Git directory");
    let canonical_common_tags =
        fs::canonicalize(&common_tags).expect("canonicalize common tag refs");
    let canonical_linked_branch =
        fs::canonicalize(&linked_branch).expect("canonicalize linked branch ref");

    assert!(watched.contains(&linked_head));
    assert!(watched.contains(&linked_index));
    assert!(watched.contains(&common_tags));
    assert!(watched.contains(&common_refs));
    assert!(watched.contains(&linked_branch));
    assert!(
        canonical_common_tags.starts_with(&canonical_common_git),
        "tag refs must resolve through the common Git directory: {}",
        common_tags.display()
    );
    assert_ne!(
        linked_head,
        repo.path().join(".git/HEAD"),
        "linked HEAD must be watched in the per-worktree Git directory"
    );
    assert!(
        canonical_linked_branch.starts_with(&canonical_common_git),
        "linked branch ref must resolve through the common Git directory: {}",
        linked_branch.display()
    );
}

struct TempRepository {
    path: PathBuf,
}

impl TempRepository {
    fn new() -> Self {
        let path = unique_temp_path("conman-build-info-test");
        fs::create_dir_all(&path).expect("create temporary repository");
        let path = fs::canonicalize(path).expect("canonicalize temporary repository");
        let repo = Self { path };
        repo.git(&["init", "-q"]);
        repo.git(&["config", "user.email", "build-info-test@conman.invalid"]);
        repo.git(&["config", "user.name", "ConMan Build Test"]);
        repo
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.path.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create test input parent");
        }
        fs::write(path, contents).expect("write test input");
    }

    fn git(&self, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(&self.path)
            .status()
            .expect("run git");
        assert!(status.success(), "git {args:?} failed with {status}");
    }

    fn cargo(&self, args: &[&str]) -> String {
        let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .args(args)
            // The parent package intentionally exposes its embedded override
            // to its own test process; the isolated fixture must derive from
            // its temporary Git repository instead.
            .env_remove("CONMAN_BUILD_VERSION")
            .current_dir(&self.path)
            .output()
            .expect("run cargo in fixture repository");
        assert!(
            output.status.success(),
            "cargo {args:?} failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("fixture cargo stdout is UTF-8")
            .trim()
            .to_owned()
    }
}

impl Drop for TempRepository {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct LinkedWorktree<'a> {
    owner: &'a TempRepository,
    path: PathBuf,
}

impl<'a> LinkedWorktree<'a> {
    fn add(owner: &'a TempRepository) -> Self {
        let path = unique_temp_path("conman-build-info-linked");
        let path_arg = path.to_str().expect("temporary path is Unicode");
        owner.git(&[
            "worktree",
            "add",
            "-b",
            "conman-build-info-linked",
            "-q",
            path_arg,
            "HEAD",
        ]);
        let path = fs::canonicalize(path).expect("canonicalize linked worktree");
        Self { owner, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn git_path(&self, relative: &str) -> PathBuf {
        let output = Command::new("git")
            .args([
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                relative,
            ])
            .current_dir(&self.path)
            .output()
            .expect("resolve linked-worktree Git path");
        assert!(output.status.success());
        PathBuf::from(
            String::from_utf8(output.stdout)
                .expect("Git path is UTF-8")
                .trim(),
        )
    }
}

impl Drop for LinkedWorktree<'_> {
    fn drop(&mut self) {
        if let Some(path) = self.path.to_str() {
            let _ = Command::new("git")
                .args(["worktree", "remove", "--force", path])
                .current_dir(self.owner.path())
                .status();
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{timestamp}-{sequence}",
        std::process::id()
    ))
}

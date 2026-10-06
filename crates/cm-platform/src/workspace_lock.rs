//! Exclusive cross-process ownership of one canonical ConMan workspace.
//!
//! The persistent lock file is never removed. Kernel ownership is held by the
//! opened file handle and is released when its owner drops that handle.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

/// Failure to establish exclusive ownership of a workspace.
#[derive(Debug)]
pub enum WorkspaceLockError {
    /// The caller did not provide the canonical path of an existing directory.
    NonCanonicalWorkspace,
    /// The selected path is not an existing directory.
    NotDirectory,
    /// A different process already holds the workspace lock.
    AlreadyOwned,
    /// A workspace-private or lock path is a symlink/reparse point or has an
    /// unexpected filesystem type.
    UnsafePath(io::Error),
    /// An operating-system operation failed while preparing/acquiring lock.
    Io(io::Error),
}

impl std::fmt::Display for WorkspaceLockError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonCanonicalWorkspace => formatter.write_str("workspace path must be canonical"),
            Self::NotDirectory => formatter.write_str("workspace is not an existing directory"),
            Self::AlreadyOwned => formatter.write_str("workspace is already owned"),
            Self::UnsafePath(error) => write!(formatter, "unsafe workspace lock path: {error}"),
            Self::Io(error) => write!(formatter, "workspace lock I/O failed: {error}"),
        }
    }
}

impl std::error::Error for WorkspaceLockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnsafePath(error) | Self::Io(error) => Some(error),
            Self::NonCanonicalWorkspace | Self::NotDirectory | Self::AlreadyOwned => None,
        }
    }
}

/// RAII owner for `<canonical-workspace>/.conman/workspace.lock`.
#[derive(Debug)]
pub struct WorkspaceGuard {
    _file: File,
    workspace: PathBuf,
}

impl WorkspaceGuard {
    /// Acquire an exclusive advisory lock for a canonical, existing directory.
    ///
    /// The `.conman` directory uses owner-only mode on Unix and inherits the
    /// canonical workspace ACL on Windows. The host selects a private workspace.
    /// Existing symlinks/reparse points and non-directory paths are
    /// rejected. The lock file is opened with `cm-platform`'s existing safe
    /// lock-file primitives before using the standard-library file lock.
    pub fn acquire(canonical_workspace: &Path) -> Result<Self, WorkspaceLockError> {
        let canonical = fs::canonicalize(canonical_workspace).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                WorkspaceLockError::NotDirectory
            } else {
                WorkspaceLockError::Io(error)
            }
        })?;
        if canonical != canonical_workspace {
            return Err(WorkspaceLockError::NonCanonicalWorkspace);
        }
        if !fs::metadata(&canonical)
            .map_err(WorkspaceLockError::Io)?
            .is_dir()
        {
            return Err(WorkspaceLockError::NotDirectory);
        }

        let private_dir = canonical.join(".conman");
        match fs::create_dir(&private_dir) {
            Ok(()) => set_private_dir_permissions(&private_dir).map_err(WorkspaceLockError::Io)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                validate_private_dir(&private_dir)?;
                set_private_dir_permissions(&private_dir).map_err(WorkspaceLockError::Io)?;
            }
            Err(error) => return Err(WorkspaceLockError::Io(error)),
        }
        validate_private_dir(&private_dir)?;

        let lock_path = private_dir.join("workspace.lock");
        let file =
            crate::safe_lock::open_lock_file(&lock_path).map_err(WorkspaceLockError::UnsafePath)?;
        match file.try_lock() {
            Ok(()) => Ok(Self {
                _file: file,
                workspace: canonical,
            }),
            Err(std::fs::TryLockError::WouldBlock) => Err(WorkspaceLockError::AlreadyOwned),
            Err(std::fs::TryLockError::Error(error)) => Err(WorkspaceLockError::Io(error)),
        }
    }

    /// Canonical workspace directory held by this guard.
    #[must_use]
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }
}

fn validate_private_dir(path: &Path) -> Result<(), WorkspaceLockError> {
    let metadata = fs::symlink_metadata(path).map_err(WorkspaceLockError::Io)?;
    let is_reparse_point = metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata);
    if is_reparse_point {
        return Err(WorkspaceLockError::UnsafePath(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workspace .conman path is a symlink",
        )));
    }
    if !metadata.is_dir() {
        return Err(WorkspaceLockError::UnsafePath(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workspace .conman path is not a directory",
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cm-platform-workspace-lock-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("unique temporary directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn lock_is_exclusive_and_persistent_file_is_reused_after_release() {
        let workspace = TempDir::new();
        let canonical = fs::canonicalize(workspace.path()).unwrap();

        let guard = WorkspaceGuard::acquire(&canonical).unwrap();
        assert_eq!(guard.workspace(), canonical);
        let lock_path = canonical.join(".conman/workspace.lock");
        assert!(lock_path.is_file());
        assert!(matches!(
            WorkspaceGuard::acquire(&canonical),
            Err(WorkspaceLockError::AlreadyOwned)
        ));

        drop(guard);
        let next = WorkspaceGuard::acquire(&canonical).unwrap();
        assert!(lock_path.is_file());
        drop(next);
        assert!(lock_path.is_file());
    }

    #[test]
    fn rejects_noncanonical_workspace_path() {
        let workspace = TempDir::new();
        let child = workspace.path().join("child");
        fs::create_dir(&child).unwrap();
        let alias = child.join("..");
        assert!(matches!(
            WorkspaceGuard::acquire(&alias),
            Err(WorkspaceLockError::NonCanonicalWorkspace)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_private_directory_and_lock_file() {
        use std::os::unix::fs::symlink;

        let workspace = TempDir::new();
        let canonical = fs::canonicalize(workspace.path()).unwrap();
        let other = TempDir::new();
        symlink(other.path(), canonical.join(".conman")).unwrap();
        assert!(matches!(
            WorkspaceGuard::acquire(&canonical),
            Err(WorkspaceLockError::UnsafePath(_))
        ));

        fs::remove_file(canonical.join(".conman")).unwrap();
        fs::create_dir(canonical.join(".conman")).unwrap();
        symlink(
            other.path().join("victim"),
            canonical.join(".conman/workspace.lock"),
        )
        .unwrap();
        assert!(matches!(
            WorkspaceGuard::acquire(&canonical),
            Err(WorkspaceLockError::UnsafePath(_))
        ));
        assert!(!other.path().join("victim").exists());
    }
}

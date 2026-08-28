//! Secure temporary storage used by RDP clipboard file transfer.

#![allow(unsafe_code)]

use std::path::{Path, PathBuf};

const STALE_PROCESS_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
const STARTUP_ENTRY_BUDGET: usize = 4096;

/// Failure to establish or use ConMan's private clipboard staging root.
#[derive(Debug, thiserror::Error)]
pub enum SecureTempError {
    #[error("temporary directory is unavailable")]
    Unavailable,
    #[error("clipboard staging component is not a private owned directory")]
    UnsafeComponent,
    #[error("clipboard staging I/O failed")]
    Io(#[from] std::io::Error),
}

#[derive(Debug)]
struct SecureClipboardRootInner {
    path: PathBuf,
    #[cfg(any(unix, windows))]
    directory: std::fs::File,
    #[cfg(windows)]
    identity: WindowsFileIdentity,
}

/// Validated, process-private root for all CLIPRDR staging.
#[derive(Clone, Debug)]
pub struct SecureClipboardRoot(std::sync::Arc<SecureClipboardRootInner>);

/// Retained handle to one flat transfer directory below the validated root.
#[derive(Debug)]
pub struct SecureStagingDirectory {
    path: PathBuf,
    #[cfg(any(unix, windows))]
    directory: std::fs::File,
    #[cfg(windows)]
    identity: WindowsFileIdentity,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowsFileIdentity {
    volume: u32,
    index: u64,
}

impl SecureStagingDirectory {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Atomically create one private regular file without following links.
    pub fn create_new_file(&self, name: &str) -> Result<std::fs::File, SecureTempError> {
        validate_component(name)?;
        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::os::fd::{AsRawFd as _, FromRawFd as _};
            let name = CString::new(name).map_err(|_| SecureTempError::UnsafeComponent)?;
            // SAFETY: the retained fd is a validated private directory and
            // `name` is exactly one NUL-free component.
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: `openat` returned one newly-owned descriptor.
            Ok(unsafe { std::fs::File::from_raw_fd(fd) })
        }
        #[cfg(windows)]
        {
            windows_validate_display_identity(&self.directory, self.identity, &self.path, true)?;
            let file = windows_open_relative_file(&self.directory, name, true)?;
            windows_validate_display_identity(&self.directory, self.identity, &self.path, true)?;
            Ok(file)
        }
        #[cfg(not(any(unix, windows)))]
        {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(self.path.join(name))
                .map_err(Into::into)
        }
    }

    pub fn rename_leaf(&self, from: &str, to: &str) -> Result<(), SecureTempError> {
        validate_component(from)?;
        validate_component(to)?;
        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::os::fd::AsRawFd as _;
            let from = CString::new(from).map_err(|_| SecureTempError::UnsafeComponent)?;
            let to = CString::new(to).map_err(|_| SecureTempError::UnsafeComponent)?;
            // SAFETY: both names are flat components beneath the same retained
            // private directory; renameat never follows the source leaf.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    from.as_ptr(),
                    self.directory.as_raw_fd(),
                    to.as_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        }
        #[cfg(windows)]
        {
            windows_validate_display_identity(&self.directory, self.identity, &self.path, true)?;
            windows_rename_relative(&self.directory, from, to)?;
            windows_validate_display_identity(&self.directory, self.identity, &self.path, true)
        }
        #[cfg(not(any(unix, windows)))]
        std::fs::rename(self.path.join(from), self.path.join(to)).map_err(Into::into)
    }
}

impl SecureClipboardRoot {
    /// Bootstrap `$TMPDIR/conman/cliprdr/<process-instance>` once.
    pub fn bootstrap() -> Result<Self, SecureTempError> {
        Self::bootstrap_in(std::env::temp_dir())
    }

    fn bootstrap_in(temporary: PathBuf) -> Result<Self, SecureTempError> {
        if temporary.as_os_str().is_empty() {
            return Err(SecureTempError::Unavailable);
        }

        #[cfg(unix)]
        {
            use std::os::fd::FromRawFd as _;
            use std::os::unix::ffi::OsStrExt as _;

            let root_fd = open_directory_nofollow(&temporary)?;
            // SAFETY: `open_directory_nofollow` returns one newly-owned fd.
            let mut parent = unsafe { std::fs::File::from_raw_fd(root_fd) };
            for component in ["conman", "cliprdr"] {
                parent = open_or_create_private_child(&parent, component)?;
            }
            cleanup_stale_process_roots_unix(&parent)?;

            let startup_nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let mut created = None;
            for counter in 0..100_u32 {
                let process_name = format!("{}-{startup_nanos}-{counter}", std::process::id());
                match create_new_private_child(&parent, &process_name) {
                    Ok(process) => {
                        created = Some((process_name, process));
                        break;
                    }
                    Err(SecureTempError::Io(error))
                        if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
            }
            let (process_name, process) = created.ok_or(SecureTempError::Unavailable)?;
            let path = temporary.join("conman").join("cliprdr").join(process_name);
            let _ = temporary.as_os_str().as_bytes();
            Ok(Self(std::sync::Arc::new(SecureClipboardRootInner {
                path,
                directory: process,
            })))
        }

        #[cfg(windows)]
        {
            let temporary_root = windows_open_absolute_directory(&temporary)?;
            let conman = windows_open_relative_directory(&temporary_root, "conman", false)?;
            let base = windows_open_relative_directory(&conman, "cliprdr", false)?;
            cleanup_stale_process_roots_windows(&base)?;
            let startup_nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let mut created = None;
            for counter in 0..100_u32 {
                let process_name = format!("{}-{startup_nanos}-{counter}", std::process::id());
                match windows_open_relative_directory(&base, &process_name, true) {
                    Ok(process) => {
                        created = Some((process_name, process));
                        break;
                    }
                    Err(SecureTempError::Io(error))
                        if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
            }
            let (process_name, process) = created.ok_or(SecureTempError::Unavailable)?;
            let identity = windows_file_identity(&process)?;
            Ok(Self(std::sync::Arc::new(SecureClipboardRootInner {
                path: temporary.join("conman").join("cliprdr").join(process_name),
                directory: process,
                identity,
            })))
        }

        #[cfg(not(any(unix, windows)))]
        {
            let conman = temporary.join("conman");
            validate_or_create_private_directory(&conman)?;
            let base = conman.join("cliprdr");
            validate_or_create_private_directory(&base)?;
            cleanup_stale_process_roots_portable(&base)?;
            let startup_nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let mut path = None;
            for counter in 0..100_u32 {
                let candidate =
                    base.join(format!("{}-{startup_nanos}-{counter}", std::process::id()));
                match std::fs::create_dir(&candidate) {
                    Ok(()) => {
                        path = Some(candidate);
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
            let path = path.ok_or(SecureTempError::Unavailable)?;
            Ok(Self(std::sync::Arc::new(SecureClipboardRootInner { path })))
        }
    }

    /// Display path sent in the CLIPRDR temporary-directory PDU.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0.path
    }

    /// Create a private, flat child directory.
    pub fn create_child(&self, component: &str) -> Result<PathBuf, SecureTempError> {
        validate_component(component)?;

        #[cfg(unix)]
        {
            let child = open_or_create_private_child(&self.0.directory, component)?;
            drop(child);
        }
        #[cfg(windows)]
        {
            windows_validate_display_identity(
                &self.0.directory,
                self.0.identity,
                &self.0.path,
                true,
            )?;
            drop(windows_open_relative_directory(
                &self.0.directory,
                component,
                false,
            )?);
            windows_validate_display_identity(
                &self.0.directory,
                self.0.identity,
                &self.0.path,
                true,
            )?;
        }
        #[cfg(not(any(unix, windows)))]
        validate_or_create_private_directory(&self.0.path.join(component))?;

        Ok(self.0.path.join(component))
    }

    /// Create `<endpoint>/<revision>` relative to the retained process root.
    pub fn create_transfer_directory(
        &self,
        endpoint: u64,
        revision: u64,
    ) -> Result<SecureStagingDirectory, SecureTempError> {
        let endpoint_name = endpoint.to_string();
        let revision_name = revision.to_string();
        #[cfg(unix)]
        {
            let endpoint_directory =
                open_or_create_private_child(&self.0.directory, &endpoint_name)?;
            let directory = open_or_create_private_child(&endpoint_directory, &revision_name)?;
            Ok(SecureStagingDirectory {
                path: self.0.path.join(endpoint_name).join(revision_name),
                directory,
            })
        }
        #[cfg(windows)]
        {
            windows_validate_display_identity(
                &self.0.directory,
                self.0.identity,
                &self.0.path,
                true,
            )?;
            let endpoint_directory =
                windows_open_relative_directory(&self.0.directory, &endpoint_name, false)?;
            let directory =
                windows_open_relative_directory(&endpoint_directory, &revision_name, false)?;
            let identity = windows_file_identity(&directory)?;
            windows_validate_display_identity(
                &self.0.directory,
                self.0.identity,
                &self.0.path,
                true,
            )?;
            Ok(SecureStagingDirectory {
                path: self.0.path.join(endpoint_name).join(revision_name),
                directory,
                identity,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let endpoint_path = self.0.path.join(endpoint_name);
            validate_or_create_private_directory(&endpoint_path)?;
            let path = endpoint_path.join(revision_name);
            validate_or_create_private_directory(&path)?;
            Ok(SecureStagingDirectory { path })
        }
    }

    /// Create `source/<platform-sequence>` for an eagerly materialized
    /// Windows virtual-file clipboard offer.
    pub fn create_source_directory(
        &self,
        sequence: u64,
    ) -> Result<SecureStagingDirectory, SecureTempError> {
        let sequence_name = sequence.to_string();
        #[cfg(unix)]
        {
            let source = open_or_create_private_child(&self.0.directory, "source")?;
            let directory = open_or_create_private_child(&source, &sequence_name)?;
            Ok(SecureStagingDirectory {
                path: self.0.path.join("source").join(sequence_name),
                directory,
            })
        }
        #[cfg(windows)]
        {
            windows_validate_display_identity(
                &self.0.directory,
                self.0.identity,
                &self.0.path,
                true,
            )?;
            let source = windows_open_relative_directory(&self.0.directory, "source", false)?;
            let directory = windows_open_relative_directory(&source, &sequence_name, false)?;
            let identity = windows_file_identity(&directory)?;
            windows_validate_display_identity(
                &self.0.directory,
                self.0.identity,
                &self.0.path,
                true,
            )?;
            Ok(SecureStagingDirectory {
                path: self.0.path.join("source").join(sequence_name),
                directory,
                identity,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let source = self.0.path.join("source");
            validate_or_create_private_directory(&source)?;
            let path = source.join(sequence_name);
            validate_or_create_private_directory(&path)?;
            Ok(SecureStagingDirectory { path })
        }
    }

    /// Remove one known flat transfer directory without traversing children.
    pub fn cleanup_staging_path(&self, path: &Path) -> Result<(), SecureTempError> {
        let components = self.staging_components(path)?;

        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::os::fd::AsRawFd as _;
            let parent = match open_existing_private_child(&self.0.directory, &components[0]) {
                Ok(parent) => parent,
                Err(SecureTempError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let directory = match open_existing_private_child(&parent, &components[1]) {
                Ok(directory) => directory,
                Err(SecureTempError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let mut budget = STARTUP_ENTRY_BUDGET;
            for name in read_directory_names(&directory, &mut budget)? {
                if !safe_unix_leaf(&directory, &name)? {
                    return Err(SecureTempError::UnsafeComponent);
                }
                validate_component(&name)?;
                let name = CString::new(name).map_err(|_| SecureTempError::UnsafeComponent)?;
                // SAFETY: directory is retained/validated and this removes one
                // leaf without following it.
                if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            drop(directory);
            let child = CString::new(components[1].as_str())
                .map_err(|_| SecureTempError::UnsafeComponent)?;
            // SAFETY: parent is retained and child was opened/validated above.
            if unsafe { libc::unlinkat(parent.as_raw_fd(), child.as_ptr(), libc::AT_REMOVEDIR) }
                != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        }
        #[cfg(windows)]
        {
            windows_validate_display_identity(
                &self.0.directory,
                self.0.identity,
                &self.0.path,
                true,
            )?;
            let parent = match windows_open_existing_directory(&self.0.directory, &components[0]) {
                Ok(parent) => parent,
                Err(SecureTempError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let directory = match windows_open_existing_directory(&parent, &components[1]) {
                Ok(directory) => directory,
                Err(SecureTempError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            windows_remove_flat_directory(&parent, &components[1], &directory)?;
            windows_validate_display_identity(
                &self.0.directory,
                self.0.identity,
                &self.0.path,
                true,
            )
        }
        #[cfg(not(any(unix, windows)))]
        {
            let parent = self.0.path.join(&components[0]);
            let directory = parent.join(&components[1]);
            for candidate in [&parent, &directory] {
                match std::fs::symlink_metadata(candidate) {
                    Ok(_) if safe_existing_directory(candidate) => {}
                    Ok(_) => return Err(SecureTempError::UnsafeComponent),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                    Err(error) => return Err(error.into()),
                }
            }
            for entry in std::fs::read_dir(&directory)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_dir() || !(file_type.is_file() || file_type.is_symlink()) {
                    return Err(SecureTempError::UnsafeComponent);
                }
                std::fs::remove_file(entry.path())?;
            }
            std::fs::remove_dir(directory)?;
            Ok(())
        }
    }

    /// Check that a display path still names the same safe two-level staging
    /// shape beneath this retained process root. No component is followed.
    #[must_use]
    pub fn is_live_staging_path(&self, path: &Path) -> bool {
        let Ok(components) = self.staging_components(path) else {
            return false;
        };
        #[cfg(unix)]
        {
            let Ok(parent) = open_existing_private_child(&self.0.directory, &components[0]) else {
                return false;
            };
            open_existing_private_child(&parent, &components[1]).is_ok()
        }
        #[cfg(windows)]
        {
            if windows_validate_display_identity(
                &self.0.directory,
                self.0.identity,
                &self.0.path,
                true,
            )
            .is_err()
            {
                return false;
            }
            let Ok(parent) = windows_open_existing_directory(&self.0.directory, &components[0])
            else {
                return false;
            };
            windows_open_existing_directory(&parent, &components[1]).is_ok()
        }
        #[cfg(not(any(unix, windows)))]
        {
            let parent = self.0.path.join(&components[0]);
            let child = parent.join(&components[1]);
            safe_existing_directory(&parent) && safe_existing_directory(&child)
        }
    }

    fn staging_components(&self, path: &Path) -> Result<[String; 2], SecureTempError> {
        let relative = path
            .strip_prefix(&self.0.path)
            .map_err(|_| SecureTempError::UnsafeComponent)?;
        let components = relative
            .components()
            .map(|component| component.as_os_str().to_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or(SecureTempError::UnsafeComponent)?;
        let [parent, child]: [String; 2] = components
            .try_into()
            .map_err(|_| SecureTempError::UnsafeComponent)?;
        validate_component(&parent)?;
        validate_component(&child)?;
        Ok([parent, child])
    }
}

fn validate_component(component: &str) -> Result<(), SecureTempError> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.contains(['/', '\\'])
        || component.contains('\0')
    {
        Err(SecureTempError::UnsafeComponent)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn open_directory_nofollow(path: &Path) -> Result<std::os::fd::RawFd, SecureTempError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| SecureTempError::UnsafeComponent)?;
    // SAFETY: the C string is NUL terminated and flags request a directory fd only.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(fd)
}

#[cfg(unix)]
fn open_or_create_private_child(
    parent: &std::fs::File,
    component: &str,
) -> Result<std::fs::File, SecureTempError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::fs::MetadataExt as _;

    let name = CString::new(component).map_err(|_| SecureTempError::UnsafeComponent)?;
    // SAFETY: parent is a live directory fd and name is one validated component.
    let mkdir_result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if mkdir_result != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
    }
    // SAFETY: same live fd/name; O_NOFOLLOW rejects a hostile symlink.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `openat` returned a newly owned fd.
    let directory = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != effective_uid || metadata.mode() & 0o777 != 0o700 {
        return Err(SecureTempError::UnsafeComponent);
    }
    Ok(directory)
}

#[cfg(unix)]
fn create_new_private_child(
    parent: &std::fs::File,
    component: &str,
) -> Result<std::fs::File, SecureTempError> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;

    let name = CString::new(component).map_err(|_| SecureTempError::UnsafeComponent)?;
    // SAFETY: parent is retained and component is one NUL-free name.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    open_existing_private_child(parent, component)
}

#[cfg(unix)]
fn open_existing_private_child(
    parent: &std::fs::File,
    component: &str,
) -> Result<std::fs::File, SecureTempError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::fs::MetadataExt as _;

    let name = CString::new(component).map_err(|_| SecureTempError::UnsafeComponent)?;
    // SAFETY: parent is a live validated directory and the flat name is
    // opened without following links.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `openat` returned one newly owned fd.
    let directory = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != effective_uid || metadata.mode() & 0o777 != 0o700 {
        return Err(SecureTempError::UnsafeComponent);
    }
    Ok(directory)
}

#[cfg(not(any(unix, windows)))]
fn validate_or_create_private_directory(path: &Path) -> Result<(), SecureTempError> {
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path)?;
            let is_reparse = metadata.file_type().is_symlink();
            if metadata.is_dir() && !is_reparse {
                Ok(())
            } else {
                Err(SecureTempError::UnsafeComponent)
            }
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(any(unix, windows)))]
fn safe_existing_directory(path: &Path) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    let is_reparse = metadata.file_type().is_symlink();
    metadata.is_dir() && !is_reparse
}

fn is_process_instance_name(name: &str) -> bool {
    let mut parts = name.split('-');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(pid), Some(nanos), Some(counter), None)
            if !pid.is_empty()
                && !nanos.is_empty()
                && !counter.is_empty()
                && pid.bytes().all(|byte| byte.is_ascii_digit())
                && nanos.bytes().all(|byte| byte.is_ascii_digit())
                && counter.bytes().all(|byte| byte.is_ascii_digit())
    )
}

fn is_old(metadata: &std::fs::Metadata) -> bool {
    metadata.modified().ok().is_some_and(|modified| {
        std::time::SystemTime::now()
            .duration_since(modified)
            .is_ok_and(|age| age >= STALE_PROCESS_AGE)
    })
}

#[cfg(unix)]
struct StartupDirectory {
    name: String,
    directory: std::fs::File,
    children: Vec<StartupLeafDirectory>,
}

#[cfg(unix)]
struct StartupLeafDirectory {
    name: String,
    directory: std::fs::File,
    leaves: Vec<String>,
}

#[cfg(unix)]
fn cleanup_stale_process_roots_unix(base: &std::fs::File) -> Result<(), SecureTempError> {
    let mut budget = STARTUP_ENTRY_BUDGET;
    for name in read_directory_names(base, &mut budget)? {
        if !is_process_instance_name(&name) {
            continue;
        }
        let Ok(process) = open_existing_private_child(base, &name) else {
            continue;
        };
        if !is_old(&process.metadata()?) {
            continue;
        }
        let Some(levels) = inspect_stale_process_root(&process, &mut budget)? else {
            continue;
        };
        remove_inspected_process_root(base, &name, levels)?;
    }
    Ok(())
}

#[cfg(unix)]
fn inspect_stale_process_root(
    process: &std::fs::File,
    budget: &mut usize,
) -> Result<Option<Vec<StartupDirectory>>, SecureTempError> {
    let mut levels = Vec::new();
    for name in read_directory_names(process, budget)? {
        if name != "source" && !name.bytes().all(|byte| byte.is_ascii_digit()) {
            return Ok(None);
        }
        let Ok(directory) = open_existing_private_child(process, &name) else {
            return Ok(None);
        };
        let mut children = Vec::new();
        for child_name in read_directory_names(&directory, budget)? {
            if !child_name.bytes().all(|byte| byte.is_ascii_digit()) {
                return Ok(None);
            }
            let Ok(child) = open_existing_private_child(&directory, &child_name) else {
                return Ok(None);
            };
            let leaves = read_directory_names(&child, budget)?;
            if leaves
                .iter()
                .any(|leaf| !safe_unix_leaf(&child, leaf).unwrap_or(false))
            {
                return Ok(None);
            }
            children.push(StartupLeafDirectory {
                name: child_name,
                directory: child,
                leaves,
            });
        }
        levels.push(StartupDirectory {
            name,
            directory,
            children,
        });
    }
    Ok(Some(levels))
}

#[cfg(unix)]
fn safe_unix_leaf(parent: &std::fs::File, name: &str) -> Result<bool, SecureTempError> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd as _;

    let name = CString::new(name).map_err(|_| SecureTempError::UnsafeComponent)?;
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent/name are live and stat points to writable storage.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fstatat initialized the structure on success.
    let stat = unsafe { stat.assume_init() };
    Ok(matches!(
        stat.st_mode & libc::S_IFMT,
        libc::S_IFREG | libc::S_IFLNK
    ))
}

#[cfg(unix)]
fn remove_inspected_process_root(
    base: &std::fs::File,
    process_name: &str,
    levels: Vec<StartupDirectory>,
) -> Result<(), SecureTempError> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;

    for level in levels {
        for child in level.children {
            for leaf in child.leaves {
                let leaf = CString::new(leaf).map_err(|_| SecureTempError::UnsafeComponent)?;
                // SAFETY: this is one previously inspected leaf under the
                // retained child handle; unlinkat never follows it.
                if unsafe { libc::unlinkat(child.directory.as_raw_fd(), leaf.as_ptr(), 0) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            let child_name =
                CString::new(child.name).map_err(|_| SecureTempError::UnsafeComponent)?;
            // SAFETY: child is the inspected empty directory below level.
            if unsafe {
                libc::unlinkat(
                    level.directory.as_raw_fd(),
                    child_name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        let level_name = CString::new(level.name).map_err(|_| SecureTempError::UnsafeComponent)?;
        let process = open_existing_private_child(base, process_name)?;
        // SAFETY: level is the inspected empty directory below process.
        if unsafe { libc::unlinkat(process.as_raw_fd(), level_name.as_ptr(), libc::AT_REMOVEDIR) }
            != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    let process_name = CString::new(process_name).map_err(|_| SecureTempError::UnsafeComponent)?;
    // SAFETY: the validated process root is now empty.
    if unsafe { libc::unlinkat(base.as_raw_fd(), process_name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(unix)]
fn read_directory_names(
    directory: &std::fs::File,
    budget: &mut usize,
) -> Result<Vec<String>, SecureTempError> {
    use std::ffi::CStr;
    use std::os::fd::AsRawFd as _;

    // SAFETY: dup returns an independently owned descriptor on success.
    let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fdopendir consumes the duplicate descriptor on success.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: fdopendir did not consume duplicate on failure.
        unsafe { libc::close(duplicate) };
        return Err(std::io::Error::last_os_error().into());
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: stream is live and accessed only by this thread.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: readdir returns a live NUL-terminated d_name.
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if *budget == 0 {
            // SAFETY: stream is live and closes the duplicate descriptor.
            unsafe { libc::closedir(stream) };
            return Err(SecureTempError::Unavailable);
        }
        *budget -= 1;
        let Ok(name) = std::str::from_utf8(bytes) else {
            // Unknown entries are intentionally left untouched.
            continue;
        };
        names.push(name.to_owned());
    }
    // SAFETY: stream is live and closes the duplicate descriptor.
    if unsafe { libc::closedir(stream) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(names)
}

#[cfg(windows)]
pub fn windows_file_identity(
    file: &impl std::os::windows::io::AsRawHandle,
) -> Result<WindowsFileIdentity, SecureTempError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file is live and information is writable.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information) }
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(WindowsFileIdentity {
        volume: information.dwVolumeSerialNumber,
        index: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    })
}

#[cfg(windows)]
fn windows_validate_identity(
    file: &std::fs::File,
    expected: WindowsFileIdentity,
    directory: bool,
) -> Result<(), SecureTempError> {
    use std::os::windows::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    if windows_file_identity(file)? != expected
        || metadata.is_dir() != directory
        || metadata.file_attributes() & 0x0000_0400 != 0
    {
        return Err(SecureTempError::UnsafeComponent);
    }
    Ok(())
}

#[cfg(windows)]
fn windows_validate_display_identity(
    retained: &std::fs::File,
    expected: WindowsFileIdentity,
    display_path: &Path,
    directory: bool,
) -> Result<(), SecureTempError> {
    windows_validate_identity(retained, expected, directory)?;
    let display = if directory {
        windows_open_absolute_directory(display_path)?
    } else {
        return Err(SecureTempError::UnsafeComponent);
    };
    if windows_file_identity(&display)? != expected {
        return Err(SecureTempError::UnsafeComponent);
    }
    Ok(())
}

#[cfg(windows)]
fn windows_open_absolute_directory(path: &Path) -> Result<std::fs::File, SecureTempError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & 0x0000_0400 != 0 {
        return Err(SecureTempError::UnsafeComponent);
    }
    let _ = windows_file_identity(&file)?;
    Ok(file)
}

#[cfg(windows)]
fn windows_open_relative_directory(
    parent: &std::fs::File,
    name: &str,
    create_new: bool,
) -> Result<std::fs::File, SecureTempError> {
    use windows::Wdk::Storage::FileSystem::{FILE_CREATE, FILE_OPEN_IF};

    windows_open_relative_directory_with_disposition(
        parent,
        name,
        if create_new {
            FILE_CREATE
        } else {
            FILE_OPEN_IF
        },
    )
}

#[cfg(windows)]
fn windows_open_existing_directory(
    parent: &std::fs::File,
    name: &str,
) -> Result<std::fs::File, SecureTempError> {
    windows_open_relative_directory_with_disposition(
        parent,
        name,
        windows::Wdk::Storage::FileSystem::FILE_OPEN,
    )
}

#[cfg(windows)]
fn windows_open_relative_directory_with_disposition(
    parent: &std::fs::File,
    name: &str,
    disposition: windows::Wdk::Storage::FileSystem::NTCREATEFILE_CREATE_DISPOSITION,
) -> Result<std::fs::File, SecureTempError> {
    use windows::Wdk::Storage::FileSystem::{
        FILE_DIRECTORY_FILE, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT,
        FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows::Win32::Storage::FileSystem::{
        DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_DELETE_CHILD,
        FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, SYNCHRONIZE,
    };

    validate_component(name)?;
    let access = DELETE
        | FILE_ADD_FILE
        | FILE_ADD_SUBDIRECTORY
        | FILE_DELETE_CHILD
        | FILE_LIST_DIRECTORY
        | FILE_READ_ATTRIBUTES
        | FILE_TRAVERSE
        | FILE_WRITE_ATTRIBUTES
        | SYNCHRONIZE;
    let options = FILE_DIRECTORY_FILE
        | FILE_OPEN_REPARSE_POINT
        | FILE_OPEN_FOR_BACKUP_INTENT
        | FILE_SYNCHRONOUS_IO_NONALERT;
    let file = windows_nt_open_relative(
        parent,
        name,
        access,
        disposition,
        options,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )?;
    let identity = windows_file_identity(&file)?;
    windows_validate_identity(&file, identity, true)?;
    Ok(file)
}

#[cfg(windows)]
fn windows_open_relative_file(
    parent: &std::fs::File,
    name: &str,
    create_new: bool,
) -> Result<std::fs::File, SecureTempError> {
    use windows::Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
        FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_NORMAL, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, SYNCHRONIZE,
    };

    validate_component(name)?;
    let file = windows_nt_open_relative(
        parent,
        name,
        DELETE
            | FILE_READ_ATTRIBUTES
            | FILE_READ_DATA
            | FILE_WRITE_ATTRIBUTES
            | FILE_WRITE_DATA
            | SYNCHRONIZE,
        if create_new { FILE_CREATE } else { FILE_OPEN },
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )?;
    let identity = windows_file_identity(&file)?;
    windows_validate_identity(&file, identity, false)?;
    Ok(file)
}

#[cfg(windows)]
fn windows_nt_open_relative(
    parent: &std::fs::File,
    name: &str,
    access: windows::Win32::Storage::FileSystem::FILE_ACCESS_RIGHTS,
    disposition: windows::Wdk::Storage::FileSystem::NTCREATEFILE_CREATE_DISPOSITION,
    options: windows::Wdk::Storage::FileSystem::NTCREATEFILE_CREATE_OPTIONS,
    attributes: windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES,
    sharing: windows::Win32::Storage::FileSystem::FILE_SHARE_MODE,
) -> Result<std::fs::File, SecureTempError> {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows::Wdk::Storage::FileSystem::{NtCreateFile, RtlNtStatusToDosErrorNoTeb};
    use windows::Win32::Foundation::{HANDLE, OBJ_CASE_INSENSITIVE, UNICODE_STRING};
    use windows::Win32::System::IO::IO_STATUS_BLOCK;
    use windows::core::PWSTR;

    let mut wide = name.encode_utf16().collect::<Vec<_>>();
    let byte_len = wide
        .len()
        .checked_mul(2)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(SecureTempError::UnsafeComponent)?;
    let unicode = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: PWSTR(wide.as_mut_ptr()),
    };
    let object = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: HANDLE(parent.as_raw_handle()),
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle = HANDLE::default();
    let mut io = IO_STATUS_BLOCK::default();
    // SAFETY: all structures and the relative UTF-16 name stay live for the
    // synchronous call; RootDirectory is a retained validated directory.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &object,
            &mut io,
            None,
            attributes,
            sharing,
            disposition,
            options,
            None,
            0,
        )
    };
    if status.0 < 0 {
        // SAFETY: conversion accepts every NTSTATUS.
        let code = unsafe { RtlNtStatusToDosErrorNoTeb(status) };
        return Err(std::io::Error::from_raw_os_error(code as i32).into());
    }
    // SAFETY: NtCreateFile returned one newly-owned Win32 handle.
    Ok(unsafe { std::fs::File::from_raw_handle(handle.0) })
}

#[cfg(windows)]
fn windows_rename_relative(
    parent: &std::fs::File,
    from: &str,
    to: &str,
) -> Result<(), SecureTempError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows::Wdk::Storage::FileSystem::{
        FILE_RENAME_INFORMATION, FileRenameInformation, NtSetInformationFile,
        RtlNtStatusToDosErrorNoTeb,
    };
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::IO::IO_STATUS_BLOCK;

    let source = windows_open_relative_file(parent, from, false)?;
    let target = to.encode_utf16().collect::<Vec<_>>();
    let name_bytes = target
        .len()
        .checked_mul(2)
        .ok_or(SecureTempError::UnsafeComponent)?;
    let header = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let bytes = header
        .checked_add(name_bytes)
        .ok_or(SecureTempError::UnsafeComponent)?;
    let mut storage = vec![0_u64; bytes.div_ceil(std::mem::size_of::<u64>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: storage is aligned and sized for the header plus target name.
    unsafe {
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = HANDLE(parent.as_raw_handle());
        (*info).FileNameLength = name_bytes as u32;
        std::ptr::copy_nonoverlapping(target.as_ptr(), (*info).FileName.as_mut_ptr(), target.len());
    }
    let mut io = IO_STATUS_BLOCK::default();
    // SAFETY: source and parent are retained handles; the aligned variable-
    // length FILE_RENAME_INFORMATION buffer remains live for the synchronous
    // native call.
    let status = unsafe {
        NtSetInformationFile(
            HANDLE(source.as_raw_handle()),
            &mut io,
            info.cast(),
            bytes as u32,
            FileRenameInformation,
        )
    };
    if status.0 < 0 {
        // SAFETY: conversion accepts every NTSTATUS.
        let code = unsafe { RtlNtStatusToDosErrorNoTeb(status) };
        return Err(std::io::Error::from_raw_os_error(code as i32).into());
    }
    Ok(())
}

#[cfg(windows)]
fn windows_delete_handle(file: &std::fs::File) -> Result<(), SecureTempError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        FILE_DISPOSITION_INFO_EX, FileDispositionInfoEx, SetFileInformationByHandle,
    };

    let info = FILE_DISPOSITION_INFO_EX {
        Flags: windows::Win32::Storage::FileSystem::FILE_DISPOSITION_INFO_EX_FLAGS(
            FILE_DISPOSITION_FLAG_DELETE.0 | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS.0,
        ),
    };
    // SAFETY: handle is live and info has the exact class layout.
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfoEx,
            std::ptr::addr_of!(info).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    }
    .map_err(|error| std::io::Error::other(error.to_string()).into())
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsDirectoryEntry {
    name: String,
    attributes: u32,
}

#[cfg(windows)]
fn windows_directory_entries(
    directory: &std::fs::File,
    budget: &mut usize,
) -> Result<Vec<WindowsDirectoryEntry>, SecureTempError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows::Win32::Foundation::{ERROR_NO_MORE_FILES, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        FILE_ID_BOTH_DIR_INFO, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
        GetFileInformationByHandleEx,
    };
    use windows::core::HRESULT;

    let mut result = Vec::new();
    let mut restart = true;
    loop {
        let mut storage = vec![0_u64; (64 * 1024) / std::mem::size_of::<u64>()];
        let class = if restart {
            FileIdBothDirectoryRestartInfo
        } else {
            FileIdBothDirectoryInfo
        };
        // SAFETY: directory is live and storage is writable for its full size.
        let query = unsafe {
            GetFileInformationByHandleEx(
                HANDLE(directory.as_raw_handle()),
                class,
                storage.as_mut_ptr().cast(),
                (storage.len() * std::mem::size_of::<u64>()) as u32,
            )
        };
        if let Err(error) = query {
            if error.code() == HRESULT::from_win32(ERROR_NO_MORE_FILES.0) {
                break;
            }
            return Err(std::io::Error::from_raw_os_error(error.code().0).into());
        }
        restart = false;
        let mut offset = 0_usize;
        loop {
            if offset + std::mem::size_of::<FILE_ID_BOTH_DIR_INFO>() > storage.len() * 8 {
                return Err(SecureTempError::UnsafeComponent);
            }
            // SAFETY: offset was bounded above and buffer is suitably aligned.
            let entry = unsafe {
                &*storage
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<FILE_ID_BOTH_DIR_INFO>()
            };
            let units = usize::try_from(entry.FileNameLength / 2)
                .map_err(|_| SecureTempError::UnsafeComponent)?;
            let name_offset = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
            if offset + name_offset + units * 2 > storage.len() * 8 {
                return Err(SecureTempError::UnsafeComponent);
            }
            // SAFETY: filename byte range was checked against storage.
            let name_units = unsafe { std::slice::from_raw_parts(entry.FileName.as_ptr(), units) };
            let name =
                String::from_utf16(name_units).map_err(|_| SecureTempError::UnsafeComponent)?;
            if name != "." && name != ".." {
                if *budget == 0 {
                    return Err(SecureTempError::Unavailable);
                }
                *budget -= 1;
                result.push(WindowsDirectoryEntry {
                    name,
                    attributes: entry.FileAttributes,
                });
            }
            if entry.NextEntryOffset == 0 {
                break;
            }
            offset = offset
                .checked_add(entry.NextEntryOffset as usize)
                .ok_or(SecureTempError::UnsafeComponent)?;
        }
    }
    Ok(result)
}

#[cfg(windows)]
fn windows_remove_flat_directory(
    parent: &std::fs::File,
    name: &str,
    directory: &std::fs::File,
) -> Result<(), SecureTempError> {
    const FILE_ATTRIBUTE_DIRECTORY_RAW: u32 = 0x10;
    let mut budget = STARTUP_ENTRY_BUDGET;
    for entry in windows_directory_entries(directory, &mut budget)? {
        if entry.attributes & FILE_ATTRIBUTE_DIRECTORY_RAW != 0 {
            return Err(SecureTempError::UnsafeComponent);
        }
        let leaf = windows_open_relative_file(directory, &entry.name, false)?;
        windows_delete_handle(&leaf)?;
    }
    let reopened = windows_open_existing_directory(parent, name)?;
    if windows_file_identity(&reopened)? != windows_file_identity(directory)? {
        return Err(SecureTempError::UnsafeComponent);
    }
    windows_delete_handle(&reopened)
}

#[cfg(windows)]
fn cleanup_stale_process_roots_windows(base: &std::fs::File) -> Result<(), SecureTempError> {
    const FILE_ATTRIBUTE_DIRECTORY_RAW: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_RAW: u32 = 0x400;
    let mut budget = STARTUP_ENTRY_BUDGET;
    for entry in windows_directory_entries(base, &mut budget)? {
        if !is_process_instance_name(&entry.name)
            || entry.attributes & FILE_ATTRIBUTE_DIRECTORY_RAW == 0
            || entry.attributes & FILE_ATTRIBUTE_REPARSE_RAW != 0
        {
            continue;
        }
        let Ok(process) = windows_open_existing_directory(base, &entry.name) else {
            continue;
        };
        if !is_old(&process.metadata()?)
            || !windows_process_root_is_structurally_valid(&process, &mut budget)?
        {
            continue;
        }
        windows_remove_process_root(base, &entry.name, &process, &mut budget)?;
    }
    Ok(())
}

#[cfg(windows)]
fn windows_process_root_is_structurally_valid(
    process: &std::fs::File,
    budget: &mut usize,
) -> Result<bool, SecureTempError> {
    const DIRECTORY: u32 = 0x10;
    const REPARSE: u32 = 0x400;
    for level in windows_directory_entries(process, budget)? {
        if (level.name != "source" && !level.name.bytes().all(|byte| byte.is_ascii_digit()))
            || level.attributes & DIRECTORY == 0
            || level.attributes & REPARSE != 0
        {
            return Ok(false);
        }
        let directory = windows_open_existing_directory(process, &level.name)?;
        for child in windows_directory_entries(&directory, budget)? {
            if !child.name.bytes().all(|byte| byte.is_ascii_digit())
                || child.attributes & DIRECTORY == 0
                || child.attributes & REPARSE != 0
            {
                return Ok(false);
            }
            let child = windows_open_existing_directory(&directory, &child.name)?;
            if windows_directory_entries(&child, budget)?
                .iter()
                .any(|leaf| leaf.attributes & DIRECTORY != 0)
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[cfg(windows)]
fn windows_remove_process_root(
    base: &std::fs::File,
    process_name: &str,
    process: &std::fs::File,
    budget: &mut usize,
) -> Result<(), SecureTempError> {
    for level in windows_directory_entries(process, budget)? {
        let level_directory = windows_open_existing_directory(process, &level.name)?;
        for child in windows_directory_entries(&level_directory, budget)? {
            let child_directory = windows_open_existing_directory(&level_directory, &child.name)?;
            windows_remove_flat_directory(&level_directory, &child.name, &child_directory)?;
        }
        windows_delete_handle(&level_directory)?;
    }
    let reopened = windows_open_existing_directory(base, process_name)?;
    if windows_file_identity(&reopened)? != windows_file_identity(process)? {
        return Err(SecureTempError::UnsafeComponent);
    }
    windows_delete_handle(&reopened)
}

#[cfg(not(any(unix, windows)))]
fn cleanup_stale_process_roots_portable(base: &Path) -> Result<(), SecureTempError> {
    let mut budget = STARTUP_ENTRY_BUDGET;
    for entry in std::fs::read_dir(base)? {
        if budget == 0 {
            return Err(SecureTempError::Unavailable);
        }
        budget -= 1;
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !is_process_instance_name(&name)
            || !safe_existing_directory(&entry.path())
            || !is_old(&entry.metadata()?)
        {
            continue;
        }
        let Some(levels) = inspect_stale_process_root_portable(&entry.path(), &mut budget)? else {
            continue;
        };
        for (level, children) in levels {
            for (child, leaves) in children {
                for leaf in leaves {
                    std::fs::remove_file(leaf)?;
                }
                std::fs::remove_dir(child)?;
            }
            std::fs::remove_dir(level)?;
        }
        std::fs::remove_dir(entry.path())?;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
type PortableCleanupTree = Vec<(PathBuf, Vec<(PathBuf, Vec<PathBuf>)>)>;

#[cfg(not(any(unix, windows)))]
fn inspect_stale_process_root_portable(
    process: &Path,
    budget: &mut usize,
) -> Result<Option<PortableCleanupTree>, SecureTempError> {
    let mut levels = Vec::new();
    for level in std::fs::read_dir(process)? {
        let level = level?;
        if *budget == 0 {
            return Err(SecureTempError::Unavailable);
        }
        *budget -= 1;
        let Some(name) = level.file_name().to_str().map(str::to_owned) else {
            return Ok(None);
        };
        if (name != "source" && !name.bytes().all(|byte| byte.is_ascii_digit()))
            || !safe_existing_directory(&level.path())
        {
            return Ok(None);
        }
        let mut children = Vec::new();
        for child in std::fs::read_dir(level.path())? {
            let child = child?;
            if *budget == 0 {
                return Err(SecureTempError::Unavailable);
            }
            *budget -= 1;
            let Some(name) = child.file_name().to_str().map(str::to_owned) else {
                return Ok(None);
            };
            if !name.bytes().all(|byte| byte.is_ascii_digit())
                || !safe_existing_directory(&child.path())
            {
                return Ok(None);
            }
            let mut leaves = Vec::new();
            for leaf in std::fs::read_dir(child.path())? {
                let leaf = leaf?;
                if *budget == 0 {
                    return Err(SecureTempError::Unavailable);
                }
                *budget -= 1;
                let metadata = std::fs::symlink_metadata(leaf.path())?;
                if metadata.is_dir() || !(metadata.is_file() || metadata.file_type().is_symlink()) {
                    return Ok(None);
                }
                leaves.push(leaf.path());
            }
            children.push((child.path(), leaves));
        }
        levels.push((level.path(), children));
    }
    Ok(Some(levels))
}

/// Canonicalize a local clipboard source's parent once, retain that directory
/// while opening its basename without following the final symlink/reparse
/// point, and return the opened file. The caller must still validate type,
/// identity, size, and modification time from the returned handle.
pub fn open_regular_file_nofollow(path: &Path) -> Result<std::fs::File, SecureTempError> {
    if !path.is_absolute() {
        return Err(SecureTempError::UnsafeComponent);
    }
    let parent = path.parent().ok_or(SecureTempError::UnsafeComponent)?;
    let basename = path.file_name().ok_or(SecureTempError::UnsafeComponent)?;
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        use std::os::unix::ffi::OsStrExt as _;
        let basename =
            CString::new(basename.as_bytes()).map_err(|_| SecureTempError::UnsafeComponent)?;
        let canonical_parent = std::fs::canonicalize(parent)?;
        let parent_fd = open_directory_nofollow(&canonical_parent)?;
        // SAFETY: `open_directory_nofollow` returned one newly-owned fd.
        let parent = unsafe { std::fs::File::from_raw_fd(parent_fd) };
        // SAFETY: the retained parent is a live directory and basename is one
        // NUL-free component; O_NOFOLLOW rejects the final symlink.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                basename.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: `open` returned one newly-owned descriptor.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
    #[cfg(windows)]
    {
        let basename = basename.to_str().ok_or(SecureTempError::UnsafeComponent)?;
        validate_component(basename)?;
        let parent_path = parent;
        let parent = windows_open_absolute_directory(parent_path)?;
        let identity = windows_file_identity(&parent)?;
        let file = windows_open_relative_file(&parent, basename, false)?;
        windows_validate_display_identity(&parent, identity, parent_path, true)?;
        Ok(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let canonical_parent = std::fs::canonicalize(parent)?;
        let resolved = canonical_parent.join(basename);
        let metadata = std::fs::symlink_metadata(&resolved)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(SecureTempError::UnsafeComponent);
        }
        std::fs::File::open(resolved).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_names_are_flat() {
        let root = SecureClipboardRoot::bootstrap().expect("secure root");
        assert!(root.create_child("endpoint-1").is_ok());
        assert!(matches!(
            root.create_child("../escape"),
            Err(SecureTempError::UnsafeComponent)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn hostile_fixed_ancestor_fails_closed() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let broad = tempfile::tempdir().unwrap();
        let conman = broad.path().join("conman");
        std::fs::create_dir(&conman).unwrap();
        std::fs::set_permissions(&conman, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(SecureClipboardRoot::bootstrap_in(broad.path().to_path_buf()).is_err());

        let linked = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        symlink(target.path(), linked.path().join("conman")).unwrap();
        assert!(SecureClipboardRoot::bootstrap_in(linked.path().to_path_buf()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_source_open_does_not_follow_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        std::fs::write(&target, b"synthetic").unwrap();
        let link = directory.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(open_regular_file_nofollow(&link).is_err());
        assert!(open_regular_file_nofollow(&target).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn startup_cleanup_removes_only_old_structurally_valid_process_roots() {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        let temporary = tempfile::tempdir().unwrap();
        let root_fd = open_directory_nofollow(temporary.path()).unwrap();
        // SAFETY: helper returned one newly-owned descriptor.
        let root = unsafe { std::fs::File::from_raw_fd(root_fd) };
        let conman = open_or_create_private_child(&root, "conman").unwrap();
        let base = open_or_create_private_child(&conman, "cliprdr").unwrap();
        let process = create_new_private_child(&base, "123-1-0").unwrap();
        let endpoint = create_new_private_child(&process, "7").unwrap();
        let _revision = create_new_private_child(&endpoint, "9").unwrap();
        let leaf = temporary
            .path()
            .join("conman/cliprdr/123-1-0/7/9/0.partial");
        std::fs::write(&leaf, b"synthetic").unwrap();

        let old = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(STALE_PROCESS_AGE.as_secs() + 60) as libc::time_t;
        let times = [
            libc::timespec {
                tv_sec: old,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: old,
                tv_nsec: 0,
            },
        ];
        // SAFETY: process is a live fd and times contains two initialized entries.
        assert_eq!(
            unsafe { libc::futimens(process.as_raw_fd(), times.as_ptr()) },
            0
        );

        let unknown = create_new_private_child(&base, "unknown").unwrap();
        drop(unknown);
        cleanup_stale_process_roots_unix(&base).unwrap();
        assert!(!temporary.path().join("conman/cliprdr/123-1-0").exists());
        assert!(temporary.path().join("conman/cliprdr/unknown").is_dir());
    }

    #[cfg(windows)]
    #[test]
    fn windows_identity_validation_rejects_wrong_retained_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = windows_open_absolute_directory(temporary.path()).unwrap();
        let identity = windows_file_identity(&directory).unwrap();
        let wrong = WindowsFileIdentity {
            volume: identity.volume,
            index: identity.index.wrapping_add(1),
        };
        assert!(matches!(
            windows_validate_identity(&directory, wrong, true),
            Err(SecureTempError::UnsafeComponent)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_replaced_display_ancestor_cannot_redirect_retained_root() {
        let temporary = tempfile::tempdir().unwrap();
        let root = SecureClipboardRoot::bootstrap_in(temporary.path().to_path_buf()).unwrap();
        let old_display = root.path().to_path_buf();
        let moved = old_display.with_extension("retained");
        std::fs::rename(&old_display, &moved).unwrap();
        std::fs::create_dir(&old_display).unwrap();

        assert!(matches!(
            root.create_child("safe-child"),
            Err(SecureTempError::UnsafeComponent)
        ));
        assert!(!moved.join("safe-child").exists());
        assert!(!old_display.join("safe-child").exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_staging_leaf_rename_and_cleanup_are_handle_relative() {
        use std::io::Write as _;

        let temporary = tempfile::tempdir().unwrap();
        let root = SecureClipboardRoot::bootstrap_in(temporary.path().to_path_buf()).unwrap();
        let directory = root.create_transfer_directory(7, 9).unwrap();
        let mut file = directory.create_new_file("0.partial").unwrap();
        file.write_all(b"synthetic").unwrap();
        file.sync_all().unwrap();
        drop(file);
        directory.rename_leaf("0.partial", "final.bin").unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("final.bin")).unwrap(),
            b"synthetic"
        );
        let path = directory.path().to_path_buf();
        drop(directory);
        root.cleanup_staging_path(&path).unwrap();
        assert!(!path.exists());
    }
}

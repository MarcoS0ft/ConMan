//! Linux installation-context detection and safe update primitives.
//!
//! This module deliberately knows about Linux file ownership and desktop
//! handoff mechanics, but not about update policy or the update reducer.  The
//! latter belongs to `cm-update`; callers pass an already-authorized artifact
//! to the staging functions below.  In particular, this module never invokes
//! a package manager or a privilege escalation helper.

#![cfg(target_os = "linux")]

use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// The marker installed by ConMan's native DEB and RPM packages.
pub const INSTALL_CONTEXT_MARKER: &str = "/usr/share/conman/install-context.json";

/// The private directory used for update plans, health tokens, and result
/// records.  It is intentionally under the user data directory rather than a
/// cache directory so desktop cleanup tools do not remove an in-flight plan.
pub const UPDATE_STATE_DIR_NAME: &str = "update-state";

/// Resolve and create ConMan's private update-state directory. The caller may
/// use this path for apply plans, health acknowledgements, and bounded helper
/// results; every entry is expected to be mode 0600 or stricter.
pub fn update_state_dir() -> Result<PathBuf, LinuxUpdateError> {
    let data =
        dirs::data_dir().ok_or_else(|| LinuxUpdateError::NoParent(PathBuf::from("conman")))?;
    let conman = data.join("conman");
    fs::create_dir_all(&conman).map_err(|e| io_at(&conman, e))?;
    fs::set_permissions(&conman, fs::Permissions::from_mode(0o700))
        .map_err(|e| io_at(&conman, e))?;
    let state = conman.join(UPDATE_STATE_DIR_NAME);
    fs::create_dir_all(&state).map_err(|e| io_at(&state, e))?;
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).map_err(|e| io_at(&state, e))?;
    Ok(state)
}

/// Linux update errors are typed so a caller can turn them into a concise
/// safe status without exposing arbitrary filesystem or server strings.
#[derive(Debug, thiserror::Error)]
pub enum LinuxUpdateError {
    #[error("path is not absolute: {0}")]
    NotAbsolute(PathBuf),
    #[error("path is not a regular executable file: {0}")]
    NotExecutable(PathBuf),
    #[error("path is a symbolic link: {0}")]
    Symlink(PathBuf),
    #[error("path has no parent directory: {0}")]
    NoParent(PathBuf),
    #[error("AppImage parent directory is not writable: {0}")]
    ParentNotWritable(PathBuf),
    #[error("file identity changed while preparing an update")]
    IdentityChanged,
    #[error("filesystem boundary does not permit an atomic replacement")]
    DifferentFilesystem,
    #[error("artifact is not a Type-2 AppImage: {0}")]
    NotType2AppImage(PathBuf),
    #[error("artifact length mismatch: expected {expected}, received {received}")]
    LengthMismatch { expected: u64, received: u64 },
    #[error("artifact hash mismatch")]
    HashMismatch,
    #[error("operation id must contain 128 random bits")]
    InvalidOperationId,
    #[error("marker is invalid or not owned by root: {0}")]
    InvalidMarker(PathBuf),
    #[error("package handoff handler could not be started: {0}")]
    Handoff(String),
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid JSON: {0}")]
    Json(String),
    #[error("process identity is not available for pid {0}")]
    ProcessIdentity(u32),
}

fn io_at(path: impl Into<PathBuf>, source: io::Error) -> LinuxUpdateError {
    LinuxUpdateError::Io {
        path: path.into(),
        source,
    }
}

/// Package type asserted by a root-owned ConMan marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativePackageKind {
    Deb,
    Rpm,
}

impl NativePackageKind {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Deb => "deb",
            Self::Rpm => "rpm",
        }
    }
}

/// Strict contents of `/usr/share/conman/install-context.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageMarker {
    pub schema: u32,
    pub product: String,
    pub kind: NativePackageKind,
    pub package: String,
}

impl<'de> Deserialize<'de> for PackageMarker {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MarkerVisitor;

        impl<'de> Visitor<'de> for MarkerVisitor {
            type Value = PackageMarker;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a strict ConMan install-context marker")
            }

            fn visit_map<M>(self, mut map: M) -> Result<PackageMarker, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut schema = None;
                let mut product = None;
                let mut kind = None;
                let mut package = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "schema" => {
                            if schema.is_some() {
                                return Err(de::Error::duplicate_field("schema"));
                            }
                            schema = Some(map.next_value::<u32>()?);
                        }
                        "product" => {
                            if product.is_some() {
                                return Err(de::Error::duplicate_field("product"));
                            }
                            product = Some(map.next_value::<String>()?);
                        }
                        "kind" => {
                            if kind.is_some() {
                                return Err(de::Error::duplicate_field("kind"));
                            }
                            kind = Some(map.next_value::<String>()?);
                        }
                        "package" => {
                            if package.is_some() {
                                return Err(de::Error::duplicate_field("package"));
                            }
                            package = Some(map.next_value::<String>()?);
                        }
                        other => return Err(de::Error::unknown_field(other, FIELDS)),
                    }
                }

                let schema = schema.ok_or_else(|| de::Error::missing_field("schema"))?;
                let product = product.ok_or_else(|| de::Error::missing_field("product"))?;
                let kind_name = kind.ok_or_else(|| de::Error::missing_field("kind"))?;
                let package = package.ok_or_else(|| de::Error::missing_field("package"))?;
                let kind = match kind_name.as_str() {
                    "deb" => NativePackageKind::Deb,
                    "rpm" => NativePackageKind::Rpm,
                    _ => return Err(de::Error::custom("kind must be deb or rpm")),
                };
                Ok(PackageMarker {
                    schema,
                    product,
                    kind,
                    package,
                })
            }
        }

        const FIELDS: &[&str] = &["schema", "product", "kind", "package"];
        let marker = deserializer.deserialize_map(MarkerVisitor)?;
        if marker.schema != 1 || marker.product != "conman" || marker.package != "conman" {
            return Err(de::Error::custom(
                "marker identity does not match ConMan schema 1",
            ));
        }
        Ok(marker)
    }
}

/// Identity captured from the opened AppImage file, not from an untrusted
/// `argv[0]` string.  The digest is kept in binary form to make comparisons
/// constant-shape and avoid accidental case differences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppImageIdentity {
    pub path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub byte_length: u64,
    pub sha256: [u8; 32],
}

impl AppImageIdentity {
    /// Capture a resolved absolute path.  Symlinks in the input are resolved
    /// once, then the resulting path is opened with `O_NOFOLLOW`.
    pub fn capture_resolved(path: &Path) -> Result<Self, LinuxUpdateError> {
        if !path.is_absolute() {
            return Err(LinuxUpdateError::NotAbsolute(path.to_path_buf()));
        }
        let resolved = fs::canonicalize(path).map_err(|e| io_at(path, e))?;
        Self::capture_opened(&resolved)
    }

    /// Capture a path that is already known to be resolved.  This still
    /// rejects a symlink because identity must be bound to one inode.
    pub fn capture_opened(path: &Path) -> Result<Self, LinuxUpdateError> {
        if !path.is_absolute() {
            return Err(LinuxUpdateError::NotAbsolute(path.to_path_buf()));
        }
        let link_metadata = fs::symlink_metadata(path).map_err(|e| io_at(path, e))?;
        if link_metadata.file_type().is_symlink() {
            return Err(LinuxUpdateError::Symlink(path.to_path_buf()));
        }
        let file = open_nofollow_read(path)?;
        let metadata = file.metadata().map_err(|e| io_at(path, e))?;
        validate_executable_regular(path, &metadata)?;
        validate_type2_appimage(path, &file)?;
        let sha256 = digest_file(&file, path)?;
        Ok(Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
            byte_length: metadata.len(),
            sha256,
        })
    }

    pub fn same_inode(&self, other: &Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.byte_length == other.byte_length
            && self.sha256 == other.sha256
    }

    pub fn sha256_hex(&self) -> String {
        hex_lower(&self.sha256)
    }
}

/// AppImage installation contexts recognised by the Linux adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxInstallContext {
    WritableAppImage(AppImageIdentity),
    ReadOnlyAppImage(AppImageIdentity),
    NativePackage(PackageMarker),
    ManagedExternally,
    ArchiveOrUnknown,
}

impl LinuxInstallContext {
    pub fn completion_is_replaceable(&self) -> bool {
        matches!(self, Self::WritableAppImage(_))
    }

    pub fn completion_action(&self) -> LinuxCompletionAction {
        match self {
            Self::WritableAppImage(_) => LinuxCompletionAction::RestartToCompleteUpdate,
            Self::ReadOnlyAppImage(_) | Self::ArchiveOrUnknown => {
                LinuxCompletionAction::OpenDownloadedUpdate
            }
            Self::NativePackage(_) => LinuxCompletionAction::FinishInSystemInstaller,
            Self::ManagedExternally => LinuxCompletionAction::OpenPackageManagerOrReleasePage,
        }
    }
}

/// Linux-specific completion wording mapped by the shared update reducer to
/// its platform-neutral completion actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxCompletionAction {
    RestartToCompleteUpdate,
    FinishInSystemInstaller,
    OpenDownloadedUpdate,
    OpenPackageManagerOrReleasePage,
}

/// Detect the current installation using the fixed P11.4 order.
pub fn detect_install_context() -> LinuxInstallContext {
    detect_install_context_at(
        std::env::var_os("APPIMAGE").as_deref(),
        Path::new(INSTALL_CONTEXT_MARKER),
        Path::new("/.flatpak-info"),
    )
}

/// Testable variant of [`detect_install_context`].  `appimage_env` models the
/// resolved value supplied by the AppImage runtime; `marker_path` and
/// `flatpak_path` are injectable only for fixtures and tests.
pub fn detect_install_context_at(
    appimage_env: Option<&OsStr>,
    marker_path: &Path,
    flatpak_path: &Path,
) -> LinuxInstallContext {
    if let Some(value) = appimage_env
        && !value.is_empty()
        && Path::new(value).is_absolute()
        && let Ok(identity) = AppImageIdentity::capture_resolved(Path::new(value))
    {
        let writable = identity.path.parent().is_some_and(directory_is_writable);
        return if writable {
            LinuxInstallContext::WritableAppImage(identity)
        } else {
            LinuxInstallContext::ReadOnlyAppImage(identity)
        };
    }

    if let Some(marker) = read_package_marker(marker_path) {
        return LinuxInstallContext::NativePackage(marker);
    }

    if flatpak_path.is_absolute()
        && fs::symlink_metadata(flatpak_path).is_ok_and(|metadata| metadata.file_type().is_file())
    {
        return LinuxInstallContext::ManagedExternally;
    }

    LinuxInstallContext::ArchiveOrUnknown
}

/// Parse and validate a native package marker.  A marker is authoritative only
/// when it is a regular, non-symlink, root-owned file that is not writable by
/// non-root users.
pub fn read_package_marker(path: &Path) -> Option<PackageMarker> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let marker = PackageMarker::deserialize(&mut deserializer).ok()?;
    deserializer.end().ok()?;
    Some(marker)
}

/// A random operation id, represented as exactly 32 lowercase hexadecimal
/// characters in all on-disk names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationId([u8; 16]);

impl OperationId {
    pub fn random() -> Result<Self, LinuxUpdateError> {
        let mut bytes = [0_u8; 16];
        let mut source = File::open("/dev/urandom").map_err(|e| io_at("/dev/urandom", e))?;
        source
            .read_exact(&mut bytes)
            .map_err(|e| io_at("/dev/urandom", e))?;
        Ok(Self(bytes))
    }

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }

    pub fn as_hex(self) -> String {
        hex_lower(&self.0)
    }
}

/// Paths produced by [`stage_appimage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedAppImage {
    pub operation_id: OperationId,
    pub partial_path: PathBuf,
    pub ready_path: PathBuf,
    pub identity: AppImageIdentity,
}

/// Stage and verify a full AppImage beside the current image.  The candidate
/// itself is only read; the only filesystem mutation is the create-new partial
/// file followed by a same-directory rename to the ready basename.
pub fn stage_appimage(
    current: &AppImageIdentity,
    candidate_path: &Path,
    operation_id: OperationId,
    expected_length: u64,
    expected_sha256: [u8; 32],
) -> Result<StagedAppImage, LinuxUpdateError> {
    if operation_id.is_zero() {
        return Err(LinuxUpdateError::InvalidOperationId);
    }
    let parent = current
        .path
        .parent()
        .ok_or_else(|| LinuxUpdateError::NoParent(current.path.clone()))?;
    if !directory_is_writable(parent) {
        return Err(LinuxUpdateError::ParentNotWritable(parent.to_path_buf()));
    }

    let candidate = open_nofollow_read(candidate_path)?;
    let candidate_meta = candidate.metadata().map_err(|e| io_at(candidate_path, e))?;
    if !candidate_meta.file_type().is_file() {
        return Err(LinuxUpdateError::NotExecutable(
            candidate_path.to_path_buf(),
        ));
    }
    if candidate_meta.len() != expected_length {
        return Err(LinuxUpdateError::LengthMismatch {
            expected: expected_length,
            received: candidate_meta.len(),
        });
    }

    let name = current
        .path
        .file_name()
        .ok_or_else(|| LinuxUpdateError::NoParent(current.path.clone()))?
        .to_string_lossy();
    let stem = format!(".{name}.conman-update-{}", operation_id.as_hex());
    let partial_path = parent.join(format!("{stem}.partial"));
    let ready_path = parent.join(format!("{stem}.ready"));

    let mut partial = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o700)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&partial_path)
        .map_err(|e| io_at(&partial_path, e))?;
    let copy_result = (|| {
        let mut reader = candidate;
        let mut digest = Sha256::new();
        let mut received = 0_u64;
        let mut buffer = [0_u8; 128 * 1024];
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|e| io_at(candidate_path, e))?;
            if count == 0 {
                break;
            }
            received =
                received
                    .checked_add(count as u64)
                    .ok_or(LinuxUpdateError::LengthMismatch {
                        expected: expected_length,
                        received: u64::MAX,
                    })?;
            if received > expected_length {
                return Err(LinuxUpdateError::LengthMismatch {
                    expected: expected_length,
                    received,
                });
            }
            digest.update(&buffer[..count]);
            partial
                .write_all(&buffer[..count])
                .map_err(|e| io_at(&partial_path, e))?;
        }
        if received != expected_length {
            return Err(LinuxUpdateError::LengthMismatch {
                expected: expected_length,
                received,
            });
        }
        let digest: [u8; 32] = digest.finalize().into();
        if digest != expected_sha256 {
            return Err(LinuxUpdateError::HashMismatch);
        }
        partial.flush().map_err(|e| io_at(&partial_path, e))?;
        partial.sync_all().map_err(|e| io_at(&partial_path, e))?;
        validate_type2_appimage(&partial_path, &partial)?;
        Ok(())
    })();
    if let Err(error) = copy_result {
        drop(partial);
        let _ = fs::remove_file(&partial_path);
        return Err(error);
    }
    drop(partial);

    // Do not expose a ready file after the user has replaced the running image.
    let current_now = AppImageIdentity::capture_opened(&current.path)?;
    if !current.same_inode(&current_now) {
        let _ = fs::remove_file(&partial_path);
        return Err(LinuxUpdateError::IdentityChanged);
    }
    fs::rename(&partial_path, &ready_path).map_err(|e| io_at(&ready_path, e))?;
    sync_directory(parent)?;
    let ready_identity = AppImageIdentity::capture_opened(&ready_path)?;
    if ready_identity.byte_length != expected_length || ready_identity.sha256 != expected_sha256 {
        let _ = fs::remove_file(&ready_path);
        return Err(LinuxUpdateError::HashMismatch);
    }
    Ok(StagedAppImage {
        operation_id,
        partial_path,
        ready_path,
        identity: ready_identity,
    })
}

/// Name of the backup corresponding to a staged operation.  The caller must
/// keep this under the exact current image parent directory.
pub fn backup_path(
    current: &AppImageIdentity,
    operation_id: OperationId,
) -> Result<PathBuf, LinuxUpdateError> {
    let parent = current
        .path
        .parent()
        .ok_or_else(|| LinuxUpdateError::NoParent(current.path.clone()))?;
    let name = current
        .path
        .file_name()
        .ok_or_else(|| LinuxUpdateError::NoParent(current.path.clone()))?
        .to_string_lossy();
    Ok(parent.join(format!(".{name}.conman-backup-{}", operation_id.as_hex())))
}

/// Remove a staged artifact only when its name is the exact path generated for
/// the supplied current image and operation.  This is used by Cancel and
/// startup cleanup; it never follows a symlink.
pub fn discard_staged(
    current: &AppImageIdentity,
    operation_id: OperationId,
) -> Result<(), LinuxUpdateError> {
    let parent = current
        .path
        .parent()
        .ok_or_else(|| LinuxUpdateError::NoParent(current.path.clone()))?;
    let name = current
        .path
        .file_name()
        .ok_or_else(|| LinuxUpdateError::NoParent(current.path.clone()))?
        .to_string_lossy();
    let stem = format!(".{name}.conman-update-{}", operation_id.as_hex());
    for suffix in [".partial", ".ready"] {
        let path = parent.join(format!("{stem}{suffix}"));
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(LinuxUpdateError::Symlink(path));
            }
            Ok(_) => fs::remove_file(&path).map_err(|e| io_at(&path, e))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_at(&path, error)),
        }
    }
    sync_directory(parent)?;
    Ok(())
}

/// Spawn a package/document handoff with one path argument.  A successful
/// return means only that the desktop handler process was launched; it does
/// not mean the package transaction completed.
pub fn handoff_package(path: &Path) -> Result<Child, LinuxUpdateError> {
    let metadata = fs::symlink_metadata(path).map_err(|e| io_at(path, e))?;
    if !metadata.file_type().is_file() || path.is_symlink() {
        return Err(LinuxUpdateError::NotExecutable(path.to_path_buf()));
    }
    let mut command = Command::new("xdg-open");
    command.arg(path);
    command
        .spawn()
        .map_err(|e| LinuxUpdateError::Handoff(e.to_string()))
}

/// Build the exact fallback command used by [`handoff_package`].  Kept public
/// for deterministic tests and for a desktop portal adapter to use as its
/// fallback without duplicating argument policy.
pub fn package_handoff_command(path: &Path) -> Command {
    let mut command = Command::new("xdg-open");
    command.arg(path);
    command
}

/// `/proc/<pid>/stat` start-time field.  The process name may contain spaces
/// and parentheses, so parse from the final `)` before splitting fields.
pub fn process_start_identity(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/stat");
    let contents = fs::read_to_string(path).ok()?;
    let close = contents.rfind(") ")?;
    let rest = contents.get(close + 2..)?;
    // Field 3 starts after the comm field; starttime is field 22, therefore
    // index 19 in the remainder beginning at field 3.
    rest.split_whitespace().nth(19).map(ToOwned::to_owned)
}

/// Wait until the exact original process identity is gone.  Returning `true`
/// means the original process exited (or the pid was reused); `false` means a
/// bounded timeout and therefore no rename may be attempted.
pub fn wait_for_process_exit(pid: u32, start_identity: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match process_start_identity(pid) {
            Some(current) if current == start_identity => {
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => return true,
        }
    }
}

/// Atomically write a bounded internal state file (health token, plan result,
/// or helper result).  The target is created with mode 0600 and replaced only
/// by a same-directory rename.  Callers must supply a path in their validated
/// private update-state directory.
pub fn write_private_state(path: &Path, contents: &[u8]) -> Result<(), LinuxUpdateError> {
    if contents.len() > 64 * 1024 {
        return Err(LinuxUpdateError::LengthMismatch {
            expected: 64 * 1024,
            received: contents.len() as u64,
        });
    }
    let parent = path
        .parent()
        .ok_or_else(|| LinuxUpdateError::NoParent(path.to_path_buf()))?;
    let basename = path
        .file_name()
        .ok_or_else(|| LinuxUpdateError::NoParent(path.to_path_buf()))?;
    let temporary = parent.join(format!(".{}.partial", basename.to_string_lossy()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|e| io_at(&temporary, e))?;
    if let Err(error) = file
        .write_all(contents)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(io_at(&temporary, error));
    }
    drop(file);
    fs::rename(&temporary, path).map_err(|e| io_at(path, e))?;
    sync_directory(parent)
}

/// Read an internal file only if it is a mode-0600 regular file owned by the
/// current user.  This protects helper dispatch from an environment variable
/// becoming an arbitrary file-replacement primitive.
pub fn read_private_state(path: &Path, max_len: usize) -> Result<Vec<u8>, LinuxUpdateError> {
    let metadata = fs::symlink_metadata(path).map_err(|e| io_at(path, e))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != effective_uid()
        || metadata.len() > max_len as u64
    {
        return Err(LinuxUpdateError::InvalidMarker(path.to_path_buf()));
    }
    fs::read(path).map_err(|e| io_at(path, e))
}

fn open_nofollow_read(path: &Path) -> Result<File, LinuxUpdateError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| io_at(path, e))
}

fn validate_executable_regular(path: &Path, metadata: &Metadata) -> Result<(), LinuxUpdateError> {
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(LinuxUpdateError::NotExecutable(path.to_path_buf()));
    }
    Ok(())
}

fn digest_file(file: &File, path: &Path) -> Result<[u8; 32], LinuxUpdateError> {
    let mut reader = file.try_clone().map_err(|e| io_at(path, e))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| io_at(path, e))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = reader.read(&mut buffer).map_err(|e| io_at(path, e))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize().into())
}

fn validate_type2_appimage(path: &Path, file: &File) -> Result<(), LinuxUpdateError> {
    let metadata = file.metadata().map_err(|e| io_at(path, e))?;
    validate_executable_regular(path, &metadata)?;
    let mut reader = file.try_clone().map_err(|e| io_at(path, e))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| io_at(path, e))?;
    let mut magic = [0_u8; 4];
    reader.read_exact(&mut magic).map_err(|e| io_at(path, e))?;
    if magic != *b"\x7fELF" {
        return Err(LinuxUpdateError::NotType2AppImage(path.to_path_buf()));
    }
    Ok(())
}

fn directory_is_writable(path: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.file_type().is_dir() {
        return false;
    }
    let mode = metadata.permissions().mode();
    let writable_bits = if metadata.uid() == effective_uid() {
        mode & 0o200
    } else {
        mode & 0o022
    };
    writable_bits != 0
}

fn effective_uid() -> u32 {
    // Linux exposes the effective uid without requiring an unsafe libc call.
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                let mut values = line.strip_prefix("Uid:")?.split_whitespace();
                values.nth(1)?.parse().ok()
            })
        })
        .unwrap_or(u32::MAX)
}

fn sync_directory(path: &Path) -> Result<(), LinuxUpdateError> {
    let directory = File::open(path).map_err(|e| io_at(path, e))?;
    match directory.sync_all() {
        Ok(()) => Ok(()),
        // Some filesystems do not implement fsync for directories. Linux's
        // documented fallback is to continue when it is explicitly unsupported;
        // all other errors remain fatal at the durable rename boundary.
        Err(error) if matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOTSUP)) => Ok(()),
        Err(error) => Err(io_at(path, error)),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn executable_file(path: &Path, bytes: &[u8]) {
        let mut file = File::create(path).expect("fixture");
        file.write_all(bytes).expect("fixture bytes");
        file.sync_all().expect("fixture sync");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("fixture mode");
    }

    #[test]
    fn marker_rejects_duplicate_and_unknown_fields() {
        let directory = TempDir::new().expect("tempdir");
        let marker = directory.path().join("marker.json");
        fs::write(
            &marker,
            br#"{"schema":1,"product":"conman","kind":"deb","package":"conman","kind":"rpm"}"#,
        )
        .expect("marker");
        assert!(read_package_marker(&marker).is_none());
        fs::write(
            &marker,
            br#"{"schema":1,"product":"conman","kind":"deb","package":"conman","extra":1}"#,
        )
        .expect("marker");
        assert!(read_package_marker(&marker).is_none());
    }

    #[test]
    fn appimage_symlink_launch_resolves_but_identity_is_opened_nofollow() {
        let directory = TempDir::new().expect("tempdir");
        let real = directory.path().join("ConMan.AppImage");
        let alias = directory.path().join("current");
        executable_file(&real, b"\x7fELFfixture");
        std::os::unix::fs::symlink(&real, &alias).expect("symlink");
        let identity = AppImageIdentity::capture_resolved(&alias).expect("resolved image");
        assert_eq!(identity.path, real);
        assert!(AppImageIdentity::capture_opened(&alias).is_err());
    }

    #[test]
    fn read_only_appimage_is_download_only() {
        let directory = TempDir::new().expect("tempdir");
        let image = directory.path().join("ConMan.AppImage");
        executable_file(&image, b"\x7fELFfixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o500))
            .expect("read-only parent");
        let context = detect_install_context_at(
            Some(image.as_os_str()),
            &directory.path().join("missing-marker"),
            &directory.path().join("missing-flatpak"),
        );
        assert!(matches!(context, LinuxInstallContext::ReadOnlyAppImage(_)));
        assert!(!context.completion_is_replaceable());
        assert_eq!(
            context.completion_action(),
            LinuxCompletionAction::OpenDownloadedUpdate
        );
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("restore parent permissions");
    }

    #[test]
    fn nonregular_and_relative_appimage_values_are_not_authoritative() {
        let directory = TempDir::new().expect("tempdir");
        let marker = directory.path().join("missing-marker");
        let flatpak = directory.path().join("missing-flatpak");
        assert_eq!(
            detect_install_context_at(Some(OsStr::new("relative.AppImage")), &marker, &flatpak,),
            LinuxInstallContext::ArchiveOrUnknown
        );
        let folder = directory.path().join("folder.AppImage");
        fs::create_dir(&folder).expect("fixture directory");
        assert_eq!(
            detect_install_context_at(Some(folder.as_os_str()), &marker, &flatpak),
            LinuxInstallContext::ArchiveOrUnknown
        );
    }

    #[test]
    fn context_detection_uses_marker_after_invalid_appimage() {
        let directory = TempDir::new().expect("tempdir");
        let marker = directory.path().join("install-context.json");
        fs::write(
            &marker,
            br#"{"schema":1,"product":"conman","kind":"rpm","package":"conman"}"#,
        )
        .expect("marker");
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).expect("mode");
        // A fixture cannot claim root ownership as the ordinary user; the
        // conservative result must therefore stay unknown.
        assert_eq!(
            detect_install_context_at(
                Some(OsStr::new("relative.AppImage")),
                &marker,
                &directory.path().join("not-flatpak"),
            ),
            LinuxInstallContext::ArchiveOrUnknown
        );
    }

    #[test]
    fn operation_ids_are_lowercase_hex_and_nonrepeating() {
        let first = OperationId::random().expect("urandom");
        let second = OperationId::random().expect("urandom");
        assert_eq!(first.as_hex().len(), 32);
        assert!(first.as_hex().bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn staging_verifies_hash_length_and_uses_create_new_paths() {
        let directory = TempDir::new().expect("tempdir");
        let current_path = directory.path().join("ConMan.AppImage");
        let candidate_path = directory.path().join("candidate");
        executable_file(&current_path, b"\x7fELFold");
        executable_file(&candidate_path, b"\x7fELFnew!");
        let current = AppImageIdentity::capture_opened(&current_path).expect("current");
        let mut digest = Sha256::new();
        digest.update(b"\x7fELFnew!");
        let expected: [u8; 32] = digest.finalize().into();
        let staged = stage_appimage(
            &current,
            &candidate_path,
            OperationId::from_bytes([1; 16]),
            8,
            expected,
        )
        .expect("stage");
        assert!(staged.ready_path.exists());
        assert!(!staged.partial_path.exists());
        assert_eq!(staged.identity.sha256, expected);
        discard_staged(&current, staged.operation_id).expect("discard");
        assert!(!staged.ready_path.exists());
    }

    #[test]
    fn package_handoff_does_not_shell_split_paths() {
        let path = PathBuf::from("/tmp/a path/conman.deb");
        let command = package_handoff_command(&path);
        assert_eq!(command.get_program(), "xdg-open");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![path.as_os_str()]
        );
    }

    #[test]
    fn process_start_identity_has_expected_shape_for_self() {
        let identity = process_start_identity(std::process::id()).expect("self stat");
        assert!(!identity.is_empty());
        assert!(identity.bytes().all(|byte| byte.is_ascii_digit()));
    }

    #[test]
    fn private_state_is_atomic_and_mode_restricted() {
        let directory = TempDir::new().expect("tempdir");
        let state = directory.path().join("state");
        write_private_state(&state, b"token").expect("write state");
        let metadata = fs::symlink_metadata(&state).expect("state metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            read_private_state(&state, 64).expect("read state"),
            b"token"
        );
    }
}

//! Windows-only Velopack lifecycle and package adapter.
//!
//! P11.1 remains the update authority: this module never discovers a feed,
//! compares versions, or decides a channel.  It receives one already
//! authorized full package and gives that package to Velopack's apply engine.
//! The narrow lifecycle hooks are deliberately local and bounded so the
//! internal Velopack process forms can run before the public GUI parser.

#![cfg(target_os = "windows")]

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::mpsc::Sender;

use semver::Version;
use velopack::sources::UpdateSource;
use velopack::{
    UpdateInfo, UpdateManager, UpdateOptions, VelopackApp, VelopackAsset, VelopackAssetFeed,
};

pub const APP_ID: &str = "com.marcos0ft.conman";
pub const VELOPACK_VERSION: &str = "1.2.0";

/// The only Windows installation contexts for which this adapter may make a
/// completion handoff.  A standalone ZIP is deliberately represented as
/// `Portable`; an incomplete or tampered Velopack tree is `Unknown` and is
/// treated the same as portable by callers (check/download only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsInstallContext {
    /// A complete Velopack installation and its installation scope.
    Installed(InstallScope),
    /// A standalone portable ZIP tree, never mutated by this adapter.
    Portable,
    /// A missing or hostile package marker/layout; remain check-only.
    Unknown,
}

/// Exact internal arguments emitted by Velopack's Setup/Update.exe.
///
/// This predicate intentionally does not accept prefixes, public commands, or
/// arbitrary arguments as hooks.  The caller must dispatch this before public
/// GUI parsing and then terminate through `VelopackApp::run`.
#[must_use]
pub fn is_internal_hook(args: &[OsString]) -> bool {
    args.len() == 2
        && matches!(
            args[0].to_str().map(str::to_ascii_lowercase).as_deref(),
            Some(
                "--veloapp-install"
                    | "--veloapp-updated"
                    | "--veloapp-obsolete"
                    | "--veloapp-uninstall"
            )
        )
}

/// Run the minimal local Velopack startup path.
///
/// `set_auto_apply_on_startup(false)` is mandatory: P11.1's capsule and close
/// coordinator must authorize the external updater before a process exits.
pub fn run_startup_hooks() {
    let mut app = VelopackApp::build()
        .set_auto_apply_on_startup(false)
        .on_after_install_fast_callback(|version| hook_or_exit("install", &version))
        .on_after_update_fast_callback(|version| hook_or_exit("after", &version))
        .on_before_update_fast_callback(|version| hook_or_exit("before", &version))
        .on_before_uninstall_fast_callback(|version| hook_or_exit("uninstall", &version))
        .on_first_run(|version| {
            let _ = append_marker_event(&format!("first-run version={version}"));
        })
        .on_restarted(|version| {
            let _ = append_marker_event(&format!("restarted version={version}"));
        });
    app.run();
}

fn hook_or_exit(phase: &str, version: &Version) {
    if let Err(error) = run_lifecycle_hook(phase, version) {
        eprintln!("ConMan Windows {phase} hook failed: {error}");
        process::exit(70);
    }
}

/// Lifecycle hooks are the only Velopack callbacks that mutate installation
/// metadata.  A failure is fatal to the install/update transaction; no hook
/// silently reports success after PATH/ARP work failed.
pub fn run_lifecycle_hook(phase: &str, version: &Version) -> Result<(), String> {
    append_marker_event(&format!("hook-{phase}-begin version={version}"))?;
    let result = match phase {
        "install" => add_owned_path(),
        "before" => verify_owned_path(),
        "after" => verify_owned_path().and_then(|()| update_msi_arp_version(version)),
        "uninstall" => remove_owned_path(),
        _ => Err(format!("unknown Velopack lifecycle phase: {phase}")),
    };
    result?;
    append_marker_event(&format!("hook-{phase}-end version={version}"))
}

/// Immutable candidate fields that P11.1 has already authorized.
///
/// This adapter type intentionally contains no release-feed URL or selection
/// method.  The core may construct it from its `UpdateCandidate` and staged
/// package token at the composition boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedWindowsPackage {
    pub version: Version,
    pub channel: String,
    pub file_name: String,
    pub sha256: String,
    pub byte_length: u64,
    pub staged_path: PathBuf,
}

impl AuthorizedWindowsPackage {
    /// Construct the Velopack-facing package identity at the platform
    /// boundary. Callers must pass fields copied from one already verified
    /// P11.1 candidate; this constructor intentionally accepts no feed URL or
    /// channel-selection input.
    pub fn new(
        version: Version,
        channel: impl Into<String>,
        file_name: impl Into<String>,
        sha256: impl Into<String>,
        byte_length: u64,
        staged_path: PathBuf,
    ) -> Result<Self, String> {
        let channel = channel.into();
        if channel != "stable" && channel != "dev" {
            return Err("Windows Velopack channel must be stable or dev".into());
        }
        let file_name = file_name.into();
        if file_name.is_empty()
            || file_name.starts_with('.')
            || !file_name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
            })
            || !file_name.to_ascii_lowercase().ends_with("-full.nupkg")
        {
            return Err("Windows Velopack package name is not a full basename".into());
        }
        let sha256 = sha256.into();
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("Windows Velopack package hash is not SHA-256".into());
        }
        if byte_length == 0 {
            return Err("Windows Velopack package length must be non-zero".into());
        }
        Ok(Self {
            version,
            channel,
            file_name,
            sha256,
            byte_length,
            staged_path,
        })
    }

    fn asset(&self) -> VelopackAsset {
        VelopackAsset {
            PackageId: APP_ID.into(),
            Version: self.version.to_string(),
            Type: "Full".into(),
            FileName: self.file_name.clone(),
            SHA1: String::new(),
            SHA256: self.sha256.clone(),
            Size: self.byte_length,
            NotesMarkdown: String::new(),
            NotesHtml: String::new(),
        }
    }
}

/// Source constrained to exactly one P11.1-authorized full package.
#[derive(Debug, Clone)]
struct AuthorizedSource {
    package: AuthorizedWindowsPackage,
}

impl UpdateSource for AuthorizedSource {
    fn get_release_feed(
        &self,
        channel: &str,
        app: &velopack::bundle::Manifest,
        _staged_user_id: &str,
    ) -> Result<VelopackAssetFeed, velopack::Error> {
        if channel != self.package.channel || app.id != APP_ID {
            return Err(velopack::Error::NotSupported(
                "Velopack requested an unauthorized channel or app".into(),
            ));
        }
        Ok(VelopackAssetFeed {
            Assets: vec![self.package.asset()],
        })
    }

    fn download_release_entry(
        &self,
        asset: &VelopackAsset,
        local_file: &Path,
        progress_sender: Option<Sender<i16>>,
    ) -> Result<(), velopack::Error> {
        let expected = self.package.asset();
        if asset.PackageId != expected.PackageId
            || asset.Version != expected.Version
            || asset.Type != expected.Type
            || asset.FileName != expected.FileName
            || asset.SHA256 != expected.SHA256
            || asset.Size != expected.Size
        {
            return Err(velopack::Error::NotSupported(
                "Velopack requested content outside the authorized package".into(),
            ));
        }
        if !is_regular_file_no_symlink(&self.package.staged_path) {
            return Err(velopack::Error::FileNotFound(
                self.package.staged_path.clone(),
            ));
        }
        let mut input = File::open(&self.package.staged_path)?;
        let mut output = OpenOptions::new()
            // Velopack deliberately retries an interrupted download into the
            // same `.partial` path. Truncating that private package path is
            // required for recovery; the manager owns its location and
            // verifies the completed bytes against this exact asset below.
            .create(true)
            .truncate(true)
            .write(true)
            .open(local_file)?;
        let mut copied = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        if let Some(sender) = &progress_sender {
            let _ = sender.send(0);
        }
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            output.write_all(&buffer[..count])?;
            copied = copied.saturating_add(count as u64);
            if let Some(sender) = &progress_sender {
                let percent = copied
                    .saturating_mul(100)
                    .checked_div(expected.Size)
                    .unwrap_or(0);
                let _ = sender.send(i16::try_from(percent.min(100)).unwrap_or(100));
            }
        }
        output.flush()?;
        if copied != expected.Size {
            return Err(velopack::Error::NotSupported(
                "staged package length changed during Velopack handoff".into(),
            ));
        }
        if let Some(sender) = &progress_sender {
            let _ = sender.send(100);
        }
        Ok(())
    }
}

/// Build a Velopack manager around one immutable P11.1 candidate.
///
/// This does not call `check_for_updates`; the selected candidate has already
/// been ordered and authorized by `cm-update`.
pub fn manager_for(package: AuthorizedWindowsPackage) -> Result<UpdateManager, velopack::Error> {
    let options = UpdateOptions {
        AllowVersionDowngrade: false,
        ExplicitChannel: Some(package.channel.clone()),
        // Keep the release asset full-only until P11.1 represents every delta
        // byte in its signed manifest. Velopack remains free to use its own
        // safe full-package recovery path when a caller supplies a delta.
        MaximumDeltasBeforeFallback: -1,
    };
    UpdateManager::new(AuthorizedSource { package }, Some(options), None)
}

/// Download the already authorized full package and hand off after normal
/// process exit.  `restart_args` are the original public arguments and are
/// passed structurally to Velopack's updater.
pub fn download_and_wait_exit(
    manager: &UpdateManager,
    package: &AuthorizedWindowsPackage,
    restart_args: Vec<OsString>,
    progress_sender: Option<Sender<i16>>,
) -> Result<(), velopack::Error> {
    if manager.get_is_portable() {
        return Err(velopack::Error::NotSupported(
            "portable Windows packages are check/download-only".into(),
        ));
    }
    if manager.get_app_id() != APP_ID {
        return Err(velopack::Error::NotSupported(
            "installed package has an unexpected ConMan app ID".into(),
        ));
    }
    if package.version <= manager.get_current_version() {
        return Err(velopack::Error::NotSupported(
            "authorized Windows candidate is not newer than the installed version".into(),
        ));
    }
    if !is_regular_file_no_symlink(&package.staged_path) {
        return Err(velopack::Error::FileNotFound(package.staged_path.clone()));
    }
    let update = UpdateInfo {
        TargetFullRelease: package.asset(),
        BaseRelease: None,
        DeltasToTarget: Vec::new(),
        IsDowngrade: false,
    };
    manager.download_updates(&update, progress_sender)?;
    manager.wait_exit_then_apply_updates(&update.TargetFullRelease, true, true, restart_args)
}

fn root_dir() -> Result<PathBuf, String> {
    let executable = std::env::current_exe().map_err(io_error)?;
    let current = executable.parent().ok_or("executable has no parent")?;
    current
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "Velopack current directory has no root".into())
}

fn owned_path_entry() -> Result<String, String> {
    let executable = std::env::current_exe().map_err(io_error)?;
    Ok(executable
        .parent()
        .ok_or("executable has no parent")?
        .join("bin")
        .to_string_lossy()
        .into_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallScope {
    /// Installed below the current user's profile and updated without UAC.
    User,
    /// Installed below the machine Program Files root and updated at UAC boundary.
    Machine,
}

/// Detect the Velopack root and install context without invoking Velopack's
/// updater or touching package contents. This is intentionally conservative:
/// only the complete `Update.exe` + `current/sq.version` layout is installed;
/// every other executable tree remains check/download-only.
pub fn detect_install_context() -> WindowsInstallContext {
    let Ok(executable) = std::env::current_exe() else {
        return WindowsInstallContext::Unknown;
    };
    detect_install_context_at(&executable)
}

/// Testable install-context detector. A `.portable` marker is accepted only
/// when it is a regular file; symlinked or directory markers are hostile and
/// therefore become `Unknown` rather than authorizing replacement.
pub fn detect_install_context_at(executable: &Path) -> WindowsInstallContext {
    let Some(parent) = executable.parent() else {
        return WindowsInstallContext::Unknown;
    };
    if !is_regular_file_no_symlink(executable) {
        return WindowsInstallContext::Unknown;
    }
    let (root, in_current) = if parent
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("current"))
    {
        (parent.parent().unwrap_or(parent), true)
    } else {
        (parent, false)
    };
    let current_dir = root.join("current");
    if !is_directory_no_symlink(root)
        || (in_current && !is_directory_no_symlink(current_dir.as_path()))
    {
        return WindowsInstallContext::Unknown;
    }
    let portable = root.join(".portable");
    if let Ok(metadata) = fs::symlink_metadata(&portable) {
        return if metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
            WindowsInstallContext::Portable
        } else {
            WindowsInstallContext::Unknown
        };
    }
    let update = root.join("Update.exe");
    let manifest = root.join("current").join("sq.version");
    if in_current && is_regular_file_no_symlink(&update) && is_regular_file_no_symlink(&manifest) {
        return WindowsInstallContext::Installed(install_scope_for_path(executable));
    }
    // A ZIP extracted without a marker has no updater layout and is therefore
    // portable for first-release purposes. If it has a partial updater layout,
    // keep it unknown so no writable tree is ever mutated accidentally.
    if !update.exists() && !manifest.exists() {
        WindowsInstallContext::Portable
    } else {
        WindowsInstallContext::Unknown
    }
}

fn is_regular_file_no_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn is_directory_no_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_dir() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn install_scope_for_path(executable: &Path) -> InstallScope {
    let Some(program_files) = std::env::var_os("ProgramFiles") else {
        return InstallScope::User;
    };
    let Ok(executable) = executable.canonicalize() else {
        return InstallScope::User;
    };
    let Ok(program_files) = PathBuf::from(program_files).canonicalize() else {
        return InstallScope::User;
    };
    if executable.starts_with(program_files) {
        InstallScope::Machine
    } else {
        InstallScope::User
    }
}

fn install_scope() -> Result<InstallScope, String> {
    let executable = std::env::current_exe().map_err(io_error)?;
    Ok(install_scope_for_path(&executable))
}

fn path_key(scope: InstallScope) -> Result<(winreg::RegKey, &'static str), String> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
    let (hive, subkey) = match scope {
        InstallScope::User => (RegKey::predef(HKEY_CURRENT_USER), "Environment"),
        InstallScope::Machine => (
            RegKey::predef(HKEY_LOCAL_MACHINE),
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        ),
    };
    hive.open_subkey_with_flags(subkey, KEY_READ | KEY_WRITE)
        .map(|key| (key, "Path"))
        .map_err(io_error)
}

#[derive(Debug, Clone)]
struct RegistryPathValue {
    text: String,
    vtype: winreg::enums::RegType,
    /// Number of UTF-16 NUL code units at the end of the registry value.
    /// Keeping this representation detail lets uninstall preserve a normal
    /// value byte-for-byte when no unrelated editor touched PATH.
    terminators: usize,
}

fn read_path(scope: InstallScope) -> Result<Option<RegistryPathValue>, String> {
    use winreg::enums::{REG_EXPAND_SZ, REG_SZ};
    let (key, value_name) = path_key(scope)?;
    match key.get_raw_value(value_name) {
        Ok(value) => {
            if value.vtype != REG_SZ && value.vtype != REG_EXPAND_SZ {
                return Err("PATH registry value is not REG_SZ or REG_EXPAND_SZ".into());
            }
            if value.bytes.len() % 2 != 0 {
                return Err("PATH registry value has invalid UTF-16 bytes".into());
            }
            let mut words = value
                .bytes
                .chunks_exact(2)
                .map(|part| u16::from_le_bytes([part[0], part[1]]))
                .collect::<Vec<_>>();
            let mut terminators = 0;
            while words.last() == Some(&0) {
                words.pop();
                terminators += 1;
            }
            let text = String::from_utf16(&words)
                .map_err(|_| "PATH registry value contains invalid UTF-16".to_owned())?;
            if text.contains('\0') {
                return Err("PATH registry value contains an embedded NUL".into());
            }
            Ok(Some(RegistryPathValue {
                text,
                vtype: value.vtype,
                terminators,
            }))
        }
        Err(error) if error.raw_os_error() == Some(2) => Ok(None),
        Err(error) => Err(io_error(error)),
    }
}

fn write_path(
    scope: InstallScope,
    value: Option<(&str, winreg::enums::RegType, usize)>,
) -> Result<(), String> {
    let (key, value_name) = path_key(scope)?;
    match value {
        Some((text, vtype, terminators)) => {
            let mut words = text.encode_utf16().collect::<Vec<_>>();
            words.extend(std::iter::repeat_n(0, terminators));
            let bytes = words
                .into_iter()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            key.set_raw_value(value_name, &winreg::RegValue { bytes, vtype })
                .map_err(io_error)?;
        }
        None => key.delete_value(value_name).map_err(io_error)?,
    }
    broadcast_environment_change();
    Ok(())
}

fn add_owned_path() -> Result<(), String> {
    let scope = install_scope()?;
    let entry = owned_path_entry()?;
    let root = root_dir()?;
    let marker_path = root.join("conman-path.marker");
    let original = read_path(scope)?;
    let existing_count = path_components(original.as_ref().map_or("", |value| value.text.as_str()))
        .iter()
        .filter(|part| part.eq_ignore_ascii_case(&entry))
        .count();
    if existing_count > 1 {
        return Err("ConMan PATH entry is duplicated before install".into());
    }
    if existing_count == 1 {
        let marker = read_path_marker(&marker_path)?;
        if marker.scope == scope_name(scope)
            && marker.entry.eq_ignore_ascii_case(&entry)
            && marker.value_type
                == path_type_name(&original.as_ref().expect("entry implies value").vtype)
        {
            return Ok(());
        }
        return Err("ConMan PATH entry exists without a matching owned marker".into());
    }
    if marker_path.exists() {
        return Err("ConMan PATH marker exists while its PATH entry is absent".into());
    }
    let updated = match &original {
        None => entry.clone(),
        Some(value) if value.text.is_empty() => entry.clone(),
        Some(value) if value.text.ends_with(';') => format!("{}{entry}", value.text),
        Some(value) => format!("{};{entry}", value.text),
    };
    let value_type = original
        .as_ref()
        .map_or(winreg::enums::REG_EXPAND_SZ, |value| value.vtype.clone());
    let marker = PathMarker {
        scope: scope_name(scope).to_owned(),
        value_type: path_type_name(&value_type).to_owned(),
        terminators: original.as_ref().map_or(1, |value| value.terminators),
        entry: entry.clone(),
    };
    write_path_marker(&marker_path, &marker)?;
    if let Err(error) = write_path(scope, Some((&updated, value_type, marker.terminators))) {
        let _ = fs::remove_file(&marker_path);
        return Err(error);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PathMarker {
    scope: String,
    value_type: String,
    terminators: usize,
    entry: String,
}

fn path_type_name(value_type: &winreg::enums::RegType) -> &'static str {
    if *value_type == winreg::enums::REG_EXPAND_SZ {
        "expand"
    } else {
        "string"
    }
}

fn write_path_marker(path: &Path, marker: &PathMarker) -> Result<(), String> {
    let contents = format!(
        "scope={scope}\ntype={value_type}\nterminators={terminators}\nentry={entry}\n",
        scope = marker.scope,
        value_type = marker.value_type,
        terminators = marker.terminators,
        entry = marker.entry,
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(io_error)?;
    file.write_all(contents.as_bytes()).map_err(io_error)?;
    file.flush().map_err(io_error)
}

fn read_path_marker(path: &Path) -> Result<PathMarker, String> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("ConMan PATH marker is not a regular file".into());
    }
    if metadata.len() > 64 * 1024 {
        return Err("ConMan PATH marker is too large".into());
    }
    let text = fs::read_to_string(path).map_err(io_error)?;
    let mut scope = None;
    let mut value_type = None;
    let mut terminators = None;
    let mut entry = None;
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or("ConMan PATH marker has a malformed line")?;
        let slot = match key {
            "scope" => &mut scope,
            "type" => &mut value_type,
            "terminators" => &mut terminators,
            "entry" => &mut entry,
            _ => return Err("ConMan PATH marker has an unknown field".into()),
        };
        if slot.is_some() {
            return Err("ConMan PATH marker has a duplicate field".into());
        }
        *slot = Some(value.to_owned());
    }
    let scope = scope.ok_or("ConMan PATH marker has no scope")?;
    let value_type = value_type.ok_or("ConMan PATH marker has no value type")?;
    let terminators = terminators
        .ok_or("ConMan PATH marker has no terminator count")?
        .parse::<usize>()
        .map_err(|_| "ConMan PATH marker has an invalid terminator count")?;
    if terminators > 32 * 1024 {
        return Err("ConMan PATH marker has too many terminators".into());
    }
    let entry = entry.ok_or("ConMan PATH marker has no entry")?;
    if scope != "user" && scope != "machine" {
        return Err("ConMan PATH marker has an invalid scope".into());
    }
    if value_type != "expand" && value_type != "string" {
        return Err("ConMan PATH marker has an invalid value type".into());
    }
    if entry.is_empty() || entry.contains(['\0', '\r', '\n', ';']) {
        return Err("ConMan PATH marker has an invalid entry".into());
    }
    Ok(PathMarker {
        scope,
        value_type,
        terminators,
        entry,
    })
}

fn verify_owned_path() -> Result<(), String> {
    let entry = owned_path_entry()?;
    let scope = install_scope()?;
    let marker = read_path_marker(&root_dir()?.join("conman-path.marker"))?;
    if marker.scope != scope_name(scope) || !marker.entry.eq_ignore_ascii_case(&entry) {
        return Err("ConMan PATH marker does not match the installed root".into());
    }
    let current = read_path(scope)?;
    let count = path_components(current.as_ref().map_or("", |value| value.text.as_str()))
        .iter()
        .filter(|part| part.eq_ignore_ascii_case(&entry))
        .count();
    if count != 1 {
        return Err(format!("ConMan PATH entry count is {count}, expected one"));
    }
    Ok(())
}

fn remove_owned_path() -> Result<(), String> {
    let marker_path = root_dir()?.join("conman-path.marker");
    let marker = read_path_marker(&marker_path)?;
    let expected_scope = install_scope()?;
    let expected_entry = owned_path_entry()?;
    if marker.scope != scope_name(expected_scope)
        || !marker.entry.eq_ignore_ascii_case(&expected_entry)
    {
        return Err("ConMan PATH marker does not match the installed root".into());
    }
    let Some(current) = read_path(expected_scope)? else {
        // A user/admin may have removed PATH entirely after installation. Do
        // not recreate it during uninstall; only retire ConMan's marker.
        fs::remove_file(marker_path).map_err(io_error)?;
        return Ok(());
    };
    let count = path_components(&current.text)
        .iter()
        .filter(|part| part.eq_ignore_ascii_case(&marker.entry))
        .count();
    if count > 1 {
        return Err(format!(
            "ConMan PATH entry count is {count}, expected at most one"
        ));
    }
    if count == 1 {
        let updated = remove_exact_component(&current.text, &marker.entry)?;
        write_path(
            expected_scope,
            Some((&updated, current.vtype, current.terminators)),
        )?;
    }
    fs::remove_file(marker_path).map_err(io_error)
}

fn scope_name(scope: InstallScope) -> &'static str {
    match scope {
        InstallScope::User => "user",
        InstallScope::Machine => "machine",
    }
}

fn path_components(value: &str) -> Vec<&str> {
    value.split(';').filter(|part| !part.is_empty()).collect()
}

fn remove_exact_component(value: &str, target: &str) -> Result<String, String> {
    let mut matches = Vec::new();
    let mut start = 0usize;
    for component in value.split(';') {
        let end = start + component.len();
        if component.eq_ignore_ascii_case(target) {
            matches.push((start, end));
        }
        start = end + 1;
    }
    if matches.len() != 1 {
        return Err(format!(
            "ConMan PATH entry count is {}, expected one",
            matches.len()
        ));
    }
    let (start, end) = matches[0];
    let (remove_start, remove_end) = if start > 0 {
        (start - 1, end)
    } else if end < value.len() {
        (start, end + 1)
    } else {
        (start, end)
    };
    let mut updated = String::with_capacity(value.len() - (remove_end - remove_start));
    updated.push_str(&value[..remove_start]);
    updated.push_str(&value[remove_end..]);
    Ok(updated)
}

fn update_msi_arp_version(version: &Version) -> Result<(), String> {
    use winreg::RegKey;
    use winreg::enums::{
        HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY,
    };
    let hive = match install_scope()? {
        InstallScope::User => RegKey::predef(HKEY_CURRENT_USER),
        InstallScope::Machine => RegKey::predef(HKEY_LOCAL_MACHINE),
    };
    let uninstall = format!(r"Software\Microsoft\Windows\CurrentVersion\Uninstall\MSI:{APP_ID}");
    // Velopack's MSI creates a synthetic visible ARP key. Setup installs do
    // not have that key and need no ARP update; an access error is fatal so a
    // machine update cannot silently report success with stale metadata.
    let key = match hive.open_subkey_with_flags(&uninstall, KEY_READ | KEY_WOW64_64KEY) {
        Ok(_) => hive
            .open_subkey_with_flags(&uninstall, KEY_SET_VALUE | KEY_WOW64_64KEY)
            .map_err(io_error)?,
        Err(error) if error.raw_os_error() == Some(2) => return Ok(()),
        Err(error) => return Err(io_error(error)),
    };
    key.set_value("DisplayVersion", &version.to_string())
        .map_err(io_error)
}

fn marker_path() -> Result<PathBuf, String> {
    Ok(root_dir()?.join("conman-windows-events.log"))
}

fn append_marker_event(event: &str) -> Result<(), String> {
    let path = marker_path()?;
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (!metadata.file_type().is_file() || metadata.file_type().is_symlink())
    {
        return Err("ConMan Windows event marker is not a regular file".into());
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(io_error)?;
    writeln!(file, "pid={} event={event}", process::id()).map_err(io_error)
}

fn broadcast_environment_change() {
    use windows_sys::Win32::Foundation::{LPARAM, WPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
    };
    let mut environment = "Environment".encode_utf16().collect::<Vec<_>>();
    environment.push(0);
    // This bounded notification is the only unsafe native call in this module;
    // it cannot execute arbitrary code and aborts if a receiver is hung.
    unsafe {
        let _ = SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            WPARAM::default(),
            environment.as_ptr() as LPARAM,
            SMTO_ABORTIFHUNG,
            1000,
            std::ptr::null_mut(),
        );
    }
}

fn io_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn hooks_require_an_exact_internal_form() {
        assert!(is_internal_hook(&[
            OsString::from("--veloapp-updated"),
            OsString::from("1.2.0")
        ]));
        assert!(!is_internal_hook(&[OsString::from("--veloapp-updated")]));
        assert!(!is_internal_hook(&[
            OsString::from("--veloapp-updated-extra"),
            OsString::from("1.2.0")
        ]));
        assert!(!is_internal_hook(&[
            OsString::from("--help"),
            OsString::from("x")
        ]));
    }

    #[test]
    fn path_removal_preserves_unrelated_components() {
        let value = r"A;C:\ConMan\current\bin;B;;";
        assert_eq!(
            remove_exact_component(value, r"C:\ConMan\current\bin").unwrap(),
            "A;B;;"
        );
    }

    #[test]
    fn authorized_package_rejects_ambiguous_identity() {
        let path = PathBuf::from(r"C:\Users\tester\Downloads\update.nupkg");
        assert!(
            AuthorizedWindowsPackage::new(
                Version::parse("1.2.0").unwrap(),
                "stable",
                "../other-full.nupkg",
                "a".repeat(64),
                1,
                path.clone(),
            )
            .is_err()
        );
        assert!(
            AuthorizedWindowsPackage::new(
                Version::parse("1.2.0").unwrap(),
                "stable",
                "conman-1.2.0-stable-full.nupkg",
                "a".repeat(64),
                1,
                path,
            )
            .is_ok()
        );
        assert!(
            AuthorizedWindowsPackage::new(
                Version::parse("1.2.0").unwrap(),
                "stable",
                "conman-1.2.0-stable-full.nupkg",
                "A".repeat(64),
                1,
                PathBuf::from(r"C:\Users\tester\Downloads\update.nupkg"),
            )
            .is_err()
        );
    }

    #[test]
    fn install_context_is_conservative_about_markers() {
        let root = tempfile::tempdir().unwrap();
        let portable_exe = root.path().join("conman.exe");
        fs::write(&portable_exe, b"probe").unwrap();
        assert_eq!(
            detect_install_context_at(&portable_exe),
            WindowsInstallContext::Portable
        );

        fs::create_dir(root.path().join(".portable")).unwrap();
        assert_eq!(
            detect_install_context_at(&portable_exe),
            WindowsInstallContext::Unknown
        );
        fs::remove_dir(root.path().join(".portable")).unwrap();

        fs::write(root.path().join(".portable"), b"portable").unwrap();
        assert_eq!(
            detect_install_context_at(&portable_exe),
            WindowsInstallContext::Portable
        );
    }

    #[test]
    fn install_context_rejects_symlinked_velopack_markers() {
        let root = tempfile::tempdir().unwrap();
        let current = root.path().join("current");
        let target = root.path().join("target");
        fs::create_dir(&current).unwrap();
        fs::create_dir(&target).unwrap();
        let executable = current.join("conman.exe");
        let target_executable = target.join("conman.exe");
        fs::write(&target_executable, b"probe").unwrap();
        fs::write(&executable, b"probe").unwrap();
        fs::write(current.join("sq.version"), b"1.0.0").unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target_executable, &root.path().join("Update.exe"))
                .unwrap();
            assert_eq!(
                detect_install_context_at(&executable),
                WindowsInstallContext::Unknown
            );
        }
    }

    #[test]
    fn authorized_source_exposes_only_the_signed_full_asset() {
        let source_dir = tempfile::tempdir().unwrap();
        let staged = source_dir.path().join("authorized-full.nupkg");
        fs::write(&staged, b"package").unwrap();
        let package = AuthorizedWindowsPackage::new(
            Version::parse("1.2.0").unwrap(),
            "dev",
            "conman-1.2.0-dev-full.nupkg",
            "a".repeat(64),
            7,
            staged,
        )
        .unwrap();
        let source = AuthorizedSource { package };
        let app = velopack::bundle::Manifest {
            id: APP_ID.to_owned(),
            ..Default::default()
        };
        let feed = source.get_release_feed("dev", &app, "test").unwrap();
        assert_eq!(feed.Assets.len(), 1);
        let destination = source_dir.path().join("destination.nupkg");
        fs::write(&destination, b"stale-partial-download").unwrap();
        source
            .download_release_entry(&feed.Assets[0], &destination, None)
            .unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"package");
        let mut unauthorized = feed.Assets[0].clone();
        unauthorized.FileName = "other-1.2.0-dev-full.nupkg".to_owned();
        assert!(
            source
                .download_release_entry(&unauthorized, &destination, None)
                .is_err()
        );
        assert!(!destination.exists());
    }
}

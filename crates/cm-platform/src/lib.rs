//! `cm-platform` — OS plumbing for ConMan.
//!
//! Confines operating-system-specific behavior to one place: data and config
//! directory resolution, the single-instance guard, clipboard access, and DPI
//! helpers. Keeps the core and UI platform-agnostic.
//!
//! # Current scope
//!
//! - [`app_db_path`] / [`app_log_dir`]: OS-standard per-user data directory
//!   resolution (P1.5, extended for logging in P6.3).
//! - [`app_config_path`] / [`TextConfigStore`]: the user-editable
//!   `conman.ini` document and its line-preserving persistence adapter.
//! - [`single_instance`]: an identity-scoped OS advisory lock plus a loopback
//!   activation handshake (P6.16); see the module docs for the protocol.
//! - [`accent`]: OS accent-color read + best-effort live watch (P6.8, gap 10).
//!   Clipboard access and DPI helpers remain unimplemented (not yet scheduled).
//! - [`console`]: terminal ANSI/VT capability detection plus parent-console
//!   output for help/version from the release Windows GUI executable.

pub mod accent;
pub mod config;
pub mod console;
mod error;
mod safe_lock;
pub mod secure_temp;
pub mod single_instance;

pub use config::{
    ConfigDiagnostic, ConfigDiagnosticLevel, ConfigDocument, TextConfigStore, read_config_file,
    validate_config_document, write_config_file_noclobber,
};
pub use console::{stderr_supports_ansi, write_stderr_line, write_stdout_line};
pub use error::PlatformError;

use std::path::PathBuf;
use std::process::Command;

/// Environment override for the editable application configuration path.
pub const CONFIG_PATH_ENV_VAR: &str = "CONMAN_CONFIG_PATH";

/// Environment override for the SQLite database path.
pub const DB_PATH_ENV_VAR: &str = "CONMAN_DB_PATH";

/// Returns `<OS data dir>/conman`, creating it if it does not exist.
///
/// Shared by [`app_db_path`] and [`app_log_dir`]. Uses the `dirs` crate (P6.3:
/// consolidated with `cm-session`/`cm-ui`, which already depended on it — see
/// gap 29 / `memos/P6.3-*`; the prior `directories`-crate resolution here had
/// the smaller call-site footprint to move).
fn conman_data_dir() -> Result<PathBuf, PlatformError> {
    let base = dirs::data_dir().ok_or(PlatformError::NoDataDir)?;
    let dir = base.join("conman");
    std::fs::create_dir_all(&dir)
        .map_err(|e| PlatformError::DataDirCreate(dir.clone(), e.to_string()))?;
    Ok(dir)
}

/// Returns the path to ConMan's user-editable `conman.ini` file.
///
/// Resolution order:
/// 1. `CONMAN_CONFIG_PATH`, when set.
/// 2. `<OS config dir>/conman/conman.ini`.
///
/// The parent directory is created before the path is returned.
pub fn app_config_path() -> Result<PathBuf, PlatformError> {
    resolve_config_path(std::env::var_os(CONFIG_PATH_ENV_VAR).map(PathBuf::from))
}

/// Resolve the effective config path without creating or opening anything.
///
/// The GUI composition root uses this to derive its identity-scoped instance
/// lock before the selected config path is touched.
pub fn app_config_path_candidate() -> Result<PathBuf, PlatformError> {
    if let Some(path) = std::env::var_os(CONFIG_PATH_ENV_VAR) {
        return Ok(PathBuf::from(path));
    }
    let base = dirs::config_dir().ok_or(PlatformError::NoConfigDir)?;
    Ok(base.join("conman").join("conman.ini"))
}

/// Create the parent directory for a previously resolved config candidate.
pub fn prepare_app_config_path(path: PathBuf) -> Result<PathBuf, PlatformError> {
    ensure_parent_dir(&path)?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        restrict_directory_permissions(parent);
    }
    Ok(path)
}

/// Opens a file or directory with the operating system's default handler.
///
/// The handler process is reaped in the background; this call returns once it
/// has launched successfully and never blocks the UI waiting for an editor.
pub fn open_path(path: impl Into<PathBuf>) -> Result<(), PlatformError> {
    let path = path.into();
    let mut command = platform_open_command(&path);
    let mut child = command
        .spawn()
        .map_err(|error| PlatformError::PathOpen(path.clone(), error.to_string()))?;
    let _reaper = std::thread::spawn(move || {
        if let Err(error) = child.wait() {
            tracing::warn!(%error, "failed to reap OS file handler");
        }
    });
    Ok(())
}

#[cfg(target_os = "windows")]
fn platform_open_command(path: &std::path::Path) -> Command {
    let mut command = Command::new("explorer.exe");
    command.arg(path);
    command
}

#[cfg(target_os = "macos")]
fn platform_open_command(path: &std::path::Path) -> Command {
    let mut command = Command::new("open");
    command.arg(path);
    command
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn platform_open_command(path: &std::path::Path) -> Command {
    let mut command = Command::new("xdg-open");
    command.arg(path);
    command
}

fn resolve_config_path(config_path_override: Option<PathBuf>) -> Result<PathBuf, PlatformError> {
    if let Some(path) = config_path_override {
        ensure_parent_dir(&path)?;
        return Ok(path);
    }

    let base = dirs::config_dir().ok_or(PlatformError::NoConfigDir)?;
    let dir = base.join("conman");
    std::fs::create_dir_all(&dir)
        .map_err(|error| PlatformError::ConfigDirCreate(dir.clone(), error.to_string()))?;
    restrict_directory_permissions(&dir);
    Ok(dir.join("conman.ini"))
}

fn ensure_parent_dir(path: &std::path::Path) -> Result<(), PlatformError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    std::fs::create_dir_all(parent)
        .map_err(|error| PlatformError::ConfigDirCreate(parent.to_path_buf(), error.to_string()))?;
    Ok(())
}

#[cfg(unix)]
fn restrict_directory_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)) {
        tracing::warn!(path = %path.display(), %error, "could not restrict config directory permissions");
    }
}

#[cfg(not(unix))]
fn restrict_directory_permissions(_path: &std::path::Path) {}

/// Returns the path to the application SQLite database file.
///
/// Resolution order:
/// 1. `CONMAN_DB_PATH` environment variable (useful for tests and CI).
/// 2. `<OS data dir>/conman/conman.sqlite`.
///
/// The parent directory is created if it does not exist.
///
/// # Errors
/// Returns [`PlatformError`] when no data directory can be determined or the
/// directory cannot be created.
pub fn app_db_path() -> Result<PathBuf, PlatformError> {
    resolve_db_path(std::env::var(DB_PATH_ENV_VAR).ok())
}

/// Resolve the effective database path without creating or opening anything.
///
/// The GUI composition root uses this alongside
/// [`app_config_path_candidate`] to derive its instance identity.
pub fn app_db_path_candidate() -> Result<PathBuf, PlatformError> {
    if let Some(path) = std::env::var_os(DB_PATH_ENV_VAR) {
        return Ok(PathBuf::from(path));
    }
    let base = dirs::data_dir().ok_or(PlatformError::NoDataDir)?;
    Ok(base.join("conman").join("conman.sqlite"))
}

/// Create the parent directory for a previously resolved database candidate.
pub fn prepare_app_db_path(path: PathBuf) -> Result<PathBuf, PlatformError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|error| {
            PlatformError::DataDirCreate(parent.to_path_buf(), error.to_string())
        })?;
    }
    Ok(path)
}

/// The override-vs-default decision behind [`app_db_path`], split out so it
/// is unit-testable without mutating the real process env var (which would
/// need `unsafe` since Rust 2024, and race other tests in this binary).
fn resolve_db_path(db_path_override: Option<String>) -> Result<PathBuf, PlatformError> {
    // Env override takes precedence (tests, headless CI, power-user override).
    if let Some(p) = db_path_override {
        let path = PathBuf::from(p);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| PlatformError::DataDirCreate(parent.to_path_buf(), e.to_string()))?;
        }
        return Ok(path);
    }

    Ok(conman_data_dir()?.join("conman.sqlite"))
}

/// Returns `<OS data dir>/conman/logs`, the directory the release-build
/// rotating file log layer writes into (P6.3 — `windows_subsystem = "windows"`
/// swallows stderr in release, so this is the only place release diagnostics
/// land). Created if it does not exist.
///
/// # Errors
/// Returns [`PlatformError`] when no data directory can be determined or the
/// directory cannot be created.
pub fn app_log_dir() -> Result<PathBuf, PlatformError> {
    let dir = conman_data_dir()?.join("logs");
    std::fs::create_dir_all(&dir)
        .map_err(|e| PlatformError::DataDirCreate(dir.clone(), e.to_string()))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P6.3 gap 29: the `directories` -> `dirs` consolidation must not change
    /// the CONMAN_DB_PATH override contract.
    #[test]
    fn resolve_db_path_honors_override() {
        let dir = std::env::temp_dir().join(format!("conman-test-{}", std::process::id()));
        let override_path = dir.join("nested").join("custom.sqlite");

        let resolved = resolve_db_path(Some(override_path.to_string_lossy().into_owned()))
            .expect("override path should resolve");
        assert_eq!(resolved, override_path);
        assert!(
            override_path.parent().unwrap().is_dir(),
            "parent dir of the override path must be created"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_db_path_defaults_to_conman_subdir_of_os_data_dir() {
        let resolved = resolve_db_path(None).expect("default path should resolve");
        assert_eq!(resolved.file_name().unwrap(), "conman.sqlite");
        assert_eq!(resolved.parent().unwrap().file_name().unwrap(), "conman");
    }

    #[test]
    fn resolve_config_path_honors_explicit_path() {
        let dir = std::env::temp_dir().join(format!("conman-config-test-{}", std::process::id()));
        let path = dir.join("nested").join("custom.conman");

        let resolved = resolve_config_path(Some(path.clone())).expect("path should resolve");
        assert_eq!(resolved, path);
        assert!(path.parent().unwrap().is_dir());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_config_path_defaults_to_conman_ini() {
        let resolved = resolve_config_path(None).expect("default path should resolve");
        assert_eq!(resolved.file_name().unwrap(), "conman.ini");
        assert_eq!(resolved.parent().unwrap().file_name().unwrap(), "conman");
    }

    #[test]
    fn platform_open_command_passes_path_as_one_argument() {
        let path = PathBuf::from("a path").join("conman.ini");
        let command = platform_open_command(&path);
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![path.as_os_str()]
        );

        #[cfg(target_os = "windows")]
        assert_eq!(command.get_program(), "explorer.exe");
        #[cfg(target_os = "macos")]
        assert_eq!(command.get_program(), "open");
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        assert_eq!(command.get_program(), "xdg-open");
    }
}

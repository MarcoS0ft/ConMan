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
//! - [`single_instance`]: the single-instance guard (P6.16) — a `std`-only
//!   loopback-TCP lock + activation handshake; see the module docs for the
//!   protocol.
//! - [`accent`]: OS accent-color read + best-effort live watch (P6.8, gap 10).
//!   Clipboard access and DPI helpers remain unimplemented (not yet scheduled).

pub mod accent;
mod error;
pub mod single_instance;

pub use error::PlatformError;

use std::path::PathBuf;

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
    resolve_db_path(std::env::var("CONMAN_DB_PATH").ok())
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
}

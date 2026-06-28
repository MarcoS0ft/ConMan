//! `cm-platform` — OS plumbing for ConMan.
//!
//! Confines operating-system-specific behavior to one place: data and config
//! directory resolution, the single-instance guard, clipboard access, and DPI
//! helpers. Keeps the core and UI platform-agnostic.

mod error;

pub use error::PlatformError;

use std::path::PathBuf;

/// Returns the path to the application SQLite database file.
///
/// Resolution order:
/// 1. `CONMAN_DB_PATH` environment variable (useful for tests and CI).
/// 2. `<OS data dir>/conman/conman.sqlite` via the `directories` crate.
///
/// The parent directory is created if it does not exist.
///
/// # Errors
/// Returns [`PlatformError`] when no data directory can be determined or the
/// directory cannot be created.
pub fn app_db_path() -> Result<PathBuf, PlatformError> {
    // Env override takes precedence (tests, headless CI, power-user override).
    if let Ok(p) = std::env::var("CONMAN_DB_PATH") {
        let path = PathBuf::from(p);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| PlatformError::DataDirCreate(parent.to_path_buf(), e.to_string()))?;
        }
        return Ok(path);
    }

    // Use the OS-standard per-user data directory.
    let proj =
        directories::ProjectDirs::from("io", "ConMan", "conman").ok_or(PlatformError::NoDataDir)?;
    let data_dir = proj.data_dir();
    std::fs::create_dir_all(data_dir)
        .map_err(|e| PlatformError::DataDirCreate(data_dir.to_path_buf(), e.to_string()))?;
    Ok(data_dir.join("conman.sqlite"))
}

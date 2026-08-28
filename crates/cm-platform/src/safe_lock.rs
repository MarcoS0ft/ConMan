//! Safe opened-handle primitives shared by advisory lock users.

use std::fs;
use std::path::Path;

pub(crate) fn reject_non_regular_lock_path(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing symbolic-link lock file {}", path.display()),
        )),
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("lock path is not a regular file: {}", path.display()),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) fn open_lock_file_unverified(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    configure_no_follow(&mut options);
    options.open(path)
}

pub(crate) fn verify_opened_lock_file(file: &fs::File, path: &Path) -> std::io::Result<()> {
    reject_opened_reparse_point(file, path)?;
    let clone = file.try_clone()?;
    let opened = same_file::Handle::from_file(clone)?;
    let named = same_file::Handle::from_path(path)?;
    if opened != named {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("lock file changed while opening {}", path.display()),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub(crate) fn open_lock_file(path: &Path) -> std::io::Result<fs::File> {
    reject_non_regular_lock_path(path)?;
    let file = open_lock_file_unverified(path)?;
    verify_opened_lock_file(&file, path)?;
    Ok(file)
}

#[cfg(unix)]
fn configure_no_follow(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
}

#[cfg(target_os = "windows")]
fn configure_no_follow(options: &mut fs::OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
}

#[cfg(not(any(unix, target_os = "windows")))]
fn configure_no_follow(_options: &mut fs::OpenOptions) {}

#[cfg(target_os = "windows")]
fn reject_opened_reparse_point(file: &fs::File, path: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::MetadataExt as _;
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let attributes = file.metadata()?.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing reparse-point lock file {}", path.display()),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn reject_opened_reparse_point(_file: &fs::File, _path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn no_follow_open_rejects_a_hostile_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let linked = directory.path().join("lock");
        fs::write(&target, b"victim").unwrap();
        symlink(&target, &linked).unwrap();
        assert!(open_lock_file(&linked).is_err());
        assert_eq!(fs::read(target).unwrap(), b"victim");
    }

    #[test]
    fn opened_handle_identity_rejects_a_regular_file_swap() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lock");
        let displaced = directory.path().join("displaced");
        fs::write(&path, b"original").unwrap();
        let file = open_lock_file_unverified(&path).unwrap();
        fs::rename(&path, &displaced).unwrap();
        fs::write(&path, b"replacement").unwrap();
        assert!(verify_opened_lock_file(&file, &path).is_err());
        assert_eq!(fs::read(displaced).unwrap(), b"original");
        assert_eq!(fs::read(path).unwrap(), b"replacement");
    }
}

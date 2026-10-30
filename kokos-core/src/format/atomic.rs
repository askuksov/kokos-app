//! Atomic save: temp + fsync + rename in the same directory.
//! A crash between temp and rename must leave the original file intact.

use std::io::Write;
use std::path::{Path, PathBuf};

use rand::Rng;

use crate::error::{Result, VaultError};

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or(VaultError::Io("path has no parent".into()))?;
    let suffix: u64 = rand::thread_rng().gen();
    let tmp: PathBuf = dir.join(format!(
        "{}.tmp-{:016x}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("vault"),
        suffix
    ));

    let result: Result<()> = (|| {
        let mut f = std::fs::File::create(&tmp)?;
        #[cfg(unix)]
        harden_permissions(&f, path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        rename_replacing(&tmp, path)
    })();

    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    if let Ok(d) = std::fs::File::open(dir) {
        d.sync_all()?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn rename_replacing(from: &Path, to: &Path) -> Result<()> {
    std::fs::rename(from, to)?;
    Ok(())
}

#[cfg(windows)]
fn rename_replacing(from: &Path, to: &Path) -> Result<()> {
    let mut last = None;
    for _ in 0..5 {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
    Err(VaultError::Io(last.map(|e| e.to_string()).unwrap_or_default()))
}

/// Aligns the temp file's mode with the file it is about to replace, before the
/// rename, so an atomic save never changes a vault's permissions.
///
/// `File::create` takes its mode from the process umask (commonly 0644 = world
/// readable), and POSIX `rename` does not carry over the replaced file's mode —
/// so without this, every save could silently widen the permissions of a file
/// holding real credentials. If `target` doesn't exist yet (a brand-new vault),
/// fall back to 0600 (owner read/write only): a password vault must not be born
/// world-readable.
#[cfg(unix)]
fn harden_permissions(f: &std::fs::File, target: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(target)
        .map(|m| m.permissions().mode())
        .unwrap_or(0o600);
    f.set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// The `.bak` path `backup()` writes to. Exposed so callers (`vault::save`'s
/// migrated-backup guard) can check its existence without duplicating the
/// suffixing logic and risking it drifting out of sync with `backup()` itself.
pub fn backup_path(path: &Path) -> PathBuf {
    let mut bak = path.as_os_str().to_owned();
    bak.push(".bak");
    PathBuf::from(bak)
}

pub fn backup(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    std::fs::copy(path, backup_path(path))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.vault");
        write_atomic(&p, b"hello").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"hello");
    }

    #[test]
    fn replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.vault");
        std::fs::write(&p, b"old").unwrap();
        write_atomic(&p, b"new").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
    }

    #[test]
    fn leaves_no_temp_files_behind() {
        let dir = tempfile::tempdir().unwrap();
        write_atomic(&dir.path().join("a.vault"), b"x").unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp file left behind: {:?}", leftovers);
    }

    #[test]
    fn backup_copies_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.vault");
        std::fs::write(&p, b"data").unwrap();
        backup(&p).unwrap();
        assert_eq!(std::fs::read(dir.path().join("a.vault.bak")).unwrap(), b"data");
    }

    #[test]
    fn backup_of_missing_file_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        backup(&dir.path().join("nope.vault")).unwrap();
        assert!(!dir.path().join("nope.vault.bak").exists());
    }

    #[cfg(unix)]
    #[test]
    fn replace_preserves_existing_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.vault");
        std::fs::write(&p, b"old").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();

        write_atomic(&p, b"new").unwrap();

        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "existing file mode must survive the atomic replace");
    }

    #[cfg(unix)]
    #[test]
    fn new_file_gets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.vault");

        write_atomic(&p, b"hello").unwrap();

        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a brand-new vault must not be born world-readable");
    }
}

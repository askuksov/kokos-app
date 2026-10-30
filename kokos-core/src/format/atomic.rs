//! Atomic save: temp + fsync + rename in the same directory.
//! A crash between temp and rename must leave the original file intact.

use std::io::Write;
use std::path::{Path, PathBuf};

use rand::Rng;

use crate::error::{Result, VaultError};

/// A random temp path next to `path`, so the final rename stays within one
/// directory (and one filesystem). The name is opaque, not derived from the
/// target's, so a long vault name cannot push it past the filename limit.
fn temp_sibling(path: &Path) -> Result<(&Path, PathBuf)> {
    let dir = path.parent().ok_or(VaultError::Io("path has no parent".into()))?;
    let suffix: u64 = rand::thread_rng().gen();
    let tmp: PathBuf = dir.join(format!(".kokos-{:016x}.tmp", suffix));
    Ok((dir, tmp))
}

/// Creates the temp file. On unix it is owner-only (0600) from the first
/// byte, so no other local user can open it before `harden_permissions` runs.
#[cfg(unix)]
fn create_temp(tmp: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(tmp)?)
}

#[cfg(not(unix))]
fn create_temp(tmp: &Path) -> Result<std::fs::File> {
    Ok(std::fs::File::create(tmp)?)
}

/// Best-effort: by now the rename has committed and the new file is what the
/// disk holds, so a failing directory fsync must not report the write as failed.
fn sync_dir(dir: &Path) {
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let (dir, tmp) = temp_sibling(path)?;

    let result: Result<()> = (|| {
        let mut f = create_temp(&tmp)?;
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

    sync_dir(dir);
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
/// The temp file starts as 0600, and POSIX `rename` does not carry over the
/// replaced file's mode — so without this, every save would reset the vault's
/// mode to 0600 instead of keeping it. If `target` doesn't exist yet (a brand-new vault),
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

/// The `.bak` path `backup()` writes to. Exposed so callers (e.g.
/// `vault::change_password` removing its transient backup) don't duplicate the
/// suffixing logic and risk it drifting out of sync with `backup()` itself.
pub fn backup_path(path: &Path) -> PathBuf {
    let mut bak = path.as_os_str().to_owned();
    bak.push(".bak");
    PathBuf::from(bak)
}

/// Copies `path` to its `.bak` the same way `write_atomic` writes: temp file,
/// fsync, rename. A crash or a full disk mid-copy therefore never leaves a
/// truncated `.bak` in place of a good one.
pub fn backup(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let bak = backup_path(path);
    let (dir, tmp) = temp_sibling(&bak)?;

    let result: Result<()> = (|| {
        let mut src = std::fs::File::open(path)?;
        let mut f = create_temp(&tmp)?;
        #[cfg(unix)]
        harden_permissions(&f, path)?;
        std::io::copy(&mut src, &mut f)?;
        f.sync_all()?;
        rename_replacing(&tmp, &bak)
    })();

    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    sync_dir(dir);
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
    fn backup_replaces_existing_bak_and_leaves_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.vault");
        std::fs::write(&p, b"fresh").unwrap();
        std::fs::write(backup_path(&p), b"stale").unwrap();
        backup(&p).unwrap();
        assert_eq!(std::fs::read(backup_path(&p)).unwrap(), b"fresh");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp file left behind: {:?}", leftovers);
    }

    #[test]
    fn long_vault_name_saves_and_backs_up() {
        let dir = tempfile::tempdir().unwrap();
        // 250 bytes: the `.bak` name still fits, a name-derived temp would not.
        let p = dir.path().join(format!("{}.vault", "a".repeat(244)));
        write_atomic(&p, b"long").unwrap();
        backup(&p).unwrap();
        assert_eq!(std::fs::read(backup_path(&p)).unwrap(), b"long");
    }

    #[cfg(unix)]
    #[test]
    fn temp_file_is_owner_only_from_creation() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let (_, tmp) = temp_sibling(&dir.path().join("a.vault")).unwrap();
        let _f = create_temp(&tmp).unwrap();
        let mode = std::fs::metadata(&tmp).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "temp file must not start world-readable");
        assert!(create_temp(&tmp).is_err(), "an existing temp path is never reused");
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

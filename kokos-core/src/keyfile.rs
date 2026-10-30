//! Key file support: KDF material is password || SHA256(keyfile).

use std::path::Path;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Result, VaultError};

/// A key file is only ever hashed, so anything past this is a wrong pick (or a
/// hostile path such as a device node), not a key: refuse instead of reading it
/// whole into memory.
const MAX_KEYFILE_BYTES: u64 = 16 * 1024 * 1024;

/// Streams the key file into SHA-256 through one fixed, wiped chunk buffer, so
/// no growing `Vec` leaves stray copies of key-file bytes behind on realloc or
/// on an error path. Only regular files are accepted: a FIFO or device node
/// could block the read forever or never end.
fn hash_capped(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    use std::io::Read;
    let is_file = |m: std::fs::Metadata| m.is_file();
    if !std::fs::metadata(path).map(is_file).unwrap_or(false) {
        return Err(VaultError::KeyfileUnreadable);
    }
    let mut f = std::fs::File::open(path).map_err(|_| VaultError::KeyfileUnreadable)?;
    // Re-check on the handle: the path may have been swapped since the stat.
    if !f.metadata().map(is_file).unwrap_or(false) {
        return Err(VaultError::KeyfileUnreadable);
    }

    let mut hasher = Sha256::new();
    let mut chunk = Zeroizing::new([0u8; 8192]);
    let mut total: u64 = 0;
    loop {
        let n = match f.read(chunk.as_mut()) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(VaultError::KeyfileUnreadable),
        };
        total += n as u64;
        if total > MAX_KEYFILE_BYTES {
            return Err(VaultError::KeyfileUnreadable);
        }
        hasher.update(&chunk[..n]);
    }
    let mut digest = hasher.finalize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    Ok(out)
}

pub fn key_material(password: &[u8], keyfile: Option<&Path>) -> Result<Zeroizing<Vec<u8>>> {
    let mut material = Zeroizing::new(password.to_vec());
    if let Some(path) = keyfile {
        // Defence in depth only: the real gate is the path allowlist every IPC
        // caller applies before reaching here. A picked key file is always an
        // absolute path with no `..`, so this never rejects a legitimate one.
        if path.components().any(|c| c == std::path::Component::ParentDir) {
            return Err(VaultError::PathNotAllowed);
        }
        let digest = hash_capped(path)?;
        material.extend_from_slice(digest.as_ref());
    }
    Ok(material)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn material_without_keyfile_is_password() {
        let m = key_material(b"pw", None).unwrap();
        assert_eq!(m.as_slice(), b"pw");
    }

    #[test]
    fn material_with_keyfile_appends_sha256() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"keyfile contents").unwrap();

        let m = key_material(b"pw", Some(f.path())).unwrap();
        assert_eq!(m.len(), 2 + 32, "password bytes followed by a 32-byte digest");
        assert_eq!(&m[..2], b"pw");

        use sha2::{Digest, Sha256};
        let expected = Sha256::digest(b"keyfile contents");
        assert_eq!(&m[2..], expected.as_slice());
    }

    #[test]
    fn parent_dir_component_is_rejected_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("kf"), b"k").unwrap();

        let traversal = dir.path().join("sub/../kf");
        let err = key_material(b"pw", Some(&traversal)).unwrap_err();
        assert!(matches!(err, VaultError::PathNotAllowed), "`..` must be refused even when the file exists");
    }

    #[test]
    fn oversized_keyfile_is_rejected() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.as_file().set_len(MAX_KEYFILE_BYTES + 1).unwrap();
        f.flush().unwrap();
        let err = key_material(b"pw", Some(f.path())).unwrap_err();
        assert!(matches!(err, VaultError::KeyfileUnreadable));
    }

    #[test]
    fn keyfile_at_the_cap_is_accepted() {
        let f = tempfile::NamedTempFile::new().unwrap();
        f.as_file().set_len(MAX_KEYFILE_BYTES).unwrap();
        let m = key_material(b"pw", Some(f.path())).unwrap();
        let expected = Sha256::digest(vec![0u8; MAX_KEYFILE_BYTES as usize]);
        assert_eq!(&m[2..], expected.as_slice());
    }

    #[test]
    fn directory_is_not_a_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let err = key_material(b"pw", Some(dir.path())).unwrap_err();
        assert!(matches!(err, VaultError::KeyfileUnreadable));
    }

    #[cfg(unix)]
    #[test]
    fn fifo_is_rejected_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("kf.fifo");
        let status = std::process::Command::new("mkfifo").arg(&fifo).status().unwrap();
        assert!(status.success());
        let err = key_material(b"pw", Some(&fifo)).unwrap_err();
        assert!(matches!(err, VaultError::KeyfileUnreadable));
    }

    #[test]
    fn missing_keyfile_is_reported() {
        let err = key_material(b"pw", Some(std::path::Path::new("/nonexistent/kf"))).unwrap_err();
        assert!(matches!(err, VaultError::KeyfileUnreadable));
    }
}

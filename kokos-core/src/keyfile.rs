//! Key file support: KDF material is password || SHA256(keyfile).

use std::path::Path;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Result, VaultError};

/// A key file is only ever hashed, so anything past this is a wrong pick (or a
/// hostile path such as a device node), not a key: refuse instead of reading it
/// whole into memory.
const MAX_KEYFILE_BYTES: u64 = 16 * 1024 * 1024;

fn read_capped(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let f = std::fs::File::open(path).map_err(|_| VaultError::KeyfileUnreadable)?;
    let mut buf = Vec::new();
    f.take(MAX_KEYFILE_BYTES + 1).read_to_end(&mut buf).map_err(|_| VaultError::KeyfileUnreadable)?;
    if buf.len() as u64 > MAX_KEYFILE_BYTES {
        buf.zeroize();
        return Err(VaultError::KeyfileUnreadable);
    }
    Ok(buf)
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
        let contents = Zeroizing::new(read_capped(path)?);
        let mut digest = Sha256::digest(&contents);
        material.extend_from_slice(&digest);
        digest.as_mut_slice().zeroize();
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
    fn missing_keyfile_is_reported() {
        let err = key_material(b"pw", Some(std::path::Path::new("/nonexistent/kf"))).unwrap_err();
        assert!(matches!(err, VaultError::KeyfileUnreadable));
    }
}

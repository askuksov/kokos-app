//! Vault header: unencrypted, little-endian.
//! v1 layout matches the Go reference byte for byte (formats/vault/header.go).
//! v2 inserts a single flags byte after the version; everything else is identical.
//! v3 rebrands the magic to `KOKOS\0\0\0` and intentionally diverges from the Go
//! reference from this point on; the legacy `VAULTDB\0` magic (v1/v2) is still
//! accepted on read (dual-accept), so existing files keep opening.

use std::io::Read;
use std::path::Path;

use crate::crypto::{Argon2Params, NONCE_LEN, SALT_LEN};
use crate::error::{Result, VaultError};

pub const MAGIC: [u8; 8] = *b"KOKOS\0\0\0";
pub const LEGACY_MAGIC: [u8; 8] = *b"VAULTDB\0";
pub const FLAG_KEYFILE: u8 = 0b0000_0001;
pub const CURRENT_VERSION: u32 = 3;

/// Enough for magic + version + flags + a generous hint + KDF + salt + nonce.
const HEADER_READ_LIMIT: usize = 4096;

/// Maximum hint length in **bytes** (UTF-8), enforced by `vault::create`,
/// `vault::change_password`, and `vault::set_hint`.
///
/// The cap exists so a hint can never make `read_header_only` fail: that
/// function reads at most `HEADER_READ_LIMIT` bytes (it must never touch the
/// encrypted body), and the fixed part of the header is 80 bytes — 8 magic +
/// 4 version + 1 flags + 2 hint length + 9 KDF + 32 salt + 24 nonce. A hint
/// beyond the remaining budget yields a vault whose PRE-OPEN probe cannot
/// parse, so `Welcome`/`TabLock` silently lose both the hint line and the
/// "needs a key file" line while `open` — which reads the whole file — keeps
/// working. 255 leaves an enormous margin and is far more than a usable hint
/// needs.
///
/// Bytes, not characters: Cyrillic is 2 bytes per character in UTF-8, so any
/// character-based limit in the UI would misreport the real budget.
pub const MAX_HINT_LEN: usize = 255;

/// Verify that a hint fits within the byte budget. This is the single
/// enforcement point for `MAX_HINT_LEN` across all write paths: called by
/// `vault::create`, `vault::change_password`, and `vault::set_hint`.
pub fn check_hint_len(hint: &str) -> Result<()> {
    if hint.len() > MAX_HINT_LEN {
        return Err(VaultError::HintTooLong);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u32,
    pub flags: u8,
    pub hint: String,
    pub kdf: Argon2Params,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    pub fn requires_keyfile(&self) -> bool {
        self.flags & FLAG_KEYFILE != 0
    }

    /// Returns the header and the offset where ciphertext begins.
    pub fn parse(bytes: &[u8]) -> Result<(Header, usize)> {
        let mut c = Reader::new(bytes);

        let magic: [u8; 8] = c.take(8)?.try_into().map_err(|_| VaultError::HeaderMalformed)?;
        if magic != MAGIC && magic != LEGACY_MAGIC {
            return Err(VaultError::NotAVaultFile);
        }
        let version = c.u32()?;
        if version == 0 || version > CURRENT_VERSION {
            return Err(VaultError::UnsupportedVersion { found: version });
        }

        let flags = if version >= 2 { c.u8()? } else { 0 };

        let hint_len = c.u16()? as usize;
        let hint = String::from_utf8(c.take(hint_len)?.to_vec()).map_err(|_| VaultError::HeaderMalformed)?;

        let kdf = Argon2Params {
            memory_kib: c.u32()?,
            time_cost: c.u32()?,
            parallelism: c.u8()?,
        };

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(c.take(SALT_LEN)?);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(c.take(NONCE_LEN)?);

        Ok((Header { version, flags, hint, kdf, salt, nonce }, c.pos))
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        if self.version >= 2 {
            out.push(self.flags);
        }
        let hint = self.hint.as_bytes();
        // New hints are capped at MAX_HINT_LEN, but a pre-cap vault re-saved
        // as-is may carry a longer one; the hard limit is the u16 length field,
        // which the cast below would silently wrap past.
        debug_assert!(hint.len() <= u16::MAX as usize, "hint exceeds the u16 length field");
        out.extend_from_slice(&(hint.len() as u16).to_le_bytes());
        out.extend_from_slice(hint);
        out.extend_from_slice(&self.kdf.memory_kib.to_le_bytes());
        out.extend_from_slice(&self.kdf.time_cost.to_le_bytes());
        out.push(self.kdf.parallelism);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
    }
}

/// Reads only the header — the file body is never touched.
///
/// Uses `Read::take` + `read_to_end` rather than a single `read()` call:
/// `Read::read` is permitted by the trait contract to return fewer bytes
/// than requested even when more are available and EOF has not been hit,
/// so one call is not guaranteed to fill the buffer. `take(N).read_to_end`
/// loops until either `N` bytes have been read or EOF, while still never
/// requesting a single byte past `HEADER_READ_LIMIT` from the underlying
/// file — the body remains untouched.
pub fn read_header_only(path: &Path) -> Result<Header> {
    let f = std::fs::File::open(path)?;
    let mut buf = Vec::with_capacity(HEADER_READ_LIMIT);
    f.take(HEADER_READ_LIMIT as u64).read_to_end(&mut buf)?;
    Header::parse(&buf).map(|(h, _)| h)
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(VaultError::HeaderMalformed)?;
        let slice = self.data.get(self.pos..end).ok_or(VaultError::HeaderMalformed)?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2Params;

    fn sample_header(version: u32) -> Header {
        Header {
            version,
            flags: 0,
            hint: "hi".to_string(),
            kdf: Argon2Params { memory_kib: 19456, time_cost: 2, parallelism: 1 },
            salt: [7u8; SALT_LEN],
            nonce: [9u8; NONCE_LEN],
        }
    }

    #[test]
    fn fresh_header_uses_kokos_magic_and_v3() {
        assert_eq!(&MAGIC, b"KOKOS\0\0\0");
        assert_eq!(CURRENT_VERSION, 3);
        let mut out = Vec::new();
        sample_header(CURRENT_VERSION).write(&mut out);
        assert_eq!(&out[0..8], b"KOKOS\0\0\0");
        assert_eq!(u32::from_le_bytes(out[8..12].try_into().unwrap()), 3);
    }

    #[test]
    fn write_then_parse_roundtrips_v3() {
        let h = sample_header(CURRENT_VERSION);
        let mut out = Vec::new();
        h.write(&mut out);
        let (parsed, _) = Header::parse(&out).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn parse_accepts_legacy_vaultdb_magic() {
        let mut out = Vec::new();
        sample_header(2).write(&mut out);
        out[0..8].copy_from_slice(&LEGACY_MAGIC);
        let (parsed, _) = Header::parse(&out).unwrap();
        assert_eq!(parsed.version, 2);
    }

    #[test]
    fn parse_rejects_foreign_magic() {
        let mut out = Vec::new();
        sample_header(CURRENT_VERSION).write(&mut out);
        out[0..8].copy_from_slice(b"NOTVAULT");
        assert!(matches!(Header::parse(&out), Err(VaultError::NotAVaultFile)));
    }
}

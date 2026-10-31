//! Per-vault, per-machine encrypted vector sidecar. NOT synced, NOT in the
//! `.kokos` container. On-disk envelope:
//!
//!   MAGIC "KVEC" (4) ‖ ENVELOPE_VER u8 ‖ nonce (24) ‖ AEAD(subkey, nonce, plaintext)
//!
//! The plaintext (little-endian) is:
//!
//!   FORMAT_VER u16 ‖ model_id(str) ‖ dim u32 ‖ count u32 ‖
//!   count × { entry_id(str) ‖ content_hash(str) ‖ vec_len u32 ‖ vec_len × f32 }
//!
//! where str = u16 length ‖ utf8 bytes. Because the blob is AEAD-authenticated,
//! the parser only ever sees bytes we wrote (a corrupt/truncated file or a wrong
//! key fails `decrypt` first) — but `deserialize` is still fully checked and
//! returns `Err` (never panics) on any short read, and every open-path failure
//! degrades to an empty store so the caller rebuilds.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use kokos_core::crypto::{self, KEY_LEN, NONCE_LEN};

use crate::AiError;

const MAGIC: &[u8; 4] = b"KVEC";
const ENVELOPE_VER: u8 = 1;
const FORMAT_VER: u16 = 1;

#[derive(Debug, Clone, PartialEq)]
pub struct VectorRecord {
    pub content_hash: String,
    pub vec: Vec<f32>,
}

#[derive(Debug, Clone)]
pub struct VectorStore {
    pub model_id: String,
    pub dim: u32,
    pub records: HashMap<String, VectorRecord>,
}

impl VectorStore {
    pub fn empty(model_id: &str, dim: u32) -> Self {
        Self { model_id: model_id.to_string(), dim, records: HashMap::new() }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&FORMAT_VER.to_le_bytes());
        put_str(&mut out, &self.model_id);
        out.extend_from_slice(&self.dim.to_le_bytes());
        out.extend_from_slice(&(self.records.len() as u32).to_le_bytes());
        let mut ids: Vec<&String> = self.records.keys().collect();
        ids.sort();
        for id in ids {
            let rec = &self.records[id];
            put_str(&mut out, id);
            put_str(&mut out, &rec.content_hash);
            out.extend_from_slice(&(rec.vec.len() as u32).to_le_bytes());
            for f in &rec.vec {
                out.extend_from_slice(&f.to_le_bytes());
            }
        }
        out
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, AiError> {
        let mut c = Cursor { b: bytes, pos: 0 };
        let format_ver = c.u16()?;
        if format_ver != FORMAT_VER {
            return Err(AiError::Backend(format!("unsupported sidecar format {format_ver}")));
        }
        let model_id = c.string()?;
        let dim = c.u32()?;
        let count = c.u32()?;
        let mut records = HashMap::with_capacity(count as usize);
        for _ in 0..count {
            let entry_id = c.string()?;
            let content_hash = c.string()?;
            let vec_len = c.u32()? as usize;
            let mut vec = Vec::with_capacity(vec_len);
            for _ in 0..vec_len {
                vec.push(c.f32()?);
            }
            records.insert(entry_id, VectorRecord { content_hash, vec });
        }
        Ok(Self { model_id, dim, records })
    }

    /// Envelope + AEAD seal. Nonce is fresh per write (never reused).
    pub fn seal(&self, subkey: &[u8; KEY_LEN]) -> Result<Vec<u8>, AiError> {
        let plain = self.serialize();
        let nonce = crypto::random_nonce();
        let ct = crypto::encrypt(subkey, &nonce, &plain).map_err(|e| AiError::Backend(e.to_string()))?;
        let mut out = Vec::with_capacity(4 + 1 + NONCE_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.push(ENVELOPE_VER);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt + parse. ANY failure — bad magic/version, wrong key, corrupt
    /// bytes, or a stored `model_id` that differs from `active_model_id` — is
    /// swallowed into an EMPTY store for the active model, so the caller cleanly
    /// rebuilds. Never returns `Err`, never panics.
    pub fn open(bytes: &[u8], subkey: &[u8; KEY_LEN], active_model_id: &str, active_dim: u32) -> Self {
        Self::try_open(bytes, subkey)
            .filter(|s| s.model_id == active_model_id)
            .unwrap_or_else(|| Self::empty(active_model_id, active_dim))
    }

    fn try_open(bytes: &[u8], subkey: &[u8; KEY_LEN]) -> Option<VectorStore> {
        let head = 4 + 1 + NONCE_LEN;
        if bytes.len() < head || &bytes[..4] != MAGIC || bytes[4] != ENVELOPE_VER {
            return None;
        }
        let nonce: [u8; NONCE_LEN] = bytes[5..head].try_into().ok()?;
        let plain = crypto::decrypt(subkey, &nonce, &bytes[head..]).ok()?;
        Self::deserialize(&plain).ok()
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// Bounds-checked little-endian reader — every read returns `Err` on a short
/// buffer instead of panicking on an out-of-range slice.
struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], AiError> {
        let end = self.pos.checked_add(n).ok_or_else(|| AiError::Backend("length overflow".into()))?;
        let slice = self.b.get(self.pos..end).ok_or_else(|| AiError::Backend("truncated sidecar".into()))?;
        self.pos = end;
        Ok(slice)
    }
    fn u16(&mut self) -> Result<u16, AiError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, AiError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn f32(&mut self) -> Result<f32, AiError> {
        Ok(f32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn string(&mut self) -> Result<String, AiError> {
        let len = self.u16()? as usize;
        let raw = self.take(len)?;
        String::from_utf8(raw.to_vec()).map_err(|e| AiError::Backend(e.to_string()))
    }
}

/// `<vectors_dir>/<vault_id>.vec`.
pub fn store_path(vectors_dir: &Path, vault_id: &str) -> PathBuf {
    vectors_dir.join(format!("{vault_id}.vec"))
}

/// Read + open the sidecar; a missing/unreadable file (or any open failure) is
/// an empty store for the active model.
pub fn load(path: &Path, subkey: &[u8; KEY_LEN], active_model_id: &str, active_dim: u32) -> VectorStore {
    match std::fs::read(path) {
        Ok(bytes) => VectorStore::open(&bytes, subkey, active_model_id, active_dim),
        Err(_) => VectorStore::empty(active_model_id, active_dim),
    }
}

/// Engine-free cleanup: drops every record `keep` rejects, without needing the
/// active model (works while AI is off or the engine is not loaded). Returns
/// whether the file changed. A missing, unreadable or foreign-keyed file is left
/// untouched (nothing this key can edit).
pub fn prune(path: &Path, subkey: &[u8; KEY_LEN], keep: &dyn Fn(&str) -> bool) -> Result<bool, AiError> {
    let Ok(bytes) = std::fs::read(path) else {
        return Ok(false);
    };
    let Some(mut store) = VectorStore::try_open(&bytes, subkey) else {
        return Ok(false);
    };
    let before = store.records.len();
    store.records.retain(|id, _| keep(id));
    if store.records.len() == before {
        return Ok(false);
    }
    save(path, &store, subkey)?;
    Ok(true)
}

/// Seal + atomic-write (`.part` then rename), the same shape the downloader uses.
pub fn save(path: &Path, store: &VectorStore, subkey: &[u8; KEY_LEN]) -> Result<(), AiError> {
    let sealed = store.seal(subkey)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("vec.part");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&sealed)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VectorStore {
        let mut s = VectorStore::empty("mid", 3);
        s.records.insert("e1".into(), VectorRecord { content_hash: "a".repeat(64), vec: vec![0.1, 0.2, 0.3] });
        s.records.insert("e2".into(), VectorRecord { content_hash: "b".repeat(64), vec: vec![-1.0, 0.0, 1.0] });
        s
    }

    #[test]
    fn serialize_then_deserialize_round_trips() {
        let s = sample();
        let bytes = s.serialize();
        let back = VectorStore::deserialize(&bytes).unwrap();
        assert_eq!(back.model_id, "mid");
        assert_eq!(back.dim, 3);
        assert_eq!(back.records.get("e1").unwrap().vec, vec![0.1, 0.2, 0.3]);
        assert_eq!(back.records.get("e2").unwrap().content_hash, "b".repeat(64));
    }

    #[test]
    fn seal_then_open_round_trips_with_the_subkey() {
        let subkey = [9u8; crypto::KEY_LEN];
        let sealed = sample().seal(&subkey).unwrap();
        let opened = VectorStore::open(&sealed, &subkey, "mid", 3);
        assert_eq!(opened.records.len(), 2);
        assert_eq!(opened.records.get("e1").unwrap().vec, vec![0.1, 0.2, 0.3]);
    }

    #[test]
    fn open_with_wrong_subkey_yields_empty_for_rebuild() {
        let sealed = sample().seal(&[9u8; crypto::KEY_LEN]).unwrap();
        let opened = VectorStore::open(&sealed, &[1u8; crypto::KEY_LEN], "mid", 3);
        assert!(opened.records.is_empty(), "undecryptable -> empty");
        assert_eq!(opened.model_id, "mid");
        assert_eq!(opened.dim, 3);
    }

    #[test]
    fn open_with_different_active_model_yields_empty_for_reindex() {
        let sealed = sample().seal(&[9u8; crypto::KEY_LEN]).unwrap();
        let opened = VectorStore::open(&sealed, &[9u8; crypto::KEY_LEN], "large", 1024);
        assert!(opened.records.is_empty(), "model change -> full reindex");
        assert_eq!(opened.model_id, "large");
        assert_eq!(opened.dim, 1024);
    }

    #[test]
    fn open_garbage_bytes_yields_empty_never_panics() {
        let opened = VectorStore::open(b"not a vec file", &[9u8; crypto::KEY_LEN], "mid", 3);
        assert!(opened.records.is_empty());
    }

    #[test]
    fn deserialize_truncated_plaintext_errs_not_panics() {
        let bytes = sample().serialize();
        for cut in [0usize, 1, 5, bytes.len().saturating_sub(2)] {
            assert!(VectorStore::deserialize(&bytes[..cut]).is_err(), "cut={cut} must Err, not panic");
        }
    }

    #[test]
    fn save_then_load_round_trips_via_disk() {
        let dir = tempfile::tempdir().unwrap();
        let subkey = [4u8; crypto::KEY_LEN];
        let path = store_path(dir.path(), "device-uuid-1");
        save(&path, &sample(), &subkey).unwrap();
        assert!(path.exists());
        let loaded = load(&path, &subkey, "mid", 3);
        assert_eq!(loaded.records.len(), 2);
        assert!(load(&path, &[0u8; crypto::KEY_LEN], "mid", 3).records.is_empty());
        let missing = store_path(dir.path(), "nope");
        assert!(load(&missing, &subkey, "mid", 3).records.is_empty());
        let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".part"))
            .collect();
        assert!(leftovers.is_empty());
    }
}

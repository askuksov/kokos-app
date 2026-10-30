//! Container operations: create, open, save, change password/key file.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::crypto::{self, Argon2Params, KEY_LEN};
use crate::db;
use crate::error::{Result, VaultError};
use crate::format::atomic;
use crate::format::header::{check_hint_len, Header, CURRENT_VERSION, FLAG_KEYFILE};
use crate::keyfile::key_material;

pub struct OpenVault {
    pub conn: Connection,
    pub header: Header,
    pub path: PathBuf,
    pub key: Zeroizing<[u8; KEY_LEN]>,
    pub migrated: bool,
    /// Whether this session already took the pre-migration `.bak`. Per
    /// `OpenVault`, not per file: a stale `.bak` from an earlier session must
    /// not stop a new migration cycle from taking a fresh one.
    backup_taken: bool,
}

/// Hand-written rather than `#[derive(Debug)]`: `zeroize::Zeroizing<Z>` itself
/// derives `Debug` (it forwards straight to `Z`'s own impl), so a derived
/// `Debug` on `OpenVault` would compile cleanly and print all 32 raw key
/// bytes in `key` on every `{:?}`, panic message and log line that touches
/// this struct. This impl exists solely to redact `key` and must never be
/// replaced by `#[derive(Debug)]` — that would silently start leaking the
/// key. `Connection`'s own `Debug` only prints its file path, so it is safe
/// to include as-is.
impl std::fmt::Debug for OpenVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenVault")
            .field("conn", &self.conn)
            .field("header", &self.header)
            .field("path", &self.path)
            .field("key", &"<redacted>")
            .field("migrated", &self.migrated)
            .field("backup_taken", &self.backup_taken)
            .finish()
    }
}

impl OpenVault {
    /// Ordering triple for the sync core (device_id + current revision +
    /// last_modified). Read after `save` to know what to push.
    pub fn sync_meta(&self) -> Result<crate::sync::SyncMeta> {
        let device = crate::db::get_device_id(&self.conn)?;
        let rev = crate::db::get_sync_revision(&self.conn)?;
        let modified: i64 = self.conn.query_row(
            "SELECT value FROM metadata WHERE key='last_modified'", [], |r| r.get::<_, String>(0),
        ).ok().and_then(|s| s.parse().ok()).unwrap_or(0);
        Ok(crate::sync::SyncMeta { rev, modified, device })
    }
}

pub enum KeyfileAction {
    Keep,
    Set(PathBuf),
    Remove,
}

pub fn create(
    path: &Path,
    password: &[u8],
    hint: &str,
    kdf: Argon2Params,
    keyfile: Option<&Path>,
) -> Result<OpenVault> {
    if path.exists() {
        return Err(VaultError::AlreadyExists);
    }
    check_hint_len(hint)?;
    kdf.validate_for_new()?;
    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let material = key_material(password, keyfile)?;
    let key = crypto::derive_key(&material, &salt, kdf)?;

    let header = Header {
        version: CURRENT_VERSION,
        flags: if keyfile.is_some() { FLAG_KEYFILE } else { 0 },
        hint: hint.to_string(),
        kdf,
        salt,
        nonce,
    };

    let conn = db::create_fresh()?;
    write_container(&conn, &header, &key, path)?;
    Ok(OpenVault { conn, header, path: path.to_path_buf(), key, migrated: false, backup_taken: false })
}

/// Upper bound on a vault container accepted by `open`, checked BEFORE the
/// header is parsed (the file is untrusted until the AEAD tag verifies). The
/// container is the whole SQLite DB, attachments included, each capped at
/// `MAX_ATTACHMENT_SIZE` (10 MiB) with no count limit; opening holds the
/// ciphertext, the plaintext and the in-memory DB at once. 1 GiB leaves room
/// for ~100 max-size attachments (far beyond real use) while refusing a
/// crafted or runaway file that would otherwise be read fully into memory.
pub const MAX_VAULT_FILE_SIZE: u64 = 1024 * 1024 * 1024;

/// Reads a vault file with a hard size cap: one handle, a metadata pre-check
/// (cheap rejection) and a `take(MAX + 1)` read (the file may grow or lie
/// about its length after the check). Oversize maps to
/// `InvalidCredentialsOrCorrupt`, the same "damaged file" answer the UI
/// already shows for any container that cannot be opened.
fn read_vault_capped(path: &Path, max: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len > max {
        return Err(VaultError::InvalidCredentialsOrCorrupt);
    }
    let mut bytes = Vec::with_capacity(len as usize);
    f.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(VaultError::InvalidCredentialsOrCorrupt);
    }
    Ok(bytes)
}

pub fn open(path: &Path, password: &[u8], keyfile: Option<&Path>) -> Result<OpenVault> {
    let bytes = read_vault_capped(path, MAX_VAULT_FILE_SIZE)?;
    let (header, offset) = Header::parse(&bytes)?;

    if header.requires_keyfile() && keyfile.is_none() {
        return Err(VaultError::KeyfileRequired);
    }
    header.kdf.validate()?;
    if !header.kdf.within_open_budget() {
        return Err(VaultError::KdfParamsTooExpensive);
    }

    let material = key_material(password, keyfile)?;
    let key = crypto::derive_key(&material, &header.salt, header.kdf)?;
    let plain = crypto::decrypt(&key, &header.nonce, &bytes[offset..])?;

    let conn = db::open_in_memory(&plain)?;
    let migrated = db::migrate::migrate(&conn)?;

    let retention = crate::trash::trash_auto_delete_days(&conn);
    crate::trash::auto_delete_old(&conn, retention)?;

    Ok(OpenVault { conn, header, path: path.to_path_buf(), key, migrated, backup_taken: false })
}

/// Saves in the container's current header version: a v1 file stays v1 until
/// the user enables a key file. The header is always written with the
/// `KOKOS` magic, so the Go version cannot read a re-saved file; the only
/// rollback after a migration is the retained pre-migration `.bak`.
///
/// `v.migrated` is true from the moment `open()` migrates a legacy container
/// in memory until the next successful `save()`/`save_opened()` (or
/// `change_password`). A `.bak` is required before "the first save after a
/// schema migration" — this is the one and only place that moment is
/// observable, since the file on disk is untouched by `migrate()` itself (it
/// runs in memory at open time). Order matters: the backup must be taken
/// before `write_container` touches the file, and `migrated` must only be
/// cleared once that write actually succeeded — otherwise a failed write
/// would falsely mark the vault as backed up.
///
/// The backup is taken at most once per `OpenVault` (`backup_taken`). A
/// failed write may still have landed on disk, so a retry in the same session
/// must not re-run `atomic::backup`: it would overwrite the good
/// pre-migration `.bak` with the already-migrated file. A `.bak` left over
/// from an earlier session, though, is stale and gets replaced by this
/// cycle's pre-migration copy.
pub fn save(v: &mut OpenVault) -> Result<()> {
    v.conn.execute(
        "INSERT INTO metadata (key, value) VALUES ('last_modified', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [crate::db::now_unix().to_string()],
    )?;
    let next_rev = crate::db::get_sync_revision(&v.conn)?.saturating_add(1);
    crate::db::set_sync_revision(&v.conn, next_rev)?;
    backup_before_first_migrated_save(v)?;
    v.header.nonce = crypto::random_nonce();
    write_container(&v.conn, &v.header, &v.key, &v.path)?;
    v.migrated = false;
    Ok(())
}

/// Takes the pre-migration `.bak` once per session; see `save`.
fn backup_before_first_migrated_save(v: &mut OpenVault) -> Result<()> {
    if v.migrated && !v.backup_taken {
        atomic::backup(&v.path)?;
        v.backup_taken = true;
    }
    Ok(())
}

/// All-or-nothing: every fallible step (resolving the key file, deriving the
/// new key) runs against **local** values first. `v` is only touched after
/// the new file has actually been written to disk, so a failure at any point
/// — an unreadable key file, a bad KDF param, a disk error — leaves `v`
/// byte-for-byte as it was on entry: still usable with the old credentials,
/// safe to retry, and safe for an autosave to pick up via `save()`.
///
/// Do not reorder this back to mutating `v.header`/`v.key` up front "for
/// simplicity" — that was the exact shape of a critical bug:
/// a failed keyfile read left the in-memory header rotated to a new
/// salt/version while `v.key` still held the *old* key, and the next `save()`
/// silently wrote a file that no password or key file could ever decrypt
/// again.
pub fn change_password(
    v: &mut OpenVault,
    new_password: &[u8],
    new_hint: Option<&str>,
    keyfile: KeyfileAction,
) -> Result<()> {
    let keyfile_path: Option<PathBuf> = match keyfile {
        KeyfileAction::Keep if v.header.requires_keyfile() => {
            return Err(VaultError::KeyfileRequired)
        }
        KeyfileAction::Keep => None,
        KeyfileAction::Set(p) => Some(p),
        KeyfileAction::Remove => None,
    };

    if let Some(h) = new_hint {
        check_hint_len(h)?;
    }

    let uses_keyfile = keyfile_path.is_some();
    let mut new_header = v.header.clone();
    new_header.salt = crypto::random_salt();
    new_header.nonce = crypto::random_nonce();
    new_header.flags = if uses_keyfile { FLAG_KEYFILE } else { 0 };
    if uses_keyfile {
        new_header.version = CURRENT_VERSION;
    }
    if let Some(h) = new_hint {
        new_header.hint = h.to_string();
    }

    let material = key_material(new_password, keyfile_path.as_deref())?;
    let new_key = crypto::derive_key(&material, &new_header.salt, new_header.kdf)?;

    atomic::backup(&v.path)?;
    write_container(&v.conn, &new_header, &new_key, &v.path)?;
    let _ = std::fs::remove_file(atomic::backup_path(&v.path));

    v.header = new_header;
    v.key = new_key;
    // The migrated DB is now on disk and its transient `.bak` is gone; a later
    // save must not take a "pre-migration" backup of this file.
    v.migrated = false;
    Ok(())
}

/// Rewrite ONLY the plaintext header hint. `hint == ""` removes it.
///
/// Deliberately cheap: unlike `change_password` this derives no key and
/// rotates no salt. It re-writes the container under the vault's EXISTING
/// key (with a fresh nonce, via `save`), so a hint edit costs an ordinary
/// save instead of a full Argon2 re-derivation — and a key-file vault does
/// not have to re-supply its key file, because `key_material` is never
/// called.
///
/// Persisted through `save`, NOT `save_opened`. `save_opened` exists to skip
/// the `last_modified`/`sync_revision` bump so that a plain open cannot win
/// LWW; a hint edit is a real user modification, and leaving the revision
/// unchanged would let a later cloud pull treat this device as stale and
/// silently revert the hint.
///
/// All-or-nothing on the in-memory header, mirroring `change_password`'s
/// ordering discipline: if the write fails, `v.header.hint` is restored, so a
/// later autosave cannot persist a hint whose own write already failed. The
/// revision bump that `save` performs before writing is not unwound — that is
/// `save`'s pre-existing behaviour on any failed save, not something this
/// function introduces.
pub fn set_hint(v: &mut OpenVault, hint: &str) -> Result<()> {
    check_hint_len(hint)?;
    let previous = std::mem::replace(&mut v.header.hint, hint.to_string());
    save(v).inspect_err(|_| {
        v.header.hint = previous;
    })
}

/// Verify a candidate master password (+ the current key file, if the vault
/// uses one) against an already-open vault WITHOUT re-keying: re-derive the key
/// from the same salt/KDF the vault was opened with and constant-time-compare
/// it to the live in-memory key. Gates credential rotation (add/replace/remove
/// key file, change master password) behind proof of the current password,
/// since an open session is otherwise the sole authorization. A key-file vault
/// needs the current key file too — the stored key mixes in SHA256(keyfile), so
/// the password alone can't reproduce it — hence the (password, keyfile) shape
/// mirrors `open`.
pub fn verify_password(v: &OpenVault, password: &[u8], keyfile: Option<&Path>) -> Result<bool> {
    let material = key_material(password, keyfile)?;
    let candidate = crypto::derive_key(&material, &v.header.salt, v.header.kdf)?;
    let equal = candidate
        .iter()
        .zip(v.key.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0;
    Ok(equal)
}

/// Persist an already-open vault WITHOUT recording a modification: unlike
/// `save`, it does NOT bump `metadata.last_modified` or `sync_revision`, so a
/// plain open (which only appends an "unlock" audit row) never makes this
/// device win LWW or trigger an auto-push. Still rotates the nonce and takes
/// the one-time pre-migration `.bak` if this open migrated the schema.
pub fn save_opened(v: &mut OpenVault) -> Result<()> {
    backup_before_first_migrated_save(v)?;
    v.header.nonce = crypto::random_nonce();
    write_container(&v.conn, &v.header, &v.key, &v.path)?;
    v.migrated = false;
    Ok(())
}

fn write_container(conn: &Connection, header: &Header, key: &[u8; KEY_LEN], path: &Path) -> Result<()> {
    let image = db::serialize(conn)?;
    let ciphertext = crypto::encrypt(key, &header.nonce, &image)?;

    let mut out = Vec::with_capacity(128 + ciphertext.len());
    header.write(&mut out);
    out.extend_from_slice(&ciphertext);

    atomic::write_atomic(path, &out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Argon2Params = Argon2Params { memory_kib: 19_456, time_cost: 2, parallelism: 1 };

    #[test]
    fn read_vault_capped_rejects_a_file_over_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.kokos");
        std::fs::write(&path, vec![0u8; 101]).unwrap();
        assert!(matches!(read_vault_capped(&path, 100), Err(VaultError::InvalidCredentialsOrCorrupt)));
        assert_eq!(read_vault_capped(&path, 101).unwrap().len(), 101);
    }

    /// A failed migrated save may still have renamed the new file into place;
    /// the retry in the same session must keep the pre-migration `.bak`.
    #[test]
    fn migrated_save_retry_in_same_session_keeps_the_first_bak() {
        use sha2::{Digest, Sha256};

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v1_favorite.vault");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures").join("v1_favorite.vault");
        std::fs::copy(&fixture, &p).unwrap();
        let original_hash = Sha256::digest(std::fs::read(&p).unwrap());

        let mut v = open(&p, b"fixture-password", None).unwrap();
        assert!(v.migrated, "fixture must actually migrate for this test to mean anything");

        // First attempt: backup taken, then the write lands but reports an error.
        backup_before_first_migrated_save(&mut v).unwrap();
        std::fs::write(&p, b"already-migrated bytes from the failed attempt").unwrap();
        assert!(v.migrated);

        save(&mut v).unwrap();
        assert_eq!(
            Sha256::digest(std::fs::read(atomic::backup_path(&p)).unwrap()),
            original_hash,
            "a same-session retry must not overwrite the pre-migration .bak"
        );
    }

    #[test]
    fn save_opened_does_not_bump_sync_revision() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kokos");
        let _v = create(&path, b"pw", "", FAST, None).unwrap();
        let mut v = open(&path, b"pw", None).unwrap();
        let rev_before = crate::db::get_sync_revision(&v.conn).unwrap();
        crate::audit::append(&v.conn, "unlock", None).unwrap();
        save_opened(&mut v).unwrap();
        let rev_after = crate::db::get_sync_revision(&v.conn).unwrap();
        assert_eq!(rev_before, rev_after, "open-time persist must not bump sync_revision");
    }

    #[test]
    fn verify_password_password_only_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let v = create(&path, b"correct horse", "hint", FAST, None).unwrap();

        assert!(verify_password(&v, b"correct horse", None).unwrap());
        assert!(!verify_password(&v, b"wrong", None).unwrap());
    }

    #[test]
    fn verify_password_keyfile_vault() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let mut kf = tempfile::NamedTempFile::new().unwrap();
        kf.write_all(b"keyfile contents").unwrap();

        let v = create(&path, b"pw", "hint", FAST, Some(kf.path())).unwrap();

        assert!(verify_password(&v, b"pw", Some(kf.path())).unwrap());
        assert!(!verify_password(&v, b"pw", None).unwrap());
        assert!(!verify_password(&v, b"wrong", Some(kf.path())).unwrap());
    }

    #[test]
    fn open_rejects_kdf_cost_bomb_before_deriving() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bomb.kokos");

        let header = Header {
            version: CURRENT_VERSION,
            flags: 0,
            hint: String::new(),
            kdf: Argon2Params { memory_kib: 1_048_576, time_cost: 100, parallelism: 1 },
            salt: [0u8; crypto::SALT_LEN],
            nonce: [0u8; crypto::NONCE_LEN],
        };
        let mut bytes = Vec::new();
        header.write(&mut bytes);
        bytes.extend_from_slice(&[0u8; 32]);

        std::fs::write(&path, &bytes).unwrap();

        let t0 = std::time::Instant::now();
        let err = open(&path, b"whatever", None).unwrap_err();
        let elapsed = t0.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "open took {elapsed:?} -- the KDF ceiling must reject BEFORE derive_key"
        );
        assert!(
            matches!(err, VaultError::KdfParamsTooExpensive),
            "expected KdfParamsTooExpensive (early reject before Argon2), got {err:?}"
        );
    }

    #[test]
    fn save_bumps_sync_revision_and_meta_reads_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kokos");
        let mut v = create(&path, b"pw", "hint", FAST, None).unwrap();
        assert_eq!(v.sync_meta().unwrap().rev, 0);
        save(&mut v).unwrap();
        assert_eq!(v.sync_meta().unwrap().rev, 1);
        save(&mut v).unwrap();
        let meta = v.sync_meta().unwrap();
        assert_eq!(meta.rev, 2);
        assert_eq!(meta.device.len(), 36);
        assert!(meta.modified > 0);
    }

    #[test]
    fn create_rejects_below_floor_kdf_params() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("weak.kokos");
        let weak = Argon2Params { memory_kib: 1024, time_cost: 1, parallelism: 1 };
        assert!(matches!(create(&path, b"pw", "", weak, None), Err(VaultError::InvalidKdfParams)));
        assert!(!path.exists(), "a rejected create must not leave a file behind");
    }

    #[test]
    fn open_still_accepts_below_floor_kdf_for_go_parity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.kokos");
        let weak = Argon2Params { memory_kib: 1024, time_cost: 1, parallelism: 1 };
        let salt = crypto::random_salt();
        let nonce = crypto::random_nonce();
        let material = key_material(b"pw", None).unwrap();
        let key = crypto::derive_key(&material, &salt, weak).unwrap();
        let header = Header { version: CURRENT_VERSION, flags: 0, hint: String::new(), kdf: weak, salt, nonce };
        let conn = db::create_fresh().unwrap();
        write_container(&conn, &header, &key, &path).unwrap();
        drop(conn);
        assert!(open(&path, b"pw", None).is_ok(), "open must read below-floor (Go-parity) vaults");
    }
}

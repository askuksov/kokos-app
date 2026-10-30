//! Argon2id key derivation and XChaCha20-Poly1305 AEAD.
//! Mirrors the Go reference (archive/key-vault/formats/vault/encryption.go):
//! same algorithm (Argon2id) and AEAD (chacha20poly1305.NewX), no AAD.
//!
//! The two APIs take their Argon2 cost parameters in **opposite order**, not the
//! same order: Go's `argon2.IDKey(password, salt, time, memory, threads, keyLen)`
//! is time-then-memory; Rust's `Params::new(m_cost, t_cost, p_cost, output_len)`
//! is memory-then-time. They agree by **meaning, not position**:
//!   Go `Time`        -> Rust `t_cost`
//!   Go `Memory`       -> Rust `m_cost`
//!   Go `Parallelism`  -> Rust `p_cost`
//! Do not "align" this call to Go's argument order — that compiles fine but
//! silently derives a different key from the same password. The known-answer
//! tests below (checked against Go's own output) fail if this mapping drifts.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Result, VaultError};

pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u8,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self { memory_kib: 65536, time_cost: 3, parallelism: 4 }
    }
}

/// Open-time ceiling on attacker-controllable KDF cost.
///
/// A `.kokos` file's `header.kdf` is UNAUTHENTICATED and fed to Argon2 in
/// `vault::open` *before* any password check, so a crafted file could set
/// 1 GiB / t=100 and hang or OOM the app on open. `validate()`'s wide
/// Go-parity bounds (up to 1 GiB / t=100) stay for CREATE; `open()`
/// additionally rejects params above anything a real interactive vault uses.
/// Values chosen well above the app's own 64 MiB / t=3 default and the Go
/// migration's 19 MiB / t=2, and below the OOM / multi-minute-hang zone.
pub const OPEN_MAX_MEMORY_KIB: u32 = 262_144;
pub const OPEN_MAX_TIME_COST: u32 = 10;

/// OWASP Argon2id minimums, enforced ONLY at vault CREATION (the sole minting
/// point). `validate()` keeps the wider Go-parity range for `open`, so legacy /
/// Go-migrated vaults with weaker params still open.
pub const CREATE_MIN_MEMORY_KIB: u32 = 19_456;
pub const CREATE_MIN_TIME_COST: u32 = 2;

impl Argon2Params {
    /// Ranges match the Go reference's Header.Validate().
    pub fn validate(&self) -> Result<()> {
        let ok = (1024..=1_048_576).contains(&self.memory_kib)
            && (1..=100).contains(&self.time_cost)
            && self.parallelism >= 1;
        if ok {
            Ok(())
        } else {
            Err(VaultError::InvalidKdfParams)
        }
    }

    /// Stricter than `validate()`: the open-time ceiling for UNTRUSTED header
    /// params. A failure means REJECT — never silently clamp, since lowering
    /// the params would derive a different key and surface as a bogus
    /// wrong-password error. Enforced only at the untrusted `vault::open`
    /// boundary; `create`/`change_password` use app-chosen params.
    pub fn within_open_budget(&self) -> bool {
        self.memory_kib <= OPEN_MAX_MEMORY_KIB && self.time_cost <= OPEN_MAX_TIME_COST
    }

    /// Stricter than `validate()`: the create-time floor for NEW vaults. Keeps
    /// the outer Go-parity bounds AND enforces the OWASP Argon2id minimum, so a
    /// raw create_vault IPC call cannot mint a sub-OWASP vault. Also caps at
    /// `within_open_budget()`, so `create` can never write a vault that `open`
    /// would refuse. NOT used by `open` (which must read weaker legacy headers).
    pub fn validate_for_new(&self) -> Result<()> {
        self.validate()?;
        if self.memory_kib < CREATE_MIN_MEMORY_KIB || self.time_cost < CREATE_MIN_TIME_COST {
            return Err(VaultError::InvalidKdfParams);
        }
        if !self.within_open_budget() {
            return Err(VaultError::InvalidKdfParams);
        }
        Ok(())
    }
}

pub fn derive_key(material: &[u8], salt: &[u8], p: Argon2Params) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    p.validate()?;
    let params = Params::new(p.memory_kib, p.time_cost, p.parallelism as u32, Some(KEY_LEN))
        .map_err(|_| VaultError::InvalidKdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(material, salt, key.as_mut())
        .map_err(|_| VaultError::InvalidKdfParams)?;
    Ok(key)
}

/// Derive a domain-separated 32-byte subkey from an already-uniformly-random
/// 32-byte key (e.g. the vault AEAD key) for encrypting a *derived-data*
/// sidecar such as the AI vector store. This is NOT a password KDF: the input
/// is already high-entropy, so a single SHA-256 over `key ‖ label` is a sound
/// one-way subkey with clean domain separation (a different `label` yields an
/// unrelated subkey), and unlike `derive_key` (Argon2) it is cheap enough to
/// call per operation. The result is `Zeroizing`, so it wipes on drop.
pub fn derive_subkey(key: &[u8; KEY_LEN], label: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut h = Sha256::new();
    h.update(key);
    h.update(label);
    let mut digest = h.finalize();
    let mut sk = Zeroizing::new([0u8; KEY_LEN]);
    sk.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    sk
}

pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .map_err(|_| VaultError::InvalidCredentialsOrCorrupt)
}

pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let plain = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| VaultError::InvalidCredentialsOrCorrupt)?;
    Ok(Zeroizing::new(plain))
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Argon2Params = Argon2Params { memory_kib: 1024, time_cost: 1, parallelism: 1 };

    #[test]
    fn derive_key_is_deterministic() {
        let salt = [7u8; SALT_LEN];
        let a = derive_key(b"password", &salt, FAST).unwrap();
        let b = derive_key(b"password", &salt, FAST).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn derive_key_depends_on_password_and_salt() {
        let salt = [7u8; SALT_LEN];
        let other_salt = [8u8; SALT_LEN];
        let base = derive_key(b"password", &salt, FAST).unwrap();
        assert_ne!(base.as_ref(), derive_key(b"password2", &salt, FAST).unwrap().as_ref());
        assert_ne!(base.as_ref(), derive_key(b"password", &other_salt, FAST).unwrap().as_ref());
    }

    #[test]
    fn derive_subkey_is_deterministic_domain_separated_and_not_the_source() {
        let key = [7u8; KEY_LEN];
        let a = derive_subkey(&key, b"kokos-ai:vectors:v1");
        let b = derive_subkey(&key, b"kokos-ai:vectors:v1");
        assert_eq!(a.as_ref(), b.as_ref(), "same key+label -> same subkey");
        let other = derive_subkey(&key, b"kokos-ai:vectors:v2");
        assert_ne!(a.as_ref(), other.as_ref(), "different label -> unrelated subkey");
        assert_ne!(a.as_ref(), &key, "subkey must not equal the source vault key");
        assert_eq!(a.len(), KEY_LEN);
    }

    #[test]
    fn derive_subkey_deterministic_and_label_separated() {
        let key = [7u8; KEY_LEN];
        let a = derive_subkey(&key, b"ai-vector-store");
        let a2 = derive_subkey(&key, b"ai-vector-store");
        let b = derive_subkey(&key, b"other-label");
        assert_eq!(*a, *a2);
        assert_ne!(*a, *b);
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [1u8; KEY_LEN];
        let nonce = [2u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"secret payload").unwrap();
        assert_eq!(ct.len(), b"secret payload".len() + TAG_LEN);
        let pt = decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt.as_slice(), b"secret payload");
    }

    #[test]
    fn decrypt_with_wrong_key_fails_without_leaking_reason() {
        let ct = encrypt(&[1u8; KEY_LEN], &[2u8; NONCE_LEN], b"payload").unwrap();
        let err = decrypt(&[9u8; KEY_LEN], &[2u8; NONCE_LEN], &ct).unwrap_err();
        assert!(matches!(err, VaultError::InvalidCredentialsOrCorrupt));
    }

    #[test]
    fn decrypt_rejects_tampered_tag() {
        let mut ct = encrypt(&[1u8; KEY_LEN], &[2u8; NONCE_LEN], b"payload").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert!(matches!(
            decrypt(&[1u8; KEY_LEN], &[2u8; NONCE_LEN], &ct).unwrap_err(),
            VaultError::InvalidCredentialsOrCorrupt
        ));
    }

    #[test]
    fn random_nonces_do_not_repeat() {
        let a = random_nonce();
        let b = random_nonce();
        assert_ne!(a, b);
    }

    #[test]
    fn params_validate_ranges() {
        assert!(Argon2Params::default().validate().is_ok());
        assert!(Argon2Params { memory_kib: 512, time_cost: 3, parallelism: 4 }.validate().is_err());
        assert!(Argon2Params { memory_kib: 65536, time_cost: 0, parallelism: 4 }.validate().is_err());
        assert!(Argon2Params { memory_kib: 65536, time_cost: 3, parallelism: 0 }.validate().is_err());
    }

    #[test]
    fn validate_for_new_enforces_owasp_floor_but_validate_stays_go_parity() {
        let weak = Argon2Params { memory_kib: 1024, time_cost: 1, parallelism: 1 };
        assert!(weak.validate_for_new().is_err());
        assert!(Argon2Params { memory_kib: 19_455, time_cost: 2, parallelism: 1 }.validate_for_new().is_err());
        assert!(Argon2Params { memory_kib: 19_456, time_cost: 1, parallelism: 1 }.validate_for_new().is_err());
        assert!(Argon2Params { memory_kib: 19_456, time_cost: 2, parallelism: 1 }.validate_for_new().is_ok());
        assert!(Argon2Params::default().validate_for_new().is_ok());
        assert!(weak.validate().is_ok());
    }

    #[test]
    fn within_open_budget_accepts_real_vault_params() {
        assert!(Argon2Params::default().within_open_budget());
        assert!(Argon2Params { memory_kib: 19456, time_cost: 2, parallelism: 1 }.within_open_budget());
        assert!(Argon2Params {
            memory_kib: OPEN_MAX_MEMORY_KIB,
            time_cost: OPEN_MAX_TIME_COST,
            parallelism: 4,
        }
        .within_open_budget());
    }

    #[test]
    fn within_open_budget_rejects_crafted_cost_bomb() {
        let bomb = Argon2Params { memory_kib: 1_048_576, time_cost: 100, parallelism: 1 };
        assert!(bomb.validate().is_ok());
        assert!(!bomb.within_open_budget());
        assert!(!Argon2Params { memory_kib: 524_288, time_cost: 3, parallelism: 4 }.within_open_budget());
        assert!(!Argon2Params { memory_kib: 65_536, time_cost: 11, parallelism: 4 }.within_open_budget());
    }

    #[test]
    fn validate_for_new_rejects_params_open_would_refuse() {
        let bomb = Argon2Params { memory_kib: 1_048_576, time_cost: 100, parallelism: 1 };
        assert!(bomb.validate().is_ok());
        assert!(matches!(bomb.validate_for_new(), Err(VaultError::InvalidKdfParams)));
        let over_memory = Argon2Params { memory_kib: OPEN_MAX_MEMORY_KIB + 1, time_cost: 2, parallelism: 1 };
        assert!(matches!(over_memory.validate_for_new(), Err(VaultError::InvalidKdfParams)));
        let over_time = Argon2Params { memory_kib: 19_456, time_cost: OPEN_MAX_TIME_COST + 1, parallelism: 1 };
        assert!(matches!(over_time.validate_for_new(), Err(VaultError::InvalidKdfParams)));
        let at_cap = Argon2Params { memory_kib: OPEN_MAX_MEMORY_KIB, time_cost: OPEN_MAX_TIME_COST, parallelism: 4 };
        assert!(at_cap.validate_for_new().is_ok());
    }


    /// vault.DeriveKey(password, salt, params) from the Go program above.
    const GO_KAT_KEY_HEX: &str = "2df009912d93ad360ef68ce481fd6b7d867fe0daaba8ee227f05090f4f12ca5d";
    /// vault.Encrypt(key, nonce, plaintext) from the Go program above.
    const GO_KAT_CIPHERTEXT_HEX: &str =
        "33c22994648fa3667d63baa8bcaa09e8325c41e6b82ae40a0fc83a1e9b4a56e14d696cbc851d29";

    /// Tiny local decoder so the two constants above can be pasted as hex —
    /// not worth a dependency for this.
    fn decode_hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0, "odd-length hex string");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex digit in constant"))
            .collect()
    }

    /// [1, 2, 3, ..., N] i.e. byte i = i + 1 — matches kat-gen's `sequentialBytes`.
    fn sequential_bytes<const N: usize>() -> [u8; N] {
        std::array::from_fn(|i| (i + 1) as u8)
    }

    #[test]
    fn known_answer_derive_key_matches_go() {
        let salt: [u8; SALT_LEN] = sequential_bytes();
        let params = Argon2Params { memory_kib: 1024, time_cost: 1, parallelism: 1 };
        let key = derive_key(b"fixture-password", &salt, params).unwrap();
        assert_eq!(key.as_slice(), decode_hex(GO_KAT_KEY_HEX).as_slice());
    }

    #[test]
    fn known_answer_decrypt_matches_go() {
        let key: [u8; KEY_LEN] = decode_hex(GO_KAT_KEY_HEX).try_into().unwrap();
        let nonce: [u8; NONCE_LEN] = sequential_bytes();
        let ciphertext = decode_hex(GO_KAT_CIPHERTEXT_HEX);
        let plaintext = decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), b"kokos known answer test");
    }
}

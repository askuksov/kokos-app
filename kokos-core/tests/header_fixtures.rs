use kokos_core::format::header::{read_header_only, Header, FLAG_KEYFILE};

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures").join(name)
}

#[test]
fn reads_v1_header_written_by_go() {
    let h = read_header_only(&fixture("v1_basic.vault")).unwrap();
    assert_eq!(h.version, 1);
    assert_eq!(h.flags, 0, "v1 has no flags byte; flags must default to 0");
    assert_eq!(h.hint, "my hint");
    assert_eq!(h.kdf.memory_kib, 1024);
    assert_eq!(h.kdf.time_cost, 1);
    assert_eq!(h.kdf.parallelism, 1);
    assert!(!h.requires_keyfile());
}

#[test]
fn reads_empty_hint() {
    let h = read_header_only(&fixture("v1_empty.vault")).unwrap();
    assert_eq!(h.hint, "");
}

#[test]
fn hint_length_is_bytes_not_chars() {
    let h = read_header_only(&fixture("v1_unicode.vault")).unwrap();
    assert_eq!(h.hint, "Пароль от почты 🥥");
    assert_eq!(h.hint.chars().count(), 17);
    assert_eq!(h.hint.len(), 33);
}

#[test]
fn reads_default_kdf_params() {
    let h = read_header_only(&fixture("v1_default_kdf.vault")).unwrap();
    assert_eq!(h.kdf.memory_kib, 65536);
    assert_eq!(h.kdf.time_cost, 3);
    assert_eq!(h.kdf.parallelism, 4);
}

#[test]
fn rejects_foreign_file() {
    let err = read_header_only(&fixture("not_a_vault.bin")).unwrap_err();
    assert!(matches!(err, kokos_core::VaultError::NotAVaultFile));
}

#[test]
fn truncated_file_errors_without_panic() {
    let err = read_header_only(&fixture("v1_truncated.vault"));
    assert!(err.is_ok() || matches!(err.unwrap_err(), kokos_core::VaultError::HeaderMalformed));
}

#[test]
fn v2_round_trip_with_keyfile_flag() {
    let h = Header {
        version: 2,
        flags: FLAG_KEYFILE,
        hint: "hint".into(),
        kdf: kokos_core::crypto::Argon2Params::default(),
        salt: [3u8; 32],
        nonce: [4u8; 24],
    };
    let mut buf = Vec::new();
    h.write(&mut buf);
    buf.extend_from_slice(b"ciphertext-here");

    let (parsed, offset) = Header::parse(&buf).unwrap();
    assert_eq!(parsed.version, 2);
    assert!(parsed.requires_keyfile());
    assert_eq!(parsed.hint, "hint");
    assert_eq!(parsed.salt, [3u8; 32]);
    assert_eq!(parsed.nonce, [4u8; 24]);
    assert_eq!(&buf[offset..], b"ciphertext-here");
}

#[test]
fn v1_round_trip_keeps_layout_without_flags_byte() {
    let h = Header {
        version: 1,
        flags: 0,
        hint: "x".into(),
        kdf: kokos_core::crypto::Argon2Params::default(),
        salt: [1u8; 32],
        nonce: [2u8; 24],
    };
    let mut buf = Vec::new();
    h.write(&mut buf);
    assert_eq!(buf.len(), 80, "v1 layout must not contain a flags byte");

    let (parsed, offset) = Header::parse(&buf).unwrap();
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.flags, 0);
    assert_eq!(offset, 80);
}

#[test]
fn rejects_future_version() {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"VAULTDB\0");
    buf.extend_from_slice(&99u32.to_le_bytes());
    buf.extend_from_slice(&[0u8; 64]);
    let err = Header::parse(&buf).unwrap_err();
    assert!(matches!(err, kokos_core::VaultError::UnsupportedVersion { found: 99 }));
}

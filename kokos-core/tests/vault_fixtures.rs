use kokos_core::crypto::Argon2Params;
use kokos_core::vault::{self, KeyfileAction};

const FAST: Argon2Params = Argon2Params { memory_kib: 19_456, time_cost: 2, parallelism: 1 };
const FIXTURE_PW: &[u8] = b"fixture-password";

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures").join(name)
}

/// Live-data rule: fixtures are never written to. Copy first.
fn copy_fixture(name: &str, dir: &tempfile::TempDir) -> std::path::PathBuf {
    let dst = dir.path().join(name);
    std::fs::copy(fixture(name), &dst).unwrap();
    dst
}

#[test]
fn opens_go_written_vault_and_reads_entries() {
    let v = vault::open(&fixture("v1_basic.vault"), FIXTURE_PW, None).unwrap();
    assert_eq!(v.header.version, 1);
    let n: i64 = v.conn.query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 2);
    let title: String = v.conn.query_row("SELECT title FROM entries WHERE id='e1'", [], |r| r.get(0)).unwrap();
    assert_eq!(title, "GitHub");
}

#[test]
fn migrates_on_open() {
    let v = vault::open(&fixture("v1_favorite.vault"), FIXTURE_PW, None).unwrap();
    assert!(v.migrated);
    let fav: i64 = v.conn.query_row("SELECT is_favorite FROM entries WHERE id='e1'", [], |r| r.get(0)).unwrap();
    assert_eq!(fav, 1);
}

#[test]
fn wrong_password_is_indistinguishable_from_corruption() {
    let by_password = vault::open(&fixture("v1_basic.vault"), b"wrong", None).unwrap_err();
    let by_corruption = vault::open(&fixture("v1_corrupt.vault"), FIXTURE_PW, None).unwrap_err();
    assert!(matches!(by_password, kokos_core::VaultError::InvalidCredentialsOrCorrupt));
    assert!(matches!(by_corruption, kokos_core::VaultError::InvalidCredentialsOrCorrupt));
    assert_eq!(by_password.to_string(), by_corruption.to_string(), "no oracle: messages must match");
}

#[test]
fn truncated_file_errors_without_panic() {
    let err = vault::open(&fixture("v1_truncated.vault"), FIXTURE_PW, None).unwrap_err();
    assert!(matches!(err, kokos_core::VaultError::InvalidCredentialsOrCorrupt));
}

#[test]
fn create_writes_v3_and_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("new.vault");

    let v = vault::create(&p, b"pw", "my hint", FAST, None).unwrap();
    assert_eq!(v.header.version, 3, "new files are created in v3");
    drop(v);

    let reopened = vault::open(&p, b"pw", None).unwrap();
    assert_eq!(reopened.header.hint, "my hint");
    let root: i64 = reopened.conn.query_row("SELECT COUNT(*) FROM folders WHERE id='root'", [], |r| r.get(0)).unwrap();
    assert_eq!(root, 1);
}

#[test]
fn v1_file_stays_v1_after_save() {
    let dir = tempfile::tempdir().unwrap();
    let p = copy_fixture("v1_basic.vault", &dir);

    let mut v = vault::open(&p, FIXTURE_PW, None).unwrap();
    v.conn
        .execute("INSERT INTO entries (id, folder_id, title, created_at, updated_at) VALUES ('e3','root','New',1,1)", [])
        .unwrap();
    vault::save(&mut v).unwrap();

    let h = kokos_core::format::header::read_header_only(&p).unwrap();
    assert_eq!(h.version, 1);

    let reopened = vault::open(&p, FIXTURE_PW, None).unwrap();
    let n: i64 = reopened.conn.query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 3);
}

#[test]
fn save_uses_a_fresh_nonce() {
    let dir = tempfile::tempdir().unwrap();
    let p = copy_fixture("v1_basic.vault", &dir);

    let before = kokos_core::format::header::read_header_only(&p).unwrap().nonce;
    let mut v = vault::open(&p, FIXTURE_PW, None).unwrap();
    vault::save(&mut v).unwrap();
    let after = kokos_core::format::header::read_header_only(&p).unwrap().nonce;

    assert_ne!(before, after, "nonce reuse breaks XChaCha20-Poly1305");
}

#[test]
fn keyfile_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("kf.vault");
    let kf = dir.path().join("secret.key");
    std::fs::write(&kf, b"key file bytes").unwrap();

    let v = vault::create(&p, b"pw", "", FAST, Some(&kf)).unwrap();
    assert!(v.header.requires_keyfile());
    drop(v);

    let h = kokos_core::format::header::read_header_only(&p).unwrap();
    assert!(h.requires_keyfile(), "UI must learn about the key file before asking for a password");

    assert!(matches!(
        vault::open(&p, b"pw", None).unwrap_err(),
        kokos_core::VaultError::KeyfileRequired
    ));
    assert!(vault::open(&p, b"pw", Some(&kf)).is_ok());
}

#[test]
fn enabling_keyfile_upgrades_v1_to_v3() {
    let dir = tempfile::tempdir().unwrap();
    let p = copy_fixture("v1_basic.vault", &dir);
    let kf = dir.path().join("k.key");
    std::fs::write(&kf, b"kf").unwrap();

    let mut v = vault::open(&p, FIXTURE_PW, None).unwrap();
    vault::change_password(&mut v, FIXTURE_PW, None, KeyfileAction::Set(kf.clone())).unwrap();

    let h = kokos_core::format::header::read_header_only(&p).unwrap();
    assert_eq!(h.version, 3, "key file requires v3");
    assert!(h.requires_keyfile());
    assert!(!dir.path().join("v1_basic.vault.bak").exists(), "old-key .bak must be removed after a successful change_password");
    assert!(vault::open(&p, FIXTURE_PW, Some(&kf)).is_ok());
}

#[test]
fn change_password_removes_old_key_bak() {
    let dir = tempfile::tempdir().unwrap();
    let p = copy_fixture("v1_basic.vault", &dir);
    let bak = kokos_core::format::atomic::backup_path(&p);

    let mut v = vault::open(&p, FIXTURE_PW, None).unwrap();
    vault::change_password(&mut v, b"new-password", None, KeyfileAction::Keep).unwrap();

    assert!(!bak.exists(), "old-key .bak must be removed after a successful change_password");

    assert!(vault::open(&p, b"new-password", None).is_ok());
    assert!(vault::open(&p, FIXTURE_PW, None).is_err());
}

#[test]
fn change_password_rewrites_salt() {
    let dir = tempfile::tempdir().unwrap();
    let p = copy_fixture("v1_basic.vault", &dir);
    let old_salt = kokos_core::format::header::read_header_only(&p).unwrap().salt;

    let mut v = vault::open(&p, FIXTURE_PW, None).unwrap();
    vault::change_password(&mut v, b"new-password", Some("new hint"), KeyfileAction::Keep).unwrap();

    let h = kokos_core::format::header::read_header_only(&p).unwrap();
    assert_ne!(h.salt, old_salt);
    assert_eq!(h.hint, "new hint");
    assert!(vault::open(&p, b"new-password", None).is_ok());
    assert!(vault::open(&p, FIXTURE_PW, None).is_err());
}


#[test]
fn failed_change_password_does_not_poison_open_vault() {
    let dir = tempfile::tempdir().unwrap();
    let p = copy_fixture("v1_basic.vault", &dir);

    let mut v = vault::open(&p, FIXTURE_PW, None).unwrap();
    let version_before = v.header.version;
    let salt_before = v.header.salt;
    let requires_keyfile_before = v.header.requires_keyfile();

    let missing_keyfile = dir.path().join("does-not-exist.key");
    let err =
        vault::change_password(&mut v, b"new-password", None, KeyfileAction::Set(missing_keyfile)).unwrap_err();
    assert!(matches!(err, kokos_core::VaultError::KeyfileUnreadable));

    assert_eq!(v.header.version, version_before, "header.version must be untouched on failure");
    assert_eq!(v.header.salt, salt_before, "header.salt must be untouched on failure");
    assert_eq!(
        v.header.requires_keyfile(),
        requires_keyfile_before,
        "requires_keyfile() must be untouched on failure"
    );

    vault::save(&mut v).unwrap();

    let h = kokos_core::format::header::read_header_only(&p).unwrap();
    assert_eq!(h.version, 1, "a v1 file must stay v1 even after a failed change_password");

    assert!(vault::open(&p, FIXTURE_PW, None).is_ok(), "original password must still open the vault");
}


#[test]
fn keep_on_keyfile_vault_is_rejected_and_leaves_file_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("kf.vault");
    let kf = dir.path().join("secret.key");
    std::fs::write(&kf, b"key file bytes").unwrap();

    let v = vault::create(&p, b"pw", "hint", FAST, Some(&kf)).unwrap();
    drop(v);
    let before = kokos_core::format::header::read_header_only(&p).unwrap();

    let mut v = vault::open(&p, b"pw", Some(&kf)).unwrap();
    let err = vault::change_password(&mut v, b"new-pw", None, KeyfileAction::Keep).unwrap_err();
    assert!(
        matches!(err, kokos_core::VaultError::KeyfileRequired),
        "Keep cannot mean \"reuse key file bytes we no longer hold\""
    );

    let after = kokos_core::format::header::read_header_only(&p).unwrap();
    assert_eq!(after, before, "a rejected change_password must not touch the file on disk");
    assert_eq!(after.version, 3);
    assert!(after.requires_keyfile());
    assert!(
        !dir.path().join("kf.vault.bak").exists(),
        "a rejected no-op must not clobber a previous .bak"
    );

    assert!(
        vault::open(&p, b"pw", Some(&kf)).is_ok(),
        "original password + key file must still open the vault"
    );
}


#[test]
fn first_save_after_migration_backs_up_pre_migration_bytes() {
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().unwrap();
    let p = copy_fixture("v1_favorite.vault", &dir);
    let original_hash = Sha256::digest(std::fs::read(&p).unwrap());

    let mut v = vault::open(&p, FIXTURE_PW, None).unwrap();
    assert!(v.migrated, "fixture must actually migrate for this test to mean anything");
    vault::save(&mut v).unwrap();

    let bak = std::fs::read(dir.path().join("v1_favorite.vault.bak")).unwrap();
    assert_eq!(
        Sha256::digest(&bak),
        original_hash,
        ".bak must be byte-identical to the file as it was before the migrated save"
    );
}

/// A `.bak` left over from an earlier session (e.g. a migration months ago)
/// is not this cycle's rollback copy: the first migrated save of a new session
/// must replace it with the current pre-migration bytes. The same-session
/// retry case (must NOT clobber) is covered by a unit test in `vault.rs`,
/// since it needs to fake a failed write.
#[test]
fn migrated_save_replaces_a_stale_bak_from_an_earlier_session() {
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().unwrap();
    let p = copy_fixture("v1_favorite.vault", &dir);
    let original_hash = Sha256::digest(std::fs::read(&p).unwrap());
    let bak_path = dir.path().join("v1_favorite.vault.bak");
    std::fs::write(&bak_path, b"stale .bak from an earlier migration cycle").unwrap();

    let mut v = vault::open(&p, FIXTURE_PW, None).unwrap();
    assert!(v.migrated, "fixture must actually migrate for this test to mean anything");
    vault::save(&mut v).unwrap();
    assert!(!v.migrated, "migrated must clear once the backing-up save has succeeded");

    assert_eq!(
        Sha256::digest(std::fs::read(&bak_path).unwrap()),
        original_hash,
        "a stale .bak must be replaced by this cycle's pre-migration bytes"
    );
}

#[test]
fn change_password_on_a_migrated_vault_clears_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let p = copy_fixture("v1_favorite.vault", &dir);
    let bak_path = dir.path().join("v1_favorite.vault.bak");

    let mut v = vault::open(&p, FIXTURE_PW, None).unwrap();
    assert!(v.migrated, "fixture must actually migrate for this test to mean anything");
    vault::change_password(&mut v, b"new-pw", None, KeyfileAction::Keep).unwrap();
    assert!(!v.migrated, "the migrated DB is on disk after change_password");
    assert!(!bak_path.exists());

    vault::save(&mut v).unwrap();
    assert!(
        !bak_path.exists(),
        "a later save must not take a pre-migration .bak of an already-migrated file"
    );
}

#[test]
fn second_save_after_migration_does_not_reclobber_bak() {
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().unwrap();
    let p = copy_fixture("v1_favorite.vault", &dir);
    let original_hash = Sha256::digest(std::fs::read(&p).unwrap());
    let bak_path = dir.path().join("v1_favorite.vault.bak");

    let mut v = vault::open(&p, FIXTURE_PW, None).unwrap();
    vault::save(&mut v).unwrap();
    assert!(!v.migrated, "migrated must clear once the backing-up save has succeeded");
    assert_eq!(Sha256::digest(std::fs::read(&bak_path).unwrap()), original_hash);

    v.conn
        .execute(
            "INSERT INTO entries (id, folder_id, title, created_at, updated_at) VALUES ('e9','root','Second',2,2)",
            [],
        )
        .unwrap();
    vault::save(&mut v).unwrap();

    assert_eq!(
        Sha256::digest(std::fs::read(&bak_path).unwrap()),
        original_hash,
        "a second save must not overwrite the .bak taken on the first save after migration"
    );
}

#[test]
fn bak_after_migration_save_is_still_a_valid_v1_container() {
    let dir = tempfile::tempdir().unwrap();
    let p = copy_fixture("v1_favorite.vault", &dir);

    let mut v = vault::open(&p, FIXTURE_PW, None).unwrap();
    vault::save(&mut v).unwrap();

    let bak_path = dir.path().join("v1_favorite.vault.bak");
    let reopened = vault::open(&bak_path, FIXTURE_PW, None).unwrap();
    assert_eq!(reopened.header.version, 1, ".bak must be the untouched pre-migration v1 file");
    assert!(reopened.migrated, ".bak must still be legacy schema, i.e. genuinely pre-migration");

    let fav: i64 = reopened
        .conn
        .query_row("SELECT is_favorite FROM entries WHERE id='e1'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(fav, 1, ".bak's data must be fully intact, not just its header");
}


#[test]
fn create_on_existing_path_is_refused_and_leaves_file_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("existing.vault");
    std::fs::write(&p, b"not a vault, just bytes that must survive").unwrap();
    let before = std::fs::read(&p).unwrap();

    let err = vault::create(&p, b"pw", "hint", FAST, None).unwrap_err();
    assert!(matches!(err, kokos_core::VaultError::AlreadyExists));

    let after = std::fs::read(&p).unwrap();
    assert_eq!(after, before, "a refused create must not touch the existing file's bytes");
}

#[test]
fn removing_keyfile_allows_password_only_open() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("kf2.vault");
    let kf = dir.path().join("secret2.key");
    std::fs::write(&kf, b"key file bytes").unwrap();

    let mut v = vault::create(&p, b"pw", "hint", FAST, Some(&kf)).unwrap();
    assert!(v.header.requires_keyfile());

    vault::change_password(&mut v, b"pw", None, KeyfileAction::Remove).unwrap();
    assert!(!v.header.requires_keyfile());
    drop(v);

    let h = kokos_core::format::header::read_header_only(&p).unwrap();
    assert!(!h.requires_keyfile(), "Remove must clear the on-disk flag too");
    assert!(
        vault::open(&p, b"pw", None).is_ok(),
        "vault must open with password alone after Remove"
    );
}

#[test]
fn nmh_grant_survives_save_and_reopen_then_is_gone_after_a_revoke_and_save() {
    use kokos_core::nmh_grants;

    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("grants.vault");

    let mut v = vault::create(&p, b"pw", "hint", FAST, None).unwrap();
    nmh_grants::upsert(&v.conn, "chrome-extension://aaa/", "example.com", 100).unwrap();
    vault::save(&mut v).unwrap();
    drop(v);

    let reopened = vault::open(&p, b"pw", None).unwrap();
    assert!(
        nmh_grants::is_granted(&reopened.conn, "chrome-extension://aaa/", "example.com").unwrap(),
        "a saved grant must survive a close/reopen, exactly like any other vault mutation"
    );
    drop(reopened);

    let mut v = vault::open(&p, b"pw", None).unwrap();
    assert!(
        nmh_grants::delete(&v.conn, "chrome-extension://aaa/", "example.com").unwrap(),
        "the grant inserted above must still be there to delete"
    );
    vault::save(&mut v).unwrap();
    drop(v);

    let reopened = vault::open(&p, b"pw", None).unwrap();
    assert!(
        !nmh_grants::is_granted(&reopened.conn, "chrome-extension://aaa/", "example.com").unwrap(),
        "a revoked grant must stay revoked across a close/reopen -- the durability gap this test pins"
    );
}

#[test]
fn save_updates_last_modified() {
    let dir = tempfile::tempdir().unwrap();
    let p = copy_fixture("v1_basic.vault", &dir);
    let mut v = vault::open(&p, FIXTURE_PW, None).unwrap();

    let before: Option<String> = v
        .conn
        .query_row("SELECT value FROM metadata WHERE key = 'last_modified'", [], |r| r.get(0))
        .ok();

    v.conn.execute("UPDATE metadata SET value = 'x' WHERE key = 'db_description'", []).unwrap();
    vault::save(&mut v).unwrap();

    let after: String = v
        .conn
        .query_row("SELECT value FROM metadata WHERE key = 'last_modified'", [], |r| r.get(0))
        .expect("last_modified must exist after a save");
    let after_n: i64 = after.parse().expect("last_modified is a unix integer in a text column");
    assert!(after_n > 0, "last_modified must be a real timestamp");
    assert_ne!(Some(after), before, "save must refresh last_modified");
}


#[test]
fn create_rejects_an_oversized_hint() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("long-hint.vault");
    let hint = "x".repeat(kokos_core::format::header::MAX_HINT_LEN + 1);

    let err = vault::create(&p, b"pw", &hint, FAST, None).unwrap_err();

    assert!(matches!(err, kokos_core::VaultError::HintTooLong));
    assert!(!p.exists(), "a rejected create must not leave a file behind");
}

#[test]
fn a_max_length_hint_still_parses_through_the_header_probe() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("max-hint.vault");
    let hint = "x".repeat(kokos_core::format::header::MAX_HINT_LEN);

    let v = vault::create(&p, b"pw", &hint, FAST, None).unwrap();
    drop(v);

    let h = kokos_core::format::header::read_header_only(&p).unwrap();
    assert_eq!(h.hint, hint, "a maximum-length hint must survive the header probe");
}

#[test]
fn change_password_rejects_an_oversized_hint() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("change-hint.vault");
    let hint = "x".repeat(kokos_core::format::header::MAX_HINT_LEN + 1);

    let mut v = vault::create(&p, b"pw", "original hint", FAST, None).unwrap();
    let bak_path = kokos_core::format::atomic::backup_path(&p);

    let err = vault::change_password(&mut v, b"new-pw", Some(&hint), KeyfileAction::Keep).unwrap_err();

    assert!(matches!(err, kokos_core::VaultError::HintTooLong));
    assert!(!bak_path.exists(), "a rejected change_password must not create a .bak");

    let reopened = vault::open(&p, b"pw", None).unwrap();
    assert_eq!(reopened.header.hint, "original hint", "the vault must be untouched after a rejected hint");
}

#[test]
fn cyrillic_hint_byte_length_cap_is_enforced() {

    let cyrillic_char = "М";
    assert_eq!(cyrillic_char.len(), 2, "Cyrillic М must be 2 bytes in UTF-8");

    let at_boundary_hint = cyrillic_char.repeat(127);
    assert_eq!(
        at_boundary_hint.len(),
        254,
        "a Cyrillic hint of 127 characters must be 254 bytes (just under limit)"
    );

    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("cyrillic-254.vault");
    let v = vault::create(&p, b"pw", &at_boundary_hint, FAST, None).unwrap();
    drop(v);

    let h = kokos_core::format::header::read_header_only(&p).unwrap();
    assert_eq!(
        h.hint, at_boundary_hint,
        "a Cyrillic hint at 254 bytes must survive the header probe"
    );

    let p2 = dir.path().join("cyrillic-256.vault");
    let over_max_hint = cyrillic_char.repeat(128);
    assert_eq!(over_max_hint.len(), 256, "overcapacity Cyrillic must be 256 bytes");

    let err = vault::create(&p2, b"pw", &over_max_hint, FAST, None).unwrap_err();
    assert!(matches!(err, kokos_core::VaultError::HintTooLong));
    assert!(!p2.exists(), "a rejected create must not leave a file behind");
}


#[test]
fn set_hint_rewrites_the_hint_without_rekeying() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("hint.vault");
    let mut v = vault::create(&p, b"pw", "old hint", FAST, None).unwrap();
    let salt_before = v.header.salt;

    vault::set_hint(&mut v, "new hint").unwrap();
    drop(v);

    let h = kokos_core::format::header::read_header_only(&p).unwrap();
    assert_eq!(h.hint, "new hint");
    assert_eq!(h.salt, salt_before, "set_hint must not rotate the salt — it does no key derivation");
    assert!(vault::open(&p, b"pw", None).is_ok(), "the same password must still open the vault");
}

#[test]
fn set_hint_with_an_empty_string_removes_the_hint() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("clear.vault");
    let mut v = vault::create(&p, b"pw", "old hint", FAST, None).unwrap();

    vault::set_hint(&mut v, "").unwrap();
    drop(v);

    assert_eq!(kokos_core::format::header::read_header_only(&p).unwrap().hint, "");
}

#[test]
fn set_hint_bumps_the_sync_revision() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("rev.vault");
    let mut v = vault::create(&p, b"pw", "old hint", FAST, None).unwrap();
    let rev_before = kokos_core::db::get_sync_revision(&v.conn).unwrap();

    vault::set_hint(&mut v, "new hint").unwrap();

    let rev_after = kokos_core::db::get_sync_revision(&v.conn).unwrap();
    assert!(rev_after > rev_before, "a hint edit must advance the sync revision ({rev_before} -> {rev_after})");
}

#[test]
fn set_hint_needs_no_keyfile_on_a_keyfile_vault() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("kf-hint.vault");
    let kf = dir.path().join("secret.key");
    std::fs::write(&kf, b"key file bytes").unwrap();
    let mut v = vault::create(&p, b"pw", "old hint", FAST, Some(&kf)).unwrap();

    vault::set_hint(&mut v, "new hint").unwrap();
    drop(v);

    let h = kokos_core::format::header::read_header_only(&p).unwrap();
    assert_eq!(h.hint, "new hint");
    assert!(h.requires_keyfile(), "the key-file flag must survive a hint edit");
    assert!(vault::open(&p, b"pw", Some(&kf)).is_ok());
}

#[test]
fn set_hint_rejects_an_oversized_hint_and_leaves_the_file_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("too-long.vault");
    let mut v = vault::create(&p, b"pw", "old hint", FAST, None).unwrap();
    let before = std::fs::read(&p).unwrap();

    let err = vault::set_hint(&mut v, &"x".repeat(kokos_core::format::header::MAX_HINT_LEN + 1)).unwrap_err();

    assert!(matches!(err, kokos_core::VaultError::HintTooLong));
    assert_eq!(v.header.hint, "old hint", "a rejected set_hint must not touch the in-memory header");
    assert_eq!(std::fs::read(&p).unwrap(), before, "a rejected set_hint must not touch the file");
}

#[test]
fn failed_set_hint_restores_the_previous_hint() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    let p = sub.join("gone.vault");
    let mut v = vault::create(&p, b"pw", "old hint", FAST, None).unwrap();

    std::fs::remove_dir_all(&sub).unwrap();
    let err = vault::set_hint(&mut v, "new hint").unwrap_err();

    assert!(matches!(err, kokos_core::VaultError::Io(_)), "expected an io error, got {err:?}");
    assert_eq!(v.header.hint, "old hint", "a failed write must leave the in-memory hint as it was");
}


#[test]
fn read_header_only_still_parses_a_pre_cap_vault_with_an_oversized_hint() {
    use kokos_core::format::header::{read_header_only, Header, CURRENT_VERSION, MAX_HINT_LEN};

    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("pre-cap-long-hint.vault");

    let long_hint = "x".repeat(MAX_HINT_LEN + 200);
    let header = Header {
        version: CURRENT_VERSION,
        flags: 0,
        hint: long_hint.clone(),
        kdf: FAST,
        salt: kokos_core::crypto::random_salt(),
        nonce: kokos_core::crypto::random_nonce(),
    };
    let mut bytes = Vec::new();
    header.write(&mut bytes);
    bytes.extend_from_slice(&[0u8; 32]);

    std::fs::write(&p, &bytes).unwrap();

    let h = read_header_only(&p).unwrap();
    assert_eq!(h.hint, long_hint, "a pre-cap vault's oversized hint must survive the header probe intact");
}

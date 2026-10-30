//! In-memory SQLite: the decrypted container lives here and nowhere else.

pub mod migrate;
pub mod schema;

use rusqlite::Connection;
use zeroize::Zeroizing;

pub use schema::SCHEMA_VERSION;

use crate::error::Result;

/// Loads a decrypted SQLite image into memory.
///
/// deserialize() hands ownership of the buffer to SQLite, which will free it
/// with sqlite3_free — so the buffer must come from sqlite3_malloc. A Rust Vec
/// comes from Rust's global allocator and cannot be handed over: wrapping it
/// would only work while both allocators happen to wrap the same system malloc,
/// and would break silently under a custom #[global_allocator]. Copy instead.
pub fn open_in_memory(image: &[u8]) -> Result<Connection> {
    let mut conn = Connection::open_in_memory()?;

    let owned = unsafe {
        let ptr = rusqlite::ffi::sqlite3_malloc64(image.len() as u64) as *mut u8;
        let nn = std::ptr::NonNull::new(ptr)
            .ok_or_else(|| crate::error::VaultError::Db("sqlite3_malloc64 failed".into()))?;
        std::ptr::copy_nonoverlapping(image.as_ptr(), nn.as_ptr(), image.len());
        rusqlite::serialize::OwnedData::from_raw_nonnull(nn, image.len())
    };

    conn.deserialize(rusqlite::DatabaseName::Main, owned, false)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(conn)
}

/// Serializes the in-memory database to bytes.
///
/// The returned image is the entire decrypted vault — the user's whole
/// password set in plaintext — so it is wrapped in `Zeroizing` to guarantee
/// the buffer is wiped on drop. This matches every other secret-bearing
/// return in this crate (`crypto::decrypt`, `crypto::derive_key`,
/// `keyfile::key_material`); `Zeroizing<Vec<u8>>` derefs to `[u8]`, so
/// callers that only need to read the bytes are unaffected.
///
/// This does not cover every copy of the data: the `Data::Owned`/`Data::Shared`
/// buffer that rusqlite's `Connection::serialize()` hands back, and the
/// `sqlite3_malloc`'d copy made in `open_in_memory`, both live inside
/// rusqlite/SQLite and are freed without zeroing. That memory is out of
/// reach from this module.
pub fn serialize(conn: &Connection) -> Result<Zeroizing<Vec<u8>>> {
    let data = conn.serialize(rusqlite::DatabaseName::Main)?;
    Ok(Zeroizing::new(data.to_vec()))
}

pub fn create_fresh() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch(schema::TARGET_SCHEMA)?;
    conn.execute_batch(schema::FTS_SCHEMA)?;
    conn.execute_batch(schema::FTS_TRIGGERS)?;
    populate_defaults(&conn, now_unix())?;
    Ok(conn)
}

/// Root folder + default templates + metadata. Mirrors PopulateDefaultData
/// in the Go reference, including the fixed template IDs.
pub fn populate_defaults(conn: &Connection, now: i64) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO folders (id, parent_id, name, icon_id, sort_order, created_at, updated_at)
         VALUES ('root', NULL, 'Root', NULL, 0, ?1, ?1)",
        [now],
    )?;
    for (id, name, ftype, protected, order) in schema::DEFAULT_TEMPLATES {
        conn.execute(
            "INSERT OR IGNORE INTO field_templates (id, name, field_type, is_protected, sort_order)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![id, name, ftype, protected, order],
        )?;
    }
    for (k, v) in [
        ("db_name", "My Vault"),
        ("db_description", ""),
        ("trash_auto_delete_days", "0"),
        ("schema_version", SCHEMA_VERSION),
    ] {
        conn.execute("INSERT OR IGNORE INTO metadata (key, value) VALUES (?1, ?2)", [k, v])?;
    }
    conn.execute(
        "INSERT OR IGNORE INTO metadata (key, value) VALUES ('device_id', ?1)",
        [uuid::Uuid::new_v4().to_string()],
    )?;
    conn.execute("INSERT OR IGNORE INTO metadata (key, value) VALUES ('sync_revision', '0')", [])?;
    conn.execute(
        "INSERT OR IGNORE INTO metadata (key, value) VALUES ('created_at', ?1)",
        [now.to_string()],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO metadata (key, value) VALUES ('last_modified', ?1)",
        [now.to_string()],
    )?;
    Ok(())
}

/// Stable per-vault device identity (uuid v4), minted at creation / migration.
pub fn get_device_id(conn: &rusqlite::Connection) -> crate::error::Result<String> {
    Ok(conn.query_row("SELECT value FROM metadata WHERE key='device_id'", [], |r| r.get(0))?)
}

/// Monotonic sync revision (bumped every `vault::save`). Missing/garbage → 0.
pub fn get_sync_revision(conn: &rusqlite::Connection) -> crate::error::Result<u64> {
    use rusqlite::OptionalExtension;
    let raw: Option<String> = conn
        .query_row("SELECT value FROM metadata WHERE key='sync_revision'", [], |r| r.get(0))
        .optional()?;
    Ok(raw.and_then(|s| s.parse().ok()).unwrap_or(0))
}

pub fn set_sync_revision(conn: &rusqlite::Connection, rev: u64) -> crate::error::Result<()> {
    conn.execute(
        "INSERT INTO metadata (key, value) VALUES ('sync_revision', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [rev.to_string()],
    )?;
    Ok(())
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_db_has_target_schema() {
        let c = create_fresh().unwrap();
        for table in ["folders", "icons", "field_templates", "tags", "entries",
                      "entry_fields", "entry_tags", "attachments", "entry_relations",
                      "metadata", "entry_field_history", "entries_fts", "audit_log"] {
            let n: i64 = c
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "missing table: {table}");
        }
    }

    #[test]
    fn fresh_db_has_root_folder_and_templates() {
        let c = create_fresh().unwrap();
        let root: i64 = c.query_row("SELECT COUNT(*) FROM folders WHERE id = 'root'", [], |r| r.get(0)).unwrap();
        assert_eq!(root, 1);
        let tpl: i64 = c.query_row("SELECT COUNT(*) FROM field_templates", [], |r| r.get(0)).unwrap();
        assert_eq!(tpl, 8);
        let name: String = c
            .query_row("SELECT name FROM field_templates WHERE id = 'tpl_password'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(name, "Password");
    }

    #[test]
    fn fresh_db_records_schema_version() {
        let c = create_fresh().unwrap();
        let v: String = c
            .query_row("SELECT value FROM metadata WHERE key = 'schema_version'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }

    #[test]
    fn fresh_vault_has_device_id_and_zero_revision() {
        let conn = create_fresh().unwrap();
        let dev = get_device_id(&conn).unwrap();
        assert_eq!(dev.len(), 36);
        assert_eq!(get_sync_revision(&conn).unwrap(), 0);
    }

    #[test]
    fn set_and_get_sync_revision_roundtrips() {
        let conn = create_fresh().unwrap();
        set_sync_revision(&conn, 7).unwrap();
        assert_eq!(get_sync_revision(&conn).unwrap(), 7);
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let c = create_fresh().unwrap();
        let err = c.execute(
            "INSERT INTO entry_fields (id, entry_id, name, value) VALUES ('f', 'no-such-entry', 'n', 'v')",
            [],
        );
        assert!(err.is_err(), "foreign_keys must be ON");
    }

    #[test]
    fn fts_trigger_indexes_new_entries() {
        let c = create_fresh().unwrap();
        c.execute(
            "INSERT INTO entries (id, folder_id, title, notes, created_at, updated_at)
             VALUES ('e1', 'root', 'GitHub', 'work', 1, 1)",
            [],
        )
        .unwrap();
        let hits: i64 = c
            .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'GitHub'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(hits, 1, "insert trigger must populate the FTS index");
    }

    #[test]
    fn serialize_round_trip_preserves_rows() {
        let c = create_fresh().unwrap();
        c.execute(
            "INSERT INTO entries (id, folder_id, title, created_at, updated_at) VALUES ('e1', 'root', 'T', 1, 1)",
            [],
        )
        .unwrap();
        let image: Zeroizing<Vec<u8>> = serialize(&c).unwrap();
        let restored = open_in_memory(&image).unwrap();
        let title: String = restored.query_row("SELECT title FROM entries WHERE id='e1'", [], |r| r.get(0)).unwrap();
        assert_eq!(title, "T");
    }

    #[test]
    fn fts_trigger_indexes_new_field() {
        let c = create_fresh().unwrap();
        c.execute(
            "INSERT INTO entries (id, folder_id, title, created_at, updated_at)
             VALUES ('e1', 'root', 'Site', 1, 1)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO entry_fields (id, entry_id, name, value) VALUES ('f1', 'e1', 'login', 'octocat')",
            [],
        )
        .unwrap();

        let hits: i64 = c
            .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'octocat'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(hits, 1, "entry_fields insert trigger must index the new field value");
    }

    #[test]
    fn fts_trigger_reindexes_on_field_update() {
        let c = create_fresh().unwrap();
        c.execute(
            "INSERT INTO entries (id, folder_id, title, created_at, updated_at)
             VALUES ('e1', 'root', 'Site', 1, 1)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO entry_fields (id, entry_id, name, value) VALUES ('f1', 'e1', 'login', 'octocat')",
            [],
        )
        .unwrap();

        c.execute("UPDATE entry_fields SET value = 'newlogin' WHERE id = 'f1'", []).unwrap();

        let new_hits: i64 = c
            .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'newlogin'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(new_hits, 1, "entry_fields update trigger must index the new value");

        let stale_hits: i64 = c
            .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'octocat'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stale_hits, 0, "entry_fields update trigger must drop the stale value, not just append the new one");
    }

    #[test]
    fn fts_trigger_removes_deleted_field_term() {
        let c = create_fresh().unwrap();
        c.execute(
            "INSERT INTO entries (id, folder_id, title, created_at, updated_at)
             VALUES ('e1', 'root', 'Site', 1, 1)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO entry_fields (id, entry_id, name, value) VALUES ('f1', 'e1', 'login', 'octocat')",
            [],
        )
        .unwrap();
        c.execute("UPDATE entry_fields SET value = 'newlogin' WHERE id = 'f1'", []).unwrap();

        c.execute("DELETE FROM entry_fields WHERE id = 'f1'", []).unwrap();

        let field_hits: i64 = c
            .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'newlogin'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(field_hits, 0, "entry_fields delete trigger must remove the field's term from the index");

        let title_hits: i64 = c
            .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'Site'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(title_hits, 1, "the entry itself must still be indexed by title after its field is deleted");
    }

    #[test]
    fn fts_trigger_reindexes_entry_title_keeps_fields() {
        let c = create_fresh().unwrap();
        c.execute(
            "INSERT INTO entries (id, folder_id, title, created_at, updated_at)
             VALUES ('e1', 'root', 'Old Title', 1, 1)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO entry_fields (id, entry_id, name, value) VALUES ('f1', 'e1', 'login', 'octocat')",
            [],
        )
        .unwrap();

        c.execute("UPDATE entries SET title = 'New Title', updated_at = 2 WHERE id = 'e1'", []).unwrap();

        let title_hits: i64 = c
            .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'New'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(title_hits, 1, "entries update trigger must index the new title");

        let field_hits: i64 = c
            .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'octocat'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(field_hits, 1, "entries update trigger must not drop existing fields when reindexing the title");
    }

    #[test]
    fn fts_trigger_removes_entry_on_delete() {
        let c = create_fresh().unwrap();
        c.execute(
            "INSERT INTO entries (id, folder_id, title, created_at, updated_at)
             VALUES ('e1', 'root', 'Site', 1, 1)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO entry_fields (id, entry_id, name, value) VALUES ('f1', 'e1', 'login', 'octocat')",
            [],
        )
        .unwrap();

        c.execute("DELETE FROM entries WHERE id = 'e1'", []).unwrap();

        let n: i64 = c.query_row("SELECT COUNT(*) FROM entries_fts", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "deleting an entry must not leave an orphaned row in the FTS index");
    }

    #[test]
    fn fts_trigger_removes_soft_deleted_entry() {
        let c = create_fresh().unwrap();
        c.execute(
            "INSERT INTO entries (id, folder_id, title, notes, created_at, updated_at)
             VALUES ('e1', 'root', 'GitHub', 'work', 1, 1)",
            [],
        )
        .unwrap();

        c.execute("UPDATE entries SET is_deleted = 1, updated_at = 2 WHERE id = 'e1'", []).unwrap();

        let hits: i64 = c
            .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'GitHub'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(hits, 0, "soft-deleting an entry (is_deleted=1) must remove it from the FTS index");
    }

    #[test]
    fn fts_trigger_restores_entry_and_fields_on_undelete() {
        let c = create_fresh().unwrap();
        c.execute(
            "INSERT INTO entries (id, folder_id, title, notes, created_at, updated_at)
             VALUES ('e1', 'root', 'GitHub', 'work', 1, 1)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO entry_fields (id, entry_id, name, value) VALUES ('f1', 'e1', 'login', 'octocat')",
            [],
        )
        .unwrap();

        c.execute("UPDATE entries SET is_deleted = 1, updated_at = 2 WHERE id = 'e1'", []).unwrap();
        c.execute("UPDATE entries SET is_deleted = 0, updated_at = 3 WHERE id = 'e1'", []).unwrap();

        let title_hits: i64 = c
            .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'GitHub'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(title_hits, 1, "restoring an entry from the trash (is_deleted=0) must reindex it");

        let field_hits: i64 = c
            .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'octocat'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(field_hits, 1, "restoring an entry must bring its field values back into the index");
    }

    #[test]
    fn fts_trigger_skips_field_edit_on_trashed_entry() {
        let c = create_fresh().unwrap();
        c.execute(
            "INSERT INTO entries (id, folder_id, title, created_at, updated_at)
             VALUES ('e1', 'root', 'Site', 1, 1)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO entry_fields (id, entry_id, name, value) VALUES ('f1', 'e1', 'login', 'octocat')",
            [],
        )
        .unwrap();
        c.execute("UPDATE entries SET is_deleted = 1, updated_at = 2 WHERE id = 'e1'", []).unwrap();

        c.execute("UPDATE entry_fields SET value = 'newlogin' WHERE id = 'f1'", []).unwrap();

        let hits: i64 = c
            .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'newlogin'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(hits, 0, "editing a field on a trashed entry must not index the new value");

        let n: i64 = c.query_row("SELECT COUNT(*) FROM entries_fts", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "a trashed entry must have no row in the FTS index, even after a field edit");
    }

    #[test]
    fn fts_trigger_skips_insert_of_already_deleted_entry() {
        let c = create_fresh().unwrap();
        c.execute(
            "INSERT INTO entries (id, folder_id, title, notes, is_deleted, created_at, updated_at)
             VALUES ('e1', 'root', 'GitHub', 'work', 1, 1, 1)",
            [],
        )
        .unwrap();

        let n: i64 = c.query_row("SELECT COUNT(*) FROM entries_fts", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "inserting an entry that is already is_deleted=1 must not index it");
    }

    #[test]
    fn open_in_memory_enables_foreign_keys() {
        let c = create_fresh().unwrap();
        let image = serialize(&c).unwrap();
        let restored = open_in_memory(&image).unwrap();

        let err = restored.execute(
            "INSERT INTO entry_fields (id, entry_id, name, value) VALUES ('f', 'no-such-entry', 'n', 'v')",
            [],
        );
        assert!(err.is_err(), "open_in_memory must turn foreign_keys ON so a loaded vault enforces referential integrity");
    }

    #[test]
    fn field_with_null_value_keeps_its_name_in_the_index() {
        let conn = create_fresh().unwrap();
        let now = now_unix();
        conn.execute(
            "INSERT INTO entries (id, folder_id, title, is_deleted, created_at, updated_at)
             VALUES ('e1', 'root', 'Site', 0, ?1, ?1)",
            [now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type)
             VALUES ('f1', 'e1', 'tpl_totp', 'Recovery Code', NULL, 1, 'secret')",
            [],
        )
        .unwrap();

        let hits: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'Recovery'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(hits, 1, "a NULL-valued field must not drop its name from the index");
    }

    #[test]
    fn protected_field_value_is_not_indexed_but_name_is() {
        let c = create_fresh().unwrap();
        let now = now_unix();
        c.execute(
            "INSERT INTO entries (id, folder_id, title, is_deleted, created_at, updated_at)
             VALUES ('e1', 'root', 'Bank', 0, ?1, ?1)",
            [now],
        ).unwrap();
        c.execute(
            "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type)
             VALUES ('f1', 'e1', 'tpl_password', 'Password', 'hunter2xyz', 1, 'secret')",
            [],
        ).unwrap();

        let by_value: i64 = c.query_row(
            "SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'hunter2xyz'", [], |r| r.get(0),
        ).unwrap();
        assert_eq!(by_value, 0, "a protected field's VALUE must never enter the FTS index");

        let by_name: i64 = c.query_row(
            "SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'Password'", [], |r| r.get(0),
        ).unwrap();
        assert_eq!(by_name, 1, "a protected field's NAME must still be searchable");
    }
}

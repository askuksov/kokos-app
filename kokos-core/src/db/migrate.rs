//! Migration of a live v1 container to the current schema.
//!
//! Runs in memory at open time: the file on disk is untouched until the user
//! saves. Mostly additive -- the Go version keeps working as a fallback (it
//! reads favorites from the tag, ignores is_favorite, and treats
//! schema_version as one more metadata row) -- but widening a CHECK
//! constraint (entry_fields.field_type, field_templates.field_type) is not
//! expressible as an ALTER in SQLite, so those columns go through a
//! drop-and-rename table rebuild in place.

use rusqlite::Connection;

use super::schema::{self, SCHEMA_VERSION};
use crate::error::{Result, VaultError};

/// Returns true if the database was legacy and has been migrated.
///
/// Compares versions numerically rather than as opaque strings: a plain
/// string-equality guard treats "not equal to the current version" as one
/// bucket, so a container from a *future* version (e.g. `schema_version =
/// "3"` while this binary's `SCHEMA_VERSION` is `"2"`) would fail the
/// equality check, fall through, and get its FTS shape rebuilt to the older
/// v2 layout and its version stamped back down to `"2"` — destroying data on
/// a downgrade. Parsing lets a future version be told apart from a legacy one
/// and refused instead. A value that fails to parse is treated the same way
/// an absent one always has been: as legacy, safe to migrate.
pub fn migrate(conn: &Connection) -> Result<bool> {
    let current: u32 = SCHEMA_VERSION.parse().expect("SCHEMA_VERSION must be a plain integer");
    let stored = current_version(conn)?.and_then(|v| v.parse::<u32>().ok());

    match stored {
        Some(found) if found == current => return Ok(false),
        Some(found) if found > current => return Err(VaultError::UnsupportedVersion { found }),
        _ => {}
    }

    if !column_exists(conn, "entries", "is_favorite")? {
        conn.execute("ALTER TABLE entries ADD COLUMN is_favorite INTEGER DEFAULT 0", [])?;
    }

    if !column_exists(conn, "entries", "entry_type")? {
        conn.execute(
            "ALTER TABLE entries ADD COLUMN entry_type TEXT NOT NULL DEFAULT 'login' \
             CHECK (entry_type IN ('login','card','secure_note','wifi'))",
            [],
        )?;
    }

    conn.execute(
        "UPDATE entries SET is_favorite = 1 WHERE id IN (
             SELECT et.entry_id FROM entry_tags et
             JOIN tags t ON t.id = et.tag_id
             WHERE t.name = 'favorite'
         )",
        [],
    )?;

    conn.execute_batch(schema::TARGET_SCHEMA)?;

    super::populate_defaults(conn, super::now_unix())?;

    if !entry_fields_field_type_check_allows_phone(conn)? {
        conn.execute_batch(
            "CREATE TABLE entry_fields_new (
                 id TEXT PRIMARY KEY,
                 entry_id TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
                 template_id TEXT REFERENCES field_templates(id) ON DELETE SET NULL,
                 name TEXT NOT NULL,
                 value TEXT,
                 is_protected INTEGER DEFAULT 0,
                 field_type TEXT DEFAULT 'text' CHECK (field_type IN ('text','secret','url','email','otp','date','phone')),
                 sort_order INTEGER DEFAULT 0
             );
             INSERT INTO entry_fields_new
                 (id, entry_id, template_id, name, value, is_protected, field_type, sort_order)
             SELECT id, entry_id, template_id, name, value, is_protected,
                    CASE WHEN field_type IN ('text','secret','url','email','otp','date','phone')
                         THEN field_type ELSE 'text' END,
                    sort_order
             FROM entry_fields;
             DROP TABLE entry_fields;
             DROP TRIGGER IF EXISTS entries_fts_ai;
             DROP TRIGGER IF EXISTS entries_fts_ad;
             DROP TRIGGER IF EXISTS entries_fts_au;
             ALTER TABLE entry_fields_new RENAME TO entry_fields;
             CREATE INDEX IF NOT EXISTS idx_entry_fields_entry ON entry_fields(entry_id);",
        )?;
    }

    if !field_templates_field_type_check_allows_phone(conn)? {
        conn.pragma_update(None, "foreign_keys", "OFF")?;
        conn.execute_batch(
            "CREATE TABLE field_templates_new (
                 id TEXT PRIMARY KEY,
                 name TEXT NOT NULL UNIQUE,
                 field_type TEXT NOT NULL CHECK (field_type IN ('text','secret','url','email','otp','date','phone')),
                 is_protected INTEGER DEFAULT 0,
                 sort_order INTEGER DEFAULT 0
             );
             INSERT INTO field_templates_new (id, name, field_type, is_protected, sort_order)
             SELECT id, name,
                    CASE WHEN field_type IN ('text','secret','url','email','otp','date','phone')
                         THEN field_type ELSE 'text' END,
                    is_protected, sort_order
             FROM field_templates;
             DROP TABLE field_templates;
             ALTER TABLE field_templates_new RENAME TO field_templates;",
        )?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let mut stmt = conn.prepare("PRAGMA foreign_key_check")?;
        let orphaned = stmt.query([])?.next()?.is_some();
        if orphaned {
            return Err(VaultError::Db(
                "field_templates rebuild left a dangling entry_fields.template_id reference".into(),
            ));
        }
    }

    conn.execute_batch("DROP TABLE IF EXISTS entries_fts;")?;
    conn.execute_batch(schema::FTS_SCHEMA)?;
    conn.execute_batch(schema::FTS_TRIGGERS)?;
    rebuild_fts(conn)?;

    conn.execute(
        "INSERT OR IGNORE INTO metadata (key, value) VALUES ('device_id', ?1)",
        [uuid::Uuid::new_v4().to_string()],
    )?;
    conn.execute("INSERT OR IGNORE INTO metadata (key, value) VALUES ('sync_revision', '0')", [])?;

    conn.execute(
        "INSERT INTO metadata (key, value) VALUES ('schema_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [SCHEMA_VERSION],
    )?;

    Ok(true)
}

/// Backfills the freshly (re)created FTS index from existing rows. The
/// insert/update/delete triggers installed above only cover writes from this
/// point forward; rows that already existed in the v1 container need to be
/// indexed explicitly once.
fn rebuild_fts(conn: &Connection) -> Result<()> {
    conn.execute("DELETE FROM entries_fts", [])?;
    conn.execute(
        "INSERT INTO entries_fts (id, title, notes, fields)
         SELECT e.id, e.title, COALESCE(e.notes, ''),
                COALESCE(GROUP_CONCAT(ef.name || ': ' || CASE WHEN ef.is_protected = 0 THEN COALESCE(ef.value, '') ELSE '' END, ' '), '')
         FROM entries e
         LEFT JOIN entry_fields ef ON ef.entry_id = e.id
         WHERE e.is_deleted = 0
         GROUP BY e.id",
        [],
    )?;
    Ok(())
}

/// The schema_version recorded in `metadata`, or `None` if the container
/// predates the `metadata` table entirely (there is no such fixture in
/// practice — the Go app always creates `metadata` — but this keeps
/// `migrate` from panicking on a container that somehow lacks it).
fn current_version(conn: &Connection) -> Result<Option<String>> {
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='metadata'",
        [],
        |r| r.get(0),
    )?;
    if exists == 0 {
        return Ok(None);
    }
    let v: Option<String> = conn
        .query_row("SELECT value FROM metadata WHERE key='schema_version'", [], |r| r.get(0))
        .ok();
    Ok(v)
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// True if the live `entry_fields` table already carries a CHECK on field_type
/// (i.e. this DB is already at/after v7). Read from the stored DDL text.
///
/// Only the v6 test below still calls this (the v9 guard uses the more
/// specific `entry_fields_field_type_check_allows_phone` instead) — cfg-gated
/// to `test` so a non-test `cargo build` doesn't flag it as dead code.
#[cfg(test)]
fn entry_fields_has_field_type_check(conn: &Connection) -> Result<bool> {
    let sql: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='entry_fields'",
            [],
            |r| r.get(0),
        )
        .ok();
    Ok(sql.map(|s| s.contains("CHECK")).unwrap_or(false))
}

/// True if the live `entry_fields` field_type CHECK already lists 'phone' (this
/// DB is at/after v9). Distinct from `entry_fields_has_field_type_check`, which
/// only detects *some* CHECK: a v8 vault has a CHECK but not 'phone' and must
/// still be rebuilt to gain it.
fn entry_fields_field_type_check_allows_phone(conn: &Connection) -> Result<bool> {
    let sql: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='entry_fields'",
            [],
            |r| r.get(0),
        )
        .ok();
    Ok(sql.map(|s| s.contains("'phone'")).unwrap_or(false))
}

/// True if the live `field_templates` field_type CHECK already lists 'phone'
/// (this DB is at/after v9). field_templates has carried a field_type CHECK
/// since the first schema commit, so — unlike entry_fields, which only grew a
/// CHECK at v7 — every existing vault already matches "some CHECK present";
/// only the exact allow-list distinguishes an old CHECK from the v9 one.
fn field_templates_field_type_check_allows_phone(conn: &Connection) -> Result<bool> {
    let sql: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='field_templates'",
            [],
            |r| r.get(0),
        )
        .ok();
    Ok(sql.map(|s| s.contains("'phone'")).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_vault_migrates_in_sync_rows() {
        let conn = crate::db::create_fresh().unwrap();
        conn.execute("UPDATE metadata SET value='4' WHERE key='schema_version'", []).unwrap();
        conn.execute("DELETE FROM metadata WHERE key IN ('device_id','sync_revision')", []).unwrap();
        assert!(crate::db::get_device_id(&conn).is_err(), "pre-migration v4 vault must have no device_id row");

        let migrated = migrate(&conn).unwrap();
        assert!(migrated);

        assert_eq!(crate::db::get_sync_revision(&conn).unwrap(), 0);
        assert_eq!(crate::db::get_device_id(&conn).unwrap().len(), 36);
        let ver: String =
            conn.query_row("SELECT value FROM metadata WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(ver, "9");
    }

    #[test]
    fn v5_vault_gains_nmh_grants() {
        let conn = crate::db::create_fresh().unwrap();
        conn.execute("DROP TABLE nmh_grants", []).unwrap();
        conn.execute("UPDATE metadata SET value='5' WHERE key='schema_version'", []).unwrap();

        let probe: rusqlite::Result<i64> =
            conn.query_row("SELECT COUNT(*) FROM nmh_grants", [], |r| r.get(0));
        assert!(probe.is_err(), "pre-migration v5 vault must have no nmh_grants table");

        let migrated = migrate(&conn).unwrap();
        assert!(migrated);

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM nmh_grants", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 0, "migration (re)creates the table, empty");

        let ver: String =
            conn.query_row("SELECT value FROM metadata WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(ver, "9");
    }

    #[test]
    fn v6_vault_gains_entry_fields_check() {
        let conn = crate::db::create_fresh().unwrap();
        conn.execute_batch(
            "DROP TABLE entry_fields;
             CREATE TABLE entry_fields (
                 id TEXT PRIMARY KEY,
                 entry_id TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
                 template_id TEXT REFERENCES field_templates(id) ON DELETE SET NULL,
                 name TEXT NOT NULL, value TEXT,
                 is_protected INTEGER DEFAULT 0,
                 field_type TEXT DEFAULT 'text',
                 sort_order INTEGER DEFAULT 0
             );",
        )
        .unwrap();
        conn.execute("UPDATE metadata SET value='6' WHERE key='schema_version'", []).unwrap();
        assert!(!entry_fields_has_field_type_check(&conn).unwrap(), "pre-state must lack the CHECK");

        assert!(migrate(&conn).unwrap());

        assert!(entry_fields_has_field_type_check(&conn).unwrap(), "migration must add the CHECK");
        let ver: String =
            conn.query_row("SELECT value FROM metadata WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(ver, "9");
    }

    #[test]
    fn v7_vault_gains_entry_type_defaulting_existing_rows_to_login() {
        let conn = crate::db::create_fresh().unwrap();
        conn.execute("ALTER TABLE entries DROP COLUMN entry_type", []).unwrap();
        conn.execute(
            "INSERT INTO entries (id, folder_id, title, is_deleted, created_at, updated_at)
             VALUES ('e_pre', 'root', 'Legacy', 0, 1, 1)",
            [],
        )
        .unwrap();
        conn.execute("UPDATE metadata SET value='7' WHERE key='schema_version'", []).unwrap();
        assert!(!column_exists(&conn, "entries", "entry_type").unwrap(), "pre-state must lack entry_type");

        assert!(migrate(&conn).unwrap());

        assert!(column_exists(&conn, "entries", "entry_type").unwrap(), "migration must add entry_type");
        let t: String =
            conn.query_row("SELECT entry_type FROM entries WHERE id='e_pre'", [], |r| r.get(0)).unwrap();
        assert_eq!(t, "login", "an existing row must default to 'login'");
        let ver: String =
            conn.query_row("SELECT value FROM metadata WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(ver, "9");
    }
}

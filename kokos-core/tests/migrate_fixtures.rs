use kokos_core::db::{migrate::migrate, open_in_memory};

/// Builds a legacy v1 image: the schema as the Go version leaves it —
/// no is_favorite, no entry_field_history, favorite stored as a tag.
fn legacy_image() -> Vec<u8> {
    let c = rusqlite::Connection::open_in_memory().unwrap();
    c.execute_batch(
        r#"
        CREATE TABLE folders (id TEXT PRIMARY KEY, parent_id TEXT, name TEXT NOT NULL,
            icon_id TEXT, sort_order INTEGER DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
        CREATE TABLE icons (id TEXT PRIMARY KEY, name TEXT, data BLOB NOT NULL, mime_type TEXT);
        CREATE TABLE field_templates (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
            field_type TEXT NOT NULL, is_protected INTEGER DEFAULT 0, sort_order INTEGER DEFAULT 0);
        CREATE TABLE tags (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, color TEXT);
        CREATE TABLE entries (id TEXT PRIMARY KEY, folder_id TEXT, title TEXT NOT NULL, icon_id TEXT,
            notes TEXT, is_deleted INTEGER DEFAULT 0, deleted_at INTEGER,
            created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
        CREATE TABLE entry_fields (id TEXT PRIMARY KEY, entry_id TEXT NOT NULL, template_id TEXT,
            name TEXT NOT NULL, value TEXT, is_protected INTEGER DEFAULT 0,
            field_type TEXT DEFAULT 'text', sort_order INTEGER DEFAULT 0);
        CREATE TABLE entry_tags (entry_id TEXT NOT NULL, tag_id TEXT NOT NULL, PRIMARY KEY (entry_id, tag_id));
        CREATE TABLE attachments (id TEXT PRIMARY KEY, entry_id TEXT NOT NULL, filename TEXT NOT NULL,
            mime_type TEXT, data BLOB NOT NULL, size INTEGER NOT NULL, created_at INTEGER NOT NULL);
        CREATE TABLE entry_relations (id TEXT PRIMARY KEY, source_id TEXT NOT NULL, target_id TEXT NOT NULL,
            relation_type TEXT NOT NULL, created_at INTEGER NOT NULL);
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);
        CREATE VIRTUAL TABLE entries_fts USING fts5(id UNINDEXED, title, notes, fields,
            content='entries', content_rowid='rowid');

        INSERT INTO folders VALUES ('root', NULL, 'Root', NULL, 0, 1, 1);
        INSERT INTO entries (id, folder_id, title, notes, created_at, updated_at)
            VALUES ('e1', 'root', 'GitHub', 'work', 1, 1), ('e2', 'root', 'Gmail', NULL, 1, 1);
        INSERT INTO entry_fields (id, entry_id, template_id, name, value)
            VALUES ('f1', 'e1', 'tpl_username', 'Username', 'octocat');
        INSERT INTO tags VALUES ('t-fav', 'favorite', '#FFD700');
        INSERT INTO entry_tags VALUES ('e1', 't-fav');
        "#,
    )
    .unwrap();
    c.serialize(rusqlite::DatabaseName::Main).unwrap().to_vec()
}

#[test]
fn migrates_favorite_tag_into_column() {
    let c = open_in_memory(&legacy_image()).unwrap();
    assert!(migrate(&c).unwrap(), "legacy schema must report as migrated");

    let fav: i64 = c.query_row("SELECT is_favorite FROM entries WHERE id='e1'", [], |r| r.get(0)).unwrap();
    assert_eq!(fav, 1);
    let not_fav: i64 = c.query_row("SELECT is_favorite FROM entries WHERE id='e2'", [], |r| r.get(0)).unwrap();
    assert_eq!(not_fav, 0);
}

#[test]
fn keeps_favorite_tag_so_go_still_sees_it() {
    let c = open_in_memory(&legacy_image()).unwrap();
    migrate(&c).unwrap();

    let linked_favorite: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM tags t
             INNER JOIN entry_tags et ON t.id = et.tag_id
             WHERE et.entry_id = 'e1' AND t.name = 'favorite'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(linked_favorite, 1, "migration must be additive: e1 must still resolve to the favorite tag for the Go fallback");
}

#[test]
fn adds_history_table_and_schema_version() {
    let c = open_in_memory(&legacy_image()).unwrap();
    migrate(&c).unwrap();

    let t: i64 = c
        .query_row("SELECT COUNT(*) FROM sqlite_master WHERE name='entry_field_history'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(t, 1);
    let v: String = c
        .query_row("SELECT value FROM metadata WHERE key='schema_version'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, "9");
}

#[test]
fn migration_adds_empty_audit_log() {
    let c = open_in_memory(&legacy_image()).unwrap();
    migrate(&c).unwrap();
    let t: i64 = c
        .query_row("SELECT COUNT(*) FROM sqlite_master WHERE name='audit_log'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(t, 1, "migration must add the audit_log table");
    let n: i64 = c.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 0, "a freshly-migrated audit_log is empty");
}

#[test]
fn rebuilds_fts_as_standalone_and_indexes_existing_rows() {
    let c = open_in_memory(&legacy_image()).unwrap();
    migrate(&c).unwrap();

    let hits: i64 = c
        .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'GitHub'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(hits, 1, "existing rows must be indexed after the rebuild");

    let by_field: i64 = c
        .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'octocat'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(by_field, 1);
}

#[test]
fn is_idempotent() {
    let c = open_in_memory(&legacy_image()).unwrap();
    assert!(migrate(&c).unwrap());
    assert!(!migrate(&c).unwrap(), "second run must be a no-op");

    let fav: i64 = c.query_row("SELECT is_favorite FROM entries WHERE id='e1'", [], |r| r.get(0)).unwrap();
    assert_eq!(fav, 1);
}

/// `is_idempotent` above only proves the version-guard short-circuit works —
/// the second `migrate()` call returns on its first line and never re-runs
/// the body. This test clears the guard between runs so the body itself
/// (ALTER/UPDATE/CREATE IF NOT EXISTS/FTS rebuild/populate_defaults) executes
/// twice against the same data, and checks the result is stable rather than
/// duplicated.
#[test]
fn migration_body_is_idempotent_across_reruns() {
    let c = open_in_memory(&legacy_image()).unwrap();
    assert!(migrate(&c).unwrap(), "first run must report a migration happened");

    c.execute("DELETE FROM metadata WHERE key = 'schema_version'", []).unwrap();
    assert!(migrate(&c).unwrap(), "second run (guard cleared) must re-run the body, not short-circuit");

    let templates: i64 = c.query_row("SELECT COUNT(*) FROM field_templates", [], |r| r.get(0)).unwrap();
    assert_eq!(templates, 8, "re-running the body must not duplicate default templates");

    let tag: i64 = c.query_row("SELECT COUNT(*) FROM tags WHERE name = 'favorite'", [], |r| r.get(0)).unwrap();
    assert_eq!(tag, 1, "re-running the body must not duplicate the favorite tag");

    let link: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM tags t
             INNER JOIN entry_tags et ON t.id = et.tag_id
             WHERE et.entry_id = 'e1' AND t.name = 'favorite'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(link, 1, "re-running the body must not duplicate or drop e1's favorite link");

    let fav: i64 = c.query_row("SELECT is_favorite FROM entries WHERE id = 'e1'", [], |r| r.get(0)).unwrap();
    assert_eq!(fav, 1, "re-running the body must leave is_favorite stable");

    let fts_rows: i64 = c.query_row("SELECT COUNT(*) FROM entries_fts", [], |r| r.get(0)).unwrap();
    assert_eq!(fts_rows, 2, "re-running the body must produce exactly one FTS row per live entry, no duplicates");
}

#[test]
fn adds_missing_default_templates() {
    let c = open_in_memory(&legacy_image()).unwrap();
    migrate(&c).unwrap();
    let n: i64 = c.query_row("SELECT COUNT(*) FROM field_templates", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 8);
}

/// A v2 vault that leaked secret values into its FTS index must have them
/// purged when it is migrated to the current schema (rebuild_fts re-derives
/// the index with the is_protected guard). Also confirms the version is
/// stamped to "9".
#[test]
fn migrating_legacy_rebuilds_fts_without_secrets() {
    let conn = kokos_core::db::create_fresh().unwrap();
    conn.execute("UPDATE metadata SET value='2' WHERE key='schema_version'", []).unwrap();
    conn.execute(
        "INSERT INTO entries (id, folder_id, title, is_deleted, created_at, updated_at)
         VALUES ('e1','root','Bank',0,1,1)", []).unwrap();
    conn.execute(
        "INSERT INTO entry_fields (id, entry_id, name, value, is_protected, field_type)
         VALUES ('f1','e1','Password','leakedpw',1,'secret')", []).unwrap();

    conn.execute("DELETE FROM entries_fts WHERE id='e1'", []).unwrap();
    conn.execute(
        "INSERT INTO entries_fts (id, title, notes, fields)
         VALUES ('e1','Bank','','Password: leakedpw')", []).unwrap();
    let before: i64 = conn.query_row(
        "SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'leakedpw'", [], |r| r.get(0)).unwrap();
    assert_eq!(before, 1, "precondition: the simulated v2 index holds the secret");

    let migrated = kokos_core::db::migrate::migrate(&conn).unwrap();
    assert!(migrated, "v2 < current schema must migrate");

    let after: i64 = conn.query_row(
        "SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'leakedpw'", [], |r| r.get(0)).unwrap();
    assert_eq!(after, 0, "legacy rebuild must purge secret terms");
    let by_name: i64 = conn.query_row(
        "SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'Password'", [], |r| r.get(0)).unwrap();
    assert_eq!(by_name, 1, "the field NAME remains searchable after the rebuild");
    let v: String = conn.query_row(
        "SELECT value FROM metadata WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
    assert_eq!(v, "9");
}

#[test]
fn migrating_v6_adds_entry_fields_field_type_check_and_normalizes() {
    use kokos_core::db::{create_fresh, migrate::migrate};
    let c = create_fresh().unwrap();
    c.execute_batch(
        "DROP TABLE entry_fields;
         CREATE TABLE entry_fields (
             id TEXT PRIMARY KEY,
             entry_id TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
             template_id TEXT REFERENCES field_templates(id) ON DELETE SET NULL,
             name TEXT NOT NULL, value TEXT,
             is_protected INTEGER DEFAULT 0,
             field_type TEXT DEFAULT 'text',
             sort_order INTEGER DEFAULT 0
         );
         CREATE INDEX IF NOT EXISTS idx_entry_fields_entry ON entry_fields(entry_id);",
    )
    .unwrap();
    c.execute(
        "INSERT INTO entries (id, folder_id, title, is_favorite, is_deleted, created_at, updated_at)
         VALUES ('e1','root','E1',0,0,1,1)",
        [],
    )
    .unwrap();
    c.execute(
        "INSERT INTO entry_fields (id, entry_id, name, value, is_protected, field_type, sort_order)
         VALUES ('f1','e1','Weird','v',0,'bogus',0)",
        [],
    )
    .unwrap();
    c.execute("UPDATE metadata SET value='6' WHERE key='schema_version'", []).unwrap();

    assert!(migrate(&c).unwrap());

    let ft: String = c
        .query_row("SELECT field_type FROM entry_fields WHERE id='f1'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(ft, "text", "out-of-set legacy field_type normalized to 'text'");
    let bad = c.execute(
        "INSERT INTO entry_fields (id, entry_id, name, field_type) VALUES ('f2','e1','X','nope')",
        [],
    );
    assert!(bad.is_err(), "post-migration DB must reject an out-of-set field_type");
    let v: String = c
        .query_row("SELECT value FROM metadata WHERE key='schema_version'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, "9");
}

#[test]
fn fresh_db_rejects_bad_entry_field_type_at_db() {
    use kokos_core::db::create_fresh;
    let c = create_fresh().unwrap();
    c.execute(
        "INSERT INTO entries (id, folder_id, title, is_favorite, is_deleted, created_at, updated_at)
         VALUES ('e1','root','E1',0,0,1,1)",
        [],
    )
    .unwrap();
    let bad = c.execute(
        "INSERT INTO entry_fields (id, entry_id, name, field_type) VALUES ('f1','e1','X','bogus')",
        [],
    );
    assert!(bad.is_err(), "a fresh v7 DB must reject an out-of-set field_type");
}

/// A container stamped with a schema_version from a
/// *future* build must be refused, not silently treated as legacy and
/// migrated (which would rebuild its FTS shape to the older layout and stamp
/// its version back down — a downgrade that destroys data).
#[test]
fn refuses_a_future_schema_version_without_stamping_it_down() {
    let c = kokos_core::db::create_fresh().unwrap();
    c.execute("UPDATE metadata SET value = '10' WHERE key = 'schema_version'", []).unwrap();

    let err = migrate(&c).unwrap_err();
    assert!(matches!(err, kokos_core::VaultError::UnsupportedVersion { found: 10 }));

    let v: String =
        c.query_row("SELECT value FROM metadata WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
    assert_eq!(v, "10", "a refused future-version migration must not touch the stored version");
}

#[test]
fn migrating_v8_adds_phone_to_field_type_check() {
    use kokos_core::db::{create_fresh, migrate::migrate};
    let c = create_fresh().unwrap();
    c.execute_batch(
        "PRAGMA foreign_keys=OFF;
         ALTER TABLE field_templates RENAME TO field_templates_old;
         CREATE TABLE field_templates (
             id TEXT PRIMARY KEY,
             name TEXT NOT NULL UNIQUE,
             field_type TEXT NOT NULL CHECK (field_type IN ('text','secret','url','email','otp','date')),
             is_protected INTEGER DEFAULT 0,
             sort_order INTEGER DEFAULT 0
         );
         INSERT INTO field_templates (id, name, field_type, is_protected, sort_order)
             SELECT id, name, field_type, is_protected, sort_order FROM field_templates_old;
         DROP TABLE field_templates_old;
         PRAGMA foreign_keys=ON;
         DROP TABLE entry_fields;
         CREATE TABLE entry_fields (
             id TEXT PRIMARY KEY,
             entry_id TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
             template_id TEXT REFERENCES field_templates(id) ON DELETE SET NULL,
             name TEXT NOT NULL, value TEXT,
             is_protected INTEGER DEFAULT 0,
             field_type TEXT DEFAULT 'text' CHECK (field_type IN ('text','secret','url','email','otp','date')),
             sort_order INTEGER DEFAULT 0
         );
         CREATE INDEX IF NOT EXISTS idx_entry_fields_entry ON entry_fields(entry_id);",
    )
    .unwrap();
    c.execute(
        "INSERT INTO entries (id, folder_id, title, is_favorite, is_deleted, created_at, updated_at)
         VALUES ('e1','root','E1',0,0,1,1)",
        [],
    )
    .unwrap();
    c.execute(
        "INSERT INTO entry_fields (id, entry_id, template_id, name, field_type)
         VALUES ('f_tpl','e1','tpl_username','Username','text')",
        [],
    )
    .unwrap();
    c.execute("UPDATE metadata SET value='8' WHERE key='schema_version'", []).unwrap();

    let pre = c.execute(
        "INSERT INTO entry_fields (id, entry_id, name, field_type) VALUES ('p0','e1','Phone','phone')",
        [],
    );
    assert!(pre.is_err(), "pre-migration v8 DB must reject field_type='phone' on entry_fields");
    let pre_tpl = c.execute(
        "INSERT INTO field_templates (id, name, field_type) VALUES ('tpl_phone_test','PhoneTest','phone')",
        [],
    );
    assert!(pre_tpl.is_err(), "pre-migration v8 DB must reject field_type='phone' on field_templates");

    assert!(migrate(&c).unwrap());

    c.execute(
        "INSERT INTO entry_fields (id, entry_id, name, field_type) VALUES ('p1','e1','Phone','phone')",
        [],
    )
    .expect("post-migration DB must accept field_type='phone' on entry_fields");
    c.execute(
        "INSERT INTO field_templates (id, name, field_type) VALUES ('tpl_phone_test','PhoneTest','phone')",
        [],
    )
    .expect("post-migration DB must accept field_type='phone' on field_templates");
    let bad = c.execute(
        "INSERT INTO entry_fields (id, entry_id, name, field_type) VALUES ('p2','e1','X','nope')",
        [],
    );
    assert!(bad.is_err(), "post-migration DB must still reject an out-of-set field_type");

    let resolved_name: String = c
        .query_row(
            "SELECT ft.name FROM entry_fields ef JOIN field_templates ft ON ft.id = ef.template_id
             WHERE ef.id = 'f_tpl'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(resolved_name, "Username", "entry_fields.template_id must still resolve after the field_templates rebuild");
    let mut fk_stmt = c.prepare("PRAGMA foreign_key_check").unwrap();
    let mut fk_rows = fk_stmt.query([]).unwrap();
    assert!(fk_rows.next().unwrap().is_none(), "post-migration foreign_key_check must report no violations");

    let v: String = c
        .query_row("SELECT value FROM metadata WHERE key='schema_version'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, "9");
}

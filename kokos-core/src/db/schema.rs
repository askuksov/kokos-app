//! Target schema, with three corrections found in real v1 data:
//! entry_fields keeps is_protected/field_type, the root
//! folder exists, and entries_fts uses the column name `id` — the Go
//! implementation writes `INSERT INTO entries_fts (id, ...)`, so renaming
//! it to `entry_id` would silently break its search.

pub const SCHEMA_VERSION: &str = "9";

pub const TARGET_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS folders (
    id TEXT PRIMARY KEY,
    parent_id TEXT REFERENCES folders(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    icon_id TEXT REFERENCES icons(id) ON DELETE SET NULL,
    sort_order INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id);

CREATE TABLE IF NOT EXISTS icons (
    id TEXT PRIMARY KEY, name TEXT, data BLOB NOT NULL, mime_type TEXT DEFAULT 'image/png'
);

CREATE TABLE IF NOT EXISTS field_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    field_type TEXT NOT NULL CHECK (field_type IN ('text','secret','url','email','otp','date','phone')),
    is_protected INTEGER DEFAULT 0,
    sort_order INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tags (
    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, color TEXT
);

CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,
    folder_id TEXT REFERENCES folders(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    entry_type TEXT NOT NULL DEFAULT 'login' CHECK (entry_type IN ('login','card','secure_note','wifi')),
    icon_id TEXT REFERENCES icons(id) ON DELETE SET NULL,
    notes TEXT,
    is_favorite INTEGER DEFAULT 0,
    is_deleted INTEGER DEFAULT 0,
    deleted_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_folder ON entries(folder_id);
CREATE INDEX IF NOT EXISTS idx_entries_deleted ON entries(is_deleted);
CREATE INDEX IF NOT EXISTS idx_entries_title ON entries(title);

CREATE TABLE IF NOT EXISTS entry_fields (
    id TEXT PRIMARY KEY,
    entry_id TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    template_id TEXT REFERENCES field_templates(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    value TEXT,
    is_protected INTEGER DEFAULT 0,
    field_type TEXT DEFAULT 'text' CHECK (field_type IN ('text','secret','url','email','otp','date','phone')),
    sort_order INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_entry_fields_entry ON entry_fields(entry_id);

CREATE TABLE IF NOT EXISTS entry_field_history (
    id TEXT PRIMARY KEY,
    entry_id TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    field_name TEXT NOT NULL,
    value TEXT,
    changed_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_field_history_entry ON entry_field_history(entry_id);

CREATE TABLE IF NOT EXISTS entry_tags (
    entry_id TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    tag_id TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (entry_id, tag_id)
);
CREATE INDEX IF NOT EXISTS idx_entry_tags_tag ON entry_tags(tag_id);

CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    entry_id TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    filename TEXT NOT NULL, mime_type TEXT, data BLOB NOT NULL,
    size INTEGER NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attachments_entry ON attachments(entry_id);

CREATE TABLE IF NOT EXISTS entry_relations (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    target_id TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL CHECK (relation_type IN ('related','parent','child','duplicate','see-also')),
    created_at INTEGER NOT NULL,
    UNIQUE(source_id, target_id, relation_type)
);
CREATE INDEX IF NOT EXISTS idx_relations_source ON entry_relations(source_id);
CREATE INDEX IF NOT EXISTS idx_relations_target ON entry_relations(target_id);

CREATE TABLE IF NOT EXISTS metadata ( key TEXT PRIMARY KEY, value TEXT );

CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event      TEXT NOT NULL,
  detail     TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nmh_grants (
  origin       TEXT NOT NULL,
  domain       TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER,
  PRIMARY KEY (origin, domain)
);
"#;

pub const FTS_SCHEMA: &str = r#"
CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(
    id UNINDEXED, title, notes, fields, tokenize = 'unicode61'
);
"#;

/// Nothing else fills entries_fts — without triggers
/// the index stays empty and search silently returns nothing.
///
/// The index must hold live entries only, matching `migrate::rebuild_fts`'s
/// `WHERE e.is_deleted = 0` filter: every trigger below re-checks is_deleted
/// before inserting, so soft-deleting an entry drops it from search, editing
/// a trashed entry (or one of its fields) does not reindex it, and restoring
/// it is the only way back in.
pub const FTS_TRIGGERS: &str = r#"
CREATE TRIGGER IF NOT EXISTS entries_fts_ai AFTER INSERT ON entries
WHEN new.is_deleted = 0
BEGIN
    INSERT INTO entries_fts (id, title, notes, fields)
    VALUES (new.id, new.title, COALESCE(new.notes, ''), '');
END;

CREATE TRIGGER IF NOT EXISTS entries_fts_ad AFTER DELETE ON entries BEGIN
    DELETE FROM entries_fts WHERE id = old.id;
END;

CREATE TRIGGER IF NOT EXISTS entries_fts_au AFTER UPDATE ON entries BEGIN
    DELETE FROM entries_fts WHERE id = old.id;
    INSERT INTO entries_fts (id, title, notes, fields)
    SELECT new.id, new.title, COALESCE(new.notes, ''),
           COALESCE((SELECT GROUP_CONCAT(ef.name || ': ' || CASE WHEN ef.is_protected = 0 THEN COALESCE(ef.value, '') ELSE '' END, ' ')
                     FROM entry_fields ef WHERE ef.entry_id = new.id), '')
    WHERE new.is_deleted = 0;
END;

CREATE TRIGGER IF NOT EXISTS entry_fields_fts_ai AFTER INSERT ON entry_fields BEGIN
    DELETE FROM entries_fts WHERE id = new.entry_id;
    INSERT INTO entries_fts (id, title, notes, fields)
    SELECT e.id, e.title, COALESCE(e.notes, ''),
           COALESCE((SELECT GROUP_CONCAT(ef.name || ': ' || CASE WHEN ef.is_protected = 0 THEN COALESCE(ef.value, '') ELSE '' END, ' ')
                     FROM entry_fields ef WHERE ef.entry_id = e.id), '')
    FROM entries e WHERE e.id = new.entry_id AND e.is_deleted = 0;
END;

CREATE TRIGGER IF NOT EXISTS entry_fields_fts_au AFTER UPDATE ON entry_fields BEGIN
    DELETE FROM entries_fts WHERE id = new.entry_id;
    INSERT INTO entries_fts (id, title, notes, fields)
    SELECT e.id, e.title, COALESCE(e.notes, ''),
           COALESCE((SELECT GROUP_CONCAT(ef.name || ': ' || CASE WHEN ef.is_protected = 0 THEN COALESCE(ef.value, '') ELSE '' END, ' ')
                     FROM entry_fields ef WHERE ef.entry_id = e.id), '')
    FROM entries e WHERE e.id = new.entry_id AND e.is_deleted = 0;
END;

CREATE TRIGGER IF NOT EXISTS entry_fields_fts_ad AFTER DELETE ON entry_fields BEGIN
    DELETE FROM entries_fts WHERE id = old.entry_id;
    INSERT INTO entries_fts (id, title, notes, fields)
    SELECT e.id, e.title, COALESCE(e.notes, ''),
           COALESCE((SELECT GROUP_CONCAT(ef.name || ': ' || CASE WHEN ef.is_protected = 0 THEN COALESCE(ef.value, '') ELSE '' END, ' ')
                     FROM entry_fields ef WHERE ef.entry_id = e.id), '')
    FROM entries e WHERE e.id = old.entry_id AND e.is_deleted = 0;
END;
"#;

/// IDs are fixed and must match the Go reference (schema.go DefaultFieldTemplates).
pub const DEFAULT_TEMPLATES: &[(&str, &str, &str, i32, i32)] = &[
    ("tpl_username", "Username", "text", 0, 1),
    ("tpl_password", "Password", "secret", 1, 2),
    ("tpl_url", "URL", "url", 0, 3),
    ("tpl_email", "Email", "email", 0, 4),
    ("tpl_totp", "TOTP", "otp", 1, 5),
    ("tpl_pin", "PIN", "secret", 1, 6),
    ("tpl_security_question", "Security Question", "text", 0, 7),
    ("tpl_security_answer", "Security Answer", "secret", 1, 8),
];

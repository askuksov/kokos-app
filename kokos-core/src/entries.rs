//! Entry CRUD. Column names are always spelled out (never SELECT *): a fresh
//! and a migrated vault have different physical column order in `entries`
//! and four of the five shifted columns are INTEGER, so a
//! positional read fails silently.

use rusqlite::Connection;

use crate::error::Result;

pub enum View {
    All,
    Favorites,
    Recent,
}

#[derive(Debug, Clone)]
pub struct Field {
    pub id: String,
    pub entry_id: String,
    pub template_id: Option<String>,
    pub name: String,
    pub value: Option<String>,
    pub is_protected: bool,
    pub field_type: String,
    pub sort_order: i32,
    pub strength: Option<u8>,
}

/// A non-favorite tag reference attached to an entry. The
/// reserved `favorite` tag is never included here -- it already has its own
/// `is_favorite` field on both `EntrySummary` and `Entry`.
#[derive(Debug, Clone)]
pub struct TagRef {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub id: String,
    pub folder_id: Option<String>,
    pub title: String,
    pub entry_type: String,
    pub icon_id: Option<String>,
    pub notes: Option<String>,
    pub is_favorite: bool,
    pub is_deleted: bool,
    pub deleted_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub fields: Vec<Field>,
    pub tags: Vec<TagRef>,
}

#[derive(Debug, Clone)]
pub struct EntrySummary {
    pub id: String,
    pub folder_id: Option<String>,
    pub title: String,
    pub entry_type: String,
    pub username: Option<String>,
    pub is_favorite: bool,
    pub has_totp: bool,
    pub has_attachments: bool,
    pub updated_at: i64,
    pub tags: Vec<TagRef>,
    pub password_field_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewField {
    pub template_id: Option<String>,
    pub name: String,
    pub value: Option<String>,
    pub is_protected: bool,
    pub field_type: String,
}

#[derive(Debug, Clone)]
pub struct NewEntry {
    pub title: String,
    pub folder_id: Option<String>,
    pub notes: Option<String>,
    pub entry_type: String,
    pub fields: Vec<NewField>,
}

/// The four first-class entry types (a fixed enum). The DB
/// enforces this exact set via the CHECK on entries.entry_type; this const is
/// the app-side mirror used for seeding + validation.
pub const ENTRY_TYPES: [&str; 4] = ["login", "card", "secure_note", "wifi"];

pub fn is_valid_entry_type(t: &str) -> bool {
    ENTRY_TYPES.contains(&t)
}

/// The curated default field set a New-entry seeds for a given type.
/// Login reuses the tpl_* ids so its Username feeds SUMMARY_COLS'
/// username sub-select exactly as before; card/secure_note fields and
/// wifi's SSID/Security are ad-hoc (template_id None). Wi-Fi's Password
/// reuses `tpl_password` (GUI fix: it IS a password, so it
/// keeps the frontend's password-role generator-dice gate, consistent with
/// login's Password). Wi-Fi's "Security" defaults to "WPA2". An unknown
/// type seeds nothing — the DB CHECK is the real gate.
pub fn default_fields(entry_type: &str) -> Vec<NewField> {
    let f = |template_id: Option<&str>, name: &str, value: Option<&str>, is_protected: bool, field_type: &str| NewField {
        template_id: template_id.map(str::to_string),
        name: name.to_string(),
        value: value.map(str::to_string),
        is_protected,
        field_type: field_type.to_string(),
    };
    match entry_type {
        "login" => vec![
            f(Some("tpl_username"), "Username", None, false, "text"),
            f(Some("tpl_password"), "Password", None, true, "secret"),
            f(Some("tpl_url"), "URL", None, false, "url"),
        ],
        "card" => vec![
            f(None, "Cardholder name", None, false, "text"),
            f(None, "Card number", None, false, "text"),
            f(None, "Expiry (MM/YY)", None, false, "text"),
            f(None, "Security code (CVV)", None, true, "secret"),
        ],
        "secure_note" => vec![f(None, "Note", None, false, "text")],
        "wifi" => vec![
            f(None, "Network name (SSID)", None, false, "text"),
            f(Some("tpl_password"), "Password", None, true, "secret"),
            f(None, "Security", Some("WPA2"), false, "text"),
        ],
        _ => vec![],
    }
}

#[derive(Debug, Clone)]
pub struct EntryPatch {
    pub title: Option<String>,
    pub notes: Option<String>,
    pub is_favorite: Option<bool>,
    pub folder_id: Option<String>,
    pub fields: Option<Vec<FieldInput>>,
}

/// All non-favorite tags for one entry, ordered by name. A private helper
/// shared by `list()` and `get()`.
fn tags_for_entry(conn: &Connection, entry_id: &str) -> Result<Vec<TagRef>> {
    let mut stmt = conn.prepare(
        "SELECT t.id, t.name, t.color FROM entry_tags et JOIN tags t ON t.id = et.tag_id
         WHERE et.entry_id = ?1 AND t.name != 'favorite'
         ORDER BY t.name COLLATE NOCASE ASC",
    )?;
    let rows = stmt.query_map([entry_id], |r| {
        Ok(TagRef { id: r.get(0)?, name: r.get(1)?, color: r.get(2)? })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Column list shared by `list()` and `search::search()` — same columns,
/// same order, so both build an identical `EntrySummary`. `e` is the entries
/// alias the caller's FROM clause must bind. The `username` sub-selects skip
/// protected fields (`ef.is_protected = 0`): the summary is shown and copied
/// from the list, so a protected identity value must not surface there
/// (`entries::get` masks it the same way).
pub(crate) const SUMMARY_COLS: &str = "e.id, e.title, e.is_favorite, e.updated_at,
    COALESCE(
      (SELECT ef.value FROM entry_fields ef
         WHERE ef.entry_id = e.id AND ef.template_id = 'tpl_username'
           AND ef.is_protected = 0 LIMIT 1),
      (SELECT ef.value FROM entry_fields ef
         WHERE ef.entry_id = e.id
           AND (ef.template_id = 'tpl_email' OR ef.field_type = 'email')
           AND ef.is_protected = 0 LIMIT 1)) AS username,
    EXISTS(SELECT 1 FROM entry_fields ef
       WHERE ef.entry_id = e.id
         AND (ef.template_id = 'tpl_totp' OR ef.field_type = 'otp')) AS has_totp,
    EXISTS(SELECT 1 FROM attachments a WHERE a.entry_id = e.id) AS has_attachments,
    e.folder_id, e.entry_type,
    (SELECT ef.id FROM entry_fields ef
       WHERE ef.entry_id = e.id
         AND ef.field_type <> 'otp'
         AND (ef.template_id IS NULL OR ef.template_id <> 'tpl_totp')
         AND (ef.field_type = 'secret' OR ef.is_protected = 1)
       ORDER BY ef.sort_order ASC, ef.id ASC LIMIT 1) AS password_field_id";

pub(crate) fn map_summary(r: &rusqlite::Row) -> rusqlite::Result<EntrySummary> {
    Ok(EntrySummary {
        id: r.get(0)?,
        title: r.get(1)?,
        is_favorite: r.get::<_, i64>(2)? != 0,
        updated_at: r.get(3)?,
        username: r.get(4)?,
        has_totp: r.get::<_, i64>(5)? != 0,
        has_attachments: r.get::<_, i64>(6)? != 0,
        folder_id: r.get(7)?,
        entry_type: r.get(8)?,
        tags: Vec::new(),
        password_field_id: r.get(9)?,
    })
}

/// Fills each summary's tags in a second pass, batched: one chunked (≤900
/// ids) `IN (...)` query per pass instead of one query per entry, grouped
/// into an id→tags map and then re-attached to each `out` element. MUST run
/// after the outer summary query's rows are fully drained: the tag query
/// re-borrows `conn`, which would conflict with a live row borrow from the
/// summary query.
pub(crate) fn hydrate_tags(conn: &Connection, out: &mut [EntrySummary]) -> Result<()> {
    if out.is_empty() {
        return Ok(());
    }
    use std::collections::HashMap;
    let mut by_entry: HashMap<String, Vec<TagRef>> = HashMap::new();
    for chunk in out.chunks(900) {
        let ph = std::iter::repeat("?").take(chunk.len()).collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT et.entry_id, t.id, t.name, t.color
             FROM entry_tags et JOIN tags t ON t.id = et.tag_id
             WHERE t.name != 'favorite' AND et.entry_id IN ({ph})
             ORDER BY t.name COLLATE NOCASE ASC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            rusqlite::params_from_iter(chunk.iter().map(|s| s.id.as_str())),
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    TagRef { id: r.get(1)?, name: r.get(2)?, color: r.get(3)? },
                ))
            },
        )?;
        for row in rows {
            let (eid, tag) = row?;
            by_entry.entry(eid).or_default().push(tag);
        }
    }
    for entry in out.iter_mut() {
        entry.tags = by_entry.remove(&entry.id).unwrap_or_default();
    }
    Ok(())
}

pub fn list(conn: &Connection, view: View) -> Result<Vec<EntrySummary>> {
    let order = match view {
        View::Recent => "e.updated_at DESC",
        _ => "e.title COLLATE NOCASE ASC",
    };
    let filter = match view {
        View::Favorites => "AND e.is_favorite = 1",
        _ => "",
    };
    let sql = format!(
        "SELECT {SUMMARY_COLS} FROM entries e WHERE e.is_deleted = 0 {filter} ORDER BY {order}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], map_summary)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    hydrate_tags(conn, &mut out)?;
    Ok(out)
}

pub fn get(conn: &Connection, id: &str) -> Result<Option<Entry>> {
    let mut stmt = conn.prepare(
        "SELECT id, folder_id, title, icon_id, notes, is_favorite, entry_type,
                is_deleted, deleted_at, created_at, updated_at
         FROM entries WHERE id = ?1 AND is_deleted = 0",
    )?;
    let mut rows = stmt.query([id])?;
    let Some(row) = rows.next()? else { return Ok(None) };

    let mut entry = Entry {
        id: row.get(0)?,
        folder_id: row.get(1)?,
        title: row.get(2)?,
        icon_id: row.get(3)?,
        notes: row.get(4)?,
        is_favorite: row.get::<_, i64>(5)? != 0,
        entry_type: row.get(6)?,
        is_deleted: row.get::<_, i64>(7)? != 0,
        deleted_at: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
        fields: Vec::new(),
        tags: Vec::new(),
    };

    let mut fstmt = conn.prepare(
        "SELECT id, entry_id, template_id, name, value, is_protected, field_type, sort_order
         FROM entry_fields WHERE entry_id = ?1 ORDER BY sort_order ASC, id ASC",
    )?;
    let frows = fstmt.query_map([id], |r| {
        let is_protected = r.get::<_, i64>(5)? != 0;
        let raw_value: Option<String> = r.get(4)?;
        let field_type: String = r.get(6)?;
        let strength = if field_type == "secret" {
            raw_value.as_deref().filter(|s| !s.is_empty()).map(crate::strength::estimate)
        } else {
            None
        };
        Ok(Field {
            id: r.get(0)?,
            entry_id: r.get(1)?,
            template_id: r.get(2)?,
            name: r.get(3)?,
            value: if is_protected { None } else { raw_value },
            is_protected,
            field_type,
            sort_order: r.get(7)?,
            strength,
        })
    })?;
    for f in frows {
        entry.fields.push(f?);
    }
    entry.tags = tags_for_entry(conn, id)?;
    Ok(Some(entry))
}

pub fn create(conn: &Connection, new: NewEntry, now: i64) -> Result<Entry> {
    let id = uuid::Uuid::new_v4().to_string();
    let folder_id = new.folder_id.unwrap_or_else(|| "root".to_string());
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT INTO entries (id, folder_id, title, notes, is_favorite, entry_type, is_deleted, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 0, ?5, 0, ?6, ?6)",
        rusqlite::params![id, folder_id, new.title, new.notes, new.entry_type, now],
    )?;
    for (i, f) in new.fields.into_iter().enumerate() {
        tx.execute(
            "INSERT INTO entry_fields
               (id, entry_id, template_id, name, value, is_protected, field_type, sort_order)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                uuid::Uuid::new_v4().to_string(),
                id,
                f.template_id,
                f.name,
                f.value,
                f.is_protected as i64,
                f.field_type,
                i as i64,
            ],
        )?;
    }
    tx.commit()?;
    get(conn, &id).map(|o| o.expect("just-created entry must exist"))
}

pub fn update(conn: &Connection, id: &str, patch: EntryPatch, now: i64) -> Result<Option<Entry>> {
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM entries WHERE id = ?1 AND is_deleted = 0",
        [id],
        |r| r.get(0),
    )?;
    if exists == 0 {
        return Ok(None);
    }

    let tx = conn.unchecked_transaction()?;

    if let Some(title) = patch.title {
        tx.execute("UPDATE entries SET title = ?1 WHERE id = ?2", rusqlite::params![title, id])?;
    }
    if let Some(notes) = patch.notes {
        tx.execute("UPDATE entries SET notes = ?1 WHERE id = ?2", rusqlite::params![notes, id])?;
    }
    if let Some(fav) = patch.is_favorite {
        tx.execute(
            "UPDATE entries SET is_favorite = ?1 WHERE id = ?2",
            rusqlite::params![fav as i64, id],
        )?;
    }
    if let Some(folder) = patch.folder_id {
        tx.execute(
            "UPDATE entries SET folder_id = ?1 WHERE id = ?2",
            rusqlite::params![folder, id],
        )?;
    }
    if let Some(inputs) = patch.fields {
        reconcile_fields(&tx, id, inputs, now)?;
    }
    tx.execute("UPDATE entries SET updated_at = ?1 WHERE id = ?2", rusqlite::params![now, id])?;
    tx.commit()?;
    get(conn, id)
}

/// How `set_fields` should treat a field's stored value on reconcile: leave
/// an existing (possibly protected/masked) value untouched, write a new
/// plaintext value, or null it out.
#[derive(Debug, Clone)]
pub enum FieldValue {
    Keep,
    Set(String),
    Clear,
}

/// One field to reconcile into `entry_fields` via `set_fields`. `id: Some`
/// targets an existing row (updated in place, id preserved); `id: None`
/// inserts a new row with a fresh uuid.
#[derive(Debug, Clone)]
pub struct FieldInput {
    pub id: Option<String>,
    pub template_id: Option<String>,
    pub name: String,
    pub is_protected: bool,
    pub field_type: String,
    pub value: FieldValue,
}

/// Diff body for `set_fields`, split out so a caller can run it
/// inside `update()`'s own transaction (`reconcile_fields(&tx, ...)`)
/// without nesting a second `unchecked_transaction()` / `BEGIN`. Takes a
/// plain `&Connection` and does NOT open a transaction itself -- the caller
/// (here, `set_fields`) is responsible for atomicity.
fn reconcile_fields(conn: &Connection, entry_id: &str, inputs: Vec<FieldInput>, now: i64) -> Result<()> {
    let mut existing: std::collections::HashSet<String> = std::collections::HashSet::new();
    {
        let mut stmt = conn.prepare("SELECT id FROM entry_fields WHERE entry_id = ?1")?;
        let ids = stmt.query_map([entry_id], |r| r.get::<_, String>(0))?;
        for id in ids { existing.insert(id?); }
    }
    let keep_ids: std::collections::HashSet<&String> =
        inputs.iter().filter_map(|f| f.id.as_ref()).filter(|id| existing.contains(*id)).collect();

    for old in &existing {
        if !keep_ids.contains(old) {
            conn.execute("DELETE FROM entry_fields WHERE id = ?1 AND entry_id = ?2",
                       rusqlite::params![old, entry_id])?;
        }
    }

    for (i, f) in inputs.into_iter().enumerate() {
        let is_existing = f.id.as_ref().map(|id| existing.contains(id)).unwrap_or(false);
        if is_existing {
            let id = f.id.as_ref().unwrap();
            conn.execute(
                "UPDATE entry_fields SET template_id = ?1, name = ?2, is_protected = ?3,
                                         field_type = ?4, sort_order = ?5 WHERE id = ?6 AND entry_id = ?7",
                rusqlite::params![f.template_id, f.name, f.is_protected as i64, f.field_type, i as i64, id, entry_id],
            )?;

            if f.field_type == "secret" && !matches!(f.value, FieldValue::Keep) {
                let changes_to: Option<&str> = match &f.value {
                    FieldValue::Set(v) => Some(v.as_str()),
                    FieldValue::Clear => None,
                    FieldValue::Keep => unreachable!(),
                };
                let old: Option<String> = conn.query_row(
                    "SELECT value FROM entry_fields WHERE id = ?1",
                    [id],
                    |r| r.get(0),
                )?;
                let old_non_empty = old.as_deref().is_some_and(|s| !s.is_empty());
                if old_non_empty && old.as_deref() != changes_to {
                    let hist_id = uuid::Uuid::new_v4().to_string();
                    conn.execute(
                        "INSERT INTO entry_field_history (id, entry_id, field_name, value, changed_at)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![hist_id, entry_id, f.name, old, now],
                    )?;
                    conn.execute(
                        "DELETE FROM entry_field_history
                          WHERE entry_id = ?1 AND field_name = ?2
                            AND id NOT IN (
                              SELECT id FROM entry_field_history
                               WHERE entry_id = ?1 AND field_name = ?2
                               ORDER BY changed_at DESC, id DESC LIMIT 10)",
                        rusqlite::params![entry_id, f.name],
                    )?;
                }
            }

            match f.value {
                FieldValue::Keep => {}
                FieldValue::Set(v) => { conn.execute("UPDATE entry_fields SET value = ?1 WHERE id = ?2",
                                                    rusqlite::params![v, id])?; }
                FieldValue::Clear => { conn.execute("UPDATE entry_fields SET value = NULL WHERE id = ?1", [id])?; }
            }
        } else {
            let new_id = uuid::Uuid::new_v4().to_string();
            let value: Option<String> = match f.value {
                FieldValue::Set(v) => Some(v),
                FieldValue::Keep | FieldValue::Clear => None,
            };
            conn.execute(
                "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type, sort_order)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![new_id, entry_id, f.template_id, f.name, value, f.is_protected as i64, f.field_type, i as i64],
            )?;
        }
    }
    Ok(())
}

/// Reconciles `entry_id`'s `entry_fields` rows to exactly `inputs`, in
/// order (id-keyed diff: update-in-place / delete-absent / insert-new --
/// see `reconcile_fields`). A thin transactional wrapper: all the logic
/// lives in `reconcile_fields` so a caller can reuse it inside another
/// already-open transaction (see that function's doc comment).
pub fn set_fields(conn: &Connection, entry_id: &str, inputs: Vec<FieldInput>, now: i64) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    reconcile_fields(&tx, entry_id, inputs, now)?;
    tx.commit()?;
    Ok(())
}

/// One historical value of a secret field, captured by `reconcile_fields`
/// just before it was overwritten. See the capture-site comment
/// in `reconcile_fields` for the field_name-keyed fragility this implies.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub id: String,
    pub value: Option<String>,
    pub changed_at: i64,
}

/// Newest first. Keyed by field_name (see capture-site note on fragility).
pub fn list_field_history(conn: &Connection, entry_id: &str, field_name: &str) -> Result<Vec<HistoryEntry>> {
    let mut stmt = conn.prepare(
        "SELECT id, value, changed_at FROM entry_field_history
          WHERE entry_id = ?1 AND field_name = ?2 ORDER BY changed_at DESC, id DESC",
    )?;
    let rows = stmt.query_map(rusqlite::params![entry_id, field_name], |r| {
        Ok(HistoryEntry { id: r.get(0)?, value: r.get(1)?, changed_at: r.get(2)? })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn clear_field_history(conn: &Connection, entry_id: &str, field_name: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM entry_field_history WHERE entry_id = ?1 AND field_name = ?2",
        rusqlite::params![entry_id, field_name],
    )?;
    Ok(())
}

pub fn soft_delete(conn: &Connection, id: &str, now: i64) -> Result<bool> {
    let changed = conn.execute(
        "UPDATE entries SET is_deleted = 1, deleted_at = ?1, updated_at = ?1
         WHERE id = ?2 AND is_deleted = 0",
        rusqlite::params![now, id],
    )?;
    Ok(changed > 0)
}

pub fn reveal_field(
    conn: &Connection,
    entry_id: &str,
    field_id: &str,
) -> Result<Option<String>> {
    let mut stmt = conn.prepare(
        "SELECT ef.value FROM entry_fields ef
         JOIN entries e ON e.id = ef.entry_id
         WHERE ef.id = ?1 AND ef.entry_id = ?2 AND e.is_deleted = 0",
    )?;
    let mut rows = stmt.query(rusqlite::params![field_id, entry_id])?;
    match rows.next()? {
        Some(row) => {
            let v: Option<String> = row.get(0)?;
            Ok(Some(v.unwrap_or_default()))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use std::path::PathBuf;

    /// Both databases the CRUD code must work on: a freshly created one and
    /// one migrated from a real Go v1 file. Every CRUD test runs against BOTH — this is the
    /// only defence against the column-order trap.
    fn both_dbs() -> Vec<(&'static str, Connection)> {
        let fresh = db::create_fresh().unwrap();

        let fixture: PathBuf =
            [env!("CARGO_MANIFEST_DIR"), "fixtures", "v1_basic.vault"].iter().collect();
        let migrated = crate::vault::open(&fixture, b"fixture-password", None).unwrap().conn;

        vec![("fresh", fresh), ("migrated", migrated)]
    }

    /// Inserts a minimal live entry directly (bypassing create())
    /// so list() can be tested in isolation.
    fn seed_entry(conn: &Connection, id: &str, title: &str, favorite: i64) {
        let now = db::now_unix();
        conn.execute(
            "INSERT INTO entries (id, folder_id, title, is_favorite, is_deleted, created_at, updated_at)
             VALUES (?1, 'root', ?2, ?3, 0, ?4, ?4)",
            rusqlite::params![id, title, favorite, now],
        )
        .unwrap();
    }

    /// Inserts an `entry_fields` row with every column named explicitly
    /// (never positional/`SELECT *`), mirroring the exact column list the Go
    /// fixture writer uses (tools/fixture-gen/main.go) so seeded rows have
    /// the same shape as real migrated data.
    fn seed_field(
        conn: &Connection,
        id: &str,
        entry_id: &str,
        template_id: Option<&str>,
        name: &str,
        value: &str,
        field_type: &str,
    ) {
        conn.execute(
            "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type, sort_order)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, 0)",
            rusqlite::params![id, entry_id, template_id, name, value, field_type],
        )
        .unwrap();
    }

    /// Inserts an `attachments` row with every NOT-NULL column named
    /// explicitly, so `list()`'s `EXISTS(SELECT 1 FROM attachments ...)` has
    /// a real row to find.
    fn seed_attachment(conn: &Connection, id: &str, entry_id: &str) {
        let data: Vec<u8> = b"fake-attachment-bytes".to_vec();
        let size = data.len() as i64;
        conn.execute(
            "INSERT INTO attachments (id, entry_id, filename, mime_type, data, size, created_at)
             VALUES (?1, ?2, 'proof.txt', 'text/plain', ?3, ?4, ?5)",
            rusqlite::params![id, entry_id, data, size, db::now_unix()],
        )
        .unwrap();
    }

    #[test]
    fn list_all_returns_live_entries_on_both_dbs() {
        for (label, conn) in both_dbs() {
            let before = list(&conn, View::All).unwrap().len();
            seed_entry(&conn, "z-new", "Zzz Added", 0);
            let after = list(&conn, View::All).unwrap();
            assert_eq!(after.len(), before + 1, "[{label}] list must see the new entry");
            assert!(
                after.iter().any(|e| e.id == "z-new" && e.title == "Zzz Added"),
                "[{label}] the seeded entry must be present with its title"
            );
        }
    }

    #[test]
    fn list_excludes_soft_deleted() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "keep", "Keep", 0);
            seed_entry(&conn, "gone", "Gone", 0);
            conn.execute("UPDATE entries SET is_deleted = 1 WHERE id = 'gone'", []).unwrap();
            let ids: Vec<String> = list(&conn, View::All).unwrap().into_iter().map(|e| e.id).collect();
            assert!(ids.contains(&"keep".to_string()), "[{label}] live entry present");
            assert!(!ids.contains(&"gone".to_string()), "[{label}] deleted entry absent");
        }
    }

    #[test]
    fn list_favorites_filters_on_the_column_not_the_tag() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "fav", "Fav", 1);
            seed_entry(&conn, "plain", "Plain", 0);
            let ids: Vec<String> =
                list(&conn, View::Favorites).unwrap().into_iter().map(|e| e.id).collect();
            assert!(ids.contains(&"fav".to_string()), "[{label}] favorite present");
            assert!(!ids.contains(&"plain".to_string()), "[{label}] non-favorite absent");
        }
    }

    /// Covers: `username`/`has_totp`/
    /// `has_attachments` are derived by `list()` via subqueries/EXISTS
    /// against `entry_fields`/`attachments`, never read as columns on
    /// `entries` itself. A fresh DB and a migrated (Go-written) DB store
    /// `entries` with different physical column order — a
    /// migrated-only regression in these derived fields would still pass
    /// tests that only ever assert `id`/`title` on the fresh DB. Every
    /// assertion below runs against both `fresh` and `migrated`.
    #[test]
    fn list_derives_username_totp_attachments_on_both_dbs() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "df-live", "Derived Live", 0);
            seed_field(&conn, "df-live-f1", "df-live", Some("tpl_username"), "Username", "alice", "text");
            seed_field(&conn, "df-live-f2", "df-live", Some("tpl_totp"), "TOTP", "otpauth://totp/x", "otp");
            seed_attachment(&conn, "df-live-a1", "df-live");

            seed_entry(&conn, "df-bare", "Derived Bare", 0);

            let rows = list(&conn, View::All).unwrap();

            let live = rows
                .iter()
                .find(|e| e.id == "df-live")
                .unwrap_or_else(|| panic!("[{label}] seeded live entry must appear in list()"));
            assert_eq!(
                live.username.as_deref(),
                Some("alice"),
                "[{label}] username must be derived from the tpl_username field's value"
            );
            assert!(live.has_totp, "[{label}] has_totp must be true when a tpl_totp/otp field exists");
            assert!(live.has_attachments, "[{label}] has_attachments must be true when an attachments row exists");

            let bare = rows
                .iter()
                .find(|e| e.id == "df-bare")
                .unwrap_or_else(|| panic!("[{label}] seeded bare entry must appear in list()"));
            assert_eq!(bare.username, None, "[{label}] neither a username nor an email field means username must be None");
            assert!(!bare.has_totp, "[{label}] no totp field means has_totp must be false");
            assert!(!bare.has_attachments, "[{label}] no attachments row means has_attachments must be false");
        }
    }

    /// A protected identity field must never reach `EntrySummary.username`,
    /// via `list()` or `search::search()` (both build from `SUMMARY_COLS`).
    /// Covers tpl_username, tpl_email and a bare field_type='email'.
    #[test]
    fn summary_username_skips_protected_identity_fields() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "pr-user", "Protected user", 0);
            seed_field(&conn, "pr-user-f1", "pr-user", Some("tpl_username"), "Username", "secretuser1", "text");
            seed_entry(&conn, "pr-tpl", "Protected tpl email", 0);
            seed_field(&conn, "pr-tpl-f1", "pr-tpl", Some("tpl_email"), "Email", "secret2@example.com", "email");
            seed_entry(&conn, "pr-typed", "Protected typed email", 0);
            seed_field(&conn, "pr-typed-f1", "pr-typed", None, "Email", "secret3@example.com", "email");
            // Protected username, open email: the open email must be the fallback.
            seed_entry(&conn, "pr-mix", "Protected user open email", 0);
            seed_field(&conn, "pr-mix-f1", "pr-mix", Some("tpl_username"), "Username", "secretuser4", "text");
            seed_field(&conn, "pr-mix-f2", "pr-mix", Some("tpl_email"), "Email", "open4@example.com", "email");
            conn.execute(
                "UPDATE entry_fields SET is_protected = 1
                 WHERE id IN ('pr-user-f1', 'pr-tpl-f1', 'pr-typed-f1', 'pr-mix-f1')",
                [],
            )
            .unwrap();

            let listed = list(&conn, View::All).unwrap();
            let searched = crate::search::search(
                &conn,
                "Protected",
                &crate::search::SearchFilters {
                    folder_id: None,
                    tag_id: None,
                    favorites_only: false,
                    regex: false,
                },
            )
            .unwrap();
            for (path, rows) in [("list", &listed), ("search", &searched)] {
                let find = |id: &str| {
                    rows.iter()
                        .find(|e| e.id == id)
                        .unwrap_or_else(|| panic!("[{label}] {path}: entry {id} must appear"))
                        .username
                        .clone()
                };
                assert_eq!(find("pr-user"), None, "[{label}] {path}: protected tpl_username must not leak");
                assert_eq!(find("pr-tpl"), None, "[{label}] {path}: protected tpl_email must not leak");
                assert_eq!(find("pr-typed"), None, "[{label}] {path}: protected field_type='email' must not leak");
                assert_eq!(
                    find("pr-mix"),
                    Some("open4@example.com".to_string()),
                    "[{label}] {path}: protected username must fall through to an unprotected email"
                );
            }
        }
    }

    /// The list's subtitle is the same derived identity the browser
    /// extension receives, so an entry whose login is an email must not read
    /// as anonymous here either — it did until testing on Windows
    /// surfaced it. `tpl_username` still wins when both exist.
    #[test]
    fn list_falls_back_to_an_email_when_there_is_no_username() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "em-only", "Email only", 0);
            seed_field(&conn, "em-only-f1", "em-only", Some("tpl_email"), "Email", "ann@example.com", "email");

            seed_entry(&conn, "em-typed", "Typed email only", 0);
            seed_field(&conn, "em-typed-f1", "em-typed", None, "Email", "bob@example.com", "email");

            seed_entry(&conn, "em-both", "Both", 0);
            seed_field(&conn, "em-both-f1", "em-both", Some("tpl_email"), "Email", "ann@example.com", "email");
            seed_field(&conn, "em-both-f2", "em-both", Some("tpl_username"), "Username", "ann", "text");

            let rows = list(&conn, View::All).unwrap();
            let find = |id: &str| {
                rows.iter()
                    .find(|e| e.id == id)
                    .unwrap_or_else(|| panic!("[{label}] seeded entry {id} must appear in list()"))
                    .username
                    .clone()
            };
            assert_eq!(find("em-only"), Some("ann@example.com".to_string()),
                "[{label}] a tpl_email field must stand in for the missing username");
            assert_eq!(find("em-typed"), Some("bob@example.com".to_string()),
                "[{label}] a field_type='email' field must stand in too");
            assert_eq!(find("em-both"), Some("ann".to_string()),
                "[{label}] tpl_username must win when both are present");
        }
    }

    /// Covers: `View::Recent` orders by
    /// `e.updated_at DESC` and `EntrySummary.updated_at` must carry the real
    /// value through. Compares relative position, not absolute index/count,
    /// since the migrated fixture already has entries of its own.
    #[test]
    fn list_recent_orders_newest_first_on_both_dbs() {
        for (label, conn) in both_dbs() {
            let now = db::now_unix();
            seed_entry(&conn, "ord-older", "Order Older", 0);
            conn.execute("UPDATE entries SET updated_at = ?1 WHERE id = 'ord-older'", [now - 1000])
                .unwrap();
            seed_entry(&conn, "ord-newer", "Order Newer", 0);
            conn.execute("UPDATE entries SET updated_at = ?1 WHERE id = 'ord-newer'", [now]).unwrap();

            let rows = list(&conn, View::Recent).unwrap();
            let newer_pos = rows
                .iter()
                .position(|e| e.id == "ord-newer")
                .unwrap_or_else(|| panic!("[{label}] seeded newer entry must appear in View::Recent"));
            let older_pos = rows
                .iter()
                .position(|e| e.id == "ord-older")
                .unwrap_or_else(|| panic!("[{label}] seeded older entry must appear in View::Recent"));
            assert!(
                newer_pos < older_pos,
                "[{label}] the more recently updated entry must precede the older one under View::Recent"
            );
            assert_eq!(
                rows[newer_pos].updated_at, now,
                "[{label}] EntrySummary.updated_at must carry through the seeded value"
            );
        }
    }

    #[test]
    fn get_hides_protected_values_but_returns_plain_ones() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "get-protected-test", "Site", 0);
            conn.execute(
                "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type)
                 VALUES ('get-plain', 'get-protected-test', 'tpl_username', 'Username', 'alice', 0, 'text'),
                        ('get-secret', 'get-protected-test', 'tpl_password', 'Password', 'hunter2', 1, 'secret')",
                [],
            )
            .unwrap();

            let e = get(&conn, "get-protected-test").unwrap().expect("[{label}] entry exists");
            let user = e.fields.iter().find(|f| f.id == "get-plain").unwrap();
            let pass = e.fields.iter().find(|f| f.id == "get-secret").unwrap();
            assert_eq!(user.value.as_deref(), Some("alice"), "[{label}] plain value present");
            assert_eq!(pass.value, None, "[{label}] protected value must be withheld");
            assert!(pass.is_protected, "[{label}] but the field is still marked protected");
            assert_eq!(
                pass.strength,
                Some(crate::strength::estimate("hunter2")),
                "[{label}] secret field scored from its withheld plaintext"
            );
            assert_eq!(user.strength, None, "[{label}] a non-secret field carries no strength");
        }
    }

    #[test]
    fn get_returns_none_for_missing_or_deleted() {
        for (label, conn) in both_dbs() {
            assert!(get(&conn, "get-missing").unwrap().is_none(), "[{label}] missing -> None");
            seed_entry(&conn, "get-deleted", "Del", 0);
            conn.execute("UPDATE entries SET is_deleted = 1 WHERE id = 'get-deleted'", []).unwrap();
            assert!(get(&conn, "get-deleted").unwrap().is_none(), "[{label}] soft-deleted -> None");
        }
    }

    #[test]
    fn create_inserts_entry_and_fields_visible_to_list_and_get() {
        for (label, conn) in both_dbs() {
            let new = NewEntry {
                title: "GitHub".into(),
                folder_id: None,
                notes: Some("work".into()),
                entry_type: "login".into(),
                fields: vec![
                    NewField { template_id: Some("tpl_username".into()), name: "Username".into(),
                               value: Some("octocat".into()), is_protected: false, field_type: "text".into() },
                    NewField { template_id: Some("tpl_password".into()), name: "Password".into(),
                               value: Some("s3cr3t".into()), is_protected: true, field_type: "secret".into() },
                ],
            };
            let created = create(&conn, new, 1000).unwrap();

            assert_eq!(created.title, "GitHub", "[{label}]");
            assert_eq!(created.folder_id.as_deref(), Some("root"), "[{label}] defaults to root");
            assert!(!created.id.is_empty(), "[{label}] id assigned");
            assert_eq!(created.created_at, 1000, "[{label}]");

            assert!(list(&conn, View::All).unwrap().iter().any(|e| e.id == created.id), "[{label}]");
            let got = get(&conn, &created.id).unwrap().unwrap();
            assert_eq!(got.fields.len(), 2, "[{label}] both fields persisted");

            let u = got.fields.iter().find(|f| f.name == "Username").unwrap();
            assert_eq!(u.value.as_deref(), Some("octocat"), "[{label}] non-protected value survives read-back");
            assert!(!u.is_protected, "[{label}] username is not protected");
            assert_eq!(u.sort_order, 0, "[{label}] username keeps its input order (index 0)");

            let p = got.fields.iter().find(|f| f.name == "Password").unwrap();
            assert_eq!(p.value, None, "[{label}] password withheld on read-back");
            assert!(p.is_protected, "[{label}]");
            assert_eq!(p.sort_order, 1, "[{label}] password keeps its input order (index 1)");
        }
    }

    #[test]
    fn update_patches_scalars_and_replaces_fields() {
        for (label, conn) in both_dbs() {
            let created = create(
                &conn,
                NewEntry {
                    title: "Old".into(),
                    folder_id: None,
                    notes: None,
                    entry_type: "login".into(),
                    fields: vec![NewField {
                        template_id: Some("tpl_username".into()), name: "Username".into(),
                        value: Some("old-user".into()), is_protected: false, field_type: "text".into(),
                    }],
                },
                1000,
            )
            .unwrap();

            let patch = EntryPatch {
                title: Some("New".into()),
                notes: Some("noted".into()),
                is_favorite: Some(true),
                folder_id: None,
                fields: Some(vec![FieldInput {
                    id: None, template_id: Some("tpl_username".into()), name: "Username".into(),
                    is_protected: false, field_type: "text".into(),
                    value: FieldValue::Set("new-user".into()),
                }]),
            };
            let updated = update(&conn, &created.id, patch, 2000).unwrap().unwrap();

            assert_eq!(updated.title, "New", "[{label}]");
            assert_eq!(updated.notes.as_deref(), Some("noted"), "[{label}]");
            assert!(updated.is_favorite, "[{label}]");
            assert_eq!(updated.updated_at, 2000, "[{label}] updated_at bumped");
            assert_eq!(updated.fields.len(), 1, "[{label}] fields replaced, not appended");
            assert_eq!(
                updated.fields[0].value.as_deref(), Some("new-user"),
                "[{label}] field value replaced"
            );
        }
    }

    #[test]
    fn update_missing_entry_returns_none() {
        for (label, conn) in both_dbs() {
            let patch = EntryPatch { title: Some("x".into()), notes: None, is_favorite: None,
                                     folder_id: None, fields: None };
            assert!(update(&conn, "nope", patch, 1).unwrap().is_none(), "[{label}]");
        }
    }

    #[test]
    fn soft_delete_hides_entry_and_drops_it_from_search() {
        for (label, conn) in both_dbs() {
            let e = create(
                &conn,
                NewEntry { title: "SearchMe".into(), folder_id: None, notes: None, entry_type: "login".into(), fields: vec![] },
                1000,
            )
            .unwrap();
            let before: i64 = conn
                .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'SearchMe'", [], |r| r.get(0))
                .unwrap();
            assert_eq!(before, 1, "[{label}] indexed before delete");

            assert!(soft_delete(&conn, &e.id, 2000).unwrap(), "[{label}] deletes a live entry");
            assert!(get(&conn, &e.id).unwrap().is_none(), "[{label}] gone from get");
            assert!(!list(&conn, View::All).unwrap().iter().any(|x| x.id == e.id), "[{label}] gone from list");

            let after: i64 = conn
                .query_row("SELECT COUNT(*) FROM entries_fts WHERE entries_fts MATCH 'SearchMe'", [], |r| r.get(0))
                .unwrap();
            assert_eq!(after, 0, "[{label}] trigger dropped it from the index");

            assert!(!soft_delete(&conn, &e.id, 3000).unwrap(), "[{label}] second delete is a no-op");
        }
    }

    #[test]
    fn list_and_get_carry_tags_excluding_favorite() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "e-t", "Tagged", 0);
            conn.execute("INSERT INTO tags (id, name, color) VALUES ('tg-a','Alpha','#4d8fd6')", []).unwrap();
            conn.execute("INSERT INTO tags (id, name, color) VALUES ('tg-f','favorite','#FFD700')", []).unwrap();
            conn.execute("INSERT INTO entry_tags (entry_id, tag_id) VALUES ('e-t','tg-a'),('e-t','tg-f')", []).unwrap();

            let summary = list(&conn, View::All).unwrap();
            let s = summary.iter().find(|e| e.id == "e-t").unwrap();
            assert!(s.tags.iter().any(|t| t.id == "tg-a"), "[{label}] summary carries the tag");
            assert!(s.tags.iter().all(|t| t.name != "favorite"), "[{label}] summary excludes favorite");
            assert_eq!(s.folder_id.as_deref(), Some("root"), "[{label}] summary carries folder_id");

            let full = get(&conn, "e-t").unwrap().unwrap();
            assert!(full.tags.iter().any(|t| t.id == "tg-a"), "[{label}] detail carries the tag");
            assert!(full.tags.iter().all(|t| t.name != "favorite"), "[{label}] detail excludes favorite");

            seed_entry(&conn, "e-no-tags", "NoTags", 0);
            let s2 = list(&conn, View::All).unwrap().into_iter().find(|e| e.id == "e-no-tags").unwrap();
            assert!(s2.tags.is_empty(), "[{label}] summary tags empty when entry has no tag links");
            let full2 = get(&conn, "e-no-tags").unwrap().unwrap();
            assert!(full2.tags.is_empty(), "[{label}] detail tags empty when entry has no tag links");
        }
    }

    #[test]
    fn reveal_field_returns_the_stored_secret() {
        for (label, conn) in both_dbs() {
            let e = create(
                &conn,
                NewEntry {
                    title: "Site".into(), folder_id: None, notes: None, entry_type: "login".into(),
                    fields: vec![
                        NewField { template_id: Some("tpl_password".into()), name: "Password".into(),
                                   value: Some("hunter2".into()), is_protected: true, field_type: "secret".into() },
                        NewField { template_id: Some("tpl_totp".into()), name: "Recovery".into(),
                                   value: None, is_protected: true, field_type: "secret".into() },
                    ],
                },
                1000,
            )
            .unwrap();
            let got = get(&conn, &e.id).unwrap().unwrap();
            let pw_id = &got.fields.iter().find(|f| f.name == "Password").unwrap().id;
            let empty_id = &got.fields.iter().find(|f| f.name == "Recovery").unwrap().id;

            assert_eq!(
                reveal_field(&conn, &e.id, pw_id).unwrap().as_deref(), Some("hunter2"),
                "[{label}] reveals the real secret"
            );
            assert_eq!(
                reveal_field(&conn, &e.id, empty_id).unwrap().as_deref(), Some(""),
                "[{label}] NULL value reveals as empty string, not error"
            );
            assert!(reveal_field(&conn, &e.id, "no-such-field").unwrap().is_none(), "[{label}]");

            assert!(
                reveal_field(&conn, "not-the-entry", pw_id).unwrap().is_none(),
                "[{label}] a valid field id under the wrong entry id is denied"
            );

            soft_delete(&conn, &e.id, 2000).unwrap();
            assert!(
                reveal_field(&conn, &e.id, pw_id).unwrap().is_none(),
                "[{label}] a trashed entry's field is not revealable"
            );
        }
    }

    /// set_fields with all-new (id: None) inputs inserts them, replacing whatever
    /// the entry had — the wholesale-equivalent baseline before diffing is added.
    #[test]
    fn set_fields_inserts_new_and_deletes_absent() {
        for (label, conn) in both_dbs() {
            let e = create(
                &conn,
                NewEntry { title: "S".into(), folder_id: None, notes: None, entry_type: "login".into(), fields: vec![
                    NewField { template_id: Some("tpl_username".into()), name: "Username".into(),
                               value: Some("old".into()), is_protected: false, field_type: "text".into() },
                ]},
                1000,
            ).unwrap();
            let old_field_id = get(&conn, &e.id).unwrap().unwrap().fields[0].id.clone();

            set_fields(&conn, &e.id, vec![
                FieldInput { id: None, template_id: Some("tpl_password".into()), name: "Password".into(),
                             is_protected: true, field_type: "secret".into(), value: FieldValue::Set("s3cr3t".into()) },
            ], 2000).unwrap();

            let got = get(&conn, &e.id).unwrap().unwrap();
            assert_eq!(got.fields.len(), 1, "[{label}] the absent old field was deleted");
            assert_eq!(got.fields[0].name, "Password", "[{label}] the new field was inserted");
            assert!(got.fields.iter().all(|f| f.id != old_field_id), "[{label}] old field id is gone");
            assert_eq!(got.fields[0].sort_order, 0, "[{label}] positional sort_order");
        }
    }

    #[test]
    fn set_fields_on_unknown_entry_is_a_noop_delete_then_insert() {
        for (label, conn) in both_dbs() {
            assert!(set_fields(&conn, "ghost", vec![], 1).is_ok(), "[{label}] empty set on ghost is Ok");
        }
    }

    #[test]
    fn set_fields_keeps_id_and_untouched_secret_without_plaintext() {
        for (label, conn) in both_dbs() {
            let e = create(&conn, NewEntry { title: "K".into(), folder_id: None, notes: None, entry_type: "login".into(), fields: vec![
                NewField { template_id: Some("tpl_username".into()), name: "Username".into(),
                           value: Some("alice".into()), is_protected: false, field_type: "text".into() },
                NewField { template_id: Some("tpl_password".into()), name: "Password".into(),
                           value: Some("hunter2".into()), is_protected: true, field_type: "secret".into() },
            ]}, 1000).unwrap();
            let before = get(&conn, &e.id).unwrap().unwrap();
            let user_id = before.fields.iter().find(|f| f.name == "Username").unwrap().id.clone();
            let pass_id = before.fields.iter().find(|f| f.name == "Password").unwrap().id.clone();

            set_fields(&conn, &e.id, vec![
                FieldInput { id: Some(user_id.clone()), template_id: Some("tpl_username".into()), name: "Username".into(),
                             is_protected: false, field_type: "text".into(), value: FieldValue::Set("bob".into()) },
                FieldInput { id: Some(pass_id.clone()), template_id: Some("tpl_password".into()), name: "Password".into(),
                             is_protected: true, field_type: "secret".into(), value: FieldValue::Keep },
            ], 2000).unwrap();

            let after = get(&conn, &e.id).unwrap().unwrap();
            assert_eq!(after.fields.iter().find(|f| f.name == "Username").unwrap().id, user_id, "[{label}] username id stable");
            assert_eq!(after.fields.iter().find(|f| f.name == "Password").unwrap().id, pass_id, "[{label}] password id stable");
            assert_eq!(after.fields.iter().find(|f| f.name == "Username").unwrap().value.as_deref(), Some("bob"), "[{label}] username updated");
            assert_eq!(reveal_field(&conn, &e.id, &pass_id).unwrap().as_deref(), Some("hunter2"), "[{label}] kept secret intact");
        }
    }

    #[test]
    fn set_fields_clear_and_reorder_by_position() {
        for (label, conn) in both_dbs() {
            let e = create(&conn, NewEntry { title: "C".into(), folder_id: None, notes: None, entry_type: "login".into(), fields: vec![
                NewField { template_id: None, name: "A".into(), value: Some("a".into()), is_protected: false, field_type: "text".into() },
                NewField { template_id: None, name: "B".into(), value: Some("b".into()), is_protected: false, field_type: "text".into() },
            ]}, 1000).unwrap();
            let before = get(&conn, &e.id).unwrap().unwrap();
            let a = before.fields.iter().find(|f| f.name == "A").unwrap().id.clone();
            let b = before.fields.iter().find(|f| f.name == "B").unwrap().id.clone();

            set_fields(&conn, &e.id, vec![
                FieldInput { id: Some(b.clone()), template_id: None, name: "B".into(), is_protected: false, field_type: "text".into(), value: FieldValue::Keep },
                FieldInput { id: Some(a.clone()), template_id: None, name: "A".into(), is_protected: false, field_type: "text".into(), value: FieldValue::Clear },
            ], 2000).unwrap();

            let after = get(&conn, &e.id).unwrap().unwrap();
            assert_eq!(after.fields[0].id, b, "[{label}] B now sorts first (sort_order 0)");
            assert_eq!(after.fields[1].id, a, "[{label}] A now second");
            assert_eq!(after.fields.iter().find(|f| f.id == a).unwrap().value, None, "[{label}] A cleared to NULL");
        }
    }

    #[test]
    fn secret_change_records_history_and_prunes_to_ten() {
        for (label, conn) in both_dbs() {
            let e = create(&conn, NewEntry { title: "H".into(), folder_id: None, notes: None, entry_type: "login".into(), fields: vec![
                NewField { template_id: Some("tpl_password".into()), name: "Password".into(),
                           value: Some("v0".into()), is_protected: true, field_type: "secret".into() },
            ]}, 0).unwrap();
            let pid = get(&conn, &e.id).unwrap().unwrap().fields[0].id.clone();

            for i in 1..=12 {
                set_fields(&conn, &e.id, vec![FieldInput { id: Some(pid.clone()), template_id: Some("tpl_password".into()),
                    name: "Password".into(), is_protected: true, field_type: "secret".into(),
                    value: FieldValue::Set(format!("v{i}")) }], i).unwrap();
            }
            let hist = list_field_history(&conn, &e.id, "Password").unwrap();
            assert_eq!(hist.len(), 10, "[{label}] pruned to 10");
            assert_eq!(hist[0].value.as_deref(), Some("v11"), "[{label}] newest recorded old-value first (v11 was replaced by v12)");
            clear_field_history(&conn, &e.id, "Password").unwrap();
            assert!(list_field_history(&conn, &e.id, "Password").unwrap().is_empty(), "[{label}] cleared");
        }
    }
    #[test]
    fn non_secret_change_records_no_history() {
        for (label, conn) in both_dbs() {
            let e = create(&conn, NewEntry { title: "H2".into(), folder_id: None, notes: None, entry_type: "login".into(), fields: vec![
                NewField { template_id: Some("tpl_username".into()), name: "Username".into(),
                           value: Some("u0".into()), is_protected: false, field_type: "text".into() },
            ]}, 0).unwrap();
            let uid = get(&conn, &e.id).unwrap().unwrap().fields[0].id.clone();
            set_fields(&conn, &e.id, vec![FieldInput { id: Some(uid), template_id: Some("tpl_username".into()),
                name: "Username".into(), is_protected: false, field_type: "text".into(),
                value: FieldValue::Set("u1".into()) }], 1).unwrap();
            assert!(list_field_history(&conn, &e.id, "Username").unwrap().is_empty(), "[{label}] no history for non-secret");
        }
    }

    #[test]
    fn clearing_a_non_empty_secret_records_history() {
        for (label, conn) in both_dbs() {
            let e = create(&conn, NewEntry { title: "HC".into(), folder_id: None, notes: None, entry_type: "login".into(), fields: vec![
                NewField { template_id: Some("tpl_password".into()), name: "Password".into(),
                           value: Some("v0".into()), is_protected: true, field_type: "secret".into() },
            ]}, 0).unwrap();
            let pid = get(&conn, &e.id).unwrap().unwrap().fields[0].id.clone();
            set_fields(&conn, &e.id, vec![FieldInput { id: Some(pid), template_id: Some("tpl_password".into()),
                name: "Password".into(), is_protected: true, field_type: "secret".into(),
                value: FieldValue::Clear }], 1).unwrap();
            let hist = list_field_history(&conn, &e.id, "Password").unwrap();
            assert_eq!(hist.len(), 1, "[{label}] clearing a non-empty secret records one history row");
            assert_eq!(hist[0].value.as_deref(), Some("v0"), "[{label}] recorded row holds the OLD value");
        }
    }
    #[test]
    fn create_defaults_entry_type_to_login_and_round_trips() {
        let conn = crate::db::create_fresh().unwrap();
        let e = create(
            &conn,
            NewEntry {
                title: "Acct".into(),
                folder_id: None,
                notes: None,
                entry_type: "login".into(),
                fields: vec![],
            },
            1000,
        )
        .unwrap();
        assert_eq!(e.entry_type, "login");

        let got = get(&conn, &e.id).unwrap().unwrap();
        assert_eq!(got.entry_type, "login");

        let card = create(
            &conn,
            NewEntry { title: "Visa".into(), folder_id: None, notes: None, entry_type: "card".into(), fields: vec![] },
            1001,
        )
        .unwrap();
        assert_eq!(get(&conn, &card.id).unwrap().unwrap().entry_type, "card");
    }

    #[test]
    fn create_rejects_out_of_set_entry_type() {
        let conn = crate::db::create_fresh().unwrap();
        let err = create(
            &conn,
            NewEntry { title: "X".into(), folder_id: None, notes: None, entry_type: "bogus".into(), fields: vec![] },
            1000,
        );
        assert!(err.is_err(), "the DB CHECK must reject an out-of-set entry_type");
    }

    #[test]
    fn list_and_summary_carry_entry_type() {
        let conn = crate::db::create_fresh().unwrap();
        create(&conn, NewEntry { title: "N".into(), folder_id: None, notes: None, entry_type: "wifi".into(), fields: vec![] }, 1000).unwrap();
        let rows = list(&conn, View::All).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].entry_type, "wifi");
    }

    #[test]
    fn create_secure_note_with_default_body_persists_as_text() {
        let conn = crate::db::create_fresh().unwrap();
        let new = NewEntry {
            title: "My note".into(),
            folder_id: None,
            notes: None,
            entry_type: "secure_note".into(),
            fields: default_fields("secure_note"),
        };
        let entry = create(&conn, new, 0).unwrap();
        let body = entry.fields.iter().find(|f| f.name == "Note").expect("Note field present");
        assert_eq!(body.field_type, "text");
        assert!(!body.is_protected);
    }

    #[test]
    fn resetting_a_secret_to_its_current_value_records_no_history() {
        for (label, conn) in both_dbs() {
            let e = create(&conn, NewEntry { title: "HN".into(), folder_id: None, notes: None, entry_type: "login".into(), fields: vec![
                NewField { template_id: Some("tpl_password".into()), name: "Password".into(),
                           value: Some("same".into()), is_protected: true, field_type: "secret".into() },
            ]}, 0).unwrap();
            let pid = get(&conn, &e.id).unwrap().unwrap().fields[0].id.clone();
            set_fields(&conn, &e.id, vec![FieldInput { id: Some(pid), template_id: Some("tpl_password".into()),
                name: "Password".into(), is_protected: true, field_type: "secret".into(),
                value: FieldValue::Set("same".into()) }], 1).unwrap();
            assert!(list_field_history(&conn, &e.id, "Password").unwrap().is_empty(),
                "[{label}] re-Set of the identical value records no history");
        }
    }

    #[test]
    fn default_fields_match_each_type_exactly() {
        let names = |t: &str| default_fields(t).into_iter().map(|f| f.name).collect::<Vec<_>>();
        assert_eq!(names("login"), vec!["Username", "Password", "URL"]);
        assert_eq!(names("card"), vec!["Cardholder name", "Card number", "Expiry (MM/YY)", "Security code (CVV)"]);
        assert_eq!(names("secure_note"), vec!["Note"]);
        assert_eq!(names("wifi"), vec!["Network name (SSID)", "Password", "Security"]);

        let card = default_fields("card");
        let cvv = card.iter().find(|f| f.name == "Security code (CVV)").unwrap();
        assert_eq!(cvv.field_type, "secret");
        assert!(cvv.is_protected);
        let login = default_fields("login");
        assert_eq!(login[0].template_id.as_deref(), Some("tpl_username"));
        let wifi = default_fields("wifi");
        let sec = wifi.iter().find(|f| f.name == "Security").unwrap();
        assert_eq!(sec.value.as_deref(), Some("WPA2"), "Wi-Fi security defaults to WPA2");
        let wifi_pw = wifi.iter().find(|f| f.name == "Password").unwrap();
        assert_eq!(
            wifi_pw.template_id.as_deref(),
            Some("tpl_password"),
            "Wi-Fi Password is a password-role field: keeps the frontend generator dice"
        );

        let note = default_fields("secure_note");
        let body = &note[0];
        assert_eq!(body.field_type, "text");
        assert!(!body.is_protected);
        assert_eq!(body.template_id, None);
        assert_eq!(body.value, None);
    }

    #[test]
    fn default_fields_unknown_type_is_empty_and_validity_check() {
        assert!(default_fields("nope").is_empty());
        assert!(is_valid_entry_type("card"));
        assert!(!is_valid_entry_type("nope"));
        assert_eq!(ENTRY_TYPES.len(), 4);
    }

    /// `password_field_id` on the summary must mirror `pick_secret_field`'s
    /// "first eligible" pick (nmh/handlers.rs): a secret or otherwise-protected
    /// field, excluding OTP, in sort_order/id order. None when no field
    /// qualifies. Covers the NULL-safe template_id handling in SUMMARY_COLS
    /// (a naive `template_id <> 'tpl_totp'` would silently drop every field
    /// whose template_id IS NULL, since SQL NULL <> 'x' is NULL, not true).
    #[test]
    fn list_summary_carries_primary_password_field_id() {
        let conn = crate::db::create_fresh().unwrap();

        let login_a = create(
            &conn,
            NewEntry {
                title: "Login A".into(),
                folder_id: None,
                notes: None,
                entry_type: "login".into(),
                fields: vec![
                    NewField { template_id: Some("tpl_username".into()), name: "Username".into(),
                               value: Some("alice".into()), is_protected: false, field_type: "text".into() },
                    NewField { template_id: Some("tpl_password".into()), name: "Password".into(),
                               value: Some("hunter2".into()), is_protected: true, field_type: "secret".into() },
                    NewField { template_id: Some("tpl_totp".into()), name: "TOTP".into(),
                               value: Some("otpauth://totp/x".into()), is_protected: true, field_type: "otp".into() },
                ],
            },
            1000,
        )
        .unwrap();
        let secret_id = login_a.fields.iter().find(|f| f.name == "Password").unwrap().id.clone();

        create(
            &conn,
            NewEntry {
                title: "Note B".into(),
                folder_id: None,
                notes: None,
                entry_type: "secure_note".into(),
                fields: vec![
                    NewField { template_id: None, name: "Note".into(),
                               value: Some("just text".into()), is_protected: false, field_type: "text".into() },
                ],
            },
            1000,
        )
        .unwrap();

        create(
            &conn,
            NewEntry {
                title: "Otp C".into(),
                folder_id: None,
                notes: None,
                entry_type: "login".into(),
                fields: vec![
                    NewField { template_id: Some("tpl_totp".into()), name: "TOTP".into(),
                               value: Some("otpauth://totp/y".into()), is_protected: true, field_type: "otp".into() },
                ],
            },
            1000,
        )
        .unwrap();

        let protected_d = create(
            &conn,
            NewEntry {
                title: "Protected D".into(),
                folder_id: None,
                notes: None,
                entry_type: "login".into(),
                fields: vec![
                    NewField { template_id: None, name: "Secret Note".into(),
                               value: Some("shh".into()), is_protected: true, field_type: "text".into() },
                ],
            },
            1000,
        )
        .unwrap();
        let protected_d_id = protected_d.fields[0].id.clone();

        let summaries = list(&conn, View::All).unwrap();
        let by_title = |title: &str| summaries.iter().find(|s| s.title == title).unwrap();

        assert_eq!(by_title("Login A").password_field_id.as_deref(), Some(secret_id.as_str()));
        assert_eq!(by_title("Note B").password_field_id, None);
        assert_eq!(by_title("Otp C").password_field_id, None);
        assert_eq!(by_title("Protected D").password_field_id.as_deref(), Some(protected_d_id.as_str()));
    }
}

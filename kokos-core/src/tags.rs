//! Tag CRUD + entry-tag links + favorite. The reserved `favorite` tag
//! (name `favorite`, color `#FFD700`) is hidden from `list()` and backs
//! `is_favorite` alongside the column. Colors are `#RRGGBB` only.

use rusqlite::{Connection, OptionalExtension};

use crate::error::{Result, VaultError};

pub const FAVORITE_TAG: &str = "favorite";
pub const FAVORITE_COLOR: &str = "#FFD700";

#[derive(Debug, Clone)]
pub struct Tag {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
    pub usage: i64,
}

pub fn list(conn: &Connection) -> Result<Vec<Tag>> {
    let mut stmt = conn.prepare(
        "SELECT t.id, t.name, t.color,
                (SELECT COUNT(*) FROM entry_tags et JOIN entries e ON e.id = et.entry_id
                   WHERE et.tag_id = t.id AND e.is_deleted = 0) AS usage
         FROM tags t
         WHERE t.name != ?1
         ORDER BY usage DESC, t.name COLLATE NOCASE ASC",
    )?;
    let rows = stmt.query_map([FAVORITE_TAG], |r| {
        Ok(Tag { id: r.get(0)?, name: r.get(1)?, color: r.get(2)?, usage: r.get(3)? })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The favorite tag's id if it has been created yet.
fn fav_tag_id(conn: &Connection) -> Result<Option<String>> {
    use rusqlite::OptionalExtension;
    Ok(conn
        .query_row("SELECT id FROM tags WHERE name = ?1", [FAVORITE_TAG], |r| r.get(0))
        .optional()?)
}

/// `#RRGGBB`, hex digits in either case.
pub(crate) fn is_valid_color(c: &str) -> bool {
    c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|ch| ch.is_ascii_hexdigit())
}

fn validate_color(color: Option<&str>) -> Result<()> {
    if let Some(c) = color {
        if !is_valid_color(c) {
            return Err(VaultError::InvalidColor);
        }
    }
    Ok(())
}

/// The reserved favorite name is taken. Exact match (after trim), like the
/// `name != 'favorite'` filters elsewhere: other spellings are ordinary tags.
fn reject_reserved_name(name: &str) -> Result<()> {
    if name.trim() == FAVORITE_TAG {
        return Err(VaultError::DuplicateTagName);
    }
    Ok(())
}

/// The reserved favorite tag is not addressable through user tag CRUD.
fn reject_favorite_id(conn: &Connection, id: &str) -> Result<()> {
    if fav_tag_id(conn)?.as_deref() == Some(id) {
        return Err(VaultError::TagNotFound);
    }
    Ok(())
}

/// tags has exactly one UNIQUE constraint (name), so a constraint violation
/// here is always a duplicate name.
fn map_unique(e: rusqlite::Error) -> VaultError {
    if let rusqlite::Error::SqliteFailure(f, _) = &e {
        if f.code == rusqlite::ErrorCode::ConstraintViolation {
            return VaultError::DuplicateTagName;
        }
    }
    e.into()
}

/// Get-or-create the reserved favorite tag, returning its id. No own
/// transaction (callable inside `portable::import`'s outer tx).
pub fn ensure_favorite_tag(conn: &Connection) -> Result<String> {
    if let Some(id) = fav_tag_id(conn)? { return Ok(id); }
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO tags (id, name, color) VALUES (?1, ?2, ?3)",
        rusqlite::params![id, FAVORITE_TAG, FAVORITE_COLOR],
    )?;
    Ok(id)
}

pub fn create(conn: &Connection, name: &str, color: Option<&str>) -> Result<Tag> {
    reject_reserved_name(name)?;
    validate_color(color)?;
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO tags (id, name, color) VALUES (?1, ?2, ?3)",
        rusqlite::params![id, name, color],
    )
    .map_err(map_unique)?;
    Ok(Tag { id, name: name.to_string(), color: color.map(str::to_string), usage: 0 })
}

fn read_tag(conn: &Connection, id: &str) -> Result<Tag> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT t.id, t.name, t.color,
                (SELECT COUNT(*) FROM entry_tags et JOIN entries e ON e.id = et.entry_id
                   WHERE et.tag_id = t.id AND e.is_deleted = 0)
         FROM tags t WHERE t.id = ?1",
        [id],
        |r| Ok(Tag { id: r.get(0)?, name: r.get(1)?, color: r.get(2)?, usage: r.get(3)? }),
    )
    .optional()?
    .ok_or(VaultError::TagNotFound)
}

pub fn rename(conn: &Connection, id: &str, name: &str) -> Result<Tag> {
    reject_favorite_id(conn, id)?;
    reject_reserved_name(name)?;
    let n = conn
        .execute("UPDATE tags SET name = ?1 WHERE id = ?2", rusqlite::params![name, id])
        .map_err(map_unique)?;
    if n == 0 {
        return Err(VaultError::TagNotFound);
    }
    read_tag(conn, id)
}

pub fn recolor(conn: &Connection, id: &str, color: Option<&str>) -> Result<Tag> {
    reject_favorite_id(conn, id)?;
    validate_color(color)?;
    let n = conn.execute("UPDATE tags SET color = ?1 WHERE id = ?2", rusqlite::params![color, id])?;
    if n == 0 {
        return Err(VaultError::TagNotFound);
    }
    read_tag(conn, id)
}

pub fn delete(conn: &Connection, id: &str) -> Result<()> {
    reject_favorite_id(conn, id)?;
    let n = conn.execute("DELETE FROM tags WHERE id = ?1", [id])?;
    if n == 0 {
        return Err(VaultError::TagNotFound);
    }
    Ok(())
}

/// Bumps a live entry's updated_at; `EntryNotFound` when it is missing or
/// trashed. Runs before any link write so a missing entry never reaches the
/// entry_tags foreign key.
fn touch_live_entry(conn: &Connection, entry_id: &str, now: i64) -> Result<()> {
    let n = conn.execute(
        "UPDATE entries SET updated_at = ?1 WHERE id = ?2 AND is_deleted = 0",
        rusqlite::params![now, entry_id],
    )?;
    if n == 0 {
        return Err(VaultError::EntryNotFound);
    }
    Ok(())
}

pub fn set_entry_tags(conn: &Connection, entry_id: &str, tag_ids: &[String], now: i64) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    touch_live_entry(&tx, entry_id, now)?;
    let fav = fav_tag_id(&tx)?;
    match &fav {
        Some(f) => tx.execute(
            "DELETE FROM entry_tags WHERE entry_id = ?1 AND tag_id != ?2",
            rusqlite::params![entry_id, f],
        )?,
        None => tx.execute("DELETE FROM entry_tags WHERE entry_id = ?1", [entry_id])?,
    };
    for tid in tag_ids {
        if Some(tid) == fav.as_ref() {
            continue;
        }
        tx.execute(
            "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?1, ?2)",
            rusqlite::params![entry_id, tid],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Add or remove ONE tag on an entry (bulk tag +/-). `add=true` inserts
/// (idempotent), `add=false` removes. Touches updated_at like the other
/// tag ops. The reserved favorite tag is rejected with `TagNotFound` — use
/// `toggle_favorite`, which keeps `is_favorite` in sync.
pub fn set_entry_tag(conn: &Connection, entry_id: &str, tag_id: &str, add: bool, now: i64) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    reject_favorite_id(&tx, tag_id)?;
    touch_live_entry(&tx, entry_id, now)?;
    if add {
        tx.execute("INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?1, ?2)", rusqlite::params![entry_id, tag_id])?;
    } else {
        tx.execute("DELETE FROM entry_tags WHERE entry_id = ?1 AND tag_id = ?2", rusqlite::params![entry_id, tag_id])?;
    }
    tx.commit()?;
    Ok(())
}

pub fn toggle_favorite(conn: &Connection, entry_id: &str, now: i64) -> Result<bool> {
    let tx = conn.unchecked_transaction()?;
    let cur: Option<i64> = tx
        .query_row(
            "SELECT is_favorite FROM entries WHERE id = ?1 AND is_deleted = 0",
            [entry_id],
            |r| r.get(0),
        )
        .optional()?;
    let cur = cur.ok_or(VaultError::EntryNotFound)?;
    let new = cur == 0;

    let fav = match fav_tag_id(&tx)? {
        Some(id) => id,
        None => {
            let id = uuid::Uuid::new_v4().to_string();
            tx.execute(
                "INSERT INTO tags (id, name, color) VALUES (?1, ?2, ?3)",
                rusqlite::params![id, FAVORITE_TAG, FAVORITE_COLOR],
            )?;
            id
        }
    };

    tx.execute(
        "UPDATE entries SET is_favorite = ?1, updated_at = ?2 WHERE id = ?3",
        rusqlite::params![new as i64, now, entry_id],
    )?;
    if new {
        tx.execute(
            "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?1, ?2)",
            rusqlite::params![entry_id, fav],
        )?;
    } else {
        tx.execute(
            "DELETE FROM entry_tags WHERE entry_id = ?1 AND tag_id = ?2",
            rusqlite::params![entry_id, fav],
        )?;
    }
    tx.commit()?;
    Ok(new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{both_dbs, seed_entry};

    #[test]
    fn list_hides_favorite_and_counts_live_usage() {
        for (label, conn) in both_dbs() {
            conn.execute("INSERT INTO tags (id, name, color) VALUES ('t-work','Work','#4d8fd6')", []).unwrap();
            conn.execute("INSERT INTO tags (id, name, color) VALUES ('t-fav','favorite','#FFD700')", []).unwrap();
            seed_entry(&conn, "e-a", "A", 0);
            conn.execute("INSERT INTO entry_tags (entry_id, tag_id) VALUES ('e-a','t-work')", []).unwrap();

            let tags = list(&conn).unwrap();
            assert!(tags.iter().all(|t| t.name != "favorite"), "[{label}] reserved favorite tag hidden");
            let work = tags.iter().find(|t| t.id == "t-work")
                .unwrap_or_else(|| panic!("[{label}] Work tag present"));
            assert_eq!(work.usage, 1, "[{label}] usage counts the live link");
        }
    }

    /// The usage subquery's `AND e.is_deleted = 0` filter
    /// had zero regression coverage -- the only existing test links a tag to
    /// a single live entry. Mirrors folders::list_tree_counts_only_live_entries_in_their_own_folder:
    /// links one tag to TWO entries, one live and one soft-deleted (seeded
    /// live via `seed_entry`, then flipped with an `UPDATE`), and pins
    /// usage == 1, not 2. Deleting or inverting the `is_deleted` filter
    /// would make this fail.
    #[test]
    fn list_counts_only_live_links_excludes_soft_deleted_entry() {
        for (label, conn) in both_dbs() {
            conn.execute("INSERT INTO tags (id, name, color) VALUES ('t-mix','Mixed','#4d8fd6')", []).unwrap();

            seed_entry(&conn, "tg-live", "Live", 0);
            conn.execute("INSERT INTO entry_tags (entry_id, tag_id) VALUES ('tg-live','t-mix')", []).unwrap();

            seed_entry(&conn, "tg-deleted", "Deleted", 0);
            conn.execute("UPDATE entries SET is_deleted = 1 WHERE id = 'tg-deleted'", []).unwrap();
            conn.execute("INSERT INTO entry_tags (entry_id, tag_id) VALUES ('tg-deleted','t-mix')", []).unwrap();

            let tags = list(&conn).unwrap();
            let mixed = tags.iter().find(|t| t.id == "t-mix")
                .unwrap_or_else(|| panic!("[{label}] Mixed tag present"));
            assert_eq!(mixed.usage, 1, "[{label}] usage counts only the live link, excluding the soft-deleted one");
        }
    }

    /// `ORDER BY usage DESC, name COLLATE NOCASE ASC` had zero
    /// regression coverage since the sole existing test leaves exactly one
    /// non-favorite tag after filtering. Seeds "High" (2 live links) and
    /// "Low" (1 live link) to pin the usage-DESC order, plus a same-usage
    /// ("Alpha"/"zeta", 0 links each) pair to pin the name-ASC, case-
    /// insensitive tie-break.
    #[test]
    fn list_orders_by_usage_desc_then_name_asc() {
        for (label, conn) in both_dbs() {
            conn.execute("INSERT INTO tags (id, name, color) VALUES ('t-high','High','#111111')", []).unwrap();
            conn.execute("INSERT INTO tags (id, name, color) VALUES ('t-low','Low','#222222')", []).unwrap();
            conn.execute("INSERT INTO tags (id, name, color) VALUES ('t-zeta','zeta','#333333')", []).unwrap();
            conn.execute("INSERT INTO tags (id, name, color) VALUES ('t-alpha','Alpha','#444444')", []).unwrap();

            seed_entry(&conn, "ord-h1", "H1", 0);
            seed_entry(&conn, "ord-h2", "H2", 0);
            seed_entry(&conn, "ord-l1", "L1", 0);
            conn.execute("INSERT INTO entry_tags (entry_id, tag_id) VALUES ('ord-h1','t-high')", []).unwrap();
            conn.execute("INSERT INTO entry_tags (entry_id, tag_id) VALUES ('ord-h2','t-high')", []).unwrap();
            conn.execute("INSERT INTO entry_tags (entry_id, tag_id) VALUES ('ord-l1','t-low')", []).unwrap();

            let tags = list(&conn).unwrap();
            let pos = |id: &str| tags.iter().position(|t| t.id == id)
                .unwrap_or_else(|| panic!("[{label}] tag {id} present in list()"));

            assert!(pos("t-high") < pos("t-low"),
                "[{label}] usage DESC: High (2 live links) sorts before Low (1)");
            assert!(pos("t-low") < pos("t-alpha"),
                "[{label}] usage DESC: any live usage sorts before zero usage");
            assert!(pos("t-alpha") < pos("t-zeta"),
                "[{label}] usage tie (0 == 0) falls back to name ASC, case-insensitive: Alpha before zeta");
        }
    }

    #[test]
    fn create_validates_color_and_uniqueness() {
        for (label, conn) in both_dbs() {
            let t = create(&conn, "Work", Some("#4D8FD6")).unwrap();
            assert_eq!(t.color.as_deref(), Some("#4D8FD6"), "[{label}] valid hex stored");
            assert!(matches!(create(&conn, "Work", None), Err(VaultError::DuplicateTagName)),
                "[{label}] duplicate name rejected");
            assert!(matches!(create(&conn, "Bad", Some("blue")), Err(VaultError::InvalidColor)),
                "[{label}] non-#RRGGBB rejected");
            assert!(matches!(create(&conn, "Bad2", Some("#12345")), Err(VaultError::InvalidColor)),
                "[{label}] short hex rejected");
        }
    }

    #[test]
    fn delete_removes_tag_and_links() {
        for (label, conn) in both_dbs() {
            let t = create(&conn, "Temp", None).unwrap();
            seed_entry(&conn, "e-x", "X", 0);
            conn.execute("INSERT INTO entry_tags (entry_id, tag_id) VALUES ('e-x', ?1)", [&t.id]).unwrap();
            delete(&conn, &t.id).unwrap();
            let links: i64 = conn.query_row("SELECT COUNT(*) FROM entry_tags WHERE tag_id = ?1", [&t.id], |r| r.get(0)).unwrap();
            assert_eq!(links, 0, "[{label}] FK cascade removed the links");
            assert!(matches!(delete(&conn, "ghost"), Err(VaultError::TagNotFound)),
                "[{label}] missing tag -> TagNotFound");
        }
    }

    #[test]
    fn rename_updates_tag_and_rejects_duplicates() {
        for (label, conn) in both_dbs() {
            let t = create(&conn, "Original", None).unwrap();
            let renamed = rename(&conn, &t.id, "Renamed").unwrap();
            assert_eq!(renamed.name, "Renamed", "[{label}] rename SUCCESS path: returned Tag.name reflects it");

            let t2 = create(&conn, "Existing", None).unwrap();
            assert!(matches!(rename(&conn, &t2.id, "Renamed"), Err(VaultError::DuplicateTagName)),
                "[{label}] rename to existing name rejected");

            assert!(matches!(rename(&conn, "ghost", "Anything"), Err(VaultError::TagNotFound)),
                "[{label}] rename missing tag -> TagNotFound");
        }
    }

    #[test]
    fn recolor_updates_color_and_validates() {
        for (label, conn) in both_dbs() {
            let t = create(&conn, "Colorful", Some("#123456")).unwrap();
            let recolored = recolor(&conn, &t.id, Some("#ABCDEF")).unwrap();
            assert_eq!(recolored.color.as_deref(), Some("#ABCDEF"), "[{label}] recolor SUCCESS path: returned Tag.color reflects it");

            let cleared = recolor(&conn, &t.id, None).unwrap();
            assert_eq!(cleared.color.as_deref(), None, "[{label}] recolor to None (clears color) works");

            assert!(matches!(recolor(&conn, &t.id, Some("#1234567")), Err(VaultError::InvalidColor)),
                "[{label}] too long #1234567 (8 chars) rejected");
            assert!(matches!(recolor(&conn, &t.id, Some("#12345G")), Err(VaultError::InvalidColor)),
                "[{label}] non-hex char #12345G rejected");
            assert!(recolor(&conn, &t.id, Some("#abcdef")).is_ok(),
                "[{label}] valid LOWERCASE hex #abcdef accepted");

            assert!(matches!(recolor(&conn, "ghost", Some("#123456")), Err(VaultError::TagNotFound)),
                "[{label}] recolor missing id -> TagNotFound");
        }
    }

    #[test]
    fn set_entry_tags_replaces_but_keeps_favorite() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_entry(&conn, "e-s", "S", 0);
            let t1 = create(&conn, "One", None).unwrap();
            let t2 = create(&conn, "Two", None).unwrap();
            conn.execute("INSERT INTO tags (id, name, color) VALUES ('t-fav','favorite','#FFD700')", []).unwrap();
            conn.execute("INSERT INTO entry_tags (entry_id, tag_id) VALUES ('e-s','t-fav')", []).unwrap();
            conn.execute("INSERT INTO entry_tags (entry_id, tag_id) VALUES ('e-s', ?1)", [&t1.id]).unwrap();

            set_entry_tags(&conn, "e-s", &[t2.id.clone()], now).unwrap();

            let ids: Vec<String> = {
                let mut s = conn.prepare("SELECT tag_id FROM entry_tags WHERE entry_id = 'e-s'").unwrap();
                s.query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap()
            };
            assert!(ids.contains(&t2.id), "[{label}] new tag applied");
            assert!(!ids.contains(&t1.id), "[{label}] old tag removed");
            assert!(ids.contains(&"t-fav".to_string()), "[{label}] favorite link PRESERVED across replace");
        }
    }

    #[test]
    fn set_entry_tags_no_favorite_path_replaces_cleanly() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_entry(&conn, "e-clean", "Clean", 0);
            let t1 = create(&conn, "Regular1", None).unwrap();
            let t2 = create(&conn, "Regular2", None).unwrap();
            let t3 = create(&conn, "Regular3", None).unwrap();
            conn.execute("INSERT INTO entry_tags (entry_id, tag_id) VALUES ('e-clean', ?1)", [&t1.id]).unwrap();
            conn.execute("INSERT INTO entry_tags (entry_id, tag_id) VALUES ('e-clean', ?1)", [&t2.id]).unwrap();

            set_entry_tags(&conn, "e-clean", &[t3.id.clone()], now).unwrap();

            let ids: Vec<String> = {
                let mut s = conn.prepare("SELECT tag_id FROM entry_tags WHERE entry_id = 'e-clean'").unwrap();
                s.query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap()
            };
            assert!(ids.contains(&t3.id), "[{label}] new tag applied");
            assert!(!ids.contains(&t1.id), "[{label}] old tag t1 removed");
            assert!(!ids.contains(&t2.id), "[{label}] old tag t2 removed");
        }
    }

    #[test]
    fn set_entry_tags_bumps_updated_at() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "e-ts", "Timestamp", 0);
            let original_ts: i64 = conn.query_row("SELECT updated_at FROM entries WHERE id = 'e-ts'", [], |r| r.get(0)).unwrap();

            let t1 = create(&conn, "TagForTS", None).unwrap();
            let distinct_now = original_ts + 12345;

            set_entry_tags(&conn, "e-ts", &[t1.id.clone()], distinct_now).unwrap();

            let new_ts: i64 = conn.query_row("SELECT updated_at FROM entries WHERE id = 'e-ts'", [], |r| r.get(0)).unwrap();
            assert_eq!(new_ts, distinct_now, "[{label}] entries.updated_at bumped to passed now");
        }
    }

    #[test]
    fn set_entry_tags_favorite_in_list_is_no_op() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_entry(&conn, "e-fav-in", "FavIn", 0);
            let regular = create(&conn, "Regular", None).unwrap();
            conn.execute("INSERT INTO tags (id, name, color) VALUES ('t-fav','favorite','#FFD700')", []).unwrap();
            conn.execute("INSERT INTO entry_tags (entry_id, tag_id) VALUES ('e-fav-in','t-fav')", []).unwrap();

            set_entry_tags(&conn, "e-fav-in", &[regular.id.clone(), "t-fav".to_string()], now).unwrap();

            let ids: Vec<String> = {
                let mut s = conn.prepare("SELECT tag_id FROM entry_tags WHERE entry_id = 'e-fav-in'").unwrap();
                s.query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap()
            };
            assert_eq!(ids.iter().filter(|id| *id == "t-fav").count(), 1, "[{label}] favorite link appears exactly once");
            assert!(ids.contains(&regular.id), "[{label}] regular tag applied");
        }
    }

    /// `set_entry_tags` returned `Ok(())` even when
    /// `entry_id` named no real entry (with an empty `tag_ids`, the DELETE
    /// and UPDATE both affect 0 rows and the insert loop never runs, so
    /// nothing ever surfaces the missing entry). Siblings check existence --
    /// `delete` -> `TagNotFound` on a 0-row delete, entries use
    /// `EntryNotFound` -- so this pins the same contract here.
    #[test]
    fn set_entry_tags_missing_entry_returns_entry_not_found() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            assert!(
                matches!(set_entry_tags(&conn, "ghost-entry", &[], now), Err(VaultError::EntryNotFound)),
                "[{label}] nonexistent entry -> EntryNotFound"
            );
            // A non-empty list must not reach the entry_tags foreign key first.
            let t = create(&conn, "GhostTag", None).unwrap();
            assert!(
                matches!(set_entry_tags(&conn, "ghost-entry", &[t.id.clone()], now), Err(VaultError::EntryNotFound)),
                "[{label}] nonexistent entry with tags -> EntryNotFound"
            );
            for add in [true, false] {
                assert!(
                    matches!(set_entry_tag(&conn, "ghost-entry", &t.id, add, now), Err(VaultError::EntryNotFound)),
                    "[{label}] set_entry_tag(add={add}) on nonexistent entry -> EntryNotFound"
                );
            }
        }
    }

    /// A duplicate id inside `tag_ids` (e.g. a caller
    /// double-submitting the same tag) had zero regression coverage. The
    /// composite PK on `entry_tags (entry_id, tag_id)` plus `INSERT OR
    /// IGNORE` should make the repeat a no-op, leaving exactly one link.
    #[test]
    fn set_entry_tags_duplicate_id_in_list_is_a_single_link() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_entry(&conn, "e-dup", "Dup", 0);
            let t1 = create(&conn, "DupTag", None).unwrap();

            set_entry_tags(&conn, "e-dup", &[t1.id.clone(), t1.id.clone()], now).unwrap();

            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM entry_tags WHERE entry_id = 'e-dup' AND tag_id = ?1",
                    [&t1.id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "[{label}] duplicate id in tag_ids yields exactly one link");
        }
    }

    #[test]
    fn create_and_rename_reject_reserved_favorite_name() {
        for (label, conn) in both_dbs() {
            for name in ["favorite", "  favorite "] {
                assert!(matches!(create(&conn, name, None), Err(VaultError::DuplicateTagName)),
                    "[{label}] create {name:?} rejected");
            }
            // Only the exact reserved name is taken; other spellings are ordinary tags.
            assert!(create(&conn, "Favorite", None).is_ok(), "[{label}] create \"Favorite\" allowed");
            let t = create(&conn, "Plain", None).unwrap();
            assert!(matches!(rename(&conn, &t.id, " favorite"), Err(VaultError::DuplicateTagName)),
                "[{label}] rename to reserved name rejected");
            assert_eq!(read_tag(&conn, &t.id).unwrap().name, "Plain", "[{label}] name unchanged");
        }
    }

    #[test]
    fn crud_on_favorite_tag_id_returns_not_found() {
        for (label, conn) in both_dbs() {
            let fav = ensure_favorite_tag(&conn).unwrap();
            assert!(matches!(rename(&conn, &fav, "Starred"), Err(VaultError::TagNotFound)), "[{label}] rename");
            assert!(matches!(recolor(&conn, &fav, Some("#000000")), Err(VaultError::TagNotFound)), "[{label}] recolor");
            assert!(matches!(delete(&conn, &fav), Err(VaultError::TagNotFound)), "[{label}] delete");
            let (name, color): (String, String) = conn.query_row(
                "SELECT name, color FROM tags WHERE id = ?1", [&fav], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            assert_eq!((name.as_str(), color.as_str()), (FAVORITE_TAG, FAVORITE_COLOR), "[{label}] favorite tag untouched");
        }
    }

    #[test]
    fn set_entry_tag_rejects_favorite_tag_id() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "e-fav-one", "FavOne", 0);
            conn.execute("UPDATE entries SET updated_at = 5 WHERE id = 'e-fav-one'", []).unwrap();
            let fav = ensure_favorite_tag(&conn).unwrap();
            for add in [true, false] {
                assert!(matches!(set_entry_tag(&conn, "e-fav-one", &fav, add, 99), Err(VaultError::TagNotFound)),
                    "[{label}] set_entry_tag(add={add}) with the favorite id -> TagNotFound");
            }
            let (links, col, ts): (i64, i64, i64) = conn.query_row(
                "SELECT (SELECT COUNT(*) FROM entry_tags WHERE entry_id = e.id), e.is_favorite, e.updated_at
                 FROM entries e WHERE e.id = 'e-fav-one'", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
            assert_eq!((links, col, ts), (0, 0, 5), "[{label}] link, column and updated_at untouched");
        }
    }

    #[test]
    fn is_valid_color_accepts_only_rrggbb() {
        assert!(is_valid_color("#a1B2c3"));
        for bad in ["", "#", "a1b2c3", "#a1b2c", "#a1b2c3d", "#a1b2cg", "#ä1b2c"] {
            assert!(!is_valid_color(bad), "{bad:?} rejected");
        }
    }

    #[test]
    fn tag_links_on_trashed_entry_return_entry_not_found() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "e-trash", "Trash", 0);
            conn.execute("UPDATE entries SET is_deleted = 1, updated_at = 5 WHERE id = 'e-trash'", []).unwrap();
            let t = create(&conn, "Any", None).unwrap();
            assert!(matches!(set_entry_tags(&conn, "e-trash", &[t.id.clone()], 99), Err(VaultError::EntryNotFound)),
                "[{label}] set_entry_tags on trashed entry");
            assert!(matches!(set_entry_tag(&conn, "e-trash", &t.id, true, 99), Err(VaultError::EntryNotFound)),
                "[{label}] set_entry_tag on trashed entry");
            let links: i64 = conn.query_row(
                "SELECT COUNT(*) FROM entry_tags WHERE entry_id = 'e-trash'", [], |r| r.get(0)).unwrap();
            let ts: i64 = conn.query_row(
                "SELECT updated_at FROM entries WHERE id = 'e-trash'", [], |r| r.get(0)).unwrap();
            assert_eq!(links, 0, "[{label}] rolled back: no link added");
            assert_eq!(ts, 5, "[{label}] rolled back: updated_at untouched");
        }
    }

    #[test]
    fn toggle_favorite_syncs_column_and_tag() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_entry(&conn, "e-f", "F", 0);

            let on = toggle_favorite(&conn, "e-f", now).unwrap();
            assert!(on, "[{label}] first toggle turns it on");
            let col: i64 = conn.query_row("SELECT is_favorite FROM entries WHERE id='e-f'", [], |r| r.get(0)).unwrap();
            let linked: i64 = conn.query_row(
                "SELECT COUNT(*) FROM entry_tags et JOIN tags t ON t.id=et.tag_id
                 WHERE et.entry_id='e-f' AND t.name='favorite'", [], |r| r.get(0)).unwrap();
            assert_eq!(col, 1, "[{label}] column set");
            assert_eq!(linked, 1, "[{label}] favorite tag linked");

            let off = toggle_favorite(&conn, "e-f", now).unwrap();
            assert!(!off, "[{label}] second toggle turns it off");
            let col2: i64 = conn.query_row("SELECT is_favorite FROM entries WHERE id='e-f'", [], |r| r.get(0)).unwrap();
            let linked2: i64 = conn.query_row(
                "SELECT COUNT(*) FROM entry_tags et JOIN tags t ON t.id=et.tag_id
                 WHERE et.entry_id='e-f' AND t.name='favorite'", [], |r| r.get(0)).unwrap();
            assert_eq!(col2, 0, "[{label}] column cleared");
            assert_eq!(linked2, 0, "[{label}] favorite tag unlinked");

            assert!(matches!(toggle_favorite(&conn, "ghost", now), Err(VaultError::EntryNotFound)),
                "[{label}] missing entry -> EntryNotFound");
        }
    }

    #[test]
    fn toggle_favorite_creates_reserved_tag_if_needed() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_entry(&conn, "e-create", "Create", 0);

            let on = toggle_favorite(&conn, "e-create", now).unwrap();
            assert!(on, "[{label}] first toggle turns it on");

            let tag: (String, String) = conn.query_row(
                "SELECT name, color FROM tags WHERE name = ?1",
                [FAVORITE_TAG],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ).unwrap();
            assert_eq!(tag.0, FAVORITE_TAG, "[{label}] tag name is 'favorite'");
            assert_eq!(tag.1, FAVORITE_COLOR, "[{label}] tag color is #FFD700");

            let tags = list(&conn).unwrap();
            assert!(tags.iter().all(|t| t.name != "favorite"), "[{label}] favorite tag hidden from list()");
        }
    }

    #[test]
    fn toggle_favorite_interplay_with_set_entry_tags() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_entry(&conn, "e-cross", "Cross", 0);
            let regular = create(&conn, "Regular", None).unwrap();

            let _ = toggle_favorite(&conn, "e-cross", now).unwrap();

            set_entry_tags(&conn, "e-cross", &[regular.id.clone()], now).unwrap();

            let linked: i64 = conn.query_row(
                "SELECT COUNT(*) FROM entry_tags et JOIN tags t ON t.id=et.tag_id
                 WHERE et.entry_id='e-cross' AND t.name='favorite'", [], |r| r.get(0)).unwrap();
            assert_eq!(linked, 1, "[{label}] favorite link survives set_entry_tags");

            let col: i64 = conn.query_row("SELECT is_favorite FROM entries WHERE id='e-cross'", [], |r| r.get(0)).unwrap();
            assert_eq!(col, 1, "[{label}] is_favorite column still 1");

            let has_regular: i64 = conn.query_row(
                "SELECT COUNT(*) FROM entry_tags WHERE entry_id='e-cross' AND tag_id=?1",
                [&regular.id],
                |r| r.get(0)).unwrap();
            assert_eq!(has_regular, 1, "[{label}] regular tag applied");
        }
    }

    #[test]
    fn set_entry_tag_add_is_idempotent_and_remove_works() {
        let conn = crate::db::create_fresh().unwrap();
        let e = crate::entries::create(&conn, crate::entries::NewEntry{ title:"E".into(), folder_id:None, notes:None, entry_type: "login".into(), fields:vec![] }, 1).unwrap();
        let t = create(&conn, "work", None).unwrap();
        set_entry_tag(&conn, &e.id, &t.id, true, 2).unwrap();
        set_entry_tag(&conn, &e.id, &t.id, true, 3).unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM entry_tags WHERE entry_id=?1 AND tag_id=?2", rusqlite::params![e.id, t.id], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
        set_entry_tag(&conn, &e.id, &t.id, false, 4).unwrap();
        let n2: i64 = conn.query_row("SELECT COUNT(*) FROM entry_tags WHERE entry_id=?1 AND tag_id=?2", rusqlite::params![e.id, t.id], |r| r.get(0)).unwrap();
        assert_eq!(n2, 0);
    }
}

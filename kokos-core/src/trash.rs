//! Recycle bin: list / restore / permanent-delete / empty, plus age-based
//! auto-delete wired into `vault::open` (unwired in Go).

use rusqlite::Connection;

use crate::db;
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct TrashItem {
    pub id: String,
    pub title: String,
    pub folder_name: Option<String>,
    pub deleted_at: Option<i64>,
    pub updated_at: i64,
}

pub fn list_trash(conn: &Connection) -> Result<Vec<TrashItem>> {
    let mut stmt = conn.prepare(
        "SELECT e.id, e.title, f.name, e.deleted_at, e.updated_at
         FROM entries e LEFT JOIN folders f ON f.id = e.folder_id
         WHERE e.is_deleted = 1
         ORDER BY e.deleted_at DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(TrashItem {
            id: r.get(0)?,
            title: r.get(1)?,
            folder_name: r.get(2)?,
            deleted_at: r.get(3)?,
            updated_at: r.get(4)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn restore(conn: &Connection, id: &str, now: i64) -> Result<bool> {
    let n = conn.execute(
        "UPDATE entries SET is_deleted = 0, deleted_at = NULL, updated_at = ?1
         WHERE id = ?2 AND is_deleted = 1",
        rusqlite::params![now, id],
    )?;
    Ok(n > 0)
}

pub fn permanent_delete(conn: &Connection, id: &str) -> Result<bool> {
    let n = conn.execute("DELETE FROM entries WHERE id = ?1 AND is_deleted = 1", [id])?;
    Ok(n > 0)
}

pub fn empty_trash(conn: &Connection) -> Result<usize> {
    let n = conn.execute("DELETE FROM entries WHERE is_deleted = 1", [])?;
    Ok(n)
}

/// The recycle-bin retention window (metadata `trash_auto_delete_days`,
/// default 0 = disabled).
pub fn trash_auto_delete_days(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT value FROM metadata WHERE key = 'trash_auto_delete_days'",
        [],
        |r| r.get::<_, String>(0),
    )
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or(0)
}

pub fn auto_delete_old(conn: &Connection, days: i64) -> Result<usize> {
    if days <= 0 {
        return Ok(0);
    }
    // A crafted retention value must not overflow into "purge everything".
    let Some(window) = days.checked_mul(86_400) else {
        return Ok(0);
    };
    let cutoff = db::now_unix().saturating_sub(window);
    let n = conn.execute(
        "DELETE FROM entries WHERE is_deleted = 1 AND deleted_at < ?1",
        [cutoff],
    )?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{both_dbs, seed_entry};

    #[test]
    fn list_trash_shows_only_deleted_with_folder_name() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "live", "Live", 0);
            seed_entry(&conn, "dead", "Dead", 0);
            conn.execute("UPDATE entries SET is_deleted = 1, deleted_at = 100 WHERE id = 'dead'", []).unwrap();

            let items = list_trash(&conn).unwrap();
            assert!(items.iter().any(|i| i.id == "dead"), "[{label}] deleted entry present");
            assert!(items.iter().all(|i| i.id != "live"), "[{label}] live entry absent");
            let dead = items.iter().find(|i| i.id == "dead").unwrap();
            assert_eq!(dead.folder_name.as_deref(), Some("Root"), "[{label}] folder name joined (root='Root')");
        }
    }

    #[test]
    fn auto_delete_respects_days_and_cutoff() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_entry(&conn, "old", "Old", 0);
            seed_entry(&conn, "fresh", "Fresh", 0);
            conn.execute("UPDATE entries SET is_deleted=1, deleted_at=?1 WHERE id='old'", [now - 40 * 86400]).unwrap();
            conn.execute("UPDATE entries SET is_deleted=1, deleted_at=?1 WHERE id='fresh'", [now - 1 * 86400]).unwrap();

            assert_eq!(auto_delete_old(&conn, 0).unwrap(), 0, "[{label}] days=0 disables");
            let removed = auto_delete_old(&conn, 30).unwrap();
            assert_eq!(removed, 1, "[{label}] only the 40-day-old entry purged");
            let gone: i64 = conn.query_row("SELECT COUNT(*) FROM entries WHERE id='old'", [], |r| r.get(0)).unwrap();
            let kept: i64 = conn.query_row("SELECT COUNT(*) FROM entries WHERE id='fresh'", [], |r| r.get(0)).unwrap();
            assert_eq!(gone, 0, "[{label}] old purged");
            assert_eq!(kept, 1, "[{label}] fresh kept");
        }
    }

    #[test]
    fn auto_delete_with_overflowing_days_purges_nothing() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "ovf", "Ovf", 0);
            conn.execute("UPDATE entries SET is_deleted=1, deleted_at=100 WHERE id='ovf'", []).unwrap();
            for days in [i64::MAX, i64::MAX / 86_400 + 1] {
                assert_eq!(auto_delete_old(&conn, days).unwrap(), 0, "[{label}] days={days} purges nothing");
            }
            let kept: i64 = conn.query_row("SELECT COUNT(*) FROM entries WHERE id='ovf'", [], |r| r.get(0)).unwrap();
            assert_eq!(kept, 1, "[{label}] trashed entry kept");
        }
    }

    #[test]
    fn auto_delete_days_defaults_to_zero_without_metadata_row() {
        for (label, conn) in both_dbs() {
            conn.execute("DELETE FROM metadata WHERE key = 'trash_auto_delete_days'", []).unwrap();
            assert_eq!(trash_auto_delete_days(&conn), 0, "[{label}] defaults to 0 without a metadata row");
        }
    }

    #[test]
    fn restore_permanent_and_empty() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_entry(&conn, "d1", "D1", 0);
            conn.execute("INSERT INTO entry_fields (id, entry_id, name, value, is_protected, field_type, sort_order)
                          VALUES ('d1f','d1','Username','u',0,'text',0)", []).unwrap();
            conn.execute("UPDATE entries SET is_deleted=1, deleted_at=100 WHERE id='d1'", []).unwrap();

            assert!(restore(&conn, "d1", now).unwrap(), "[{label}] restore returns true");
            let live: i64 = conn.query_row("SELECT is_deleted FROM entries WHERE id='d1'", [], |r| r.get(0)).unwrap();
            assert_eq!(live, 0, "[{label}] restored");

            conn.execute("UPDATE entries SET is_deleted=1, deleted_at=100 WHERE id='d1'", []).unwrap();
            assert!(permanent_delete(&conn, "d1").unwrap(), "[{label}] permanent delete returns true");
            let fields: i64 = conn.query_row("SELECT COUNT(*) FROM entry_fields WHERE entry_id='d1'", [], |r| r.get(0)).unwrap();
            assert_eq!(fields, 0, "[{label}] FK cascade removed fields");
            assert!(!permanent_delete(&conn, "d1").unwrap(), "[{label}] second permanent delete is a no-op");

            seed_entry(&conn, "d2", "D2", 0);
            conn.execute("UPDATE entries SET is_deleted=1, deleted_at=100 WHERE id='d2'", []).unwrap();
            assert_eq!(empty_trash(&conn).unwrap(), 1, "[{label}] empty removed the one trashed entry");
        }
    }
}

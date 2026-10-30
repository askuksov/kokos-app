//! In-vault audit log: an append-only journal of security events
//! (unlock, lock, failed attempts, credential rotation, ...) capped at the
//! 500 newest rows. `detail` is a human-readable label ONLY -- never a field
//! value, password, or key material; the secret boundary is enforced by the
//! `append` signature (`&str` / `Option<&str>`), not by any runtime check.

use rusqlite::Connection;

use crate::error::Result;

/// Maximum rows kept; `append` prunes older rows past this cap.
const MAX_AUDIT_ROWS: i64 = 500;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub event: String,
    pub detail: Option<String>,
    pub created_at: i64,
}

/// Records one security event, then prunes anything past the newest 500.
/// `detail` is a human action label (e.g. "N failed attempts") -- NEVER a
/// field value, password, or key material (see module doc).
pub fn append(conn: &Connection, event: &str, detail: Option<&str>) -> Result<()> {
    let now = crate::db::now_unix();
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT INTO audit_log (event, detail, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![event, detail, now],
    )?;
    tx.execute(
        "DELETE FROM audit_log WHERE id NOT IN
            (SELECT id FROM audit_log ORDER BY created_at DESC, id DESC LIMIT ?1)",
        [MAX_AUDIT_ROWS],
    )?;
    tx.commit()?;
    Ok(())
}

/// Newest-first, capped at `limit` rows. Same `created_at DESC, id DESC`
/// tiebreak as the prune in `append`, for a stable, deterministic order.
pub fn list(conn: &Connection, limit: u32) -> Result<Vec<AuditEntry>> {
    let mut stmt = conn.prepare(
        "SELECT event, detail, created_at FROM audit_log ORDER BY created_at DESC, id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |r| {
        Ok(AuditEntry {
            event: r.get(0)?,
            detail: r.get(1)?,
            created_at: r.get(2)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Empties the log (Settings "clear audit log").
pub fn clear(conn: &Connection) -> Result<()> {
    conn.execute("DELETE FROM audit_log", [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_then_list() {
        let conn = crate::db::create_fresh().unwrap();
        append(&conn, "unlock", None).unwrap();
        append(&conn, "lock", Some("manual")).unwrap();
        let rows = list(&conn, 10).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].event, "lock");
    }

    #[test]
    fn prune_keeps_500_newest() {
        let conn = crate::db::create_fresh().unwrap();
        for i in 0..510 {
            append(&conn, "unlock", Some(&i.to_string())).unwrap();
        }
        assert_eq!(list(&conn, 1000).unwrap().len(), 500);
    }

    #[test]
    fn clear_empties() {
        let conn = crate::db::create_fresh().unwrap();
        append(&conn, "lock", None).unwrap();
        clear(&conn).unwrap();
        assert!(list(&conn, 10).unwrap().is_empty());
    }
}

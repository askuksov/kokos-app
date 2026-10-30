//! Typed relations BETWEEN entries. ONE directional row is stored
//! per relation; `list_for_entry` surfaces it from BOTH endpoints, inverse-
//! labelling incoming rows (`parent` <-> `child`; every other type, including
//! `related`, is its own inverse). `A --parent--> B` is a single row: A's
//! panel reads "parent: B", B's panel reads "child: A" -- no second row.

use rusqlite::Connection;

use crate::error::{Result, VaultError};

pub const RELATION_TYPES: [&str; 5] = ["related", "parent", "child", "duplicate", "see-also"];

#[derive(Debug, Clone)]
pub struct RelationView {
    pub relation_id: String,
    pub other_id: String,
    pub other_title: String,
    pub other_is_deleted: bool,
    pub relation_type: String,
}

/// How a relation type reads from the OTHER side: `parent` <-> `child`;
/// every other type (including "related") is its own inverse.
fn inverse(t: &str) -> &str {
    match t {
        "parent" => "child",
        "child" => "parent",
        other => other,
    }
}

/// Maps only a UNIQUE violation -- the single (source_id, target_id,
/// relation_type) constraint -- to `DuplicateRelation`. Every other failure,
/// including a FOREIGN KEY violation for a missing entry id, passes through.
fn map_unique(e: rusqlite::Error) -> VaultError {
    if let rusqlite::Error::SqliteFailure(f, _) = &e {
        if f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE {
            return VaultError::DuplicateRelation;
        }
    }
    e.into()
}

pub fn add(conn: &Connection, source_id: &str, target_id: &str, relation_type: &str, now: i64) -> Result<()> {
    if !RELATION_TYPES.contains(&relation_type) {
        return Err(VaultError::InvalidRelationType);
    }
    if source_id == target_id {
        return Err(VaultError::SelfRelation);
    }
    // The inverse row already reads as this relation from both panels.
    let inverse_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM entry_relations
                        WHERE source_id = ?1 AND target_id = ?2 AND relation_type = ?3)",
        rusqlite::params![target_id, source_id, inverse(relation_type)],
        |r| r.get(0),
    )?;
    if inverse_exists {
        return Err(VaultError::DuplicateRelation);
    }
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO entry_relations (id, source_id, target_id, relation_type, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![id, source_id, target_id, relation_type, now],
    )
    .map_err(map_unique)?;
    Ok(())
}

pub fn list_for_entry(conn: &Connection, entry_id: &str) -> Result<Vec<RelationView>> {
    let mut out = Vec::new();

    let mut stmt = conn.prepare(
        "SELECT r.id, e.id, e.title, e.is_deleted, r.relation_type
         FROM entry_relations r JOIN entries e ON e.id = r.target_id
         WHERE r.source_id = ?1 ORDER BY e.title COLLATE NOCASE ASC, r.id ASC",
    )?;
    let rows = stmt.query_map([entry_id], |r| {
        Ok(RelationView {
            relation_id: r.get(0)?,
            other_id: r.get(1)?,
            other_title: r.get(2)?,
            other_is_deleted: r.get::<_, i64>(3)? != 0,
            relation_type: r.get(4)?,
        })
    })?;
    for row in rows {
        out.push(row?);
    }

    let mut stmt = conn.prepare(
        "SELECT r.id, e.id, e.title, e.is_deleted, r.relation_type
         FROM entry_relations r JOIN entries e ON e.id = r.source_id
         WHERE r.target_id = ?1 ORDER BY e.title COLLATE NOCASE ASC, r.id ASC",
    )?;
    let rows = stmt.query_map([entry_id], |r| {
        let raw_type: String = r.get(4)?;
        Ok(RelationView {
            relation_id: r.get(0)?,
            other_id: r.get(1)?,
            other_title: r.get(2)?,
            other_is_deleted: r.get::<_, i64>(3)? != 0,
            relation_type: inverse(&raw_type).to_string(),
        })
    })?;
    for row in rows {
        out.push(row?);
    }

    Ok(out)
}

pub fn delete(conn: &Connection, relation_id: &str) -> Result<()> {
    let n = conn.execute("DELETE FROM entry_relations WHERE id = ?1", [relation_id])?;
    if n == 0 {
        return Err(VaultError::RelationNotFound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{both_dbs, seed_entry};

    #[test]
    fn add_rejects_self_bad_type_and_duplicates() {
        for (label, conn) in both_dbs() {
            crate::testutil::seed_entry(&conn, "r-a", "A", 0);
            crate::testutil::seed_entry(&conn, "r-b", "B", 0);
            assert!(matches!(add(&conn, "r-a", "r-a", "related", 1), Err(VaultError::SelfRelation)), "[{label}] self");
            assert!(matches!(add(&conn, "r-a", "r-b", "banana", 1), Err(VaultError::InvalidRelationType)), "[{label}] bad type");
            add(&conn, "r-a", "r-b", "parent", 1).unwrap();
            assert!(matches!(add(&conn, "r-a", "r-b", "parent", 1), Err(VaultError::DuplicateRelation)), "[{label}] dup");
        }
    }

    #[test]
    fn add_rejects_inverse_of_existing_relation() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "r-i1", "I1", 0);
            seed_entry(&conn, "r-i2", "I2", 0);
            add(&conn, "r-i1", "r-i2", "parent", 1).unwrap();
            assert!(matches!(add(&conn, "r-i2", "r-i1", "child", 1), Err(VaultError::DuplicateRelation)),
                "[{label}] B->A child mirrors A->B parent");
            add(&conn, "r-i1", "r-i2", "related", 1).unwrap();
            assert!(matches!(add(&conn, "r-i2", "r-i1", "related", 1), Err(VaultError::DuplicateRelation)),
                "[{label}] B->A related mirrors A->B related");
            add(&conn, "r-i2", "r-i1", "parent", 1).unwrap();
            assert_eq!(list_for_entry(&conn, "r-i1").unwrap().len(), 3, "[{label}] no doubled rows in the panel");
        }
    }

    #[test]
    fn add_missing_entry_is_not_reported_as_duplicate() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "r-fk", "FK", 0);
            let res = add(&conn, "r-fk", "ghost", "related", 1);
            assert!(res.is_err(), "[{label}] FK violation still fails");
            assert!(!matches!(res, Err(VaultError::DuplicateRelation)), "[{label}] FK violation is not a duplicate");
        }
    }

    #[test]
    fn list_shows_both_directions_with_inverse_labels() {
        for (label, conn) in both_dbs() {
            crate::testutil::seed_entry(&conn, "r-p", "Parent", 0);
            crate::testutil::seed_entry(&conn, "r-c", "Child", 0);
            add(&conn, "r-p", "r-c", "parent", 1).unwrap();
            let from_p = list_for_entry(&conn, "r-p").unwrap();
            assert_eq!(from_p.len(), 1, "[{label}] P sees 1");
            assert_eq!((from_p[0].other_id.as_str(), from_p[0].relation_type.as_str()), ("r-c", "parent"), "[{label}] P: parent of C");
            let from_c = list_for_entry(&conn, "r-c").unwrap();
            assert_eq!((from_c[0].other_id.as_str(), from_c[0].relation_type.as_str()), ("r-p", "child"), "[{label}] C: child of P (inverse)");
            conn.execute("UPDATE entries SET is_deleted = 1 WHERE id = 'r-c'", []).unwrap();
            let from_p2 = list_for_entry(&conn, "r-p").unwrap();
            assert!(from_p2[0].other_is_deleted, "[{label}] trashed target flagged, not hidden");
        }
    }

    #[test]
    fn delete_removes_relation_and_missing_returns_not_found() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "r-d1", "D1", 0);
            seed_entry(&conn, "r-d2", "D2", 0);
            add(&conn, "r-d1", "r-d2", "related", 1).unwrap();
            let relation_id = list_for_entry(&conn, "r-d1").unwrap()[0].relation_id.clone();

            delete(&conn, &relation_id).unwrap();

            assert!(list_for_entry(&conn, "r-d1").unwrap().is_empty(), "[{label}] gone from source's list");
            assert!(list_for_entry(&conn, "r-d2").unwrap().is_empty(), "[{label}] gone from target's list");
            assert!(matches!(delete(&conn, "ghost"), Err(VaultError::RelationNotFound)), "[{label}] missing id -> RelationNotFound");
        }
    }

    #[test]
    fn self_inverse_type_reads_the_same_from_both_ends() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "r-x", "X", 0);
            seed_entry(&conn, "r-y", "Y", 0);
            add(&conn, "r-x", "r-y", "related", 1).unwrap();

            let from_x = list_for_entry(&conn, "r-x").unwrap();
            let from_y = list_for_entry(&conn, "r-y").unwrap();
            assert_eq!((from_x[0].other_id.as_str(), from_x[0].relation_type.as_str()), ("r-y", "related"), "[{label}] X: related to Y");
            assert_eq!((from_y[0].other_id.as_str(), from_y[0].relation_type.as_str()), ("r-x", "related"), "[{label}] Y: related to X (self-inverse)");
        }
    }
}

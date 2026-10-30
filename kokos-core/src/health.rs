//! Password-health scan. Reuses the whole-vault iteration of
//! `portable::export` but emits ONLY derived signals -- weak-password flags
//! and reuse groups keyed by SHA-1 digest. Plaintext and the digest bytes
//! never leave this module: like `strength::estimate`, the password is read
//! from the unlocked in-memory DB, scored/hashed here, and dropped.

use std::collections::HashMap;

use rusqlite::Connection;
use sha1::{Digest, Sha1};
use zeroize::Zeroize;

use crate::error::Result;

/// A secret field is "weak" when its 0-4 strength is <= this bound (Weak/Fair).
const WEAK_MAX: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeakField {
    pub entry_id: String,
    pub title: String,
    pub field_name: String,
    pub strength: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthEntryRef {
    pub entry_id: String,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusedGroup {
    pub count: u32,
    pub entries: Vec<HealthEntryRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HealthReport {
    pub weak: Vec<WeakField>,
    pub reused: Vec<ReusedGroup>,
}

pub fn scan(conn: &Connection) -> Result<HealthReport> {
    let mut stmt = conn.prepare(
        "SELECT e.id, e.title, ef.name, ef.value
         FROM entries e
         JOIN entry_fields ef ON ef.entry_id = e.id
         WHERE e.is_deleted = 0
           AND ef.field_type = 'secret'
           AND (ef.template_id IS NULL OR ef.template_id NOT IN ('tpl_pin', 'tpl_security_answer'))
         ORDER BY e.title COLLATE NOCASE ASC, ef.sort_order ASC",
    )?;

    let mut weak: Vec<WeakField> = Vec::new();
    let mut groups: HashMap<[u8; 20], Vec<HealthEntryRef>> = HashMap::new();

    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
        ))
    })?;

    for row in rows {
        let (entry_id, title, field_name, value) = row?;
        let Some(mut value) = value.filter(|s| !s.is_empty()) else {
            continue;
        };

        let score = crate::strength::estimate(&value);
        if score <= WEAK_MAX {
            weak.push(WeakField {
                entry_id: entry_id.clone(),
                title: title.clone(),
                field_name,
                strength: score,
            });
        }

        let mut hasher = Sha1::new();
        hasher.update(value.as_bytes());
        let digest: [u8; 20] = hasher.finalize().into();
        value.zeroize();

        let bucket = groups.entry(digest).or_default();
        if !bucket.iter().any(|e| e.entry_id == entry_id) {
            bucket.push(HealthEntryRef { entry_id, title });
        }
    }

    let mut reused: Vec<([u8; 20], ReusedGroup)> = groups
        .into_iter()
        .filter(|(_, entries)| entries.len() >= 2)
        .map(|(digest, entries)| {
            (
                digest,
                ReusedGroup {
                    count: entries.len() as u32,
                    entries,
                },
            )
        })
        .collect();
    reused.sort_by(|(digest_a, a), (digest_b, b)| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.entries[0].title.cmp(&b.entries[0].title))
            .then_with(|| a.entries[0].entry_id.cmp(&b.entries[0].entry_id))
            .then_with(|| digest_a.cmp(digest_b))
    });
    let reused: Vec<ReusedGroup> = reused.into_iter().map(|(_, group)| group).collect();

    Ok(HealthReport { weak, reused })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::testutil::seed_entry;

    /// Seed one secret field (`is_protected = 1`, `field_type = 'secret'`).
    fn seed_secret(
        conn: &Connection,
        fid: &str,
        entry_id: &str,
        name: &str,
        tpl: Option<&str>,
        value: &str,
    ) {
        conn.execute(
            "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, 'secret')",
            rusqlite::params![fid, entry_id, tpl, name, value],
        )
        .unwrap();
    }

    #[test]
    fn weak_includes_scores_0_and_1_excludes_2() {
        let conn = db::create_fresh().unwrap();
        seed_entry(&conn, "e0", "Score0", 0);
        seed_secret(&conn, "f0", "e0", "Password", Some("tpl_password"), "abc");
        seed_entry(&conn, "e1", "Score1", 0);
        seed_secret(&conn, "f1", "e1", "Password", Some("tpl_password"), "aB");
        seed_entry(&conn, "e2", "Score2", 0);
        seed_secret(
            &conn,
            "f2",
            "e2",
            "Password",
            Some("tpl_password"),
            "password123",
        );

        let r = scan(&conn).unwrap();
        let ids: Vec<&str> = r.weak.iter().map(|w| w.entry_id.as_str()).collect();
        assert!(ids.contains(&"e0"), "score 0 is weak");
        assert!(ids.contains(&"e1"), "score 1 is weak");
        assert!(!ids.contains(&"e2"), "score 2 is NOT weak");
    }

    #[test]
    fn reused_groups_identical_value_across_entries() {
        let conn = db::create_fresh().unwrap();
        seed_entry(&conn, "a", "Alpha", 0);
        seed_secret(
            &conn,
            "fa",
            "a",
            "Password",
            Some("tpl_password"),
            "Shared#Pw9x",
        );
        seed_entry(&conn, "b", "Bravo", 0);
        seed_secret(
            &conn,
            "fb",
            "b",
            "Password",
            Some("tpl_password"),
            "Shared#Pw9x",
        );
        seed_entry(&conn, "c", "Charlie", 0);
        seed_secret(
            &conn,
            "fc",
            "c",
            "Password",
            Some("tpl_password"),
            "Different#Pw1",
        );

        let r = scan(&conn).unwrap();
        assert_eq!(r.reused.len(), 1, "one reused group");
        assert_eq!(r.reused[0].count, 2);
        let mut ids: Vec<&str> = r.reused[0]
            .entries
            .iter()
            .map(|e| e.entry_id.as_str())
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[test]
    fn reused_groups_tie_break_by_digest_for_determinism() {
        let conn = db::create_fresh().unwrap();
        seed_entry(&conn, "e1", "AAA", 0);
        conn.execute(
            "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type, sort_order)
             VALUES ('f1a', 'e1', 'tpl_password', 'Password', 'SharedValue1', 1, 'secret', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type, sort_order)
             VALUES ('f1b', 'e1', 'tpl_password', 'Old password', 'SharedValue2', 1, 'secret', 1)",
            [],
        )
        .unwrap();
        seed_entry(&conn, "e2", "ZZZ", 0);
        seed_secret(
            &conn,
            "f2",
            "e2",
            "Password",
            Some("tpl_password"),
            "SharedValue1",
        );
        seed_entry(&conn, "e3", "ZZZ2", 0);
        seed_secret(
            &conn,
            "f3",
            "e3",
            "Password",
            Some("tpl_password"),
            "SharedValue2",
        );

        let r1 = scan(&conn).unwrap();
        let r2 = scan(&conn).unwrap();
        assert_eq!(r1.reused.len(), 2, "two distinct reuse groups");
        assert_eq!(
            r1.reused, r2.reused,
            "order must be deterministic across repeated scans, not HashMap iteration order"
        );
    }

    #[test]
    fn reused_ignores_same_password_within_one_entry() {
        let conn = db::create_fresh().unwrap();
        seed_entry(&conn, "solo", "Solo", 0);
        seed_secret(
            &conn,
            "s1",
            "solo",
            "Password",
            Some("tpl_password"),
            "Same#Value1",
        );
        seed_secret(&conn, "s2", "solo", "Old password", None, "Same#Value1");
        let r = scan(&conn).unwrap();
        assert!(r.reused.is_empty(), "one entry cannot reuse against itself");
    }

    #[test]
    fn trash_is_excluded() {
        let conn = db::create_fresh().unwrap();
        seed_entry(&conn, "live", "Live", 0);
        seed_secret(&conn, "fl", "live", "Password", Some("tpl_password"), "abc");
        seed_entry(&conn, "dead", "Dead", 0);
        seed_secret(&conn, "fd", "dead", "Password", Some("tpl_password"), "abc");
        conn.execute("UPDATE entries SET is_deleted = 1 WHERE id = 'dead'", [])
            .unwrap();

        let r = scan(&conn).unwrap();
        assert_eq!(r.weak.len(), 1, "only the live weak field");
        assert_eq!(r.weak[0].entry_id, "live");
        assert!(
            r.reused.is_empty(),
            "the trashed twin cannot form a reuse pair"
        );
    }

    #[test]
    fn pin_and_security_answer_are_out_of_scope() {
        let conn = db::create_fresh().unwrap();
        seed_entry(&conn, "e", "Bank", 0);
        seed_secret(&conn, "pin", "e", "PIN", Some("tpl_pin"), "12");
        seed_secret(
            &conn,
            "ans",
            "e",
            "Answer",
            Some("tpl_security_answer"),
            "no",
        );
        seed_secret(&conn, "pw", "e", "Password", Some("tpl_password"), "abc");

        let r = scan(&conn).unwrap();
        assert_eq!(r.weak.len(), 1, "only the password field is in scope");
        assert_eq!(r.weak[0].field_name, "Password");
    }

    #[test]
    fn empty_secret_and_non_secret_are_ignored() {
        let conn = db::create_fresh().unwrap();
        seed_entry(&conn, "e", "Site", 0);
        seed_secret(&conn, "empty", "e", "Password", Some("tpl_password"), "");
        conn.execute(
            "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type)
             VALUES ('note', 'e', NULL, 'Note', 'abc', 0, 'text')",
            [],
        )
        .unwrap();
        let r = scan(&conn).unwrap();
        assert!(
            r.weak.is_empty(),
            "empty secret + non-secret text are both ignored"
        );
    }

    #[test]
    fn custom_secret_field_with_null_template_is_in_scope() {
        let conn = db::create_fresh().unwrap();
        seed_entry(&conn, "e", "Site", 0);
        seed_secret(&conn, "cf", "e", "API key", None, "abc");
        let r = scan(&conn).unwrap();
        assert_eq!(
            r.weak.len(),
            1,
            "NULL-template secret is included (IS NULL branch)"
        );
    }
}

//! Persistent browser-extension read grants.
//!
//! A row here means: this browser-extension origin has already been granted
//! read access (`get_secret`/`get_totp`/autofill-style lookups -- never
//! `save_login`/`update_login`, which always confirm) for this site, and the
//! grant survives an app restart. This is the persistent tier; `nmh::confirm::Grants`
//! (`src-tauri/src/nmh/grants.rs`) remains the in-memory "once per site
//! per session" tier -- the two are independent state, composed by the caller.
//!
//! NORMALISATION CONTRACT: exactly like `nmh::confirm::Grants` (see its doc
//! comment), this module performs NO normalisation of either key half.
//! `domain` must already be an eTLD+1 reduced by the caller (e.g. via
//! `kokos_core::url_match::etld_plus_one`) before it reaches any function
//! here; `origin` is compared exactly as the handshake authenticated it --
//! raw `TEXT` equality, no case-folding, no trailing-dot stripping. A caller
//! that reaches this module directly without first reducing the domain will
//! silently create two unrelated grants for what a user would consider the
//! same site.
//!
//! There is deliberately no `clear()`: the revocation UI is
//! grouped by extension, so "Forget all" for one extension is
//! `delete_by_origin`, which also serves the whitelist-edit cascade.

use rusqlite::Connection;

use crate::error::Result;

/// One persistent grant: `origin` has been allowed to read secrets for
/// `domain` without prompting, since `created_at`. `last_used_at` is `None`
/// until the first `touch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub origin: String,
    pub domain: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

/// All grants, ordered by `(origin, domain)` so a revocation UI grouped by
/// extension gets its rows pre-sorted.
pub fn list(conn: &Connection) -> Result<Vec<Grant>> {
    let mut stmt = conn.prepare(
        "SELECT origin, domain, created_at, last_used_at FROM nmh_grants ORDER BY origin, domain",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Grant {
            origin: r.get(0)?,
            domain: r.get(1)?,
            created_at: r.get(2)?,
            last_used_at: r.get(3)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Whether `(origin, domain)` has a standing grant.
pub fn is_granted(conn: &Connection, origin: &str, domain: &str) -> Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM nmh_grants WHERE origin = ?1 AND domain = ?2",
        rusqlite::params![origin, domain],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// Records a grant for `(origin, domain)` if one does not already exist. An
/// existing row is left completely untouched (`created_at` included) --
/// re-granting an already-granted site is a no-op, not a refresh.
pub fn upsert(conn: &Connection, origin: &str, domain: &str, now: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO nmh_grants (origin, domain, created_at, last_used_at) VALUES (?1, ?2, ?3, NULL)
         ON CONFLICT(origin, domain) DO NOTHING",
        rusqlite::params![origin, domain, now],
    )?;
    Ok(())
}

/// Stamps `last_used_at` on an existing grant. A missing `(origin, domain)`
/// is a silent no-op (0 rows affected) -- callers that need to know whether
/// the grant exists should check with `is_granted` first.
pub fn touch(conn: &Connection, origin: &str, domain: &str, now: i64) -> Result<()> {
    conn.execute(
        "UPDATE nmh_grants SET last_used_at = ?1 WHERE origin = ?2 AND domain = ?3",
        rusqlite::params![now, origin, domain],
    )?;
    Ok(())
}

/// Removes exactly one grant. Returns whether a row was actually removed.
pub fn delete(conn: &Connection, origin: &str, domain: &str) -> Result<bool> {
    let n = conn.execute(
        "DELETE FROM nmh_grants WHERE origin = ?1 AND domain = ?2",
        rusqlite::params![origin, domain],
    )?;
    Ok(n > 0)
}

/// Removes every grant for `origin` ("Forget all" for one extension, and the
/// whitelist-edit cascade). Returns the number of rows removed.
pub fn delete_by_origin(conn: &Connection, origin: &str) -> Result<usize> {
    Ok(conn.execute("DELETE FROM nmh_grants WHERE origin = ?1", [origin])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::create_fresh;

    #[test]
    fn upsert_then_is_granted_and_listed() {
        let conn = create_fresh().unwrap();
        let now = 1_700_000_000;
        upsert(&conn, "chrome-extension://aaa/", "example.com", now).unwrap();

        assert!(is_granted(&conn, "chrome-extension://aaa/", "example.com").unwrap());

        let grants = list(&conn).unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].origin, "chrome-extension://aaa/");
        assert_eq!(grants[0].domain, "example.com");
        assert_eq!(grants[0].created_at, now);
        assert_eq!(grants[0].last_used_at, None);
    }

    /// Negative control: without this, the positive check above proves
    /// nothing.
    #[test]
    fn is_granted_false_for_same_domain_different_origin() {
        let conn = create_fresh().unwrap();
        upsert(&conn, "chrome-extension://aaa/", "example.com", 100).unwrap();

        assert!(
            is_granted(&conn, "chrome-extension://aaa/", "example.com").unwrap(),
            "positive control: the granting origin itself is covered"
        );
        assert!(
            !is_granted(&conn, "chrome-extension://bbb/", "example.com").unwrap(),
            "a different origin on the same domain must not inherit the grant"
        );
    }

    #[test]
    fn is_granted_false_for_same_origin_different_domain() {
        let conn = create_fresh().unwrap();
        upsert(&conn, "chrome-extension://aaa/", "example.com", 100).unwrap();

        assert!(
            is_granted(&conn, "chrome-extension://aaa/", "example.com").unwrap(),
            "positive control: the granted domain itself is covered"
        );
        assert!(
            !is_granted(&conn, "chrome-extension://aaa/", "other.com").unwrap(),
            "a different domain for the same origin must not inherit the grant"
        );
    }

    #[test]
    fn second_upsert_for_same_pair_keeps_original_created_at_and_does_not_duplicate() {
        let conn = create_fresh().unwrap();
        upsert(&conn, "chrome-extension://aaa/", "example.com", 100).unwrap();
        upsert(&conn, "chrome-extension://aaa/", "example.com", 200).unwrap();

        let grants = list(&conn).unwrap();
        assert_eq!(
            grants.len(),
            1,
            "second upsert for the same pair must not duplicate the row"
        );
        assert_eq!(
            grants[0].created_at, 100,
            "ON CONFLICT DO NOTHING must not overwrite created_at"
        );
    }

    #[test]
    fn touch_sets_last_used_at_and_leaves_created_at() {
        let conn = create_fresh().unwrap();
        upsert(&conn, "chrome-extension://aaa/", "example.com", 100).unwrap();
        touch(&conn, "chrome-extension://aaa/", "example.com", 200).unwrap();

        let grants = list(&conn).unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(
            grants[0].created_at, 100,
            "touch must leave created_at untouched"
        );
        assert_eq!(
            grants[0].last_used_at,
            Some(200),
            "touch must set last_used_at"
        );
    }

    #[test]
    fn delete_returns_true_once_then_false() {
        let conn = create_fresh().unwrap();
        upsert(&conn, "chrome-extension://aaa/", "example.com", 100).unwrap();

        assert!(
            delete(&conn, "chrome-extension://aaa/", "example.com").unwrap(),
            "first delete removes the existing row"
        );
        assert!(
            !delete(&conn, "chrome-extension://aaa/", "example.com").unwrap(),
            "second delete of the same pair is a no-op"
        );
        assert!(
            list(&conn).unwrap().is_empty(),
            "list is empty after delete"
        );
    }

    #[test]
    fn delete_by_origin_removes_only_that_origins_rows() {
        let conn = create_fresh().unwrap();
        upsert(&conn, "chrome-extension://aaa/", "example.com", 100).unwrap();
        upsert(&conn, "chrome-extension://aaa/", "other.com", 100).unwrap();
        upsert(&conn, "chrome-extension://bbb/", "example.com", 100).unwrap();

        let removed = delete_by_origin(&conn, "chrome-extension://aaa/").unwrap();
        assert_eq!(
            removed, 2,
            "delete_by_origin returns the count of rows removed"
        );

        let remaining = list(&conn).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(
            remaining[0].origin, "chrome-extension://bbb/",
            "a different origin's rows must survive"
        );
        assert_eq!(remaining[0].domain, "example.com");
    }

    #[test]
    fn list_is_ordered_by_origin_then_domain() {
        let conn = create_fresh().unwrap();
        upsert(&conn, "chrome-extension://bbb/", "example.com", 100).unwrap();
        upsert(&conn, "chrome-extension://aaa/", "zzz.com", 100).unwrap();
        upsert(&conn, "chrome-extension://aaa/", "aaa.com", 100).unwrap();

        let grants = list(&conn).unwrap();
        let order: Vec<(String, String)> = grants
            .iter()
            .map(|g| (g.origin.clone(), g.domain.clone()))
            .collect();
        assert_eq!(
            order,
            vec![
                ("chrome-extension://aaa/".to_string(), "aaa.com".to_string()),
                ("chrome-extension://aaa/".to_string(), "zzz.com".to_string()),
                (
                    "chrome-extension://bbb/".to_string(),
                    "example.com".to_string()
                ),
            ],
            "list must be ordered by (origin, domain)"
        );
    }
}

//! `get_logins` lookup: entries whose `url`-typed field values sit
//! on the same site as the requested URL. Metadata only — this module never
//! reads a protected value. The `username` sub-select enforces that in SQL
//! with `AND ef2.is_protected = 0`, matching the guard in
//! `entries::SUMMARY_COLS`. `get_logins` hands its answer to a browser
//! extension with no confirmation prompt and no audit row, so a user who
//! marks their username field protected must not have it disclosed in
//! cleartext here (nor in the in-app list, which applies the same guard).

use rusqlite::Connection;

use crate::error::Result;
use crate::url_match;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginMatch {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub has_totp: bool,
    /// True when one of the entry's URLs has exactly the requested host —
    /// used for ranking, so `accounts.example.com` beats `example.com`.
    pub exact_host: bool,
}

/// Only unprotected `url` fields match (`ef.is_protected = 0`): a protected
/// URL must not anchor an extension request, and the ids returned here become
/// `ConnScope.candidate_ids`, which `handlers::anchored` trusts for a later
/// `get_secret`/`get_totp` that omits `url`. `entries::get` already withholds
/// protected values; this keeps the lookup consistent with it.
///
/// Columns mostly mirror `entries::SUMMARY_COLS`'s username/has_totp
/// sub-selects so the browser sees the same derived facts the app's list
/// does, including the `is_protected = 0` guard on BOTH identity branches
/// below.
///
/// An entry whose login is an email address carries no `tpl_username` at all
/// — KeePass import writes emails to `tpl_email`, and the editor's own Email
/// field type is `email`. Keying identity on `tpl_username` alone left such
/// entries looking anonymous: the extension got `username: null` and filled
/// the password only. The fallback mirrors the `has_totp` sub-select right
/// below it, which has always accepted either the template or the field type.
const SQL: &str = "SELECT e.id, e.title,
    COALESCE(
      (SELECT ef2.value FROM entry_fields ef2
         WHERE ef2.entry_id = e.id AND ef2.template_id = 'tpl_username'
           AND ef2.is_protected = 0 LIMIT 1),
      (SELECT ef2.value FROM entry_fields ef2
         WHERE ef2.entry_id = e.id
           AND (ef2.template_id = 'tpl_email' OR ef2.field_type = 'email')
           AND ef2.is_protected = 0 LIMIT 1)) AS username,
    EXISTS(SELECT 1 FROM entry_fields ef3
       WHERE ef3.entry_id = e.id
         AND (ef3.template_id = 'tpl_totp' OR ef3.field_type = 'otp')) AS has_totp,
    ef.value AS url_value
  FROM entries e
  JOIN entry_fields ef ON ef.entry_id = e.id
  WHERE e.is_deleted = 0 AND ef.field_type = 'url' AND ef.is_protected = 0
    AND ef.value IS NOT NULL AND ef.value != ''
  ORDER BY e.title COLLATE NOCASE ASC";

pub fn for_url(conn: &Connection, url: &str, limit: usize) -> Result<Vec<LoginMatch>> {
    let Some(req_host) = url_match::host_of(url) else {
        return Ok(Vec::new());
    };

    let mut stmt = conn.prepare(SQL)?;
    let mut rows = stmt.query([])?;
    let mut out: Vec<LoginMatch> = Vec::new();
    while let Some(r) = rows.next()? {
        let stored: String = r.get(4)?;
        if !url_match::same_site(&stored, &req_host) {
            continue;
        }
        let exact = url_match::host_of(&stored)
            .map(|h| h == req_host)
            .unwrap_or(false);
        let id: String = r.get(0)?;
        if let Some(existing) = out.iter_mut().find(|m| m.id == id) {
            existing.exact_host |= exact;
            continue;
        }
        out.push(LoginMatch {
            id,
            title: r.get(1)?,
            username: r.get(2)?,
            has_totp: r.get::<_, i64>(3)? != 0,
            exact_host: exact,
        });
    }
    out.sort_by_key(|m| !m.exact_host);
    out.truncate(limit);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{both_dbs, seed_entry};

    /// Adds one field row directly: `logins::for_url` only reads, so the
    /// test does not need the full `entries::create` path.
    fn seed_field(
        conn: &rusqlite::Connection,
        id: &str,
        entry: &str,
        name: &str,
        value: &str,
        kind: &str,
        template: Option<&str>,
    ) {
        conn.execute(
            "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type, sort_order)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, 0)",
            rusqlite::params![id, entry, template, name, value, kind],
        )
        .unwrap();
    }

    #[test]
    fn matches_by_etld_plus_one_and_ranks_exact_host_first() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "l-1", "Example root", 0);
            seed_field(
                &conn,
                "f-1",
                "l-1",
                "URL",
                "https://example.com/login",
                "url",
                Some("tpl_url"),
            );
            seed_entry(&conn, "l-2", "Example sub", 0);
            seed_field(
                &conn,
                "f-2",
                "l-2",
                "URL",
                "https://accounts.example.com",
                "url",
                Some("tpl_url"),
            );
            seed_entry(&conn, "l-3", "Other site", 0);
            seed_field(
                &conn,
                "f-3",
                "l-3",
                "URL",
                "https://elsewhere.org",
                "url",
                Some("tpl_url"),
            );

            let hits = for_url(&conn, "https://accounts.example.com/signin", 50).unwrap();
            let ids: Vec<&str> = hits.iter().map(|h| h.id.as_str()).collect();
            assert_eq!(
                ids,
                vec!["l-2", "l-1"],
                "[{label}] exact host first, then same-site"
            );
            assert!(
                hits[0].exact_host,
                "[{label}] accounts.example.com is the exact host"
            );
            assert!(!hits[1].exact_host);
        }
    }

    #[test]
    fn reports_username_and_totp_without_any_secret() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "l-4", "GitHub", 0);
            seed_field(
                &conn,
                "f-4",
                "l-4",
                "URL",
                "https://github.com",
                "url",
                Some("tpl_url"),
            );
            seed_field(
                &conn,
                "f-5",
                "l-4",
                "Username",
                "octocat",
                "text",
                Some("tpl_username"),
            );
            seed_field(
                &conn,
                "f-6",
                "l-4",
                "TOTP",
                "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
                "otp",
                None,
            );

            let hits = for_url(&conn, "https://github.com/login", 50).unwrap();
            assert_eq!(hits.len(), 1, "[{label}]");
            assert_eq!(hits[0].username.as_deref(), Some("octocat"), "[{label}]");
            assert!(hits[0].has_totp, "[{label}]");
        }
    }

    #[test]
    fn skips_trashed_entries_non_url_fields_and_empty_values() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "l-5", "Trashed", 0);
            conn.execute("UPDATE entries SET is_deleted = 1 WHERE id = 'l-5'", [])
                .unwrap();
            seed_field(
                &conn,
                "f-7",
                "l-5",
                "URL",
                "https://example.com",
                "url",
                Some("tpl_url"),
            );
            seed_entry(&conn, "l-6", "Notes only", 0);
            seed_field(
                &conn,
                "f-8",
                "l-6",
                "Note",
                "https://example.com",
                "text",
                None,
            );
            seed_entry(&conn, "l-7", "Empty url", 0);
            seed_field(&conn, "f-9", "l-7", "URL", "", "url", Some("tpl_url"));

            assert!(
                for_url(&conn, "https://example.com", 50)
                    .unwrap()
                    .is_empty(),
                "[{label}]"
            );
        }
    }

    #[test]
    fn one_row_per_entry_even_with_several_matching_urls_and_limit_is_honoured() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "l-8", "Two urls", 0);
            seed_field(
                &conn,
                "f-10",
                "l-8",
                "URL",
                "https://www.example.com",
                "url",
                Some("tpl_url"),
            );
            seed_field(
                &conn,
                "f-11",
                "l-8",
                "URL 2",
                "https://example.com",
                "url",
                None,
            );
            seed_entry(&conn, "l-9", "Another", 0);
            seed_field(
                &conn,
                "f-12",
                "l-9",
                "URL",
                "https://cdn.example.com",
                "url",
                Some("tpl_url"),
            );

            let hits = for_url(&conn, "https://example.com", 50).unwrap();
            assert_eq!(hits.len(), 2, "[{label}] deduped by entry id");
            assert_eq!(
                for_url(&conn, "https://example.com", 1).unwrap().len(),
                1,
                "[{label}] limit applied"
            );
        }
    }

    #[test]
    fn unreadable_request_url_yields_no_matches() {
        for (_label, conn) in both_dbs() {
            seed_entry(&conn, "l-10", "Site", 0);
            seed_field(
                &conn,
                "f-13",
                "l-10",
                "URL",
                "https://example.com",
                "url",
                Some("tpl_url"),
            );
            assert!(for_url(&conn, "about:blank", 50).unwrap().is_empty());
        }
    }

    /// Proves the row-mapping reads the real title column,
    /// not just the id — a column-index slip would otherwise ship silently.
    /// Scoped to the seeded id so pre-existing rows in the migrated fixture
    /// (`testutil::both_dbs()`) cannot make this pass or fail by accident.
    #[test]
    fn returns_the_entrys_real_title_not_just_its_id() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "l-11", "My Unique Readback Title", 0);
            seed_field(
                &conn,
                "f-14",
                "l-11",
                "URL",
                "https://readback-title-check.example",
                "url",
                Some("tpl_url"),
            );

            let hits = for_url(&conn, "https://readback-title-check.example", 50).unwrap();
            let mine: Vec<_> = hits.iter().filter(|h| h.id == "l-11").collect();
            assert_eq!(mine.len(), 1, "[{label}] seeded entry must be found");
            assert_eq!(
                mine[0].title, "My Unique Readback Title",
                "[{label}] title must come from e.title, not e.id"
            );
        }
    }

    /// A field flipped `is_protected` must not leave
    /// through `get_logins` even though it keys on `tpl_username` — this is
    /// the one vault read with no confirmation prompt and no audit row, so
    /// the guard is enforced in SQL, not left to caller discipline. The
    /// match itself must not disappear: only the value is withheld.
    #[test]
    fn protected_username_is_withheld_but_the_entry_still_matches() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "l-13", "Protected username site", 0);
            seed_field(
                &conn,
                "f-16",
                "l-13",
                "URL",
                "https://protected-username-check.example",
                "url",
                Some("tpl_url"),
            );
            conn.execute(
                "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type, sort_order)
                 VALUES ('f-17', 'l-13', 'tpl_username', 'Username', 'shouldnotleak', 1, 'text', 0)",
                [],
            )
            .unwrap();

            let hits = for_url(&conn, "https://protected-username-check.example", 50).unwrap();
            let mine = hits
                .iter()
                .find(|h| h.id == "l-13")
                .unwrap_or_else(|| panic!("[{label}] seeded entry must still be returned"));
            assert_eq!(
                mine.username, None,
                "[{label}] a protected username must not leave through get_logins"
            );
        }
    }

    /// A protected `url` field must not match: its entry id would land in
    /// `ConnScope.candidate_ids` and anchor a later secret request that
    /// omits `url`, bypassing the invariant that protected URLs never anchor.
    #[test]
    fn protected_url_field_does_not_match() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "l-14", "Protected url site", 0);
            conn.execute(
                "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type, sort_order)
                 VALUES ('f-18', 'l-14', 'tpl_url', 'URL', 'https://protected-url-check.example', 1, 'url', 0)",
                [],
            )
            .unwrap();

            let hits = for_url(&conn, "https://protected-url-check.example", 50).unwrap();
            assert!(
                hits.iter().all(|h| h.id != "l-14"),
                "[{label}] an entry whose only url is protected must not be offered"
            );
        }
    }

    /// An entry with a url field but no username/otp field
    /// must yield `None`/`false`, proving both sub-selects' negative case
    /// (the positive-case test alone would not catch an always-Some
    /// or always-true mapping bug). Id-scoped for the same reason as above.
    #[test]
    fn url_only_entry_yields_no_username_and_no_totp() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "l-12", "Bare url only", 0);
            seed_field(
                &conn,
                "f-15",
                "l-12",
                "URL",
                "https://bare-url-check.example",
                "url",
                Some("tpl_url"),
            );

            let hits = for_url(&conn, "https://bare-url-check.example", 50).unwrap();
            let mine = hits
                .iter()
                .find(|h| h.id == "l-12")
                .unwrap_or_else(|| panic!("[{label}] seeded entry must be found"));
            assert_eq!(
                mine.username, None,
                "[{label}] no tpl_username field means username must be None"
            );
            assert!(
                !mine.has_totp,
                "[{label}] no totp field means has_totp must be false"
            );
        }
    }

    /// Found on the Windows bench: an entry whose login is an email carries
    /// no `tpl_username`, so the extension used to receive `username: null`
    /// and filled the password alone. Both spellings of an email field must
    /// answer, since KeePass import writes `tpl_email` while the editor's own
    /// Email field type is `email` with no template.
    #[test]
    fn an_email_stands_in_for_a_missing_username() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "l-20", "Templated email", 0);
            seed_field(&conn, "f-30", "l-20", "URL", "https://email-tpl.example", "url", Some("tpl_url"));
            seed_field(&conn, "f-31", "l-20", "Email", "ann@example.com", "email", Some("tpl_email"));

            seed_entry(&conn, "l-21", "Typed email, no template", 0);
            seed_field(&conn, "f-32", "l-21", "URL", "https://email-typed.example", "url", Some("tpl_url"));
            seed_field(&conn, "f-33", "l-21", "Email", "bob@example.com", "email", None);

            let tpl = for_url(&conn, "https://email-tpl.example", 50).unwrap();
            assert_eq!(
                tpl.iter().find(|h| h.id == "l-20").and_then(|h| h.username.clone()),
                Some("ann@example.com".to_string()),
                "[{label}] a tpl_email field must stand in for the missing username"
            );

            let typed = for_url(&conn, "https://email-typed.example", 50).unwrap();
            assert_eq!(
                typed.iter().find(|h| h.id == "l-21").and_then(|h| h.username.clone()),
                Some("bob@example.com".to_string()),
                "[{label}] a field_type='email' field must stand in too, template or not"
            );
        }
    }

    /// The fallback is a fallback, not a replacement: an entry carrying both
    /// must still answer with the username, or the browser would autofill the
    /// wrong identity on every such entry.
    #[test]
    fn a_username_still_wins_over_an_email() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "l-22", "Both fields", 0);
            seed_field(&conn, "f-34", "l-22", "URL", "https://both-fields.example", "url", Some("tpl_url"));
            seed_field(&conn, "f-35", "l-22", "Email", "ann@example.com", "email", Some("tpl_email"));
            seed_field(&conn, "f-36", "l-22", "Username", "ann", "text", Some("tpl_username"));

            let hits = for_url(&conn, "https://both-fields.example", 50).unwrap();
            assert_eq!(
                hits.iter().find(|h| h.id == "l-22").and_then(|h| h.username.clone()),
                Some("ann".to_string()),
                "[{label}] tpl_username must win even when an email field is present"
            );
        }
    }

    /// The `is_protected = 0` guard this module documents applies to the new
    /// branch too — otherwise the fallback would become a way to read a
    /// deliberately hidden value through the one vault read that has neither
    /// a confirmation prompt nor an audit row.
    #[test]
    fn a_protected_email_is_withheld_like_a_protected_username() {
        for (label, conn) in both_dbs() {
            seed_entry(&conn, "l-23", "Protected email site", 0);
            seed_field(&conn, "f-37", "l-23", "URL", "https://protected-email.example", "url", Some("tpl_url"));
            conn.execute(
                "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type, sort_order)
                 VALUES ('f-38', 'l-23', 'tpl_email', 'Email', 'shouldnotleak@example.com', 1, 'email', 0)",
                [],
            )
            .unwrap();

            let hits = for_url(&conn, "https://protected-email.example", 50).unwrap();
            let mine = hits
                .iter()
                .find(|h| h.id == "l-23")
                .unwrap_or_else(|| panic!("[{label}] seeded entry must still match on its URL"));
            assert_eq!(
                mine.username, None,
                "[{label}] a protected email must be withheld, not exposed by the fallback"
            );
        }
    }
}

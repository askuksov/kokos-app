//! HIBP breach check — k-anonymity range core. Plaintext and the full
//! SHA-1 hash live ONLY here: `scan_queries` reads the same secret scope as
//! `health::scan`, hashes each value, splits it into a public 5-char `prefix`
//! and a PRIVATE 35-char `suffix`, and zeroizes the plaintext. The Tauri layer
//! sends only `prefix` (via `range_url`) over the network and calls
//! `HibpQuery::match_in`; it can never reconstruct the full hash because
//! `suffix` is not accessible outside this module. `split`/`match_suffix`/
//! `range_url` are pure and injected-response tested — no network in core.

use rusqlite::Connection;
use sha1::{Digest, Sha1};
use zeroize::Zeroize;

use crate::error::Result;

/// HIBP range API base. Only the 5-char prefix is ever appended (see
/// `range_url`); the suffix / full hash is never in a request.
const HIBP_RANGE_BASE: &str = "https://api.pwnedpasswords.com/range";

/// SHA-1 the password, hex-uppercase, split into `(prefix5, suffix35)`.
pub fn split(password: &str) -> (String, String) {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let digest: [u8; 20] = hasher.finalize().into();
    let hex: String = digest.iter().map(|b| format!("{b:02X}")).collect();
    let (prefix, suffix) = hex.split_at(5);
    (prefix.to_string(), suffix.to_string())
}

/// The request URL for a prefix. This is the ONLY thing that egresses, so
/// anything but exactly 5 ASCII hex chars (the k-anonymity prefix) is `None`.
pub fn range_url(prefix: &str) -> Option<String> {
    if prefix.len() != 5 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("{HIBP_RANGE_BASE}/{prefix}"))
}

/// Match a suffix against an HIBP range response body (`SUFFIX:COUNT` lines,
/// CRLF-separated, uppercase). Case-insensitive; malformed lines are skipped;
/// a matched line with count `0` (Add-Padding filler) is NOT a breach.
pub fn match_suffix(suffix: &str, body: &str) -> Option<u32> {
    for line in body.lines() {
        let Some((suf, count)) = line.split_once(':') else {
            continue;
        };
        if suf.trim().eq_ignore_ascii_case(suffix.trim()) {
            return count.trim().parse::<u32>().ok().filter(|&c| c > 0);
        }
    }
    None
}

/// One password's range query. `prefix` is public (goes in the URL); `suffix`
/// is PRIVATE so no caller outside this module can rebuild the full hash.
#[derive(Clone)]
pub struct HibpQuery {
    pub entry_id: String,
    pub title: String,
    pub field_name: String,
    pub prefix: String,
    suffix: String,
}

impl std::fmt::Debug for HibpQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HibpQuery")
            .field("entry_id", &self.entry_id)
            .field("title", &self.title)
            .field("field_name", &self.field_name)
            .field("prefix", &self.prefix)
            .field("suffix", &"<redacted>")
            .finish()
    }
}

impl HibpQuery {
    /// Look this query's suffix up in a range response body.
    pub fn match_in(&self, body: &str) -> Option<u32> {
        match_suffix(&self.suffix, body)
    }
}

/// Build a range query per in-scope secret. SAME scope as `health::scan`:
/// live entries, `field_type='secret'`, minus `tpl_pin`/`tpl_security_answer`,
/// non-empty. Plaintext is hashed and zeroized here — it never leaves.
pub fn scan_queries(conn: &Connection) -> Result<Vec<HibpQuery>> {
    let mut stmt = conn.prepare(
        "SELECT e.id, e.title, ef.name, ef.value
         FROM entries e
         JOIN entry_fields ef ON ef.entry_id = e.id
         WHERE e.is_deleted = 0
           AND ef.field_type = 'secret'
           AND (ef.template_id IS NULL OR ef.template_id NOT IN ('tpl_pin', 'tpl_security_answer'))
         ORDER BY e.title COLLATE NOCASE ASC, e.id ASC, ef.sort_order ASC, ef.id ASC",
    )?;

    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
        ))
    })?;

    let mut queries = Vec::new();
    for row in rows {
        let (entry_id, title, field_name, value) = row?;
        let Some(mut value) = value.filter(|s| !s.is_empty()) else {
            continue;
        };
        let (prefix, suffix) = split(&value);
        value.zeroize();
        queries.push(HibpQuery {
            entry_id,
            title,
            field_name,
            prefix,
            suffix,
        });
    }
    Ok(queries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::testutil::seed_entry;
    use rusqlite::Connection;

    #[test]
    fn split_uppercase_prefix5_suffix35() {
        let (prefix, suffix) = split("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert_eq!(prefix.len(), 5);
        assert_eq!(suffix.len(), 35);
    }

    #[test]
    fn range_url_carries_only_the_prefix() {
        let (prefix, suffix) = split("password");
        let url = range_url(&prefix).unwrap();
        assert!(url.ends_with("/5BAA6"), "url = {url}");
        assert!(
            !url.contains(&suffix),
            "the suffix must NEVER be in the URL"
        );
        assert!(
            !url.to_uppercase().contains(&format!("{prefix}{suffix}")),
            "no full hash"
        );
    }

    #[test]
    fn range_url_rejects_anything_but_a_5_hex_prefix() {
        let (prefix, suffix) = split("password");
        for bad in [
            "",
            "5BAA",
            "5BAA61",
            "5BAG6",
            "5BAA/",
            "../x",
            "5BAÄ",
        ] {
            assert_eq!(range_url(bad), None, "{bad:?} must be refused");
        }
        assert_eq!(range_url(&format!("{prefix}{suffix}")), None, "full hash refused");
        assert!(range_url("5baa6").is_some(), "lowercase hex is still a 5-char prefix");
    }

    #[test]
    fn match_suffix_hit_case_insensitive() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:37359195\r\n";
        let (_p, suffix) = split("password");
        assert_eq!(match_suffix(&suffix, body), Some(37_359_195));
        assert_eq!(match_suffix(&suffix.to_lowercase(), body), Some(37_359_195));
    }

    #[test]
    fn match_suffix_clean_miss() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n";
        let (_p, suffix) = split("a-password-never-breached-zzz");
        assert_eq!(match_suffix(&suffix, body), None);
    }

    #[test]
    fn match_suffix_zero_count_padding_is_not_compromised() {
        let (_p, suffix) = split("password");
        let body = format!("{suffix}:0\r\n");
        assert_eq!(
            match_suffix(&suffix, &body),
            None,
            "count 0 = padding, not a breach"
        );
    }

    #[test]
    fn match_suffix_tolerates_malformed_lines() {
        let (_p, suffix) = split("password");
        let body = format!("garbage-no-colon\r\nNOTAHEX:notanumber\r\n{suffix}:5\r\n\r\n");
        assert_eq!(match_suffix(&suffix, &body), Some(5));
    }

    /// Same helper shape as health.rs's test module.
    fn seed_secret(
        conn: &Connection,
        fid: &str,
        eid: &str,
        name: &str,
        tpl: Option<&str>,
        val: &str,
    ) {
        conn.execute(
            "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, 'secret')",
            rusqlite::params![fid, eid, tpl, name, val],
        )
        .unwrap();
    }

    #[test]
    fn scan_queries_uses_d4_scope_and_splits() {
        let conn = db::create_fresh().unwrap();
        seed_entry(&conn, "e", "Bank", 0);
        seed_secret(
            &conn,
            "pw",
            "e",
            "Password",
            Some("tpl_password"),
            "password",
        );
        seed_secret(&conn, "pin", "e", "PIN", Some("tpl_pin"), "1234");
        seed_secret(&conn, "empty", "e", "Old", None, "");
        conn.execute(
            "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type)
             VALUES ('note','e',NULL,'Note','hi',0,'text')",
            [],
        )
        .unwrap();

        let qs = scan_queries(&conn).unwrap();
        assert_eq!(qs.len(), 1, "only the in-scope password field");
        assert_eq!(qs[0].entry_id, "e");
        assert_eq!(qs[0].field_name, "Password");
        assert_eq!(qs[0].prefix, "5BAA6");
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:99\r\n";
        assert_eq!(qs[0].match_in(body), Some(99));
    }

    #[test]
    fn debug_never_prints_the_suffix() {
        let conn = db::create_fresh().unwrap();
        seed_entry(&conn, "e", "Bank", 0);
        seed_secret(
            &conn,
            "pw",
            "e",
            "Password",
            Some("tpl_password"),
            "password",
        );
        let qs = scan_queries(&conn).unwrap();
        let dbg = format!("{:?}", qs[0]);
        assert!(
            !dbg.contains("1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
            "suffix must never appear in Debug: {dbg}"
        );
        assert!(dbg.contains("5BAA6"), "prefix (non-secret) may appear");
    }

    #[test]
    fn scan_queries_breaks_title_ties_by_entry_id() {
        let conn = db::create_fresh().unwrap();
        seed_entry(&conn, "b", "Same", 0);
        seed_secret(&conn, "pb", "b", "Password", Some("tpl_password"), "pw-b");
        seed_entry(&conn, "a", "same", 0);
        seed_secret(&conn, "pa", "a", "Password", Some("tpl_password"), "pw-a");
        let ids: Vec<String> = scan_queries(&conn).unwrap().into_iter().map(|q| q.entry_id).collect();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[test]
    fn scan_queries_excludes_trash() {
        let conn = db::create_fresh().unwrap();
        seed_entry(&conn, "dead", "Dead", 0);
        seed_secret(
            &conn,
            "d",
            "dead",
            "Password",
            Some("tpl_password"),
            "password",
        );
        conn.execute("UPDATE entries SET is_deleted = 1 WHERE id = 'dead'", [])
            .unwrap();
        assert!(scan_queries(&conn).unwrap().is_empty());
    }
}

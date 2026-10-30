//! Substring search over live entries. Scans each entry's non-secret searchable
//! text — title, notes, field NAMES, and NON-protected field VALUES — for the
//! query tokens (case-insensitive; every whitespace-separated token must be a
//! substring). Protected values are never in the haystack (CASE WHEN
//! is_protected = 0), so a secret can never surface a match. Regex search
//! (`search_regex`) shares the same candidate scan.

use regex::RegexBuilder;
use rusqlite::Connection;

use crate::entries::{hydrate_tags, map_summary, EntrySummary, SUMMARY_COLS};
use crate::error::{Result, VaultError};

#[derive(Debug, Clone, Default)]
pub struct SearchFilters {
    pub folder_id: Option<String>,
    pub tag_id: Option<String>,
    pub favorites_only: bool,
    pub regex: bool,
}

/// Appends the folder/tag/favorites filter clauses to `where_extra` and their
/// bound params. Called by `scan()` (which both `search` and `search_regex`
/// reach), so every search path admits the identical entries under a filter.
/// `e` is the entries alias the caller's FROM clause binds.
fn apply_filters<'a>(
    f: &'a SearchFilters,
    where_extra: &mut String,
    params: &mut Vec<(&'static str, &'a dyn rusqlite::ToSql)>,
) {
    if f.favorites_only {
        where_extra.push_str(" AND e.is_favorite = 1");
    }
    if let Some(fid) = &f.folder_id {
        where_extra.push_str(" AND e.folder_id = :folder");
        params.push((":folder", fid));
    }
    if let Some(tid) = &f.tag_id {
        where_extra.push_str(
            " AND EXISTS(SELECT 1 FROM entry_tags et WHERE et.entry_id = e.id AND et.tag_id = :tag)",
        );
        params.push((":tag", tid));
    }
}

/// Scans every live (non-trashed) entry's non-secret searchable text and keeps
/// those whose haystack satisfies `is_hit`, then rebuilds each match's summary
/// under the folder/tag/favorites filters. Shared by `search` (substring) and
/// `search_regex` (regex) so both use the identical visibility rule (protected
/// values are never scanned) and the same filter/summary path.
fn scan(
    conn: &Connection,
    f: &SearchFilters,
    is_hit: impl Fn(&str) -> bool,
) -> Result<Vec<EntrySummary>> {
    let mut where_extra = String::new();
    let mut params: Vec<(&'static str, &dyn rusqlite::ToSql)> = Vec::new();
    apply_filters(f, &mut where_extra, &mut params);

    let sql = format!(
        "SELECT e.id, e.title, COALESCE(e.notes,''),
                COALESCE((SELECT GROUP_CONCAT(ef.name || ' ' ||
                    CASE WHEN ef.is_protected = 0 THEN COALESCE(ef.value,'') ELSE '' END, ' ')
                  FROM entry_fields ef WHERE ef.entry_id = e.id), '')
         FROM entries e WHERE e.is_deleted = 0{where_extra}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(&params[..], |r| {
        let id: String = r.get(0)?;
        let hay = format!(
            "{} {} {}",
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?
        );
        Ok((id, hay))
    })?;
    let mut matched_ids: Vec<String> = Vec::new();
    for row in rows {
        let (id, hay) = row?;
        if is_hit(&hay) {
            matched_ids.push(id);
        }
    }

    use std::collections::HashMap;
    let mut by_id: HashMap<String, EntrySummary> = HashMap::new();
    for chunk in matched_ids.chunks(900) {
        let ph = std::iter::repeat("?").take(chunk.len()).collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT {SUMMARY_COLS} FROM entries e WHERE e.is_deleted = 0 AND e.id IN ({ph})"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            rusqlite::params_from_iter(chunk.iter().map(|s| s.as_str())),
            map_summary,
        )?;
        for row in rows {
            let s = row?;
            by_id.insert(s.id.clone(), s);
        }
    }
    let mut out: Vec<EntrySummary> =
        matched_ids.iter().filter_map(|id| by_id.remove(id)).collect();
    hydrate_tags(conn, &mut out)?;
    Ok(out)
}

/// Case-insensitive substring search: every whitespace-separated token in
/// `query` must appear as a substring of the entry's non-secret text. An
/// empty / whitespace-only query returns no rows.
pub fn search(conn: &Connection, query: &str, f: &SearchFilters) -> Result<Vec<EntrySummary>> {
    let tokens: Vec<String> = query.split_whitespace().map(|t| t.to_lowercase()).collect();
    if tokens.is_empty() {
        return Ok(Vec::new());
    }
    scan(conn, f, |hay| {
        let hay = hay.to_lowercase();
        tokens.iter().all(|t| hay.contains(t.as_str()))
    })
}

/// Opt-in regex search: scans the same non-secret candidate text as `search`,
/// matching by regex instead of substring. Protected values are never scanned.
pub fn search_regex(
    conn: &Connection,
    pattern: &str,
    f: &SearchFilters,
) -> Result<Vec<EntrySummary>> {
    if pattern.is_empty() {
        return Ok(Vec::new());
    }
    let re = RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .build()
        .map_err(|e| VaultError::InvalidRegex(e.to_string()))?;
    scan(conn, f, |hay| re.is_match(hay))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::create_fresh;
    use crate::db::now_unix;

    fn seed(conn: &rusqlite::Connection, id: &str, title: &str, fav: i64, folder: &str) {
        let now = now_unix();
        conn.execute(
            "INSERT INTO entries (id, folder_id, title, is_favorite, is_deleted, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)",
            rusqlite::params![id, folder, title, fav, now],
        ).unwrap();
    }
    fn none() -> SearchFilters {
        SearchFilters {
            folder_id: None,
            tag_id: None,
            favorites_only: false,
            regex: false,
        }
    }

    #[test]
    fn matches_by_substring() {
        let c = create_fresh().unwrap();
        seed(&c, "e1", "GitHub", 0, "root");
        seed(&c, "e2", "GitLab", 0, "root");
        assert_eq!(search(&c, "git", &none()).unwrap().len(), 2, "'git' matches both");
        let lab = search(&c, "lab", &none()).unwrap();
        assert_eq!(lab.len(), 1, "'lab' matches GitLab by substring");
        assert_eq!(lab[0].id, "e2");
        let hub = search(&c, "hub", &none()).unwrap();
        assert_eq!(hub.len(), 1, "'hub' matches only GitHub");
        assert_eq!(hub[0].id, "e1");
    }

    #[test]
    fn substring_is_case_insensitive() {
        let c = create_fresh().unwrap();
        seed(&c, "e1", "GitLab", 0, "root");
        assert_eq!(search(&c, "LAB", &none()).unwrap().len(), 1);
        assert_eq!(search(&c, "gItLaB", &none()).unwrap().len(), 1);
    }

    #[test]
    fn multi_word_requires_all_tokens() {
        let c = create_fresh().unwrap();
        seed(&c, "e1", "GitHub", 0, "root");
        assert_eq!(search(&c, "git hub", &none()).unwrap().len(), 1, "both tokens are substrings");
        assert!(search(&c, "git xyz", &none()).unwrap().is_empty(), "one token missing → no match");
    }

    #[test]
    fn matches_by_field_name_and_nonsecret_value() {
        let c = create_fresh().unwrap();
        seed(&c, "e1", "Bank", 0, "root");
        c.execute(
            "INSERT INTO entry_fields (id, entry_id, name, value, is_protected, field_type)
             VALUES ('f1','e1','Username','alicexyz',0,'text')", []).unwrap();
        assert_eq!(search(&c, "usern", &none()).unwrap().len(), 1, "field NAME substring");
        assert_eq!(search(&c, "alicexyz", &none()).unwrap().len(), 1, "non-secret field VALUE substring");
    }

    #[test]
    fn excludes_trashed() {
        let c = create_fresh().unwrap();
        seed(&c, "e1", "GitHub", 0, "root");
        c.execute("UPDATE entries SET is_deleted=1 WHERE id='e1'", [])
            .unwrap();
        assert!(search(&c, "GitHub", &none()).unwrap().is_empty());
    }

    #[test]
    fn secret_value_is_not_findable() {
        let c = create_fresh().unwrap();
        seed(&c, "e1", "Bank", 0, "root");
        c.execute(
            "INSERT INTO entry_fields (id, entry_id, name, value, is_protected, field_type)
             VALUES ('f1','e1','Password','hunter2xyz',1,'secret')",
            [],
        )
        .unwrap();
        assert!(
            search(&c, "hunter2xyz", &none()).unwrap().is_empty(),
            "search must never surface an entry by its secret value"
        );
    }

    #[test]
    fn favorites_filter_narrows() {
        let c = create_fresh().unwrap();
        seed(&c, "e1", "Alpha", 1, "root");
        seed(&c, "e2", "Alpha2", 0, "root");
        let f = SearchFilters {
            favorites_only: true,
            ..none()
        };
        let hits = search(&c, "alpha", &f).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "e1");
    }

    #[test]
    fn folder_filter_narrows() {
        let c = create_fresh().unwrap();
        c.execute("INSERT INTO folders (id,parent_id,name,sort_order,created_at,updated_at) VALUES ('fold',NULL,'F',0,1,1)", []).unwrap();
        seed(&c, "e1", "Alpha", 0, "root");
        seed(&c, "e2", "Alpha2", 0, "fold");
        let f = SearchFilters {
            folder_id: Some("fold".into()),
            ..none()
        };
        let hits = search(&c, "alpha", &f).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "e2");
    }

    #[test]
    fn empty_query_returns_nothing() {
        let c = create_fresh().unwrap();
        seed(&c, "e1", "GitHub", 0, "root");
        assert!(search(&c, "   ", &none()).unwrap().is_empty());
    }

    #[test]
    fn tag_filter_narrows() {
        let c = create_fresh().unwrap();
        seed(&c, "e1", "Alpha", 0, "root");
        seed(&c, "e2", "Alpha2", 0, "root");
        c.execute(
            "INSERT INTO tags (id, name, color) VALUES ('t1', 'Work', '#ffffff')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO entry_tags (entry_id, tag_id) VALUES ('e1', 't1')",
            [],
        )
        .unwrap();
        let f = SearchFilters {
            tag_id: Some("t1".into()),
            ..none()
        };
        let hits = search(&c, "alpha", &f).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "e1");
    }

    #[test]
    fn regex_matches_title_and_field_name_not_secret() {
        let c = create_fresh().unwrap();
        seed(&c, "e1", "Server-01", 0, "root");
        c.execute(
            "INSERT INTO entry_fields (id, entry_id, name, value, is_protected, field_type)
             VALUES ('f1','e1','Password','s3cr3t',1,'secret')",
            [],
        )
        .unwrap();
        let f = SearchFilters {
            regex: true,
            ..Default::default()
        };
        assert_eq!(
            search_regex(&c, r"Server-\d+", &f).unwrap().len(),
            1,
            "matches title regex"
        );
        assert_eq!(
            search_regex(&c, "Password", &f).unwrap().len(),
            1,
            "matches field NAME"
        );
        assert!(
            search_regex(&c, "s3cr3t", &f).unwrap().is_empty(),
            "must NOT scan secret values"
        );
    }

    #[test]
    fn regex_bad_pattern_errors() {
        let c = create_fresh().unwrap();
        let f = SearchFilters {
            regex: true,
            ..Default::default()
        };
        assert!(matches!(
            search_regex(&c, "(unclosed", &f),
            Err(crate::error::VaultError::InvalidRegex(_))
        ));
    }

    #[test]
    fn regex_tag_filter_narrows() {
        let c = create_fresh().unwrap();
        seed(&c, "e1", "Alpha", 0, "root");
        seed(&c, "e2", "Alpha2", 0, "root");
        c.execute(
            "INSERT INTO tags (id, name, color) VALUES ('t1', 'Work', '#ffffff')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO entry_tags (entry_id, tag_id) VALUES ('e1', 't1')",
            [],
        )
        .unwrap();
        let f = SearchFilters {
            regex: true,
            tag_id: Some("t1".into()),
            ..Default::default()
        };
        let hits = search_regex(&c, "Alpha", &f).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "e1");
    }

    #[test]
    fn empty_regex_returns_nothing() {
        let c = create_fresh().unwrap();
        seed(&c, "e1", "GitHub", 0, "root");
        let f = SearchFilters { regex: true, ..Default::default() };
        assert!(
            search_regex(&c, "", &f).unwrap().is_empty(),
            "an empty regex must not match every entry (symmetry with the FTS empty-query path)"
        );
    }
}

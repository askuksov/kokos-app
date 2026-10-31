//! The single security chokepoint between vault entries and the embedding
//! model. `embedding_input` is a WHITELIST — it can only ever emit the handful
//! of non-sensitive metadata fields named here, so a password, a protected
//! value, `notes`, or a TOTP seed cannot reach the model even if the source
//! `Entry` still carried it. The boundary test in this file asserts exactly
//! that; do not widen the whitelist without extending that test.

use std::collections::HashMap;

use rusqlite::Connection;

use kokos_core::entries::{self, Entry, View};
use kokos_core::folders::{self, FolderNode};
use kokos_core::url_match::{etld_plus_one, host_of};

use crate::AiError;

/// The ONLY entry-derived data allowed into an embedding.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EmbeddingMetadata {
    pub title: String,
    pub entry_type: String,
    pub url_domain: Option<String>,
    pub folder_name: Option<String>,
    pub tag_names: Vec<String>,
}

/// One live entry's whitelisted input string + its invalidation hash.
#[derive(Debug, Clone, PartialEq)]
pub struct EntryMeta {
    pub entry_id: String,
    pub input: String,
    pub content_hash: String,
}

/// Fixed-order join so the same metadata always produces the same string (and
/// therefore the same `content_hash`). Empty parts are skipped.
pub fn embedding_input(m: &EmbeddingMetadata) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let title = m.title.trim();
    if !title.is_empty() { parts.push(title); }
    if let Some(d) = &m.url_domain { if !d.is_empty() { parts.push(d); } }
    if let Some(f) = &m.folder_name { if !f.is_empty() { parts.push(f); } }
    for t in &m.tag_names { if !t.is_empty() { parts.push(t); } }
    if !m.entry_type.is_empty() { parts.push(&m.entry_type); }
    parts.join(" • ")
}

/// `content_hash = SHA-256(embedding_input ‖ 0x1F ‖ model_id)`. Reuses the
/// crate's existing `sha256_hex`. The unit separator prevents any ambiguity
/// between the two fields; `model_id` is folded in so a model switch never
/// matches an old hash.
pub fn content_hash(input: &str, model_id: &str) -> String {
    let mut buf = Vec::with_capacity(input.len() + 1 + model_id.len());
    buf.extend_from_slice(input.as_bytes());
    buf.push(0x1f);
    buf.extend_from_slice(model_id.as_bytes());
    crate::download::sha256_hex(&buf)
}

/// Registrable domain from an entry's URL field, or `None`. Reads ONLY a
/// non-protected field marked as a URL (by `field_type` or the `tpl_url`
/// template) — it never scans all fields (a non-protected username would else
/// leak) and never a protected value.
fn url_domain_of(entry: &Entry) -> Option<String> {
    let field = entry.fields.iter().find(|f| {
        !f.is_protected && (f.field_type == "url" || f.template_id.as_deref() == Some("tpl_url"))
    })?;
    url_domain_from_str(field.value.as_deref()?)
}

/// Registrable domain (eTLD+1) of a raw URL string, or `None` for an empty or
/// unparseable value. Extracted from `url_domain_of` so a DRAFT (which has a
/// raw URL string, not an `Entry`) produces the identical whitelist token an
/// indexed entry would. `host_of` wants a scheme; a bare host is retried with a
/// synthetic `https://`.
pub fn url_domain_from_str(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let host = host_of(raw).or_else(|| host_of(&format!("https://{raw}")))?;
    Some(etld_plus_one(&host).unwrap_or(host))
}

/// Assemble the whitelist from a DRAFT entry being composed in the editor
/// before it exists or is indexed. Only the create-panel's
/// whitelist-safe fields cross: `title`, the registrable domain of `url`, and
/// `entry_type`. Deliberately NO folder or tag context — a fresh draft has
/// none, and folding a pre-picked folder into the target would bias the folder
/// suggestion toward it (circularity). Mirrors `metadata_from_entry` but from
/// raw strings, so a draft can NEVER carry a protected value, notes, or a
/// custom field into the model.
pub fn metadata_from_draft(title: &str, url: &str, entry_type: &str) -> EmbeddingMetadata {
    EmbeddingMetadata {
        title: title.to_string(),
        entry_type: entry_type.to_string(),
        url_domain: url_domain_from_str(url),
        folder_name: None,
        tag_names: Vec::new(),
    }
}

/// Assemble the whitelist from a single `Entry` (+ its resolved folder name).
/// `folder_name == Some("Root")` is treated as no folder (synthetic root).
pub fn metadata_from_entry(entry: &Entry, folder_name: Option<&str>) -> EmbeddingMetadata {
    let mut tag_names: Vec<String> = entry.tags.iter().map(|t| t.name.clone()).collect();
    tag_names.sort();
    EmbeddingMetadata {
        title: entry.title.clone(),
        entry_type: entry.entry_type.clone(),
        url_domain: url_domain_of(entry),
        folder_name: folder_name
            .filter(|f| *f != "Root")
            .map(str::to_string),
        tag_names,
    }
}

/// `folder_id -> name` for every real folder (the synthetic `root` is skipped).
/// Built once per sweep from `list_tree` to avoid N per-entry queries.
pub fn folder_names(conn: &Connection) -> Result<HashMap<String, String>, AiError> {
    fn walk(nodes: &[FolderNode], map: &mut HashMap<String, String>) {
        for n in nodes {
            if n.folder.id != "root" {
                map.insert(n.folder.id.clone(), n.folder.name.clone());
            }
            walk(&n.children, map);
        }
    }
    let tree = folders::list_tree(conn).map_err(|e| AiError::Backend(e.to_string()))?;
    let mut map = HashMap::new();
    walk(&tree, &mut map);
    Ok(map)
}

/// Sweep every LIVE (`is_deleted = 0`) entry into its whitelisted input +
/// `content_hash` for `model_id`. Reads folder names once. Never reads a secret
/// (protected values are already withheld by `entries::get`, and the whitelist
/// enforces it regardless).
pub fn collect_metadata(conn: &Connection, model_id: &str) -> Result<Vec<EntryMeta>, AiError> {
    let fmap = folder_names(conn)?;
    let summaries = entries::list(conn, View::All).map_err(|e| AiError::Backend(e.to_string()))?;
    let mut out = Vec::with_capacity(summaries.len());
    for s in &summaries {
        let Some(entry) = entries::get(conn, &s.id).map_err(|e| AiError::Backend(e.to_string()))? else {
            continue;
        };
        let fname = entry.folder_id.as_deref().and_then(|id| fmap.get(id)).map(String::as_str);
        let meta = metadata_from_entry(&entry, fname);
        let input = embedding_input(&meta);
        let content_hash = content_hash(&input, model_id);
        out.push(EntryMeta { entry_id: entry.id, input, content_hash });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kokos_core::db;
    use kokos_core::entries::{self, NewEntry, NewField};

    fn seed_login(conn: &rusqlite::Connection) -> String {
        let e = entries::create(
            conn,
            NewEntry {
                title: "Netflix Family".into(),
                folder_id: None,
                notes: Some("SECRET-NOTE-do-not-embed".into()),
                entry_type: "login".into(),
                fields: vec![
                    NewField { template_id: Some("tpl_username".into()), name: "Username".into(),
                        value: Some("alice@example.com".into()), is_protected: false, field_type: "text".into() },
                    NewField { template_id: Some("tpl_password".into()), name: "Password".into(),
                        value: Some("SUPERSECRETPW-123".into()), is_protected: true, field_type: "secret".into() },
                    NewField { template_id: Some("tpl_url".into()), name: "URL".into(),
                        value: Some("https://www.netflix.com/browse".into()), is_protected: false, field_type: "url".into() },
                    NewField { template_id: None, name: "TOTP".into(),
                        value: Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into()), is_protected: true, field_type: "otp".into() },
                ],
            },
            1,
        ).unwrap();
        e.id
    }

    #[test]
    fn embedding_input_whitelists_metadata_and_never_leaks_a_secret() {
        let conn = db::create_fresh().unwrap();
        let id = seed_login(&conn);
        let metas = collect_metadata(&conn, "mid").unwrap();
        let m = metas.iter().find(|m| m.entry_id == id).expect("entry present");

        assert!(m.input.contains("Netflix Family"), "title in: {}", m.input);
        assert!(m.input.contains("netflix.com"), "registrable domain in: {}", m.input);
        assert!(m.input.contains("login"), "entry_type in: {}", m.input);

        for forbidden in [
            "SUPERSECRETPW-123",
            "SECRET-NOTE-do-not-embed",
            "JBSWY3DPEHPK3PXP", "otpauth",
            "alice@example.com",
        ] {
            assert!(!m.input.contains(forbidden), "LEAK: {forbidden:?} appeared in {}", m.input);
        }
    }

    #[test]
    fn content_hash_changes_with_input_and_model_and_is_stable() {
        let a = content_hash("Netflix • netflix.com • login", "mid");
        assert_eq!(a, content_hash("Netflix • netflix.com • login", "mid"), "stable");
        assert_ne!(a, content_hash("Netflix • netflix.com • login", "large"), "model folds in");
        assert_ne!(a, content_hash("Spotify • spotify.com • login", "mid"), "input folds in");
        assert_eq!(a.len(), 64, "sha-256 hex");
    }

    #[test]
    fn root_folder_name_is_dropped_as_noise() {
        let conn = db::create_fresh().unwrap();
        let e = entries::create(&conn, NewEntry {
            title: "T".into(), folder_id: None, notes: None, entry_type: "login".into(),
            fields: vec![],
        }, 1).unwrap();
        let entry = entries::get(&conn, &e.id).unwrap().unwrap();
        let m = metadata_from_entry(&entry, Some("Root"));
        assert_eq!(m.folder_name, None, "the synthetic root folder is not real metadata");
    }

    #[test]
    fn draft_metadata_whitelists_and_extracts_domain() {
        let m = metadata_from_draft("Netflix Family", "https://www.netflix.com/browse", "login");
        let input = embedding_input(&m);
        assert!(input.contains("Netflix Family"), "title in: {input}");
        assert!(input.contains("netflix.com"), "registrable domain in: {input}");
        assert!(input.contains("login"), "entry_type in: {input}");
        assert_eq!(m.folder_name, None, "a draft carries no folder context");
        assert!(m.tag_names.is_empty(), "a draft carries no tag context");
    }

    #[test]
    fn draft_url_domain_handles_bare_host_and_empty() {
        assert_eq!(url_domain_from_str(""), None, "empty -> None");
        assert_eq!(url_domain_from_str("   "), None, "whitespace -> None");
        assert_eq!(
            url_domain_from_str("example.com").as_deref(),
            Some("example.com"),
            "bare host gets a synthetic scheme"
        );
        assert_eq!(
            url_domain_from_str("https://www.sub.example.co.uk/x").as_deref(),
            Some("example.co.uk"),
            "eTLD+1 collapses the host"
        );
    }

    #[test]
    fn draft_and_entry_targets_agree_on_the_same_metadata() {
        let conn = db::create_fresh().unwrap();
        let e = entries::create(&conn, NewEntry {
            title: "GitHub".into(), folder_id: None, notes: None, entry_type: "login".into(),
            fields: vec![NewField {
                template_id: Some("tpl_url".into()), name: "URL".into(),
                value: Some("https://github.com/login".into()), is_protected: false, field_type: "url".into(),
            }],
        }, 1).unwrap();
        let entry = entries::get(&conn, &e.id).unwrap().unwrap();
        let entry_input = embedding_input(&metadata_from_entry(&entry, None));
        let draft_input = embedding_input(&metadata_from_draft("GitHub", "https://github.com/login", "login"));
        assert_eq!(entry_input, draft_input, "draft target string matches the entry target string");
    }
}

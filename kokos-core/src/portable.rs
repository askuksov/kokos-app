//! Portable JSON export/import. Mid-fidelity: entries + custom fields +
//! folders + tags + custom templates + relations + password history. NO
//! attachments (those live only in the encrypted .kokos). Export reads the
//! in-memory DB directly -- when the vault is unlocked `entry_fields.value`
//! is plaintext, so no crypto/reveal step is involved. Import is additive:
//! it ALWAYS mints new entry ids and never overwrites existing rows.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};

pub const EXPORT_FORMAT: &str = "kokos-export";
pub const EXPORT_VERSION: u32 = 1;
pub const FIDELITY: &str = "mid";

/// Built-in template ids — never exported (present in every vault). Single
/// source of truth is `templates::BUILTIN_IDS`.
const DEFAULT_TEMPLATE_IDS: [&str; 8] = crate::templates::BUILTIN_IDS;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportBundle {
    pub format: String,
    pub version: u32,
    pub exported_at: i64,
    pub app_version: String,
    pub fidelity: String,
    pub data: ExportData,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportData {
    pub folders: Vec<ExportFolder>,
    pub tags: Vec<ExportTag>,
    pub templates: Vec<ExportTemplate>,
    pub entries: Vec<ExportEntry>,
    pub relations: Vec<ExportRelation>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportFolder {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub sort_order: i32,
    pub created_at: i64,
    pub updated_at: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportTag {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportTemplate {
    pub id: String,
    pub name: String,
    pub field_type: String,
    pub is_protected: bool,
    pub sort_order: i32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub id: String,
    pub folder_id: Option<String>,
    pub title: String,
    pub notes: Option<String>,
    pub is_favorite: bool,
    /// Absent in bundles written before entry types existed.
    #[serde(default = "default_entry_type")]
    pub entry_type: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub fields: Vec<ExportField>,
    pub tags: Vec<String>,
    pub history: Vec<ExportHistory>,
}
fn default_entry_type() -> String {
    "login".into()
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportField {
    pub template_id: Option<String>,
    pub name: String,
    pub value: Option<String>,
    pub is_protected: bool,
    pub field_type: String,
    pub sort_order: i32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportHistory {
    pub field_name: String,
    pub value: Option<String>,
    pub changed_at: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRelation {
    pub source_id: String,
    pub target_id: String,
    pub relation_type: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportReport {
    pub entries: u32,
    pub folders_new: u32,
    pub tags_new: u32,
    pub templates_new: u32,
    pub relations: u32,
    pub skipped_relations: u32,
    pub skipped_attachments: u32,
}

pub fn to_json(b: &ExportBundle) -> Result<String> {
    serde_json::to_string_pretty(b).map_err(|e| VaultError::Io(e.to_string()))
}

pub fn export(
    conn: &Connection,
    ids: Option<&[String]>,
    app_version: &str,
    now: i64,
) -> Result<ExportBundle> {
    let mut folders = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT id, parent_id, name, sort_order, created_at, updated_at FROM folders",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ExportFolder {
                id: r.get(0)?,
                parent_id: r.get(1)?,
                name: r.get(2)?,
                sort_order: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
            })
        })?;
        for row in rows {
            folders.push(row?);
        }
    }
    let mut tags = Vec::new();
    {
        let mut stmt = conn.prepare("SELECT id, name, color FROM tags WHERE name != 'favorite'")?;
        let rows = stmt.query_map([], |r| {
            Ok(ExportTag {
                id: r.get(0)?,
                name: r.get(1)?,
                color: r.get(2)?,
            })
        })?;
        for row in rows {
            tags.push(row?);
        }
    }
    let mut templates = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT id, name, field_type, is_protected, sort_order FROM field_templates",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ExportTemplate {
                id: r.get(0)?,
                name: r.get(1)?,
                field_type: r.get(2)?,
                is_protected: r.get::<_, i64>(3)? != 0,
                sort_order: r.get(4)?,
            })
        })?;
        for row in rows {
            let t = row?;
            if !DEFAULT_TEMPLATE_IDS.contains(&t.id.as_str()) {
                templates.push(t);
            }
        }
    }
    let id_filter: Option<std::collections::HashSet<&str>> =
        ids.map(|v| v.iter().map(|s| s.as_str()).collect());
    let mut entries = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT id, folder_id, title, notes, is_favorite, created_at, updated_at, entry_type FROM entries WHERE is_deleted = 0 ORDER BY created_at")?;
        let raw = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, i64>(4)? != 0,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, String>(7)?,
            ))
        })?;
        for row in raw {
            let (id, folder_id, title, notes, is_favorite, created_at, updated_at, entry_type) =
                row?;
            if let Some(f) = &id_filter {
                if !f.contains(id.as_str()) {
                    continue;
                }
            }
            let fields = read_fields(conn, &id)?;
            let entry_tags = read_entry_tag_ids(conn, &id)?;
            let history = read_history(conn, &id)?;
            entries.push(ExportEntry {
                id,
                folder_id,
                title,
                notes,
                is_favorite,
                entry_type,
                created_at,
                updated_at,
                fields,
                tags: entry_tags,
                history,
            });
        }
    }
    let mut relations = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT r.source_id, r.target_id, r.relation_type, r.created_at
             FROM entry_relations r
             JOIN entries s ON s.id = r.source_id JOIN entries t ON t.id = r.target_id
             WHERE s.is_deleted = 0 AND t.is_deleted = 0",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ExportRelation {
                source_id: r.get(0)?,
                target_id: r.get(1)?,
                relation_type: r.get(2)?,
                created_at: r.get(3)?,
            })
        })?;
        for row in rows {
            let rel = row?;
            if let Some(f) = &id_filter {
                if !f.contains(rel.source_id.as_str()) || !f.contains(rel.target_id.as_str()) {
                    continue;
                }
            }
            relations.push(rel);
        }
    }
    // Selective export: ship only metadata the selected entries reference, so
    // unrelated folder names, tag names/colors and template names do not leak.
    // Built-in templates are already excluded above (every vault has them).
    if id_filter.is_some() {
        use std::collections::HashSet;
        let used_tags: HashSet<&str> =
            entries.iter().flat_map(|e| e.tags.iter().map(|t| t.as_str())).collect();
        tags.retain(|t| used_tags.contains(t.id.as_str()));
        let used_templates: HashSet<&str> = entries
            .iter()
            .flat_map(|e| e.fields.iter().filter_map(|f| f.template_id.as_deref()))
            .collect();
        templates.retain(|t| used_templates.contains(t.id.as_str()));
        // Referenced folders plus every ancestor, so the hierarchy stays valid.
        let parent_of: std::collections::HashMap<&str, Option<&str>> =
            folders.iter().map(|f| (f.id.as_str(), f.parent_id.as_deref())).collect();
        let mut keep: HashSet<String> = HashSet::new();
        for fid in entries.iter().filter_map(|e| e.folder_id.as_deref()) {
            let mut cur = Some(fid);
            while let Some(id) = cur {
                // `insert` false = already walked (also stops parent cycles).
                if !keep.insert(id.to_string()) {
                    break;
                }
                cur = parent_of.get(id).copied().flatten();
            }
        }
        folders.retain(|f| keep.contains(&f.id));
    }
    Ok(ExportBundle {
        format: EXPORT_FORMAT.into(),
        version: EXPORT_VERSION,
        exported_at: now,
        app_version: app_version.to_string(),
        fidelity: FIDELITY.into(),
        data: ExportData {
            folders,
            tags,
            templates,
            entries,
            relations,
        },
    })
}

fn read_fields(conn: &Connection, entry_id: &str) -> Result<Vec<ExportField>> {
    let mut stmt = conn.prepare(
        "SELECT template_id, name, value, is_protected, field_type, sort_order
         FROM entry_fields WHERE entry_id = ?1 ORDER BY sort_order",
    )?;
    let rows = stmt.query_map([entry_id], |r| {
        Ok(ExportField {
            template_id: r.get(0)?,
            name: r.get(1)?,
            value: r.get(2)?,
            is_protected: r.get::<_, i64>(3)? != 0,
            field_type: r.get(4)?,
            sort_order: r.get(5)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}
fn read_entry_tag_ids(conn: &Connection, entry_id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT et.tag_id FROM entry_tags et JOIN tags t ON t.id = et.tag_id
         WHERE et.entry_id = ?1 AND t.name != 'favorite'",
    )?;
    let rows = stmt.query_map([entry_id], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}
fn read_history(conn: &Connection, entry_id: &str) -> Result<Vec<ExportHistory>> {
    let mut stmt = conn.prepare(
        "SELECT field_name, value, changed_at FROM entry_field_history WHERE entry_id = ?1 ORDER BY changed_at")?;
    let rows = stmt.query_map([entry_id], |r| {
        Ok(ExportHistory {
            field_name: r.get(0)?,
            value: r.get(1)?,
            changed_at: r.get(2)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn parse(json: &str) -> Result<ExportBundle> {
    let bundle: ExportBundle =
        serde_json::from_str(json).map_err(|_| VaultError::ImportUnsupported)?;
    if bundle.format != EXPORT_FORMAT || bundle.version > EXPORT_VERSION {
        return Err(VaultError::ImportUnsupported);
    }
    Ok(bundle)
}

pub(crate) fn find_folder_by_name(
    conn: &Connection,
    parent: Option<&str>,
    name: &str,
) -> Result<Option<String>> {
    use rusqlite::OptionalExtension;
    Ok(conn
        .query_row(
            "SELECT id FROM folders WHERE name = ?1 AND parent_id IS ?2",
            rusqlite::params![name, parent],
            |r| r.get::<_, String>(0),
        )
        .optional()?)
}

/// Deepest folder level an import nests into (top-level folders are depth 1);
/// deeper bundle folders become children of their ancestor at this depth.
const MAX_FOLDER_DEPTH: usize = 200;

/// Reuse a same-named sibling or create the folder; a newly created folder
/// takes the bundle's `sort_order`.
fn import_folder(
    tx: &Connection,
    f: &ExportFolder,
    parent: Option<&str>,
    now: i64,
    rep: &mut ImportReport,
) -> Result<String> {
    if let Some(id) = find_folder_by_name(tx, parent, &f.name)? {
        return Ok(id);
    }
    let fol = crate::folders::create(tx, &f.name, parent, now)?;
    rep.folders_new += 1;
    if f.sort_order != 0 {
        tx.execute(
            "UPDATE folders SET sort_order = ?1 WHERE id = ?2",
            rusqlite::params![f.sort_order, fol.id],
        )?;
    }
    Ok(fol.id)
}

/// Additive merge into the OPEN vault. One outer transaction; entries/fields/
/// tag-links/history/relations are raw INSERTs (new ids, preserved timestamps,
/// no nested tx); folders/tags/templates reuse the plain-execute create fns.
pub fn import(conn: &Connection, b: &ExportBundle, now: i64) -> Result<ImportReport> {
    use std::collections::HashMap;
    let mut rep = ImportReport::default();
    let tx = conn.unchecked_transaction()?;

    let mut folder_map: HashMap<String, String> = HashMap::new();
    // Bundle id -> (depth below root, new parent id); top-level folders are depth 1.
    let mut folder_pos: HashMap<String, (usize, String)> = HashMap::new();
    let mut remaining: Vec<ExportFolder> = b.data.folders.clone();
    let mut guard = remaining.len() + 1;
    while !remaining.is_empty() && guard > 0 {
        guard -= 1;
        let mut next = Vec::new();
        for f in remaining.into_iter() {
            if f.id == "root" {
                let id = import_folder(&tx, &f, None, now, &mut rep)?;
                folder_pos.insert(f.id.clone(), (0, String::new()));
                folder_map.insert(f.id.clone(), id);
                continue;
            }
            let (parent_new, depth) = match f.parent_id.as_deref() {
                None | Some("root") => ("root".to_string(), 1),
                Some(p) => match (folder_map.get(p), folder_pos.get(p)) {
                    // A crafted chain deeper than the cap would later overflow
                    // the stack in recursive tree building, so anything below
                    // the cap is attached to the ancestor at the cap instead.
                    (Some(_), Some((d, pp))) if *d > MAX_FOLDER_DEPTH => (pp.clone(), *d),
                    (Some(np), Some((d, _))) => (np.clone(), d + 1),
                    _ => {
                        next.push(f);
                        continue;
                    }
                },
            };
            let id = import_folder(&tx, &f, Some(&parent_new), now, &mut rep)?;
            folder_pos.insert(f.id.clone(), (depth, parent_new));
            folder_map.insert(f.id.clone(), id);
        }
        remaining = next;
    }
    for f in remaining {
        let new_id = import_folder(&tx, &f, Some("root"), now, &mut rep)?;
        folder_map.insert(f.id, new_id);
    }

    let mut tag_map: HashMap<String, String> = HashMap::new();
    for t in &b.data.tags {
        use rusqlite::OptionalExtension;
        // Favourites are restored from `is_favorite`; never map onto the
        // reserved tag by name.
        if t.name == crate::tags::FAVORITE_TAG {
            continue;
        }
        let existing: Option<String> = tx
            .query_row("SELECT id FROM tags WHERE name = ?1", [&t.name], |r| {
                r.get(0)
            })
            .optional()?;
        let id = match existing {
            Some(id) => id,
            None => {
                // An invalid colour must not abort the whole import.
                let color = t.color.as_deref().filter(|c| crate::tags::is_valid_color(c));
                let created = crate::tags::create(&tx, &t.name, color)?;
                rep.tags_new += 1;
                created.id
            }
        };
        tag_map.insert(t.id.clone(), id);
    }

    let mut tpl_map: HashMap<String, String> = HashMap::new();
    for tpl in &b.data.templates {
        use rusqlite::OptionalExtension;
        let existing: Option<String> = tx
            .query_row(
                "SELECT id FROM field_templates WHERE name = ?1",
                [&tpl.name],
                |r| r.get(0),
            )
            .optional()?;
        let id = match existing {
            Some(id) => id,
            None => {
                let field_type = match tpl.field_type.as_str() {
                    "text" | "secret" | "url" | "email" | "otp" | "date" | "phone" => {
                        tpl.field_type.as_str()
                    }
                    _ => "text",
                };
                let created = crate::templates::create(&tx, &tpl.name, field_type, tpl.is_protected)?;
                rep.templates_new += 1;
                created.id
            }
        };
        tpl_map.insert(tpl.id.clone(), id);
    }

    let mut entry_map: HashMap<String, String> = HashMap::new();
    for e in &b.data.entries {
        let new_entry = uuid::Uuid::new_v4().to_string();
        let folder_new: Option<String> = match e.folder_id.as_deref() {
            None => Some("root".to_string()),
            Some("root") => Some("root".to_string()),
            Some(f) => folder_map.get(f).cloned().or(Some("root".to_string())),
        };
        let entry_type = if crate::entries::is_valid_entry_type(&e.entry_type) {
            e.entry_type.as_str()
        } else {
            "login"
        };
        tx.execute(
            "INSERT INTO entries (id, folder_id, title, notes, is_favorite, is_deleted, created_at, updated_at, entry_type)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8)",
            rusqlite::params![new_entry, folder_new, e.title, e.notes, e.is_favorite as i64, e.created_at, e.updated_at, entry_type],
        )?;
        for f in &e.fields {
            let template_id: Option<String> = match f.template_id.as_deref() {
                None => None,
                Some(t) if DEFAULT_TEMPLATE_IDS.contains(&t) => Some(t.to_string()),
                Some(t) => tpl_map.get(t).cloned(),
            };
            let field_type = match f.field_type.as_str() {
                "text" | "secret" | "url" | "email" | "otp" | "date" | "phone" => {
                    f.field_type.as_str()
                }
                _ => "text",
            };
            tx.execute(
                "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type, sort_order)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![uuid::Uuid::new_v4().to_string(), new_entry, template_id, f.name, f.value, f.is_protected as i64, field_type, f.sort_order],
            )?;
        }
        for old_tag in &e.tags {
            if let Some(nt) = tag_map.get(old_tag) {
                tx.execute(
                    "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?1, ?2)",
                    rusqlite::params![new_entry, nt],
                )?;
            }
        }
        if e.is_favorite {
            let fav = crate::tags::ensure_favorite_tag(&tx)?;
            tx.execute(
                "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?1, ?2)",
                rusqlite::params![new_entry, fav],
            )?;
        }
        for h in &e.history {
            tx.execute(
                "INSERT INTO entry_field_history (id, entry_id, field_name, value, changed_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![uuid::Uuid::new_v4().to_string(), new_entry, h.field_name, h.value, h.changed_at],
            )?;
        }
        entry_map.insert(e.id.clone(), new_entry);
        rep.entries += 1;
    }

    for r in &b.data.relations {
        if r.source_id == r.target_id
            || !crate::relations::RELATION_TYPES.contains(&r.relation_type.as_str())
        {
            rep.skipped_relations += 1;
            continue;
        }
        match (entry_map.get(&r.source_id), entry_map.get(&r.target_id)) {
            (Some(s), Some(t)) => {
                let n = tx.execute(
                    "INSERT OR IGNORE INTO entry_relations (id, source_id, target_id, relation_type, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![uuid::Uuid::new_v4().to_string(), s, t, r.relation_type, r.created_at],
                )?;
                if n > 0 {
                    rep.relations += 1;
                }
            }
            _ => rep.skipped_relations += 1,
        }
    }

    tx.commit()?;
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn seed(conn: &rusqlite::Connection) {
        let now = 1_000;
        let f = crate::folders::create(conn, "Work", None, now).unwrap();
        let t = crate::tags::create(conn, "email", Some("#3366ff")).unwrap();
        let e = crate::entries::create(
            conn,
            crate::entries::NewEntry {
                title: "GitHub".into(),
                folder_id: Some(f.id.clone()),
                notes: Some("n".into()),
                entry_type: "login".into(),
                fields: vec![
                    crate::entries::NewField {
                        template_id: Some("tpl_username".into()),
                        name: "Username".into(),
                        value: Some("me".into()),
                        is_protected: false,
                        field_type: "text".into(),
                    },
                    crate::entries::NewField {
                        template_id: Some("tpl_password".into()),
                        name: "Password".into(),
                        value: Some("s3cr3t".into()),
                        is_protected: true,
                        field_type: "secret".into(),
                    },
                ],
            },
            now,
        )
        .unwrap();
        crate::tags::set_entry_tags(conn, &e.id, &[t.id.clone()], now).unwrap();
        crate::tags::toggle_favorite(conn, &e.id, now).unwrap();
    }

    #[test]
    fn export_shape_has_plaintext_and_excludes_reserved_favorite_tag() {
        let conn = db::create_fresh().unwrap();
        seed(&conn);
        let b = export(&conn, None, "0.1.0", 42).unwrap();
        assert_eq!(b.format, EXPORT_FORMAT);
        assert_eq!(b.version, EXPORT_VERSION);
        assert_eq!(b.fidelity, FIDELITY);
        assert_eq!(b.exported_at, 42);
        assert_eq!(b.data.entries.len(), 1);
        let e = &b.data.entries[0];
        assert!(e.is_favorite);
        let pw = e.fields.iter().find(|f| f.name == "Password").unwrap();
        assert_eq!(pw.value.as_deref(), Some("s3cr3t"));
        assert!(b.data.tags.iter().all(|t| t.name != "favorite"));
        assert!(e.tags.iter().all(|id| !id.is_empty()));
        assert!(b.data.templates.iter().all(|t| !t.id.starts_with("tpl_")));
    }

    #[test]
    fn export_excludes_trashed_and_dead_relations() {
        let conn = db::create_fresh().unwrap();
        let now = 5;
        let a = crate::entries::create(
            &conn,
            crate::entries::NewEntry {
                title: "A".into(),
                folder_id: None,
                notes: None,
                entry_type: "login".into(),
                fields: vec![],
            },
            now,
        )
        .unwrap();
        let b_ = crate::entries::create(
            &conn,
            crate::entries::NewEntry {
                title: "B".into(),
                folder_id: None,
                notes: None,
                entry_type: "login".into(),
                fields: vec![],
            },
            now,
        )
        .unwrap();
        crate::relations::add(&conn, &a.id, &b_.id, "related", now).unwrap();
        crate::entries::soft_delete(&conn, &b_.id, now).unwrap();
        let bundle = export(&conn, None, "0.1.0", now).unwrap();
        assert_eq!(bundle.data.entries.len(), 1);
        assert_eq!(bundle.data.relations.len(), 0);
    }

    #[test]
    fn export_selected_ids_only() {
        let conn = db::create_fresh().unwrap();
        let now = 5;
        let a = crate::entries::create(
            &conn,
            crate::entries::NewEntry {
                title: "A".into(),
                folder_id: None,
                notes: None,
                entry_type: "login".into(),
                fields: vec![],
            },
            now,
        )
        .unwrap();
        let _b = crate::entries::create(
            &conn,
            crate::entries::NewEntry {
                title: "B".into(),
                folder_id: None,
                notes: None,
                entry_type: "login".into(),
                fields: vec![],
            },
            now,
        )
        .unwrap();
        let bundle = export(&conn, Some(&[a.id.clone()]), "0.1.0", now).unwrap();
        assert_eq!(bundle.data.entries.len(), 1);
        assert_eq!(bundle.data.entries[0].title, "A");
    }

    #[test]
    fn roundtrip_export_import_into_empty() {
        let src = db::create_fresh().unwrap();
        seed(&src);
        let now = 1_000;
        let a = crate::entries::create(
            &src,
            crate::entries::NewEntry {
                title: "A".into(),
                folder_id: None,
                notes: None,
                entry_type: "login".into(),
                fields: vec![],
            },
            now,
        )
        .unwrap();
        let b_ = crate::entries::create(
            &src,
            crate::entries::NewEntry {
                title: "B".into(),
                folder_id: None,
                notes: None,
                entry_type: "login".into(),
                fields: vec![],
            },
            now,
        )
        .unwrap();
        crate::relations::add(&src, &a.id, &b_.id, "related", now).unwrap();

        let json = to_json(&export(&src, None, "0.1.0", now).unwrap()).unwrap();
        let bundle = parse(&json).unwrap();

        let dst = db::create_fresh().unwrap();
        let rep = import(&dst, &bundle, 2_000).unwrap();
        assert_eq!(rep.entries, 3);
        assert_eq!(rep.relations, 1);
        assert_eq!(rep.skipped_relations, 0);
        let live = crate::entries::list(&dst, crate::entries::View::All).unwrap();
        assert_eq!(live.len(), 3);
        assert!(live.iter().all(|e| e.id != a.id && e.id != b_.id));
    }

    #[test]
    fn import_never_overwrites_reimport_duplicates() {
        let src = db::create_fresh().unwrap();
        seed(&src);
        let bundle = export(&src, None, "0.1.0", 1).unwrap();
        let dst = db::create_fresh().unwrap();
        import(&dst, &bundle, 2).unwrap();
        import(&dst, &bundle, 3).unwrap();
        assert_eq!(
            crate::entries::list(&dst, crate::entries::View::All)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn import_dedups_folder_and_tag_by_name() {
        let src = db::create_fresh().unwrap();
        seed(&src);
        let bundle = export(&src, None, "0.1.0", 1).unwrap();
        let dst = db::create_fresh().unwrap();
        crate::folders::create(&dst, "Work", None, 1).unwrap();
        crate::tags::create(&dst, "email", Some("#000000")).unwrap();
        let rep = import(&dst, &bundle, 2).unwrap();
        assert_eq!(rep.folders_new, 0);
        assert_eq!(rep.tags_new, 0);
    }

    #[test]
    fn import_preserves_timestamps_and_history() {
        let src = db::create_fresh().unwrap();
        let now = 777;
        let e = crate::entries::create(
            &src,
            crate::entries::NewEntry {
                title: "T".into(),
                folder_id: None,
                notes: None,
                entry_type: "login".into(),
                fields: vec![crate::entries::NewField {
                    template_id: None,
                    name: "note".into(),
                    value: Some("v1".into()),
                    is_protected: false,
                    field_type: "text".into(),
                }],
            },
            now,
        )
        .unwrap();
        src.execute("INSERT INTO entry_field_history (id, entry_id, field_name, value, changed_at) VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![uuid::Uuid::new_v4().to_string(), e.id, "note", "old", 700]).unwrap();
        let bundle = export(&src, None, "0.1.0", now).unwrap();
        let dst = db::create_fresh().unwrap();
        import(&dst, &bundle, 9_999).unwrap();
        let (created, hist): (i64, i64) = dst.query_row(
            "SELECT e.created_at, (SELECT COUNT(*) FROM entry_field_history h WHERE h.entry_id=e.id) FROM entries e LIMIT 1",
            [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(created, 777);
        assert_eq!(hist, 1);
    }

    #[test]
    fn import_reject_foreign_format() {
        assert!(matches!(parse("{\"format\":\"other\",\"version\":1,\"exported_at\":0,\"app_version\":\"x\",\"fidelity\":\"mid\",\"data\":{\"folders\":[],\"tags\":[],\"templates\":[],\"entries\":[],\"relations\":[]}}"),
            Err(VaultError::ImportUnsupported)));
        assert!(matches!(parse("not json at all"), Err(_)));
    }

    #[test]
    fn import_maps_custom_template_and_field_reference() {
        let src = db::create_fresh().unwrap();
        let now = 100;
        let tpl = crate::templates::create(&src, "Recovery Code", "secret", true).unwrap();
        crate::entries::create(
            &src,
            crate::entries::NewEntry {
                title: "Acct".into(),
                folder_id: None,
                notes: None,
                entry_type: "login".into(),
                fields: vec![crate::entries::NewField {
                    template_id: Some(tpl.id.clone()),
                    name: "Recovery Code".into(),
                    value: Some("abc".into()),
                    is_protected: true,
                    field_type: "secret".into(),
                }],
            },
            now,
        )
        .unwrap();
        let bundle = export(&src, None, "0.1.0", now).unwrap();
        assert_eq!(bundle.data.templates.len(), 1);

        let dst = db::create_fresh().unwrap();
        let rep = import(&dst, &bundle, 200).unwrap();
        assert_eq!(rep.templates_new, 1);
        let tpl_name: Option<String> = dst.query_row(
            "SELECT ft.name FROM entry_fields ef LEFT JOIN field_templates ft ON ft.id = ef.template_id
             WHERE ef.name = 'Recovery Code'", [], |r| r.get(0)).unwrap();
        assert_eq!(
            tpl_name.as_deref(),
            Some("Recovery Code"),
            "field remapped to the custom template, not orphaned"
        );
    }

    #[test]
    fn import_normalizes_out_of_set_field_type() {
        let dst = db::create_fresh().unwrap();
        let bundle = ExportBundle {
            format: "kokos-export".into(),
            version: 1,
            exported_at: 100,
            app_version: "0.1.0".into(),
            fidelity: "mid".into(),
            data: ExportData {
                folders: vec![],
                tags: vec![],
                templates: vec![],
                entries: vec![ExportEntry {
                    id: "srcentry".into(),
                    folder_id: None,
                    title: "Legacy".into(),
                    notes: None,
                    is_favorite: false,
                    entry_type: "login".into(),
                    created_at: 1,
                    updated_at: 1,
                    fields: vec![ExportField {
                        template_id: None,
                        name: "Weird".into(),
                        value: Some("v".into()),
                        is_protected: false,
                        field_type: "bogus".into(),
                        sort_order: 0,
                    }],
                    tags: vec![],
                    history: vec![],
                }],
                relations: vec![],
            },
        };
        let rep = import(&dst, &bundle, 2).expect("import must succeed, not roll back on a bad field_type");
        assert_eq!(rep.entries, 1);
        let stored: String = dst
            .query_row(
                "SELECT field_type FROM entry_fields WHERE name = 'Weird'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, "text");
    }

    #[test]
    fn import_preserves_phone_field_type() {
        let dst = db::create_fresh().unwrap();
        let bundle = ExportBundle {
            format: "kokos-export".into(),
            version: 1,
            exported_at: 100,
            app_version: "0.1.0".into(),
            fidelity: "mid".into(),
            data: ExportData {
                folders: vec![],
                tags: vec![],
                templates: vec![],
                entries: vec![ExportEntry {
                    id: "srcentry".into(),
                    folder_id: None,
                    title: "Contact".into(),
                    notes: None,
                    is_favorite: false,
                    entry_type: "login".into(),
                    created_at: 1,
                    updated_at: 1,
                    fields: vec![ExportField {
                        template_id: None,
                        name: "Mobile".into(),
                        value: Some("+15551234567".into()),
                        is_protected: false,
                        field_type: "phone".into(),
                        sort_order: 0,
                    }],
                    tags: vec![],
                    history: vec![],
                }],
                relations: vec![],
            },
        };
        let rep = import(&dst, &bundle, 2).expect("import must succeed for a 'phone' field_type");
        assert_eq!(rep.entries, 1);
        let stored: String = dst
            .query_row(
                "SELECT field_type FROM entry_fields WHERE name = 'Mobile'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, "phone", "phone field_type must round-trip through export->import, not degrade to text");
    }

    #[test]
    fn import_normalizes_out_of_set_template_field_type() {
        let dst = db::create_fresh().unwrap();
        let bundle = ExportBundle {
            format: "kokos-export".into(),
            version: 1,
            exported_at: 100,
            app_version: "0.1.0".into(),
            fidelity: "mid".into(),
            data: ExportData {
                folders: vec![],
                tags: vec![],
                templates: vec![ExportTemplate {
                    id: "srctpl".into(),
                    name: "Legacy Template".into(),
                    field_type: "bogus".into(),
                    is_protected: false,
                    sort_order: 0,
                }],
                entries: vec![ExportEntry {
                    id: "srcentry".into(),
                    folder_id: None,
                    title: "Untouched".into(),
                    notes: None,
                    is_favorite: false,
                    entry_type: "login".into(),
                    created_at: 1,
                    updated_at: 1,
                    fields: vec![],
                    tags: vec![],
                    history: vec![],
                }],
                relations: vec![],
            },
        };
        let rep = import(&dst, &bundle, 2)
            .expect("import must succeed, not roll back the whole bundle on a bad template field_type");
        assert_eq!(rep.templates_new, 1);
        assert_eq!(rep.entries, 1, "the unrelated entry must not be lost to the rollback either");
        let stored: String = dst
            .query_row(
                "SELECT field_type FROM field_templates WHERE name = 'Legacy Template'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, "text");
    }

    #[test]
    fn import_none_parent_folder_dedups_against_root() {
        let dst = db::create_fresh().unwrap();
        let bundle = ExportBundle {
            format: "kokos-export".into(),
            version: 1,
            exported_at: 100,
            app_version: "0.1.0".into(),
            fidelity: "mid".into(),
            data: ExportData {
                folders: vec![ExportFolder {
                    id: "srcfolder".into(),
                    parent_id: None,
                    name: "Imported".into(),
                    sort_order: 0,
                    created_at: 1,
                    updated_at: 1,
                }],
                tags: vec![],
                templates: vec![],
                entries: vec![],
                relations: vec![],
            },
        };
        let r1 = import(&dst, &bundle, 2).unwrap();
        assert_eq!(r1.folders_new, 1, "first import creates the folder once");
        let r2 = import(&dst, &bundle, 3).unwrap();
        assert_eq!(r2.folders_new, 0, "re-import must dedup, not duplicate");

        let count: i64 = dst
            .query_row(
                "SELECT COUNT(*) FROM folders WHERE name='Imported' AND parent_id='root'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "exactly one top-level 'Imported' folder");
    }

    #[test]
    fn import_unresolved_parent_folder_dedups_against_root() {
        let dst = db::create_fresh().unwrap();
        let bundle = ExportBundle {
            format: "kokos-export".into(),
            version: 1,
            exported_at: 100,
            app_version: "0.1.0".into(),
            fidelity: "mid".into(),
            data: ExportData {
                folders: vec![ExportFolder {
                    id: "dangling_folder".into(),
                    parent_id: Some("nonexistent_parent_id".into()),
                    name: "Orphaned".into(),
                    sort_order: 0,
                    created_at: 1,
                    updated_at: 1,
                }],
                tags: vec![],
                templates: vec![],
                entries: vec![],
                relations: vec![],
            },
        };
        let r1 = import(&dst, &bundle, 2).unwrap();
        assert_eq!(r1.folders_new, 1, "first import creates the unresolved folder at root");
        let r2 = import(&dst, &bundle, 3).unwrap();
        assert_eq!(r2.folders_new, 0, "re-import of unresolved folder must dedup, not duplicate");

        let count: i64 = dst
            .query_row(
                "SELECT COUNT(*) FROM folders WHERE name='Orphaned' AND parent_id='root'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "exactly one 'Orphaned' folder under root");
    }

    /// Selective export must carry only metadata the selected entries use;
    /// full export stays unfiltered; ancestors of a used folder are kept.
    fn seed_selective(conn: &rusqlite::Connection) -> (String, String) {
        let now = 7;
        let top = crate::folders::create(conn, "Top", None, now).unwrap();
        let mid = crate::folders::create(conn, "Mid", Some(&top.id), now).unwrap();
        let leaf = crate::folders::create(conn, "Leaf", Some(&mid.id), now).unwrap();
        let _unused = crate::folders::create(conn, "UnusedFolder", None, now).unwrap();
        let used_tag = crate::tags::create(conn, "usedtag", None).unwrap();
        let _unused_tag = crate::tags::create(conn, "unusedtag", Some("#112233")).unwrap();
        let used_tpl = crate::templates::create(conn, "UsedTpl", "text", false).unwrap();
        let _unused_tpl = crate::templates::create(conn, "UnusedTpl", "text", false).unwrap();
        let mk = |title: &str, folder: Option<String>, tpl: Option<String>| {
            crate::entries::create(
                conn,
                crate::entries::NewEntry {
                    title: title.into(),
                    folder_id: folder,
                    notes: None,
                    entry_type: "login".into(),
                    fields: vec![crate::entries::NewField {
                        template_id: tpl,
                        name: "F".into(),
                        value: Some("v".into()),
                        is_protected: false,
                        field_type: "text".into(),
                    }],
                },
                now,
            )
            .unwrap()
        };
        let sel = mk("Selected", Some(leaf.id.clone()), Some(used_tpl.id.clone()));
        crate::tags::set_entry_tags(conn, &sel.id, &[used_tag.id.clone()], now).unwrap();
        let other = mk("Other", None, None);
        (sel.id, other.id)
    }

    #[test]
    fn selective_export_omits_unreferenced_folder_tag_template() {
        let conn = db::create_fresh().unwrap();
        let (sel, _other) = seed_selective(&conn);
        let b = export(&conn, Some(&[sel]), "0.1.0", 1).unwrap();
        assert_eq!(b.data.entries.len(), 1);
        assert!(b.data.folders.iter().all(|f| f.name != "UnusedFolder"));
        let tag_names: Vec<&str> = b.data.tags.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(tag_names, vec!["usedtag"]);
        let tpl_names: Vec<&str> = b.data.templates.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(tpl_names, vec!["UsedTpl"]);
    }

    #[test]
    fn selective_export_keeps_ancestor_folders_of_referenced_folder() {
        let conn = db::create_fresh().unwrap();
        let (sel, _other) = seed_selective(&conn);
        let b = export(&conn, Some(&[sel]), "0.1.0", 1).unwrap();
        let names: Vec<&str> = b.data.folders.iter().map(|f| f.name.as_str()).collect();
        for want in ["Leaf", "Mid", "Top"] {
            assert!(names.contains(&want), "ancestor chain must keep {want}");
        }
        // Every kept folder's parent must itself be kept (or be absent from the vault).
        for f in &b.data.folders {
            if let Some(p) = &f.parent_id {
                assert!(
                    b.data.folders.iter().any(|x| &x.id == p),
                    "parent {p} of {} must be present",
                    f.name
                );
            }
        }
    }

    #[test]
    fn full_export_still_includes_all_metadata() {
        let conn = db::create_fresh().unwrap();
        seed_selective(&conn);
        let b = export(&conn, None, "0.1.0", 1).unwrap();
        assert!(b.data.folders.iter().any(|f| f.name == "UnusedFolder"));
        let tag_names: Vec<&str> = b.data.tags.iter().map(|t| t.name.as_str()).collect();
        assert!(tag_names.contains(&"usedtag") && tag_names.contains(&"unusedtag"));
        let tpl_names: Vec<&str> = b.data.templates.iter().map(|t| t.name.as_str()).collect();
        assert!(tpl_names.contains(&"UsedTpl") && tpl_names.contains(&"UnusedTpl"));
    }

    fn bundle_of(
        folders: Vec<ExportFolder>,
        tags: Vec<ExportTag>,
        entries: Vec<ExportEntry>,
        relations: Vec<ExportRelation>,
    ) -> ExportBundle {
        ExportBundle {
            format: EXPORT_FORMAT.into(),
            version: EXPORT_VERSION,
            exported_at: 1,
            app_version: "0.1.0".into(),
            fidelity: FIDELITY.into(),
            data: ExportData {
                folders,
                tags,
                templates: vec![],
                entries,
                relations,
            },
        }
    }

    fn bare_entry(id: &str, tags: Vec<String>) -> ExportEntry {
        ExportEntry {
            id: id.into(),
            folder_id: None,
            title: id.into(),
            notes: None,
            is_favorite: false,
            entry_type: "login".into(),
            created_at: 1,
            updated_at: 1,
            fields: vec![],
            tags,
            history: vec![],
        }
    }

    #[test]
    fn roundtrip_preserves_non_login_entry_type() {
        let src = db::create_fresh().unwrap();
        crate::entries::create(
            &src,
            crate::entries::NewEntry {
                title: "Visa".into(),
                folder_id: None,
                notes: None,
                entry_type: "card".into(),
                fields: vec![],
            },
            1,
        )
        .unwrap();
        let json = to_json(&export(&src, None, "0.1.0", 1).unwrap()).unwrap();
        let bundle = parse(&json).unwrap();
        assert_eq!(bundle.data.entries[0].entry_type, "card");
        let dst = db::create_fresh().unwrap();
        import(&dst, &bundle, 2).unwrap();
        let t: String = dst
            .query_row("SELECT entry_type FROM entries WHERE title='Visa'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(t, "card");
    }

    #[test]
    fn import_defaults_missing_and_invalid_entry_type_to_login() {
        let mut bad = bare_entry("bad", vec![]);
        bad.entry_type = "spaceship".into();
        let mut json = to_json(&bundle_of(vec![], vec![], vec![bare_entry("old", vec![])], vec![]))
            .unwrap();
        json = json.replace("\"entry_type\": \"login\",", "");
        let old = parse(&json).unwrap();
        assert_eq!(old.data.entries[0].entry_type, "login");
        let dst = db::create_fresh().unwrap();
        import(&dst, &old, 2).unwrap();
        import(&dst, &bundle_of(vec![], vec![], vec![bad], vec![]), 2).unwrap();
        let n: i64 = dst
            .query_row("SELECT count(*) FROM entries WHERE entry_type='login' AND title IN ('old','bad')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn import_drops_invalid_tag_colour_and_skips_reserved_favorite() {
        let dst = db::create_fresh().unwrap();
        let tags = vec![
            ExportTag { id: "t1".into(), name: "work".into(), color: Some("not-a-colour".into()) },
            ExportTag { id: "t2".into(), name: crate::tags::FAVORITE_TAG.into(), color: None },
        ];
        let e = bare_entry("A", vec!["t1".into(), "t2".into()]);
        let rep = import(&dst, &bundle_of(vec![], tags, vec![e], vec![]), 2)
            .expect("a bad tag colour must not abort the import");
        assert_eq!(rep.tags_new, 1);
        let color: Option<String> = dst
            .query_row("SELECT color FROM tags WHERE name='work'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(color, None);
        let fav_links: i64 = dst
            .query_row(
                "SELECT count(*) FROM entry_tags et JOIN tags t ON t.id = et.tag_id WHERE t.name = ?1",
                [crate::tags::FAVORITE_TAG],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(fav_links, 0, "a non-favourite entry must not be favourited via a bundle tag");
    }

    #[test]
    fn import_skips_self_and_unknown_type_relations() {
        let dst = db::create_fresh().unwrap();
        let rel = |s: &str, t: &str, ty: &str| ExportRelation {
            source_id: s.into(),
            target_id: t.into(),
            relation_type: ty.into(),
            created_at: 1,
        };
        let b = bundle_of(
            vec![],
            vec![],
            vec![bare_entry("a", vec![]), bare_entry("b", vec![])],
            vec![rel("a", "a", "related"), rel("a", "b", "bogus"), rel("a", "b", "related")],
        );
        let rep = import(&dst, &b, 2).unwrap();
        assert_eq!(rep.relations, 1);
        assert_eq!(rep.skipped_relations, 2);
    }

    #[test]
    fn import_keeps_sort_order_of_created_folders() {
        let dst = db::create_fresh().unwrap();
        let folder = |id: &str, name: &str, order: i32| ExportFolder {
            id: id.into(),
            parent_id: None,
            name: name.into(),
            sort_order: order,
            created_at: 1,
            updated_at: 1,
        };
        import(&dst, &bundle_of(vec![folder("f1", "Second", 2), folder("f2", "First", 1)], vec![], vec![], vec![]), 2)
            .unwrap();
        let order: i32 = dst
            .query_row("SELECT sort_order FROM folders WHERE name='Second'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(order, 2);
    }

    #[test]
    fn import_caps_folder_depth() {
        let dst = db::create_fresh().unwrap();
        let n = MAX_FOLDER_DEPTH + 50;
        let folders: Vec<ExportFolder> = (0..n)
            .map(|i| ExportFolder {
                id: format!("f{i}"),
                parent_id: if i == 0 { None } else { Some(format!("f{}", i - 1)) },
                name: format!("F{i}"),
                sort_order: 0,
                created_at: 1,
                updated_at: 1,
            })
            .collect();
        let rep = import(&dst, &bundle_of(folders, vec![], vec![], vec![]), 2).unwrap();
        assert_eq!(rep.folders_new as usize, n, "every folder is still imported");
        let max_depth: i64 = dst
            .query_row(
                "WITH RECURSIVE d(id, depth) AS (
                     SELECT id, 1 FROM folders WHERE parent_id = 'root'
                     UNION ALL SELECT f.id, d.depth + 1 FROM folders f JOIN d ON f.parent_id = d.id)
                 SELECT max(depth) FROM d",
                [],
                |r| r.get(0),
            )
            .unwrap();
        // Overflow folders hang off the ancestor at the cap.
        assert_eq!(max_depth as usize, MAX_FOLDER_DEPTH + 1);
        let anchor: String = dst
            .query_row(
                "SELECT p.name FROM folders f JOIN folders p ON p.id = f.parent_id WHERE f.name = ?1",
                [format!("F{}", n - 1)],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(anchor, format!("F{}", MAX_FOLDER_DEPTH - 1));
    }
}

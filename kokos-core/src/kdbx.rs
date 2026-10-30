//! One-time KeePass `.kdbx` import. The file is UNTRUSTED: every parse
//! failure maps to a typed `VaultError` token (never a panic), and the size is
//! capped before decryption. `open` lowers the `keepass` database into an owned
//! `KdbxTree` so the mapping/import code and its tests never touch `keepass`
//! types. Password-only; key-file DBs fail closed via `KdbxWrongPassword`.

use rusqlite::{params, Connection};

use crate::error::{Result, VaultError};
use crate::portable::{find_folder_by_name, ImportReport};

pub const MAX_KDBX_SIZE: usize = 50 * 1024 * 1024;

#[derive(Debug)]
pub struct KdbxTree {
    pub root: KdbxGroup,
}

#[derive(Debug)]
pub struct KdbxGroup {
    pub name: String,
    pub groups: Vec<KdbxGroup>,
    pub entries: Vec<KdbxEntry>,
}

pub struct KdbxEntry {
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub totp_raw: Option<String>,
    pub custom: Vec<KdbxField>,
    pub binaries: Vec<KdbxBinary>,
    pub tags: Vec<String>,
}

impl std::fmt::Debug for KdbxEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KdbxEntry")
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("url", &self.url)
            .field("notes", &self.notes)
            .field("totp_raw", &self.totp_raw.as_ref().map(|_| "<redacted>"))
            .field("custom", &self.custom)
            .field("binaries_count", &self.binaries.len())
            .field("tags", &self.tags)
            .finish()
    }
}

pub struct KdbxField {
    pub name: String,
    pub value: String,
    pub protected: bool,
}

impl std::fmt::Debug for KdbxField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KdbxField")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("protected", &self.protected)
            .finish()
    }
}

#[derive(Debug)]
pub struct KdbxBinary {
    pub filename: String,
    pub data: Vec<u8>,
}

pub fn open(bytes: &[u8], password: &str) -> Result<KdbxTree> {
    if bytes.len() > MAX_KDBX_SIZE {
        return Err(VaultError::KdbxTooLarge);
    }
    use keepass::{Database, DatabaseKey};
    let key = DatabaseKey::new().with_password(password);
    let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Database::open(&mut &bytes[..], key)
    }));
    let db = match opened {
        Ok(Ok(db)) => db,
        Ok(Err(e)) => return Err(map_open_err(e)),
        Err(_) => return Err(VaultError::KdbxCorrupt),
    };
    let recycle = db.meta.recyclebin_uuid.filter(|u| !u.is_nil());
    Ok(KdbxTree {
        root: lower_group(&db.root, recycle.as_ref()),
    })
}

fn map_open_err(e: keepass::error::DatabaseOpenError) -> VaultError {
    use keepass::error::{DatabaseKeyError, DatabaseOpenError as E};
    match e {
        E::Key(DatabaseKeyError::IncorrectKey) => VaultError::KdbxWrongPassword,
        E::UnsupportedVersion => VaultError::KdbxUnsupported,
        _ => VaultError::KdbxCorrupt,
    }
}

fn lower_group(g: &keepass::db::Group, recycle: Option<&uuid::Uuid>) -> KdbxGroup {
    use keepass::db::Node;
    let mut groups = Vec::new();
    let mut entries = Vec::new();
    for node in &g.children {
        match node {
            Node::Group(child) => {
                if recycle == Some(&child.uuid) {
                    continue;
                }
                groups.push(lower_group(child, recycle));
            }
            Node::Entry(e) => entries.push(lower_entry(e)),
        }
    }
    KdbxGroup {
        name: g.name.clone(),
        groups,
        entries,
    }
}

fn lower_entry(e: &keepass::db::Entry) -> KdbxEntry {
    let title = field_str(e, "Title").unwrap_or_default();
    let username = field_str(e, "UserName");
    let password = field_str(e, "Password");
    let url = field_str(e, "URL");
    let notes = field_str(e, "Notes");
    let totp_raw = [
        "otp",
        "TOTP Seed",
        "TimeOtp-Secret-Base32",
        "TimeOtp-Secret",
    ]
    .iter()
    .find_map(|k| field_str(e, k));
    const STD: [&str; 8] = [
        "Title",
        "UserName",
        "Password",
        "URL",
        "Notes",
        "otp",
        "TOTP Seed",
        "TimeOtp-Secret-Base32",
    ];
    let mut custom = Vec::new();
    for (name, value) in &e.fields {
        if STD.contains(&name.as_str()) || name == "TimeOtp-Secret" {
            continue;
        }
        if let Some(v) = value_str(value) {
            custom.push(KdbxField {
                name: name.clone(),
                value: v,
                protected: is_protected(value),
            });
        }
    }
    let tags = e
        .tags
        .iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    KdbxEntry {
        title,
        username,
        password,
        url,
        notes,
        totp_raw,
        custom,
        binaries: lower_binaries(e),
        tags,
    }
}

/// The string content of a field (Unprotected/Protected), `None` if absent or
/// a raw byte value.
fn field_str(e: &keepass::db::Entry, key: &str) -> Option<String> {
    e.fields.get(key).and_then(value_str)
}

/// String content for Unprotected/Protected, `None` for `Value::Bytes`.
fn value_str(v: &keepass::db::Value) -> Option<String> {
    use keepass::db::Value;
    match v {
        Value::Unprotected(s) => Some(s.clone()),
        Value::Protected(p) => std::str::from_utf8(p.unsecure()).ok().map(str::to_string),
        Value::Bytes(_) => None,
    }
}

fn is_protected(v: &keepass::db::Value) -> bool {
    matches!(v, keepass::db::Value::Protected(_))
}

/// keepass 0.8.7 parses per-entry `<Binary>` XML references but discards them
/// (see `xml_db/parse/entry.rs`: the parsed `BinaryField` result is dropped
/// with a `// TODO reference into a binary field from the Meta` comment) and
/// exposes no stable per-entry binary attachment field on `Entry`. So this
/// always returns empty for this crate version; revisit if
/// upstream adds the mapping.
fn lower_binaries(_e: &keepass::db::Entry) -> Vec<KdbxBinary> {
    vec![]
}

/// Additive merge of a parsed `.kdbx` tree into the OPEN vault. Mirrors
/// `portable::import`'s machinery: one outer transaction, fresh uuid per
/// entry/field, INSERT-only, existing rows untouched. Never writes
/// `nmh_grants` -- a supplied file must never inject a grant.
pub fn import(conn: &Connection, tree: &KdbxTree, now: i64) -> Result<ImportReport> {
    let mut rep = ImportReport::default();
    let tx = conn.unchecked_transaction()?;
    import_group(&tx, &tree.root, Some("root"), Some("root"), now, &mut rep)?;
    tx.commit()?;
    Ok(rep)
}

fn import_group(
    tx: &Connection,
    g: &KdbxGroup,
    entry_folder: Option<&str>,
    child_parent: Option<&str>,
    now: i64,
    rep: &mut ImportReport,
) -> Result<()> {
    for e in &g.entries {
        import_entry(tx, e, entry_folder, now, rep)?;
    }
    for child in &g.groups {
        let fid = match find_folder_by_name(tx, child_parent, &child.name)? {
            Some(id) => id,
            None => {
                let f = crate::folders::create(tx, &child.name, child_parent, now)?;
                rep.folders_new += 1;
                f.id
            }
        };
        import_group(tx, child, Some(&fid), Some(&fid), now, rep)?;
    }
    Ok(())
}

fn ensure_tag(tx: &Connection, name: &str, rep: &mut ImportReport) -> Result<Option<String>> {
    let name = name.trim();
    if name.is_empty() || name.eq_ignore_ascii_case(crate::tags::FAVORITE_TAG) {
        return Ok(None);
    }
    use rusqlite::OptionalExtension;
    let existing: Option<String> = tx
        .query_row("SELECT id FROM tags WHERE name = ?1", [name], |r| r.get(0))
        .optional()?;
    let id = match existing {
        Some(id) => id,
        None => {
            let created = crate::tags::create(tx, name, None)?;
            rep.tags_new += 1;
            created.id
        }
    };
    Ok(Some(id))
}

fn import_entry(
    tx: &Connection,
    e: &KdbxEntry,
    folder: Option<&str>,
    now: i64,
    rep: &mut ImportReport,
) -> Result<()> {
    let entry_id = uuid::Uuid::new_v4().to_string();
    tx.execute(
        "INSERT INTO entries (id, folder_id, title, notes, is_favorite, is_deleted, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 0, 0, ?5, ?5)",
        params![entry_id, folder, e.title, e.notes, now],
    )?;
    let mut sort: i64 = 0;
    if let Some(v) = &e.username {
        insert_field(
            tx,
            &entry_id,
            Some("tpl_username"),
            "Username",
            v,
            false,
            "text",
            &mut sort,
        )?;
    }
    if let Some(v) = &e.password {
        insert_field(
            tx,
            &entry_id,
            Some("tpl_password"),
            "Password",
            v,
            true,
            "secret",
            &mut sort,
        )?;
    }
    if let Some(v) = &e.url {
        insert_field(
            tx,
            &entry_id,
            Some("tpl_url"),
            "URL",
            v,
            false,
            "url",
            &mut sort,
        )?;
    }
    if let Some(raw) = &e.totp_raw {
        if let Some(uri) = totp_uri(&e.title, raw) {
            insert_field(
                tx,
                &entry_id,
                Some("tpl_totp"),
                "TOTP",
                &uri,
                true,
                "otp",
                &mut sort,
            )?;
        }
    }
    for c in &e.custom {
        let lname = c.name.to_lowercase();
        if lname == "email" || lname == "e-mail" {
            insert_field(
                tx,
                &entry_id,
                Some("tpl_email"),
                &c.name,
                &c.value,
                c.protected,
                "email",
                &mut sort,
            )?;
        } else {
            let ft = if c.protected { "secret" } else { "text" };
            insert_field(
                tx,
                &entry_id,
                None,
                &c.name,
                &c.value,
                c.protected,
                ft,
                &mut sort,
            )?;
        }
    }
    for b in &e.binaries {
        match crate::attachments::add(tx, &entry_id, &b.filename, None, &b.data, now) {
            Ok(_) => {}
            Err(VaultError::AttachmentTooLarge) => rep.skipped_attachments += 1,
            Err(err) => return Err(err),
        }
    }
    for tag_name in &e.tags {
        if let Some(tag_id) = ensure_tag(tx, tag_name, rep)? {
            tx.execute(
                "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?1, ?2)",
                params![entry_id, tag_id],
            )?;
        }
    }
    rep.entries += 1;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_field(
    tx: &Connection,
    entry_id: &str,
    template_id: Option<&str>,
    name: &str,
    value: &str,
    is_protected: bool,
    field_type: &str,
    sort: &mut i64,
) -> Result<()> {
    tx.execute(
        "INSERT INTO entry_fields (id, entry_id, template_id, name, value, is_protected, field_type, sort_order)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            uuid::Uuid::new_v4().to_string(),
            entry_id,
            template_id,
            name,
            value,
            is_protected as i64,
            field_type,
            *sort
        ],
    )?;
    *sort += 1;
    Ok(())
}

fn totp_uri(title: &str, raw: &str) -> Option<String> {
    let candidate = if raw.trim_start().starts_with("otpauth://") {
        raw.trim().to_string()
    } else {
        let label: String = title.chars().filter(|c| c.is_alphanumeric()).collect();
        let label = if label.is_empty() {
            "Account".to_string()
        } else {
            label
        };
        format!("otpauth://totp/{}?secret={}", label, raw.trim())
    };
    crate::totp::parse(&candidate).ok().map(|_| candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn entry(title: &str) -> KdbxEntry {
        KdbxEntry {
            title: title.into(),
            username: None,
            password: None,
            url: None,
            notes: None,
            totp_raw: None,
            custom: vec![],
            binaries: vec![],
            tags: vec![],
        }
    }
    fn one(root_entries: Vec<KdbxEntry>, groups: Vec<KdbxGroup>) -> KdbxTree {
        KdbxTree {
            root: KdbxGroup {
                name: "Root".into(),
                groups,
                entries: root_entries,
            },
        }
    }

    #[test]
    fn import_maps_standard_fields() {
        let conn = db::create_fresh().unwrap();
        let mut e = entry("GitHub");
        e.username = Some("me".into());
        e.password = Some("s3cr3t".into());
        e.url = Some("https://github.com".into());
        e.notes = Some("hello".into());
        let rep = import(&conn, &one(vec![e], vec![]), 1_000).unwrap();
        assert_eq!(rep.entries, 1);
        let (title, notes, folder): (String, Option<String>, Option<String>) = conn
            .query_row("SELECT title, notes, folder_id FROM entries", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(title, "GitHub");
        assert_eq!(notes.as_deref(), Some("hello"));
        assert_eq!(folder.as_deref(), Some("root"));
        let pw: (String, String, i64) = conn
            .query_row(
                "SELECT template_id, field_type, is_protected FROM entry_fields WHERE name='Password'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(pw, ("tpl_password".into(), "secret".into(), 1));
    }

    #[test]
    fn import_builds_totp_uri_from_seed() {
        let conn = db::create_fresh().unwrap();
        let mut e = entry("MFA");
        e.totp_raw = Some("JBSWY3DPEHPK3PXP".into());
        import(&conn, &one(vec![e], vec![]), 1_000).unwrap();
        let (tpl, ft, val): (String, String, String) = conn
            .query_row(
                "SELECT template_id, field_type, value FROM entry_fields WHERE name='TOTP'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(tpl, "tpl_totp");
        assert_eq!(ft, "otp");
        assert!(val.starts_with("otpauth://totp/"));
        assert!(crate::totp::parse(&val).is_ok());
    }

    #[test]
    fn import_maps_custom_email_and_protected() {
        let conn = db::create_fresh().unwrap();
        let mut e = entry("Acct");
        e.custom = vec![
            KdbxField {
                name: "Email".into(),
                value: "a@b.com".into(),
                protected: false,
            },
            KdbxField {
                name: "Recovery".into(),
                value: "note".into(),
                protected: false,
            },
            KdbxField {
                name: "Backup Code".into(),
                value: "xyz".into(),
                protected: true,
            },
        ];
        import(&conn, &one(vec![e], vec![]), 1_000).unwrap();
        let email: (Option<String>, String) = conn
            .query_row(
                "SELECT template_id, field_type FROM entry_fields WHERE name='Email'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(email, (Some("tpl_email".into()), "email".into()));
        let rec: (Option<String>, String) = conn
            .query_row(
                "SELECT template_id, field_type FROM entry_fields WHERE name='Recovery'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(rec, (None, "text".into()));
        let bkp: (Option<String>, String, i64) = conn
            .query_row(
                "SELECT template_id, field_type, is_protected FROM entry_fields WHERE name='Backup Code'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(bkp, (None, "secret".into(), 1));
    }

    #[test]
    fn import_nests_folders_and_dedupes() {
        let conn = db::create_fresh().unwrap();
        let inner = KdbxGroup {
            name: "Sub".into(),
            groups: vec![],
            entries: vec![entry("A"), entry("B")],
        };
        let outer = KdbxGroup {
            name: "Work".into(),
            groups: vec![inner],
            entries: vec![],
        };
        let tree = one(
            vec![],
            vec![
                outer,
                KdbxGroup {
                    name: "Work".into(),
                    groups: vec![],
                    entries: vec![entry("C")],
                },
            ],
        );
        import(&conn, &tree, 1_000).unwrap();
        let work_folders: i64 = conn
            .query_row("SELECT count(*) FROM folders WHERE name='Work'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(work_folders, 1);
        let sub_parent: String = conn
            .query_row("SELECT parent_id FROM folders WHERE name='Sub'", [], |r| {
                r.get(0)
            })
            .unwrap();
        let work_id: String = conn
            .query_row("SELECT id FROM folders WHERE name='Work'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sub_parent, work_id);
    }

    #[test]
    fn import_binary_added_and_oversized_skipped() {
        let conn = db::create_fresh().unwrap();
        let mut ok = entry("HasFile");
        ok.binaries = vec![KdbxBinary {
            filename: "a.txt".into(),
            data: vec![1, 2, 3],
        }];
        let mut big = entry("TooBig");
        big.binaries = vec![KdbxBinary {
            filename: "big.bin".into(),
            data: vec![0u8; crate::attachments::MAX_ATTACHMENT_SIZE + 1],
        }];
        let rep = import(&conn, &one(vec![ok, big], vec![]), 1_000).unwrap();
        assert_eq!(rep.skipped_attachments, 1);
        let n: i64 = conn
            .query_row("SELECT count(*) FROM attachments", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn import_is_additive_and_never_touches_nmh_grants() {
        let conn = db::create_fresh().unwrap();
        let pre = crate::entries::create(
            &conn,
            crate::entries::NewEntry {
                title: "Keep".into(),
                folder_id: None,
                notes: None,
                entry_type: "login".into(),
                fields: vec![],
            },
            1,
        )
        .unwrap();
        let grants_before: i64 = conn
            .query_row("SELECT count(*) FROM nmh_grants", [], |r| r.get(0))
            .unwrap();
        import(&conn, &one(vec![entry("New")], vec![]), 2_000).unwrap();
        let still: i64 = conn
            .query_row("SELECT count(*) FROM entries WHERE id=?1", [&pre.id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(still, 1);
        let grants_after: i64 = conn
            .query_row("SELECT count(*) FROM nmh_grants", [], |r| r.get(0))
            .unwrap();
        assert_eq!(grants_after, grants_before);
    }

    #[test]
    fn import_maps_entry_tags_additively() {
        let conn = db::create_fresh().unwrap();
        let mut a = entry("A");
        a.tags = vec!["work".into(), "email".into()];
        let mut b = entry("B");
        b.tags = vec!["work".into()];
        let rep = import(&conn, &one(vec![a, b], vec![]), 1_000).unwrap();
        assert_eq!(rep.tags_new, 2);
        let names: i64 = conn
            .query_row(
                "SELECT count(*) FROM tags WHERE name IN ('work','email')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(names, 2);
        let links: i64 = conn
            .query_row("SELECT count(*) FROM entry_tags", [], |r| r.get(0))
            .unwrap();
        assert_eq!(links, 3);
    }

    #[test]
    fn import_skips_reserved_favorite_tag() {
        let conn = db::create_fresh().unwrap();
        let mut e = entry("A");
        e.tags = vec!["favorite".into(), "real".into()];
        let rep = import(&conn, &one(vec![e], vec![]), 1_000).unwrap();
        assert_eq!(rep.tags_new, 1);
        let real: i64 = conn
            .query_row("SELECT count(*) FROM tags WHERE name='real'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(real, 1);
        let fav: i64 = conn
            .query_row("SELECT count(*) FROM tags WHERE name='favorite'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(fav, 0);
    }

    #[test]
    fn import_only_uses_allowed_field_types() {
        let conn = db::create_fresh().unwrap();
        let mut e = entry("All");
        e.username = Some("u".into());
        e.password = Some("p".into());
        e.url = Some("x".into());
        e.totp_raw = Some("JBSWY3DPEHPK3PXP".into());
        e.custom = vec![
            KdbxField {
                name: "Email".into(),
                value: "a@b.com".into(),
                protected: false,
            },
            KdbxField {
                name: "Note".into(),
                value: "n".into(),
                protected: true,
            },
        ];
        import(&conn, &one(vec![e], vec![]), 1_000).unwrap();
        let mut stmt = conn
            .prepare("SELECT DISTINCT field_type FROM entry_fields")
            .unwrap();
        let types: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        let allowed = ["text", "secret", "url", "email", "otp", "date"];
        assert!(
            types.iter().all(|t| allowed.contains(&t.as_str())),
            "got {types:?}"
        );
    }

    fn mk_kdbx(password: &str, keyfile: Option<&[u8]>) -> Vec<u8> {
        use keepass::db::{Entry, Node, Value};
        use keepass::{Database, DatabaseKey};
        let mut db = Database::new(Default::default());
        db.root.name = "Root".to_string();
        let mut e = Entry::new();
        e.fields
            .insert("Title".into(), Value::Unprotected("GitHub".into()));
        e.fields
            .insert("UserName".into(), Value::Unprotected("me".into()));
        e.fields.insert(
            "Password".into(),
            Value::Protected("s3cr3t".as_bytes().into()),
        );
        db.root.children.push(Node::Entry(e));
        let mut key = DatabaseKey::new().with_password(password);
        if let Some(kf) = keyfile {
            key = key.with_keyfile(&mut &kf[..]).unwrap();
        }
        let mut out = Vec::new();
        db.save(&mut out, key).unwrap();
        out
    }

    #[test]
    fn open_good_returns_tree() {
        let bytes = mk_kdbx("pw", None);
        let tree = open(&bytes, "pw").unwrap();
        assert_eq!(tree.root.entries.len(), 1);
        let e = &tree.root.entries[0];
        assert_eq!(e.title, "GitHub");
        assert_eq!(e.username.as_deref(), Some("me"));
        assert_eq!(e.password.as_deref(), Some("s3cr3t"));
    }

    #[test]
    fn open_wrong_password_is_fail_closed() {
        let bytes = mk_kdbx("pw", None);
        assert!(matches!(
            open(&bytes, "nope"),
            Err(VaultError::KdbxWrongPassword)
        ));
    }

    #[test]
    fn open_corrupt_is_fail_closed() {
        assert!(matches!(
            open(b"not a kdbx file at all", "pw"),
            Err(VaultError::KdbxCorrupt)
        ));
    }

    #[test]
    fn open_oversized_is_rejected_before_parse() {
        let big = vec![0u8; MAX_KDBX_SIZE + 1];
        assert!(matches!(open(&big, "pw"), Err(VaultError::KdbxTooLarge)));
    }

    #[test]
    fn open_composite_key_required_maps_to_combined_bucket() {
        let bytes = mk_kdbx("pw", Some(b"my-key-file-bytes"));
        assert!(matches!(
            open(&bytes, "pw"),
            Err(VaultError::KdbxWrongPassword)
        ));
    }

    #[test]
    fn open_truncated_valid_header_is_fail_closed_no_panic() {
        let full = mk_kdbx("pw", None);
        for n in [12usize, 20, 40, 100, full.len().saturating_sub(1)] {
            let got = open(&full[..n.min(full.len())], "pw");
            assert!(got.is_err(), "truncation to {n} bytes must be Err, got Ok");
        }
        assert!(matches!(
            open(&full[..20], "pw"),
            Err(VaultError::KdbxCorrupt)
        ));
    }

    fn mk_kdbx_nested(password: &str, depth: usize) -> Vec<u8> {
        use keepass::db::{Group, Node};
        use keepass::{Database, DatabaseKey};
        let mut db = Database::new(Default::default());
        let mut chain = Group::new("g");
        for _ in 0..depth {
            let mut parent = Group::new("g");
            parent.children.push(Node::Group(chain));
            chain = parent;
        }
        db.root.children.push(Node::Group(chain));
        let mut out = Vec::new();
        db.save(&mut out, DatabaseKey::new().with_password(password))
            .unwrap();
        out
    }

    #[test]
    fn open_deeply_nested_groups_fails_closed_not_abort() {
        let deep = mk_kdbx_nested("pw", 500);
        assert!(
            matches!(open(&deep, "pw"), Err(VaultError::KdbxCorrupt)),
            "deep <Group> nesting must fail closed as KdbxCorrupt, not abort"
        );
    }

    #[test]
    fn open_moderately_nested_groups_still_imports() {
        let ok = mk_kdbx_nested("pw", 50);
        assert!(open(&ok, "pw").is_ok(), "50-deep nesting is legit and must still open");
    }

    fn mk_kdbx_deep_history(password: &str, depth: usize) -> Vec<u8> {
        use keepass::db::{Entry, History, Node, Value};
        use keepass::{Database, DatabaseKey};
        let mut db = Database::new(Default::default());
        let mut e = Entry::new();
        e.fields.insert("Title".into(), Value::Unprotected("leaf".into()));
        for _ in 0..depth {
            let mut parent = Entry::new();
            parent.history = Some(History { entries: vec![e] });
            e = parent;
        }
        db.root.children.push(Node::Entry(e));
        let mut out = Vec::new();
        db.save(&mut out, DatabaseKey::new().with_password(password))
            .unwrap();
        out
    }

    #[test]
    fn open_deeply_nested_entry_history_fails_closed_not_abort() {
        let deep = mk_kdbx_deep_history("pw", 300);
        assert!(
            matches!(open(&deep, "pw"), Err(VaultError::KdbxCorrupt)),
            "deep Entry/History nesting must fail closed as KdbxCorrupt, not abort"
        );
    }

    fn mk_kdbx_rich(password: &str) -> Vec<u8> {
        use keepass::db::{Entry, Group, Node, Value};
        use keepass::{Database, DatabaseKey};
        let mut db = Database::new(Default::default());
        db.root.name = "Root".to_string();
        let mut top = Entry::new();
        top.fields
            .insert("Title".into(), Value::Unprotected("GitHub".into()));
        top.fields
            .insert("UserName".into(), Value::Unprotected("me".into()));
        top.fields.insert(
            "Password".into(),
            Value::Protected("s3cr3t".as_bytes().into()),
        );
        db.root.children.push(Node::Entry(top));
        let mut sub = Group::new("Social");
        let mut e = Entry::new();
        e.fields
            .insert("Title".into(), Value::Unprotected("Twitter".into()));
        e.fields
            .insert("UserName".into(), Value::Unprotected("bird".into()));
        e.fields
            .insert("otp".into(), Value::Unprotected("JBSWY3DPEHPK3PXP".into()));
        e.fields
            .insert("Recovery".into(), Value::Unprotected("kittens".into()));
        e.tags.push("social".into());
        sub.children.push(Node::Entry(e));
        db.root.children.push(Node::Group(sub));
        let mut out = Vec::new();
        db.save(&mut out, DatabaseKey::new().with_password(password))
            .unwrap();
        out
    }

    #[test]
    fn round_trip_real_kdbx_bytes_into_vault() {
        let bytes = mk_kdbx_rich("pw");
        let tree = open(&bytes, "pw").unwrap();
        let conn = db::create_fresh().unwrap();
        let rep = import(&conn, &tree, 5_000).unwrap();
        assert_eq!(rep.entries, 2);
        let social: i64 = conn
            .query_row(
                "SELECT count(*) FROM folders WHERE name='Social'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(social, 1);
        let pass: String = conn
            .query_row(
                "SELECT value FROM entry_fields WHERE name='Password'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pass, "s3cr3t");
        let (tpl, val): (String, String) = conn
            .query_row(
                "SELECT template_id, value FROM entry_fields WHERE name='TOTP'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(tpl, "tpl_totp");
        assert!(val.starts_with("otpauth://totp/") && crate::totp::parse(&val).is_ok());
        let rec_tpl: Option<String> = conn
            .query_row(
                "SELECT template_id FROM entry_fields WHERE name='Recovery'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rec_tpl, None);
        let tag_exists: i64 = conn
            .query_row("SELECT count(*) FROM tags WHERE name='social'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(tag_exists, 1);
        let tag_linked: i64 = conn
            .query_row(
                "SELECT count(*) FROM entry_tags et
                 JOIN tags t ON t.id = et.tag_id
                 JOIN entries e ON e.id = et.entry_id
                 WHERE t.name = 'social' AND e.title = 'Twitter'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tag_linked, 1);
    }

    #[test]
    fn import_skips_recycle_bin_entries() {
        use keepass::db::{Entry, Group, Node, Value};
        use keepass::{Database, DatabaseKey};
        let mut db = Database::new(Default::default());
        db.root.name = "Root".to_string();
        let mut live = Entry::new();
        live.fields
            .insert("Title".into(), Value::Unprotected("LiveAcct".into()));
        db.root.children.push(Node::Entry(live));
        let mut bin = Group::new("Recycle Bin");
        let mut dead = Entry::new();
        dead.fields
            .insert("Title".into(), Value::Unprotected("DeletedAcct".into()));
        bin.children.push(Node::Entry(dead));
        let bin_uuid = bin.uuid;
        db.root.children.push(Node::Group(bin));
        db.meta.recyclebin_uuid = Some(bin_uuid);

        let mut bytes = Vec::new();
        db.save(&mut bytes, DatabaseKey::new().with_password("pw"))
            .unwrap();

        let tree = open(&bytes, "pw").unwrap();
        let names: Vec<&str> = tree.root.groups.iter().map(|g| g.name.as_str()).collect();
        assert!(
            !names.contains(&"Recycle Bin"),
            "recycle bin must not be lowered"
        );
        fn all_entry_titles<'a>(g: &'a KdbxGroup, out: &mut Vec<&'a str>) {
            for e in &g.entries {
                out.push(e.title.as_str());
            }
            for sub in &g.groups {
                all_entry_titles(sub, out);
            }
        }
        let mut titles = Vec::new();
        all_entry_titles(&tree.root, &mut titles);
        assert!(titles.contains(&"LiveAcct"));
        assert!(
            !titles.contains(&"DeletedAcct"),
            "deleted entry must not be imported"
        );
    }

    #[test]
    fn debug_never_prints_secrets() {
        let mut e = entry("Bank");
        e.password = Some("s3cr3t".into());
        e.totp_raw = Some("JBSWY3DPEHPK3PXP".into());
        e.custom = vec![KdbxField {
            name: "Backup Code".into(),
            value: "topsecretvalue".into(),
            protected: true,
        }];
        let dbg = format!("{:?}", e);
        assert!(
            !dbg.contains("s3cr3t"),
            "password must never appear in Debug: {dbg}"
        );
        assert!(
            !dbg.contains("JBSWY3DPEHPK3PXP"),
            "totp seed must never appear in Debug: {dbg}"
        );
        assert!(
            !dbg.contains("topsecretvalue"),
            "protected custom value must never appear in Debug: {dbg}"
        );
        assert!(dbg.contains("Bank"), "non-secret title may appear");
        assert!(
            dbg.contains("Backup Code"),
            "non-secret field name may appear"
        );
    }
}

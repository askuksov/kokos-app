//! Field-template CRUD. The 8 frozen `tpl_*` defaults (seeded by
//! `db::populate_defaults`) are protected from update/delete: `tpl_username`
//! and `tpl_totp` are hardcoded in `entries::list` for subtitle/icon
//! derivation, so renaming or removing a builtin would break that.

use rusqlite::{Connection, OptionalExtension};

use crate::error::{Result, VaultError};

/// IDs are fixed and must match `db::schema::DEFAULT_TEMPLATES`.
pub const BUILTIN_IDS: [&str; 8] = [
    "tpl_username",
    "tpl_password",
    "tpl_url",
    "tpl_email",
    "tpl_totp",
    "tpl_pin",
    "tpl_security_question",
    "tpl_security_answer",
];

#[derive(Debug, Clone)]
pub struct FieldTemplate {
    pub id: String,
    pub name: String,
    pub field_type: String,
    pub is_protected: bool,
    pub sort_order: i32,
    pub is_builtin: bool,
}

pub fn list(conn: &Connection) -> Result<Vec<FieldTemplate>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, field_type, is_protected, sort_order
         FROM field_templates
         ORDER BY sort_order, name",
    )?;
    let rows = stmt.query_map([], |r| {
        let id: String = r.get(0)?;
        let is_builtin = BUILTIN_IDS.contains(&id.as_str());
        Ok(FieldTemplate {
            id,
            name: r.get(1)?,
            field_type: r.get(2)?,
            is_protected: r.get::<_, i64>(3)? != 0,
            sort_order: r.get(4)?,
            is_builtin,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

fn validate_field_type(ft: &str) -> Result<()> {
    match ft {
        "text" | "secret" | "url" | "email" | "otp" | "date" | "phone" => Ok(()),
        _ => Err(VaultError::InvalidFieldType),
    }
}

/// field_templates has exactly one UNIQUE constraint (name); a constraint
/// violation reaching this point is always a duplicate name. (The table also
/// has a field_type CHECK, but validate_field_type() rejects a bad type
/// before any INSERT/UPDATE runs, so a CHECK violation never reaches here.)
fn map_unique(e: rusqlite::Error) -> VaultError {
    if let rusqlite::Error::SqliteFailure(f, _) = &e {
        if f.code == rusqlite::ErrorCode::ConstraintViolation {
            return VaultError::DuplicateTemplateName;
        }
    }
    e.into()
}

fn read_template(conn: &Connection, id: &str) -> Result<FieldTemplate> {
    conn.query_row(
        "SELECT id, name, field_type, is_protected, sort_order
         FROM field_templates WHERE id = ?1",
        [id],
        |r| {
            let id: String = r.get(0)?;
            let is_builtin = BUILTIN_IDS.contains(&id.as_str());
            Ok(FieldTemplate {
                id,
                name: r.get(1)?,
                field_type: r.get(2)?,
                is_protected: r.get::<_, i64>(3)? != 0,
                sort_order: r.get(4)?,
                is_builtin,
            })
        },
    )
    .optional()?
    .ok_or(VaultError::TemplateNotFound)
}

pub fn create(conn: &Connection, name: &str, field_type: &str, is_protected: bool) -> Result<FieldTemplate> {
    validate_field_type(field_type)?;
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO field_templates (id, name, field_type, is_protected, sort_order)
         VALUES (?1, ?2, ?3, ?4, (SELECT COALESCE(MAX(sort_order), 0) FROM field_templates) + 1)",
        rusqlite::params![id, name, field_type, is_protected],
    )
    .map_err(map_unique)?;
    read_template(conn, &id)
}

pub fn update(conn: &Connection, id: &str, name: &str, field_type: &str, is_protected: bool) -> Result<FieldTemplate> {
    if BUILTIN_IDS.contains(&id) {
        return Err(VaultError::TemplateProtected);
    }
    validate_field_type(field_type)?;
    let n = conn
        .execute(
            "UPDATE field_templates SET name = ?1, field_type = ?2, is_protected = ?3 WHERE id = ?4",
            rusqlite::params![name, field_type, is_protected, id],
        )
        .map_err(map_unique)?;
    if n == 0 {
        return Err(VaultError::TemplateNotFound);
    }
    read_template(conn, id)
}

pub fn delete(conn: &Connection, id: &str) -> Result<()> {
    if BUILTIN_IDS.contains(&id) {
        return Err(VaultError::TemplateProtected);
    }
    let n = conn.execute("DELETE FROM field_templates WHERE id = ?1", [id])?;
    if n == 0 {
        return Err(VaultError::TemplateNotFound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::both_dbs;

    #[test]
    fn list_returns_the_eight_seeded_defaults_flagged_builtin() {
        for (label, conn) in both_dbs() {
            let t = list(&conn).unwrap();
            assert!(t.iter().any(|x| x.id == "tpl_password" && x.is_builtin), "[{label}] tpl_password present + builtin");
            assert_eq!(t.iter().filter(|x| x.is_builtin).count(), 8, "[{label}] exactly 8 builtins");
        }
    }
    #[test]
    fn create_validates_type_and_uniqueness() {
        for (label, conn) in both_dbs() {
            let c = create(&conn, "Recovery Code", "secret", true).unwrap();
            assert!(!c.is_builtin, "[{label}] user template is not builtin");
            assert_eq!(c.field_type, "secret", "[{label}] type stored");
            assert!(matches!(create(&conn, "Recovery Code", "text", false), Err(VaultError::DuplicateTemplateName)), "[{label}] dup name");
            assert!(matches!(create(&conn, "Bad", "banana", false), Err(VaultError::InvalidFieldType)), "[{label}] bad type");
        }
    }
    #[test]
    fn builtins_cannot_be_updated_or_deleted() {
        for (label, conn) in both_dbs() {
            assert!(matches!(delete(&conn, "tpl_password"), Err(VaultError::TemplateProtected)), "[{label}] no delete builtin");
            assert!(matches!(update(&conn, "tpl_password", "PW", "secret", true), Err(VaultError::TemplateProtected)), "[{label}] no update builtin");
        }
    }
    #[test]
    fn update_and_delete_user_template_roundtrip() {
        for (label, conn) in both_dbs() {
            let c = create(&conn, "Temp", "text", false).unwrap();
            let u = update(&conn, &c.id, "Temp2", "email", false).unwrap();
            assert_eq!((u.name.as_str(), u.field_type.as_str()), ("Temp2", "email"), "[{label}] updated");
            delete(&conn, &c.id).unwrap();
            assert!(!list(&conn).unwrap().iter().any(|x| x.id == c.id), "[{label}] gone");
            assert!(matches!(delete(&conn, "ghost"), Err(VaultError::TemplateNotFound)), "[{label}] missing -> NotFound");
        }
    }
}

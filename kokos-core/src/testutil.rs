//! Test-only helpers shared across the CRUD modules (entries/folders/tags/
//! trash). Every CRUD test runs against BOTH a fresh vault and a real
//! migrated one: only the migrated DB has Go-written rows.
#![cfg(test)]

use std::path::PathBuf;

use rusqlite::Connection;

use crate::db;

/// Fresh (`TARGET_SCHEMA`) + migrated (opened from the real v1 fixture).
pub(crate) fn both_dbs() -> Vec<(&'static str, Connection)> {
    let fresh = db::create_fresh().unwrap();
    let fixture: PathBuf =
        [env!("CARGO_MANIFEST_DIR"), "fixtures", "v1_basic.vault"].iter().collect();
    let migrated = crate::vault::open(&fixture, b"fixture-password", None).unwrap().conn;
    vec![("fresh", fresh), ("migrated", migrated)]
}

/// A minimal live entry under `folder_id='root'`.
#[allow(dead_code)]
pub(crate) fn seed_entry(conn: &Connection, id: &str, title: &str, favorite: i64) {
    let now = db::now_unix();
    conn.execute(
        "INSERT INTO entries (id, folder_id, title, is_favorite, is_deleted, created_at, updated_at)
         VALUES (?1, 'root', ?2, ?3, 0, ?4, ?4)",
        rusqlite::params![id, title, favorite, now],
    )
    .unwrap();
}

/// A folder row with named columns; `parent` = `None` writes NULL (Go forest).
pub(crate) fn seed_folder(conn: &Connection, id: &str, name: &str, parent: Option<&str>) {
    let now = db::now_unix();
    conn.execute(
        "INSERT INTO folders (id, parent_id, name, sort_order, created_at, updated_at)
         VALUES (?1, ?2, ?3, 0, ?4, ?4)",
        rusqlite::params![id, parent, name, now],
    )
    .unwrap();
}

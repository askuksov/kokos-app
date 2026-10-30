//! Folder-tree CRUD. Single-rooted at the literal `root` folder (entries
//! default to `folder_id='root'`). Never `SELECT *`. `list_tree`
//! stays robust to Go's `parent_id=NULL` forests as well as Kokos's
//! `parent_id='root'` convention.

use std::collections::{HashMap, HashSet};

use rusqlite::{Connection, OptionalExtension};

use crate::error::{Result, VaultError};

#[derive(Debug, Clone)]
pub struct Folder {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub icon_id: Option<String>,
    pub sort_order: i32,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct FolderNode {
    pub folder: Folder,
    pub entry_count: i64,
    pub children: Vec<FolderNode>,
}

pub fn list_tree(conn: &Connection) -> Result<Vec<FolderNode>> {
    let mut fstmt = conn.prepare(
        "SELECT id, parent_id, name, icon_id, sort_order, created_at, updated_at
         FROM folders ORDER BY sort_order ASC, name COLLATE NOCASE ASC",
    )?;
    let folders: Vec<Folder> = fstmt
        .query_map([], |r| {
            Ok(Folder {
                id: r.get(0)?,
                parent_id: r.get(1)?,
                name: r.get(2)?,
                icon_id: r.get(3)?,
                sort_order: r.get(4)?,
                created_at: r.get(5)?,
                updated_at: r.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;

    let mut counts: HashMap<String, i64> = HashMap::new();
    let mut cstmt = conn.prepare(
        "SELECT folder_id, COUNT(*) FROM entries
         WHERE is_deleted = 0 AND folder_id IS NOT NULL GROUP BY folder_id",
    )?;
    for row in cstmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
        let (fid, n) = row?;
        counts.insert(fid, n);
    }

    let ids: HashSet<String> = folders.iter().map(|f| f.id.clone()).collect();
    let eff_parent = |f: &Folder| -> Option<String> {
        if f.id == "root" {
            return None;
        }
        match &f.parent_id {
            Some(p) if p != "root" && p != &f.id && ids.contains(p) => Some(p.clone()),
            _ => Some("root".to_string()),
        }
    };

    let mut kids: HashMap<String, Vec<Folder>> = HashMap::new();
    let mut roots: Vec<Folder> = Vec::new();
    for f in folders {
        match eff_parent(&f) {
            None => roots.push(f),
            Some(p) => kids.entry(p).or_default().push(f),
        }
    }

    fn build(f: Folder, kids: &HashMap<String, Vec<Folder>>, counts: &HashMap<String, i64>) -> FolderNode {
        let entry_count = *counts.get(&f.id).unwrap_or(&0);
        let children = kids
            .get(&f.id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|c| build(c, kids, counts))
            .collect();
        FolderNode { folder: f, entry_count, children }
    }

    Ok(roots.into_iter().map(|r| build(r, &kids, &counts)).collect())
}

pub fn get_folder(conn: &Connection, id: &str) -> Result<Option<Folder>> {
    let mut stmt = conn.prepare(
        "SELECT id, parent_id, name, icon_id, sort_order, created_at, updated_at
         FROM folders WHERE id = ?1",
    )?;
    stmt.query_row([id], |r| {
        Ok(Folder {
            id: r.get(0)?,
            parent_id: r.get(1)?,
            name: r.get(2)?,
            icon_id: r.get(3)?,
            sort_order: r.get(4)?,
            created_at: r.get(5)?,
            updated_at: r.get(6)?,
        })
    })
    .optional()
    .map_err(VaultError::from)
}

pub fn create(conn: &Connection, name: &str, parent_id: Option<&str>, now: i64) -> Result<Folder> {
    let id = uuid::Uuid::new_v4().to_string();
    let parent = parent_id.unwrap_or("root");
    conn.execute(
        "INSERT INTO folders (id, parent_id, name, sort_order, created_at, updated_at)
         VALUES (?1, ?2, ?3, 0, ?4, ?4)",
        rusqlite::params![id, parent, name, now],
    )?;
    get_folder(conn, &id)?.ok_or(VaultError::FolderNotFound)
}

/// Find a folder by exact name under `parent` (defaults to "root"), or create
/// it. Dedups by name so a repeated import into the same folder reuses it —
/// unlike `create`, which always mints a new row. Used by the text-import
/// commit to resolve its single destination folder.
pub fn find_or_create(conn: &Connection, parent_id: Option<&str>, name: &str, now: i64) -> Result<Folder> {
    let parent = parent_id.unwrap_or("root");
    let existing: Option<String> = conn
        .query_row(
            // A Go-migrated top-level folder has parent_id NULL, not 'root'.
            // The seeded root row itself also has a NULL parent, so skip it;
            // an exact parent match wins over a legacy NULL-parent one.
            "SELECT id FROM folders
              WHERE name = ?1 AND id <> 'root'
                AND (parent_id = ?2 OR (?2 = 'root' AND parent_id IS NULL))
              ORDER BY (parent_id IS NULL) ASC, created_at ASC, id ASC
              LIMIT 1",
            rusqlite::params![name, parent],
            |r| r.get(0),
        )
        .optional()?;
    match existing {
        Some(id) => get_folder(conn, &id)?.ok_or(VaultError::FolderNotFound),
        None => create(conn, name, Some(parent), now),
    }
}

pub fn rename(conn: &Connection, id: &str, name: &str, now: i64) -> Result<Folder> {
    if id == "root" {
        return Err(VaultError::CannotModifyRoot);
    }
    let n = conn.execute(
        "UPDATE folders SET name = ?1, updated_at = ?2 WHERE id = ?3",
        rusqlite::params![name, now, id],
    )?;
    if n == 0 {
        return Err(VaultError::FolderNotFound);
    }
    get_folder(conn, id)?.ok_or(VaultError::FolderNotFound)
}

pub fn move_to(conn: &Connection, id: &str, new_parent: Option<&str>, now: i64) -> Result<()> {
    if id == "root" {
        return Err(VaultError::CannotModifyRoot);
    }
    let target = new_parent.unwrap_or("root");
    if target == id {
        return Err(VaultError::CircularReference);
    }
    let mut visited: HashSet<String> = HashSet::new();
    let mut cur = Some(target.to_string());
    while let Some(c) = cur {
        if c == id {
            return Err(VaultError::CircularReference);
        }
        if !visited.insert(c.clone()) {
            break;
        }
        cur = conn
            .query_row("SELECT parent_id FROM folders WHERE id = ?1", [&c], |r| {
                r.get::<_, Option<String>>(0)
            })
            .optional()?
            .flatten();
    }
    let n = conn.execute(
        "UPDATE folders SET parent_id = ?1, updated_at = ?2 WHERE id = ?3",
        rusqlite::params![target, now, id],
    )?;
    if n == 0 {
        return Err(VaultError::FolderNotFound);
    }
    Ok(())
}

pub fn delete(conn: &Connection, id: &str, now: i64) -> Result<()> {
    if id == "root" {
        return Err(VaultError::CannotModifyRoot);
    }
    let tx = conn.unchecked_transaction()?;
    let parent: Option<String> = tx
        .query_row("SELECT parent_id FROM folders WHERE id = ?1", [id], |r| {
            r.get::<_, Option<String>>(0)
        })
        .optional()?
        .ok_or(VaultError::FolderNotFound)?;
    // A Go-migrated top-level folder has parent_id NULL, and a corrupt one may
    // point at itself; either way its contents land in root.
    let dest = parent.as_deref().filter(|p| *p != id).unwrap_or("root");
    tx.execute(
        "UPDATE folders SET parent_id = ?1, updated_at = ?2 WHERE parent_id = ?3",
        rusqlite::params![dest, now, id],
    )?;
    tx.execute(
        "UPDATE entries SET folder_id = ?1, updated_at = ?2 WHERE folder_id = ?3",
        rusqlite::params![dest, now, id],
    )?;
    tx.execute("DELETE FROM folders WHERE id = ?1", [id])?;
    tx.commit()?;
    Ok(())
}

/// Same effective-parent rule as `list_tree`'s `eff_parent` closure (kept as
/// its own fn here since `list_tree` itself must not change): `root` has no
/// parent (`None`); any other folder's stated `parent_id` is honored only
/// when it names a different, existing, non-`root` folder -- otherwise
/// (NULL / `"root"` / self / dangling) the folder folds into the top-level
/// group under `root`.
fn effective_parent(folder_id: &str, parent_id: Option<&str>, ids: &HashSet<String>) -> Option<String> {
    if folder_id == "root" {
        return None;
    }
    match parent_id {
        Some(p) if p != "root" && p != folder_id && ids.contains(p) => Some(p.to_string()),
        _ => Some("root".to_string()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    Before,
    After,
}

/// Places folder `id` as a sibling immediately Before/After `target_id`,
/// inside `target_id`'s sibling group (its effective parent, per
/// `effective_parent`), rewriting that whole group's `sort_order` to a dense
/// `0..N` so `list_tree` renders the new order. Also re-parents `id` into
/// the group when it was elsewhere (a cross-parent before/after drop).
///
/// `target_id == "root"` and `target_id == id` are no-ops: the UI maps a
/// root drop to "move inside", never "place before/after", so this only
/// guards defensively -- it is never the expected path.
pub fn reorder(conn: &Connection, id: &str, target_id: &str, place: Placement, now: i64) -> Result<()> {
    if id == "root" {
        return Err(VaultError::CannotModifyRoot);
    }
    if target_id == "root" || target_id == id {
        return Ok(());
    }

    get_folder(conn, id)?.ok_or(VaultError::FolderNotFound)?;
    let target = get_folder(conn, target_id)?.ok_or(VaultError::FolderNotFound)?;

    struct Row {
        id: String,
        parent_id: Option<String>,
        name: String,
        sort_order: i32,
    }
    let mut stmt = conn.prepare("SELECT id, parent_id, name, sort_order FROM folders")?;
    let rows: Vec<Row> = stmt
        .query_map([], |r| {
            Ok(Row {
                id: r.get(0)?,
                parent_id: r.get(1)?,
                name: r.get(2)?,
                sort_order: r.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    drop(stmt);

    let ids: HashSet<String> = rows.iter().map(|r| r.id.clone()).collect();

    let group_key = effective_parent(&target.id, target.parent_id.as_deref(), &ids)
        .unwrap_or_else(|| "root".to_string());
    let new_parent = group_key.clone();

    let mut visited: HashSet<String> = HashSet::new();
    let mut cur = Some(new_parent.clone());
    while let Some(c) = cur {
        if c == id {
            return Err(VaultError::CircularReference);
        }
        if !visited.insert(c.clone()) {
            break;
        }
        cur = conn
            .query_row("SELECT parent_id FROM folders WHERE id = ?1", [&c], |r| {
                r.get::<_, Option<String>>(0)
            })
            .optional()?
            .flatten();
    }

    let mut group: Vec<Row> = rows
        .into_iter()
        .filter(|r| r.id != id)
        .filter(|r| {
            effective_parent(&r.id, r.parent_id.as_deref(), &ids).as_deref() == Some(group_key.as_str())
        })
        .collect();
    group.sort_by(|a, b| {
        a.sort_order
            .cmp(&b.sort_order)
            .then_with(|| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()))
    });

    let target_idx = group
        .iter()
        .position(|r| r.id == target_id)
        .ok_or(VaultError::FolderNotFound)?;
    let insert_at = match place {
        Placement::Before => target_idx,
        Placement::After => target_idx + 1,
    };

    let mut ordered_ids: Vec<String> = group.into_iter().map(|r| r.id).collect();
    ordered_ids.insert(insert_at, id.to_string());

    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "UPDATE folders SET parent_id = ?1, updated_at = ?2 WHERE id = ?3",
        rusqlite::params![new_parent, now, id],
    )?;
    for (i, fid) in ordered_ids.iter().enumerate() {
        tx.execute(
            "UPDATE folders SET sort_order = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![i as i32, now, fid],
        )?;
    }
    tx.commit()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{both_dbs, seed_entry, seed_folder};

    #[test]
    fn list_tree_nests_root_parent_and_null_parent_alike() {
        for (label, conn) in both_dbs() {
            seed_folder(&conn, "work", "Work", Some("root"));
            seed_folder(&conn, "work-sub", "Sub", Some("work"));
            seed_folder(&conn, "legacy", "Legacy", None);
            seed_folder(&conn, "self-loop", "SelfLoop", Some("self-loop"));
            conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
            seed_folder(&conn, "dangling-child", "Dangling", Some("ghost-parent"));
            conn.pragma_update(None, "foreign_keys", "ON").unwrap();

            let tree = list_tree(&conn).unwrap();
            assert_eq!(tree.len(), 1, "[{label}] list_tree must return exactly one top-level node");
            assert_eq!(tree[0].folder.id, "root", "[{label}] the single top-level node must be root");

            let root = tree.iter().find(|n| n.folder.id == "root")
                .unwrap_or_else(|| panic!("[{label}] a single root node must exist"));
            let child_ids: Vec<&str> = root.children.iter().map(|c| c.folder.id.as_str()).collect();
            assert!(child_ids.contains(&"work"), "[{label}] 'root'-parent folder under root");
            assert!(child_ids.contains(&"legacy"), "[{label}] NULL-parent (Go) folder under root");
            assert!(child_ids.contains(&"self-loop"), "[{label}] self-parent folder falls back to root");
            assert!(child_ids.contains(&"dangling-child"), "[{label}] dangling-parent folder falls back to root");
            let work = root.children.iter().find(|c| c.folder.id == "work").unwrap();
            assert!(work.children.iter().any(|c| c.folder.id == "work-sub"),
                "[{label}] nested folder stays under its real parent");
        }
    }

    /// Covers a gap where no test asserted `FolderNode.entry_count`.
    /// Seeds one live entry and one soft-deleted entry into the same non-root
    /// folder -- only the live one may be counted.
    #[test]
    fn list_tree_counts_only_live_entries_in_their_own_folder() {
        for (label, conn) in both_dbs() {
            seed_folder(&conn, "ec-folder", "Counted", Some("root"));

            seed_entry(&conn, "ec-live", "Live Entry", 0);
            conn.execute("UPDATE entries SET folder_id = 'ec-folder' WHERE id = 'ec-live'", [])
                .unwrap();

            seed_entry(&conn, "ec-deleted", "Deleted Entry", 0);
            conn.execute(
                "UPDATE entries SET folder_id = 'ec-folder', is_deleted = 1 WHERE id = 'ec-deleted'",
                [],
            )
            .unwrap();

            let tree = list_tree(&conn).unwrap();
            let root = tree.iter().find(|n| n.folder.id == "root")
                .unwrap_or_else(|| panic!("[{label}] a single root node must exist"));
            let folder = root.children.iter().find(|c| c.folder.id == "ec-folder")
                .unwrap_or_else(|| panic!("[{label}] seeded folder must appear under root"));
            assert_eq!(
                folder.entry_count, 1,
                "[{label}] entry_count must count the one live entry and exclude the soft-deleted one"
            );
        }
    }

    #[test]
    fn create_defaults_to_root_and_reads_back() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            let f = create(&conn, "Personal", None, now).unwrap();
            assert_eq!(f.parent_id.as_deref(), Some("root"), "[{label}] defaults under root");
            assert_eq!(f.name, "Personal");
            assert!(list_tree(&conn).unwrap().iter().find(|n| n.folder.id == "root").unwrap()
                .children.iter().any(|c| c.folder.id == f.id), "[{label}] shows under root");
        }
    }

    #[test]
    fn rename_root_is_rejected() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            assert!(matches!(rename(&conn, "root", "Nope", now), Err(crate::error::VaultError::CannotModifyRoot)),
                "[{label}] root rename must be refused");
            assert!(matches!(rename(&conn, "ghost", "X", now), Err(crate::error::VaultError::FolderNotFound)),
                "[{label}] missing folder -> FolderNotFound");
        }
    }

    /// rename()'s success path was untested, so a
    /// swapped `UPDATE ... SET name=?1, updated_at=?2 WHERE id=?3` param
    /// order would pass silently. A fixed `now` sentinel, distinct from
    /// whatever wall-clock value `seed_folder` stamped at insert time,
    /// pins that `updated_at` reflects the value actually passed in.
    #[test]
    fn rename_updates_name_and_timestamp() {
        for (label, conn) in both_dbs() {
            seed_folder(&conn, "ren", "Before", Some("root"));
            let now: i64 = 1_234_567;
            let folder = rename(&conn, "ren", "After", now).unwrap();
            assert_eq!(folder.name, "After", "[{label}] rename updates the name");
            assert_eq!(folder.updated_at, now, "[{label}] rename updates updated_at to the passed `now`");
        }
    }

    /// create()'s explicit-parent branch was untested,
    /// so only the `parent_id.unwrap_or("root")` default arm was exercised.
    /// Seeds a real parent folder first since `parent_id` is
    /// `REFERENCES folders(id)` under enforced foreign keys.
    #[test]
    fn create_with_explicit_parent_is_nested_there() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_folder(&conn, "work", "Work", Some("root"));
            let f = create(&conn, "Sub", Some("work"), now).unwrap();
            assert_eq!(f.parent_id.as_deref(), Some("work"), "[{label}] explicit parent_id is honored, not defaulted to root");
            assert_eq!(f.name, "Sub", "[{label}] name is stored as given");
        }
    }

    #[test]
    fn find_or_create_dedups_by_name_under_parent() {
        let conn = crate::db::create_fresh().unwrap();
        let now = 1;
        let a = find_or_create(&conn, Some("root"), "Imported", now).unwrap();
        let b = find_or_create(&conn, Some("root"), "Imported", now).unwrap();
        assert_eq!(a.id, b.id, "same name under the same parent reuses the folder");
        assert_eq!(a.name, "Imported");
        let c = find_or_create(&conn, Some("root"), "Other", now).unwrap();
        assert_ne!(a.id, c.id);
    }

    #[test]
    fn move_into_own_descendant_is_rejected() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            let a = create(&conn, "A", None, now).unwrap();
            let b = create(&conn, "B", Some(&a.id), now).unwrap();
            assert!(matches!(move_to(&conn, &a.id, Some(&b.id), now), Err(VaultError::CircularReference)),
                "[{label}] moving a folder under its descendant must be refused");
            assert!(matches!(move_to(&conn, &a.id, Some(&a.id), now), Err(VaultError::CircularReference)),
                "[{label}] moving a folder directly under itself must be refused");
            assert!(matches!(move_to(&conn, "ghost", Some("root"), now), Err(VaultError::FolderNotFound)),
                "[{label}] moving a nonexistent folder id -> FolderNotFound");
            let move_now: i64 = now + 1_000;
            move_to(&conn, &b.id, Some("root"), move_now).unwrap();
            let b_after = get_folder(&conn, &b.id).unwrap().unwrap();
            assert_eq!(b_after.parent_id.as_deref(), Some("root"), "[{label}] parent_id is correctly updated after move_to");
            assert_eq!(b_after.updated_at, move_now, "[{label}] move_to updates updated_at to the passed `now`");
            assert!(matches!(move_to(&conn, "root", Some(&a.id), now), Err(VaultError::CannotModifyRoot)),
                "[{label}] root cannot be moved");
        }
    }

    /// The visited-set guard in move_to's ancestor walk
    /// (the `while let Some(c) = cur` loop above) had zero regression
    /// coverage. The only other cycle test (move_into_own_descendant_is_rejected)
    /// builds a fresh, acyclic A -> B chain, so deleting the guard entirely
    /// would still leave the whole suite green.
    ///
    /// This seeds a GENUINE pre-existing 2-node cycle (cyc-x <-> cyc-y)
    /// that is UNRELATED to the folder being moved, using the same
    /// FK-toggle technique as
    /// list_tree_nests_root_parent_and_null_parent_alike's `dangling-child`:
    /// foreign_keys are ON in both harness DBs, and neither row can be
    /// inserted first since each references the other, so the pragma is
    /// toggled off for the two writes only.
    ///
    /// Moving the unrelated `mover` folder under `cyc-x` makes the ancestor
    /// walk climb cyc-x -> cyc-y -> cyc-x: the third step revisits cyc-x,
    /// `visited.insert` returns `false`, and the loop `break`s instead of
    /// climbing forever. The test simply COMPLETING (and returning `Ok`) is
    /// the regression signal: without the guard, this test would hang the
    /// suite instead of failing it.
    #[test]
    fn move_to_terminates_on_pre_existing_ancestor_cycle() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();

            conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
            seed_folder(&conn, "cyc-x", "CycX", Some("cyc-y"));
            seed_folder(&conn, "cyc-y", "CycY", Some("cyc-x"));
            conn.pragma_update(None, "foreign_keys", "ON").unwrap();

            seed_folder(&conn, "mover", "Mover", Some("root"));

            let result = move_to(&conn, "mover", Some("cyc-x"), now);
            assert!(
                result.is_ok(),
                "[{label}] move_to must terminate (via the visited-set guard) and succeed \
                 when the walk from the new parent passes through a pre-existing cycle \
                 that does not involve the moved folder"
            );

            let mover_after = get_folder(&conn, "mover").unwrap().unwrap();
            assert_eq!(
                mover_after.parent_id.as_deref(),
                Some("cyc-x"),
                "[{label}] mover is persisted under cyc-x despite the cycle beyond it"
            );
        }
    }

    #[test]
    fn delete_reparents_entries_and_subfolders_up() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            let parent = create(&conn, "Parent", None, now).unwrap();
            let mid = create(&conn, "Mid", Some(&parent.id), now).unwrap();
            let leaf = create(&conn, "Leaf", Some(&mid.id), now).unwrap();
            seed_entry(&conn, "in-mid", "In Mid", 0);
            conn.execute("UPDATE entries SET folder_id = ?1 WHERE id = 'in-mid'", [&mid.id]).unwrap();

            delete(&conn, &mid.id, now).unwrap();

            assert!(get_folder(&conn, &mid.id).unwrap().is_none(), "[{label}] deleted folder is gone");
            let moved: (Option<String>, i64) = conn.query_row(
                "SELECT folder_id, is_deleted FROM entries WHERE id = 'in-mid'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            assert_eq!(moved.0.as_deref(), Some(parent.id.as_str()), "[{label}] entry reparented to grandparent");
            assert_eq!(moved.1, 0, "[{label}] entry NOT trashed");
            let leaf_parent: Option<String> = conn.query_row(
                "SELECT parent_id FROM folders WHERE id = ?1", [&leaf.id], |r| r.get(0)).unwrap();
            assert_eq!(leaf_parent.as_deref(), Some(parent.id.as_str()),
                "[{label}] mid's subfolder reparented to the grandparent");
            assert!(get_folder(&conn, &leaf.id).unwrap().is_some(), "[{label}] the subfolder subtree survives");
        }
    }

    #[test]
    fn delete_null_parent_folder_moves_contents_to_root() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_folder(&conn, "go-top", "GoTop", None);
            seed_folder(&conn, "go-sub", "GoSub", Some("go-top"));
            seed_entry(&conn, "in-go-top", "In GoTop", 0);
            conn.execute("UPDATE entries SET folder_id = 'go-top' WHERE id = 'in-go-top'", []).unwrap();

            delete(&conn, "go-top", now).unwrap();

            let folder: Option<String> = conn.query_row(
                "SELECT folder_id FROM entries WHERE id = 'in-go-top'", [], |r| r.get(0)).unwrap();
            assert_eq!(folder.as_deref(), Some("root"), "[{label}] entry lands in root, not NULL");
            let sub_parent: Option<String> = conn.query_row(
                "SELECT parent_id FROM folders WHERE id = 'go-sub'", [], |r| r.get(0)).unwrap();
            assert_eq!(sub_parent.as_deref(), Some("root"), "[{label}] subfolder lands in root, not NULL");
        }
    }

    #[test]
    fn find_or_create_reuses_null_parent_top_level_folder() {
        for (label, conn) in both_dbs() {
            seed_folder(&conn, "go-imp", "GoImported", None);
            let f = find_or_create(&conn, Some("root"), "GoImported", 1).unwrap();
            assert_eq!(f.id, "go-imp", "[{label}] NULL-parent folder reused under root");
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM folders WHERE name = 'GoImported'", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 1, "[{label}] no duplicate sibling");
            let other = find_or_create(&conn, Some("go-imp"), "GoImported", 1).unwrap();
            assert_ne!(other.id, "go-imp", "[{label}] a non-root parent does not match NULL");
        }
    }

    #[test]
    fn find_or_create_skips_root_row_and_prefers_exact_parent() {
        for (label, conn) in both_dbs() {
            let f = find_or_create(&conn, Some("root"), "Root", 1).unwrap();
            assert_ne!(f.id, "root", "[{label}] the seeded root row is never returned");
            assert_eq!(f.parent_id.as_deref(), Some("root"), "[{label}] a new child of root is created");

            seed_folder(&conn, "dup-legacy", "Dup", None);
            seed_folder(&conn, "dup-exact", "Dup", Some("root"));
            let d = find_or_create(&conn, Some("root"), "Dup", 1).unwrap();
            assert_eq!(d.id, "dup-exact", "[{label}] exact parent match wins over a NULL-parent one");
        }
    }

    #[test]
    fn delete_self_parent_folder_moves_contents_to_root() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_folder(&conn, "self-p", "SelfP", Some("self-p"));
            seed_folder(&conn, "self-sub", "SelfSub", Some("self-p"));
            seed_entry(&conn, "in-self-p", "In SelfP", 0);
            conn.execute("UPDATE entries SET folder_id = 'self-p' WHERE id = 'in-self-p'", []).unwrap();

            delete(&conn, "self-p", now).unwrap();

            assert!(get_folder(&conn, "self-p").unwrap().is_none(), "[{label}] deleted folder is gone");
            let folder: Option<String> = conn.query_row(
                "SELECT folder_id FROM entries WHERE id = 'in-self-p'", [], |r| r.get(0)).unwrap();
            assert_eq!(folder.as_deref(), Some("root"), "[{label}] entry lands in root");
            let sub = get_folder(&conn, "self-sub").unwrap()
                .unwrap_or_else(|| panic!("[{label}] subfolder survives"));
            assert_eq!(sub.parent_id.as_deref(), Some("root"), "[{label}] subfolder lands in root");
        }
    }

    #[test]
    fn delete_root_is_rejected() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            assert!(matches!(delete(&conn, "root", now), Err(crate::error::VaultError::CannotModifyRoot)),
                "[{label}] root delete must be refused");
        }
    }

    #[test]
    fn delete_missing_folder_is_rejected() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            assert!(matches!(delete(&conn, "ghost", now), Err(crate::error::VaultError::FolderNotFound)),
                "[{label}] missing folder -> FolderNotFound");
        }
    }


    /// Test-only: the ordered list of folder ids that `list_tree` renders as
    /// direct children of `parent_id` (searched anywhere in the tree, so it
    /// also works for a non-root parent). This is the "read-back" side of
    /// every reorder assertion below: it proves the DISPLAY order actually
    /// changed, not just the stored columns.
    fn child_ids_of(conn: &Connection, parent_id: &str) -> Vec<String> {
        fn find<'a>(nodes: &'a [FolderNode], id: &str) -> Option<&'a FolderNode> {
            for n in nodes {
                if n.folder.id == id {
                    return Some(n);
                }
                if let Some(found) = find(&n.children, id) {
                    return Some(found);
                }
            }
            None
        }
        let tree = list_tree(conn).unwrap();
        find(&tree, parent_id)
            .map(|n| n.children.iter().map(|c| c.folder.id.clone()).collect())
            .unwrap_or_default()
    }

    /// Test-only: `child_ids_of`, filtered down to just `keep` (in
    /// `list_tree`'s order). Isolates the folders under test from any
    /// unrelated sibling the migrated fixture DB may already carry under
    /// `root`, so an exact-order assertion is still meaningful on both
    /// harness DBs.
    fn relative_order(conn: &Connection, parent_id: &str, keep: &[&str]) -> Vec<String> {
        child_ids_of(conn, parent_id)
            .into_iter()
            .filter(|id| keep.contains(&id.as_str()))
            .collect()
    }

    #[test]
    fn reorder_moves_sibling_up_before_target_within_same_parent() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_folder(&conn, "a", "A", Some("root"));
            seed_folder(&conn, "b", "B", Some("root"));
            seed_folder(&conn, "c", "C", Some("root"));
            assert_eq!(relative_order(&conn, "root", &["a", "b", "c"]), vec!["a", "b", "c"],
                "[{label}] baseline: all sort_order=0 ties break by name -> A,B,C");

            reorder(&conn, "c", "a", Placement::Before, now).unwrap();

            let a = get_folder(&conn, "a").unwrap().unwrap();
            let b = get_folder(&conn, "b").unwrap().unwrap();
            let c = get_folder(&conn, "c").unwrap().unwrap();
            assert_eq!((c.sort_order, a.sort_order, b.sort_order), (0, 1, 2),
                "[{label}] dense sort_order reflects the new order C,A,B");
            assert_eq!(c.parent_id.as_deref(), Some("root"), "[{label}] c stays top-level");

            assert_eq!(relative_order(&conn, "root", &["a", "b", "c"]), vec!["c", "a", "b"],
                "[{label}] list_tree shows C,A,B");
        }
    }

    #[test]
    fn reorder_moves_sibling_down_after_target_within_same_parent() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_folder(&conn, "a", "A", Some("root"));
            seed_folder(&conn, "b", "B", Some("root"));
            seed_folder(&conn, "c", "C", Some("root"));

            reorder(&conn, "a", "c", Placement::After, now).unwrap();

            let a = get_folder(&conn, "a").unwrap().unwrap();
            let b = get_folder(&conn, "b").unwrap().unwrap();
            let c = get_folder(&conn, "c").unwrap().unwrap();
            assert_eq!((b.sort_order, c.sort_order, a.sort_order), (0, 1, 2),
                "[{label}] dense sort_order reflects the new order B,C,A");
            assert_eq!(a.parent_id.as_deref(), Some("root"), "[{label}] a stays top-level");

            assert_eq!(relative_order(&conn, "root", &["a", "b", "c"]), vec!["b", "c", "a"],
                "[{label}] list_tree shows B,C,A");
        }
    }

    #[test]
    fn reorder_across_parents_reparents_and_places_in_target_group() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_folder(&conn, "a", "A", Some("root"));
            seed_folder(&conn, "p", "P", Some("root"));
            seed_folder(&conn, "b", "B", Some("p"));

            reorder(&conn, "a", "b", Placement::After, now).unwrap();

            let a = get_folder(&conn, "a").unwrap().unwrap();
            assert_eq!(a.parent_id.as_deref(), Some("p"), "[{label}] a is re-parented into p");
            assert_eq!(a.updated_at, now, "[{label}] a's updated_at reflects the passed now");

            assert_eq!(relative_order(&conn, "p", &["a", "b"]), vec!["b", "a"],
                "[{label}] p's children display order is B,A");
            assert!(!child_ids_of(&conn, "root").contains(&"a".to_string()),
                "[{label}] a no longer shows as a top-level child of root");
        }
    }

    #[test]
    fn reorder_into_own_descendant_is_rejected() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_folder(&conn, "p", "P", Some("root"));
            seed_folder(&conn, "g", "G", Some("p"));

            assert!(matches!(reorder(&conn, "p", "g", Placement::Before, now), Err(VaultError::CircularReference)),
                "[{label}] reordering a folder before/after its own descendant must be refused");

            let p = get_folder(&conn, "p").unwrap().unwrap();
            assert_eq!(p.parent_id.as_deref(), Some("root"),
                "[{label}] the rejected reorder must not have changed p's parent");
        }
    }

    #[test]
    fn reorder_root_is_rejected() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_folder(&conn, "a", "A", Some("root"));
            assert!(matches!(reorder(&conn, "root", "a", Placement::Before, now), Err(VaultError::CannotModifyRoot)),
                "[{label}] root cannot be reordered");
        }
    }

    #[test]
    fn reorder_missing_folder_is_rejected() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_folder(&conn, "a", "A", Some("root"));
            assert!(matches!(reorder(&conn, "a", "nope", Placement::After, now), Err(VaultError::FolderNotFound)),
                "[{label}] reordering against a nonexistent target -> FolderNotFound");
            assert!(matches!(reorder(&conn, "ghost", "a", Placement::After, now), Err(VaultError::FolderNotFound)),
                "[{label}] reordering a nonexistent folder id -> FolderNotFound");
        }
    }

    #[test]
    fn reorder_self_or_root_target_is_a_no_op() {
        for (label, conn) in both_dbs() {
            let now: i64 = 1_234_567;
            seed_folder(&conn, "a", "A", Some("root"));
            seed_folder(&conn, "b", "B", Some("root"));
            let a_before = get_folder(&conn, "a").unwrap().unwrap();
            let order_before = relative_order(&conn, "root", &["a", "b"]);

            assert!(reorder(&conn, "a", "a", Placement::Before, now).is_ok(),
                "[{label}] reordering a folder relative to itself is a no-op, not an error");
            assert!(reorder(&conn, "a", "root", Placement::Before, now).is_ok(),
                "[{label}] reordering relative to root is a no-op, not an error");

            let a_after = get_folder(&conn, "a").unwrap().unwrap();
            assert_eq!(a_after.parent_id, a_before.parent_id, "[{label}] no-op reorders must not change parent_id");
            assert_eq!(a_after.updated_at, a_before.updated_at, "[{label}] no-op reorders must not touch updated_at");
            assert_eq!(relative_order(&conn, "root", &["a", "b"]), order_before,
                "[{label}] no-op reorders must not change sibling order");
        }
    }

    /// Nice-to-have: a Go-style folder with `parent_id = NULL` and a Kokos
    /// `parent_id = 'root'` folder must fold into the SAME sibling group and
    /// reindex together.
    #[test]
    fn reorder_folds_null_parent_and_root_parent_into_one_group() {
        for (label, conn) in both_dbs() {
            let now = crate::db::now_unix();
            seed_folder(&conn, "legacy", "Legacy", None);
            seed_folder(&conn, "modern", "Modern", Some("root"));

            reorder(&conn, "modern", "legacy", Placement::Before, now).unwrap();

            assert_eq!(relative_order(&conn, "root", &["legacy", "modern"]), vec!["modern", "legacy"],
                "[{label}] NULL-parent and 'root'-parent folders share one sibling group and reindex together");

            let modern = get_folder(&conn, "modern").unwrap().unwrap();
            assert_eq!(modern.parent_id.as_deref(), Some("root"),
                "[{label}] moving into the NULL-parent's group normalizes parent_id to the literal 'root'");
            let legacy = get_folder(&conn, "legacy").unwrap().unwrap();
            assert_eq!(legacy.parent_id, None,
                "[{label}] the target itself is untouched -- still NULL, not rewritten to 'root'");
        }
    }
}

//! Per-vault sync target, persisted OUTSIDE the encrypted vault so it can be
//! read before unlock (folder-mode materialize) and holds the last-synced
//! baseline (Drive file id + revision) for the post-open LWW reconcile. Mirrors
//! `recent.json` / `auth_failures`: a single `sync.json` in the app config dir,
//! keyed by the normalized vault path. Never holds secrets — OAuth tokens live
//! in the keyring; only a Drive file id + revision + last-sync timestamp here.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SyncTarget {
    None,
    Folder {
        path: String,
    },
    Gdrive {
        file_id: Option<String>,
        rev: u64,
        last_sync: i64,
        /// Per-vault filename in Drive's appDataFolder (`kokos-<device_id>.kokos`),
        /// derived at gdrive_connect from the vault's in-vault `device_id` (see
        /// `remote_name_for_device`) and stable across syncs AND machines: the
        /// same vault lineage always derives the same name (multi-device
        /// convergence on one remote file), while distinct vaults get distinct
        /// names (no cross-vault collision). `None` for legacy records — the
        /// client then falls back to the shared `FILE_NAME`.
        #[serde(default)]
        remote_name: Option<String>,
        /// Optional user-set backup note (e.g. "From my Macbook"), written into
        /// the Drive file's appProperties and shown on the restore list. `None`
        /// = unset (legacy records default here via serde).
        #[serde(default)]
        note: Option<String>,
    },
}

fn file(dir: &Path) -> std::path::PathBuf {
    dir.join("sync.json")
}

fn key(vault_path: &str) -> String {
    crate::paths::normalise(std::path::Path::new(vault_path))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| vault_path.to_string())
}

/// The stable per-vault remote filename in Drive's appDataFolder, derived from
/// the vault's in-vault `device_id` (DB `metadata`). That id is minted once at
/// vault creation and copied verbatim by whole-file `pull()`, so every replica
/// of one vault lineage — including the same vault opened on another machine —
/// derives the SAME name and converges on ONE remote file, while two
/// separately-created vaults get distinct names and never collide. (A vault file
/// manually COPIED into a second vault shares its lineage id, so both would map
/// to one remote file — a rare, deliberate case treated as the same sync unit.)
pub fn remote_name_for_device(device_id: &str) -> String {
    format!("kokos-{device_id}.kokos")
}

pub fn all(dir: &Path) -> BTreeMap<String, SyncTarget> {
    std::fs::read_to_string(file(dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn load(dir: &Path, vault_path: &str) -> SyncTarget {
    all(dir).remove(&key(vault_path)).unwrap_or(SyncTarget::None)
}

pub fn save(dir: &Path, vault_path: &str, target: &SyncTarget) -> std::io::Result<()> {
    let mut map = all(dir);
    match target {
        SyncTarget::None => {
            map.remove(&key(vault_path));
        }
        t => {
            map.insert(key(vault_path), t.clone());
        }
    }
    let json = serde_json::to_string_pretty(&map)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::create_dir_all(dir)?;
    let path = file(dir);
    let tmp = dir.join("sync.json.tmp");
    std::fs::write(&tmp, json.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, &path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(load(dir.path(), "/a/b/v.kokos"), SyncTarget::None));
    }

    #[test]
    fn save_then_load_roundtrips_per_path() {
        let dir = tempfile::tempdir().unwrap();
        save(dir.path(), "/a/v.kokos", &SyncTarget::Folder { path: "/ic/v.kokos".into() }).unwrap();
        save(dir.path(), "/b/v.kokos", &SyncTarget::Gdrive { file_id: Some("fid".into()), rev: 3, last_sync: 42, remote_name: Some("v-abcd1234.kokos".into()), note: Some("From my Macbook".into()) }).unwrap();
        assert!(matches!(load(dir.path(), "/a/v.kokos"), SyncTarget::Folder { path } if path == "/ic/v.kokos"));
        match load(dir.path(), "/b/v.kokos") {
            SyncTarget::Gdrive { file_id, rev, last_sync, remote_name, note } => { assert_eq!(file_id.as_deref(), Some("fid")); assert_eq!(rev, 3); assert_eq!(last_sync, 42); assert_eq!(remote_name.as_deref(), Some("v-abcd1234.kokos")); assert_eq!(note.as_deref(), Some("From my Macbook")); }
            _ => panic!("expected gdrive"),
        }
        assert!(matches!(load(dir.path(), "/c/v.kokos"), SyncTarget::None));
    }

    #[test]
    fn overwrite_replaces_target_for_path() {
        let dir = tempfile::tempdir().unwrap();
        save(dir.path(), "/a/v.kokos", &SyncTarget::Folder { path: "/x".into() }).unwrap();
        save(dir.path(), "/a/v.kokos", &SyncTarget::None).unwrap();
        assert!(matches!(load(dir.path(), "/a/v.kokos"), SyncTarget::None));
    }

    #[test]
    fn remote_name_for_device_is_stable_and_lineage_keyed() {
        let id = "9f3c1e4a-1111-2222-3333-444455556666";
        let a = remote_name_for_device(id);
        assert_eq!(a, "kokos-9f3c1e4a-1111-2222-3333-444455556666.kokos");
        assert_eq!(a, remote_name_for_device(id));
        assert_ne!(a, remote_name_for_device("a1b8c2d0-0000-0000-0000-000000000000"));
        assert!(a.ends_with(".kokos"));
    }

    #[test]
    fn legacy_gdrive_without_note_deserializes_to_none() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_json = r#"{"/legacy/v.kokos":{"kind":"gdrive","file_id":"fid","rev":1,"last_sync":10,"remote_name":"v-legacy.kokos"}}"#;
        std::fs::write(file(dir.path()), legacy_json).unwrap();
        match load(dir.path(), "/legacy/v.kokos") {
            SyncTarget::Gdrive { note, .. } => assert_eq!(note, None),
            _ => panic!("expected gdrive"),
        }
    }
}

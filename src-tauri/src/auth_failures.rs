//! Best-effort failed-unlock tracking in app-config (never in the vault,
//! which is locked during a failed attempt). Holds path + count + timestamp
//! only -- no secret ever lands here. Surfaces as an "unlock" audit `detail`
//! on the next successful open (see `commands::open_vault` /
//! `commands::unlock_vault`), then is cleared.
//!
//! Mirrors `commands::push_recent`'s app-config JSON pattern: a single flat
//! file under the OS app-config dir, read-modify-write, best-effort (every
//! failure here is swallowed -- this counter must never itself break the
//! unlock flow).

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
struct Record {
    count: u32,
    last_ts: i64,
}

fn file(dir: &Path) -> std::path::PathBuf {
    dir.join("auth-failures.json")
}

fn load(dir: &Path) -> HashMap<String, Record> {
    std::fs::read_to_string(file(dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn write(dir: &Path, map: &HashMap<String, Record>) {
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    if let Ok(json) = serde_json::to_string(map) {
        let _ = std::fs::write(file(dir), json);
    }
}

/// +1 for `vault_path`, refreshing its timestamp. Best-effort: any I/O or
/// (de)serialization error is swallowed rather than surfaced -- a wrong
/// password must still return its own error to the caller, not this
/// counter's.
pub fn bump(dir: &Path, vault_path: &str) {
    let mut map = load(dir);
    let rec = map.entry(vault_path.to_string()).or_insert(Record { count: 0, last_ts: 0 });
    rec.count += 1;
    rec.last_ts = kokos_core::db::now_unix();
    write(dir, &map);
}

/// Reads the failure count for `vault_path` and removes the entry -- a
/// successful unlock resets the counter to zero for next time. Returns 0 on
/// any error (missing file, corrupt json, or no entry for this path).
pub fn take(dir: &Path, vault_path: &str) -> u32 {
    let mut map = load(dir);
    let count = map.remove(vault_path).map(|r| r.count).unwrap_or(0);
    write(dir, &map);
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_then_take_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        bump(dir.path(), "/tmp/a.vault");
        bump(dir.path(), "/tmp/a.vault");
        bump(dir.path(), "/tmp/a.vault");
        assert_eq!(take(dir.path(), "/tmp/a.vault"), 3);
        assert_eq!(take(dir.path(), "/tmp/a.vault"), 0);
    }

    #[test]
    fn take_on_never_bumped_path_is_zero() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(take(dir.path(), "/tmp/never-bumped.vault"), 0);
    }

    #[test]
    fn bump_tracks_paths_independently() {
        let dir = tempfile::tempdir().unwrap();
        bump(dir.path(), "/tmp/a.vault");
        bump(dir.path(), "/tmp/b.vault");
        bump(dir.path(), "/tmp/b.vault");
        assert_eq!(take(dir.path(), "/tmp/a.vault"), 1);
        assert_eq!(take(dir.path(), "/tmp/b.vault"), 2);
    }

    #[test]
    fn take_does_not_resurrect_a_removed_entry_on_corrupt_write() {
        let dir = tempfile::tempdir().unwrap();
        bump(dir.path(), "/tmp/a.vault");
        assert_eq!(take(dir.path(), "/tmp/a.vault"), 1);
        let map = load(dir.path());
        assert!(map.get("/tmp/a.vault").is_none());
    }
}

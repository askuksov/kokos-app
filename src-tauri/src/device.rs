//! Per-machine device identity for the sync LWW tie-break.
//!
//! The in-vault `device_id` (DB `metadata` row) is copied verbatim by the
//! whole-file `pull()`, so every replica of a vault lineage shares one id —
//! useless as a per-replica LWW tie-break. THIS id instead lives in
//! `device.json` in the app config dir, OUTSIDE any synced vault, so each
//! machine keeps a distinct id that survives `pull()`. The sync orchestrator
//! stamps `SyncMeta.device` from here (not the in-vault id), giving
//! `resolve_lww` a real tie-break.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stored {
    device_id: String,
}

fn file(dir: &Path) -> std::path::PathBuf {
    dir.join("device.json")
}

/// Stable per-machine id (uuid v4), minted on first read and persisted to
/// `<app_config_dir>/device.json`. Subsequent calls return the same id.
/// Unlike the in-vault `device_id`, this never travels with a synced vault, so
/// it distinguishes replicas of the same vault lineage.
pub fn machine_id(dir: &Path) -> std::io::Result<String> {
    if let Ok(s) = std::fs::read_to_string(file(dir)) {
        if let Ok(stored) = serde_json::from_str::<Stored>(&s) {
            if !stored.device_id.is_empty() {
                return Ok(stored.device_id);
            }
        }
    }
    let id = uuid::Uuid::new_v4().to_string();
    let json = serde_json::to_string_pretty(&Stored { device_id: id.clone() })
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::create_dir_all(dir)?;
    let path = file(dir);
    let tmp = dir.join("device.json.tmp");
    std::fs::write(&tmp, json.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(id)
}

use std::sync::OnceLock;

static CACHED: OnceLock<String> = OnceLock::new();

/// Per-process cached machine id. Runs `machine_id(dir)` exactly once — which
/// also closes the first-call `device.json.tmp` write race — and returns the
/// cached value on every later call (`dir` is ignored after the first). Empty
/// string only if both the read and the mint fail.
pub fn cached(dir: &Path) -> String {
    CACHED.get_or_init(|| machine_id(dir).unwrap_or_default()).clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mints_a_uuid_and_persists_it() {
        let dir = tempfile::tempdir().unwrap();
        let id = machine_id(dir.path()).unwrap();
        assert_eq!(id.len(), 36);
        assert!(file(dir.path()).exists());
    }

    #[test]
    fn second_call_returns_the_same_id() {
        let dir = tempfile::tempdir().unwrap();
        let a = machine_id(dir.path()).unwrap();
        let b = machine_id(dir.path()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_dirs_get_distinct_ids() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        assert_ne!(machine_id(d1.path()).unwrap(), machine_id(d2.path()).unwrap());
    }

    #[test]
    fn corrupt_file_is_reminted_and_then_stable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(file(dir.path()), b"not json").unwrap();
        let id = machine_id(dir.path()).unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(id, machine_id(dir.path()).unwrap());
    }

    #[test]
    fn cached_returns_stable_nonempty_id() {
        let dir = tempfile::tempdir().unwrap();
        let a = cached(dir.path());
        assert!(!a.is_empty());
        assert_eq!(a, cached(dir.path()));
    }
}

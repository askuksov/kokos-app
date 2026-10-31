//! Path allowlist: open/create only accept a path the Rust side itself handed
//! out (from pick_vault_path or recent_files), compared canonically so that
//! `..` and symlinks cannot smuggle a path past the check.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

// Object-bound file I/O helpers (declared here so the allowlist and the
// write/read side that must accompany it live side by side).
#[path = "safe_io.rs"]
pub mod safe_io;

/// Canonicalise for comparison. Existing files resolve directly; a save-mode
/// path does not exist yet, so canonicalise the PARENT and re-attach the file
/// name. Returns Err (→ path not allowed) when even the parent cannot be
/// resolved: the guard fails CLOSED.
pub fn normalise(p: &Path) -> std::io::Result<PathBuf> {
    match p.canonicalize() {
        Ok(c) => Ok(c),
        Err(_) => {
            let parent = p
                .parent()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent"))?;
            let name = p
                .file_name()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?;
            Ok(parent.canonicalize()?.join(name))
        }
    }
}

pub fn allow(set: &Mutex<HashSet<PathBuf>>, raw: &str) {
    if let Ok(c) = normalise(Path::new(raw)) {
        if let Ok(mut s) = set.lock() {
            s.insert(c);
        }
    }
}

/// Advisory for the PATHNAME only: it proves the canonical path was handed out
/// by this app, not that the file system object stays the same afterwards. A
/// symlink or file swapped in after this check is not detected, so callers
/// MUST do the actual I/O through `safe_io` (`write_atomic_owner_only`,
/// `read_regular_capped`) instead of reopening the raw pathname.
pub fn is_allowed(set: &Mutex<HashSet<PathBuf>>, raw: &str) -> bool {
    match normalise(Path::new(raw)) {
        Ok(c) => set.lock().map(|s| s.contains(&c)).unwrap_or(false),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_and_direct_forms_match_after_allow() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("real.vault"), b"x").unwrap();
        let set = Mutex::new(HashSet::new());

        let direct = dir.path().join("real.vault");
        allow(&set, direct.to_str().unwrap());

        let traversal = dir.path().join("sub/../real.vault");
        assert!(is_allowed(&set, traversal.to_str().unwrap()), "traversal form must resolve equal");
        assert!(!is_allowed(&set, dir.path().join("other.vault").to_str().unwrap()), "unlisted path denied");
    }

    #[test]
    fn save_mode_nonexistent_path_normalises_via_parent() {
        let dir = tempfile::tempdir().unwrap();
        let set = Mutex::new(HashSet::new());
        let newp = dir.path().join("brand-new.vault");
        allow(&set, newp.to_str().unwrap());
        assert!(is_allowed(&set, newp.to_str().unwrap()), "a save-mode path must be allowable before it exists");
    }

    #[test]
    fn missing_parent_fails_closed() {
        let set = Mutex::new(HashSet::new());
        assert!(!is_allowed(&set, "/no/such/dir/x.vault"), "unresolvable parent -> denied");
    }

    #[test]
    fn open_style_guard_refuses_a_path_never_handed_out() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real.vault"), b"x").unwrap();
        let set = Mutex::new(HashSet::new());
        assert!(!is_allowed(&set, dir.path().join("real.vault").to_str().unwrap()));
    }
}

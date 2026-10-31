//! Folder-provider helpers: detect the sibling copies external sync
//! clients drop next to a file on conflict, and a heuristic for whether a
//! path lives under a known synced root (drives a soft warning in the UI).

use std::path::Path;

/// Files next to `vault_path` that look like an external client's conflict
/// copy of it: `"{stem} N.{ext}"` (iCloud/Finder) or containing
/// `"conflicted copy"` / `"conflict"` (Dropbox/OneDrive), same extension.
pub fn sibling_conflicts(vault_path: &Path) -> Vec<String> {
    let stem = vault_path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let ext = vault_path.extension().and_then(|s| s.to_str()).unwrap_or("");
    let self_name = vault_path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let dir = match vault_path.parent() { Some(d) => d, None => return Vec::new() };
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == self_name { continue; }
        let matches_ext = ext.is_empty() || name.ends_with(&format!(".{ext}"));
        if !matches_ext { continue; }
        let low = name.to_lowercase();
        let numbered = name.starts_with(&format!("{stem} "))
            && name[stem.len()..].trim_start().chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false);
        let conflicted = low.contains("conflicted copy") || low.contains("conflict");
        if (numbered || conflicted) && name.starts_with(stem) {
            out.push(name);
        }
    }
    out
}

/// Best-effort: is this path under a folder some external client syncs?
pub fn looks_synced(path: &Path) -> bool {
    // Windows paths use `\`; normalise so the `/`-anchored markers match.
    let s = path.to_string_lossy().replace('\\', "/");
    const MARKERS: [&str; 6] = [
        "Mobile Documents",
        "/Dropbox",
        "/OneDrive",
        "Google Drive",
        "/Nextcloud",
        "/Sync",
    ];
    MARKERS.iter().any(|m| s.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detects_numbered_and_conflicted_copies() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("passwords.kokos");
        std::fs::write(&vault, b"x").unwrap();
        std::fs::write(dir.path().join("passwords 2.kokos"), b"x").unwrap();
        std::fs::write(dir.path().join("passwords (conflicted copy).kokos"), b"x").unwrap();
        std::fs::write(dir.path().join("unrelated.kokos"), b"x").unwrap();
        let mut got = sibling_conflicts(&vault);
        got.sort();
        assert_eq!(got.len(), 2, "got {:?}", got);
        assert!(got.iter().any(|s| s.contains("passwords 2")));
        assert!(got.iter().any(|s| s.contains("conflicted copy")));
    }

    #[test]
    fn no_conflicts_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.kokos");
        std::fs::write(&vault, b"x").unwrap();
        assert!(sibling_conflicts(&vault).is_empty());
    }

    #[test]
    fn looks_synced_recognizes_icloud_and_dropbox() {
        assert!(looks_synced(Path::new("/Users/me/Library/Mobile Documents/com~apple~CloudDocs/v.kokos")));
        assert!(looks_synced(Path::new("/Users/me/Dropbox/v.kokos")));
        assert!(!looks_synced(Path::new("/Users/me/Documents/v.kokos")));
    }

    #[test]
    fn looks_synced_recognizes_windows_paths() {
        assert!(looks_synced(Path::new(r"C:\Users\me\Dropbox\v.kokos")));
        assert!(looks_synced(Path::new(r"C:\Users\me\OneDrive\Documents\v.kokos")));
        assert!(!looks_synced(Path::new(r"C:\Users\me\Documents\v.kokos")));
    }
}

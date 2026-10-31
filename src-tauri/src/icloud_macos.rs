//! iCloud `.icloud` placeholder handling (folder provider). Detection is pure
//! filesystem (works on every OS). Materialization — triggering iCloud to
//! download an evicted file — is macOS-only; the non-macOS twin is a no-op
//! (folder sync there relies purely on the external client having the file).

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The hidden placeholder macOS leaves for an evicted ubiquitous file:
/// `dir/.{filename}.icloud`.
fn placeholder_path(path: &Path) -> PathBuf {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or_default();
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    dir.join(format!(".{name}.icloud"))
}

/// True when the real file is absent but its `.icloud` placeholder exists.
pub fn is_placeholder(path: &Path) -> bool {
    !path.exists() && placeholder_path(path).exists()
}

#[cfg(target_os = "macos")]
pub fn ensure_materialized(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        return Ok(());
    }
    if !is_placeholder(path) {
        return Ok(());
    }
    let _ = std::process::Command::new("/usr/bin/brctl")
        .args(["download", &path.to_string_lossy()])
        .status();
    for _ in 0..100 {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "iCloud download did not complete",
    ))
}

#[cfg(not(target_os = "macos"))]
pub fn ensure_materialized(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_file_is_not_a_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.kokos");
        std::fs::write(&p, b"hi").unwrap();
        assert!(!is_placeholder(&p));
    }

    #[test]
    fn evicted_file_with_dot_icloud_sibling_is_a_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("v.kokos");
        std::fs::write(dir.path().join(".v.kokos.icloud"), b"").unwrap();
        assert!(is_placeholder(&real));
    }

    #[test]
    fn ensure_materialized_noops_when_file_present() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.kokos");
        std::fs::write(&p, b"hi").unwrap();
        assert!(ensure_materialized(&p).is_ok());
    }
}

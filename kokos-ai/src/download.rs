//! Model downloader. The ONLY network egress in the AI feature: a pinned URL, streamed straight to disk while being hashed, and
//! SHA-256-verified before the file is accepted. Nothing lands at the
//! destination path unverified.

use std::io::{Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::AiError;

/// Ceiling on a single download. The largest pinned artifact is bge-m3 fp16 at
/// roughly 1.13 GB; a response an order of magnitude past that is a redirect
/// somewhere unintended or a hostile server, not a model. Checked twice —
/// against the advertised length, then against what actually arrives, because
/// `Content-Length` is a claim, not a promise.
const MAX_DOWNLOAD_BYTES: u64 = 3 * 1024 * 1024 * 1024;

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Accept or reject a finished `.part` file. On a hash match it is renamed
/// onto `dest`; on a mismatch it is deleted and `dest` is left untouched.
fn finalize(
    tmp: &Path,
    dest: &Path,
    got: String,
    expect_sha256: &str,
    what: &str,
) -> Result<(), AiError> {
    if !got.eq_ignore_ascii_case(expect_sha256) {
        let _ = std::fs::remove_file(tmp);
        return Err(AiError::Checksum {
            what: what.to_string(),
            expected: expect_sha256.to_string(),
            got,
        });
    }
    std::fs::rename(tmp, dest)?;
    Ok(())
}

/// Stream `url` into `<dest>.part`, hashing as the bytes arrive, and accept it
/// only if the digest matches. Buffering the whole response in memory first
/// would cost twice the file size in RSS, which for the largest model is over
/// two gigabytes.
///
/// `is_cancelled` is polled after every chunk; on cancel the `.part` file is
/// deleted and `AiError::Cancelled` is returned, so a re-download starts
/// clean — a half-written file is never resumed and never verified.
pub fn download_verified(
    url: &str,
    dest: &Path,
    expect_sha256: &str,
    what: &str,
    on_progress: impl Fn(u64, u64),
    is_cancelled: impl Fn() -> bool,
) -> Result<(), AiError> {
    let resp = reqwest::blocking::get(url).map_err(|e| AiError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(AiError::Http(format!("status {}", resp.status())));
    }
    let total = resp.content_length().unwrap_or(0);
    if total > MAX_DOWNLOAD_BYTES {
        return Err(AiError::Http(format!(
            "{what}: server advertises {total} bytes, over the {MAX_DOWNLOAD_BYTES} ceiling"
        )));
    }

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = dest.with_extension("part");

    let mut reader = resp;
    let mut hasher = Sha256::new();
    let mut written: u64 = 0;
    let mut chunk = vec![0u8; 64 * 1024];

    let mut f = std::fs::File::create(&tmp)?;
    loop {
        if is_cancelled() {
            drop(f);
            let _ = std::fs::remove_file(&tmp);
            return Err(AiError::Cancelled);
        }
        let n = match reader.read(&mut chunk) {
            Ok(n) => n,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(AiError::Http(e.to_string()));
            }
        };
        if n == 0 {
            break;
        }
        written += n as u64;
        if written > MAX_DOWNLOAD_BYTES {
            let _ = std::fs::remove_file(&tmp);
            return Err(AiError::Http(format!(
                "{what}: response passed the {MAX_DOWNLOAD_BYTES} ceiling mid-stream"
            )));
        }
        hasher.update(&chunk[..n]);
        if let Err(e) = f.write_all(&chunk[..n]) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        on_progress(written, total);
    }
    if let Err(e) = f.sync_all() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    drop(f);

    finalize(&tmp, dest, hex(&hasher.finalize()), expect_sha256, what)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part_with(dir: &Path, contents: &[u8]) -> (std::path::PathBuf, std::path::PathBuf) {
        let dest = dir.join("model.onnx");
        let tmp = dest.with_extension("part");
        std::fs::write(&tmp, contents).unwrap();
        (dest, tmp)
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn finalize_writes_file_on_match_and_leaves_no_temp() {
        let d = tempfile::tempdir().unwrap();
        let (dest, _) = part_with(d.path(), b"abc");
        let tmp = dest.with_extension("part");
        finalize(&tmp, &dest, sha256_hex(b"abc"), &sha256_hex(b"abc"), "test").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"abc");
        assert!(!tmp.exists(), "no .part temp left behind");
    }

    #[test]
    fn finalize_rejects_mismatch_and_writes_no_dest() {
        let d = tempfile::tempdir().unwrap();
        let (dest, tmp) = part_with(d.path(), b"abc");
        let err = finalize(&tmp, &dest, sha256_hex(b"abc"), &"00".repeat(32), "test").unwrap_err();
        assert!(matches!(err, AiError::Checksum { .. }));
        assert!(!dest.exists(), "a bad download must not land at dest");
        assert!(!tmp.exists(), "a rejected .part must be cleaned up");
    }

    #[test]
    fn the_ceiling_clears_the_largest_pinned_model() {
        assert!(MAX_DOWNLOAD_BYTES > 2 * 1_133_992_936);
    }
}

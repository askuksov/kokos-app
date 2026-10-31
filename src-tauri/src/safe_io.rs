//! Object-bound file I/O for user-picked paths. `paths::is_allowed` only
//! authorises a PATHNAME; between that check and the actual open an attacker
//! with write access to the directory can swap a symlink in. The helpers here
//! never reopen an unchecked pathname: writes go to an exclusively created
//! temp file in the destination directory and are renamed into place (rename
//! replaces a symlink at the destination, it never follows it); reads open the
//! file once and judge type/size on the open handle.

use std::io::{Read, Write};
use std::path::Path;

/// Upper bound for reading a vault file back for a ciphertext copy export.
/// Vault files are bounded by the vault open limit; this is a defensive cap.
pub const MAX_VAULT_COPY_SIZE: u64 = 1024 * 1024 * 1024;

/// Writes `bytes` to `path` owner-only (0600 / owner-only DACL), atomically:
/// temp file (create_new, no-follow, owner-only BEFORE any data is written) in
/// the same directory, `sync_all`, then rename over the destination. The temp
/// file is removed on any error. An existing destination is replaced, and its
/// old mode/ACL is NOT inherited. Pure + Tauri-free (testable).
pub fn write_atomic_owner_only(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    let dest = Path::new(path);
    let name = dest
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?;
    let parent = match dest.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    // Resolve the directory once; temp creation and rename then use the same
    // resolved directory, never the original (re-resolvable) spelling.
    let dir = parent.canonicalize()?;
    let final_path = dir.join(name);

    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
    let tmp_path = dir.join(tmp_name);

    let result = (|| -> std::io::Result<()> {
        let mut f = create_new_owner_only(&tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp_path, &final_path)?;
        #[cfg(unix)]
        {
            // Best effort: persist the rename itself.
            if let Ok(d) = std::fs::File::open(&dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

#[cfg(unix)]
fn create_new_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn create_new_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    // create_new never follows or reuses an existing name. The DACL is locked
    // down before any plaintext is written, so it is never under the
    // inherited/broad ACL.
    let f = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(e) = restrict_to_owner(path) {
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(f)
}

#[cfg(not(any(unix, windows)))]
fn create_new_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).create_new(true).open(path)
}

/// Reads a regular file of at most `max` bytes, opening it ONCE: type and size
/// are judged on the open handle and the read itself is capped with
/// `take(max + 1)`, so a file swapped or grown after any earlier check cannot
/// cause an oversized read. `Ok(None)` = not a regular file or over the cap.
pub fn read_regular_capped(path: &str, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    read_regular_capped_path(Path::new(path), max)
}

/// [`read_regular_capped`] for a `Path`, so non-UTF-8 paths work too.
pub fn read_regular_capped_path(path: &Path, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A FIFO/device would otherwise block in open() before we can look at it.
        opts.custom_flags(libc::O_NONBLOCK);
    }
    let f = opts.open(path)?;
    let md = f.metadata()?;
    if !md.is_file() || md.len() > max {
        return Ok(None);
    }
    let mut buf = Vec::with_capacity(md.len().min(max) as usize);
    f.take(max.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Ok(None);
    }
    Ok(Some(buf))
}

/// Replaces the file's DACL with a protected (non-inherited) one granting
/// full access only to the Owner Rights SID (`OW`), i.e. the file's owner.
#[cfg(windows)]
pub fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let wide = |s: &std::ffi::OsStr| -> Vec<u16> { s.encode_wide().chain(std::iter::once(0)).collect() };
    let wpath = wide(path.as_os_str());
    let sddl = wide(std::ffi::OsStr::new("D:P(A;;FA;;;OW)"));

    let mut sd: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated; `sd` is freed with LocalFree below.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut())
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `sd` is a valid self-relative descriptor returned above; `dacl`
    // points into it and stays valid until LocalFree.
    let got = unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) };
    let result = if got == 0 || present == 0 || dacl.is_null() {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: `wpath` is NUL-terminated; `dacl` is valid (see above).
        let rc = unsafe {
            SetNamedSecurityInfoW(
                wpath.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        };
        if rc == 0 { Ok(()) } else { Err(std::io::Error::from_raw_os_error(rc as i32)) }
    };
    // SAFETY: `sd` was allocated by the SDDL conversion (LocalAlloc).
    unsafe { LocalFree(sd) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn write_owner_only_is_0600_even_over_existing_0644() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("export.json");
        std::fs::write(&p, b"{}").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic_owner_only(p.to_str().unwrap(), b"{\"secret\":\"x\"}").unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&p).unwrap(), b"{\"secret\":\"x\"}");
        let p2 = dir.path().join("new.json");
        write_atomic_owner_only(p2.to_str().unwrap(), b"{}").unwrap();
        assert_eq!(std::fs::metadata(&p2).unwrap().permissions().mode() & 0o777, 0o600);
        // No temp file is left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_at_destination_is_replaced_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, b"keep").unwrap();
        let link = dir.path().join("export.json");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        write_atomic_owner_only(link.to_str().unwrap(), b"secret").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep", "symlink target must be untouched");
        assert_eq!(std::fs::read(&link).unwrap(), b"secret");
        assert!(!std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    }

    #[test]
    fn read_regular_capped_enforces_cap_and_type() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f.bin");
        std::fs::write(&f, b"hello").unwrap();
        assert_eq!(read_regular_capped(f.to_str().unwrap(), 5).unwrap().as_deref(), Some(&b"hello"[..]));
        assert!(read_regular_capped(f.to_str().unwrap(), 4).unwrap().is_none());
        assert!(read_regular_capped(dir.path().to_str().unwrap(), u64::MAX).unwrap().is_none());
    }
}

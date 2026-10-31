//! Cleanup mode for the Windows uninstaller.
//!
//! The uninstaller's pre-uninstall hook runs `kokos.exe --uninstall-scan` and,
//! if the user agrees, `kokos.exe --uninstall-purge`. Both deal only with what
//! the app wrote outside its install directory: saved master passwords and
//! Google Drive tokens in the OS credential store, and the browser
//! native-messaging registration. Vault files are never touched.
//!
//! The mode is picked in `run()` before the Tauri builder, so no window or
//! WebView ever starts.

use std::ffi::OsStr;

use crate::nmh::manifest::Browser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Scan,
    Purge,
}

/// Scan: nothing to remove. Purge: everything removed.
pub const EXIT_CLEAN: i32 = 0;
/// Scan only: there is something to remove.
pub const EXIT_FOUND: i32 = 1;
/// The scan could not finish, or the purge left something behind.
pub const EXIT_ERROR: i32 = 2;

/// The cleanup mode named by `argv[1]`, if any. Only the first argument
/// counts: a vault path opened by file association is never read as a flag,
/// and a flag placed after a path is ignored.
pub fn mode_from_args<I, S>(args: I) -> Option<Mode>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let first = args.into_iter().nth(1)?;
    match first.as_ref().to_str()? {
        "--uninstall-scan" => Some(Mode::Scan),
        "--uninstall-purge" => Some(Mode::Purge),
        _ => None,
    }
}

/// Whether a generic credential was written by `keyring_store`. keyring's
/// Windows backend stores `TargetName = "<account>.<service>"`,
/// `UserName = "<account>"` and `Comment = "keyring v<version>"`; requiring
/// all three keeps out a foreign credential that merely ends in `.Kokos`.
/// If a keyring upgrade changes the comment, the scan finds nothing — a
/// missed cleanup, never a wrong deletion.
#[cfg_attr(not(windows), allow(dead_code))] // only the Windows backend calls it
pub fn is_kokos_credential(target: &str, user: &str, comment: &str) -> bool {
    !user.is_empty()
        && target == format!("{user}.{}", crate::keyring_store::SERVICE)
        && comment.starts_with("keyring v")
}

pub fn scan_exit_code<T>(credentials: &Result<Vec<T>, u32>, browsers: &[Browser]) -> i32 {
    match credentials {
        Err(_) => EXIT_ERROR,
        Ok(found) if found.is_empty() && browsers.is_empty() => EXIT_CLEAN,
        Ok(_) => EXIT_FOUND,
    }
}

pub fn purge_exit_code(failures: usize) -> i32 {
    if failures == 0 {
        EXIT_CLEAN
    } else {
        EXIT_ERROR
    }
}

/// Runs one cleanup mode and returns the process exit code. The purge is
/// best-effort: every item is attempted even after one fails.
pub fn run(mode: Mode) -> i32 {
    let credentials = platform::kokos_credentials();
    let browsers = platform::registered_browsers();
    match mode {
        Mode::Scan => scan_exit_code(&credentials, &browsers),
        Mode::Purge => {
            let mut failures = match &credentials {
                Ok(targets) => targets
                    .iter()
                    .filter(|t| platform::delete_credential(t).is_err())
                    .count(),
                Err(_) => 1,
            };
            failures += browsers
                .iter()
                .filter(|b| platform::unregister_browser(**b).is_err())
                .count();
            purge_exit_code(failures)
        }
    }
}

/// No installer calls the cleanup flags outside Windows, so both are no-ops.
#[cfg(not(windows))]
mod platform {
    use crate::nmh::manifest::Browser;

    pub type Target = Vec<u16>;

    pub fn kokos_credentials() -> Result<Vec<Target>, u32> {
        Ok(Vec::new())
    }

    pub fn delete_credential(_target: &Target) -> Result<(), u32> {
        Ok(())
    }

    pub fn registered_browsers() -> Vec<Browser> {
        Vec::new()
    }

    pub fn unregister_browser(_browser: Browser) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
/// Windows: the credential store via `CredEnumerateW`/`CredDeleteW`, and the
/// browser registration via `nmh::manifest`.
mod platform {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    use windows_sys::Win32::Foundation::{GetLastError, ERROR_NOT_FOUND};
    use windows_sys::Win32::Security::Credentials::{
        CredDeleteW, CredEnumerateW, CredFree, CREDENTIALW, CRED_TYPE_GENERIC,
    };

    use super::is_kokos_credential;
    use crate::nmh::manifest::{self, Browser};

    /// A credential's `TargetName` as UTF-16 without the trailing NUL. Kept raw
    /// so the delete names exactly what the enumeration returned, even if the
    /// path is not valid Unicode.
    pub type Target = Vec<u16>;

    const BROWSERS: [Browser; 2] = [Browser::Chrome, Browser::Firefox];

    pub fn kokos_credentials() -> Result<Vec<Target>, u32> {
        let mut count: u32 = 0;
        let mut list: *mut *mut CREDENTIALW = std::ptr::null_mut();
        // The API filter only supports a `PREFIX*` pattern, and Kokos targets
        // share a suffix, so enumerate everything and let
        // `is_kokos_credential` pick ours.
        // SAFETY: a NULL filter is allowed. On success the API returns `count`
        // credential pointers that stay valid until `CredFree(list)` below.
        if unsafe { CredEnumerateW(std::ptr::null(), 0, &mut count, &mut list) } == 0 {
            // SAFETY: plain thread-local error read.
            let err = unsafe { GetLastError() };
            return if err == ERROR_NOT_FOUND { Ok(Vec::new()) } else { Err(err) };
        }
        let mut found = Vec::new();
        for i in 0..count as usize {
            // SAFETY: `i < count` and `list` holds `count` valid pointers.
            let cred = unsafe { &**list.add(i) };
            if cred.Type != CRED_TYPE_GENERIC {
                continue;
            }
            // SAFETY: each field is NULL or a NUL-terminated string owned by `list`.
            let (target, user, comment) = unsafe {
                (
                    from_wide(cred.TargetName),
                    from_wide(cred.UserName),
                    from_wide(cred.Comment),
                )
            };
            if is_kokos_credential(&lossy(&target), &lossy(&user), &lossy(&comment)) {
                found.push(target);
            }
        }
        // SAFETY: `list` came from a successful `CredEnumerateW` and is freed once.
        unsafe { CredFree(list as *const _) };
        Ok(found)
    }

    pub fn delete_credential(target: &Target) -> Result<(), u32> {
        let mut name = target.clone();
        name.push(0);
        // SAFETY: `name` is NUL-terminated and outlives the call.
        if unsafe { CredDeleteW(name.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            // SAFETY: plain thread-local error read.
            let err = unsafe { GetLastError() };
            // Gone already (the running app removed it meanwhile) is removed.
            return if err == ERROR_NOT_FOUND { Ok(()) } else { Err(err) };
        }
        Ok(())
    }

    pub fn registered_browsers() -> Vec<Browser> {
        let Some(home) = crate::commands::nmh_home() else {
            return Vec::new();
        };
        BROWSERS
            .into_iter()
            .filter(|b| manifest::is_installed(*b, &home))
            .collect()
    }

    pub fn unregister_browser(browser: Browser) -> std::io::Result<()> {
        let home = crate::commands::nmh_home().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "APPDATA is not set")
        })?;
        manifest::remove(browser, &home)
    }

    /// # Safety
    /// `p` must be NULL or point at a NUL-terminated UTF-16 string.
    unsafe fn from_wide(p: *const u16) -> Vec<u16> {
        if p.is_null() {
            return Vec::new();
        }
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        std::slice::from_raw_parts(p, len).to_vec()
    }

    fn lossy(w: &[u16]) -> String {
        OsString::from_wide(w).to_string_lossy().into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_master_password_is_ours() {
        assert!(is_kokos_credential(
            r"\\?\C:\Users\u\Documents\a.kokos.Kokos",
            r"\\?\C:\Users\u\Documents\a.kokos",
            "keyring v3.6.3",
        ));
        assert!(is_kokos_credential(
            r"C:\Users\u\Documents\a.kokos.Kokos",
            r"C:\Users\u\Documents\a.kokos",
            "keyring v3.6.3",
        ));
    }

    #[test]
    fn drive_token_is_ours() {
        assert!(is_kokos_credential(
            r"gdrive:C:\Users\u\Documents\a.kokos.Kokos",
            r"gdrive:C:\Users\u\Documents\a.kokos",
            "keyring v3.6.3",
        ));
    }

    #[test]
    fn foreign_credential_ending_in_kokos_is_not_ours() {
        // Target and user disagree.
        assert!(!is_kokos_credential("other.Kokos", "someone", "keyring v3.6.3"));
        // Right shape, written by something other than keyring.
        assert!(!is_kokos_credential(
            r"C:\a.kokos.Kokos",
            r"C:\a.kokos",
            "Created by another app",
        ));
        // Another service of ours (the macOS Touch ID copy uses this name).
        assert!(!is_kokos_credential(
            r"C:\a.kokos.Kokos-Biometric",
            r"C:\a.kokos",
            "keyring v3.6.3",
        ));
    }

    #[test]
    fn empty_user_is_never_ours() {
        assert!(!is_kokos_credential(".Kokos", "", "keyring v3.6.3"));
        assert!(!is_kokos_credential("Kokos", "", "keyring v3.6.3"));
    }

    #[test]
    fn flags_select_their_mode() {
        assert_eq!(mode_from_args(["kokos.exe", "--uninstall-scan"]), Some(Mode::Scan));
        assert_eq!(mode_from_args(["kokos.exe", "--uninstall-purge"]), Some(Mode::Purge));
    }

    #[test]
    fn anything_else_is_a_normal_launch() {
        assert_eq!(mode_from_args(["kokos.exe"]), None);
        assert_eq!(mode_from_args(["kokos.exe", r"C:\Users\u\a.kokos"]), None);
        assert_eq!(mode_from_args(["kokos.exe", "--uninstall"]), None);
        assert_eq!(mode_from_args(["kokos.exe", "--UNINSTALL-SCAN"]), None);
        assert_eq!(mode_from_args(Vec::<&str>::new()), None);
    }

    #[test]
    fn flag_after_a_path_is_ignored() {
        assert_eq!(
            mode_from_args(["kokos.exe", r"C:\Users\u\a.kokos", "--uninstall-purge"]),
            None
        );
    }

    #[test]
    fn scan_exit_codes() {
        let none: Result<Vec<Vec<u16>>, u32> = Ok(Vec::new());
        let one: Result<Vec<Vec<u16>>, u32> = Ok(vec![vec![0x61]]);
        let failed: Result<Vec<Vec<u16>>, u32> = Err(1312);

        assert_eq!(scan_exit_code(&none, &[]), EXIT_CLEAN);
        assert_eq!(scan_exit_code(&one, &[]), EXIT_FOUND);
        assert_eq!(scan_exit_code(&none, &[Browser::Chrome]), EXIT_FOUND);
        assert_eq!(scan_exit_code(&one, &[Browser::Firefox]), EXIT_FOUND);
        // A failed credential scan is an error even when browsers were found:
        // the hook still asks, and the purge still removes what it can.
        assert_eq!(scan_exit_code(&failed, &[]), EXIT_ERROR);
        assert_eq!(scan_exit_code(&failed, &[Browser::Chrome]), EXIT_ERROR);
    }

    #[test]
    fn purge_exit_codes() {
        assert_eq!(purge_exit_code(0), EXIT_CLEAN);
        assert_eq!(purge_exit_code(1), EXIT_ERROR);
        assert_eq!(purge_exit_code(3), EXIT_ERROR);
    }

    #[test]
    fn exit_codes_are_the_hook_contract() {
        // The NSIS hook asks on any non-zero scan code; `uninstall-hooks.nsh`
        // relies on these values, so they must not drift.
        assert_eq!((EXIT_CLEAN, EXIT_FOUND, EXIT_ERROR), (0, 1, 2));
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_both_modes_do_nothing() {
        assert_eq!(run(Mode::Scan), EXIT_CLEAN);
        assert_eq!(run(Mode::Purge), EXIT_CLEAN);
    }
}

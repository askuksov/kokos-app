//! Chrome/Firefox native-messaging manifest writer + per-OS path table. This
//! module puts a *manifest file* into the browser's own
//! native-messaging-hosts directory; its `allowed_origins` /
//! `allowed_extensions` entry is the browser-side half of the whitelist (the
//! app-side half is `Settings.nmh_chrome_ids` / `nmh_firefox_ids`, checked in
//! `super::is_allowed_origin`). A manifest written with a wrong or
//! too-wide entry silently widens who may open a channel to the vault, and a
//! `remove` that fails to delete leaves a live channel registered, so:
//!  - every function takes `home: &Path` explicitly — nothing here reads
//!    `$HOME` itself; the real value is supplied by the command layer, tests
//!    always pass a `tempfile::tempdir()`. Windows extends
//!    the same discipline to the registry: the private `*_at` seams take the
//!    HKCU subkey ROOT explicitly (`""` in production), so a test run writes
//!    under a throwaway key and can never touch the developer's real
//!    Chrome/Firefox registration.
//!  - the Chrome extension id is normalised defensively before it is ever
//!    embedded in `allowed_origins` (see `normalise_chrome_id` below); full
//!    id-SHAPE validation (32 a-p letters) is the Tauri command layer's job,
//!    not this module's — this is only a floor against this
//!    module itself manufacturing a malformed entry.
//!  - the file is written via temp-file + rename and `0o600` under
//!    `#[cfg(unix)]`, mirroring `settings::save`.
//!  - Windows registration is two-part (file + HKCU key, see `registry_key`),
//!    and the two halves are ordered so a partial failure fails CLOSED:
//!    `install` writes the file first and rolls it back if the key write
//!    fails, `remove` drops the key first — the key is the only half a
//!    browser follows, so a leftover of the other half grants nothing.

pub use kokos_nmh::origin::Browser;

use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(windows)]
use std::ffi::{OsStr, OsString};
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR,
};
#[cfg(windows)]
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegGetValueW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ,
};

/// Full path of the manifest file inside a browser's native-messaging-hosts
/// directory. The filename is shared by both browsers: each browser looks
/// up the host by `HOST_NAME`, and the file's own `name` field (set in
/// `json_for`) must match it.
fn manifest_path(dir: &Path) -> PathBuf {
    dir.join(format!("{}.json", kokos_nmh::transport::HOST_NAME))
}

/// Per-OS, per-browser native-messaging-hosts directory, rooted at `home`
/// (the user's home directory — the parent of `Library/...` on macOS, NOT
/// the browser's own config dir). `None` on a platform this module does not
/// yet support; `install`/`remove` turn that into `io::ErrorKind::Unsupported`
/// so the command layer can map it to a user-facing
/// `unsupported_platform` error instead of silently doing nothing.
#[cfg(target_os = "macos")]
pub fn dir_for(browser: Browser, home: &Path) -> Option<PathBuf> {
    let tail = match browser {
        Browser::Chrome => "Library/Application Support/Google/Chrome/NativeMessagingHosts",
        Browser::Firefox => "Library/Application Support/Mozilla/NativeMessagingHosts",
    };
    Some(home.join(tail))
}

#[cfg(target_os = "linux")]
pub fn dir_for(browser: Browser, home: &Path) -> Option<PathBuf> {
    let tail = match browser {
        Browser::Chrome => ".config/google-chrome/NativeMessagingHosts",
        Browser::Firefox => ".mozilla/native-messaging-hosts",
    };
    Some(home.join(tail))
}

/// Windows has no directory a browser scans (that whole mechanism is
/// registry-based — see `registry_key`), so where the manifest FILE lives is
/// entirely our choice; the registry value is what points at it. It goes in
/// the app's own roaming config dir, i.e. the same `<config-root>/<bundle-id>`
/// shape `kokos_nmh::transport::config_dir_from` derives on the other
/// platforms, so all three OSes keep the app's files in one place per user.
/// The per-browser leaf is not cosmetic: both browsers' manifests share ONE
/// filename (`manifest_path` names it after `HOST_NAME`) while their bodies
/// differ (`allowed_origins` vs `allowed_extensions`), so a flat directory
/// would make installing one browser silently overwrite the other's manifest.
///
/// Mind the parameter: on Windows `home` is `%APPDATA%` — the roaming
/// app-data root, `C:\Users\<user>\AppData\Roaming` — NOT the user profile
/// directory the unix arms take. `%APPDATA%` is the authoritative value and
/// is routinely redirected (roaming profiles, folder redirection on managed
/// machines), so deriving it from the profile path would write to a
/// directory the user's actual environment does not use.
#[cfg(windows)]
pub fn dir_for(browser: Browser, home: &Path) -> Option<PathBuf> {
    let leaf = match browser {
        Browser::Chrome => "Chrome",
        Browser::Firefox => "Firefox",
    };
    Some(
        home.join(kokos_nmh::transport::HOST_NAME)
            .join("NativeMessagingHosts")
            .join(leaf),
    )
}

/// Every platform this module does not implement falls back here — `None`,
/// turned into `Unsupported` by `install`/`remove`. No live target lands here
/// today (macOS, Linux and Windows all have an arm above); it is what keeps a
/// hypothetical fourth OS from silently registering nothing.
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
pub fn dir_for(_browser: Browser, _home: &Path) -> Option<PathBuf> {
    None
}


/// HKCU subkey the browser reads, under `registry_root`.
///
/// `registry_root` is the registry's counterpart to the `home` parameter
/// threaded through the rest of this module: `""` produces the real,
/// browser-visible key, and the unit tests pass a throwaway `Software\...`
/// prefix so that exercising install/remove for real cannot disturb the
/// developer's own Chrome/Firefox host registrations. Only the private `*_at`
/// seams take it; every public entry point pins it to `LIVE_REGISTRY_ROOT`.
#[cfg(windows)]
fn registry_key(browser: Browser, registry_root: &str) -> String {
    let vendor = match browser {
        Browser::Chrome => r"Software\Google\Chrome\NativeMessagingHosts",
        Browser::Firefox => r"Software\Mozilla\NativeMessagingHosts",
    };
    let key = format!(r"{vendor}\{}", kokos_nmh::transport::HOST_NAME);
    if registry_root.is_empty() {
        key
    } else {
        format!(r"{registry_root}\{key}")
    }
}

/// The real thing: no prefix, so `registry_key` yields the exact paths the
/// browsers read.
#[cfg(windows)]
const LIVE_REGISTRY_ROOT: &str = "";

/// NUL-terminated UTF-16 for the Win32 `*W` entry points. An INTERIOR NUL is
/// rejected instead of being passed on: C string handling would silently
/// truncate there, which for a registry path or a manifest path means the API
/// acting on a *different*, shorter target than the one this module computed.
/// Nothing we build can contain one today (the pieces are constants plus
/// `home`), so this is a floor, not a live case.
#[cfg(windows)]
fn wide(s: &OsStr) -> io::Result<Vec<u16>> {
    let mut v: Vec<u16> = s.encode_wide().collect();
    if v.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interior NUL in a registry path or value",
        ));
    }
    v.push(0);
    Ok(v)
}

/// Win32 status -> `io::Error`. `from_raw_os_error` is the mapping the
/// standard library itself uses on Windows, so callers keep getting the
/// ordinary `ErrorKind`s (`ERROR_FILE_NOT_FOUND` -> `NotFound`,
/// `ERROR_ACCESS_DENIED` -> `PermissionDenied`) that the command layer
/// already classifies.
#[cfg(windows)]
fn win32_error(code: WIN32_ERROR) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

/// Creates (or opens) `key` under HKCU and sets its default value to
/// `manifest` — the browser-side registration proper.
///
/// `manifest` must be absolute: a relative value would be resolved by the
/// BROWSER against its own working directory, which is the same trap
/// `host_binary_path`'s `is_absolute()` guard exists for one seam further
/// down. Checked here rather than assumed, because `install` derives the path
/// from a caller-supplied `home`.
///
/// The key is created with default security (null `SECURITY_ATTRIBUTES`),
/// which under HKCU means "writable by this user only" — the inherited ACL is
/// what we want, never a permissive one of our own making.
#[cfg(windows)]
fn write_host_key(key: &str, manifest: &Path) -> io::Result<()> {
    if !manifest.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "manifest path must be absolute",
        ));
    }
    let key_w = wide(OsStr::new(key))?;
    let value_w = wide(manifest.as_os_str())?;
    let value_bytes = u32::try_from(std::mem::size_of_val(&value_w[..])).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "registry value too large")
    })?;

    let mut hkey: HKEY = std::ptr::null_mut();
    // SAFETY: `key_w` is a live NUL-terminated UTF-16 buffer for the duration
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            key_w.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut hkey,
            std::ptr::null_mut(),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(win32_error(rc));
    }

    // SAFETY: `hkey` is the live handle just returned by `RegCreateKeyExW`
    let rc = unsafe {
        RegSetValueExW(
            hkey,
            std::ptr::null(),
            0,
            REG_SZ,
            value_w.as_ptr().cast::<u8>(),
            value_bytes,
        )
    };
    // SAFETY: `hkey` is still the live handle from `RegCreateKeyExW` and is
    unsafe {
        RegCloseKey(hkey);
    }
    if rc != ERROR_SUCCESS {
        return Err(win32_error(rc));
    }
    Ok(())
}

/// The manifest path currently registered under `key`, or `None` when the key
/// or its default value is absent, is not a string, or cannot be read. Fail
/// closed in the "not installed" direction: this only ever feeds
/// `is_installed`, where reporting a registration that is not really there is
/// the worse mistake.
#[cfg(windows)]
fn read_host_key(key: &str) -> Option<PathBuf> {
    let key_w = wide(OsStr::new(key)).ok()?;
    let mut cb: u32 = 0;
    // SAFETY: `key_w` is a live NUL-terminated UTF-16 buffer; a null
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key_w.as_ptr(),
            std::ptr::null(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut cb,
        )
    };
    if rc != ERROR_SUCCESS || cb == 0 {
        return None;
    }

    let mut buf = vec![0u16; (cb as usize).div_ceil(2)];
    let mut cb_out = u32::try_from(std::mem::size_of_val(&buf[..])).ok()?;
    // SAFETY: same arguments as the probe above, except `pvdata` now points
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key_w.as_ptr(),
            std::ptr::null(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast::<std::ffi::c_void>(),
            &mut cb_out,
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let chars = (cb_out as usize / 2).min(buf.len());
    let value = &buf[..chars];
    let value = match value.iter().position(|&c| c == 0) {
        Some(end) => &value[..end],
        None => value,
    };
    if value.is_empty() {
        return None;
    }
    Some(PathBuf::from(OsString::from_wide(value)))
}

/// Deletes `key` under HKCU. Idempotent, mirroring the unix file delete: a
/// key that was never created is not an error.
///
/// `RegDeleteKeyW` removes ONE key and refuses when that key still has
/// subkeys, which is exactly the safety property wanted here — the leaf
/// `dev.kuksov.kokos` goes away while the shared parent
/// `...\NativeMessagingHosts`, which holds every OTHER application's host
/// registrations, is never touched, and no recursive delete exists on this
/// path to get pointed at the wrong key.
#[cfg(windows)]
fn delete_host_key(key: &str) -> io::Result<()> {
    let key_w = wide(OsStr::new(key))?;
    // SAFETY: `key_w` is a live NUL-terminated UTF-16 buffer naming a subkey
    let rc = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, key_w.as_ptr()) };
    match rc {
        ERROR_SUCCESS | ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(()),
        other => Err(win32_error(other)),
    }
}

/// Normalises a Chrome extension id/origin into the exact
/// `chrome-extension://<id>/` form `allowed_origins` expects — defensively,
/// since this module writes into the browser's own trust store. Decisions,
/// keyed to the hostile shapes it must handle:
///   - `"abc"`                               -> `chrome-extension://abc/` (bare id, wrapped)
///   - `"chrome-extension://abc/"`           -> `chrome-extension://abc/` (already correct, unchanged)
///   - `"chrome-extension://abc"`            -> `chrome-extension://abc/` (missing trailing slash, added)
///   - `"chrome-extension://abc/popup.html"` -> `chrome-extension://abc/` (path segment stripped, never embedded)
///   - `"ab/cd"` (a `/` inside the id itself) -> `chrome-extension://ab/` (cut at the first separator, same rule as `chrome_key` in `mod.rs`)
///   - `"ab\0cd"` (embedded NUL)              -> `chrome-extension://ab/` (cut at the NUL too)
///   - `""` / `"chrome-extension://"`        -> `chrome-extension://invalid/` (an empty id is neutralised to a fixed placeholder, never left as an empty path segment)
///   - `".."` / `"..."` / `"chrome-extension://../"` -> `chrome-extension://invalid/` (a candidate that is nothing but dots is neutralised the same way, so a traversal-shaped id can never reach `allowed_origins`)
///
/// `"invalid"` is not a wildcard: it can never match a real Chrome extension
/// id (which is always 32 lowercase a-p letters), so this only ever makes
/// the whitelist check fail closed, never wider.
fn normalise_chrome_id(input: &str) -> String {
    let trimmed = input.trim();
    let without_scheme = trimmed
        .strip_prefix("chrome-extension://")
        .unwrap_or(trimmed);
    let candidate = without_scheme
        .split(['/', '?', '#', '\0'])
        .next()
        .unwrap_or("");
    let safe = if candidate.is_empty() || candidate.chars().all(|c| c == '.') {
        "invalid"
    } else {
        candidate
    };
    format!("chrome-extension://{safe}/")
}

/// Builds the native-messaging manifest JSON body for `browser`. `host_path`
/// is the absolute path to the `kokos-nmh` binary (`host_binary_path`
/// resolves it; this function embeds it verbatim). `extension_id` is normalised for Chrome
/// (see `normalise_chrome_id`) before being embedded; Firefox ids have no
/// scheme/path structure to strip (they are `name@domain` or a `{uuid}` —
/// see `nmh/mod.rs`'s `firefox_key`, which trims only and compares
/// case-sensitively), so they are embedded as given.
pub fn json_for(browser: Browser, host_path: &str, extension_id: &str) -> String {
    let body = match browser {
        Browser::Chrome => serde_json::json!({
            "name": kokos_nmh::transport::HOST_NAME,
            "description": "Kokos native messaging host",
            "path": host_path,
            "type": "stdio",
            "allowed_origins": [normalise_chrome_id(extension_id)],
        }),
        Browser::Firefox => serde_json::json!({
            "name": kokos_nmh::transport::HOST_NAME,
            "description": "Kokos native messaging host",
            "path": host_path,
            "type": "stdio",
            "allowed_extensions": [extension_id],
        }),
    };
    serde_json::to_string_pretty(&body)
        .expect("a serde_json::json! Value built only from strings never fails to serialise")
}

/// Writes the manifest file for `browser` into `dir_for`'s directory under
/// `home`, creating the directory if needed and overwriting any existing
/// manifest. Mirrors `settings::save`: write to a temp file, `0o600` it under
/// `#[cfg(unix)]`, then atomically `rename` into place — so a reader (the
/// browser) never observes a partially-written manifest. Returns the
/// manifest's final path. `Err(Unsupported)` when `dir_for` returns `None`
/// for this platform.
///
/// The whole of `install` on macOS/Linux; on Windows only its first half —
/// see `install_at`, which adds the registry key that makes this file
/// reachable at all.
fn write_manifest(
    browser: Browser,
    home: &Path,
    host_path: &str,
    extension_id: &str,
) -> io::Result<PathBuf> {
    let Some(dir) = dir_for(browser, home) else {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    };
    std::fs::create_dir_all(&dir)?;
    let path = manifest_path(&dir);
    let tmp = dir.join(format!("{}.json.tmp", kokos_nmh::transport::HOST_NAME));
    let data = json_for(browser, host_path, extension_id);
    std::fs::write(&tmp, data)?;
    #[cfg(unix)]
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Deletes the manifest file for `browser` under `home`. Idempotent: a
/// missing file (never installed, or already removed) is not an error — a
/// caller that unconditionally calls this on every "disable browser
/// integration" path must not have to first check whether it ran before.
/// `Err(Unsupported)` when `dir_for` returns `None` for this platform (there
/// is nothing to remove because nothing could have been installed).
fn remove_manifest_file(browser: Browser, home: &Path) -> io::Result<()> {
    let Some(dir) = dir_for(browser, home) else {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    };
    match std::fs::remove_file(manifest_path(&dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Registers `browser`'s manifest under `home` (see `write_manifest`) and
/// returns its path. `Err(Unsupported)` on a platform without a `dir_for`
/// entry.
#[cfg(not(windows))]
pub fn install(
    browser: Browser,
    home: &Path,
    host_path: &str,
    extension_id: &str,
) -> io::Result<PathBuf> {
    write_manifest(browser, home, host_path, extension_id)
}

/// Windows registration: the manifest file (`write_manifest`) plus the HKCU
/// key that points the browser at it. Both halves, or neither.
#[cfg(windows)]
pub fn install(
    browser: Browser,
    home: &Path,
    host_path: &str,
    extension_id: &str,
) -> io::Result<PathBuf> {
    install_at(browser, home, host_path, extension_id, LIVE_REGISTRY_ROOT)
}

/// `install` with the HKCU root left open for the tests (see `registry_key`).
#[cfg(windows)]
fn install_at(
    browser: Browser,
    home: &Path,
    host_path: &str,
    extension_id: &str,
    registry_root: &str,
) -> io::Result<PathBuf> {
    let path = write_manifest(browser, home, host_path, extension_id)?;
    if let Err(e) = write_host_key(&registry_key(browser, registry_root), &path) {
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    Ok(path)
}

/// Unregisters `browser` under `home`. Idempotent — see
/// `remove_manifest_file`.
#[cfg(not(windows))]
pub fn remove(browser: Browser, home: &Path) -> io::Result<()> {
    remove_manifest_file(browser, home)
}

/// Windows: drops the HKCU key AND the manifest file, in that order, and
/// tolerates either being absent already.
#[cfg(windows)]
pub fn remove(browser: Browser, home: &Path) -> io::Result<()> {
    remove_at(browser, home, LIVE_REGISTRY_ROOT)
}

/// `remove` with the HKCU root left open for the tests (see `registry_key`).
///
/// Key BEFORE file, the mirror image of `install_at`'s order: the key is the
/// only half a browser follows, so deleting it is what actually revokes the
/// channel. If the file delete then fails (a lock, a permission change), what
/// is left on disk is an inert JSON file nothing looks for — whereas the
/// other order could leave a live registration pointing at a manifest that is
/// already gone, and a browser resolving that key would be operating on our
/// registration with a path we no longer control.
#[cfg(windows)]
fn remove_at(browser: Browser, home: &Path, registry_root: &str) -> io::Result<()> {
    delete_host_key(&registry_key(browser, registry_root))?;
    remove_manifest_file(browser, home)
}

/// Whether a manifest file for `browser` already exists under `home`. Reads
/// only the filesystem, never `dir_for`'s absence as a truthy signal: an
/// unsupported platform reports `false` (nothing can be installed there),
/// not an error — this is a plain presence check, not a capability probe.
#[cfg(not(windows))]
pub fn is_installed(browser: Browser, home: &Path) -> bool {
    match dir_for(browser, home) {
        Some(dir) => manifest_path(&dir).is_file(),
        None => false,
    }
}

/// Whether `browser` is registered. On Windows that question is answered by
/// the REGISTRY, not by the filesystem: the key is what a browser resolves,
/// and the manifest file it names is ours to place anywhere — a file sitting
/// in `dir_for`'s directory with no key registers nothing at all, so
/// reporting it as installed would tell the user the integration is live when
/// no browser can see it. `home` is therefore unused here; it stays in the
/// signature because this is one function to every caller, cfg'd only in its
/// implementation.
#[cfg(windows)]
pub fn is_installed(browser: Browser, _home: &Path) -> bool {
    is_installed_at(browser, LIVE_REGISTRY_ROOT)
}

/// `is_installed` with the HKCU root left open for the tests (see
/// `registry_key`).
#[cfg(windows)]
fn is_installed_at(browser: Browser, registry_root: &str) -> bool {
    read_host_key(&registry_key(browser, registry_root)).is_some()
}

/// Both `tauri dev` (target/debug/Kokos) and a bundle
/// (Kokos.app/Contents/MacOS/Kokos) put the sidecar next to the app binary,
/// so one rule serves both.
fn sibling_host(exe: &Path) -> Option<PathBuf> {
    Some(exe.parent()?.join(HOST_BINARY_NAME))
}

/// File name of the sidecar sitting next to the app binary. Windows is the
/// odd one out only in carrying the `.exe` suffix Tauri's `copy_binaries`
/// gives it. Hardcoding the bare name there would not fail loudly: the
/// `is_file()` check in `host_binary_path` would simply not find it, and the
/// Settings UI would report a missing sidecar for a sidecar that is present
/// under a different name — so the suffix lives here, once, rather than being
/// spelled into either caller.
#[cfg(windows)]
const HOST_BINARY_NAME: &str = "kokos-nmh.exe";
#[cfg(not(windows))]
const HOST_BINARY_NAME: &str = "kokos-nmh";

/// Absolute path to write into a manifest's `path` field. `None` when the
/// sidecar is missing — the Settings UI then tells the user to build it
/// instead of registering a dangling path. `json_for` embeds whatever this
/// returns with no further check, so this is the one seam
/// that must never hand back a relative or empty path: `current_exe()` is
/// documented to return an absolute path on the platforms we support, and
/// `sibling_host` only ever swaps the file name via `parent()`/`join()`,
/// which preserves that — but the `is_absolute()` guard below asserts it
/// rather than trusting the platform doc, so a future change to either
/// function fails closed (`None`) instead of silently writing a relative
/// `path` into a browser's trust store.
pub fn host_binary_path(_app: &tauri::AppHandle) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let p = sibling_host(&exe)?;
    if !(p.is_absolute() && p.is_file()) {
        return None;
    }
    if let Some(wrapper) = crate::nmh::snap::host_wrapper() {
        return Some(wrapper);
    }
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kokos_nmh::origin::Browser;

    #[cfg(windows)]
    fn install(
        browser: Browser,
        home: &Path,
        host_path: &str,
        extension_id: &str,
    ) -> io::Result<PathBuf> {
        install_at(browser, home, host_path, extension_id, &test_registry_root())
    }

    #[cfg(windows)]
    fn remove(browser: Browser, home: &Path) -> io::Result<()> {
        remove_at(browser, home, &test_registry_root())
    }

    #[cfg(windows)]
    fn is_installed(browser: Browser, _home: &Path) -> bool {
        is_installed_at(browser, &test_registry_root())
    }

    /// A registry prefix private to the calling test. The Rust test harness
    /// names each thread after its test, which makes that name the one
    /// isolation key available without threading a parameter through tests
    /// shared with unix. Non-alphanumerics are mapped to `_` so a `::` in a
    /// test path can never introduce another key level.
    ///
    /// Wiped once per thread on first use, so a crashed earlier run cannot
    /// leave a key that makes the next run's opening `assert!(!is_installed(..))`
    /// fail. Everything lives under one `Software\Kokos-tests` subtree that no
    /// browser reads.
    #[cfg(windows)]
    fn test_registry_root() -> String {
        use std::cell::Cell;
        let thread = std::thread::current();
        let safe: String = thread
            .name()
            .unwrap_or("unnamed")
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let root = format!(r"Software\Kokos-tests\{safe}");
        thread_local! {
            static PURGED: Cell<bool> = const { Cell::new(false) };
        }
        PURGED.with(|p| {
            if !p.get() {
                p.set(true);
                purge_registry_subtree(&root);
            }
        });
        root
    }

    /// Best-effort recursive delete of a test's own subtree. Failure is
    /// ignored on purpose: the subtree simply may not exist yet, and a test
    /// must not fail over housekeeping.
    #[cfg(windows)]
    fn purge_registry_subtree(root: &str) {
        let Ok(w) = wide(OsStr::new(root)) else {
            return;
        };
        // SAFETY: `w` is a live NUL-terminated UTF-16 buffer naming a subkey of
        unsafe {
            windows_sys::Win32::System::Registry::RegDeleteTreeW(
                windows_sys::Win32::System::Registry::HKEY_CURRENT_USER,
                w.as_ptr(),
            )
        };
    }

    #[test]
    fn chrome_manifest_shape() {
        let s = json_for(
            Browser::Chrome,
            "/Applications/Kokos.app/Contents/MacOS/kokos-nmh",
            "abcdefghijklmnop",
        );
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["name"], "dev.kuksov.kokos");
        assert_eq!(v["type"], "stdio");
        assert_eq!(
            v["path"],
            "/Applications/Kokos.app/Contents/MacOS/kokos-nmh"
        );
        assert_eq!(
            v["allowed_origins"][0],
            "chrome-extension://abcdefghijklmnop/"
        );
        assert!(
            v.get("allowed_extensions").is_none(),
            "that key is Firefox-only"
        );
    }

    #[test]
    fn firefox_manifest_shape() {
        let s = json_for(Browser::Firefox, "/x/kokos-nmh", "kokos@example.org");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["allowed_extensions"][0], "kokos@example.org");
        assert!(
            v.get("allowed_origins").is_none(),
            "that key is Chrome-only"
        );
    }

    #[test]
    fn a_bare_chrome_id_is_expanded_to_an_origin_and_an_origin_is_kept() {
        for input in [
            "abcdefghijklmnop",
            "chrome-extension://abcdefghijklmnop/",
            "chrome-extension://abcdefghijklmnop",
        ] {
            let v: serde_json::Value =
                serde_json::from_str(&json_for(Browser::Chrome, "/x", input)).unwrap();
            assert_eq!(
                v["allowed_origins"][0], "chrome-extension://abcdefghijklmnop/",
                "input {input}"
            );
        }
    }

    #[test]
    fn install_then_detect_then_remove_is_idempotent() {
        let home = tempfile::tempdir().unwrap();
        let Some(_dir) = dir_for(Browser::Chrome, home.path()) else {
            return;
        };
        assert!(!is_installed(Browser::Chrome, home.path()));
        let p = install(
            Browser::Chrome,
            home.path(),
            "/x/kokos-nmh",
            "abcdefghijklmnop",
        )
        .unwrap();
        assert!(p.is_file());
        assert!(is_installed(Browser::Chrome, home.path()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        install(Browser::Chrome, home.path(), "/x/kokos-nmh", "other").unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v["allowed_origins"][0], "chrome-extension://other/");
        remove(Browser::Chrome, home.path()).unwrap();
        assert!(!is_installed(Browser::Chrome, home.path()));
        remove(Browser::Chrome, home.path()).unwrap();
    }

    #[test]
    fn directory_table_is_per_browser_and_per_os() {
        let home = std::path::Path::new("/home/x");
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                dir_for(Browser::Chrome, home).unwrap(),
                home.join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
            );
            assert_eq!(
                dir_for(Browser::Firefox, home).unwrap(),
                home.join("Library/Application Support/Mozilla/NativeMessagingHosts")
            );
        }
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                dir_for(Browser::Chrome, home).unwrap(),
                home.join(".config/google-chrome/NativeMessagingHosts")
            );
            assert_eq!(
                dir_for(Browser::Firefox, home).unwrap(),
                home.join(".mozilla/native-messaging-hosts")
            );
        }
        #[cfg(windows)]
        {
            let base = home.join(kokos_nmh::transport::HOST_NAME).join("NativeMessagingHosts");
            assert_eq!(dir_for(Browser::Chrome, home).unwrap(), base.join("Chrome"));
            assert_eq!(dir_for(Browser::Firefox, home).unwrap(), base.join("Firefox"));
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        assert!(
            dir_for(Browser::Chrome, home).is_none(),
            "a platform with no table entry must register nothing"
        );
    }


    #[test]
    fn chrome_id_with_a_trailing_path_segment_is_stripped_not_embedded() {
        let s = json_for(Browser::Chrome, "/x", "abcdefghijklmnop/popup.html");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(
            v["allowed_origins"][0],
            "chrome-extension://abcdefghijklmnop/"
        );
    }

    #[test]
    fn chrome_id_containing_a_slash_itself_is_cut_at_the_first_separator() {
        let s = json_for(Browser::Chrome, "/x", "ab/cd");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["allowed_origins"][0], "chrome-extension://ab/");
    }

    #[test]
    fn chrome_id_containing_a_nul_byte_is_cut_at_the_nul() {
        let s = json_for(Browser::Chrome, "/x", "abc\0evil");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["allowed_origins"][0], "chrome-extension://abc/");
    }

    #[test]
    fn an_empty_chrome_id_is_neutralised_not_left_as_an_empty_segment() {
        for input in ["", "chrome-extension://", "chrome-extension:///"] {
            let s = json_for(Browser::Chrome, "/x", input);
            let v: serde_json::Value = serde_json::from_str(&s).unwrap();
            let origin = v["allowed_origins"][0].as_str().unwrap();
            assert_ne!(
                origin, "chrome-extension:///",
                "input {input}: must not embed an empty id segment"
            );
            assert!(
                origin.len() > "chrome-extension://".len() + 1,
                "input {input}: id part must be non-empty, got {origin}"
            );
        }
    }

    #[test]
    fn a_dots_only_chrome_id_is_neutralised_not_kept_as_a_traversal_fragment() {
        for input in ["..", "...", "chrome-extension://../"] {
            let s = json_for(Browser::Chrome, "/x", input);
            let v: serde_json::Value = serde_json::from_str(&s).unwrap();
            let origin = v["allowed_origins"][0].as_str().unwrap();
            assert!(
                !origin.contains(".."),
                "input {input} produced a traversal fragment: {origin}"
            );
        }
    }

    #[test]
    fn firefox_id_needs_no_url_normalisation_and_is_kept_verbatim() {
        let s = json_for(Browser::Firefox, "/x", "Kokos@Example.ORG");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["allowed_extensions"][0], "Kokos@Example.ORG");
    }


    #[test]
    fn install_writes_a_firefox_manifest_whose_fields_all_read_back_correctly() {
        let home = tempfile::tempdir().unwrap();
        let Some(_dir) = dir_for(Browser::Firefox, home.path()) else {
            return;
        };
        let p = install(
            Browser::Firefox,
            home.path(),
            "/opt/kokos-nmh",
            "kokos@example.org",
        )
        .unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v["name"], "dev.kuksov.kokos");
        assert_eq!(v["type"], "stdio");
        assert_eq!(v["path"], "/opt/kokos-nmh");
        assert_eq!(v["allowed_extensions"][0], "kokos@example.org");
        assert!(v.get("allowed_origins").is_none());
    }


    #[test]
    fn installing_chrome_does_not_report_firefox_as_installed() {
        let home = tempfile::tempdir().unwrap();
        let (Some(_c), Some(_f)) = (
            dir_for(Browser::Chrome, home.path()),
            dir_for(Browser::Firefox, home.path()),
        ) else {
            return;
        };
        install(
            Browser::Chrome,
            home.path(),
            "/x/kokos-nmh",
            "abcdefghijklmnop",
        )
        .unwrap();
        assert!(is_installed(Browser::Chrome, home.path()));
        assert!(
            !is_installed(Browser::Firefox, home.path()),
            "a shared manifest filename in two different browser directories must not cross-report"
        );
    }

    #[test]
    fn removing_when_never_installed_is_a_noop() {
        let home = tempfile::tempdir().unwrap();
        let Some(_dir) = dir_for(Browser::Chrome, home.path()) else {
            return;
        };
        assert!(!is_installed(Browser::Chrome, home.path()));
        remove(Browser::Chrome, home.path()).unwrap();
        assert!(!is_installed(Browser::Chrome, home.path()));
    }

    #[test]
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    fn install_and_remove_return_unsupported_when_the_platform_has_no_directory_entry() {
        let home = tempfile::tempdir().unwrap();
        let err = install(Browser::Chrome, home.path(), "/x", "abc").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        let err2 = remove(Browser::Chrome, home.path()).unwrap_err();
        assert_eq!(err2.kind(), std::io::ErrorKind::Unsupported);
    }


    #[test]
    fn dev_path_sits_next_to_the_running_binary() {
        let exe = std::path::Path::new("/repo/target/debug/Kokos");
        assert_eq!(
            sibling_host(exe).unwrap(),
            std::path::Path::new("/repo/target/debug").join(HOST_BINARY_NAME)
        );
    }

    #[test]
    fn bundled_path_stays_inside_the_app_bundle() {
        let exe = std::path::Path::new("/Applications/Kokos.app/Contents/MacOS/Kokos");
        assert_eq!(
            sibling_host(exe).unwrap(),
            std::path::Path::new("/Applications/Kokos.app/Contents/MacOS").join(HOST_BINARY_NAME),
            "a sidecar lands next to the main binary, so one rule covers dev and bundled"
        );
    }

    #[test]
    fn a_bare_relative_exe_yields_a_non_absolute_sibling() {
        let exe = std::path::Path::new("kokos");
        assert!(!sibling_host(exe).unwrap().is_absolute());
    }
}

//! Per-vault master-password storage in the OS keyring (macOS Keychain /
//! Windows Credential Manager / Linux Secret Service). Opt-in fast-unlock:
//! the master password is stored deliberately and read back only in the
//! backend — it is never returned to the WebView. Keyed by the
//! canonical vault path so a moved vault simply misses (graceful fallback).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

#[cfg(target_os = "macos")]
use security_framework::item::{ItemClass, ItemSearchOptions};

pub(crate) const SERVICE: &str = "Kokos";

/// Canonical vault path used as the keyring account. Must match across
/// store/fetch/delete/has or entries never line up. Falls back to the raw
/// string when the path cannot be canonicalised (e.g. file already moved).
fn account(path: &str) -> String {
    crate::paths::normalise(Path::new(path))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
}

/// Process-local cache of one `keyring::Entry` handle per account.
///
/// The real backends (macOS Keychain, Windows Credential Manager, Linux
/// Secret Service) always query the OS store live on every call and never
/// cache the secret itself, so reusing a handle changes nothing for
/// production behaviour or the secret boundary — the cached
/// value here is only the (service, account) descriptor, never the
/// password. keyring's mock backend, however, has
/// `CredentialPersistence::EntryOnly`: its in-memory data lives on the
/// single `Entry` object that created it, with no persistence tied to the
/// (service, user) pair across independent `Entry::new` calls (this is by
/// design — the mock exists so a test can inject errors on a held entry,
/// not to model a real store). Without this cache, `store(path, ..)`
/// followed by `fetch(path)` in a test would always see `None`, because
/// each call would build its own throwaway mock credential.
fn entries() -> &'static Mutex<HashMap<String, Arc<keyring::Entry>>> {
    static ENTRIES: OnceLock<Mutex<HashMap<String, Arc<keyring::Entry>>>> = OnceLock::new();
    ENTRIES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Run `f` against the cached entry for `path`, creating it on first use.
fn with_entry<T>(
    path: &str,
    f: impl FnOnce(&keyring::Entry) -> keyring::Result<T>,
) -> keyring::Result<T> {
    let acct = account(path);
    let entry = {
        let mut cache = entries().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(e) = cache.get(&acct) {
            Arc::clone(e)
        } else {
            let e = Arc::new(keyring::Entry::new(SERVICE, &acct)?);
            cache.insert(acct, Arc::clone(&e));
            e
        }
    };
    f(&entry)
}

pub fn store(path: &str, master_pw: &str) -> keyring::Result<()> {
    with_entry(path, |entry| entry.set_password(master_pw))
}

pub fn fetch(path: &str) -> keyring::Result<Option<String>> {
    with_entry(path, |entry| match entry.get_password() {
        Ok(pw) => Ok(Some(pw)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e),
    })
}

pub fn delete(path: &str) -> keyring::Result<()> {
    let result = with_entry(path, |entry| match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e),
    });
    if result.is_ok() {
        let acct = account(path);
        let mut cache = entries().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.remove(&acct);
    }
    result
}

/// Existence check for the fast-unlock master-password entry — MUST NOT read
/// the secret. The Settings screen and every lock screen call this on mount
/// just to decide whether to render a "saved password" button, so it runs
/// unattended and often. Reading the item's DATA (`get_password`) makes macOS
/// present an "authenticate to continue" Keychain dialog whenever the item is
/// foreign to the running code signature (e.g. after re-signing the app), and
/// costs a live secret access for nothing. A metadata-only
/// `SecItemCopyMatching` that requests neither `kSecReturnData` nor a ref only
/// confirms presence via the returned metadata without decrypting the payload,
/// so it never prompts — mirrors `biometric_macos::has_biometric`. As there,
/// `.load_attributes(true)` (`kSecReturnAttributes`, unprotected metadata) is
/// REQUIRED: a search with no `kSecReturn*` key makes macOS fall back toward
/// data access, which for a foreign/re-signed item raises the very keychain
/// authorization prompt this avoids.
#[cfg(target_os = "macos")]
pub fn has(path: &str) -> bool {
    ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .service(SERVICE)
        .account(&account(path))
        .load_attributes(true)
        .limit(1i64)
        .search()
        .is_ok()
}

/// Non-macOS: the Windows Credential Manager / Linux Secret Service backends
/// don't have the foreign-item prompt problem, and the `keyring` crate exposes
/// no metadata-only probe, so keep the `fetch`-based existence check there.
#[cfg(not(target_os = "macos"))]
pub fn has(path: &str) -> bool {
    fetch(path).map(|o| o.is_some()).unwrap_or(false)
}

/// Gdrive refresh-token account, prefixed so it never collides with the
/// master-pw entry keyed by the bare path above.
fn gdrive_account(path: &str) -> String {
    format!("gdrive:{}", account(path))
}

pub fn gdrive_store(path: &str, refresh_token: &str) -> keyring::Result<()> {
    with_entry(&gdrive_account(path), |e| e.set_password(refresh_token))
}

pub fn gdrive_fetch(path: &str) -> keyring::Result<Option<String>> {
    with_entry(&gdrive_account(path), |e| match e.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e),
    })
}

pub fn gdrive_delete(path: &str) -> keyring::Result<()> {
    with_entry(&gdrive_account(path), |e| match e.delete_credential() {
        Err(keyring::Error::NoEntry) => Ok(()),
        r => r,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock() {
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
    }

    #[test]
    fn store_fetch_delete_roundtrip() {
        mock();
        let p = "/tmp/kokos-kr-roundtrip.vault";
        store(p, "pw1").unwrap();
        assert_eq!(fetch(p).unwrap().as_deref(), Some("pw1"));
        #[cfg(not(target_os = "macos"))]
        assert!(has(p));
        delete(p).unwrap();
        assert_eq!(fetch(p).unwrap(), None);
        #[cfg(not(target_os = "macos"))]
        assert!(!has(p));
    }

    #[test]
    fn fetch_absent_is_none_not_err() {
        mock();
        assert_eq!(fetch("/tmp/kokos-kr-absent.vault").unwrap(), None);
        assert!(!has("/tmp/kokos-kr-absent.vault"));
    }

    #[test]
    fn delete_absent_is_ok() {
        mock();
        delete("/tmp/kokos-kr-neverstored.vault").unwrap();
    }

    #[test]
    fn store_overwrites_existing() {
        mock();
        let p = "/tmp/kokos-kr-overwrite.vault";
        store(p, "old").unwrap();
        store(p, "new").unwrap();
        assert_eq!(fetch(p).unwrap().as_deref(), Some("new"));
    }

    #[test]
    fn gdrive_store_fetch_delete_roundtrip_and_no_master_pw_collision() {
        mock();
        let p = "/tmp/kokos-kr-gdrive.vault";
        store(p, "MASTERPW").unwrap();
        gdrive_store(p, "REFRESH").unwrap();
        assert_eq!(gdrive_fetch(p).unwrap().as_deref(), Some("REFRESH"));
        assert_eq!(fetch(p).unwrap().as_deref(), Some("MASTERPW"));
        gdrive_delete(p).unwrap();
        assert_eq!(gdrive_fetch(p).unwrap(), None);
        assert_eq!(fetch(p).unwrap().as_deref(), Some("MASTERPW"));
        delete(p).unwrap();
    }
}

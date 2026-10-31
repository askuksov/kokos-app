//! macOS: Touch ID gate on a stored master password.
//!
//! Storage: a Keychain generic-password item
//! carrying a `SecAccessControl` with a biometry flag
//! (`kSecAttrAccessControl`). Reading the item's *data*
//! (`SecItemCopyMatching` with `kSecReturnData`) makes the OS itself present
//! the Touch ID sheet — the gate is OS-enforced, not just an app-level check,
//! so even Kokos cannot read the password without a successful fingerprint
//! match. This is a SEPARATE Keychain item from the plain fast-unlock
//! (`keyring_store.rs`, service "Kokos"): this module uses its own service
//! name, so "Password" mode and "Touch ID" mode (this module) are distinct
//! stores that the unified control switches between.
//!
//! `is_biometric_available()` has no Security.framework equivalent (the
//! existence of a Keychain item says nothing about the hardware), so it
//! alone reaches into LocalAuthentication (`LAContext.canEvaluatePolicy`) —
//! a non-prompting capability probe, unrelated to the storage mechanism
//! above. This is needed regardless of the storage-path choice.
//!
//! Non-macOS targets get a no-op/Err twin for every public fn so lib.rs
//! call-sites stay cfg-free, mirroring `sleep_macos.rs`.

#[cfg(target_os = "macos")]
use security_framework::access_control::{ProtectionMode, SecAccessControl};
#[cfg(target_os = "macos")]
use security_framework::item::{ItemClass, ItemSearchOptions};
#[cfg(target_os = "macos")]
use security_framework::passwords::{
    delete_generic_password_options, generic_password, set_generic_password_options,
    AccessControlOptions, PasswordOptions,
};
#[cfg(target_os = "macos")]
use zeroize::Zeroizing;

/// Distinct from the plain-keyring service ("Kokos" in keyring_store.rs) so
/// the two modes never collide in the Keychain — see module docs.
#[cfg(target_os = "macos")]
const SERVICE: &str = "Kokos-Biometric";

/// Plain companion item (NO access control) that merely RECORDS that Touch ID
/// is enabled for a vault. `has_biometric` reads THIS instead of the biometry-
/// gated `SERVICE` item, so an existence check never triggers a Touch ID sheet.
/// Written/removed in lock-step with `SERVICE` by store/delete below.
#[cfg(target_os = "macos")]
const PRESENCE_SERVICE: &str = "Kokos-Biometric-Present";

/// Canonicalise the vault path into the keychain account string. This
/// mirrors `keyring_store::account()` byte-for-byte but is intentionally
/// duplicated rather than shared: this is deliberately a SEPARATE module
/// from keyring_store.rs (not routed through its cache), and the two
/// stores only need to be internally consistent with themselves, not with
/// each other — they are different SecItems by design.
#[cfg(target_os = "macos")]
fn account(path: &str) -> String {
    crate::paths::normalise(std::path::Path::new(path))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
}

/// Hardware + enrollment probe. Does NOT prompt. LocalAuthentication is the
/// only framework that exposes this (Security.framework's Keychain API has
/// no "would this succeed" query). `DeviceOwnerAuthenticationWithBiometrics`
/// is biometry-only, no passcode fallback — matching the literal "Touch ID"
/// promise the UI makes (same posture as the BIOMETRY_CURRENT_SET flag used
/// below, not the broader UserPresence/DeviceOwnerAuthentication policy,
/// which would silently accept the Mac's login password too).
/// Apple docs: https://developer.apple.com/documentation/localauthentication/lacontext/canevaluatepolicy(_:error:)
#[cfg(target_os = "macos")]
pub fn is_biometric_available() -> bool {
    use objc2_local_authentication::{LAContext, LAPolicy};
    unsafe {
        let ctx = LAContext::new();
        ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
            .is_ok()
    }
}

/// Existence check for the biometric entry — MUST NOT prompt. The Lock/Welcome
/// screens and the Settings control call it on every mount just to decide
/// whether to show a button, so ANY Touch ID sheet here is a bug.
///
/// Probing the real biometry item cannot be made silent on macOS. A bare
/// `SecItemCopyMatching` defaults toward data access and prompts; even an
/// attributes-only query (`kSecReturnAttributes`) on an item whose
/// `SecAccessControl` carries `BIOMETRY_CURRENT_SET` STILL raises the sheet
/// (verified on a signed build). The crate's only other lever,
/// `skip_authenticated_items` → `kSecUseAuthenticationUISkip`, avoids the
/// prompt only by EXCLUDING the item, so existence would always read false.
///
/// So enablement is tracked out-of-band: `store_biometric` writes a plain,
/// NON-access-controlled companion item under `PRESENCE_SERVICE`, and this
/// check searches THAT. A keychain item with no ACL never presents a prompt.
/// The real biometry item is touched only by `unlock_biometric` (a genuine
/// data read → the sheet, which is precisely when the user asked for it).
/// Not unit-testable (needs a signed build + Touch ID hardware) — GUI-verified.
#[cfg(target_os = "macos")]
pub fn has_biometric(path: &str) -> bool {
    ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .service(PRESENCE_SERVICE)
        .account(&account(path))
        .load_attributes(true)
        .limit(1i64)
        .search()
        .is_ok()
}

/// Store `pw` behind a Touch ID gate, creating or replacing the entry.
///
/// Access control: `BIOMETRY_CURRENT_SET` (requires Touch ID with the
/// CURRENTLY enrolled finger set — re-enrolling invalidates the item, a
/// deliberate choice: a changed fingerprint set should not silently keep
/// unlocking this vault) combined with the
/// `AccessibleWhenPasscodeSetThisDeviceOnly` protection class (device-bound:
/// excluded from iCloud Keychain sync/backup, and destroyed if the device's
/// login password is ever removed — which is also Apple's documented
/// recommended pairing for biometry-gated items).
/// https://developer.apple.com/documentation/security/secaccesscontrolcreateflags
///
/// Implementation note: this deliberately does NOT rely on
/// `set_generic_password_options`'s built-in "update on duplicate" fallback
/// (it calls `SecItemUpdate` with the OLD item's `kSecAttrAccessControl` as
/// part of the match predicate, which a freshly-constructed
/// `SecAccessControl` is not guaranteed to satisfy — Apple's own guidance
/// for replacing an access-control-gated item is delete-then-add, not
/// update). Delete first (idempotent — a first-time enable simply no-ops) so
/// every store is a plain `SecItemAdd`.
#[cfg(target_os = "macos")]
pub fn store_biometric(path: &str, pw: &str) -> Result<(), String> {
    let acct = account(path);
    let _ = delete_generic_password_options(PasswordOptions::new_generic_password(SERVICE, &acct));

    let access_control = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        AccessControlOptions::BIOMETRY_CURRENT_SET.bits(),
    )
    .map_err(|_| "biometric storage unavailable".to_string())?;

    let mut options = PasswordOptions::new_generic_password(SERVICE, &acct);
    options.set_access_control(access_control);
    set_generic_password_options(pw.as_bytes(), options).map_err(|e| store_error_message(e.code()))?;

    if let Err(e) = store_presence_marker(&acct) {
        let _ = delete_generic_password_options(PasswordOptions::new_generic_password(SERVICE, &acct));
        return Err(e);
    }
    Ok(())
}

/// Write (replacing any prior copy) the plain presence marker read by
/// `has_biometric`. No access control → searching/reading it never prompts. Its
/// data is a fixed non-secret sentinel, NEVER the master password.
#[cfg(target_os = "macos")]
fn store_presence_marker(acct: &str) -> Result<(), String> {
    let _ = delete_generic_password_options(PasswordOptions::new_generic_password(PRESENCE_SERVICE, acct));
    set_generic_password_options(b"1", PasswordOptions::new_generic_password(PRESENCE_SERVICE, acct))
        .map_err(|_| "biometric_store_failed".to_string())
}

/// Map a `SecItemAdd` OSStatus to a stable snake_case error TOKEN surfaced to
/// the UI, which the front end translates via `errorMessage()`. `-34018`
/// (`errSecMissingEntitlement`) means the biometry item can't be stored
/// because the running build is NOT signed with a `keychain-access-groups`
/// entitlement (e.g. an unsigned `tauri dev` build); any other failure
/// collapses to a single generic token. Storing is not a decryption oracle,
/// so distinguishing this one case leaks nothing.
#[cfg(target_os = "macos")]
fn store_error_message(code: i32) -> String {
    const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;
    if code == ERR_SEC_MISSING_ENTITLEMENT {
        "biometric_unsupported_build".to_string()
    } else {
        "biometric_store_failed".to_string()
    }
}

/// Read the stored master password back. This call is what makes the OS
/// present the Touch ID sheet (see module docs) — it blocks the calling
/// thread for as long as the user takes to respond, so callers must run it
/// off the async runtime (`spawn_blocking`). The returned password stays in
/// the backend — the IPC layer turns it into a `VaultInfo`, never echoing it
/// to the WebView.
///
/// Oracle-safety: every failure (no entry, wrong finger, user-cancelled,
/// biometry locked out, ...) collapses to ONE generic message — the error
/// never distinguishes "no entry" from "wrong finger".
#[cfg(target_os = "macos")]
pub fn unlock_biometric(path: &str) -> Result<String, String> {
    let options = PasswordOptions::new_generic_password(SERVICE, &account(path));
    let bytes = generic_password(options).map_err(|_| "biometric unlock failed".to_string())?;
    String::from_utf8(bytes).map_err(|e| {
        let _ = Zeroizing::new(e.into_bytes());
        "biometric unlock failed".to_string()
    })
}

/// Remove the biometric entry (the "Off" / switch-to-Password path).
/// Idempotent: deleting an entry that was never stored is not an error,
/// mirroring `keyring_store::delete`.
#[cfg(target_os = "macos")]
pub fn delete_biometric(path: &str) -> Result<(), String> {
    let acct = account(path);
    delete_one(SERVICE, &acct)?;
    delete_one(PRESENCE_SERVICE, &acct)
}

#[cfg(target_os = "macos")]
fn delete_one(service: &str, acct: &str) -> Result<(), String> {
    match delete_generic_password_options(PasswordOptions::new_generic_password(service, acct)) {
        Ok(()) => Ok(()),
        Err(e) if e.code() == security_framework_sys::base::errSecItemNotFound => Ok(()),
        Err(_) => Err("failed to delete biometric entry".to_string()),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn is_biometric_available() -> bool {
    false
}

#[cfg(not(target_os = "macos"))]
pub fn has_biometric(_path: &str) -> bool {
    false
}

#[cfg(not(target_os = "macos"))]
pub fn store_biometric(_path: &str, _pw: &str) -> Result<(), String> {
    Err("biometric unavailable on this platform".to_string())
}

#[cfg(not(target_os = "macos"))]
pub fn unlock_biometric(_path: &str) -> Result<String, String> {
    Err("biometric unavailable on this platform".to_string())
}

#[cfg(not(target_os = "macos"))]
pub fn delete_biometric(_path: &str) -> Result<(), String> {
    Err("biometric unavailable on this platform".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The only thing verifiable in an environment that cannot drive an OS
    /// Touch ID prompt: the availability probe is a safe, non-interactive
    /// call that returns a bool without panicking. No assertion on the value
    /// itself — it is hardware/enrollment/signing-context dependent (an
    /// unsigned `cargo test` binary has no expected true/false answer here).
    #[test]
    fn is_biometric_available_does_not_panic() {
        let _ = is_biometric_available();
    }

    /// -34018 (unsigned build, no keychain-access-groups) maps to a
    /// distinct token the UI turns into a clear "unavailable in this build"
    /// message; every other failure collapses to a single generic
    /// snake_case token the front end translates.
    #[cfg(target_os = "macos")]
    #[test]
    fn store_error_message_distinguishes_missing_entitlement() {
        assert_eq!(store_error_message(-34018), "biometric_unsupported_build");
        assert_eq!(store_error_message(-25300), "biometric_store_failed");
        assert_eq!(store_error_message(-25291), "biometric_store_failed");
    }
}

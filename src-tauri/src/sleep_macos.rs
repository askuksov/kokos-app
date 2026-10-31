//! macOS: lock the vault when the system is about to sleep (best-effort).
//! Non-macOS targets get a no-op `install` so lib.rs stays cfg-free.

#[cfg(target_os = "macos")]
pub fn install(handle: tauri::AppHandle) {
    use crate::state::AppState;
    use tauri::{Emitter, Manager};
    use block2::RcBlock;
    use objc2_app_kit::{NSWorkspace, NSWorkspaceWillSleepNotification};
    use objc2_foundation::NSNotification;
    use std::ptr::NonNull;

    let block = RcBlock::new(move |_note: NonNull<NSNotification>| {
        let st = handle.state::<AppState>();
        let want = st.settings.lock().map(|s| s.lock_on_sleep).unwrap_or(false);
        if want {
            // Lock every open vault, not just the active tab: same as the
            // idle auto-lock in lib.rs. The "lock" audit row is not a content
            // change, so `save_opened` keeps the sync revision as is; a bump
            // here could make a stale local copy win over a newer remote one.
            if let Ok(mut reg) = st.sessions.lock() {
                for s in reg.iter_mut() {
                    if let Some(v) = s.vault.as_mut() {
                        let _ = kokos_core::audit::append(&v.conn, "lock", None);
                        let _ = kokos_core::vault::save_opened(v);
                    }
                }
                reg.lock_all();
                drop(reg);
                let _ = handle.emit("vault-locked", serde_json::json!({ "vault_id": null }));
                crate::nmh::invalidate_confirms(&handle);
            }
        }
    });
    unsafe {
        let ws = NSWorkspace::sharedWorkspace();
        let nc = ws.notificationCenter();
        nc.addObserverForName_object_queue_usingBlock(
            Some(NSWorkspaceWillSleepNotification),
            None,
            None,
            &block,
        );
    }
    std::mem::forget(block);
}

#[cfg(not(target_os = "macos"))]
pub fn install(_handle: tauri::AppHandle) {}

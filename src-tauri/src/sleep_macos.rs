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
            if let Ok(mut reg) = st.sessions.lock() {
                if let Some(s) = reg.active_mut() {
                    if let Some(v) = s.vault.as_mut() {
                        let _ = kokos_core::audit::append(&v.conn, "lock", None);
                        let _ = kokos_core::vault::save(v);
                    }
                    s.lock();
                }
                let _ = handle.emit("vault-locked", ());
                drop(reg);
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

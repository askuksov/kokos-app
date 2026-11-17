//! Tray / menu-bar icon and the close-to-tray window lifecycle.
//!
//! Closing the main window hides it instead of quitting when
//! `settings.close_to_tray` is on and a tray icon is actually visible. The
//! process (and the native-messaging host with it) keeps running; the vaults
//! are locked on hide when `settings.lock_on_close` is on. Quit from the tray
//! menu or Cmd+Q ends the process for real.
//!
//! The tray menu lists the open vault tabs with their lock state. It is
//! rebuilt from the auto-lock watcher tick (lib.rs) whenever a cheap
//! signature of that state changes, so no lock/unlock call site has to know
//! about the tray.
use std::sync::Mutex;

use tauri::menu::{Menu, MenuBuilder, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager};

use crate::state::AppState;

const TRAY_ID: &str = "kokos";
const MAIN_WINDOW: &str = "main";

/// Asks the WebView to show the one-time "Kokos keeps running" dialog.
pub const EV_CLOSE_INTRO: &str = "tray-close-intro";
/// Asks the active vault screen to open Settings.
pub const EV_OPEN_SETTINGS: &str = "tray-open-settings";
/// Asks the tab bar to activate the tab of this vault path.
pub const EV_FOCUS_VAULT: &str = "tray-focus-vault";

const ID_OPEN: &str = "tray-open";
const ID_LOCK_ALL: &str = "tray-lock-all";
const ID_SETTINGS: &str = "tray-settings";
const ID_QUIT: &str = "tray-quit";
const ID_VAULT_LOCK: &str = "tray-vault-lock:";
const ID_VAULT_UNLOCK: &str = "tray-vault-unlock:";

/// Signature of the last menu built; `None` while no tray icon exists.
static MENU_SIG: Mutex<Option<String>> = Mutex::new(None);

/// One vault row in the tray menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRow {
    pub path: String,
    pub unlocked: bool,
}

/// Menu labels for one UI language. The native menus are not driven by the
/// WebView's i18n tables, so the few tray strings live here.
struct Labels {
    open: &'static str,
    no_vaults: &'static str,
    lock: &'static str,
    unlock: &'static str,
    lock_all: &'static str,
    settings: &'static str,
    quit: &'static str,
}

fn labels(lang: &str) -> Labels {
    match lang {
        "ru" => Labels {
            open: "Открыть Kokos",
            no_vaults: "Нет открытых хранилищ",
            lock: "Заблокировать",
            unlock: "Разблокировать…",
            lock_all: "Заблокировать все",
            settings: "Настройки…",
            quit: "Выйти из Kokos",
        },
        "uk" => Labels {
            open: "Відкрити Kokos",
            no_vaults: "Немає відкритих сховищ",
            lock: "Заблокувати",
            unlock: "Розблокувати…",
            lock_all: "Заблокувати всі",
            settings: "Налаштування…",
            quit: "Вийти з Kokos",
        },
        _ => Labels {
            open: "Open Kokos",
            no_vaults: "No open vaults",
            lock: "Lock",
            unlock: "Unlock…",
            lock_all: "Lock All",
            settings: "Settings…",
            quit: "Quit Kokos",
        },
    }
}

/// File name without the vault extension, like the WebView's `vaultDisplayName`.
pub fn display_name(path: &str) -> String {
    let base = path
        .rsplit(['/', '\\'])
        .find(|s| !s.is_empty())
        .unwrap_or(path);
    for ext in [".kokos", ".vault"] {
        if let Some(stem) = base.strip_suffix(ext) {
            if !stem.is_empty() {
                return stem.to_string();
            }
        }
    }
    base.to_string()
}

/// Registry sessions in tab order, then the restored-at-launch paths that
/// have not been unlocked yet (they never enter the registry until then).
/// `None` while another thread holds the registry (a lock-all saving every
/// vault, say): this runs on the main thread and must not wait for that.
fn vault_rows(app: &AppHandle) -> Option<Vec<VaultRow>> {
    let st = app.state::<AppState>();
    let mut rows: Vec<VaultRow> = {
        let reg = st.sessions.try_lock().ok()?;
        reg.open_paths()
            .into_iter()
            .map(|id| {
                let unlocked = reg.get(&id).map(|s| s.is_open_or_borrowed()).unwrap_or(false);
                VaultRow { path: id, unlocked }
            })
            .collect()
    };
    let restored = st.restored_locked.try_lock().ok()?;
    for p in restored.iter() {
        if !rows.iter().any(|r| &r.path == p) {
            rows.push(VaultRow { path: p.clone(), unlocked: false });
        }
    }
    Some(rows)
}

/// Everything the menu shows; a change means the menu needs a rebuild.
pub fn menu_signature(lang: &str, rows: &[VaultRow]) -> String {
    let mut sig = String::from(lang);
    for r in rows {
        sig.push('\n');
        sig.push(if r.unlocked { '1' } else { '0' });
        sig.push_str(&r.path);
    }
    sig
}

/// A vault row with its lock state. macOS draws the system padlock template
/// images, which follow the menu's light/dark appearance; the 🔒/🔓 emoji are
/// hard to tell apart at menu size there. Windows and Linux have no such
/// native icons, so they keep the emoji.
#[cfg(target_os = "macos")]
fn vault_submenu(app: &AppHandle, i: usize, name: &str, unlocked: bool) -> tauri::Result<Submenu<tauri::Wry>> {
    use tauri::menu::NativeIcon;
    let icon = if unlocked { NativeIcon::LockUnlocked } else { NativeIcon::LockLocked };
    Submenu::with_id_and_native_icon(app, format!("tray-vault-{i}"), name, true, Some(icon))
}

#[cfg(not(target_os = "macos"))]
fn vault_submenu(app: &AppHandle, i: usize, name: &str, unlocked: bool) -> tauri::Result<Submenu<tauri::Wry>> {
    let mark = if unlocked { "🔓" } else { "🔒" };
    Submenu::with_id(app, format!("tray-vault-{i}"), format!("{mark} {name}"), true)
}

fn build_menu(app: &AppHandle, lang: &str, rows: &[VaultRow]) -> tauri::Result<Menu<tauri::Wry>> {
    let l = labels(lang);
    let mut b = MenuBuilder::new(app)
        .item(&MenuItem::with_id(app, ID_OPEN, l.open, true, None::<&str>)?)
        .item(&PredefinedMenuItem::separator(app)?);
    if rows.is_empty() {
        b = b.item(&MenuItem::with_id(app, "tray-no-vaults", l.no_vaults, false, None::<&str>)?);
    }
    for (i, r) in rows.iter().enumerate() {
        let item = if r.unlocked {
            MenuItem::with_id(app, format!("{ID_VAULT_LOCK}{}", r.path), l.lock, true, None::<&str>)?
        } else {
            MenuItem::with_id(app, format!("{ID_VAULT_UNLOCK}{}", r.path), l.unlock, true, None::<&str>)?
        };
        let sub = vault_submenu(app, i, &display_name(&r.path), r.unlocked)?;
        sub.append(&item)?;
        b = b.item(&sub);
    }
    let any_unlocked = rows.iter().any(|r| r.unlocked);
    b.item(&PredefinedMenuItem::separator(app)?)
        .item(&MenuItem::with_id(app, ID_LOCK_ALL, l.lock_all, any_unlocked, None::<&str>)?)
        .item(&PredefinedMenuItem::separator(app)?)
        // Settings live inside an unlocked vault, so without one there is
        // nothing to open.
        .item(&MenuItem::with_id(app, ID_SETTINGS, l.settings, any_unlocked, None::<&str>)?)
        .item(&MenuItem::with_id(app, ID_QUIT, l.quit, true, cfg!(target_os = "macos").then_some("CmdOrCtrl+Q"))?)
        .build()
}

fn on_menu_event(app: &AppHandle, id: &str) {
    match id {
        ID_OPEN => show_main(app),
        ID_LOCK_ALL => lock_all_in_background(app),
        ID_SETTINGS => {
            show_main(app);
            let _ = app.emit(EV_OPEN_SETTINGS, ());
        }
        ID_QUIT => app.exit(0),
        _ => {
            if let Some(vault_id) = id.strip_prefix(ID_VAULT_LOCK) {
                let app = app.clone();
                let vault_id = vault_id.to_string();
                tauri::async_runtime::spawn(async move {
                    let st = app.state::<AppState>();
                    if let Err(e) = crate::commands::lock_vault(app.clone(), st, Some(vault_id)).await {
                        eprintln!("[tray] lock failed: {e}");
                    }
                });
            } else if let Some(path) = id.strip_prefix(ID_VAULT_UNLOCK) {
                show_main(app);
                let _ = app.emit(EV_FOCUS_VAULT, path.to_string());
            }
        }
    }
}

/// Whether a tray icon would actually be visible on this desktop.
///
/// Linux shows tray icons through the StatusNotifierItem protocol; without a
/// watcher on the session bus (stock GNOME without the AppIndicator
/// extension, or a Flatpak not granted that bus name) the icon silently never
/// appears, and hiding the window would leave the user with no way back.
/// Closing then quits, as before. The appindicator library is checked too:
/// `tray-icon` panics when it cannot load it.
#[cfg(target_os = "linux")]
pub fn available() -> bool {
    appindicator_loadable() && status_notifier_watcher_present()
}

#[cfg(target_os = "linux")]
fn appindicator_loadable() -> bool {
    // The names libappindicator-sys tries, in its order (the unsuffixed ones
    // are its AppImage fallback).
    const NAMES: [&std::ffi::CStr; 4] = [
        c"libayatana-appindicator3.so.1",
        c"libappindicator3.so.1",
        c"libayatana-appindicator3.so",
        c"libappindicator3.so",
    ];
    NAMES.iter().any(|name| {
        // SAFETY: plain dlopen/dlclose probe of a NUL-terminated name; no
        // symbol from the handle is used.
        unsafe {
            let h = libc::dlopen(name.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
            if h.is_null() {
                false
            } else {
                libc::dlclose(h);
                true
            }
        }
    })
}

#[cfg(target_os = "linux")]
fn status_notifier_watcher_present() -> bool {
    use std::time::Duration;
    let Ok(conn) = dbus::blocking::Connection::new_session() else {
        return false;
    };
    let proxy = conn.with_proxy("org.freedesktop.DBus", "/org/freedesktop/DBus", Duration::from_millis(500));
    let (has,): (bool,) = proxy
        .method_call("org.freedesktop.DBus", "NameHasOwner", ("org.kde.StatusNotifierWatcher",))
        .unwrap_or((false,));
    has
}

#[cfg(not(target_os = "linux"))]
pub fn available() -> bool {
    true
}

fn tray_icon_image() -> tauri::Result<tauri::image::Image<'static>> {
    #[cfg(target_os = "macos")]
    let bytes: &[u8] = include_bytes!("../icons/tray-template.png");
    #[cfg(not(target_os = "macos"))]
    let bytes: &[u8] = include_bytes!("../icons/32x32.png");
    tauri::image::Image::from_bytes(bytes)
}

/// Whether a tray icon exists right now.
pub fn is_active(app: &AppHandle) -> bool {
    app.tray_by_id(TRAY_ID).is_some()
}

/// Create, update or remove the tray icon to match the settings and the
/// current vault list. Cheap when nothing changed; called from setup, after
/// a settings write and from the auto-lock watcher tick.
///
/// The work is queued onto the main thread. Tray calls made from another
/// thread block until the main thread runs them, and sync commands such as
/// `set_settings` run on the main thread, so doing it in place could deadlock
/// on `MENU_SIG`; on one thread every sync runs to completion in turn.
pub fn sync(app: &AppHandle) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || sync_on_main(&handle));
}

fn sync_on_main(app: &AppHandle) {
    let (want, lang) = {
        let st = app.state::<AppState>();
        let s = st.settings.lock();
        match s {
            Ok(s) => (s.close_to_tray, s.lang.clone()),
            Err(_) => return,
        }
    };
    let Ok(mut last) = MENU_SIG.lock() else { return };
    if !want {
        if last.take().is_some() {
            let _ = app.remove_tray_by_id(TRAY_ID);
        }
        return;
    }
    if last.is_none() && !available_cached() {
        return;
    }
    let Some(rows) = vault_rows(app) else { return };
    let sig = menu_signature(&lang, &rows);
    if last.as_deref() == Some(sig.as_str()) {
        return;
    }
    let menu = match build_menu(app, &lang, &rows) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[tray] menu build failed: {e}");
            return;
        }
    };
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        if tray.set_menu(Some(menu)).is_ok() {
            *last = Some(sig);
        }
        return;
    }
    let icon = match tray_icon_image() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("[tray] icon load failed: {e}");
            return;
        }
    };
    let built = TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .icon_as_template(cfg!(target_os = "macos"))
        .tooltip("Kokos")
        .menu(&menu)
        // macOS: the menu-bar convention is a menu on any click.
        // Windows: left click opens the window, right click the menu.
        .show_menu_on_left_click(cfg!(target_os = "macos"))
        .on_menu_event(|app, event| on_menu_event(app, event.id().as_ref()))
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                if !cfg!(target_os = "macos") {
                    show_main(tray.app_handle());
                }
            }
        })
        .build(app);
    match built {
        Ok(_) => *last = Some(sig),
        Err(e) => eprintln!("[tray] icon build failed: {e}"),
    }
}

/// Re-check at close time on Linux: the tray host can go away after the icon
/// was created (the AppIndicator extension disabled, the panel restarted),
/// and hiding then would leave no way back. One short D-Bus round trip, only
/// when the user closes the window.
#[cfg(target_os = "linux")]
fn available_now() -> bool {
    status_notifier_watcher_present()
}

#[cfg(not(target_os = "linux"))]
fn available_now() -> bool {
    true
}

/// The D-Bus probe is a round trip; the desktop does not change under a
/// running process often enough to repeat it every tick.
fn available_cached() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(available)
}

/// Bring the main window back: Dock icon on, window shown and focused.
pub fn show_main(app: &AppHandle) {
    #[cfg(target_os = "macos")]
    {
        let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
        let _ = app.show();
    }
    if let Some(w) = app.get_webview_window(MAIN_WINDOW) {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Menu and window events arrive on the main thread; saving every vault
/// there would stall the UI, so the lock runs on its own thread.
fn lock_all_in_background(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        if let Err(e) = crate::commands::lock_all_sessions(&app) {
            eprintln!("[tray] lock all failed: {e}");
        }
        sync(&app);
    });
}

/// Hide the main window to the tray: Dock icon off on macOS, every vault
/// locked when `lock_on_close` is on.
pub fn hide_main(app: &AppHandle) {
    let lock = app
        .state::<AppState>()
        .settings
        .lock()
        .map(|s| s.lock_on_close)
        .unwrap_or(true);
    if let Some(w) = app.get_webview_window(MAIN_WINDOW) {
        let _ = w.hide();
    }
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Accessory);
    if lock {
        lock_all_in_background(app);
    }
}

/// Window-close hook. Returns `true` when the close was turned into a hide
/// (or into the one-time intro dialog) and must be prevented.
pub fn on_close_requested(window: &tauri::Window) -> bool {
    if window.label() != MAIN_WINDOW {
        return false;
    }
    let app = window.app_handle();
    let (want, intro_seen) = app
        .state::<AppState>()
        .settings
        .lock()
        .map(|s| (s.close_to_tray, s.tray_intro_seen))
        .unwrap_or((false, true));
    if !want || !is_active(app) || !available_now() {
        return false;
    }
    if intro_seen {
        hide_main(app);
    } else {
        let _ = app.emit(EV_CLOSE_INTRO, ());
    }
    true
}

/// The intro dialog's "Hide to tray": remember the answer, then hide.
#[tauri::command]
pub fn tray_hide_window(app: AppHandle, state: tauri::State<'_, AppState>) -> Result<(), String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    {
        let mut s = state.settings.lock().map_err(|e| e.to_string())?;
        if !s.tray_intro_seen {
            s.tray_intro_seen = true;
            crate::settings::save(&dir, &s).map_err(|e| e.to_string())?;
        }
    }
    hide_main(&app);
    Ok(())
}

/// The intro dialog's "Quit".
#[tauri::command]
pub fn app_quit(app: AppHandle) {
    app.exit(0);
}

/// Whether close-to-tray can work on this desktop, for the Settings screen.
#[tauri::command]
pub fn tray_supported() -> bool {
    available_cached()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_strips_vault_extension() {
        assert_eq!(display_name("/Users/a/Personal.kokos"), "Personal");
        assert_eq!(display_name(r"C:\Vaults\Work.kokos"), "Work");
        assert_eq!(display_name("/tmp/old.vault"), "old");
        assert_eq!(display_name("/tmp/.kokos"), ".kokos");
        assert_eq!(display_name("/tmp/notes.txt"), "notes.txt");
    }

    #[test]
    fn signature_changes_with_lock_state_and_lang() {
        let a = vec![VaultRow { path: "/a.kokos".into(), unlocked: true }];
        let b = vec![VaultRow { path: "/a.kokos".into(), unlocked: false }];
        assert_ne!(menu_signature("en", &a), menu_signature("en", &b));
        assert_ne!(menu_signature("en", &a), menu_signature("ru", &a));
        assert_eq!(menu_signature("en", &a), menu_signature("en", &a.clone()));
    }

    #[test]
    fn labels_fall_back_to_english() {
        assert_eq!(labels("de").open, "Open Kokos");
        assert_eq!(labels("ru").open, "Открыть Kokos");
    }
}

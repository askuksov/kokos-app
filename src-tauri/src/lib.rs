#![allow(dead_code)]

mod auth_failures;
mod autolock;
mod device;
mod icloud_macos;
mod paths;
mod settings;
pub mod session_registry;
mod synced_folder;

use tauri::menu::{AboutMetadata, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::image::Image;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            use tauri::{Emitter, Manager};
            let dir = app.path().app_config_dir()?;
            let _ = crate::device::cached(&dir);

            let handle = app.handle();

            let about = AboutMetadata {
                name: Some("Kokos".into()),
                version: Some(env!("CARGO_PKG_VERSION").into()),
                icon: Some(Image::from_bytes(include_bytes!("../icons/128x128.png"))?),
                ..Default::default()
            };

            let app_menu = Submenu::with_items(handle, "Kokos", true, &[
                &PredefinedMenuItem::about(handle, Some("About Kokos"), Some(about))?,
                &PredefinedMenuItem::separator(handle)?,
                &PredefinedMenuItem::services(handle, None)?,
                &PredefinedMenuItem::separator(handle)?,
                &PredefinedMenuItem::hide(handle, None)?,
                &PredefinedMenuItem::hide_others(handle, None)?,
                &PredefinedMenuItem::show_all(handle, None)?,
                &PredefinedMenuItem::separator(handle)?,
                &PredefinedMenuItem::quit(handle, None)?,
            ])?;

            let mi_new = MenuItem::with_id(handle, "menu-new-vault", "New Vault", true, Some("CmdOrCtrl+T"))?;
            let mi_open = MenuItem::with_id(handle, "menu-open-vault", "Open Vault\u{2026}", true, Some("CmdOrCtrl+O"))?;
            let mi_close = MenuItem::with_id(handle, "menu-close-vault", "Close Vault", true, Some("CmdOrCtrl+W"))?;
            let mi_lock_all = MenuItem::with_id(handle, "menu-lock-all", "Lock All Vaults", true, None::<&str>)?;
            let file_menu = Submenu::with_items(handle, "File", true, &[
                &mi_new,
                &mi_open,
                &PredefinedMenuItem::separator(handle)?,
                &mi_close,
                &PredefinedMenuItem::close_window(handle, Some("Close Window"))?,
                &PredefinedMenuItem::separator(handle)?,
                &mi_lock_all,
            ])?;

            let edit_menu = Submenu::with_items(handle, "Edit", true, &[
                &PredefinedMenuItem::undo(handle, None)?,
                &PredefinedMenuItem::redo(handle, None)?,
                &PredefinedMenuItem::separator(handle)?,
                &PredefinedMenuItem::cut(handle, None)?,
                &PredefinedMenuItem::copy(handle, None)?,
                &PredefinedMenuItem::paste(handle, None)?,
                &PredefinedMenuItem::select_all(handle, None)?,
            ])?;

            let window_menu = Submenu::with_items(handle, "Window", true, &[
                &PredefinedMenuItem::minimize(handle, None)?,
                &PredefinedMenuItem::maximize(handle, None)?,
                &PredefinedMenuItem::separator(handle)?,
                &PredefinedMenuItem::fullscreen(handle, None)?,
            ])?;

            let menu = Menu::with_items(handle, &[&app_menu, &file_menu, &edit_menu, &window_menu])?;
            app.set_menu(menu)?;

            app.on_menu_event(move |app, event| {
                match event.id().as_ref() {
                    "menu-new-vault" => { let _ = app.emit("menu-new-vault", ()); }
                    "menu-open-vault" => { let _ = app.emit("menu-open-vault", ()); }
                    "menu-close-vault" => { let _ = app.emit("menu-close-vault", ()); }
                    "menu-lock-all" => { let _ = app.emit("menu-lock-all", ()); }
                    _ => {}
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while building Kokos");
}

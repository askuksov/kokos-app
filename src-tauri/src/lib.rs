#![allow(dead_code)]

mod ai;
pub mod text_import;
mod auth_failures;
mod autolock;
mod biometric_macos;
mod device;
pub mod gdrive;
mod icloud_macos;
mod keyring_store;
pub mod nmh;
mod paths;
mod settings;
mod sleep_macos;
mod state;
pub mod session_registry;
mod sync_config;
mod synced_folder;
mod vault_dir;

use tauri::menu::{AboutMetadata, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::image::Image;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    use tauri::Manager;
    tauri::Builder::default()
        .manage(state::AppState::new())
        .invoke_handler(tauri::generate_handler![
            ai::ai_status,
            ai::ai_model_download,
            ai::ai_model_download_cancel,
            ai::ai_enable,
            ai::ai_disable,
            ai::ai_backfill,
            ai::ai_backfill_cancel,
            ai::ai_index_status,
            text_import::ai_gen_model_download,
            text_import::ai_gen_model_download_cancel,
            text_import::ai_text_import_analyze,
            text_import::ai_text_import_analyze_folder,
            text_import::ai_text_import_cancel,
            text_import::ai_text_import_stash,
            text_import::ai_text_import_has_stash,
            text_import::ai_text_import_restore,
            text_import::ai_text_import_discard,
            text_import::ai_gen_model_status,
            text_import::ai_gen_model_download_status,
        ])
        .setup(|app| {
            use tauri::{Emitter, Manager};
            let dir = app.path().app_config_dir()?;
            *app.state::<state::AppState>().settings.lock().unwrap() = settings::load(&dir);

            {
                let st = app.state::<state::AppState>();
                let paths = st.settings.lock().unwrap().open_vaults.clone();
                *st.restored_locked.lock().unwrap() = paths;
            }

            {
                let (ai_enabled, model_id) = {
                    let st = app.state::<state::AppState>();
                    let s = st.settings.lock().unwrap();
                    (s.ai_enabled, s.ai_model.clone())
                };
                let model_present = app
                    .path()
                    .app_local_data_dir()
                    .map(|d| ai::model_dir(&d, &model_id).join("model.onnx").exists())
                    .unwrap_or(false);
                if ai::should_prime_engine(ai_enabled, model_present) {
                    let handle = app.handle().clone();
                    std::thread::spawn(move || match ai::load_engine(&handle, &model_id) {
                        Ok(engine) => {
                            let st = handle.state::<state::AppState>();
                            let still_on = st.settings.lock().map(|s| s.ai_enabled).unwrap_or(false);
                            if still_on {
                                if let Ok(mut cache) = st.ai_embedder.lock() {
                                    *cache = Some(engine);
                                }
                            }
                        }
                        Err(e) => eprintln!("[ai] startup engine load skipped: {e}"),
                    });
                }
            }

            {
                let gen_prime = {
                    let st = app.state::<state::AppState>();
                    let ai_enabled = st.settings.lock().map(|s| s.ai_enabled).unwrap_or(false);
                    let present = app
                        .path()
                        .app_local_data_dir()
                        .map(|d| text_import::gen_model_present(&d, text_import::GEN_MODEL_ID))
                        .unwrap_or(false);
                    text_import::should_prime_gen_engine(ai_enabled, present)
                };
                if gen_prime {
                    let handle = app.handle().clone();
                    std::thread::spawn(move || match text_import::load_gen_engine(&handle, text_import::GEN_MODEL_ID) {
                        Ok(engine) => {
                            let st = handle.state::<state::AppState>();
                            let still_on = st.settings.lock().map(|s| s.ai_enabled).unwrap_or(false)
                                && handle
                                    .path()
                                    .app_local_data_dir()
                                    .map(|d| text_import::gen_model_present(&d, text_import::GEN_MODEL_ID))
                                    .unwrap_or(false);
                            if still_on {
                                if let Ok(mut cache) = st.gen_engine.lock() {
                                    *cache = Some(std::sync::Arc::new(engine));
                                }
                            }
                        }
                        Err(e) => eprintln!("[gen] startup engine load skipped: {e}"),
                    });
                }
            }

            let _ = crate::device::cached(&dir);

            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let st = handle.state::<state::AppState>();
                let minutes = st.settings.lock().map(|s| s.auto_lock_minutes).unwrap_or(0);
                let elapsed = st
                    .last_activity
                    .lock()
                    .map(|t| t.elapsed())
                    .unwrap_or_default();
                let any_open = st
                    .sessions
                    .lock()
                    .map(|reg| {
                        reg.open_paths()
                            .iter()
                            .any(|id| reg.get(id).map(|s| s.vault.is_some()).unwrap_or(false))
                    })
                    .unwrap_or(false);
                if autolock::should_lock(any_open, elapsed, minutes) {
                    if let Ok(mut reg) = st.sessions.lock() {
                        for s in reg.iter_mut() {
                            if let Some(v) = s.vault.as_mut() {
                                let _ = kokos_core::audit::append(&v.conn, "lock", None);
                                let _ = kokos_core::vault::save(v);
                            }
                        }
                        reg.lock_all();
                        drop(reg);
                        let _ = handle.emit("vault-locked", serde_json::json!({ "vault_id": null }));
                        nmh::invalidate_confirms(&handle);
                    }
                }
            });

            sleep_macos::install(app.handle().clone());

            if let Some(arg) = std::env::args().nth(1) {
                let p = std::path::PathBuf::from(&arg);
                if p.is_file() {
                    *app.state::<state::AppState>().pending_open.lock().unwrap() = Some(p);
                }
            }

            let nmh_on = app
                .state::<state::AppState>()
                .settings
                .lock()
                .map(|s| s.nmh_enabled)
                .unwrap_or(false);
            if nmh_on {
                nmh::start(app.handle().clone());
            }

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
        .build(tauri::generate_context!())
        .expect("error while building Kokos")
        .run(|handle, event| {
            if let tauri::RunEvent::ExitRequested { .. } = event {
                let clear = handle
                    .state::<state::AppState>()
                    .settings
                    .lock()
                    .map(|s| s.clear_clipboard_on_exit)
                    .unwrap_or(false);
                if clear {
                    if let Ok(mut cb) = arboard::Clipboard::new() {
                        let _ = cb.set_text("");
                    }
                }
            }
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "android"))]
            if let tauri::RunEvent::Opened { urls } = &event {
                use tauri::{Emitter, Manager};
                for url in urls {
                    if let Ok(path) = url.to_file_path() {
                        *handle
                            .state::<state::AppState>()
                            .pending_open
                            .lock()
                            .unwrap() = Some(path.clone());
                        let _ =
                            handle.emit("open-file-request", path.to_string_lossy().into_owned());
                    }
                }
            }
        });
}

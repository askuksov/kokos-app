//! Local-AI Tauri surface: opt-in enable/disable + model status, with a
//! download-progress event. The only network egress in the app besides sync:
//! a pinned model URL, SHA-256-verified inside kokos-ai.
//! Enable/disable is audited into the active vault (keychain_enable precedent).

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::state::{AiEngine, AppState};
use kokos_ai::registry;

type CmdResult<T> = Result<T, String>;

/// `<app_local_data_dir>/models/<model_id>/` — large binaries live in data,
/// not config (settings.json stays in app_config_dir).
pub fn model_dir(base_local_data: &Path, model_id: &str) -> PathBuf {
    base_local_data.join("models").join(model_id)
}

/// Domain-separation label for the vector-store subkey (must match the
/// vector-store reader).
pub const SUBKEY_LABEL: &[u8] = b"kokos-ai:vectors:v1";

/// `<app_local_data_dir>/vectors/` — sibling of `models/`, machine-local, not synced.
pub fn vectors_dir(app: &AppHandle) -> CmdResult<PathBuf> {
    Ok(app.path().app_local_data_dir().map_err(|e| e.to_string())?.join("vectors"))
}

/// Whether to eagerly load the embedding engine at startup. Only when AI is
/// enabled AND the model file is present — otherwise the cache stays empty and
/// `ai_enable` loads it on demand. Pure seam so the setup-hook decision is
/// testable without a Tauri harness.
pub fn should_prime_engine(ai_enabled: bool, model_present: bool) -> bool {
    ai_enabled && model_present
}

/// Build an `OrtEmbedder` for `model_id` from the app model dir. The files must
/// already be present (downloaded by `ai_enable`, or placed manually); a
/// missing/incompatible model surfaces as an error.
pub fn load_engine(app: &AppHandle, model_id: &str) -> CmdResult<AiEngine> {
    let def = registry::resolve(model_id).ok_or_else(|| "unknown model".to_string())?;
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    let mdir = model_dir(&dir, def.id);
    let emb = kokos_ai::embed::OrtEmbedder::load(def, &mdir.join("model.onnx"), &mdir.join("tokenizer.json"))
        .map_err(|e| e.to_string())?;
    Ok(AiEngine { model_id: def.id.to_string(), dim: def.dim as u32, embedder: std::sync::Arc::new(emb) })
}

#[derive(Serialize)]
pub struct AiStatus {
    pub enabled: bool,
    pub model_id: String,
    pub model_present: bool,
}

/// Best-effort: append audit events into the active vault and persist them,
/// mirroring keychain_enable's begin_borrow → spawn_blocking → end_borrow
/// hand-off so the blocking write never runs on the async runtime while the
/// sessions lock is held. No active/open vault ⇒ silently skip (AI enable is
/// app-level, not vault-scoped). `events` = (event_name, optional detail).
pub(crate) async fn audit_active_vault(state: &AppState, events: Vec<(&'static str, Option<String>)>) {
    let borrowed = {
        let Ok(mut reg) = state.sessions.lock() else { return };
        let Some(id) = reg.active_id().map(|s| s.to_string()) else { return };
        reg.get_mut(&id).and_then(|s| s.begin_borrow()).map(|v| (id, v))
    };
    let Some((id, mut v)) = borrowed else { return };
    let v = match tauri::async_runtime::spawn_blocking(move || {
        for (event, detail) in &events {
            let _ = kokos_core::audit::append(&v.conn, event, detail.as_deref());
        }
        let _ = kokos_core::vault::save(&mut v);
        v
    })
    .await
    {
        Ok(v) => v,
        Err(_) => return,
    };
    if let Ok(mut reg) = state.sessions.lock() {
        if let Some(s) = reg.get_mut(&id) {
            s.end_borrow(v);
        }
    }
}

/// Eager background backfill of the ACTIVE vault against the loaded engine.
/// Borrows the vault for the whole loop (edits are blocked meanwhile — same as
/// any long `spawn_blocking` mutation; the cancel token is the escape hatch).
/// Emits `ai_backfill_progress { done, total }`. Returns the count embedded.
pub async fn run_backfill_for_active(app: &AppHandle, state: &AppState) -> CmdResult<usize> {
    let engine = state
        .ai_embedder
        .lock()
        .map_err(|e| e.to_string())?
        .clone()
        .ok_or_else(|| "ai_not_enabled".to_string())?;
    let vdir = vectors_dir(app)?;

    state.ai_backfill_cancel.store(false, Ordering::SeqCst);
    let cancel = state.ai_backfill_cancel.clone();

    let id = {
        let reg = state.sessions.lock().map_err(|e| e.to_string())?;
        reg.active_id().map(str::to_string)
    }
    .ok_or_else(|| "no_vault".to_string())?;

    let v = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        reg.get_mut(&id)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or_else(|| "vault_busy".to_string())?
    };

    let app2 = app.clone();
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = (|| -> Result<usize, String> {
            let vault_id = kokos_core::db::get_device_id(&v.conn).map_err(|e| e.to_string())?;
            let wanted = kokos_ai::meta::collect_metadata(&v.conn, &engine.model_id).map_err(|e| e.to_string())?;
            let subkey = kokos_core::crypto::derive_subkey(&v.key, SUBKEY_LABEL);
            let path = kokos_ai::store::store_path(&vdir, &vault_id);
            let mut store = kokos_ai::store::load(&path, &subkey, &engine.model_id, engine.dim);
            let done = kokos_ai::index::run_backfill(
                &mut store,
                &wanted,
                engine.embedder.as_ref(),
                |d, t| {
                    let _ = app2.emit("ai_backfill_progress", serde_json::json!({ "done": d, "total": t }));
                },
                || cancel.load(Ordering::SeqCst),
            )
            .map_err(|e| e.to_string())?;
            kokos_ai::store::save(&path, &store, &subkey).map_err(|e| e.to_string())?;
            Ok(done)
        })();
        (v, outcome)
    })
    .await
    .map_err(|e| e.to_string())?;

    {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(s) = reg.get_mut(&id) {
            s.end_borrow(v);
        }
    }
    result
}

#[tauri::command]
pub async fn ai_backfill(app: AppHandle, state: State<'_, AppState>) -> CmdResult<usize> {
    run_backfill_for_active(&app, &state).await
}

#[tauri::command]
pub fn ai_backfill_cancel(state: State<'_, AppState>) -> CmdResult<()> {
    state.ai_backfill_cancel.store(true, Ordering::SeqCst);
    Ok(())
}

#[derive(Serialize)]
pub struct AiIndexStatus {
    pub model_id: String,
    pub indexed: usize,
    pub total: usize,
}

/// How much of the active vault is embedded for the active model. Read-only:
/// briefly borrows the session (no spawn_blocking, no save). Returns zeros when
/// AI is disabled or no engine is loaded.
#[tauri::command]
pub fn ai_index_status(app: AppHandle, state: State<'_, AppState>) -> CmdResult<AiIndexStatus> {
    let engine = state.ai_embedder.lock().map_err(|e| e.to_string())?.clone();
    let Some(engine) = engine else {
        let model_id = state.settings.lock().map_err(|e| e.to_string())?.ai_model.clone();
        return Ok(AiIndexStatus { model_id, indexed: 0, total: 0 });
    };
    let vdir = vectors_dir(&app)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let id = reg.active_id().map(str::to_string).ok_or_else(|| "no_vault".to_string())?;
    let s = reg.get_mut(&id).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or("no vault open")?;
    let vault_id = kokos_core::db::get_device_id(&v.conn).map_err(|e| e.to_string())?;
    let total = kokos_ai::meta::collect_metadata(&v.conn, &engine.model_id).map_err(|e| e.to_string())?.len();
    let subkey = kokos_core::crypto::derive_subkey(&v.key, SUBKEY_LABEL);
    let path = kokos_ai::store::store_path(&vdir, &vault_id);
    let indexed = kokos_ai::store::load(&path, &subkey, &engine.model_id, engine.dim).records.len();
    Ok(AiIndexStatus { model_id: engine.model_id, indexed, total })
}

#[tauri::command]
pub fn ai_status(app: AppHandle, state: State<'_, AppState>) -> CmdResult<AiStatus> {
    let s = state.settings.lock().map_err(|e| e.to_string())?.clone();
    let def = registry::resolve(&s.ai_model).ok_or_else(|| "unknown model".to_string())?;
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    let present = model_dir(&dir, def.id).join("model.onnx").exists();
    Ok(AiStatus {
        enabled: s.ai_enabled,
        model_id: def.id.to_string(),
        model_present: present,
    })
}

/// Fetch and verify the active model's files, without touching the setting.
///
/// Downloading and enabling are two decisions, not one. Keeping them apart means
/// the user consents to a specific transfer ("470 MB") rather than to a switch,
/// the model can be fetched before the feature is wanted, and — the case that
/// forced the split — a vault whose model file has gone missing can be repaired
/// in place instead of only by toggling the feature off and on again.
#[tauri::command]
pub async fn ai_model_download(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    let model_id = state.settings.lock().map_err(|e| e.to_string())?.ai_model.clone();
    let def = registry::resolve(&model_id).ok_or_else(|| "unknown model".to_string())?;
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    let mdir = model_dir(&dir, def.id);
    let model_dest = mdir.join("model.onnx");
    let tok_dest = mdir.join("tokenizer.json");
    if model_dest.exists() {
        return Ok(());
    }

    let app2 = app.clone();
    let cancel = state.ai_download_cancel.clone();
    cancel.store(false, Ordering::SeqCst);
    let (url, sha, turl, tsha) = (
        def.url.to_string(),
        def.sha256.to_string(),
        def.tokenizer_url.to_string(),
        def.tokenizer_sha256.to_string(),
    );
    tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
        let emit = |downloaded: u64, total: u64| {
            let _ = app2.emit(
                "ai_download_progress",
                serde_json::json!({ "downloaded": downloaded, "total": total }),
            );
        };
        let cancelled = || cancel.load(Ordering::SeqCst);
        kokos_ai::download::download_verified(&turl, &tok_dest, &tsha, "tokenizer.json", &emit, &cancelled)
            .map_err(|e| e.to_string())?;
        kokos_ai::download::download_verified(&url, &model_dest, &sha, "model.onnx", &emit, &cancelled)
            .map_err(|e| e.to_string())?;
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())??;

    audit_active_vault(&state, vec![("ai_model_downloaded", Some(def.id.to_string()))]).await;
    Ok(())
}

/// Stop an in-flight `ai_model_download`. The download loop checks the flag
/// after every chunk, deletes the half-written `.part` file and reports
/// `cancelled`; the awaiting `ai_model_download` call then fails with it.
#[tauri::command]
pub fn ai_model_download_cancel(state: State<'_, AppState>) -> CmdResult<()> {
    state
        .ai_download_cancel
        .store(true, Ordering::SeqCst);
    Ok(())
}

#[tauri::command]
pub async fn ai_enable(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    let model_id = state.settings.lock().map_err(|e| e.to_string())?.ai_model.clone();
    let def = registry::resolve(&model_id).ok_or_else(|| "unknown model".to_string())?;
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;

    if !model_dir(&dir, def.id).join("model.onnx").exists() {
        return Err("model_missing".to_string());
    }

    {
        let mut s = state.settings.lock().map_err(|e| e.to_string())?;
        s.ai_enabled = true;
    }
    let s = state.settings.lock().map_err(|e| e.to_string())?.clone();
    let cfg = app.path().app_config_dir().map_err(|e| e.to_string())?;
    crate::settings::save(&cfg, &s).map_err(|e| e.to_string())?;

    audit_active_vault(&state, vec![("ai_enabled", None)]).await;

    match load_engine(&app, &def.id) {
        Ok(engine) => {
            *state.ai_embedder.lock().map_err(|e| e.to_string())? = Some(engine);
            if let Err(e) = run_backfill_for_active(&app, &state).await {
                eprintln!("[ai] eager backfill after enable skipped: {e}");
            }
        }
        Err(e) => eprintln!("[ai] engine load after enable skipped (model files present?): {e}"),
    }
    Ok(())
}

#[tauri::command]
pub async fn ai_disable(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    {
        let mut s = state.settings.lock().map_err(|e| e.to_string())?;
        s.ai_enabled = false;
    }
    let s = state.settings.lock().map_err(|e| e.to_string())?.clone();
    let cfg = app.path().app_config_dir().map_err(|e| e.to_string())?;
    crate::settings::save(&cfg, &s).map_err(|e| e.to_string())?;
    audit_active_vault(&state, vec![("ai_disabled", None)]).await;
    *state.ai_embedder.lock().map_err(|e| e.to_string())? = None;
    *state.gen_engine.lock().map_err(|e| e.to_string())? = None;
    Ok(())
}

/// Best-effort: re-embed ONE entry into its sidecar record (create/edit path).
/// Runs inside the caller's existing `spawn_blocking` (it borrows `v.conn` +
/// `v.key`). A failure is logged and swallowed — vectors are derived data and
/// must never fail an entry save.
pub fn reembed_entry_blocking(v: &kokos_core::vault::OpenVault, engine: &AiEngine, entry_id: &str, vectors_dir: &Path) {
    let r = (|| -> Result<(), String> {
        let Some(entry) = kokos_core::entries::get(&v.conn, entry_id).map_err(|e| e.to_string())? else {
            return Ok(());
        };
        let fmap = kokos_ai::meta::folder_names(&v.conn).map_err(|e| e.to_string())?;
        let fname = entry.folder_id.as_deref().and_then(|id| fmap.get(id)).map(String::as_str);
        let meta = kokos_ai::meta::metadata_from_entry(&entry, fname);
        let input = kokos_ai::meta::embedding_input(&meta);
        let content_hash = kokos_ai::meta::content_hash(&input, &engine.model_id);
        let em = kokos_ai::meta::EntryMeta { entry_id: entry.id.clone(), input, content_hash };

        let vault_id = kokos_core::db::get_device_id(&v.conn).map_err(|e| e.to_string())?;
        let subkey = kokos_core::crypto::derive_subkey(&v.key, SUBKEY_LABEL);
        let path = kokos_ai::store::store_path(vectors_dir, &vault_id);
        let mut store = kokos_ai::store::load(&path, &subkey, &engine.model_id, engine.dim);
        kokos_ai::index::upsert_one(&mut store, &em, engine.embedder.as_ref()).map_err(|e| e.to_string())?;
        kokos_ai::store::save(&path, &store, &subkey).map_err(|e| e.to_string())
    })();
    if let Err(e) = r {
        eprintln!("[ai] reembed {entry_id} skipped: {e}");
    }
}

/// Best-effort: drop an entry's sidecar record (delete path). Trash/restore is
/// reconciled at the next backfill (a trashed entry is `is_deleted=1` so it
/// leaves the live set and `plan_backfill` removes it); this just keeps the
/// eager path tidy.
pub fn remove_entry_vector_blocking(v: &kokos_core::vault::OpenVault, engine: &AiEngine, entry_id: &str, vectors_dir: &Path) {
    let r = (|| -> Result<(), String> {
        let vault_id = kokos_core::db::get_device_id(&v.conn).map_err(|e| e.to_string())?;
        let subkey = kokos_core::crypto::derive_subkey(&v.key, SUBKEY_LABEL);
        let path = kokos_ai::store::store_path(vectors_dir, &vault_id);
        let mut store = kokos_ai::store::load(&path, &subkey, &engine.model_id, engine.dim);
        if store.records.remove(entry_id).is_some() {
            kokos_ai::store::save(&path, &store, &subkey).map_err(|e| e.to_string())?;
        }
        Ok(())
    })();
    if let Err(e) = r {
        eprintln!("[ai] remove-vector {entry_id} skipped: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_dir_is_under_models_by_id() {
        let p = model_dir(Path::new("/data"), "small");
        assert!(p.ends_with("models/small"), "got {p:?}");
    }

    #[test]
    fn primes_only_when_enabled_and_model_present() {
        assert!(should_prime_engine(true, true), "enabled + model present -> load");
        assert!(!should_prime_engine(true, false), "enabled but no model -> skip");
        assert!(!should_prime_engine(false, true), "disabled -> skip even if present");
        assert!(!should_prime_engine(false, false), "disabled + no model -> skip");
    }
}

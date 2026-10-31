//! IPC surface. Rules:
//!   - heavy work (KDF; save's serialize+encrypt+fsync) runs in spawn_blocking,
//!     otherwise it freezes the window;
//!   - errors are returned as strings and never carry secrets — including
//!     spawn_blocking's JoinError, whose Display can otherwise relay a
//!     panicking closure's payload verbatim (see `spawn_blocking_failed`);
//!   - the password arrives from the WebView (unavoidable) and is
//!     wrapped in Zeroizing as early as possible;
//!   - a vault that has to leave the session for a spawn_blocking call
//!     (`save_vault`, `change_master_password`) always goes out via
//!     `Session::begin_borrow` and back via `Session::end_borrow`, never a
//!     bare `take()`/assignment — see kokos_core::session for why.

use std::path::{Path, PathBuf};

use kokos_core::crypto::Argon2Params;
use kokos_core::entries::{self, View};
use kokos_core::format::header::read_header_only;
use kokos_core::session::Session;
use kokos_core::vault::{self, KeyfileAction};
use kokos_core::VaultError;
use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use tauri::State;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::session_registry::SessionRegistry;
use crate::state::AppState;

/// Resolve the target vault id for a command: the explicit `vault_id` when the
/// caller passed one and it is open, else the active session. Returns the
/// canonical id string, or a `"no_vault"` error when nothing matches (fail
/// closed) — the same shape the old `session.lock()` + `vault.as_ref()` guard
/// produced when no vault was open.
fn resolve_vault_id(reg: &SessionRegistry, vault_id: Option<&str>) -> CmdResult<String> {
    reg.resolve(vault_id)
        .map(|s| s.to_string())
        .ok_or_else(|| "no_vault".to_string())
}

#[derive(Serialize)]
pub struct HeaderInfo {
    pub hint: String,
    pub requires_keyfile: bool,
    pub format_version: u32,
}

#[derive(Serialize)]
pub struct VaultInfo {
    pub path: String,
    pub format_version: u32,
    pub has_keyfile: bool,
    pub db_name: String,
    pub entry_count: u32,
    pub schema_migrated: bool,
}

#[derive(Serialize)]
pub struct StatusInfo {
    pub open: bool,
    pub locked: bool,
    pub path: Option<String>,
    pub hint: Option<String>,
    pub migrated: bool,
}

#[derive(Serialize)]
pub struct SyncStatusInfo {
    pub kind: String,
    pub folder_path: Option<String>,
    pub gdrive_connected: bool,
    pub last_sync: i64,
    pub conflicts: Vec<String>,
    pub not_synced_warning: bool,
    pub note: Option<String>,
}

#[derive(Deserialize, Clone, Copy)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u8,
}

impl From<KdfParams> for Argon2Params {
    fn from(p: KdfParams) -> Self {
        Argon2Params { memory_kib: p.memory_kib, time_cost: p.time_cost, parallelism: p.parallelism }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyfileActionDto {
    Keep,
    Set { path: String },
    /// Mechanically identical to `Set` (both map to `KeyfileAction::Set`
    /// below) but distinct USER INTENT: the Master-password form must
    /// re-supply a key-file vault's current key file to rotate the password
    /// at all (`KeyfileAction::Keep` is rejected outright by kokos-core on
    /// such a vault), even though the file itself is not changing. See
    /// `keyfile_was_changed` — the audit log records intent, not mechanism,
    /// so this variant must never be treated as "the key file changed".
    Resupply { path: String },
    Remove,
}

#[derive(Serialize)]
pub struct RecentFile {
    pub path: String,
    pub last_opened: i64,
    pub has_keyfile: bool,
}

#[derive(Serialize)]
pub struct TagRefDto {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
}

fn to_tag_ref_dto(t: kokos_core::entries::TagRef) -> TagRefDto {
    TagRefDto { id: t.id, name: t.name, color: t.color }
}

#[derive(Serialize)]
pub struct EntrySummaryDto {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub is_favorite: bool,
    pub has_totp: bool,
    pub has_attachments: bool,
    pub updated_at: i64,
    pub folder_id: Option<String>,
    pub tags: Vec<TagRefDto>,
    pub entry_type: String,
    pub password_field_id: Option<String>,
}

/// One of the seven vault `entry_fields.field_type` values.
/// `phone` is first-class since schema v9 — it MUST stay in lockstep
/// with the DB CHECK, `templates::validate_field_type`, and `portable.rs`, or an
/// AI-imported entry containing a phone is rejected whole-batch at commit.
const VALID_FIELD_TYPES: [&str; 7] = ["text", "secret", "url", "email", "otp", "date", "phone"];

/// The commit payload from the review-UI — ALREADY in vault-type space (the
/// frontend mapped kokos-ai's EntryKind/FieldType to the vault's entry_type /
/// field_type before sending). Nested fields are snake_case. Values were
/// verbatim-validated at analyze time or deliberately edited by the user —
/// there is no second integrity check here.
#[derive(serde::Deserialize)]
pub struct CommitField {
    pub name: String,
    pub field_type: String,
    pub is_protected: bool,
    pub value: String,
}
#[derive(serde::Deserialize, Default)]
pub struct CommitEntry {
    pub title: String,
    pub entry_type: String,
    pub fields: Vec<CommitField>,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub new_folder_name: Option<String>,
}
#[derive(serde::Deserialize)]
pub struct CommitProposal {
    pub entries: Vec<CommitEntry>,
}

#[derive(serde::Serialize)]
pub struct TextImportReport {
    pub imported: u32,
    pub failed: u32,
}

/// Fail-closed type check WITHOUT building/cloning — run before any folder
/// insert so a bad-type payload writes nothing at all.
fn validate_commit_types(p: &CommitProposal) -> Result<(), VaultError> {
    for e in &p.entries {
        if !kokos_core::entries::is_valid_entry_type(&e.entry_type) {
            return Err(VaultError::ImportUnsupported);
        }
        for f in &e.fields {
            if !VALID_FIELD_TYPES.contains(&f.field_type.as_str()) {
                return Err(VaultError::ImportUnsupported);
            }
        }
    }
    Ok(())
}

/// Pure, testable seam: validate every entry_type/field_type against the DB
/// CHECK sets (fail-closed, via `validate_commit_types`) and map the
/// vault-typed proposal to `NewEntry`s bound to `folder_id`. Factored out of
/// the command so a real-DB test can drive it without an AppHandle (there is
/// no Tauri test harness).
/// Clones each value into the NewField; the command zeroizes the DTO copies
/// after the write. `secret`/`otp` fields are always stored protected
/// (defense-in-depth masking, regardless of what the DTO's `is_protected`
/// says — this only ever ADDS protection, never removes it).
fn build_new_entries(proposal: &CommitProposal, folder_ids: &[String]) -> Result<Vec<kokos_core::entries::NewEntry>, VaultError> {
    validate_commit_types(proposal)?;
    let mut out = Vec::with_capacity(proposal.entries.len());
    for (i, e) in proposal.entries.iter().enumerate() {
        let mut fields = Vec::with_capacity(e.fields.len());
        for f in &e.fields {
            fields.push(kokos_core::entries::NewField {
                template_id: None,
                name: f.name.clone(),
                value: Some(f.value.clone()),
                is_protected: f.is_protected || f.field_type == "secret" || f.field_type == "otp",
                field_type: f.field_type.clone(),
            });
        }
        let folder_id = folder_ids.get(i).map(String::as_str).unwrap_or("root");
        out.push(kokos_core::entries::NewEntry {
            title: e.title.clone(),
            folder_id: Some(folder_id.to_string()),
            notes: None,
            entry_type: e.entry_type.clone(),
            fields,
        });
    }
    Ok(out)
}

/// Resolve each proposal entry's destination folder id, order-aligned with
/// `proposal.entries`. A non-empty `new_folder_name` → find_or_create
/// under root, CACHED by name so N entries sharing a new name create exactly ONE
/// folder (find_or_create is already idempotent by (parent, name); the cache just
/// skips the repeat lookups). Otherwise the entry's `folder_id` (default "root").
/// Impure (writes folder rows) — split from the pure `build_new_entries` so the
/// dedup behaviour is unit-testable on a fresh in-memory conn, and called AFTER
/// `validate_commit_types` so a bad-type payload never leaves an orphan folder.
fn resolve_commit_folders(
    conn: &rusqlite::Connection,
    proposal: &CommitProposal,
    now: i64,
) -> Result<Vec<String>, VaultError> {
    let mut cache: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut out = Vec::with_capacity(proposal.entries.len());
    for e in &proposal.entries {
        let fid = match e.new_folder_name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(name) => match cache.get(name) {
                Some(id) => id.clone(),
                None => {
                    let folder = kokos_core::folders::find_or_create(conn, Some("root"), name, now)?;
                    cache.insert(name.to_string(), folder.id.clone());
                    folder.id
                }
            },
            None => e.folder_id.clone().unwrap_or_else(|| "root".to_string()),
        };
        out.push(fid);
    }
    Ok(out)
}

#[derive(Serialize)]
pub struct FieldDto {
    pub id: String,
    pub template_id: Option<String>,
    pub name: String,
    pub value: Option<String>,
    pub is_protected: bool,
    pub field_type: String,
    pub sort_order: i32,
    pub strength: Option<u8>,
}

#[derive(Serialize)]
pub struct EntryDto {
    pub id: String,
    pub folder_id: Option<String>,
    pub title: String,
    pub notes: Option<String>,
    pub is_favorite: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub fields: Vec<FieldDto>,
    pub tags: Vec<TagRefDto>,
    pub entry_type: String,
}

type CmdResult<T> = std::result::Result<T, String>;

fn info(v: &vault::OpenVault) -> CmdResult<VaultInfo> {
    let entry_count: i64 = v
        .conn
        .query_row("SELECT COUNT(*) FROM entries WHERE is_deleted = 0", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let db_name: String = v
        .conn
        .query_row("SELECT value FROM metadata WHERE key = 'db_name'", [], |r| r.get(0))
        .unwrap_or_else(|_| "Vault".to_string());
    Ok(VaultInfo {
        path: v.path.to_string_lossy().to_string(),
        format_version: v.header.version,
        has_keyfile: v.header.requires_keyfile(),
        db_name,
        entry_count: entry_count as u32,
        schema_migrated: v.migrated,
    })
}

/// `create_vault`/`open_vault`/`unlock_vault` must not silently overwrite an
/// `OpenVault` that is already in the session, or steal one that is
/// temporarily on loan to another in-flight command's `spawn_blocking` call
/// (`Session::is_open_or_borrowed`). Both cases mean there is unsaved state a
/// caller could otherwise lose without ever seeing an error.
fn ensure_no_vault_open(s: &Session) -> CmdResult<()> {
    if s.is_open_or_borrowed() {
        Err(VaultError::AlreadyOpen.to_string())
    } else {
        Ok(())
    }
}

/// Maps the `tauri::Error` produced when a `spawn_blocking`'d closure panics
/// or is cancelled — its `JoinError` variant here, since none of these
/// closures call other fallible Tauri APIs — to a fixed, secret-free string
/// instead of `.to_string()`-ing it. `tauri::Error::JoinError` is
/// `#[error(transparent)]` over `tokio::task::JoinError`, whose own Display
/// relays a panicking closure's payload verbatim ("task {id} panicked with
/// message {:?}"); every closure passed to `spawn_blocking` in this module
/// captures the password and/or the vault's key, so that string must never
/// reach the WebView. No panic is expected in practice — this is the
/// hardening backstop for if one ever happens.
fn spawn_blocking_failed(_e: tauri::Error) -> String {
    "internal error".to_string()
}

/// Key-file paths get the same allowlist gate as vault paths. The UI only ever
/// obtains one from `pick_any_file`, which allowlists it, so an unlisted path
/// can only come from a compromised WebView. Ungated, `key_material` would
/// `std::fs::read` any readable file on the WebView's say-so — an existence
/// oracle for arbitrary paths, and an unbounded read (DoS) on a device such as
/// `/dev/zero`. `None` (no key file) is always fine.
fn ensure_keyfile_allowed(
    allowed: &std::sync::Mutex<std::collections::HashSet<PathBuf>>,
    keyfile: Option<&str>,
) -> CmdResult<()> {
    match keyfile {
        Some(p) if !crate::paths::is_allowed(allowed, p) => Err(VaultError::PathNotAllowed.to_string()),
        _ => Ok(()),
    }
}

/// Works without a session: the header is unencrypted, so the lock screen can
/// show the hint and know whether to ask for a key file. Still
/// allowlist-gated like `open_vault`/`create_vault` — without `state` this
/// took a raw path straight from the WebView with no check at all, letting
/// any caller read the password hint for an arbitrary filesystem path.
#[tauri::command]
pub async fn get_vault_header_info(state: State<'_, AppState>, path: String) -> CmdResult<HeaderInfo> {
    if !crate::paths::is_allowed(&state.allowed_paths, &path) {
        return Err(VaultError::PathNotAllowed.to_string());
    }
    let path_for_error = path.clone();
    let h = tauri::async_runtime::spawn_blocking(move || read_header_only(&PathBuf::from(path)))
        .await
        .map_err(spawn_blocking_failed)?
        .map_err(|e| explain_vault_error(&e, &path_for_error, crate::nmh::snap::instance_name().as_deref()))?;
    Ok(HeaderInfo { hint: h.hint.clone(), requires_keyfile: h.requires_keyfile(), format_version: h.version })
}

#[tauri::command]
pub async fn create_vault(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    path: String,
    password: String,
    hint: String,
    kdf: KdfParams,
    keyfile_path: Option<String>,
) -> CmdResult<VaultInfo> {
    use tauri::Emitter;
    if !crate::paths::is_allowed(&state.allowed_paths, &path) {
        return Err(VaultError::PathNotAllowed.to_string());
    }
    ensure_keyfile_allowed(&state.allowed_paths, keyfile_path.as_deref())?;

    {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if reg.get(&path).map(|s| s.vault.is_some()).unwrap_or(false) {
            reg.set_active(&path);
            let existing = info(reg.get(&path).and_then(|s| s.vault.as_ref()).expect("checked is_some above"))?;
            drop(reg);
            let _ = app.emit("vault-unlocked", serde_json::json!({ "vault_id": path }));
            persist_open_vaults(&app, &state);
            crate::nmh::invalidate_confirms(&app);
            return Ok(existing);
        }
        if let Some(s) = reg.get(&path) {
            ensure_no_vault_open(s)?;
        }
    }

    let pw = Zeroizing::new(password.into_bytes());
    let has_keyfile = keyfile_path.is_some();
    let path_for_recent = path.clone();
    let v = tauri::async_runtime::spawn_blocking(move || {
        vault::create(
            &PathBuf::from(path),
            &pw,
            &hint,
            kdf.into(),
            keyfile_path.as_ref().map(PathBuf::from).as_deref(),
        )
    })
    .await
    .map_err(spawn_blocking_failed)?
    .map_err(|e| explain_vault_error(&e, &path_for_recent, crate::nmh::snap::instance_name().as_deref()))?;

    let result = info(&v)?;
    let vault_id = v.path.to_string_lossy().to_string();
    {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(s) = reg.get(&vault_id) {
            ensure_no_vault_open(s)?;
        }
        let mut session = Session::new();
        session.vault = Some(v);
        reg.insert(vault_id.clone(), session);
    }
    mark_restored_unlocked(&state, &vault_id);
    push_recent(&app, &path_for_recent, has_keyfile);
    *state.last_activity.lock().map_err(|e| e.to_string())? = std::time::Instant::now();
    let _ = app.emit("vault-unlocked", serde_json::json!({ "vault_id": vault_id }));
    persist_open_vaults(&app, &state);
    crate::nmh::invalidate_confirms(&app);
    Ok(result)
}

#[tauri::command]
pub async fn open_vault(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    path: String,
    password: String,
    keyfile_path: Option<String>,
) -> CmdResult<VaultInfo> {
    use tauri::{Emitter, Manager};
    if !crate::paths::is_allowed(&state.allowed_paths, &path) {
        return Err(VaultError::PathNotAllowed.to_string());
    }
    ensure_keyfile_allowed(&state.allowed_paths, keyfile_path.as_deref())?;

    {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if reg.get(&path).map(|s| s.vault.is_some()).unwrap_or(false) {
            reg.set_active(&path);
            let existing = info(reg.get(&path).and_then(|s| s.vault.as_ref()).expect("checked is_some above"))?;
            drop(reg);
            let _ = app.emit("vault-unlocked", serde_json::json!({ "vault_id": path }));
            persist_open_vaults(&app, &state);
            crate::nmh::invalidate_confirms(&app);
            return Ok(existing);
        }
        if let Some(s) = reg.get(&path) {
            ensure_no_vault_open(s)?;
        }
    }

    let pw = Zeroizing::new(password.into_bytes());
    let has_keyfile = keyfile_path.is_some();
    let path_for_recent = path.clone();
    let cfg_dir = app.path().app_config_dir().ok();

    {
        let app = app.clone();
        let vp = path.clone();
        let _ = tauri::async_runtime::spawn_blocking(move || folder_pre_open(&app, &vp)).await;
    }

    let opened = tauri::async_runtime::spawn_blocking(move || {
        vault::open(
            &PathBuf::from(path),
            &pw,
            keyfile_path.as_ref().map(PathBuf::from).as_deref(),
        )
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let mut v = match opened {
        Ok(v) => v,
        Err(e) => {
            record_open_failure(cfg_dir.as_deref(), &path_for_recent, &e);
            return Err(explain_vault_error(&e, &path_for_recent, crate::nmh::snap::instance_name().as_deref()));
        }
    };

    let n = cfg_dir.as_ref().map(|dir| crate::auth_failures::take(dir, &path_for_recent)).unwrap_or(0);
    let detail = (n > 0).then(|| format!("{n} failed attempts since last success"));

    let vdir = ai_cleanup_dir(&app);
    let v = tauri::async_runtime::spawn_blocking(move || {
        let _ = kokos_core::audit::append(&v.conn, "unlock", detail.as_deref());
        let _ = vault::save_opened(&mut v);
        if let Some(vdir) = &vdir {
            prune_orphan_vectors_blocking(&v, vdir);
        }
        v
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let result = info(&v)?;
    let vault_id = v.path.to_string_lossy().to_string();
    {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(s) = reg.get(&vault_id) {
            ensure_no_vault_open(s)?;
        }
        let mut session = Session::new();
        session.vault = Some(v);
        reg.insert(vault_id.clone(), session);
    }
    mark_restored_unlocked(&state, &vault_id);
    push_recent(&app, &path_for_recent, has_keyfile);
    *state.last_activity.lock().map_err(|e| e.to_string())? = std::time::Instant::now();
    let _ = app.emit("vault-unlocked", serde_json::json!({ "vault_id": vault_id }));
    persist_open_vaults(&app, &state);
    crate::nmh::invalidate_confirms(&app);
    Ok(result)
}

/// Folder-mode pre-open: if this vault syncs via a folder, make sure iCloud has
/// materialized the file before we read it. No-op for none/gdrive targets and on
/// non-macOS. Best-effort — a timeout does NOT block opening (the on-disk bytes,
/// possibly stale, are still openable).
///
/// Folder provider PUSH = no-op: the working vault IS the file in the synced
/// folder, so the normal atomic save already writes it and the external client
/// uploads it. Only pull (materialize) + conflict-sibling detection are active.
///
/// Callers run this inside `spawn_blocking` (see the call sites): the macOS
/// `ensure_materialized` can poll for up to ~10s on an evicted file, which must
/// not stall the async runtime. The common open-in-place case (file present)
/// returns instantly.
fn folder_pre_open(app: &tauri::AppHandle, vault_path: &str) {
    use tauri::Manager;
    let Ok(dir) = app.path().app_config_dir() else { return };
    if let crate::sync_config::SyncTarget::Folder { path } = crate::sync_config::load(&dir, vault_path) {
        let _ = crate::icloud_macos::ensure_materialized(std::path::Path::new(&path));
    }
}

/// Records a successfully opened vault. Best-effort: a failure here must never
/// break opening. Stores paths and timestamps only — never passwords.
fn push_recent(app: &tauri::AppHandle, path: &str, has_keyfile: bool) {
    use tauri::Manager;
    let Ok(dir) = app.path().app_config_dir() else { return };
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let file = dir.join("recent.json");
    let mut items: Vec<RecentFileRaw> = std::fs::read_to_string(&file)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    items.retain(|r| r.path != path);
    items.insert(
        0,
        RecentFileRaw {
            path: path.to_string(),
            last_opened: kokos_core::db::now_unix(),
            has_keyfile,
        },
    );
    items.truncate(10);
    if let Ok(json) = serde_json::to_string(&items) {
        let _ = std::fs::write(file, json);
    }
}

/// Write-through of the open-tab set (paths + active) to `settings.json`, so
/// the tab manager can restore them LOCKED on next launch. Paths only — a
/// key/password/derived material must NEVER reach this file.
///
/// Best-effort: called after every registry mutation that changes the open
/// set or the active id (create/open/unlock/close/switch — never on a plain
/// lock, which doesn't change either). A save failure here must never fail
/// the calling command, so every fallible step just bails out silently.
///
/// Lock discipline: locks `sessions`, snapshots into locals, DROPS that guard
/// (end of the block below), THEN locks `settings`. The two guards are never
/// held at once — same rule `hibp_check` follows by locking them separately —
/// which keeps lock ordering safe against any other command that might lock
/// them in the other order.
///
/// Removes `id` from the restored-but-not-yet-unlocked set the first time its
/// vault enters the registry (open/create/unlock/keychain/fast-unlock). After
/// this, the path lives in the registry, so `persist_open_vaults` no longer
/// needs the union to keep it — and a later `close_vault` correctly drops it
/// instead of it being resurrected as still-locked. No-op if `id`
/// was never a restored tab (a freshly created/opened vault).
fn mark_restored_unlocked(state: &AppState, id: &str) {
    if let Ok(mut set) = state.restored_locked.lock() {
        set.retain(|p| p != id);
    }
}

/// Pure ordering merge for `persist_open_vaults`: produces the
/// `open_vaults` list to persist WITHOUT pruning restored-but-never-unlocked
/// tabs. `skeleton` is the desired order source (the previously-persisted list
/// for a normal persist, or the frontend's full `ordered_ids` for a reorder);
/// `reg_paths` are the currently registry-backed (opened-this-session) tabs;
/// `restored` are the paths restored at launch that have NOT yet been unlocked
/// (so they are absent from the registry, see `AppState::restored_locked`).
///
/// A path survives only if it is in `reg_paths ∪ restored`. This is what lets a
/// partial unlock keep the still-locked tabs (they are in `restored`) while a
/// tab that was unlocked-then-closed is dropped (removed from `restored` at
/// unlock, gone from `reg_paths` at close, so in neither set — no resurrection).
/// Order: `skeleton` order first (stable tab positions), then any newly-opened
/// `reg_paths` not in the skeleton, then any leftover `restored` (defensive —
/// `restored ⊆ skeleton` by construction, but never drop data).
fn merge_open_vaults(skeleton: &[String], reg_paths: &[String], restored: &[String]) -> Vec<String> {
    let keep: std::collections::HashSet<&String> = reg_paths.iter().chain(restored.iter()).collect();
    let mut seen: std::collections::HashSet<&String> = std::collections::HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for p in skeleton.iter() {
        if keep.contains(p) && seen.insert(p) {
            out.push(p.clone());
        }
    }
    for p in reg_paths.iter() {
        if seen.insert(p) {
            out.push(p.clone());
        }
    }
    for p in restored.iter() {
        if seen.insert(p) {
            out.push(p.clone());
        }
    }
    out
}

/// Records an onboarding fact, mirroring `persist_open_vaults`' discipline:
/// resolve the config dir, take the settings lock briefly, write, release.
/// Every failure is swallowed — the export or import that triggered this has
/// already succeeded and must not be reported as failed.
fn mark_onboarding(app: &tauri::AppHandle, state: &AppState, fact: crate::settings::OnboardingFact) {
    use tauri::Manager;
    let Ok(dir) = app.path().app_config_dir() else { return };
    let Ok(mut settings) = state.settings.lock() else { return };
    let _ = crate::settings::mark_done(&dir, &mut settings, fact);
}

/// Persists the open-tab set. Registry paths are filtered to MEANINGFULLY-open
/// entries (`vault.is_some() || last_path.is_some()`): `close_vault`'s
/// deferred-close (see its comment) can leave a stale, empty entry — `vault=None
/// && last_path=None` — lingering in `open_paths()` when a close lands while the
/// vault is on loan to another in-flight command. Persisting that raw would
/// restore a just-closed vault as an open tab on next launch. The filter still
/// keeps a locked-but-remembered tab (`vault=None`, `last_path=Some`) — that one
/// must be restored locked, not dropped.
///
/// The filtered registry set is then UNIONed (via `merge_open_vaults`) with
/// `restored_locked` — tabs restored at launch and not yet unlocked, which never
/// enter the registry. Without this a partial unlock (unlock A of a restored
/// [A,B,C]) would persist `[A]` and prune B and C from the next launch's restore
fn persist_open_vaults(app: &tauri::AppHandle, state: &AppState) {
    persist_open_vaults_inner(app, state, None);
}

/// Shared body for `persist_open_vaults` and `reorder_vaults`. `order_override`
/// supplies the ordering skeleton when the caller owns the authoritative full
/// tab order: `reorder_vaults` passes the frontend's `ordered_ids`, which —
/// unlike the registry — includes still-locked restored tab positions. `None`
/// uses the previously persisted order so tab positions stay stable across a
/// partial unlock. `active_vault` is only persisted when it survives into the
/// merged set.
fn persist_open_vaults_inner(app: &tauri::AppHandle, state: &AppState, order_override: Option<&[String]>) {
    use tauri::Manager;
    let (reg_paths, reg_active) = {
        let Ok(reg) = state.sessions.lock() else { return };
        let reg_paths: Vec<String> = reg
            .open_paths()
            .into_iter()
            .filter(|id| reg.get(id).map(|s| s.vault.is_some() || s.last_path.is_some()).unwrap_or(false))
            .collect();
        let reg_active = reg.active_id().filter(|id| reg_paths.iter().any(|p| p == id)).map(str::to_string);
        (reg_paths, reg_active)
    };
    let restored = state.restored_locked.lock().map(|g| g.clone()).unwrap_or_default();
    let Ok(dir) = app.path().app_config_dir() else { return };
    let Ok(mut settings) = state.settings.lock() else { return };
    let skeleton: Vec<String> = match order_override {
        Some(o) => o.to_vec(),
        None => settings.open_vaults.clone(),
    };
    let merged = merge_open_vaults(&skeleton, &reg_paths, &restored);
    let active = reg_active
        .or_else(|| settings.active_vault.clone())
        .filter(|a| merged.iter().any(|p| p == a));
    settings.open_vaults = merged;
    settings.active_vault = active;
    let _ = crate::settings::save(&dir, &settings);
}

/// Async, unlike a naive plain-`fn` command: `vault::save` serializes the
/// whole decrypted database, encrypts the whole image, and does two
/// `fsync`s — real disk I/O that must not run inline on the webview dispatch
/// thread, the same rule that applies to the KDF-heavy commands (see the
/// module doc comment). Uses the same `begin_borrow`/`end_borrow` discipline
/// as `change_master_password`: the vault has to leave the session for the
/// `spawn_blocking` call, and a `lock_vault`/`close_vault` landing in that
/// window must not be silently undone once the save finishes.
#[tauri::command]
pub async fn save_vault(state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or("no vault is open")?;
        (vid, v)
    };

    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let result = vault::save(&mut v);
        (v, result)
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);

    result.map_err(|e| e.to_string())
}

/// Async, unlike a naive plain-`fn`: an audit "lock" row must be appended AND
/// saved while the vault is still present, BEFORE the key is dropped --
/// `Session::lock()` itself never saves (kokos_core::session module doc), so
/// skipping this would silently lose the audit row on every manual lock. That
/// save is the same heavy serialize+encrypt+2-fsync as `save_vault`, so it
/// runs in `spawn_blocking` via the same begin_borrow/end_borrow hand-off.
///
/// If the vault is on loan to another in-flight `spawn_blocking` mutation,
/// `begin_borrow` returns `None` -- that window is rare (kokos_core::session
/// doc), and there is nothing to audit here, so this just requests the lock,
/// which `end_borrow` honors once the other call finishes.
#[tauri::command]
pub async fn lock_vault(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    vault_id: Option<String>,
) -> CmdResult<()> {
    use tauri::Emitter;
    let id = {
        let reg = state.sessions.lock().map_err(|e| e.to_string())?;
        reg.resolve(vault_id.as_deref()).map(str::to_string)
    };
    let borrowed = match &id {
        Some(id) => {
            let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
            reg.get_mut(id).and_then(|s| s.begin_borrow())
        }
        None => None,
    };
    if let Some(mut v) = borrowed {
        let target = id.clone().expect("borrowed is only Some when id is Some");
        let app_g = app.clone();
        let (v, push_inputs) = tauri::async_runtime::spawn_blocking(move || {
            let _ = kokos_core::audit::append(&v.conn, "lock", None);
            let _ = vault::save(&mut v);
            let pi = gather_gdrive_auto_push(&app_g, &v);
            (v, pi)
        })
        .await
        .map_err(spawn_blocking_failed)?;
        {
            let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
            if let Some(s) = reg.get_mut(&target) {
                s.end_borrow(v);
                s.lock();
            }
        }
        crate::nmh::invalidate_confirms(&app);
        if let Some((vp, meta, bytes)) = push_inputs {
            let app2 = app.clone();
            let _ = tauri::async_runtime::spawn_blocking(move || {
                let _ = gdrive_sync_gathered(&app2, &vp, &meta, &bytes, PullMode::Skip);
            })
            .await;
        }
    } else {
        if let Some(id) = &id {
            let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
            reg.lock_one(id);
        }
        crate::nmh::invalidate_confirms(&app);
    }
    let _ = app.emit("vault-locked", serde_json::json!({ "vault_id": id }));
    Ok(())
}

/// Sibling of `lock_vault` with no `vault_id` -- always ALL. A plain (non-
/// `async`) command: Tauri already dispatches these on its own blocking
/// thread pool (see `vault_status` elsewhere in this file), so the inline
/// audit+save loop below never risks freezing the webview despite not going
/// through `spawn_blocking` itself. Always emits `{ vault_id: null }`, the
/// same "everyone locked" shape the idle-lock watcher uses.
#[tauri::command]
pub fn lock_all(app: tauri::AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    use tauri::Emitter;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    for s in reg.iter_mut() {
        if let Some(v) = s.vault.as_mut() {
            let _ = kokos_core::audit::append(&v.conn, "lock", None);
            let _ = vault::save(v);
        }
    }
    reg.lock_all();
    drop(reg);
    let _ = app.emit("vault-locked", serde_json::json!({ "vault_id": null }));
    crate::nmh::invalidate_confirms(&app);
    Ok(())
}

#[tauri::command]
pub async fn unlock_vault(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    password: String,
    keyfile_path: Option<String>,
) -> CmdResult<VaultInfo> {
    use tauri::{Emitter, Manager};
    ensure_keyfile_allowed(&state.allowed_paths, keyfile_path.as_deref())?;
    let (id, path) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let id = reg.active_id().ok_or("nothing to unlock")?.to_string();
        let s = reg.get_mut(&id).ok_or("nothing to unlock")?;
        ensure_no_vault_open(s)?;
        let path = s.last_path.clone().ok_or("nothing to unlock")?;
        (id, path)
    };
    let path_str = path.to_string_lossy().to_string();
    let cfg_dir = app.path().app_config_dir().ok();
    let pw = Zeroizing::new(password.into_bytes());

    {
        let app = app.clone();
        let vp = path_str.clone();
        let _ = tauri::async_runtime::spawn_blocking(move || folder_pre_open(&app, &vp)).await;
    }

    let opened = tauri::async_runtime::spawn_blocking(move || {
        vault::open(&path, &pw, keyfile_path.as_ref().map(PathBuf::from).as_deref())
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let mut v = match opened {
        Ok(v) => v,
        Err(e) => {
            record_open_failure(cfg_dir.as_deref(), &path_str, &e);
            return Err(explain_vault_error(&e, &path_str, crate::nmh::snap::instance_name().as_deref()));
        }
    };

    let n = cfg_dir.as_ref().map(|dir| crate::auth_failures::take(dir, &path_str)).unwrap_or(0);
    let detail = (n > 0).then(|| format!("{n} failed attempts since last success"));

    let vdir = ai_cleanup_dir(&app);
    let v = tauri::async_runtime::spawn_blocking(move || {
        let _ = kokos_core::audit::append(&v.conn, "unlock", detail.as_deref());
        let _ = vault::save_opened(&mut v);
        if let Some(vdir) = &vdir {
            prune_orphan_vectors_blocking(&v, vdir);
        }
        v
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let result = info(&v)?;
    {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let s = reg.get_mut(&id).ok_or("nothing to unlock")?;
        ensure_no_vault_open(s)?;
        s.vault = Some(v);
        s.last_path = None;
        s.last_header = None;
    }
    *state.last_activity.lock().map_err(|e| e.to_string())? = std::time::Instant::now();
    let _ = app.emit("vault-unlocked", serde_json::json!({ "vault_id": id }));
    persist_open_vaults(&app, &state);
    Ok(result)
}

#[tauri::command]
pub async fn close_vault(app: tauri::AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    let push_inputs = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        reg.active_mut()
            .and_then(|s| s.vault.as_ref().and_then(|v| gather_gdrive_auto_push(&app, v)))
    };
    if let Some((vp, meta, bytes)) = push_inputs {
        let app2 = app.clone();
        let _ = tauri::async_runtime::spawn_blocking(move || {
            let _ = gdrive_sync_gathered(&app2, &vp, &meta, &bytes, PullMode::Skip);
        })
        .await;
    }
    {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(id) = reg.active_id().map(str::to_string) {
            if let Some(s) = reg.get_mut(&id) {
                s.close();
                if !s.is_open_or_borrowed() {
                    reg.remove(&id);
                }
            }
        }
    }
    persist_open_vaults(&app, &state);
    crate::nmh::invalidate_confirms(&app);
    Ok(())
}

/// Switches the active tab without touching lock
/// state — `vault_id` must already be a known session (open or locked); an
/// unknown id fails closed with `"no_vault"` rather than silently no-op'ing.
/// Persists the new active id (best-effort) so a restart reopens with the
/// same tab focused.
#[tauri::command]
pub fn switch_vault(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: String) -> CmdResult<()> {
    {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if !reg.set_active(&vault_id) {
            return Err("no_vault".into());
        }
    }
    persist_open_vaults(&app, &state);
    crate::nmh::invalidate_confirms(&app);
    Ok(())
}

/// Reorder the open-vault tabs (browser-style drag reorder). The
/// frontend sends the FULL visible order — including still-locked restored tabs
/// the registry cannot represent (`reg.reorder` ignores unknown ids). We reorder
/// the registry for internal consistency, then persist using `ordered_ids` as
/// the authoritative ordering skeleton so locked-tab positions survive too.
///
/// Persisting `ordered_ids` directly (rather than the registry-derived list) is
/// what makes an all-locked reorder correct: `merge_open_vaults` filters
/// `ordered_ids` to the live set (`reg ∪ restored_locked`), so it can no longer
/// clobber `open_vaults` to empty — which is why no `if changed` gate is
/// needed to guard that empty-registry-reorder case. Unlike `switch_vault` this
/// does NOT change the active vault, so no `invalidate_confirms` is needed
/// (order != selection).
#[tauri::command]
pub fn reorder_vaults(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    ordered_ids: Vec<String>,
) -> CmdResult<()> {
    {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        reg.reorder(&ordered_ids);
    }
    persist_open_vaults_inner(&app, &state, Some(&ordered_ids));
    Ok(())
}

/// Read-only session snapshot for the frontend to reconcile after a WebView
/// reload (Cmd+R / Vite HMR / crash), where the UI resets to "no vault" while
/// the backend still holds the open vault + key.
#[tauri::command]
pub fn vault_status(state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<StatusInfo> {
    let reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let Some(id) = reg.resolve(vault_id.as_deref()).map(str::to_string) else {
        return Ok(StatusInfo { open: false, locked: false, path: None, hint: None, migrated: false });
    };
    let s = reg.get(&id).expect("resolve() only returns a contained id");
    if let Some(v) = &s.vault {
        return Ok(StatusInfo {
            open: true,
            locked: false,
            path: Some(v.path.to_string_lossy().to_string()),
            hint: Some(v.header.hint.clone()),
            migrated: v.migrated,
        });
    }
    if let Some((p, h)) = s.borrow_identity() {
        let locked = s.is_locked();
        return Ok(StatusInfo {
            open: !locked,
            locked,
            path: Some(p.to_string_lossy().to_string()),
            hint: Some(h.hint.clone()),
            migrated: false,
        });
    }
    Ok(StatusInfo {
        open: false,
        locked: s.is_locked(),
        path: s.last_path.as_ref().map(|p| p.to_string_lossy().to_string()),
        hint: s.last_header.as_ref().map(|h| h.hint.clone()),
        migrated: false,
    })
}

/// The Keychain operations a password change implies for the two stored
/// fast-unlock copies. Pure so the branch logic is unit-tested
/// without touching the OS (biometric_macos has no mock backend).
struct ReconcileOps {
    store_keyring: bool,
    store_biometric: bool,
    delete_keyring: bool,
    delete_biometric: bool,
}

/// Decide what to do with the stored copies after a successful re-key.
/// - key file now required -> the copies (password-only) can never open the
///   vault again, so delete both.
/// - password-only -> keep convenience alive: rewrite each copy that EXISTS
///   with the new password (Touch ID survives a rotation, no re-enroll).
fn plan_reconcile(requires_keyfile: bool, has_keyring: bool, has_biometric: bool) -> ReconcileOps {
    if requires_keyfile {
        ReconcileOps { store_keyring: false, store_biometric: false, delete_keyring: true, delete_biometric: true }
    } else {
        ReconcileOps { store_keyring: has_keyring, store_biometric: has_biometric, delete_keyring: false, delete_biometric: false }
    }
}

/// Thin executor: read the live presence flags, plan, then dispatch. Every
/// call is best-effort — the re-key already succeeded, so a Keychain error
/// here must not surface as a password-change failure.
fn reconcile_fast_unlock(path: &str, new_pw: &str, requires_keyfile: bool) {
    let ops = plan_reconcile(
        requires_keyfile,
        crate::keyring_store::has(path),
        crate::biometric_macos::has_biometric(path),
    );
    if ops.delete_keyring {
        let _ = crate::keyring_store::delete(path);
    }
    if ops.delete_biometric {
        let _ = crate::biometric_macos::delete_biometric(path);
    }
    if ops.store_keyring {
        let _ = crate::keyring_store::store(path, new_pw);
    }
    if ops.store_biometric {
        let _ = crate::biometric_macos::store_biometric(path, new_pw);
    }
}

/// Whether a rotation changed the vault's key file, as opposed to merely
/// re-supplying the existing one.
///
/// `Set` and `Resupply` are mechanically identical to kokos-core — both
/// produce `KeyfileAction::Set` — but they differ in user intent, and the
/// audit log records intent. A key-file vault cannot rotate its password
/// with `Keep` (core rejects it), so the master-password form has to
/// re-supply the current file; inferring "the key file changed" from the
/// enum variant alone would file a rotation the user never performed.
///
/// Pure so this decision is unit-tested directly: this repo has no
/// `AppHandle`/MockRuntime harness, so a decision left inside a
/// `#[tauri::command]` body would otherwise be untestable by construction.
fn keyfile_was_changed(action: &KeyfileActionDto) -> bool {
    matches!(action, KeyfileActionDto::Set { .. } | KeyfileActionDto::Remove)
}

/// Async + spawn_blocking, not a plain `fn`: `vault::change_password` always
/// calls `crypto::derive_key` (Argon2, 1-3 s) to derive the replacement key, so it is
/// bound by the same "KDF never runs on the async/UI-facing thread" rule as
/// create_vault/open_vault/unlock_vault. The vault has to leave the session for the
/// duration of the blocking call — a live `&mut OpenVault` can't be moved into a 'static
/// spawn_blocking closure, and a std MutexGuard can't be held across an .await point,
/// since it is not Send — so it goes out via `Session::begin_borrow` and comes back via
/// `Session::end_borrow`, never a bare `take()`/assignment: a plain `s.vault = Some(v)`
/// after the await would blindly resurrect the vault even if `lock_vault`/`close_vault`
/// ran while this was in flight and found nothing to act on. `end_borrow` restores `v`
/// unless a lock/close landed while it was out, in which case it honors that instead of
/// restoring (see kokos_core::session).
///
/// Restoring `v` when nothing was requested — including on failure — is not cosmetic:
/// kokos_core's own doc comment on `change_password` guarantees `v` is left byte-for-byte
/// usable with the old credentials if any step fails, so losing the open vault on a failed
/// password change would be a regression, not just a missed optimization.
#[tauri::command]
pub async fn change_master_password(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    new_password: String,
    new_hint: Option<String>,
    keyfile: KeyfileActionDto,
) -> CmdResult<()> {
    if let KeyfileActionDto::Set { path } | KeyfileActionDto::Resupply { path } = &keyfile {
        ensure_keyfile_allowed(&state.allowed_paths, Some(path))?;
    }
    let pw_for_reconcile = Zeroizing::new(new_password.clone());
    let pw = Zeroizing::new(new_password.into_bytes());
    let keyfile_changed = keyfile_was_changed(&keyfile);
    let action = match keyfile {
        KeyfileActionDto::Keep => KeyfileAction::Keep,
        KeyfileActionDto::Set { path } => KeyfileAction::Set(PathBuf::from(path)),
        KeyfileActionDto::Resupply { path } => KeyfileAction::Set(PathBuf::from(path)),
        KeyfileActionDto::Remove => KeyfileAction::Remove,
    };

    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or("no vault is open")?;
        (vid, v)
    };

    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let result = vault::change_password(&mut v, &pw, new_hint.as_deref(), action);
        if result.is_ok() {
            let _ = kokos_core::audit::append(&v.conn, "master_password_changed", None);
            if keyfile_changed {
                let _ = kokos_core::audit::append(&v.conn, "keyfile_changed", None);
            }
            let _ = vault::save(&mut v);
        }
        (v, result)
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let reconcile = if result.is_ok() {
        Some((v.path.to_string_lossy().to_string(), v.header.requires_keyfile()))
    } else {
        None
    };

    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);

    if let Some((path, requires_keyfile)) = reconcile {
        reconcile_fast_unlock(&path, &pw_for_reconcile, requires_keyfile);
    }

    result.map_err(|e| e.to_string())
}

/// Verify the current master password (+ the current key file, if the open
/// vault uses one) WITHOUT re-keying — the frontend gate in front of
/// `change_master_password`, since an open session is otherwise the only
/// authorization for rotating credentials. Runs Argon2 (1-3 s) off the UI
/// thread via the same begin_borrow/end_borrow hand-off as
/// `change_master_password`; verify never mutates the vault, so `end_borrow`
/// restores it byte-identical. Returns a plain bool — the password never
/// crosses back (secret boundary).
#[tauri::command]
pub async fn verify_password(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    password: String,
    keyfile_path: Option<String>,
) -> CmdResult<bool> {
    ensure_keyfile_allowed(&state.allowed_paths, keyfile_path.as_deref())?;
    let pw = Zeroizing::new(password.into_bytes());
    let keyfile = keyfile_path.map(PathBuf::from);

    let (vid, v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or("no vault is open")?;
        (vid, v)
    };

    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let r = vault::verify_password(&v, &pw, keyfile.as_deref());
        (v, r)
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);

    result.map_err(|e| e.to_string())
}

/// Rewrite the vault's plaintext header hint (`""` removes it).
///
/// Async + `spawn_blocking` like its neighbours, though this one is cheap:
/// `vault::set_hint` derives no key, so there is no Argon2 cost — but it does
/// serialize and re-write the whole container, which still does not belong on
/// the UI thread.
///
/// Not gated behind `verify_password`, unlike `change_master_password` and the
/// key-file rotation. The hint is a plaintext label in the header, readable by
/// anyone holding the vault file; it is not a credential, so a password gate
/// would cost a full Argon2 round-trip while protecting nothing. An open vault
/// is the authorization. The `hint_changed` audit row below is what makes a
/// quiet edit visible after the fact.
#[tauri::command]
pub async fn set_vault_hint(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    hint: String,
) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or("no vault is open")?;
        (vid, v)
    };

    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let result = vault::set_hint(&mut v, &hint);
        if result.is_ok() {
            let _ = kokos_core::audit::append(&v.conn, "hint_changed", None);
            let _ = vault::save(&mut v);
        }
        (v, result)
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);

    result.map_err(|e| e.to_string())
}

/// Recent files live in the app config, never in the container, and hold no
/// passwords.
#[tauri::command]
pub fn recent_files(app: tauri::AppHandle, state: State<'_, AppState>) -> CmdResult<Vec<RecentFile>> {
    use tauri::Manager;
    let path = app
        .path()
        .app_config_dir()
        .map_err(|e| e.to_string())?
        .join("recent.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let items: Vec<RecentFileRaw> = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    for r in &items {
        crate::paths::allow(&state.allowed_paths, &r.path);
    }
    Ok(items
        .into_iter()
        .map(|r| RecentFile { path: r.path, last_opened: r.last_opened, has_keyfile: r.has_keyfile })
        .collect())
}

/// True when `path` names a vault the app already knows -- an open or locked
/// tab, or an entry in the recent-files list. Export destinations must never
/// be one: `recent_files` adds every recent vault to the shared path
/// allowlist (for opening), so without this check a caller could pass another
/// vault's file as an export destination and have it truncated or replaced.
/// Fails closed: a destination that cannot be resolved counts as known.
fn is_known_vault_path(app: &tauri::AppHandle, state: &AppState, path: &str) -> bool {
    use tauri::Manager;
    let Ok(dest) = crate::paths::normalise(std::path::Path::new(path)) else {
        return true;
    };
    let mut known: Vec<String> = state
        .sessions
        .lock()
        .map(|reg| reg.open_paths())
        .unwrap_or_default();
    if let Ok(dir) = app.path().app_config_dir() {
        if let Ok(raw) = std::fs::read_to_string(dir.join("recent.json")) {
            if let Ok(items) = serde_json::from_str::<Vec<RecentFileRaw>>(&raw) {
                known.extend(items.into_iter().map(|r| r.path));
            }
        }
    }
    known.iter().any(|p| {
        crate::paths::normalise(std::path::Path::new(p))
            .map(|c| c == dest)
            .unwrap_or(false)
    })
}

#[derive(Serialize, Deserialize)]
struct RecentFileRaw {
    path: String,
    last_opened: i64,
    has_keyfile: bool,
}

/// Native open/save dialog, driven entirely from Rust. rfd's
/// AsyncFileDialog dispatches to the main thread itself and resolves back on
/// the tokio worker. The chosen path is added
/// to the allowlist so a subsequent open_vault/create_vault accepts it.
/// Save mode also seeds the dialog with `vault_dir::default_save_dir`, which is
/// `~/Documents` — and `$SNAP_REAL_HOME/Documents` under snap, because snapd
/// remaps `$HOME` into a revision-scoped tree that `snap remove` deletes.
#[tauri::command]
pub async fn pick_vault_path(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    mode: String,
) -> CmdResult<Option<String>> {
    let dialog = rfd::AsyncFileDialog::new().add_filter("Kokos vault", &["kokos", "vault"]);
    let handle = match mode.as_str() {
        "save" => {
            let dialog = match crate::vault_dir::default_save_dir(&app) {
                Some(dir) => dialog.set_directory(dir),
                None => dialog,
            };
            dialog.set_file_name("passwords.kokos").save_file().await
        }
        _ => dialog.pick_file().await,
    };
    let Some(h) = handle else { return Ok(None) };
    let raw = h.path().to_string_lossy().to_string();
    crate::paths::allow(&state.allowed_paths, &raw);
    Ok(Some(raw))
}

/// The string the UI shows for a failed open/create. Everything keeps its own
/// `VaultError` message except the permission case, which on its own says only
/// "permission denied for this file" — true, useless, and most likely to be
/// hit by a snap user whose vault sits in a hidden folder the sandbox cannot
/// see. `snap` is `nmh::snap::instance_name()`, injected so this is testable
/// without a snap.
///
/// Wired at three call sites: `create_vault`, `open_vault`, `unlock_vault`.
/// The fast-unlock pair, `keychain_unlock` and `touchid_unlock`, deliberately
/// still map their `VaultError` with a bare `.to_string()`. `keychain_unlock`
/// reads a Secret Service item, which a strictly confined snap cannot reach —
/// `packaging/snap/snapcraft.yaml` declares no `password-manager-service`
/// plug — so the keychain affordance is not expected to come up there in the
/// first place. `touchid_unlock` is macOS-only in effect (`biometric_macos`'s
/// non-macOS twin is a stub), and snap does not exist on macOS, so the
/// snap-flavoured explanation this function adds would never fire for it
/// either way. Neither omission needs fixing; both are recorded here so the
/// gap reads as a choice, not an oversight.
fn explain_vault_error(e: &VaultError, path: &str, snap: Option<&str>) -> String {
    match e {
        VaultError::PermissionDenied => crate::vault_dir::explain_permission_denied(path, snap),
        other => other.to_string(),
    }
}

/// Whether a failed open should raise the failed-attempt counter. The counter
/// exists to surface "someone was guessing at your vault" on the next
/// successful open (see `auth_failures`).
///
/// Excludes only `PermissionDenied`: a refusal at the OS level means the app
/// never even read the file, so counting it would invent a failed attempt
/// out of an error the vault's own key derivation never saw. Every other
/// variant still counts, including several that are *also* returned before a
/// password is ever checked — `NotAVaultFile`, `HeaderMalformed`,
/// `UnsupportedVersion`, `KdfParamsTooExpensive` (all from
/// `kokos_core::format::header::Header::parse`/`validate`) and generic `Io` —
/// so "never read the file" is a stronger guarantee than this predicate
/// actually provides. Narrowing it further to cover those too is a real gap,
/// left alone here deliberately; do not widen this predicate as part of some
/// other, unrelated change.
///
/// One gap this predicate cannot see at all: `kokos_core::keyfile::key_material`
/// maps any io error on the key file — including a permission refusal — to
/// `KeyfileUnreadable`, bypassing `From<io::Error>` entirely. A key file in a
/// hidden folder under snap therefore still bumps the counter and shows the
/// generic "key file cannot be read" message instead of an explained one.
fn counts_as_failed_attempt(e: &VaultError) -> bool {
    !matches!(e, VaultError::PermissionDenied)
}

/// Bumps the failed-attempt counter for `path`, unless `e` is exempt (see
/// `counts_as_failed_attempt`). Shared by `open_vault` and `unlock_vault`'s
/// error arms, which otherwise repeated this exact guard almost verbatim.
///
/// Wrong password/keyfile and a corrupt file both collapse to the same
/// oracle-safe `VaultError::InvalidCredentialsOrCorrupt` (no oracle) — see the
/// comment at each call site for why that specific merge matters there.
fn record_open_failure(cfg_dir: Option<&Path>, path: &str, e: &VaultError) {
    if !counts_as_failed_attempt(e) {
        return;
    }
    if let Some(dir) = cfg_dir {
        crate::auth_failures::bump(dir, path);
    }
}

fn view_from(s: &str) -> View {
    match s {
        "favorites" => View::Favorites,
        "recent" => View::Recent,
        _ => View::All,
    }
}

fn to_field_dto(f: entries::Field) -> FieldDto {
    FieldDto {
        id: f.id,
        template_id: f.template_id,
        name: f.name,
        value: f.value,
        is_protected: f.is_protected,
        field_type: f.field_type,
        sort_order: f.sort_order,
        strength: f.strength,
    }
}

/// Shared by `get_entry`/`create_entry`/`update_entry`, which all resolve to
/// a `kokos_core::entries::Entry` and previously repeated this exact field
/// mapping inline three times.
impl From<entries::Entry> for EntryDto {
    fn from(e: entries::Entry) -> Self {
        EntryDto {
            id: e.id,
            folder_id: e.folder_id,
            title: e.title,
            notes: e.notes,
            is_favorite: e.is_favorite,
            created_at: e.created_at,
            updated_at: e.updated_at,
            fields: e.fields.into_iter().map(to_field_dto).collect(),
            tags: e.tags.into_iter().map(to_tag_ref_dto).collect(),
            entry_type: e.entry_type,
        }
    }
}

/// Read-only: borrows the session briefly, no spawn_blocking needed.
#[tauri::command]
pub fn list_entries(state: State<'_, AppState>, vault_id: Option<String>, view: String) -> CmdResult<Vec<EntrySummaryDto>> {
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
    let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
    let rows = entries::list(&v.conn, view_from(&view)).map_err(|e| e.to_string())?;
    Ok(rows.into_iter().map(to_summary_dto).collect())
}

#[derive(Serialize)]
pub struct WeakFieldDto {
    pub entry_id: String,
    pub title: String,
    pub field_name: String,
    pub strength: u8,
}
#[derive(Serialize)]
pub struct HealthEntryRefDto {
    pub entry_id: String,
    pub title: String,
}
#[derive(Serialize)]
pub struct ReusedGroupDto {
    pub count: u32,
    pub entries: Vec<HealthEntryRefDto>,
}
#[derive(Serialize)]
pub struct HealthReportDto {
    pub weak: Vec<WeakFieldDto>,
    pub reused: Vec<ReusedGroupDto>,
}

impl From<kokos_core::health::HealthReport> for HealthReportDto {
    fn from(r: kokos_core::health::HealthReport) -> Self {
        HealthReportDto {
            weak: r.weak.into_iter().map(|w| WeakFieldDto {
                entry_id: w.entry_id, title: w.title, field_name: w.field_name, strength: w.strength,
            }).collect(),
            reused: r.reused.into_iter().map(|g| ReusedGroupDto {
                count: g.count,
                entries: g.entries.into_iter().map(|e| HealthEntryRefDto {
                    entry_id: e.entry_id, title: e.title,
                }).collect(),
            }).collect(),
        }
    }
}

/// Read-only: brief session borrow, no spawn_blocking, no save.
#[tauri::command]
pub fn health_scan(state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<HealthReportDto> {
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
    let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
    let report = kokos_core::health::scan(&v.conn).map_err(|e| e.to_string())?;
    Ok(report.into())
}

#[derive(Serialize)]
pub struct CompromisedFieldDto {
    pub entry_id: String,
    pub title: String,
    pub field_name: String,
    pub count: u32,
}

/// `checked` = a network check completed. `offline` = the network was
/// unreachable (distinct "couldn't check" state, not an error). `enabled` =
/// the opt-in flag at call time (a disabled call returns early, no network).
#[derive(Serialize)]
pub struct HibpReportDto {
    pub compromised: Vec<CompromisedFieldDto>,
    pub checked: bool,
    pub offline: bool,
    pub enabled: bool,
}

/// Check every in-scope secret against HIBP via k-anonymity. Off-by-default:
/// returns `{enabled:false}` with no scan and no network when disabled. The
/// egress boundary: `scan_queries` keeps plaintext + full hash inside core and
/// hands back queries whose suffix is private; ONLY the 5-char prefix (built
/// by `hibp::range_url`) ever leaves this process. Offline → `{offline:true}`.
#[tauri::command]
pub async fn hibp_check(state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<HibpReportDto> {
    let enabled = state.settings.lock().map_err(|e| e.to_string())?.hibp_enabled;
    if !enabled {
        return Ok(HibpReportDto { compromised: vec![], checked: false, offline: false, enabled: false });
    }

    let queries = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let id = resolve_vault_id(&reg, vault_id.as_deref())?;
        let s = reg.get_mut(&id).ok_or_else(|| "no_vault".to_string())?;
        let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
        kokos_core::hibp::scan_queries(&v.conn).map_err(|e| e.to_string())?
    };
    if queries.is_empty() {
        return Ok(HibpReportDto { compromised: vec![], checked: true, offline: false, enabled: true });
    }

    let need: Vec<String> = {
        let cache = state.hibp_cache.lock().map_err(|e| e.to_string())?;
        let mut seen = std::collections::BTreeSet::new();
        queries
            .iter()
            .map(|q| q.prefix.clone())
            .filter(|p| !cache.contains_key(p) && seen.insert(p.clone()))
            .collect()
    };

    if !need.is_empty() {
        let fetched = tauri::async_runtime::spawn_blocking(move || fetch_ranges(&need))
            .await
            .map_err(spawn_blocking_failed)?;
        match fetched {
            Ok(map) => {
                let mut cache = state.hibp_cache.lock().map_err(|e| e.to_string())?;
                cache.extend(map);
            }
            Err(_) => {
                return Ok(HibpReportDto { compromised: vec![], checked: false, offline: true, enabled: true });
            }
        }
    }

    let cache = state.hibp_cache.lock().map_err(|e| e.to_string())?;
    let mut compromised = Vec::new();
    for q in &queries {
        if let Some(body) = cache.get(&q.prefix) {
            if let Some(count) = q.match_in(body) {
                compromised.push(CompromisedFieldDto {
                    entry_id: q.entry_id.clone(),
                    title: q.title.clone(),
                    field_name: q.field_name.clone(),
                    count,
                });
            }
        }
    }
    Ok(HibpReportDto { compromised, checked: true, offline: false, enabled: true })
}

/// Blocking GET of each prefix range. `prefix → body`, or `Err` on the first
/// transport failure (mapped to the offline state upstream). `Add-Padding`
/// asks HIBP to pad the response so an observer cannot infer a hit from its
/// size. The URL carries ONLY the 5-char prefix (`hibp::range_url`).
fn fetch_ranges(prefixes: &[String]) -> Result<std::collections::HashMap<String, String>, String> {
    let client = hibp_client();
    let mut out = std::collections::HashMap::new();
    for p in prefixes {
        let url = kokos_core::hibp::range_url(p).ok_or_else(|| format!("invalid prefix {p}"))?;
        let resp = client
            .get(url)
            .header("Add-Padding", "true")
            .send()
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("status {}", resp.status()));
        }
        out.insert(p.clone(), resp.text().map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// Mirrors `gdrive::api::client` (connect 10s / timeout 60s / rustls).
fn hibp_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new())
}

/// Nested payload → stays snake_case both sides (serde default, no rename), so
/// the JS object { folder_id, tag_id, favorites_only, regex } deserializes
/// straight into this and then into the core filter.
#[derive(Deserialize, Default)]
pub struct SearchFilters {
    #[serde(default)] pub folder_id: Option<String>,
    #[serde(default)] pub tag_id: Option<String>,
    #[serde(default)] pub favorites_only: bool,
    #[serde(default)] pub regex: bool,
}

fn to_summary_dto(r: entries::EntrySummary) -> EntrySummaryDto {
    EntrySummaryDto {
        id: r.id,
        title: r.title,
        username: r.username,
        is_favorite: r.is_favorite,
        has_totp: r.has_totp,
        has_attachments: r.has_attachments,
        updated_at: r.updated_at,
        folder_id: r.folder_id,
        tags: r.tags.into_iter().map(to_tag_ref_dto).collect(),
        entry_type: r.entry_type,
        password_field_id: r.password_field_id,
    }
}

/// Read-only: brief session borrow, no spawn_blocking, no save.
#[tauri::command]
pub fn search_entries(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    query: String,
    filters: SearchFilters,
) -> CmdResult<Vec<EntrySummaryDto>> {
    let core = kokos_core::search::SearchFilters {
        folder_id: filters.folder_id,
        tag_id: filters.tag_id,
        favorites_only: filters.favorites_only,
        regex: filters.regex,
    };
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
    let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
    let rows = if core.regex {
        kokos_core::search::search_regex(&v.conn, &query, &core)
    } else {
        kokos_core::search::search(&v.conn, &query, &core)
    }
    .map_err(|e| e.to_string())?;
    Ok(rows.into_iter().map(to_summary_dto).collect())
}

/// Minimum cosine similarity for a semantic "Related" hit. Tuned for the default
/// `mid`/MiniLM model (dev benchmark ΔEN +0.267 / ΔRU +0.178); tune with real
/// GUI use. Below this, semantic results are noise and are dropped.
const SEMANTIC_MIN_SCORE: f32 = 0.35;

#[derive(Serialize)]
pub struct SemanticHitDto {
    pub entry: EntrySummaryDto,
    pub score: f32,
}

/// Query-embedding semantic search over the active vault's encrypted vector
/// sidecar. Read-only and FAIL-SOFT: every degrade path — AI disabled,
/// no engine loaded, no vault open, empty/undecryptable index — returns an empty
/// list, never an error, so the caller's exact search stays untouched. Mirrors
/// `search_entries`' brief synchronous session borrow; the query embed runs on
/// the command worker thread (like the substring scan), not the async runtime.
#[tauri::command]
pub fn ai_semantic_search(
    app: AppHandle,
    state: State<'_, AppState>,
    vault_id: Option<String>,
    query: String,
    limit: usize,
) -> CmdResult<Vec<SemanticHitDto>> {
    let engine = state.ai_embedder.lock().map_err(|e| e.to_string())?.clone();
    let Some(engine) = engine else {
        return Ok(Vec::new());
    };
    let q = query.trim();
    if q.is_empty() {
        return Ok(Vec::new());
    }
    let qv = engine.embedder.embed(q).map_err(|e| e.to_string())?;

    let vdir = crate::ai::vectors_dir(&app)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let Ok(vid) = resolve_vault_id(&reg, vault_id.as_deref()) else {
        return Ok(Vec::new());
    };
    let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
    let Some(v) = s.vault.as_ref() else {
        return Ok(Vec::new());
    };

    let vault_id_str = kokos_core::db::get_device_id(&v.conn).map_err(|e| e.to_string())?;
    let subkey = kokos_core::crypto::derive_subkey(&v.key, crate::ai::SUBKEY_LABEL);
    let path = kokos_ai::store::store_path(&vdir, &vault_id_str);
    let store = kokos_ai::store::load(&path, &subkey, &engine.model_id, engine.dim);

    let hits = kokos_ai::search::top_k(&qv, &store, limit, SEMANTIC_MIN_SCORE);
    if hits.is_empty() {
        return Ok(Vec::new());
    }
    let summaries =
        kokos_core::entries::list(&v.conn, kokos_core::entries::View::All).map_err(|e| e.to_string())?;
    let mut by_id: std::collections::HashMap<String, entries::EntrySummary> =
        summaries.into_iter().map(|row| (row.id.clone(), row)).collect();
    let out = hits
        .into_iter()
        .filter_map(|(id, score)| by_id.remove(&id).map(|row| SemanticHitDto { entry: to_summary_dto(row), score }))
        .collect();
    Ok(out)
}

/// Folder-suggestion cosine floor for the active `mid`/MiniLM model. Below this
/// a folder is not a meaningful neighbour and is dropped. Tunable with real
/// GUI use (same rationale as `SEMANTIC_MIN_SCORE`).
const SUGGEST_MIN_SCORE: f32 = 0.35;

const ORGANIZE_EXISTING_MIN: f32 = 0.45;
const ORGANIZE_CLUSTER_MIN: f32 = 0.55;
const ORGANIZE_MIN_CLUSTER: usize = 2;
const ORGANIZE_DOMAIN_FRACTION: f32 = 0.5;

#[derive(Serialize)]
pub struct OrganizeEntryDto {
    pub entry_id: String,
    pub title: String,
    pub score: f32,
}

#[derive(Serialize)]
pub struct OrganizeGroupDto {
    pub kind: String,
    pub folder_id: Option<String>,
    pub name: String,
    pub score: f32,
    pub entries: Vec<OrganizeEntryDto>,
}

#[derive(Serialize)]
pub struct OrganizeProposalDto {
    pub groups: Vec<OrganizeGroupDto>,
}

/// Cosine of two UNIT vectors (== dot). Length mismatch -> 0.0 (stale dim).
fn cosine_unit(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// Pure proposal assembly — NO IO. Given existing-folder centroids, folder
/// display names, and the unfiled entries (each already embedded), produce the
/// grouped proposal: strong existing matches first, then greedily-clustered
/// new-folder groups (heuristic-seeded names). Kept pure so it is unit-testable
/// without a Tauri harness (the command wraps IO/embeds around it).
fn assemble_proposal(
    centroids: &std::collections::HashMap<String, Vec<f32>>,
    folder_names: &std::collections::HashMap<String, String>,
    unfiled: Vec<(String, kokos_ai::meta::EmbeddingMetadata, Vec<f32>)>,
    dim: usize,
) -> OrganizeProposalDto {
    use std::collections::HashMap;

    let mut existing: HashMap<String, Vec<(String, String, f32)>> = HashMap::new();
    let mut leftovers: Vec<(String, kokos_ai::meta::EmbeddingMetadata, Vec<f32>)> = Vec::new();
    for (id, meta, vec) in unfiled {
        let ranked = kokos_ai::categorize::rank_candidates(&vec, centroids, 1, ORGANIZE_EXISTING_MIN);
        match ranked.into_iter().next() {
            Some((fid, score)) => existing.entry(fid).or_default().push((id, meta.title.clone(), score)),
            None => leftovers.push((id, meta, vec)),
        }
    }

    let mut groups: Vec<OrganizeGroupDto> = Vec::new();

    let mut existing_groups: Vec<OrganizeGroupDto> = existing
        .into_iter()
        .map(|(fid, mut items)| {
            items.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
            let score = items.iter().map(|i| i.2).sum::<f32>() / items.len() as f32;
            let name = folder_names.get(&fid).cloned().unwrap_or_default();
            let entries = items
                .into_iter()
                .map(|(entry_id, title, s)| OrganizeEntryDto { entry_id, title, score: s })
                .collect();
            OrganizeGroupDto { kind: "existing".into(), folder_id: Some(fid), name, score, entries }
        })
        .collect();
    existing_groups.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    groups.append(&mut existing_groups);

    let items: Vec<(String, Vec<f32>)> = leftovers.iter().map(|(id, _, v)| (id.clone(), v.clone())).collect();
    let clusters = kokos_ai::categorize::cluster_greedy(&items, ORGANIZE_CLUSTER_MIN, ORGANIZE_MIN_CLUSTER);
    let by_id: HashMap<&str, &(String, kokos_ai::meta::EmbeddingMetadata, Vec<f32>)> =
        leftovers.iter().map(|t| (t.0.as_str(), t)).collect();

    let mut new_groups: Vec<OrganizeGroupDto> = Vec::new();
    for cluster in clusters {
        let mut vecs: Vec<&[f32]> = Vec::new();
        let mut naming: Vec<kokos_ai::categorize::NamingInput> = Vec::new();
        let mut rows: Vec<(String, String)> = Vec::new();
        for id in &cluster {
            if let Some((_, meta, vec)) = by_id.get(id.as_str()) {
                vecs.push(vec.as_slice());
                naming.push(kokos_ai::categorize::NamingInput {
                    title: meta.title.clone(),
                    domain: meta.url_domain.clone(),
                    tags: meta.tag_names.clone(),
                });
                rows.push((id.clone(), meta.title.clone()));
            }
        }
        let Some(cen) = kokos_ai::categorize::centroid(&vecs, dim) else { continue };
        let rep_idx = vecs
            .iter()
            .enumerate()
            .map(|(i, v)| (i, cosine_unit(v, &cen)))
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
            .unwrap_or(0);
        let (name, _src) = kokos_ai::categorize::seed_folder_name(&naming, rep_idx, ORGANIZE_DOMAIN_FRACTION);
        let entries: Vec<OrganizeEntryDto> = rows
            .iter()
            .enumerate()
            .map(|(i, (entry_id, title))| OrganizeEntryDto {
                entry_id: entry_id.clone(),
                title: title.clone(),
                score: cosine_unit(vecs[i], &cen),
            })
            .collect();
        let score = if entries.is_empty() {
            0.0
        } else {
            entries.iter().map(|e| e.score).sum::<f32>() / entries.len() as f32
        };
        new_groups.push(OrganizeGroupDto { kind: "new".into(), folder_id: None, name, score, entries });
    }
    new_groups.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    groups.append(&mut new_groups);

    OrganizeProposalDto { groups }
}

/// Batch "organize unfiled" — propose an existing OR a new folder for each
/// unfiled (folder `root`/none) entry. Read-only; fail-soft empty on AI off /
/// nothing unfiled / not indexed / vault busy. Collects under the sessions
/// lock, DROPS it, then embeds (no embed under lock). Naming + embed inputs
/// flow ONLY through `metadata_from_entry` -> `EmbeddingMetadata` (whitelist).
#[tauri::command]
pub fn ai_organize_unfiled(
    app: AppHandle,
    state: State<'_, AppState>,
    vault_id: Option<String>,
) -> CmdResult<OrganizeProposalDto> {
    use std::collections::HashMap;
    let empty = || OrganizeProposalDto { groups: Vec::new() };

    let engine = state.ai_embedder.lock().map_err(|e| e.to_string())?.clone();
    let Some(engine) = engine else { return Ok(empty()) };
    let dim = engine.dim as usize;
    let vdir = crate::ai::vectors_dir(&app)?;

    struct Unfiled {
        id: String,
        meta: kokos_ai::meta::EmbeddingMetadata,
        vec: Option<Vec<f32>>,
    }
    let (mut centroids, cold_folders, mut unfiled, folder_names): (
        HashMap<String, Vec<f32>>,
        Vec<(String, String)>,
        Vec<Unfiled>,
        HashMap<String, String>,
    ) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let Ok(vid) = resolve_vault_id(&reg, vault_id.as_deref()) else { return Ok(empty()) };
        let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
        let Some(v) = s.vault.as_ref() else { return Ok(empty()) };

        let vault_dev = kokos_core::db::get_device_id(&v.conn).map_err(|e| e.to_string())?;
        let subkey = kokos_core::crypto::derive_subkey(&v.key, crate::ai::SUBKEY_LABEL);
        let path = kokos_ai::store::store_path(&vdir, &vault_dev);
        let store = kokos_ai::store::load(&path, &subkey, &engine.model_id, engine.dim);

        let folder_names = kokos_ai::meta::folder_names(&v.conn).map_err(|e| e.to_string())?;
        let summaries = kokos_core::entries::list(&v.conn, kokos_core::entries::View::All).map_err(|e| e.to_string())?;

        let is_unfiled = |f: &Option<String>| f.is_none() || f.as_deref() == Some("root");

        let mut members: HashMap<String, Vec<Vec<f32>>> = HashMap::new();
        for sm in &summaries {
            if is_unfiled(&sm.folder_id) { continue; }
            let Some(fid) = sm.folder_id.clone() else { continue };
            if !folder_names.contains_key(&fid) { continue; }
            if let Some(rec) = store.records.get(&sm.id) {
                members.entry(fid).or_default().push(rec.vec.clone());
            }
        }
        let mut centroids: HashMap<String, Vec<f32>> = HashMap::new();
        for (fid, vecs) in &members {
            let refs: Vec<&[f32]> = vecs.iter().map(|v| v.as_slice()).collect();
            if let Some(c) = kokos_ai::categorize::centroid(&refs, dim) {
                centroids.insert(fid.clone(), c);
            }
        }
        let cold_folders: Vec<(String, String)> = folder_names
            .iter()
            .filter(|(fid, _)| !centroids.contains_key(*fid))
            .map(|(fid, name)| (fid.clone(), name.clone()))
            .collect();

        let mut unfiled: Vec<Unfiled> = Vec::new();
        for sm in &summaries {
            if !is_unfiled(&sm.folder_id) { continue; }
            let Some(entry) = kokos_core::entries::get(&v.conn, &sm.id).map_err(|e| e.to_string())? else { continue };
            let meta = kokos_ai::meta::metadata_from_entry(&entry, None);
            let vec = store.records.get(&sm.id).map(|r| r.vec.clone());
            unfiled.push(Unfiled { id: sm.id.clone(), meta, vec });
        }

        (centroids, cold_folders, unfiled, folder_names)
    };

    if unfiled.is_empty() {
        return Ok(empty());
    }

    for (fid, name) in cold_folders {
        match engine.embedder.embed(&name) {
            Ok(v) => { centroids.insert(fid, v); }
            Err(e) => eprintln!("[ai] organize: cold folder embed skipped for {fid}: {e}"),
        }
    }
    for u in unfiled.iter_mut() {
        if u.vec.is_none() {
            let input = kokos_ai::meta::embedding_input(&u.meta);
            match engine.embedder.embed(&input) {
                Ok(v) => u.vec = Some(v),
                Err(e) => eprintln!("[ai] organize: cold entry embed skipped for {}: {e}", u.id),
            }
        }
    }
    let unfiled: Vec<(String, kokos_ai::meta::EmbeddingMetadata, Vec<f32>)> = unfiled
        .into_iter()
        .filter_map(|u| u.vec.map(|v| (u.id, u.meta, v)))
        .collect();
    if unfiled.is_empty() {
        return Ok(empty());
    }

    Ok(assemble_proposal(&centroids, &folder_names, unfiled, dim))
}

#[derive(Deserialize)]
pub struct OrganizeApplyGroup {
    pub folder_id: Option<String>,
    pub new_folder_name: Option<String>,
    pub entry_ids: Vec<String>,
}

/// Apply an accepted organize proposal under ONE vault borrow: create each new
/// folder (parent `root`), move its entries, then reembed every moved entry
/// (folder is part of the embedding input — `bulk_move_entries` does NOT
/// reembed; mirror `update_entry`). Not wrapped in an outer transaction:
/// `entries::update` opens its own `unchecked_transaction`, which cannot nest;
/// all changes persist only at the single `vault::save`, so an error before
/// save leaves the on-disk vault untouched.
#[tauri::command]
pub async fn ai_apply_organize(
    app: AppHandle,
    state: State<'_, AppState>,
    vault_id: Option<String>,
    groups: Vec<OrganizeApplyGroup>,
) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };

    let ai = if state.settings.lock().map_err(|e| e.to_string())?.ai_enabled {
        match (
            state.ai_embedder.lock().map_err(|e| e.to_string())?.clone(),
            crate::ai::vectors_dir(&app),
        ) {
            (Some(engine), Ok(vdir)) => Some((engine, vdir)),
            _ => None,
        }
    } else {
        None
    };

    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let mut moved: Vec<String> = Vec::new();
        let outcome = (|| -> Result<(), kokos_core::error::VaultError> {
            for g in &groups {
                let target = match (&g.folder_id, &g.new_folder_name) {
                    (Some(fid), _) => fid.clone(),
                    (None, Some(name)) => {
                        let name = name.trim();
                        if name.is_empty() {
                            continue;
                        }
                        kokos_core::folders::create(&v.conn, name, Some("root"), now)?.id
                    }
                    (None, None) => continue,
                };
                for id in &g.entry_ids {
                    kokos_core::entries::update(
                        &v.conn,
                        id,
                        kokos_core::entries::EntryPatch {
                            title: None,
                            notes: None,
                            is_favorite: None,
                            folder_id: Some(target.clone()),
                            fields: None,
                        },
                        now,
                    )?;
                    moved.push(id.clone());
                }
            }
            vault::save(&mut v)?;
            Ok(())
        })();
        if outcome.is_ok() {
            if let Some((engine, vdir)) = &ai {
                for id in &moved {
                    crate::ai::reembed_entry_blocking(&v, engine, id, vdir);
                }
            }
        }
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct FolderSuggestionDto {
    pub folder_id: String,
    pub name: String,
    pub score: f32,
}

/// A rankable bucket (a folder or a tag). `name` is whitelist-safe display
/// text that doubles as the cold-start embedding input when the bucket has no
/// indexed members; `color` is carried through to the tag DTO (always `None`
/// for folders).
#[derive(Clone)]
struct Candidate {
    name: String,
    color: Option<String>,
}

/// Where `suggest_by_centroid` gets its TARGET vector. `Entry` = an existing
/// entry (indexed record if present, else an on-demand embed of the stored
/// entry's whitelist metadata). `Draft` = an
/// entry being composed in the editor that has no id and no indexed vector yet
/// the caller has already reduced it to a whitelist `EmbeddingMetadata`
/// (title • url_domain • entry_type — no folder/tag context), which is embedded
/// directly. Both routes embed ONLY through `meta::embedding_input`.
enum TargetSource {
    Entry(String),
    Draft(kokos_ai::meta::EmbeddingMetadata),
}

/// Shared spine for `ai_suggest_folders`/`ai_suggest_tags` and their
/// `_for_draft` variants: rank candidate buckets by cosine(target vector,
/// bucket centroid) over the vector sidecar. Read-only and FAIL-SOFT — every
/// degrade (AI off, no engine, no vault, empty index, entry gone, no
/// candidates) returns `Ok(vec![])`. Every embed runs THROUGH
/// `meta::embedding_input` (target) or on a candidate NAME (both whitelist-safe);
/// no raw field reaches the model. All connection reads are collected UNDER the
/// sessions lock, which is then DROPPED before any embed (matches
/// `ai_semantic_search`), so an on-demand embed never blocks other vault ops.
///
/// `target` selects the vector source (an existing entry, or a pre-whitelisted
/// draft meta). `build_candidates(conn, entry, folder_names)` yields
/// `id -> Candidate` with all exclusions already applied; `entry` is `Some` only
/// on the `Entry` path (a draft has no entry to exclude against), and
/// `folder_names` is the shared `folder_id -> name` map (computed once here).
/// `entry_keys(summary)` yields which candidate buckets a live entry's vector
/// feeds (folders: its single non-root folder; tags: each of its tag ids).
fn suggest_by_centroid<C, K>(
    app: &tauri::AppHandle,
    state: &State<'_, AppState>,
    vault_id: Option<String>,
    target: TargetSource,
    limit: usize,
    min_score: f32,
    build_candidates: C,
    entry_keys: K,
) -> CmdResult<Vec<(String, Candidate, f32)>>
where
    C: FnOnce(
        &rusqlite::Connection,
        Option<&kokos_core::entries::Entry>,
        &std::collections::HashMap<String, String>,
    ) -> Result<std::collections::HashMap<String, Candidate>, String>,
    K: Fn(&kokos_core::entries::EntrySummary) -> Vec<String>,
{
    use std::collections::HashMap;

    let engine = state.ai_embedder.lock().map_err(|e| e.to_string())?.clone();
    let Some(engine) = engine else { return Ok(Vec::new()) };
    let dim = engine.dim as usize;
    let vdir = crate::ai::vectors_dir(app)?;

    let skip_id: Option<String> = match &target {
        TargetSource::Entry(id) => Some(id.clone()),
        TargetSource::Draft(_) => None,
    };

    let (target_rec, target_input, ready_centroids, cold, candidates): (
        Option<Vec<f32>>,
        Option<String>,
        HashMap<String, Vec<f32>>,
        Vec<(String, String)>,
        HashMap<String, Candidate>,
    ) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let Ok(vid) = resolve_vault_id(&reg, vault_id.as_deref()) else {
            return Ok(Vec::new());
        };
        let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
        let Some(v) = s.vault.as_ref() else { return Ok(Vec::new()) };

        let fnames = kokos_ai::meta::folder_names(&v.conn).map_err(|e| e.to_string())?;

        let entry_opt: Option<kokos_core::entries::Entry> = match &target {
            TargetSource::Entry(id) => {
                let Some(e) =
                    kokos_core::entries::get(&v.conn, id).map_err(|e| e.to_string())?
                else {
                    return Ok(Vec::new());
                };
                Some(e)
            }
            TargetSource::Draft(_) => None,
        };

        let candidates = build_candidates(&v.conn, entry_opt.as_ref(), &fnames)?;
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        let vault_id_str = kokos_core::db::get_device_id(&v.conn).map_err(|e| e.to_string())?;
        let subkey = kokos_core::crypto::derive_subkey(&v.key, crate::ai::SUBKEY_LABEL);
        let path = kokos_ai::store::store_path(&vdir, &vault_id_str);
        let store = kokos_ai::store::load(&path, &subkey, &engine.model_id, engine.dim);

        let (target_rec, target_input) = match &target {
            TargetSource::Entry(id) => match store.records.get(id.as_str()) {
                Some(rec) => (Some(rec.vec.clone()), None),
                None => {
                    let entry = entry_opt.as_ref().expect("Entry path read the entry above");
                    let fname = entry
                        .folder_id
                        .as_deref()
                        .and_then(|fid| fnames.get(fid))
                        .map(String::as_str);
                    let meta = kokos_ai::meta::metadata_from_entry(entry, fname);
                    (None, Some(kokos_ai::meta::embedding_input(&meta)))
                }
            },
            TargetSource::Draft(meta) => (None, Some(kokos_ai::meta::embedding_input(meta))),
        };

        let summaries = kokos_core::entries::list(&v.conn, kokos_core::entries::View::All)
            .map_err(|e| e.to_string())?;
        let mut keys_by_entry: HashMap<String, Vec<String>> = HashMap::new();
        for sm in &summaries {
            keys_by_entry.insert(sm.id.clone(), entry_keys(sm));
        }
        let mut members: HashMap<String, Vec<Vec<f32>>> = HashMap::new();
        for (eid, rec) in &store.records {
            if Some(eid.as_str()) == skip_id.as_deref() {
                continue;
            }
            let Some(keys) = keys_by_entry.get(eid) else { continue };
            for key in keys {
                if candidates.contains_key(key) {
                    members.entry(key.clone()).or_default().push(rec.vec.clone());
                }
            }
        }

        let mut ready_centroids: HashMap<String, Vec<f32>> = HashMap::new();
        let mut cold: Vec<(String, String)> = Vec::new();
        for (id, cand) in &candidates {
            let c = members.get(id).and_then(|vs| {
                let refs: Vec<&[f32]> = vs.iter().map(|v| v.as_slice()).collect();
                kokos_ai::categorize::centroid(&refs, dim)
            });
            match c {
                Some(v) => {
                    ready_centroids.insert(id.clone(), v);
                }
                None => cold.push((id.clone(), cand.name.clone())),
            }
        }

        (target_rec, target_input, ready_centroids, cold, candidates)
    };

    let target_vec = match target_rec {
        Some(v) => v,
        None => match target_input {
            Some(input) => engine.embedder.embed(&input).map_err(|e| e.to_string())?,
            None => return Ok(Vec::new()),
        },
    };

    let mut centroids = ready_centroids;
    for (id, name) in cold {
        match engine.embedder.embed(&name) {
            Ok(v) => {
                centroids.insert(id, v);
            }
            Err(e) => eprintln!("[ai] suggest: candidate-name embed skipped for {id}: {e}"),
        }
    }

    let ranked = kokos_ai::categorize::rank_candidates(&target_vec, &centroids, limit, min_score);
    let out = ranked
        .into_iter()
        .filter_map(|(id, score)| candidates.get(&id).map(|c| (id.clone(), c.clone(), score)))
        .collect();
    Ok(out)
}

#[derive(Serialize)]
pub struct TagSuggestionDto {
    pub tag_id: String,
    pub name: String,
    pub color: Option<String>,
    pub score: f32,
}

/// Suggest tags for an entry by semantic nearest-neighbour over the vector
/// sidecar. Read-only + FAIL-SOFT via `suggest_by_centroid`. Never
/// mutates — applying is the frontend's explicit `add_entry_tag`.
#[tauri::command]
pub fn ai_suggest_tags(
    app: AppHandle,
    state: State<'_, AppState>,
    vault_id: Option<String>,
    entry_id: String,
    limit: usize,
) -> CmdResult<Vec<TagSuggestionDto>> {
    let ranked = suggest_by_centroid(
        &app,
        &state,
        vault_id,
        TargetSource::Entry(entry_id),
        limit,
        SUGGEST_MIN_SCORE,
        |conn, entry, _fnames| {
            let Some(target) = entry else { return Ok(std::collections::HashMap::new()) };
            let existing: std::collections::HashSet<&str> =
                target.tags.iter().map(|t| t.id.as_str()).collect();
            let tags = kokos_core::tags::list(conn).map_err(|e| e.to_string())?;
            Ok(tags
                .into_iter()
                .filter(|t| !existing.contains(t.id.as_str()))
                .map(|t| (t.id, Candidate { name: t.name, color: t.color }))
                .collect())
        },
        |sm| sm.tags.iter().map(|t| t.id.clone()).collect(),
    )?;
    Ok(ranked
        .into_iter()
        .map(|(tag_id, cand, score)| TagSuggestionDto {
            tag_id,
            name: cand.name,
            color: cand.color,
            score,
        })
        .collect())
}

/// Suggest folders for an entry by semantic nearest-neighbour over the vector
/// sidecar. Read-only and FAIL-SOFT via `suggest_by_centroid`:
/// every degrade path — AI off, no engine, no vault, empty/undecryptable
/// index, entry gone — returns `Ok(vec![])`, never an error. NEVER mutates:
/// applying a suggestion is the frontend's explicit `update_entry`.
#[tauri::command]
pub fn ai_suggest_folders(
    app: AppHandle,
    state: State<'_, AppState>,
    vault_id: Option<String>,
    entry_id: String,
    limit: usize,
) -> CmdResult<Vec<FolderSuggestionDto>> {
    let ranked = suggest_by_centroid(
        &app,
        &state,
        vault_id,
        TargetSource::Entry(entry_id),
        limit,
        SUGGEST_MIN_SCORE,
        |_conn, entry, fnames| {
            let Some(target) = entry else { return Ok(std::collections::HashMap::new()) };
            let current =
                target.folder_id.as_deref().filter(|f| *f != "root").map(str::to_string);
            Ok(fnames
                .iter()
                .filter(|(fid, _)| current.as_deref() != Some(fid.as_str()))
                .map(|(fid, name)| (fid.clone(), Candidate { name: name.clone(), color: None }))
                .collect())
        },
        |sm| {
            sm.folder_id
                .iter()
                .filter(|f| f.as_str() != "root")
                .cloned()
                .collect()
        },
    )?;
    Ok(ranked
        .into_iter()
        .map(|(folder_id, cand, score)| FolderSuggestionDto { folder_id, name: cand.name, score })
        .collect())
}

/// Suggest folders for a DRAFT entry being composed in the editor —
/// there is no entry id / indexed vector yet. Builds a whitelist target from
/// the draft's `title`/`url`/`entry_type` ONLY (no folder context, to avoid
/// biasing the folder suggestion toward a pre-picked folder) and ranks ALL
/// real folders. Read-only + FAIL-SOFT via `suggest_by_centroid`.
#[tauri::command]
pub fn ai_suggest_folders_for_draft(
    app: AppHandle,
    state: State<'_, AppState>,
    vault_id: Option<String>,
    title: String,
    url: String,
    entry_type: String,
    limit: usize,
) -> CmdResult<Vec<FolderSuggestionDto>> {
    let meta = kokos_ai::meta::metadata_from_draft(&title, &url, &entry_type);
    let ranked = suggest_by_centroid(
        &app,
        &state,
        vault_id,
        TargetSource::Draft(meta),
        limit,
        SUGGEST_MIN_SCORE,
        |_conn, _entry, fnames| {
            Ok(fnames
                .iter()
                .map(|(fid, name)| (fid.clone(), Candidate { name: name.clone(), color: None }))
                .collect())
        },
        |sm| {
            sm.folder_id
                .iter()
                .filter(|f| f.as_str() != "root")
                .cloned()
                .collect()
        },
    )?;
    Ok(ranked
        .into_iter()
        .map(|(folder_id, cand, score)| FolderSuggestionDto { folder_id, name: cand.name, score })
        .collect())
}

/// Suggest tags for a DRAFT entry being composed in the editor.
/// Whitelist target from the draft's `title`/`url`/`entry_type`; ranks ALL tags
/// (a draft has no existing tags to exclude; favorite already hidden by
/// `tags::list`). Read-only + FAIL-SOFT via `suggest_by_centroid`.
#[tauri::command]
pub fn ai_suggest_tags_for_draft(
    app: AppHandle,
    state: State<'_, AppState>,
    vault_id: Option<String>,
    title: String,
    url: String,
    entry_type: String,
    limit: usize,
) -> CmdResult<Vec<TagSuggestionDto>> {
    let meta = kokos_ai::meta::metadata_from_draft(&title, &url, &entry_type);
    let ranked = suggest_by_centroid(
        &app,
        &state,
        vault_id,
        TargetSource::Draft(meta),
        limit,
        SUGGEST_MIN_SCORE,
        |conn, _entry, _fnames| {
            let tags = kokos_core::tags::list(conn).map_err(|e| e.to_string())?;
            Ok(tags
                .into_iter()
                .map(|t| (t.id, Candidate { name: t.name, color: t.color }))
                .collect())
        },
        |sm| sm.tags.iter().map(|t| t.id.clone()).collect(),
    )?;
    Ok(ranked
        .into_iter()
        .map(|(tag_id, cand, score)| TagSuggestionDto {
            tag_id,
            name: cand.name,
            color: cand.color,
            score,
        })
        .collect())
}

#[derive(Deserialize)]
pub struct GenOptsDto {
    pub length: usize,
    pub upper: bool, pub lower: bool, pub digits: bool, pub symbols: bool,
    #[serde(default)] pub min_upper: usize,
    #[serde(default)] pub min_lower: usize,
    #[serde(default)] pub min_digits: usize,
    #[serde(default)] pub min_symbols: usize,
}

/// Pure: no session, no save. Returns the generated password (leaves the
/// backend only as its final value, like reveal_field).
#[tauri::command]
pub fn generate_password(opts: GenOptsDto) -> CmdResult<String> {
    let o = kokos_core::generator::GenOpts {
        length: opts.length, upper: opts.upper, lower: opts.lower, digits: opts.digits, symbols: opts.symbols,
        min_upper: opts.min_upper, min_lower: opts.min_lower, min_digits: opts.min_digits, min_symbols: opts.min_symbols,
    };
    kokos_core::generator::generate(&o).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_entry(state: State<'_, AppState>, vault_id: Option<String>, id: String) -> CmdResult<EntryDto> {
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
    let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
    let e = entries::get(&v.conn, &id)
        .map_err(|e| e.to_string())?
        .ok_or(VaultError::EntryNotFound.to_string())?;
    Ok(e.into())
}

#[derive(Deserialize)]
pub struct NewFieldDto {
    pub template_id: Option<String>,
    pub name: String,
    pub value: Option<String>,
    pub is_protected: bool,
    pub field_type: String,
}

impl From<NewFieldDto> for entries::NewField {
    fn from(d: NewFieldDto) -> Self {
        entries::NewField {
            template_id: d.template_id,
            name: d.name,
            value: d.value,
            is_protected: d.is_protected,
            field_type: d.field_type,
        }
    }
}

#[derive(Deserialize)]
pub struct NewEntryDto {
    pub title: String,
    pub folder_id: Option<String>,
    pub notes: Option<String>,
    pub entry_type: String,
    pub fields: Vec<NewFieldDto>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FieldValueDto { Keep, Set { value: String }, Clear }

#[derive(Deserialize)]
pub struct FieldInputDto {
    pub id: Option<String>,
    pub template_id: Option<String>,
    pub name: String,
    pub is_protected: bool,
    pub field_type: String,
    pub value: FieldValueDto,
}
impl From<FieldValueDto> for entries::FieldValue {
    fn from(d: FieldValueDto) -> Self {
        match d {
            FieldValueDto::Keep => entries::FieldValue::Keep,
            FieldValueDto::Set { value } => entries::FieldValue::Set(value),
            FieldValueDto::Clear => entries::FieldValue::Clear,
        }
    }
}
impl From<FieldInputDto> for entries::FieldInput {
    fn from(d: FieldInputDto) -> Self {
        entries::FieldInput {
            id: d.id, template_id: d.template_id, name: d.name,
            is_protected: d.is_protected, field_type: d.field_type, value: d.value.into(),
        }
    }
}

#[derive(Deserialize)]
pub struct EntryPatchDto {
    pub title: Option<String>,
    pub notes: Option<String>,
    pub is_favorite: Option<bool>,
    pub folder_id: Option<String>,
    pub fields: Option<Vec<FieldInputDto>>,
}

/// Runs the DB mutation AND the save together in spawn_blocking, under the
/// borrow discipline. On a save failure the change is already in memory; the
/// error propagates and the UI shows the save-failed banner — nothing is
/// silently lost.
#[tauri::command]
pub async fn create_entry(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: Option<String>, entry: NewEntryDto) -> CmdResult<EntryDto> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let entry_type = entry.entry_type;
    let fields: Vec<entries::NewField> = if entry.fields.is_empty() {
        entries::default_fields(&entry_type)
    } else {
        entry.fields.into_iter().map(Into::into).collect()
    };
    let new = entries::NewEntry {
        title: entry.title,
        folder_id: entry.folder_id,
        notes: entry.notes,
        entry_type,
        fields,
    };
    let ai = if state.settings.lock().map_err(|e| e.to_string())?.ai_enabled {
        match (state.ai_embedder.lock().map_err(|e| e.to_string())?.clone(), crate::ai::vectors_dir(&app)) {
            (Some(engine), Ok(vdir)) => Some((engine, vdir)),
            _ => None,
        }
    } else {
        None
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = entries::create(&v.conn, new, now).and_then(|created| {
            vault::save(&mut v)?;
            Ok(created)
        });
        if let (Ok(created), Some((engine, vdir))) = (&outcome, &ai) {
            crate::ai::reembed_entry_blocking(&v, engine, &created.id, vdir);
        }
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);

    let created = result.map_err(|e| e.to_string())?;
    Ok(created.into())
}

#[derive(Serialize)]
pub struct FieldSeedDto {
    pub template_id: Option<String>,
    pub name: String,
    pub value: Option<String>,
    pub is_protected: bool,
    pub field_type: String,
}

/// Pure: no session, no save. Returns the canonical default field set the
/// New-entry editor seeds for the given type. Unknown type → error (the UI
/// only ever sends one of the four built-ins).
#[tauri::command]
pub fn entry_type_default_fields(entry_type: String) -> CmdResult<Vec<FieldSeedDto>> {
    if !entries::is_valid_entry_type(&entry_type) {
        return Err("invalid_entry_type".to_string());
    }
    Ok(entries::default_fields(&entry_type)
        .into_iter()
        .map(|f| FieldSeedDto {
            template_id: f.template_id,
            name: f.name,
            value: f.value,
            is_protected: f.is_protected,
            field_type: f.field_type,
        })
        .collect())
}

/// Same borrow discipline as `create_entry` — see its doc comment.
/// `Ok(Some(e))` -> save then return `e`; `Ok(None)` -> `EntryNotFound`;
/// `Err` -> propagate without saving. `end_borrow` runs regardless of which
/// arm is taken, so a failed update never leaves the session borrowed.
#[tauri::command]
pub async fn update_entry(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    vault_id: Option<String>,
    id: String,
    patch: EntryPatchDto,
) -> CmdResult<EntryDto> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let p = entries::EntryPatch {
        title: patch.title,
        notes: patch.notes,
        is_favorite: patch.is_favorite,
        folder_id: patch.folder_id,
        fields: patch.fields.map(|fs| fs.into_iter().map(Into::into).collect()),
    };
    let ai = if state.settings.lock().map_err(|e| e.to_string())?.ai_enabled {
        match (state.ai_embedder.lock().map_err(|e| e.to_string())?.clone(), crate::ai::vectors_dir(&app)) {
            (Some(engine), Ok(vdir)) => Some((engine, vdir)),
            _ => None,
        }
    } else {
        None
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = match entries::update(&v.conn, &id, p, now) {
            Ok(Some(e)) => vault::save(&mut v).map(|_| e),
            Ok(None) => Err(VaultError::EntryNotFound),
            Err(e) => Err(e),
        };
        if let (Ok(e), Some((engine, vdir))) = (&outcome, &ai) {
            crate::ai::reembed_entry_blocking(&v, engine, &e.id, vdir);
        }
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);

    let e = result.map_err(|e| e.to_string())?;
    Ok(e.into())
}

/// Same borrow discipline as `create_entry` — see its doc comment.
/// `Ok(true)` -> save; `Ok(false)` -> `EntryNotFound`; `Err` -> propagate
/// without saving. `end_borrow` runs regardless of which arm is taken, so a
/// failed delete never leaves the session borrowed.
#[tauri::command]
pub async fn delete_entry(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: Option<String>, id: String) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let ai = if state.settings.lock().map_err(|e| e.to_string())?.ai_enabled {
        match (state.ai_embedder.lock().map_err(|e| e.to_string())?.clone(), crate::ai::vectors_dir(&app)) {
            (Some(engine), Ok(vdir)) => Some((engine, vdir)),
            _ => None,
        }
    } else {
        None
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = match entries::soft_delete(&v.conn, &id, now) {
            Ok(true) => vault::save(&mut v),
            Ok(false) => Err(VaultError::EntryNotFound),
            Err(e) => Err(e),
        };
        if outcome.is_ok() {
            if let Some((engine, vdir)) = &ai {
                crate::ai::remove_entry_vector_blocking(&v, engine, &id, vdir);
            }
        }
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);

    result.map_err(|e| e.to_string())
}

/// Disclosure policy for the raw `reveal_field` endpoint: only fields stored
/// as protected may cross the IPC boundary. Non-protected values already ship
/// in `get_entry`, so a raw read of them is never needed. OTP fields stay
/// allowed because they are protected and the editor's "Reveal to edit" must
/// read the seed to let the user change it; display goes through `totp_code`.
/// Pure so it is unit-testable.
fn reveal_allowed(is_protected: bool) -> bool {
    is_protected
}

/// Returns ONE protected field's value on explicit user action. Read-only,
/// so a brief session lock is enough — no spawn_blocking. Non-protected
/// fields are refused (see `reveal_allowed`).
#[tauri::command]
pub fn reveal_field(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    entry_id: String,
    field_id: String,
) -> CmdResult<String> {
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
    let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
    let entry = entries::get(&v.conn, &entry_id)
        .map_err(|e| e.to_string())?
        .ok_or(VaultError::EntryNotFound.to_string())?;
    let field = entry.fields.iter().find(|f| f.id == field_id)
        .ok_or(VaultError::EntryNotFound.to_string())?;
    if !reveal_allowed(field.is_protected) {
        return Err("field_not_protected".to_string());
    }
    entries::reveal_field(&v.conn, &entry_id, &field_id)
        .map_err(|e| e.to_string())?
        .ok_or(VaultError::EntryNotFound.to_string())
}

#[derive(Serialize)]
pub struct TotpCodeDto { pub code: String, pub remaining: u32, pub period: u32 }

/// Reads the otp field's secret IN CORE (never returns it), parses it, and
/// returns only the derived code + countdown. Time is taken here so core stays
/// pure/testable. Read-only: brief session lock, no spawn_blocking, no save.
#[tauri::command]
pub fn totp_code(state: State<'_, AppState>, vault_id: Option<String>, entry_id: String, field_id: String) -> CmdResult<TotpCodeDto> {
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
    let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
    let secret = zeroize::Zeroizing::new(
        entries::reveal_field(&v.conn, &entry_id, &field_id)
            .map_err(|e| e.to_string())?
            .ok_or(VaultError::EntryNotFound.to_string())?,
    );
    let params = kokos_core::totp::parse(&secret).map_err(|e| e.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    let c = kokos_core::totp::code_at(&params, now);
    Ok(TotpCodeDto { code: c.code, remaining: c.remaining, period: c.period })
}

#[derive(Serialize)]
pub struct FolderDto {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub sort_order: i32,
}

#[derive(Serialize)]
pub struct FolderNodeDto {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub sort_order: i32,
    pub entry_count: i64,
    pub children: Vec<FolderNodeDto>,
}

fn to_folder_dto(f: kokos_core::folders::Folder) -> FolderDto {
    FolderDto { id: f.id, parent_id: f.parent_id, name: f.name, sort_order: f.sort_order }
}

fn to_folder_node_dto(n: kokos_core::folders::FolderNode) -> FolderNodeDto {
    FolderNodeDto {
        id: n.folder.id,
        parent_id: n.folder.parent_id,
        name: n.folder.name,
        sort_order: n.folder.sort_order,
        entry_count: n.entry_count,
        children: n.children.into_iter().map(to_folder_node_dto).collect(),
    }
}

/// Read-only: borrows the session briefly, no spawn_blocking needed — same
/// shape as `list_entries`.
#[tauri::command]
pub fn list_folders(state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<Vec<FolderNodeDto>> {
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
    let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
    let tree = kokos_core::folders::list_tree(&v.conn).map_err(|e| e.to_string())?;
    Ok(tree.into_iter().map(to_folder_node_dto).collect())
}

/// Same borrow discipline as `create_entry` — see its doc comment.
#[tauri::command]
pub async fn create_folder(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    name: String,
    parent_id: Option<String>,
) -> CmdResult<FolderDto> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = kokos_core::folders::create(&v.conn, &name, parent_id.as_deref(), now)
            .and_then(|f| {
                vault::save(&mut v)?;
                Ok(f)
            });
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    Ok(to_folder_dto(result.map_err(|e| e.to_string())?))
}

/// Same borrow discipline as `create_entry` — see its doc comment.
#[tauri::command]
pub async fn rename_folder(state: State<'_, AppState>, vault_id: Option<String>, id: String, name: String) -> CmdResult<FolderDto> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = kokos_core::folders::rename(&v.conn, &id, &name, now)
            .and_then(|f| {
                vault::save(&mut v)?;
                Ok(f)
            });
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    Ok(to_folder_dto(result.map_err(|e| e.to_string())?))
}

/// Same borrow discipline as `create_entry` — see its doc comment.
#[tauri::command]
pub async fn move_folder(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    id: String,
    new_parent: Option<String>,
) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = kokos_core::folders::move_to(&v.conn, &id, new_parent.as_deref(), now)
            .and_then(|_| vault::save(&mut v));
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

/// Same borrow discipline as `create_entry` — see its doc comment. `place` is
/// the drop position "before"/"after" (a sibling reorder); "inside" drops nest
/// via `move_folder` instead, so they never reach here.
#[tauri::command]
pub async fn reorder_folder(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    id: String,
    target_id: String,
    place: String,
) -> CmdResult<()> {
    let placement = match place.as_str() {
        "before" => kokos_core::folders::Placement::Before,
        "after" => kokos_core::folders::Placement::After,
        other => return Err(format!("invalid placement: {other}")),
    };
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = kokos_core::folders::reorder(&v.conn, &id, &target_id, placement, now)
            .and_then(|_| vault::save(&mut v));
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

/// Same borrow discipline as `create_entry` — see its doc comment.
#[tauri::command]
pub async fn delete_folder(state: State<'_, AppState>, vault_id: Option<String>, id: String) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = kokos_core::folders::delete(&v.conn, &id, now).and_then(|_| vault::save(&mut v));
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct TagDto {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
    pub usage: i64,
}

fn to_tag_dto(t: kokos_core::tags::Tag) -> TagDto {
    TagDto { id: t.id, name: t.name, color: t.color, usage: t.usage }
}

/// Read-only: borrows the session briefly, no spawn_blocking needed — same
/// shape as `list_entries` and `list_folders`.
#[tauri::command]
pub fn list_tags(state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<Vec<TagDto>> {
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
    let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
    let tags = kokos_core::tags::list(&v.conn).map_err(|e| e.to_string())?;
    Ok(tags.into_iter().map(to_tag_dto).collect())
}

/// Same borrow discipline as `create_entry` — see its doc comment.
#[tauri::command]
pub async fn create_tag(state: State<'_, AppState>, vault_id: Option<String>, name: String, color: Option<String>) -> CmdResult<TagDto> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = kokos_core::tags::create(&v.conn, &name, color.as_deref())
            .and_then(|t| {
                vault::save(&mut v)?;
                Ok(t)
            });
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    Ok(to_tag_dto(result.map_err(|e| e.to_string())?))
}

/// Same borrow discipline as `create_entry` — see its doc comment.
#[tauri::command]
pub async fn rename_tag(state: State<'_, AppState>, vault_id: Option<String>, id: String, name: String) -> CmdResult<TagDto> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = kokos_core::tags::rename(&v.conn, &id, &name).and_then(|t| {
            vault::save(&mut v)?;
            Ok(t)
        });
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    Ok(to_tag_dto(result.map_err(|e| e.to_string())?))
}

/// Same borrow discipline as `create_entry` — see its doc comment.
#[tauri::command]
pub async fn recolor_tag(state: State<'_, AppState>, vault_id: Option<String>, id: String, color: Option<String>) -> CmdResult<TagDto> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = kokos_core::tags::recolor(&v.conn, &id, color.as_deref()).and_then(|t| {
            vault::save(&mut v)?;
            Ok(t)
        });
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    Ok(to_tag_dto(result.map_err(|e| e.to_string())?))
}

/// Same borrow discipline as `create_entry` — see its doc comment.
#[tauri::command]
pub async fn delete_tag(state: State<'_, AppState>, vault_id: Option<String>, id: String) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = kokos_core::tags::delete(&v.conn, &id).and_then(|_| vault::save(&mut v));
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct FieldTemplateDto {
    pub id: String,
    pub name: String,
    pub field_type: String,
    pub is_protected: bool,
    pub sort_order: i32,
    pub is_builtin: bool,
}

fn to_field_template_dto(t: kokos_core::templates::FieldTemplate) -> FieldTemplateDto {
    FieldTemplateDto {
        id: t.id,
        name: t.name,
        field_type: t.field_type,
        is_protected: t.is_protected,
        sort_order: t.sort_order,
        is_builtin: t.is_builtin,
    }
}

/// Read-only: borrows the session briefly, no spawn_blocking needed — same
/// shape as `list_entries` and `list_folders`.
#[tauri::command]
pub fn list_templates(state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<Vec<FieldTemplateDto>> {
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
    let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
    let templates = kokos_core::templates::list(&v.conn).map_err(|e| e.to_string())?;
    Ok(templates.into_iter().map(to_field_template_dto).collect())
}

/// Same borrow discipline as `create_entry` — see its doc comment.
#[tauri::command]
pub async fn create_template(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    name: String,
    field_type: String,
    is_protected: bool,
) -> CmdResult<FieldTemplateDto> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = kokos_core::templates::create(&v.conn, &name, &field_type, is_protected).and_then(|t| {
            vault::save(&mut v)?;
            Ok(t)
        });
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    Ok(to_field_template_dto(result.map_err(|e| e.to_string())?))
}

/// Same borrow discipline as `create_entry` — see its doc comment.
#[tauri::command]
pub async fn update_template(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    id: String,
    name: String,
    field_type: String,
    is_protected: bool,
) -> CmdResult<FieldTemplateDto> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = kokos_core::templates::update(&v.conn, &id, &name, &field_type, is_protected).and_then(|t| {
            vault::save(&mut v)?;
            Ok(t)
        });
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    Ok(to_field_template_dto(result.map_err(|e| e.to_string())?))
}

/// Same borrow discipline as `create_entry` — see its doc comment.
#[tauri::command]
pub async fn delete_template(state: State<'_, AppState>, vault_id: Option<String>, id: String) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = kokos_core::templates::delete(&v.conn, &id).and_then(|_| vault::save(&mut v));
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct AttachmentMetaDto {
    pub id: String,
    pub entry_id: String,
    pub filename: String,
    pub mime_type: Option<String>,
    pub size: i64,
    pub created_at: i64,
}

fn to_attachment_meta_dto(m: kokos_core::attachments::AttachmentMeta) -> AttachmentMetaDto {
    AttachmentMetaDto {
        id: m.id,
        entry_id: m.entry_id,
        filename: m.filename,
        mime_type: m.mime_type,
        size: m.size,
        created_at: m.created_at,
    }
}

/// Best-effort MIME guess from the file extension, for the handful of types
/// the UI cares about (e.g. image preview). Anything else is stored with no
/// MIME type — `download_attachment` writes the bytes back out regardless.
fn mime_from_ext(path: &str) -> Option<String> {
    let ext = Path::new(path).extension()?.to_str()?.to_lowercase();
    let mime = match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "json" => "application/json",
        "zip" => "application/zip",
        "csv" => "text/csv",
        _ => return None,
    };
    Some(mime.to_string())
}

/// Read-only: borrows the session briefly, no spawn_blocking needed — same
/// shape as `list_entries`, `list_folders`, `list_tags`, and `list_templates`.
#[tauri::command]
pub fn list_attachments(state: State<'_, AppState>, vault_id: Option<String>, entry_id: String) -> CmdResult<Vec<AttachmentMetaDto>> {
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
    let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
    let items = kokos_core::attachments::list(&v.conn, &entry_id).map_err(|e| e.to_string())?;
    Ok(items.into_iter().map(to_attachment_meta_dto).collect())
}

/// Allowlist-gated like `get_vault_header_info` — see its doc comment: `path`
/// arrives raw from the WebView's file-picker round-trip and must be one this
/// app itself handed out (via `pick_any_file`) before it ever reaches
/// `fs::metadata`/`fs::read`. Same borrow discipline as `create_entry` for the
/// DB mutation + save.
#[tauri::command]
pub async fn upload_attachment(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    entry_id: String,
    path: String,
) -> CmdResult<AttachmentMetaDto> {
    if !crate::paths::is_allowed(&state.allowed_paths, &path) {
        return Err(VaultError::PathNotAllowed.to_string());
    }
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = (|| -> Result<kokos_core::attachments::AttachmentMeta, VaultError> {
            // Open once; type/size are judged on the handle and the read is
            // capped, so a file swapped or grown after the allowlist check
            // cannot cause an oversized read.
            let data = crate::paths::safe_io::read_regular_capped(&path, kokos_core::attachments::MAX_ATTACHMENT_SIZE as u64)?
                .ok_or(VaultError::AttachmentTooLarge)?;
            let filename = Path::new(&path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "file".to_string());
            let mime = mime_from_ext(&path);
            kokos_core::attachments::add(&v.conn, &entry_id, &filename, mime.as_deref(), &data, now)
        })()
        .and_then(|meta| {
            vault::save(&mut v)?;
            Ok(meta)
        });
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    Ok(to_attachment_meta_dto(result.map_err(|e| e.to_string())?))
}

/// Allowlist-gated like `get_vault_header_info` — see its doc comment. Reads
/// the bytes out under a brief read-only session lock, then releases it
/// before writing to disk in `spawn_blocking`, so the write's I/O never holds
/// up another command that needs the session lock. No vault save — reading
/// an attachment doesn't mutate the vault.
#[tauri::command]
pub async fn download_attachment(state: State<'_, AppState>, vault_id: Option<String>, id: String, path: String) -> CmdResult<()> {
    if !crate::paths::is_allowed(&state.allowed_paths, &path) {
        return Err(VaultError::PathNotAllowed.to_string());
    }
    let data = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let rid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let s = reg.get_mut(&rid).ok_or_else(|| "no_vault".to_string())?;
        let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
        kokos_core::attachments::get(&v.conn, &id)
            .map_err(|e| e.to_string())?
            .data
    };
    tauri::async_runtime::spawn_blocking(move || write_owner_only(&path, &data))
        .await
        .map_err(spawn_blocking_failed)?
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Serialize)]
pub struct AttachmentBytesDto {
    pub mime: Option<String>,
    pub filename: String,
    pub size: i64,
    pub data_base64: String,
}

fn attachment_bytes_dto(a: kokos_core::attachments::Attachment) -> AttachmentBytesDto {
    use base64::Engine;
    AttachmentBytesDto {
        mime: a.meta.mime_type,
        filename: a.meta.filename,
        size: a.meta.size,
        data_base64: base64::engine::general_purpose::STANDARD.encode(&a.data),
    }
}

/// Read-only, in-memory sibling of `download_attachment`: returns the decrypted
/// bytes as base64 for inline preview instead of writing them to disk. No
/// allowlist (there is no filesystem path) and no vault save (read only). Same
/// vault resolution as every other attachment command.
#[tauri::command]
pub fn read_attachment_bytes(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    id: String,
) -> CmdResult<AttachmentBytesDto> {
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let rid = resolve_vault_id(&reg, vault_id.as_deref())?;
    let s = reg.get_mut(&rid).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
    let a = kokos_core::attachments::get(&v.conn, &id).map_err(|e| e.to_string())?;
    Ok(attachment_bytes_dto(a))
}

/// Same borrow discipline as `create_entry` — see its doc comment.
#[tauri::command]
pub async fn delete_attachment(state: State<'_, AppState>, vault_id: Option<String>, id: String) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = kokos_core::attachments::delete(&v.conn, &id).and_then(|_| vault::save(&mut v));
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

/// Same picker pattern as `pick_vault_path`, but with no filter — any file
/// type is a valid attachment. Adds the chosen path to the allowlist so the
/// following `upload_attachment` call accepts it.
#[tauri::command]
pub async fn pick_any_file(state: State<'_, AppState>) -> CmdResult<Option<String>> {
    let handle = rfd::AsyncFileDialog::new().pick_file().await;
    let Some(h) = handle else { return Ok(None) };
    let raw = h.path().to_string_lossy().to_string();
    crate::paths::allow(&state.allowed_paths, &raw);
    Ok(Some(raw))
}

/// Picker restricted to `.kdbx`, allowlisting the chosen path exactly like
/// `pick_any_file` so the following `import_kdbx` passes the `is_allowed` gate.
#[tauri::command]
pub async fn pick_kdbx_file(state: State<'_, AppState>) -> CmdResult<Option<String>> {
    let handle = rfd::AsyncFileDialog::new()
        .add_filter("KeePass database", &["kdbx"])
        .pick_file()
        .await;
    let Some(h) = handle else { return Ok(None) };
    let raw = h.path().to_string_lossy().to_string();
    crate::paths::allow(&state.allowed_paths, &raw);
    Ok(Some(raw))
}

/// Directory picker for the AI folder-import, allowlisting the chosen ROOT
/// exactly like `pick_any_file` so the following `ai_text_import_analyze_folder`
/// passes the `is_allowed` gate on the root.
#[tauri::command]
pub async fn pick_folder(state: State<'_, AppState>) -> CmdResult<Option<String>> {
    let handle = rfd::AsyncFileDialog::new().pick_folder().await;
    let Some(h) = handle else { return Ok(None) };
    let raw = h.path().to_string_lossy().to_string();
    crate::paths::allow(&state.allowed_paths, &raw);
    Ok(Some(raw))
}

/// Save-file picker for `download_attachment`'s destination, defaulting the
/// file name to the attachment's own filename. Adds the chosen path to the
/// allowlist so the following `download_attachment` call accepts it.
#[tauri::command]
pub async fn pick_save_path(state: State<'_, AppState>, default_name: String) -> CmdResult<Option<String>> {
    let handle = rfd::AsyncFileDialog::new().set_file_name(&default_name).save_file().await;
    let Some(h) = handle else { return Ok(None) };
    let raw = h.path().to_string_lossy().to_string();
    crate::paths::allow(&state.allowed_paths, &raw);
    Ok(Some(raw))
}

/// Owner-only atomic write (temp file + rename, no symlink following); see
/// `paths::safe_io::write_atomic_owner_only`.
fn write_owner_only(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    crate::paths::safe_io::write_atomic_owner_only(path, bytes)
}

/// Same borrow discipline as `create_folder` (spawn_blocking needs an owned
/// `OpenVault`, never a bare `take()`/assignment — see kokos_core::session).
/// Portable JSON export: `ids` omitted exports the whole
/// vault, provided exports only those entries (+ relations with both
/// endpoints in the set).
#[tauri::command]
pub async fn export_json(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: Option<String>, path: String, ids: Option<Vec<String>>) -> CmdResult<()> {
    if !crate::paths::is_allowed(&state.allowed_paths, &path) {
        return Err(VaultError::PathNotAllowed.to_string());
    }
    if is_known_vault_path(&app, &state, &path) {
        return Err(VaultError::AlreadyExists.to_string());
    }
    let (vid, v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = (|| -> Result<(), kokos_core::error::VaultError> {
            let bundle = kokos_core::portable::export(&v.conn, ids.as_deref(), env!("CARGO_PKG_VERSION"), now)?;
            let json = kokos_core::portable::to_json(&bundle)?;
            write_owner_only(&path, json.as_bytes()).map_err(|e| kokos_core::error::VaultError::Io(e.to_string()))?;
            let _ = kokos_core::audit::append(&v.conn, "exported", Some(&format!("json:{}", bundle.data.entries.len())));
            Ok(())
        })();
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    if result.is_ok() {
        mark_onboarding(&app, &state, crate::settings::OnboardingFact::Backup);
    }
    result.map_err(|e| e.to_string())
}

/// Same borrow discipline as `create_folder`. Flushes the in-memory DB to the
/// encrypted file via `vault::save` first (so the copy reflects the current
/// session state), then copies the file byte-for-byte to `path`.
#[tauri::command]
pub async fn export_vault_copy(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: Option<String>, path: String) -> CmdResult<()> {
    if !crate::paths::is_allowed(&state.allowed_paths, &path) {
        return Err(VaultError::PathNotAllowed.to_string());
    }
    if is_known_vault_path(&app, &state, &path) {
        return Err(VaultError::AlreadyExists.to_string());
    }
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = (|| -> Result<(), kokos_core::error::VaultError> {
            if let (Ok(src), Ok(dst)) = (
                crate::paths::normalise(&v.path),
                crate::paths::normalise(std::path::Path::new(&path)),
            ) {
                if src == dst {
                    return Err(kokos_core::error::VaultError::AlreadyExists);
                }
            }
            vault::save(&mut v)?;
            // Ciphertext copy goes through the same atomic owner-only writer
            // as the other exports (no pathname-based copy onto the destination).
            let bytes = crate::paths::safe_io::read_regular_capped(&v.path.to_string_lossy(), crate::paths::safe_io::MAX_VAULT_COPY_SIZE)
                .map_err(|e| kokos_core::error::VaultError::Io(e.to_string()))?
                .ok_or_else(|| kokos_core::error::VaultError::Io("vault file is not a regular file or is too large".to_string()))?;
            write_owner_only(&path, &bytes).map_err(|e| kokos_core::error::VaultError::Io(e.to_string()))?;
            let _ = kokos_core::audit::append(&v.conn, "exported", Some("kokos-copy"));
            Ok(())
        })();
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    if result.is_ok() {
        mark_onboarding(&app, &state, crate::settings::OnboardingFact::Backup);
    }
    result.map_err(|e| e.to_string())
}

/// Pre-read size/type gate for imports, mirroring
/// upload_attachment's pre-read check. Returns Ok(true) iff `path` is a regular
/// file of at most `max` bytes. Rejecting non-regular files (dirs, FIFOs, device
/// nodes — whose metadata size is unreliable) also closes the metadata->read
/// TOCTOU. Pure + Tauri-free so it is unit-testable without an AppHandle.
fn import_file_within_cap(path: &str, max: u64) -> std::io::Result<bool> {
    let md = std::fs::metadata(path)?;
    Ok(md.is_file() && md.len() <= max)
}

/// Portable JSON import: additive merge into the OPEN
/// vault — always mints new entry ids, never overwrites existing rows (see
/// `kokos_core::portable::import`). Same borrow discipline as
/// `export_vault_copy` (needs an owned `OpenVault` across spawn_blocking to
/// call `vault::save`).
#[tauri::command]
pub async fn import_json(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: Option<String>, path: String) -> CmdResult<kokos_core::portable::ImportReport> {
    if !crate::paths::is_allowed(&state.allowed_paths, &path) {
        return Err(VaultError::PathNotAllowed.to_string());
    }
    if !import_file_within_cap(&path, 100 * 1024 * 1024)
        .map_err(|e| VaultError::Io(e.to_string()).to_string())?
    {
        return Err(VaultError::ImportUnsupported.to_string());
    }
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = (|| -> Result<kokos_core::portable::ImportReport, kokos_core::error::VaultError> {
            // Open once + capped read (the pre-check above is only a fast fail).
            let raw_bytes = crate::paths::safe_io::read_regular_capped(&path, 100 * 1024 * 1024)
                .map_err(|e| kokos_core::error::VaultError::Io(e.to_string()))?
                .ok_or(kokos_core::error::VaultError::ImportUnsupported)?;
            let raw = String::from_utf8(raw_bytes).map_err(|e| kokos_core::error::VaultError::Io(e.to_string()))?;
            let bundle = kokos_core::portable::parse(&raw)?;
            let report = kokos_core::portable::import(&v.conn, &bundle, now)?;
            vault::save(&mut v)?;
            let _ = kokos_core::audit::append(&v.conn, "imported", Some(&format!("json:{}", report.entries)));
            Ok(report)
        })();
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    if result.is_ok() {
        mark_onboarding(&app, &state, crate::settings::OnboardingFact::Import);
    }
    result.map_err(|e| e.to_string())
}

/// KDBX one-time import. Mirrors `import_json`: allowlist gate, borrow
/// the open vault across a `spawn_blocking` parse+import, save, audit, release.
/// The `.kdbx` is UNTRUSTED — every failure is a typed token from
/// `kokos_core::kdbx`, surfaced to the frontend's error map. The master password
/// is zeroized when the closure's `Zeroizing` drops.
#[tauri::command]
pub async fn import_kdbx(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: Option<String>, path: String, password: String) -> CmdResult<kokos_core::portable::ImportReport> {
    if !crate::paths::is_allowed(&state.allowed_paths, &path) {
        return Err(VaultError::PathNotAllowed.to_string());
    }
    if !import_file_within_cap(&path, kokos_core::kdbx::MAX_KDBX_SIZE as u64)
        .map_err(|e| VaultError::Io(e.to_string()).to_string())?
    {
        return Err(VaultError::KdbxTooLarge.to_string());
    }
    let password = zeroize::Zeroizing::new(password);
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = (|| -> Result<kokos_core::portable::ImportReport, kokos_core::error::VaultError> {
            let bytes = crate::paths::safe_io::read_regular_capped(&path, kokos_core::kdbx::MAX_KDBX_SIZE as u64)
                .map_err(|e| kokos_core::error::VaultError::Io(e.to_string()))?
                .ok_or(kokos_core::error::VaultError::KdbxTooLarge)?;
            let tree = kokos_core::kdbx::open(&bytes, &password)?;
            let report = kokos_core::kdbx::import(&v.conn, &tree, now)?;
            vault::save(&mut v)?;
            let _ = kokos_core::audit::append(&v.conn, "imported", Some(&format!("kdbx:{}", report.entries)));
            Ok(report)
        })();
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    if result.is_ok() {
        mark_onboarding(&app, &state, crate::settings::OnboardingFact::Import);
    }
    result.map_err(|e| e.to_string())
}

/// Commit a reviewed text-import proposal into the OPEN vault.
/// The proposal is ALREADY vault-typed + user-confirmed — no integrity
/// re-check. Per-entry partial: a `create` failure is counted, the batch
/// continues (like import_json's additive semantics; a re-commit would mint new
/// ids, so the UI closes on success). Zeroizes every field value at the boundary.
#[tauri::command]
pub async fn ai_text_import_commit(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    vault_id: Option<String>,
    mut proposal: CommitProposal,
) -> CmdResult<TextImportReport> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = (|| -> Result<TextImportReport, VaultError> {
            validate_commit_types(&proposal)?;
            let folder_ids = resolve_commit_folders(&v.conn, &proposal, now)?;
            let entries = build_new_entries(&proposal, &folder_ids)?;
            let mut imported = 0u32;
            let mut failed = 0u32;
            for ne in entries {
                match kokos_core::entries::create(&v.conn, ne, now) {
                    Ok(_) => imported += 1,
                    Err(_) => failed += 1,
                }
            }
            vault::save(&mut v)?;
            let _ = kokos_core::audit::append(&v.conn, "imported", Some(&format!("text:{}", imported)));
            Ok(TextImportReport { imported, failed })
        })();
        for e in &mut proposal.entries {
            for f in &mut e.fields {
                f.value.zeroize();
            }
        }
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    if result.is_ok() {
        mark_onboarding(&app, &state, crate::settings::OnboardingFact::Import);
    }
    result.map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct RelationViewDto {
    pub relation_id: String,
    pub other_id: String,
    pub other_title: String,
    pub other_is_deleted: bool,
    pub relation_type: String,
}

fn to_relation_view_dto(r: kokos_core::relations::RelationView) -> RelationViewDto {
    RelationViewDto {
        relation_id: r.relation_id,
        other_id: r.other_id,
        other_title: r.other_title,
        other_is_deleted: r.other_is_deleted,
        relation_type: r.relation_type,
    }
}

/// Read-only: borrows the session briefly, no spawn_blocking needed — same
/// shape as `list_entries`, `list_folders`, `list_tags`, and `list_templates`.
#[tauri::command]
pub fn list_relations(state: State<'_, AppState>, vault_id: Option<String>, entry_id: String) -> CmdResult<Vec<RelationViewDto>> {
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
    let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
    let items = kokos_core::relations::list_for_entry(&v.conn, &entry_id).map_err(|e| e.to_string())?;
    Ok(items.into_iter().map(to_relation_view_dto).collect())
}

/// Same borrow discipline as `create_entry` — see its doc comment.
#[tauri::command]
pub async fn add_relation(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    source_id: String,
    target_id: String,
    relation_type: String,
) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = kokos_core::relations::add(&v.conn, &source_id, &target_id, &relation_type, now)
            .and_then(|_| vault::save(&mut v));
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

/// Same borrow discipline as `create_entry` — see its doc comment.
#[tauri::command]
pub async fn delete_relation(state: State<'_, AppState>, vault_id: Option<String>, relation_id: String) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = kokos_core::relations::delete(&v.conn, &relation_id).and_then(|_| vault::save(&mut v));
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct HistoryEntryDto {
    pub id: String,
    pub value: Option<String>,
    pub changed_at: i64,
}

fn to_history_entry_dto(h: kokos_core::entries::HistoryEntry) -> HistoryEntryDto {
    HistoryEntryDto { id: h.id, value: h.value, changed_at: h.changed_at }
}

/// Read-only: borrows the session briefly, no spawn_blocking needed — same
/// shape as `list_relations`. NOTE: history `value`s ARE plaintext secrets
/// (same as `reveal_field`); returned only on this explicit user action and
/// MUST NOT be logged.
#[tauri::command]
pub fn list_field_history(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    entry_id: String,
    field_name: String,
) -> CmdResult<Vec<HistoryEntryDto>> {
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
    let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
    let items = kokos_core::entries::list_field_history(&v.conn, &entry_id, &field_name)
        .map_err(|e| e.to_string())?;
    Ok(items.into_iter().map(to_history_entry_dto).collect())
}

/// Same borrow discipline as `delete_relation` — mutation + save together in
/// one spawn_blocking, `end_borrow` always runs.
#[tauri::command]
pub async fn clear_field_history(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    entry_id: String,
    field_name: String,
) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = kokos_core::entries::clear_field_history(&v.conn, &entry_id, &field_name)
            .and_then(|_| vault::save(&mut v));
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

/// Same borrow discipline as `create_entry` — see its doc comment. Replaces
/// an entry's non-favorite tag links wholesale; the reserved favorite link
/// (owned by `toggle_favorite`) is preserved by `kokos_core::tags::set_entry_tags`
/// regardless of whether `tag_ids` names it.
#[tauri::command]
pub async fn set_entry_tags(state: State<'_, AppState>, vault_id: Option<String>, entry_id: String, tag_ids: Vec<String>) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = kokos_core::tags::set_entry_tags(&v.conn, &entry_id, &tag_ids, now)
            .and_then(|_| vault::save(&mut v));
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

/// Same borrow discipline as `set_entry_tags`. Adds ONE tag link (favorite is
/// `toggle_favorite`'s job and is untouched). Best-effort re-embeds the entry
/// afterward: `tag_names` is in the embedding whitelist, so a new tag changes
/// the entry's own `embedding_input`; re-embedding keeps its sidecar vector
/// coherent instead of stale-until-next-backfill. AI off / no engine -> the
/// link is still written, the re-embed is simply skipped.
#[tauri::command]
pub async fn add_entry_tag(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    vault_id: Option<String>,
    entry_id: String,
    tag_id: String,
) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let ai = if state.settings.lock().map_err(|e| e.to_string())?.ai_enabled {
        match (
            state.ai_embedder.lock().map_err(|e| e.to_string())?.clone(),
            crate::ai::vectors_dir(&app),
        ) {
            (Some(engine), Ok(vdir)) => Some((engine, vdir)),
            _ => None,
        }
    } else {
        None
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = kokos_core::tags::set_entry_tag(&v.conn, &entry_id, &tag_id, true, now)
            .and_then(|_| vault::save(&mut v));
        if outcome.is_ok() {
            if let Some((engine, vdir)) = &ai {
                crate::ai::reembed_entry_blocking(&v, engine, &entry_id, vdir);
            }
        }
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?.end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

/// Same borrow discipline as `create_entry` — see its doc comment. Flips
/// `is_favorite` AND syncs the reserved favorite tag link atomically via
/// `kokos_core::tags::toggle_favorite`; returns the new state so the caller
/// need not re-fetch the entry. Out of scope for this command: the separate,
/// already-known desync where `entries::update`'s `EntryPatch.is_favorite`
/// writes the column without touching the tag — deferred, not touched here.
#[tauri::command]
pub async fn toggle_favorite(state: State<'_, AppState>, vault_id: Option<String>, entry_id: String) -> CmdResult<bool> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = kokos_core::tags::toggle_favorite(&v.conn, &entry_id, now).and_then(|on| {
            vault::save(&mut v)?;
            Ok(on)
        });
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct TrashItemDto {
    pub id: String,
    pub title: String,
    pub folder_name: Option<String>,
    pub deleted_at: Option<i64>,
    pub updated_at: i64,
}

/// Read-only: borrows the session briefly, no spawn_blocking needed — same
/// shape as `list_entries`, `list_folders`, and `list_tags`.
#[tauri::command]
pub fn list_trash(state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<Vec<TrashItemDto>> {
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
    let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
    let items = kokos_core::trash::list_trash(&v.conn).map_err(|e| e.to_string())?;
    Ok(items
        .into_iter()
        .map(|i| TrashItemDto {
            id: i.id,
            title: i.title,
            folder_name: i.folder_name,
            deleted_at: i.deleted_at,
            updated_at: i.updated_at,
        })
        .collect())
}

/// Same borrow discipline as `create_entry` — see its doc comment.
/// `Ok(true)` → save; `Ok(false)` → `EntryNotFound`; `Err` → propagate
/// without saving. `end_borrow` runs regardless of which arm is taken, so a
/// failed restore never leaves the session borrowed.
#[tauri::command]
pub async fn restore_entry(state: State<'_, AppState>, vault_id: Option<String>, id: String) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = match kokos_core::trash::restore(&v.conn, &id, now) {
            Ok(true) => vault::save(&mut v),
            Ok(false) => Err(VaultError::EntryNotFound),
            Err(e) => Err(e),
        };
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

/// Vectors dir for sidecar cleanup. Cleanup needs only the vault key, not the
/// embedding engine, so it also runs while AI is off or the engine is unloaded.
fn ai_cleanup_dir(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    crate::ai::vectors_dir(app).ok()
}

/// Drops the AI sidecar vector records of permanently deleted entries in ONE
/// load/save. Runs inside the caller's `spawn_blocking`. Failure is logged (same
/// as `ai::remove_entry_vector_blocking`) and never fails the delete: vectors
/// are derived data, and the next backfill removes any record whose entry is gone.
fn purge_entry_vectors_blocking(v: &kokos_core::vault::OpenVault, ids: &[String], vectors_dir: &std::path::Path) {
    if ids.is_empty() {
        return;
    }
    let keep = |id: &str| !ids.iter().any(|i| i == id);
    if let Err(e) = prune_vectors(v, vectors_dir, &keep) {
        eprintln!("[ai] purge-vectors for {} permanently deleted entries skipped: {e}", ids.len());
    }
}

/// Drops sidecar records whose entry row no longer exists (e.g. removed by the
/// trash auto-delete at open, which runs inside kokos-core without the vectors
/// dir). Runs inside the caller's `spawn_blocking`; failure is only logged.
fn prune_orphan_vectors_blocking(v: &kokos_core::vault::OpenVault, vectors_dir: &std::path::Path) {
    let ids: Result<std::collections::HashSet<String>, rusqlite::Error> = v
        .conn
        .prepare("SELECT id FROM entries")
        .and_then(|mut st| st.query_map([], |r| r.get::<_, String>(0))?.collect());
    let ids = match ids {
        Ok(ids) => ids,
        Err(e) => {
            eprintln!("[ai] orphan-vector prune skipped: {e}");
            return;
        }
    };
    if let Err(e) = prune_vectors(v, vectors_dir, &|id| ids.contains(id)) {
        eprintln!("[ai] orphan-vector prune skipped: {e}");
    }
}

fn prune_vectors(v: &kokos_core::vault::OpenVault, vectors_dir: &std::path::Path, keep: &dyn Fn(&str) -> bool) -> Result<(), String> {
    let vault_id = kokos_core::db::get_device_id(&v.conn).map_err(|e| e.to_string())?;
    let subkey = kokos_core::crypto::derive_subkey(&v.key, crate::ai::SUBKEY_LABEL);
    let path = kokos_ai::store::store_path(vectors_dir, &vault_id);
    kokos_ai::store::prune(&path, &subkey, keep).map(|_| ()).map_err(|e| e.to_string())
}

/// Same borrow discipline as `create_entry` — see its doc comment.
/// `Ok(true)` → save; `Ok(false)` → `EntryNotFound`; `Err` → propagate
/// without saving. `end_borrow` runs regardless of which arm is taken, so a
/// failed permanent delete never leaves the session borrowed.
#[tauri::command]
pub async fn permanent_delete_entry(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: Option<String>, id: String) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let ai = ai_cleanup_dir(&app);
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = match kokos_core::trash::permanent_delete(&v.conn, &id) {
            Ok(true) => vault::save(&mut v),
            Ok(false) => Err(VaultError::EntryNotFound),
            Err(e) => Err(e),
        };
        // Soft delete already drops the record, but not when AI was off then
        // (or the entry was trashed by sync): purge so no per-entry sidecar
        // data survives a permanent delete.
        if outcome.is_ok() {
            if let Some(vdir) = &ai {
                purge_entry_vectors_blocking(&v, std::slice::from_ref(&id), vdir);
            }
        }
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

/// Same borrow discipline as `create_entry` — see its doc comment. Returns
/// the count of entries permanently deleted from the trash.
#[tauri::command]
pub async fn empty_trash(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<u32> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let ai = ai_cleanup_dir(&app);
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        // Collect ids first: after the DELETE they are gone from the DB.
        let trashed: Vec<String> = kokos_core::trash::list_trash(&v.conn)
            .map(|items| items.into_iter().map(|i| i.id).collect())
            .unwrap_or_default();
        let outcome = kokos_core::trash::empty_trash(&v.conn).and_then(|n| {
            vault::save(&mut v)?;
            Ok(n as u32)
        });
        if outcome.is_ok() {
            if let Some(vdir) = &ai {
                purge_entry_vectors_blocking(&v, &trashed, vdir);
            }
        }
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

/// Returns the in-memory settings cache (populated from disk at app setup),
/// never a per-call settings-file re-read. (The allowlist loop
/// below does a per-`open_vaults`-path `canonicalize` stat, but still reads
/// no settings file.)
#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> CmdResult<crate::settings::Settings> {
    let s = state.settings.lock().map_err(|e| e.to_string())?.clone();
    for p in &s.open_vaults {
        crate::paths::allow(&state.allowed_paths, p);
    }
    Ok(s)
}

/// Persists settings to disk first, then updates the cache — so the cache
/// never reflects a write that failed to save.
///
/// Grants AND any pending on-screen confirmation prompt must not survive a
/// mode change, a session-length change, a whitelist edit, or the
/// integration being turned off — the "mode change" half of the "on
/// lock/close/mode change" rule, widened to cover a pending prompt too (see
/// `grants::settings_invalidate_grants`'s doc comment for why a whitelist
/// edit leaving a prompt on screen was itself a defect: `origin` is never in
/// the confirm payload, so the human cannot tell which extension is asking).
/// The old value is read and the single pure predicate is evaluated while
/// still holding the settings guard, but acted on only AFTER it is dropped —
/// never hold the settings guard across the `invalidate_confirms` emit.
#[tauri::command]
pub fn set_settings(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    mut settings: crate::settings::Settings,
) -> CmdResult<()> {
    use tauri::Manager;
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    settings.nmh_chrome_ids = sanitize_whitelist_ids(&settings.nmh_chrome_ids, validate_chrome_id);
    settings.nmh_firefox_ids =
        sanitize_whitelist_ids(&settings.nmh_firefox_ids, validate_firefox_id);
    let new_chrome = settings.nmh_chrome_ids.clone();
    let new_firefox = settings.nmh_firefox_ids.clone();
    let (invalidate, old_chrome, old_firefox) = {
        let mut guard = state.settings.lock().map_err(|e| e.to_string())?;
        crate::settings::preserve_backend_managed(&mut settings, &guard);
        let old = guard.clone();
        let invalidate = crate::nmh::grants::settings_invalidate_grants(&old, &settings);
        crate::settings::save(&dir, &settings).map_err(|e| e.to_string())?;
        *guard = settings;
        (invalidate, old.nmh_chrome_ids, old.nmh_firefox_ids)
    };
    if invalidate {
        crate::nmh::invalidate_confirms(&app);
    }
    for (browser, old_ids, new_ids) in [
        ("chrome", &old_chrome, &new_chrome),
        ("firefox", &old_firefox, &new_firefox),
    ] {
        let removed = crate::nmh::whitelist_removed_origins(old_ids, new_ids, browser);
        if crate::nmh::cascade_forget_origins(&app, &removed) > 0 {
            crate::nmh::handlers::audit_event(&app, "extension_grant_revoked", Some(browser));
        }
    }
    Ok(())
}

/// True iff enough time has elapsed since the last idle-clock advance to advance
/// again (server-side rate-limit). Pure so it is unit-testable
/// without the AppState mutex / a real clock.
fn note_activity_should_advance(last: std::time::Instant, now: std::time::Instant) -> bool {
    now.duration_since(last) >= std::time::Duration::from_millis(500)
}

/// Reset the idle timer. The frontend calls this (throttled) on user input so
/// the auto-lock watcher (lib.rs) sees recent activity.
#[tauri::command]
pub fn note_activity(state: State<'_, AppState>) -> CmdResult<()> {
    let mut last = state.last_activity.lock().map_err(|e| e.to_string())?;
    let now = std::time::Instant::now();
    if note_activity_should_advance(*last, now) {
        *last = now;
    }
    Ok(())
}

/// The webview's answer to an `nmh-confirm-request`, with a `remember`
/// bit. Unknown or duplicate `req_id`s are ignored -- `Registry::reply`
/// already treats them as a no-op, never an error to the UI: the request may
/// have already timed out server-side, or the modal may
/// have been re-rendered and replied to the same id twice. `remember` is
/// carried through verbatim to the parked connection thread but is NOT
/// trusted there either -- `handlers::should_persist_grant` re-checks it
/// against the live server-side mode, so a modified frontend sending
/// `remember: true` in a mode that forbids persisting a grant cannot mint
/// one.
#[tauri::command]
pub fn nmh_confirm_reply(
    state: State<'_, AppState>,
    req_id: String,
    allowed: bool,
    remember: bool,
) -> CmdResult<()> {
    state
        .nmh
        .confirms
        .reply(&req_id, crate::nmh::grants::ConfirmAnswer { allowed, remember });
    Ok(())
}


/// Root `manifest::*` resolves its per-browser directory against: `$HOME` on
/// unix, %APPDATA% on Windows (see that arm below). `None` means "this platform
/// is unsupported" -- either the build has no arm here, or the variable itself
/// is absent -- and every caller maps that to the `unsupported_platform`
/// token rather than silently doing nothing. cfg-paired the same way
/// `nmh::start`/`stop` are, so the command bodies below can call it
/// unconditionally.
#[cfg(unix)]
pub(crate) fn nmh_home() -> Option<PathBuf> {
    if let Some(real) = crate::nmh::snap::real_home() {
        return Some(real);
    }
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Windows twin. `$HOME` is a unix concept and is normally unset here, so the
/// bare `None` this used to return made all four browser-registration commands
/// answer `unsupported_platform` — the registry write in `manifest` was
/// implemented and simply unreachable, which showed up in the UI as
/// "Browser registration is not available on this platform yet".
///
/// %APPDATA% is the root `manifest::dir_for` expects on Windows: it appends the
/// bundle identifier and the per-browser leaf itself, so what belongs here is
/// the Roaming root and nothing more. Read directly rather than rebuilt from
/// %USERPROFILE%, because folder redirection can point the two at different
/// places and the manifest must land where the browser actually looks.
#[cfg(windows)]
pub(crate) fn nmh_home() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(PathBuf::from)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn nmh_home() -> Option<PathBuf> {
    None
}

/// mirror the install path's shape validation on the OTHER whitelist
/// writer (set_settings). Keeps only ids that pass `validate` (in their canonical/
/// trimmed Ok form); silently drops malformed ones so a compromised WebView can't
/// seed an unmatchable/short id into the trust store — matching nmh_install, which
/// rejects the same shapes at install time. Dropping (vs rejecting the whole call)
/// keeps an unrelated settings save working and lets the existing whitelist-shrink
/// cascade forget any grants under a dropped id.
fn sanitize_whitelist_ids(
    raw: &[String],
    validate: impl Fn(&str) -> Result<String, &'static str>,
) -> Vec<String> {
    raw.iter().filter_map(|id| validate(id).ok()).collect()
}

/// `browser` argument parse, shared by all three id/whitelist-mutating
/// commands below. A thin wrapper over `Browser::from_name` whose only
/// added value is fixing the error TOKEN this layer returns on a miss -- kept
/// as a named seam, rather than inlined at each call site, so it is directly
/// unit-tested (there is no `AppHandle` harness, so every decision is
/// factored into a pure seam).
fn parse_browser(s: &str) -> Result<kokos_nmh::origin::Browser, &'static str> {
    kokos_nmh::origin::Browser::from_name(s).ok_or("unknown_browser")
}

/// Chrome extension ids are always exactly 32 lowercase a-p letters (the
/// browser's own id alphabet), so the exact-charset check below doubles as a
/// complete hostile-character filter: no `/`, `..`, NUL byte, or newline can
/// be spelled using only `a`-`p`. Trims surrounding whitespace first, then
/// requires the WHOLE trimmed string to match -- a trailing/leading stray
/// character is a rejection, not a truncation. `manifest::json_for`
/// normalises a Chrome id defensively too, but this is the only SHAPE
/// check, and it runs before anything is written to disk or to settings.
fn validate_chrome_id(raw: &str) -> Result<String, &'static str> {
    let id = raw.trim();
    if id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b)) {
        Ok(id.to_string())
    } else {
        Err("bad_chrome_id")
    }
}

/// Firefox ids have no fixed length or alphabet (`name@domain` or a
/// `{uuid}`), so -- unlike Chrome -- the shape check alone cannot double as a
/// hostile-character filter: `{../../etc/passwd}` IS "wrapped in {}" and must
/// still be rejected. This is the ONLY guard for Firefox:
/// `manifest::json_for` embeds a Firefox id VERBATIM with no
/// normalisation of its own, so validation must run before anything is
/// written. Trims surrounding whitespace first; rejects the empty string.
///
/// A bare `"@"` (or `"@x"`/`"x@"`) and a brace pair with nothing but
/// whitespace inside (`"{ }"`) both satisfied the shape check in an earlier
/// version -- not exploitable on their own (the
/// hostile-character checks below still block traversal/NUL/control bytes),
/// but a typo'd `"@"` becomes a trivially guessable whitelist entry any local
/// process could present at the socket (this project's own threat model:
/// anyone can dial the 0600 socket directly). Now requires a non-empty local
/// part AND a non-empty domain part around the `@`, and non-whitespace
/// content inside `{}`.
///
/// A Firefox id's CASE used to be handled three different, disagreeing ways
/// across this codebase -- now resolved, all three agree. This function still preserves
/// case verbatim; `manifest::json_for` still embeds it
/// verbatim into the manifest file; and `nmh_install` writes that same
/// byte-identical id into the manifest's `allowed_extensions` AND into the
/// settings whitelist Vec in one call, so for any UI-driven install the two
/// are always identical. `nmh::firefox_key` now
/// ALSO compares case-sensitively at the socket gate -- it used to lowercase
/// both sides, which is what the case divergence described above (in an
/// earlier version of this comment) meant. Because Firefox itself matches
/// `allowed_extensions` case-sensitively, a real Firefox-mediated connection
/// is only possible once Firefox's own check already matched the manifest --
/// so the origin it hands the host is guaranteed byte-identical to the
/// manifest entry, which is guaranteed byte-identical to the settings entry.
/// This is exactly what makes a mixed-case `gecko.id` work end to end: no
/// canonicalisation anywhere in the chain, just three sites that now agree
/// on the same bytes instead of one of them silently normalising.
fn validate_firefox_id(raw: &str) -> Result<String, &'static str> {
    let id = raw.trim();
    if id.is_empty() {
        return Err("bad_firefox_id");
    }
    let at_shaped = id.contains('@') && !id.starts_with('@') && !id.ends_with('@');
    let braced_shaped =
        id.starts_with('{') && id.ends_with('}') && !id[1..id.len() - 1].trim().is_empty();
    if !(at_shaped || braced_shaped) {
        return Err("bad_firefox_id");
    }
    let hostile = id.contains("..")
        || id.chars().any(|c| c == '/' || c == '\\' || c == '\0' || c.is_control());
    if hostile {
        return Err("bad_firefox_id");
    }
    Ok(id.to_string())
}

/// Decides the browser's whitelist Vec to persist after a successful
/// install. REPLACES wholesale, never appends: `manifest::json_for` embeds
/// exactly ONE id per browser, so every successful `manifest::install` call
/// overwrites the manifest file to trust ONLY the new id. If the settings
/// vector merely appended, an id a previous install wrote (A) would stay
/// trusted at the socket handshake (`nmh::is_allowed_origin`)
/// even after installing a different id (B) -- the manifest file and the
/// in-settings whitelist would silently diverge, and this project's own
/// threat model (any local process can dial the 0600 socket directly,
/// stated repeatedly in nmh/mod.rs) means a stale id A left in the Vec is
/// still a live credential, not a harmless leftover -- only `nmh_uninstall`
/// ever clears it otherwise. `_current` is intentionally unused: the whole
/// point of this seam is that the answer does NOT depend on what was there
/// before, only on the one id that now matches the manifest -- kept as a
/// parameter anyway so the covering test can hold both the "replace" result
/// and a hypothetical "append" computation side by side for comparison.
fn browser_ids_after_install(_current: &[String], id: &str) -> Vec<String> {
    vec![id.to_string()]
}

#[derive(Serialize)]
pub struct NmhStatusDto {
    pub enabled: bool,
    pub running: bool,
    pub chrome_registered: bool,
    pub firefox_registered: bool,
    pub host_path: Option<String>,
    pub chrome_ids: Vec<String>,
    pub firefox_ids: Vec<String>,
}

/// Every `Err` returned by the four `nmh_*` host-control commands
/// (`nmh_status`, `nmh_set_enabled`, `nmh_install`, `nmh_uninstall`) is
/// exactly one of the following lowercase machine tokens -- never prose,
/// never an interpolated OS error message (which can carry a filesystem
/// path) -- so the Settings UI can map each to an i18n key by
/// exact string match:
///   - `unknown_browser`      -- `browser` was neither "chrome" nor "firefox"
///   - `bad_chrome_id`        -- the Chrome extension id failed shape validation
///   - `bad_firefox_id`       -- the Firefox extension id failed shape validation
///   - `host_missing`         -- `manifest::host_binary_path` returned `None`
///                                (the `kokos-nmh` sidecar is not built/found
///                                next to this binary)
///   - `unsupported_platform` -- `$HOME` could not be resolved, or
///                                `manifest::install`/`remove` returned
///                                `io::ErrorKind::Unsupported` (no directory-
///                                table entry for this OS)
///   - `internal`             -- anything else: a poisoned mutex, or an
///                                `io::Error` that is not `Unsupported`
///
/// Read-only snapshot for the Settings UI. `running` is read from
/// `state.nmh.running` (the flag the accept loop and `stop()` maintain),
/// deliberately NEVER from `settings.nmh_enabled` -- the two fields live
/// separately in this DTO precisely because they can legitimately disagree
/// (enabled but failed to bind, or a non-unix build where `start()` is a
/// no-op and the socket never comes up). `chrome_registered`/
/// `firefox_registered` reflect the actual manifest FILE on disk, not the
/// setting -- a manifest a previous run wrote can outlive a later
/// `nmh_enabled` flip. A missing `$HOME` degrades those two to `false`
/// (nothing could be installed there, same as `manifest::is_installed`'s own
/// contract for an unsupported platform) rather than failing the whole call
/// -- every other field is independent of the filesystem and the UI still
/// needs them.
#[tauri::command]
pub fn nmh_status(app: tauri::AppHandle, state: State<'_, AppState>) -> CmdResult<NmhStatusDto> {
    let settings = state.settings.lock().map_err(|_| "internal".to_string())?.clone();
    let running = *state.nmh.running.lock().map_err(|_| "internal".to_string())?;
    let (chrome_registered, firefox_registered) = match nmh_home() {
        Some(home) => (
            crate::nmh::manifest::is_installed(kokos_nmh::origin::Browser::Chrome, &home),
            crate::nmh::manifest::is_installed(kokos_nmh::origin::Browser::Firefox, &home),
        ),
        None => (false, false),
    };
    let host_path =
        crate::nmh::manifest::host_binary_path(&app).map(|p| p.to_string_lossy().into_owned());
    Ok(NmhStatusDto {
        enabled: settings.nmh_enabled,
        running,
        chrome_registered,
        firefox_registered,
        host_path,
        chrome_ids: settings.nmh_chrome_ids,
        firefox_ids: settings.nmh_firefox_ids,
    })
}

/// Master switch. `true` persists then starts the listener -- but ONLY if it
/// is not already running: `nmh::start` (nmh/mod.rs) unconditionally unlinks
/// whatever socket file currently sits at the path and binds a fresh one, so
/// calling it a second time while an old accept loop is still live rebinds
/// out from under that loop and leaks its thread forever (it is left blocked
/// in `incoming()` on a now-orphaned listener that no `stop()` call can ever
/// wake again, since `stop()` only wakes the *current* listener via a fresh
/// connect to the current path). Same `!running` guard `nmh_install` already
/// uses below, for the same reason. `false` persists, stops it, and calls
/// `invalidate_confirms` -- NEVER the raw `grants.clear()` +
/// `confirms.cancel_all()` pair: that pair alone leaves an
/// on-screen confirm modal open forever, because only `invalidate_confirms`
/// also emits `nmh-confirm-cancel` (see its doc comment in `nmh/mod.rs`) --
/// turning integration off must not leave a confirmation prompt or a session
/// grant alive for a channel that no longer exists. Settings are saved to
/// disk BEFORE the in-memory cache is updated (the `set_settings` pattern
/// above), and the cache guard is never held across
/// `nmh::start`/`stop`/`invalidate_confirms`.
#[tauri::command]
pub fn nmh_set_enabled(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> CmdResult<()> {
    use tauri::Manager;
    let dir = app.path().app_config_dir().map_err(|_| "internal".to_string())?;
    let mut new_settings = state.settings.lock().map_err(|_| "internal".to_string())?.clone();
    new_settings.nmh_enabled = enabled;
    crate::settings::save(&dir, &new_settings).map_err(|_| "internal".to_string())?;
    {
        let mut guard = state.settings.lock().map_err(|_| "internal".to_string())?;
        *guard = new_settings;
    }
    if enabled {
        let running = *state.nmh.running.lock().map_err(|_| "internal".to_string())?;
        if !running {
            crate::nmh::start(app.clone());
        }
    } else {
        crate::nmh::stop(&app);
        crate::nmh::invalidate_confirms(&app);
    }
    Ok(())
}

/// Audited opt-in toggle for the HIBP breach check. Persists the flag to
/// `settings.json` FIRST, then updates the in-memory cache (the `set_settings`
/// discipline — the cache never reflects a write that failed to save). Then,
/// best-effort and off the UI thread, appends `hibp_enabled`/`hibp_disabled`
/// to the in-vault `audit_log` (the `keychain_enable` hand-off: begin_borrow
/// → spawn_blocking → end_borrow). The audit is skipped, not fatal, if no
/// vault is borrowable — the settings write already committed. `set_settings`
/// itself has no vault handle, which is exactly why this is its own command.
#[tauri::command]
pub async fn hibp_set_enabled(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> CmdResult<()> {
    use tauri::Manager;
    let dir = app.path().app_config_dir().map_err(|_| "internal".to_string())?;
    let mut new_settings = state.settings.lock().map_err(|_| "internal".to_string())?.clone();
    new_settings.hibp_enabled = enabled;
    crate::settings::save(&dir, &new_settings).map_err(|_| "internal".to_string())?;
    {
        let mut guard = state.settings.lock().map_err(|_| "internal".to_string())?;
        *guard = new_settings;
    }
    let event = if enabled { "hibp_enabled" } else { "hibp_disabled" };
    let (id, borrowed) = {
        let mut reg = state.sessions.lock().map_err(|_| "internal".to_string())?;
        match reg.active_id().map(str::to_string) {
            Some(id) => {
                let b = reg.get_mut(&id).and_then(|s| s.begin_borrow());
                (Some(id), b)
            }
            None => (None, None),
        }
    };
    if let (Some(id), Some(mut v)) = (id, borrowed) {
        let v = tauri::async_runtime::spawn_blocking(move || {
            let _ = kokos_core::audit::append(&v.conn, event, None);
            let _ = vault::save(&mut v);
            v
        })
        .await
        .map_err(spawn_blocking_failed)?;
        let mut reg = state.sessions.lock().map_err(|_| "internal".to_string())?;
        if let Some(s) = reg.get_mut(&id) {
            s.end_borrow(v);
        }
    }
    Ok(())
}

/// Validates `extension_id` for `browser`, resolves the sidecar path, writes
/// the browser's native-messaging manifest, then persists the id into
/// settings. Order is fixed: id validation happens
/// BEFORE anything is written (Chrome: 32 lowercase a-p letters after
/// trimming; Firefox: contains `@` or is `{}`-wrapped, plus a hostile-
/// character rejection -- see `validate_chrome_id`/`validate_firefox_id`);
/// `host_binary_path` is resolved next so a missing sidecar never produces a
/// manifest with a dangling path (never a hardcoded fallback); the manifest
/// write follows; only once THAT succeeded is the id persisted into settings
/// (save-then-cache, same as `set_settings`) -- via `browser_ids_after_install`,
/// which REPLACES that browser's whitelist Vec wholesale rather than
/// appending, matching the one-slot manifest file `manifest::json_for`
/// writes (see that function's doc comment for why an append would let a
/// stale id from a previous install stay live at the socket handshake).
/// Whitelist mutation -- replacing an id changes who may open a channel to
/// the vault -- is a revocation site (handled here explicitly
/// because this command writes settings directly and bypasses
/// `set_settings`'s own `settings_invalidate_grants` call):
/// `invalidate_confirms` runs after the new whitelist is committed, so a
/// grant or a parked prompt earned under the OLD whitelist cannot survive.
/// Finally, if the integration is enabled and the listener is not already
/// running, start it -- covers first-ever install while `nmh_enabled` was
/// already on from a previous session.
#[tauri::command]
pub fn nmh_install(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    browser: String,
    extension_id: String,
) -> CmdResult<()> {
    use tauri::Manager;
    let browser = parse_browser(&browser).map_err(|e| e.to_string())?;
    let id = match browser {
        kokos_nmh::origin::Browser::Chrome => validate_chrome_id(&extension_id),
        kokos_nmh::origin::Browser::Firefox => validate_firefox_id(&extension_id),
    }
    .map_err(|e| e.to_string())?;

    let host_path = crate::nmh::manifest::host_binary_path(&app)
        .ok_or_else(|| "host_missing".to_string())?;
    let home = nmh_home().ok_or_else(|| "unsupported_platform".to_string())?;
    let host_path_str = host_path.to_string_lossy().into_owned();
    crate::nmh::manifest::install(browser, &home, &host_path_str, &id).map_err(|e| {
        if e.kind() == std::io::ErrorKind::Unsupported {
            "unsupported_platform".to_string()
        } else {
            "internal".to_string()
        }
    })?;

    let dir = app.path().app_config_dir().map_err(|_| "internal".to_string())?;
    let mut new_settings = state.settings.lock().map_err(|_| "internal".to_string())?.clone();
    let old_ids = match browser {
        kokos_nmh::origin::Browser::Chrome => new_settings.nmh_chrome_ids.clone(),
        kokos_nmh::origin::Browser::Firefox => new_settings.nmh_firefox_ids.clone(),
    };
    match browser {
        kokos_nmh::origin::Browser::Chrome => {
            new_settings.nmh_chrome_ids =
                browser_ids_after_install(&new_settings.nmh_chrome_ids, &id);
        }
        kokos_nmh::origin::Browser::Firefox => {
            new_settings.nmh_firefox_ids =
                browser_ids_after_install(&new_settings.nmh_firefox_ids, &id);
        }
    }
    let new_ids = match browser {
        kokos_nmh::origin::Browser::Chrome => new_settings.nmh_chrome_ids.clone(),
        kokos_nmh::origin::Browser::Firefox => new_settings.nmh_firefox_ids.clone(),
    };
    crate::settings::save(&dir, &new_settings).map_err(|_| "internal".to_string())?;
    let nmh_enabled = new_settings.nmh_enabled;
    {
        let mut guard = state.settings.lock().map_err(|_| "internal".to_string())?;
        *guard = new_settings;
    }
    crate::nmh::invalidate_confirms(&app);

    let removed = crate::nmh::whitelist_removed_origins(&old_ids, &new_ids, browser.as_str());
    if crate::nmh::cascade_forget_origins(&app, &removed) > 0 {
        crate::nmh::handlers::audit_event(&app, "extension_grant_revoked", Some(browser.as_str()));
    }

    let running = *state.nmh.running.lock().map_err(|_| "internal".to_string())?;
    if nmh_enabled && !running {
        crate::nmh::start(app.clone());
    }
    Ok(())
}

/// Removes `browser`'s manifest and clears that browser's whitelisted ids.
/// `manifest::remove` is idempotent (a missing manifest is not an error), so
/// this only fails on an unsupported platform or an unexpected I/O error.
/// Whitelist mutation -> `invalidate_confirms` runs after the new (now
/// empty-for-this-browser) settings are committed, same reasoning as
/// `nmh_install` above: a grant or a parked prompt earned under the id(s)
/// just removed must not survive.
#[tauri::command]
pub fn nmh_uninstall(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    browser: String,
) -> CmdResult<()> {
    use tauri::Manager;
    let browser = parse_browser(&browser).map_err(|e| e.to_string())?;
    let home = nmh_home().ok_or_else(|| "unsupported_platform".to_string())?;
    crate::nmh::manifest::remove(browser, &home).map_err(|e| {
        if e.kind() == std::io::ErrorKind::Unsupported {
            "unsupported_platform".to_string()
        } else {
            "internal".to_string()
        }
    })?;

    let dir = app.path().app_config_dir().map_err(|_| "internal".to_string())?;
    let mut new_settings = state.settings.lock().map_err(|_| "internal".to_string())?.clone();
    let old_ids = match browser {
        kokos_nmh::origin::Browser::Chrome => new_settings.nmh_chrome_ids.clone(),
        kokos_nmh::origin::Browser::Firefox => new_settings.nmh_firefox_ids.clone(),
    };
    match browser {
        kokos_nmh::origin::Browser::Chrome => new_settings.nmh_chrome_ids.clear(),
        kokos_nmh::origin::Browser::Firefox => new_settings.nmh_firefox_ids.clear(),
    }
    // Fail closed: the manifest is already gone, so the live whitelist is
    // cleared BEFORE persisting. The listener reads `state.settings` on every
    // handshake and request, so a failed save must not leave the revoked
    // origin authorised in memory. The save error is still reported.
    let save_result = crate::settings::save(&dir, &new_settings);
    {
        let mut guard = state.settings.lock().map_err(|_| "internal".to_string())?;
        *guard = new_settings;
    }
    crate::nmh::invalidate_confirms(&app);

    let removed = crate::nmh::whitelist_removed_origins(&old_ids, &[], browser.as_str());
    if crate::nmh::cascade_forget_origins(&app, &removed) > 0 {
        crate::nmh::handlers::audit_event(&app, "extension_grant_revoked", Some(browser.as_str()));
    }
    save_result.map_err(|_| "internal".to_string())
}


/// Derives the display browser for a persistent grant's stored `origin`:
/// Chrome origins are always written as `chrome-extension://<id>/` (see
/// `kokos_nmh::origin::from_args` and
/// `whitelist_removed_origins`'s own doc comment for the exact shape a grant
/// is keyed under); anything else is a bare Firefox id (`name@domain` or
/// `{uuid}` -- `kokos_nmh::origin`'s module doc). Kept as its own pure seam
/// (no `AppHandle`/session needed) -- no `AppHandle` harness exists in this
/// repo, so every decision is factored into a pure, directly unit-tested
/// function -- so the UI never re-implements origin parsing itself.
fn browser_for_grant_origin(origin: &str) -> &'static str {
    if origin.starts_with("chrome-extension://") {
        kokos_nmh::origin::Browser::Chrome.as_str()
    } else {
        kokos_nmh::origin::Browser::Firefox.as_str()
    }
}

/// One persistent grant, shaped for the Settings "Saved permissions" list.
/// `browser` mirrors `kokos_core::nmh_grants::Grant` plus the derived display
/// browser -- see `browser_for_grant_origin` above.
#[derive(Serialize)]
pub struct NmhGrantDto {
    pub origin: String,
    pub browser: String,
    pub domain: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

fn to_grant_dto(g: kokos_core::nmh_grants::Grant) -> NmhGrantDto {
    let browser = browser_for_grant_origin(&g.origin).to_string();
    NmhGrantDto { origin: g.origin, browser, domain: g.domain, created_at: g.created_at, last_used_at: g.last_used_at }
}

/// Settings -> Browser integration -> "Saved permissions".
/// Read-only: brief session lock, no spawn_blocking -- same shape as
/// `list_entries`. A locked/closed vault has no `nmh_grants` table reachable
/// (it lives inside the encrypted vault, like every other core table) --
/// returns an empty list rather than an error, so the Settings section
/// simply does not render instead of surfacing a spurious failure banner.
#[tauri::command]
pub fn nmh_grants_list(state: State<'_, AppState>) -> CmdResult<Vec<NmhGrantDto>> {
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let Some(s) = reg.active_mut() else {
        return Ok(Vec::new());
    };
    let Some(v) = s.vault.as_ref() else {
        return Ok(Vec::new());
    };
    let rows = kokos_core::nmh_grants::list(&v.conn).map_err(|e| e.to_string())?;
    Ok(rows.into_iter().map(to_grant_dto).collect())
}

/// Revokes exactly one persistent grant -- the per-domain `x` in "Saved
/// permissions". An earlier version's revoke was silently undone by a
/// close/quit -- `delete`
/// alone only mutates the in-memory connection, and nothing else (not
/// `close_vault`, not `RunEvent::ExitRequested`, not `audit_event`) ever
/// saved it, so the extension's access resurrected on the next open. Now
/// follows the same `begin_borrow -> mutate+save -> end_borrow` discipline
/// every other vault-mutating command in this file uses -- mirrors
/// `delete_folder`/`delete_tag` exactly, including `spawn_blocking` for the
/// heavy serialize+encrypt+fsync (module doc comment at the top of this
/// file). Requires an open vault, unlike `nmh_grants_list` above: this is a
/// mutation, not a status read, so it follows the same `NoVaultOpen`
/// convention as every other vault-mutating command (e.g. `delete_entry`). A
/// save failure propagates as this command's own `Err` -- same as every
/// other mutating command here, never silently swallowed.
///
/// Audit AFTER `end_borrow`/the session guard is dropped -- `audit_event`
/// re-takes the session lock itself (`std::sync::Mutex` is not reentrant) --
/// and only when a row actually existed to remove AND the save succeeded
/// (both folded into `result`). `detail` = the revoked site's eTLD+1
/// (a single-grant revoke names the site).
#[tauri::command]
pub async fn nmh_grant_forget(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    origin: String,
    domain: String,
) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, None)?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let domain_for_audit = domain.clone();
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = kokos_core::nmh_grants::delete(&v.conn, &origin, &domain)
            .and_then(|removed| vault::save(&mut v).map(|_| removed));
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);

    let removed = result.map_err(|e| e.to_string())?;
    if removed {
        crate::nmh::handlers::audit_event(&app, "extension_grant_revoked", Some(&domain_for_audit));
    }
    Ok(())
}

/// Revokes every persistent grant for one extension origin -- the per-group
/// "Forget all" in "Saved permissions". Same fix and same shape as
/// `nmh_grant_forget` above (a group revoke must durably save too);
/// `detail` = the browser name rather than a domain (a group revoke names
/// the browser, not any one site) -- derived via `browser_for_grant_origin` rather than
/// re-parsing `origin` a second way.
#[tauri::command]
pub async fn nmh_grants_forget_origin(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    origin: String,
) -> CmdResult<u32> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, None)?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let origin_for_audit = origin.clone();
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = kokos_core::nmh_grants::delete_by_origin(&v.conn, &origin)
            .and_then(|count| vault::save(&mut v).map(|_| count));
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);

    let removed = result.map_err(|e| e.to_string())?;
    if removed > 0 {
        crate::nmh::handlers::audit_event(
            &app,
            "extension_grant_revoked",
            Some(browser_for_grant_origin(&origin_for_audit)),
        );
    }
    Ok(removed as u32)
}

/// Store the currently-open vault's master password in the OS keyring so the
/// user can fast-unlock next time. Requires an open vault (we key the keyring
/// entry by its path). We deliberately do NOT verify the password:
/// a wrong one just fails the next keychain_unlock and falls back to manual
/// entry. Secret boundary: the password goes only to the OS keyring.
#[tauri::command]
pub async fn keychain_enable(state: State<'_, AppState>, master_password: String) -> CmdResult<()> {
    let (id, path, requires_keyfile) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let id = resolve_vault_id(&reg, None)?;
        let s = reg
            .get_mut(&id)
            .ok_or_else(|| "no_vault".to_string())?;
        let v = s.vault
            .as_ref()
            .ok_or("no vault open")?;
        (id, v.path.to_string_lossy().to_string(), v.header.requires_keyfile())
    };
    fast_unlock_keyfile_guard(requires_keyfile)?;
    let master_password = Zeroizing::new(master_password);
    crate::keyring_store::store(&path, &master_password)
        .map_err(|_| "fast_unlock_store_failed".to_string())?;
    let borrowed = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        reg.get_mut(&id).and_then(|s| s.begin_borrow())
    };
    if let Some(mut v) = borrowed {
        let v = tauri::async_runtime::spawn_blocking(move || {
            let _ = kokos_core::audit::append(&v.conn, "keychain_enabled", None);
            let _ = vault::save(&mut v);
            v
        })
        .await
        .map_err(spawn_blocking_failed)?;
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(s) = reg.get_mut(&id) {
            s.end_borrow(v);
        }
    }
    Ok(())
}

/// Remove the open vault's stored master password from the OS keyring.
#[tauri::command]
pub async fn keychain_disable(state: State<'_, AppState>) -> CmdResult<()> {
    let (id, path) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let id = resolve_vault_id(&reg, None)?;
        let path = reg
            .get_mut(&id)
            .ok_or_else(|| "no_vault".to_string())?
            .vault
            .as_ref()
            .ok_or("no vault open")?
            .path
            .to_string_lossy()
            .to_string();
        (id, path)
    };
    crate::keyring_store::delete(&path).map_err(|e| e.to_string())?;
    let borrowed = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        reg.get_mut(&id).and_then(|s| s.begin_borrow())
    };
    if let Some(mut v) = borrowed {
        let v = tauri::async_runtime::spawn_blocking(move || {
            let _ = kokos_core::audit::append(&v.conn, "keychain_disabled", None);
            let _ = vault::save(&mut v);
            v
        })
        .await
        .map_err(spawn_blocking_failed)?;
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(s) = reg.get_mut(&id) {
            s.end_borrow(v);
        }
    }
    Ok(())
}

/// Whether a saved master password exists for `path` — lets Lock/Welcome
/// decide whether to show the fast-unlock button. Returns only a bool; no
/// secret is exposed — the call touches the filesystem only to canonicalise
/// `path` before querying the OS keyring. Allowlist-gated exactly like its
/// `keychain_unlock` sibling: a path the Rust side never handed
/// out returns `Ok(false)` (not an Err), so the button simply hides instead
/// of surfacing an error for an arbitrary guessed path.
#[tauri::command]
pub fn keychain_has(state: State<'_, AppState>, path: String) -> CmdResult<bool> {
    if !crate::paths::is_allowed(&state.allowed_paths, &path) {
        return Ok(false);
    }
    Ok(crate::keyring_store::has(&path))
}

/// Fast-unlock: read the stored master password from the OS keyring and open
/// the vault, without the user typing anything. Mirrors `open_vault` (KDF runs
/// in spawn_blocking) but sources the password from the keyring instead of the
/// WebView. The password stays in the backend; only `VaultInfo` is returned
/// (same secret boundary as reveal_field/totp_code).
#[tauri::command]
pub async fn keychain_unlock(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    path: String,
) -> CmdResult<VaultInfo> {
    use tauri::Emitter;
    if !crate::paths::is_allowed(&state.allowed_paths, &path) {
        return Err(VaultError::PathNotAllowed.to_string());
    }
    {
        let reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(s) = reg.get(&path) {
            ensure_no_vault_open(s)?;
        }
    }
    let pw = {
        let fetched = crate::keyring_store::fetch(&path).map_err(|e| e.to_string())?;
        Zeroizing::new(fetched.ok_or("no saved password")?.into_bytes())
    };
    let open_path = PathBuf::from(&path);
    let mut v = tauri::async_runtime::spawn_blocking(move || vault::open(&open_path, &pw, None))
        .await
        .map_err(spawn_blocking_failed)?
        .map_err(|e| e.to_string())?;

    let v = tauri::async_runtime::spawn_blocking(move || {
        let _ = kokos_core::audit::append(&v.conn, "unlock", None);
        let _ = vault::save_opened(&mut v);
        v
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let result = info(&v)?;
    let vault_id = v.path.to_string_lossy().to_string();
    {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(s) = reg.get(&path) {
            ensure_no_vault_open(s)?;
        }
        let mut session = Session::new();
        session.vault = Some(v);
        reg.insert(vault_id.clone(), session);
    }
    mark_restored_unlocked(&state, &vault_id);
    push_recent(&app, &path, false);
    *state.last_activity.lock().map_err(|e| e.to_string())? = std::time::Instant::now();
    let _ = app.emit("vault-unlocked", serde_json::json!({ "vault_id": vault_id }));
    persist_open_vaults(&app, &state);
    Ok(result)
}

/// Hardware + enrollment probe (never prompts) — lets Settings and
/// the Lock screen decide whether to offer Touch ID at all.
#[tauri::command]
pub fn biometric_available() -> CmdResult<bool> {
    Ok(crate::biometric_macos::is_biometric_available())
}

/// Fast-unlock stores only the master password; a key-file vault also needs
/// the key file to open, so a stored copy could never unlock it. Refuse to
/// enable fast-unlock there. Returns a stable snake_case token
/// (the front end translates it) — no secret, no key file ever
/// enters the Keychain, and the token carries no oracle.
fn fast_unlock_keyfile_guard(requires_keyfile: bool) -> CmdResult<()> {
    if requires_keyfile {
        Err("fast_unlock_keyfile_unsupported".to_string())
    } else {
        Ok(())
    }
}

/// Store the currently-open vault's master password behind a Touch ID gate
/// (a "Kokos-Biometric" Keychain item, distinct from keychain_enable's plain
/// keyring entry — see biometric_macos.rs module docs). Requires an open vault (keys
/// by its path, mirrors keychain_enable). No verify: a
/// wrong one just fails the next touchid_unlock and falls back to manual
/// entry. Secret boundary: the password goes only to the backend
/// biometric store.
#[tauri::command]
pub fn biometric_enable(state: State<'_, AppState>, master_password: String) -> CmdResult<()> {
    let (path, requires_keyfile) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let id = resolve_vault_id(&reg, None)?;
        let s = reg.get_mut(&id).ok_or_else(|| "no_vault".to_string())?;
        let v = s.vault.as_ref().ok_or("no vault open")?;
        (v.path.to_string_lossy().to_string(), v.header.requires_keyfile())
    };
    fast_unlock_keyfile_guard(requires_keyfile)?;
    let master_password = Zeroizing::new(master_password);
    crate::biometric_macos::store_biometric(&path, &master_password)
}

/// Remove the open vault's Touch ID entry. Mirrors keychain_disable.
#[tauri::command]
pub fn biometric_disable(state: State<'_, AppState>) -> CmdResult<()> {
    let path = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let id = resolve_vault_id(&reg, None)?;
        let s = reg.get_mut(&id).ok_or_else(|| "no_vault".to_string())?;
        let v = s.vault.as_ref().ok_or("no vault open")?;
        v.path.to_string_lossy().to_string()
    };
    crate::biometric_macos::delete_biometric(&path)
}

/// Whether a Touch ID-gated master password exists for `path` — mirrors
/// `keychain_has`. Allowlist-gated exactly like its `touchid_unlock` sibling
/// reports only whether a "Kokos-Biometric" Keychain item
/// exists, reads no file, exposes no secret, and (per `has_biometric`'s own
/// contract) never prompts. A path the Rust side never handed out returns
/// `Ok(false)` (not an Err), so the button simply hides.
#[tauri::command]
pub fn biometric_has(state: State<'_, AppState>, path: String) -> CmdResult<bool> {
    if !crate::paths::is_allowed(&state.allowed_paths, &path) {
        return Ok(false);
    }
    Ok(crate::biometric_macos::has_biometric(&path))
}

/// Fast-unlock via Touch ID: present the OS Touch ID sheet, read the stored
/// master password back, and open the vault — without the user typing
/// anything. Mirrors `keychain_unlock`, but `unlock_biometric` is
/// INTERACTIVE (blocks for as long as the OS prompt is up), so the Touch ID
/// read and the `vault::open` KDF both run inside the SAME `spawn_blocking`
/// closure: the plaintext password is created and consumed entirely on the
/// blocking thread and never lands in this async fn's scope — a strictly
/// tighter secret boundary than keychain_unlock's.
#[tauri::command]
pub async fn touchid_unlock(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    path: String,
) -> CmdResult<VaultInfo> {
    use tauri::Emitter;
    if !crate::paths::is_allowed(&state.allowed_paths, &path) {
        return Err(VaultError::PathNotAllowed.to_string());
    }
    {
        let reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(s) = reg.get(&path) {
            ensure_no_vault_open(s)?;
        }
    }
    let open_path = PathBuf::from(&path);
    let read_path = path.clone();
    let mut v = tauri::async_runtime::spawn_blocking(move || -> Result<vault::OpenVault, String> {
        let pw = Zeroizing::new(crate::biometric_macos::unlock_biometric(&read_path)?.into_bytes());
        vault::open(&open_path, &pw, None).map_err(|e| e.to_string())
    })
    .await
    .map_err(spawn_blocking_failed)??;

    let v = tauri::async_runtime::spawn_blocking(move || {
        let _ = kokos_core::audit::append(&v.conn, "unlock", None);
        let _ = vault::save_opened(&mut v);
        v
    })
    .await
    .map_err(spawn_blocking_failed)?;

    let result = info(&v)?;
    let vault_id = v.path.to_string_lossy().to_string();
    {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(s) = reg.get(&path) {
            ensure_no_vault_open(s)?;
        }
        let mut session = Session::new();
        session.vault = Some(v);
        reg.insert(vault_id.clone(), session);
    }
    mark_restored_unlocked(&state, &vault_id);
    push_recent(&app, &path, false);
    *state.last_activity.lock().map_err(|e| e.to_string())? = std::time::Instant::now();
    let _ = app.emit("vault-unlocked", serde_json::json!({ "vault_id": vault_id }));
    persist_open_vaults(&app, &state);
    Ok(result)
}

/// The bundle version, for Settings -> About. Same source as the NMH
/// handshake's `app_version` (see `nmh/handlers.rs`).
#[tauri::command]
pub fn app_version(app: tauri::AppHandle) -> String {
    app.package_info().version.to_string()
}

/// Read-only security audit log: brief session lock, no
/// spawn_blocking, no save — same shape as list_tags / reveal_field.
#[tauri::command]
pub fn list_audit(state: State<'_, AppState>, vault_id: Option<String>, limit: u32) -> CmdResult<Vec<kokos_core::audit::AuditEntry>> {
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
    let s = reg.get_mut(&vid).ok_or_else(|| "no_vault".to_string())?;
    let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
    kokos_core::audit::list(&v.conn, limit).map_err(|e| e.to_string())
}

/// Clears the audit log. Mutation → begin_borrow/
/// spawn_blocking(clear + save)/end_borrow, same shape as delete_folder. The
/// clear itself is NOT audited — no audit::append here.
#[tauri::command]
pub async fn clear_audit(state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let outcome = kokos_core::audit::clear(&v.conn).and_then(|_| vault::save(&mut v));
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}


/// Write `text` to the OS clipboard. `text` is a plaintext secret that has
/// already crossed the IPC boundary once via `reveal_field` (the secret
/// boundary allows re-crossing here); it is wrapped in `Zeroizing` on arrival and never
/// logged. On failure only a static string is returned — never arboard's own
/// error or the text.
#[tauri::command]
pub fn set_clipboard(text: String) -> CmdResult<()> {
    let text = Zeroizing::new(text);
    let mut cb = arboard::Clipboard::new().map_err(|_| "clipboard unavailable".to_string())?;
    cb.set_text(text.as_str()).map_err(|_| "clipboard write failed".to_string())
}

/// Unconditional best-effort clipboard blank — native counterpart to the
/// lock paths' `clearClipboard()` (`lib/clipboard.ts`). Mirrors the
/// exit-hook's own `set_text("")`.
#[tauri::command]
pub fn clear_clipboard() -> CmdResult<()> {
    let mut cb = arboard::Clipboard::new().map_err(|_| "clipboard unavailable".to_string())?;
    cb.set_text("").map_err(|_| "clipboard clear failed".to_string())
}

/// Clears the OS clipboard only if it still holds `expected`, so a countdown
/// firing after the user has already copied something else does not wipe
/// their new clipboard content. If the read itself fails, clears
/// unconditionally — the safe default for a secret, mirroring the former
/// frontend-only `clearIfUnchanged`. `expected` is wrapped in `Zeroizing` on
/// arrival and never logged.
#[tauri::command]
pub fn clear_clipboard_if_unchanged(expected: String) -> CmdResult<()> {
    let expected = Zeroizing::new(expected);
    let mut cb = arboard::Clipboard::new().map_err(|_| "clipboard unavailable".to_string())?;
    match cb.get_text() {
        Ok(current) => {
            let current = Zeroizing::new(current);
            if *current == *expected {
                cb.set_text("").map_err(|_| "clipboard clear failed".to_string())
            } else {
                Ok(())
            }
        }
        Err(_) => cb.set_text("").map_err(|_| "clipboard clear failed".to_string()),
    }
}

/// Drains a path buffered from a file-association launch (macOS `RunEvent::Opened`
/// or an argv path), so the Welcome screen can auto-open it on mount. Returns the
/// path once, then null.
#[tauri::command]
pub fn take_pending_open(state: tauri::State<crate::state::AppState>) -> Option<String> {
    state
        .pending_open
        .lock()
        .ok()
        .and_then(|mut g| g.take())
        .map(|p| p.to_string_lossy().into_owned())
}

/// Same borrow discipline as `export_vault_copy`/`import_json` (needs an owned `OpenVault` across spawn_blocking to call
/// `vault::save`). Loops over already-tested per-entry core fns; one
/// `vault::save` per call (not per entry). Returns the count actually
/// deleted (`entries::soft_delete`'s `Ok(false)` no-op for an already-gone id
/// is not counted).
#[tauri::command]
pub async fn bulk_delete_entries(state: State<'_, AppState>, vault_id: Option<String>, ids: Vec<String>) -> CmdResult<u32> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = (|| -> Result<u32, kokos_core::error::VaultError> {
            let mut n = 0u32;
            for id in &ids {
                if kokos_core::entries::soft_delete(&v.conn, id, now)? {
                    n += 1;
                }
            }
            vault::save(&mut v)?;
            Ok(n)
        })();
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

/// Moves each id to `folder_id` via
/// `entries::update` + `EntryPatch` (only `folder_id` set, the other 4
/// fields `None` = leave unchanged). A missing/deleted id's `Ok(None)` is a
/// silent per-entry no-op, same spirit as `bulk_delete_entries`'s `Ok(false)`.
#[tauri::command]
pub async fn bulk_move_entries(state: State<'_, AppState>, vault_id: Option<String>, ids: Vec<String>, folder_id: String) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = (|| -> Result<(), kokos_core::error::VaultError> {
            for id in &ids {
                kokos_core::entries::update(
                    &v.conn,
                    id,
                    kokos_core::entries::EntryPatch {
                        title: None,
                        notes: None,
                        is_favorite: None,
                        folder_id: Some(folder_id.clone()),
                        fields: None,
                    },
                    now,
                )?;
            }
            vault::save(&mut v)?;
            Ok(())
        })();
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

/// Adds (`add: true`) or removes (`add: false`)
/// `tag_id` on every id via `tags::set_entry_tag`. A stale/missing id must be
/// a silent per-entry no-op here too, uniform with `bulk_delete_entries`/
/// `bulk_move_entries` -- but `set_entry_tag` does not surface that uniformly
/// across the two directions: on `add=false` a truly-missing id's 0-row
/// `UPDATE entries` yields a clean `Err(EntryNotFound)`, while on `add=true`
/// the earlier `INSERT OR IGNORE INTO entry_tags` hits `entry_tags.entry_id`'s
/// FK FIRST -- SQLite's IGNORE conflict-resolution algorithm does not apply
/// to foreign-key violations, it behaves like ABORT there instead
/// (sqlite.org/lang_conflict.html) -- so that surfaces as a bare
/// `VaultError::Db` string indistinguishable from a genuine DB failure.
/// Rather than match one error shape and miss the other, or blanket-catch
/// `Db` and risk swallowing a real failure, each id is pre-checked with the
/// same liveness guard `entries::update` already uses (`is_deleted = 0`)
/// before `set_entry_tag` ever runs, so a stale id is skipped in both
/// directions and a genuine error on a live id still propagates via `?`.
#[tauri::command]
pub async fn bulk_set_tag(state: State<'_, AppState>, vault_id: Option<String>, ids: Vec<String>, tag_id: String, add: bool) -> CmdResult<()> {
    let (vid, mut v) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = resolve_vault_id(&reg, vault_id.as_deref())?;
        let v = reg
            .get_mut(&vid)
            .ok_or_else(|| "no_vault".to_string())?
            .begin_borrow()
            .ok_or(VaultError::NoVaultOpen.to_string())?;
        (vid, v)
    };
    let (v, result) = tauri::async_runtime::spawn_blocking(move || {
        let now = kokos_core::db::now_unix();
        let outcome = (|| -> Result<(), kokos_core::error::VaultError> {
            for id in &ids {
                let exists: i64 = v.conn.query_row(
                    "SELECT COUNT(*) FROM entries WHERE id = ?1 AND is_deleted = 0",
                    [id],
                    |r| r.get(0),
                )?;
                if exists == 0 {
                    continue;
                }
                kokos_core::tags::set_entry_tag(&v.conn, id, &tag_id, add, now)?;
            }
            vault::save(&mut v)?;
            Ok(())
        })();
        (v, outcome)
    })
    .await
    .map_err(spawn_blocking_failed)?;
    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
    reg.get_mut(&vid)
        .ok_or_else(|| "no_vault".to_string())?
        .end_borrow(v);
    drop(reg);
    result.map_err(|e| e.to_string())
}

/// Enable folder sync for the CURRENTLY OPEN vault at its own path (open-in-place:
/// the working vault IS the file in the synced folder — no picker, no move).
#[tauri::command]
pub async fn sync_set_folder(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<()> {
    use tauri::Manager;
    let path = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let id = resolve_vault_id(&reg, vault_id.as_deref())?;
        let s = reg.get_mut(&id).ok_or_else(|| "no_vault".to_string())?;
        let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
        v.path.to_string_lossy().to_string()
    };
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    crate::sync_config::save(&dir, &path, &crate::sync_config::SyncTarget::Folder { path: path.clone() })
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Clear this vault's sync target. (GDrive token teardown, when it exists, is
/// handled by `gdrive_disconnect`; here we only clear the target.)
#[tauri::command]
pub async fn sync_disable(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<()> {
    use tauri::Manager;
    let path = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let id = resolve_vault_id(&reg, vault_id.as_deref())?;
        let s = reg.get_mut(&id).ok_or_else(|| "no_vault".to_string())?;
        let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
        v.path.to_string_lossy().to_string()
    };
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    crate::sync_config::save(&dir, &path, &crate::sync_config::SyncTarget::None).map_err(|e| e.to_string())?;
    Ok(())
}

/// Report the current sync target + folder-mode conflict/soft-warning signals.
/// Returns `kind:"none"` when no vault is open.
#[tauri::command]
pub fn sync_status(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<SyncStatusInfo> {
    use tauri::Manager;
    let path = {
        let reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let s = reg.resolve(vault_id.as_deref()).map(str::to_string).and_then(|id| reg.get(&id));
        match s.and_then(|s| s.vault.as_ref()) {
            Some(v) => v.path.to_string_lossy().to_string(),
            None => return Ok(SyncStatusInfo {
                kind: "none".into(), folder_path: None, gdrive_connected: false,
                last_sync: 0, conflicts: vec![], not_synced_warning: false, note: None,
            }),
        }
    };
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    let info = match crate::sync_config::load(&dir, &path) {
        crate::sync_config::SyncTarget::None => SyncStatusInfo {
            kind: "none".into(), folder_path: None, gdrive_connected: false,
            last_sync: 0, conflicts: vec![], not_synced_warning: false, note: None,
        },
        crate::sync_config::SyncTarget::Folder { path: fp } => {
            let p = std::path::Path::new(&fp);
            SyncStatusInfo {
                kind: "folder".into(),
                folder_path: Some(fp.clone()),
                gdrive_connected: false,
                last_sync: 0,
                conflicts: crate::synced_folder::sibling_conflicts(p),
                not_synced_warning: !crate::synced_folder::looks_synced(p),
                note: None,
            }
        }
        crate::sync_config::SyncTarget::Gdrive { file_id, last_sync, note, .. } => SyncStatusInfo {
            kind: "gdrive".into(), folder_path: None,
            gdrive_connected: file_id.is_some(), last_sync,
            conflicts: vec![], not_synced_warning: false, note,
        },
    };
    Ok(info)
}

/// Process-wide cancel flag for the OAuth wait. One dance at a time is the
/// only sane shape — it owns the user's browser — so a single flag suffices.
/// Every flow CLEARS it on entry: a stale cancel would otherwise kill the
/// next attempt before it started.
static OAUTH_CANCEL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Run the Google OAuth Installed-App PKCE dance end-to-end (bind loopback,
/// open consent page, block for redirect, exchange code) and return the
/// refresh_token. BLOCKING — call inside spawn_blocking. Shared by
/// `gdrive_connect` and `gdrive_restore_signin`.
fn run_oauth_pkce() -> Result<String, String> {
    use crate::gdrive::oauth;
    OAUTH_CANCEL.store(false, std::sync::atomic::Ordering::Relaxed);
    let state_tok = uuid::Uuid::new_v4().simple().to_string();
    let pkce = oauth::make_pkce();
    let (tx, rx) = std::sync::mpsc::channel();
    let expected = state_tok.clone();
    let listener = std::thread::spawn(move || {
        oauth::listen_for_code_reporting(&expected, std::time::Duration::from_secs(180), tx, &OAUTH_CANCEL)
    });
    let redirect_uri = rx.recv().map_err(|_| "listener failed to start".to_string())?;
    let url = oauth::consent_url(&pkce.challenge, &redirect_uri, &state_tok);
    open::that(&url).map_err(|e| format!("open browser: {e}"))?;
    let (code, redirect_uri2) = listener
        .join()
        .map_err(|_| "listener panicked".to_string())?
        .map_err(|e| e.to_string())?;
    let tok = oauth::exchange_code(&code, &pkce.verifier, &redirect_uri2).map_err(|e| e.to_string())?;
    tok.refresh_token
        .ok_or("Google did not return a refresh_token (re-consent required)".to_string())
}

/// Run the Google Drive OAuth PKCE flow end-to-end for the currently open
/// vault: bind a loopback listener, open the consent page once the port is
/// known, block for the redirect, exchange the code, and persist the
/// refresh_token in the OS keyring (never in `sync.json`, never to the
/// WebView). Sets this vault's sync target to Gdrive on success.
#[tauri::command]
pub async fn gdrive_connect(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<()> {
    use tauri::Manager;
    let (id, vault_path, device_id) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let id = resolve_vault_id(&reg, vault_id.as_deref())?;
        let s = reg.get_mut(&id).ok_or_else(|| "no_vault".to_string())?;
        let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
        let device_id = kokos_core::db::get_device_id(&v.conn).map_err(|e| e.to_string())?;
        (id, v.path.to_string_lossy().to_string(), device_id)
    };
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;

    let refresh = tauri::async_runtime::spawn_blocking(run_oauth_pkce)
        .await
        .map_err(spawn_blocking_failed)??;

    crate::keyring_store::gdrive_store(&vault_path, &refresh).map_err(|e| e.to_string())?;
    crate::sync_config::save(
        &dir,
        &vault_path,
        &crate::sync_config::SyncTarget::Gdrive {
            file_id: None,
            rev: 0,
            last_sync: 0,
            remote_name: Some(crate::sync_config::remote_name_for_device(&device_id)),
            note: None,
        },
    )
    .map_err(|e| e.to_string())?;
    {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(v) = reg.get_mut(&id).and_then(|s| s.vault.as_ref()) {
            let _ = kokos_core::audit::append(&v.conn, "sync_connected", None);
        }
    }
    Ok(())
}

/// Abandon an OAuth wait started by `gdrive_connect` or
/// `gdrive_restore_signin`. Closing the consent tab sends nothing back — only
/// an explicit deny redirects with `error=` — so without this the listener
/// would hold the UI for its full 180-second deadline. Idempotent: setting the
/// flag with nothing in flight is harmless, the next flow clears it on entry.
#[tauri::command]
pub fn gdrive_connect_cancel() {
    OAUTH_CANCEL.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Tear down the Gdrive sync target: drop the keyring refresh_token (best
/// effort — a missing entry is not an error) and clear this vault's sync
/// target back to `None`.
#[tauri::command]
pub async fn gdrive_disconnect(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<()> {
    use tauri::Manager;
    let (id, vault_path) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let id = resolve_vault_id(&reg, vault_id.as_deref())?;
        let s = reg.get_mut(&id).ok_or_else(|| "no_vault".to_string())?;
        let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
        (id, v.path.to_string_lossy().to_string())
    };
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    let _ = crate::keyring_store::gdrive_delete(&vault_path);
    crate::sync_config::save(&dir, &vault_path, &crate::sync_config::SyncTarget::None)
        .map_err(|e| e.to_string())?;
    {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(v) = reg.get_mut(&id).and_then(|s| s.vault.as_ref()) {
            let _ = kokos_core::audit::append(&v.conn, "sync_disconnected", None);
        }
    }
    Ok(())
}

/// Set (or clear, with an empty string) the user-facing backup note for this
/// vault's Gdrive target. Persists onto `sync.json` immediately, and — when a
/// remote file already exists (`file_id: Some`) — also PATCHes the note into
/// the Drive file's appProperties right away (metadata-only, no upload) so the
/// restore list reflects it without waiting for the next push.
#[tauri::command]
pub async fn gdrive_set_note(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: Option<String>, note: String) -> CmdResult<()> {
    use tauri::Manager;
    let mut note = note;
    while note.len() > 120 {
        note.pop();
    }
    let vault_path = {
        let reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let id = resolve_vault_id(&reg, vault_id.as_deref())?;
        let s = reg.get(&id).ok_or_else(|| "no_vault".to_string())?;
        s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?.path.to_string_lossy().to_string()
    };
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    let (file_id, rev, last_sync, remote_name) = match crate::sync_config::load(&dir, &vault_path) {
        crate::sync_config::SyncTarget::Gdrive { file_id, rev, last_sync, remote_name, .. } => (file_id, rev, last_sync, remote_name),
        _ => return Err("not a Google Drive target".into()),
    };
    let note_opt = if note.is_empty() { None } else { Some(note.clone()) };
    crate::sync_config::save(&dir, &vault_path, &crate::sync_config::SyncTarget::Gdrive {
        file_id: file_id.clone(), rev, last_sync, remote_name: remote_name.clone(), note: note_opt,
    }).map_err(|e| e.to_string())?;
    if let Some(fid) = file_id {
        let vault_path2 = vault_path.clone();
        tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
            let name = remote_name.as_deref().unwrap_or(crate::gdrive::api::FILE_NAME);
            let client = gdrive_client_for(&vault_path2, name)?;
            client.patch_app_properties(&fid, &note)
        })
        .await
        .map_err(spawn_blocking_failed)??;
    }
    Ok(())
}


use kokos_core::sync::{resolve_lww, SyncDecision, SyncMeta, SyncRemote};

/// Result of a sync operation, serialized to the frontend (`sync_now`).
#[derive(serde::Serialize, Default)]
pub struct SyncOutcome {
    pub pushed: bool,
    pub pulled: bool,
    pub requires_reopen: bool,
    pub remote_newer: bool,
    pub conflicts: Vec<String>,
}

/// Controls how `gdrive_sync_gathered` reacts to a `PullRemote` LWW decision;
/// `PushLocal`/`InSync` are mode-independent (see the function body).
#[derive(Clone, Copy, PartialEq, Eq)]
enum PullMode {
    Skip,
    Detect,
    Apply,
}

/// Pure (I/O-free) outcome for a `(decision, mode)` pair. The only combination
/// that skips real network work is `PullRemote` under `Skip`/`Detect`: `Skip`
/// leaves a newer remote alone (auto path never overwrites; local changes
/// reconcile on the next open/pull) and `Detect` flags `remote_newer` for a
/// non-intrusive banner. Every other combination returns `None` -- the caller
/// performs the real I/O inline: `PushLocal`/`InSync` always push/save-baseline
/// regardless of mode, and `PullRemote` + `Apply` performs the actual download
/// + backup + overwrite. Extracted (and unit-tested directly, see the `tests`
/// module) because `gdrive_sync_gathered` needs a live `DriveClient` -- a
/// stored refresh token + network -- for every path this helper does NOT
/// cover, so there is no way to exercise the mode branching itself through a
/// fake/mock remote.
fn pull_mode_outcome(decision: SyncDecision, mode: PullMode) -> Option<SyncOutcome> {
    match (decision, mode) {
        (SyncDecision::PullRemote, PullMode::Skip) => Some(SyncOutcome::default()),
        (SyncDecision::PullRemote, PullMode::Detect) => {
            Some(SyncOutcome { remote_newer: true, ..Default::default() })
        }
        _ => None,
    }
}

/// Whether `mode` wants to reconcile past the trivial "nothing changed since
/// the last sync" shortcut: `Skip` (auto push-on-lock/close) never does --
/// it is a fire-and-forget push attempt, so both the early auto-skip and the
/// convergence guard below stop it from probing the remote at all beyond
/// that. `Detect` and `Apply` both must: `Detect` has no other way to learn
/// a newer remote exists, and `Apply` is the manual reconcile. Extracted
/// (and unit-tested directly) so an inverted comparison here -- which would
/// compile and still pass every I/O-shaped test -- cannot silently flip
/// Detect back to Skip's silent behavior.
fn mode_may_reconcile(mode: PullMode) -> bool {
    mode != PullMode::Skip
}

/// Build a DriveClient from the vault's stored refresh_token, persisting a
/// rotated refresh_token back to the keyring if Google returned a new one.
/// Blocking — call inside spawn_blocking.
fn gdrive_client_for(vault_path: &str, file_name: &str) -> Result<crate::gdrive::api::DriveClient, String> {
    let refresh = crate::keyring_store::gdrive_fetch(vault_path)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no gdrive token".to_string())?;
    let client = crate::gdrive::api::DriveClient::new(&refresh, file_name)?;
    if let Some(rotated) = client.rotated_refresh() {
        let _ = crate::keyring_store::gdrive_store(vault_path, rotated);
    }
    Ok(client)
}

/// Persist the last-synced Gdrive baseline (file id + revision + timestamp).
/// `remote_name` is passed in (from the target loaded at the start of the sync)
/// rather than re-loaded here, so a baseline save can never blank it — and never
/// resurrect a stale name from a sync.json that was concurrently disconnected.
fn save_gdrive_baseline(dir: &std::path::Path, vault_path: &str, file_id: &str, rev: u64, remote_name: Option<&str>, note: Option<&str>) -> Result<(), String> {
    crate::sync_config::save(dir, vault_path, &crate::sync_config::SyncTarget::Gdrive {
        file_id: Some(file_id.to_string()),
        rev,
        last_sync: kokos_core::db::now_unix(),
        remote_name: remote_name.map(|s| s.to_string()),
        note: note.map(|s| s.to_string()),
    }).map_err(|e| e.to_string())
}

/// The vault's filename (with extension) for the backup's `vault_name` appProperty.
fn backup_vault_name(vault_path: &str) -> String {
    std::path::Path::new(vault_path).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()
}

/// Copy the current on-disk vault to a UNIQUE, non-destructive conflict backup
/// (`<vault>.conflict-r<rev>-<unix>.bak`) before a pull overwrites it — so a
/// later pull can never destroy an earlier displaced copy (unlike
/// `atomic::backup`, which reuses the single `.bak`). Best-effort; returns the
/// backup path if made.
fn backup_conflict_copy(p: &std::path::Path, local_rev: u64) -> Option<std::path::PathBuf> {
    if !p.exists() {
        return None;
    }
    let name = format!("{}.conflict-r{}-{}.bak", p.to_string_lossy(), local_rev, kokos_core::db::now_unix());
    let cp = std::path::PathBuf::from(name);
    std::fs::copy(p, &cp).ok().map(|_| cp)
}

/// LWW sync for one open vault from an OWNED snapshot (`local_meta.device`
/// already carries the per-MACHINE id). Networked — call inside spawn_blocking.
/// `PullMode::Skip` (auto push-on-lock/close): push ONLY when local wins LWW;
/// never overwrite a newer remote, never pull. `PullMode::Detect` (background
/// open-sync): same push-when-local-wins, but flags `remote_newer` instead of
/// silently skipping when the remote is ahead — never pulls, overwrites, or
/// locks. `PullMode::Apply` (manual "Sync now"): full LWW incl. download +
/// pre-`.bak` + overwrite (sets `pulled` / `requires_reopen`; the CALLER must
/// then lock the session so no stale in-memory save clobbers the freshly-
/// pulled file).
fn gdrive_sync_gathered(
    app: &tauri::AppHandle,
    vault_path: &str,
    local_meta: &SyncMeta,
    bytes: &[u8],
    mode: PullMode,
) -> Result<SyncOutcome, String> {
    use tauri::Manager;
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    let (file_id, baseline, remote_name, note) = match crate::sync_config::load(&dir, vault_path) {
        crate::sync_config::SyncTarget::Gdrive { file_id, rev, remote_name, note, .. } => (file_id, rev, remote_name, note),
        _ => return Ok(SyncOutcome::default()),
    };
    if !mode_may_reconcile(mode) && local_meta.rev <= baseline && file_id.is_some() {
        return Ok(SyncOutcome::default());
    }
    let name = remote_name.as_deref().unwrap_or(crate::gdrive::api::FILE_NAME);
    let client = gdrive_client_for(vault_path, name)?
        .with_labels(backup_vault_name(vault_path), note.clone().unwrap_or_default());
    let fid = match file_id.clone().or_else(|| client.find_file().ok().flatten()) {
        Some(f) => f,
        None => {
            let new_fid = client.create(bytes, local_meta)?;
            save_gdrive_baseline(&dir, vault_path, &new_fid, local_meta.rev, remote_name.as_deref(), note.as_deref())?;
            return Ok(SyncOutcome { pushed: true, ..Default::default() });
        }
    };
    let remote = crate::gdrive::api::GdriveRemote { client, file_id: fid.clone() };
    let remote_meta = remote.remote_meta().map_err(|e| e.to_string())?;
    if mode_may_reconcile(mode)
        && local_meta.rev <= baseline
        && remote_meta.as_ref().map_or(false, |m| m.rev <= baseline)
    {
        save_gdrive_baseline(&dir, vault_path, &fid, baseline, remote_name.as_deref(), note.as_deref())?;
        return Ok(SyncOutcome::default());
    }
    let decision = resolve_lww(local_meta, remote_meta.as_ref());
    match decision {
        SyncDecision::PushLocal => {
            remote.push(bytes, local_meta).map_err(|e| e.to_string())?;
            save_gdrive_baseline(&dir, vault_path, &fid, local_meta.rev, remote_name.as_deref(), note.as_deref())?;
            Ok(SyncOutcome { pushed: true, ..Default::default() })
        }
        SyncDecision::PullRemote => {
            if let Some(outcome) = pull_mode_outcome(decision, mode) {
                return Ok(outcome);
            }
            let remote_rev = remote_meta.as_ref().map(|m| m.rev).unwrap_or(baseline);
            let downloaded = remote.pull().map_err(|e| e.to_string())?;
            let p = std::path::Path::new(vault_path);
            let _ = backup_conflict_copy(p, local_meta.rev);
            std::fs::write(p, &downloaded).map_err(|e| e.to_string())?;
            save_gdrive_baseline(&dir, vault_path, &fid, remote_rev, remote_name.as_deref(), note.as_deref())?;
            Ok(SyncOutcome { pulled: true, requires_reopen: true, ..Default::default() })
        }
        SyncDecision::InSync => {
            save_gdrive_baseline(&dir, vault_path, &fid, baseline.max(local_meta.rev), remote_name.as_deref(), note.as_deref())?;
            Ok(SyncOutcome::default())
        }
    }
}

/// Snapshot an OPEN vault's inputs for an AUTO push (lock/close): the
/// per-MACHINE-stamped ordering meta + the on-disk ciphertext, but only when
/// this is a gdrive target with unsynced local changes (`rev > baseline`).
/// Returns None otherwise (nothing to push -> no later network). Reads the
/// vault file, so run it while the vault is open (inside the save closure for
/// lock, or under the session lock for close).
fn gather_gdrive_auto_push(app: &tauri::AppHandle, v: &kokos_core::vault::OpenVault) -> Option<(String, SyncMeta, Vec<u8>)> {
    use tauri::Manager;
    let dir = app.path().app_config_dir().ok()?;
    let vault_path = v.path.to_string_lossy().to_string();
    let crate::sync_config::SyncTarget::Gdrive { rev: baseline, .. } =
        crate::sync_config::load(&dir, &vault_path) else { return None };
    let mut meta = v.sync_meta().ok()?;
    if meta.rev <= baseline { return None; }
    meta.device = crate::device::cached(&dir);
    let bytes = std::fs::read(&v.path).ok()?;
    Some((vault_path, meta, bytes))
}

/// True when `file_id` is one of the files a prior signin stashed. Guards
/// download against an arbitrary id injected from the WebView.
fn restore_file_known(files: &[crate::gdrive::api::RemoteFile], file_id: &str) -> bool {
    files.iter().any(|f| f.id == file_id)
}

/// Manual "Sync now" for the currently open vault. Folder targets materialize +
/// report conflict siblings. Gdrive targets run the full LWW reconcile with the
/// true local rev (push when local wins; pull with a non-destructive conflict
/// backup when the remote wins). The vault is borrowed out across the pull so the
/// idle-lock watcher can't clobber it; a pull sets `requires_reopen` and locks the
/// session (unlock to load the pulled state). All network work runs off the runtime.
#[tauri::command]
pub async fn sync_now(app: tauri::AppHandle, state: State<'_, AppState>, vault_id: Option<String>) -> CmdResult<SyncOutcome> {
    use tauri::Manager;
    let (id, vault_path) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let id = resolve_vault_id(&reg, vault_id.as_deref())?;
        let s = reg.get_mut(&id).ok_or_else(|| "no_vault".to_string())?;
        let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
        (id, v.path.to_string_lossy().to_string())
    };
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    match crate::sync_config::load(&dir, &vault_path) {
        crate::sync_config::SyncTarget::None => Ok(SyncOutcome::default()),
        crate::sync_config::SyncTarget::Folder { path } => {
            let outcome = tauri::async_runtime::spawn_blocking(move || {
                let p = std::path::Path::new(&path);
                let _ = crate::icloud_macos::ensure_materialized(p);
                SyncOutcome { conflicts: crate::synced_folder::sibling_conflicts(p), ..Default::default() }
            })
            .await
            .map_err(spawn_blocking_failed)?;
            Ok(outcome)
        }
        crate::sync_config::SyncTarget::Gdrive { .. } => {
            let borrowed = {
                let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
                reg.get_mut(&id).and_then(|s| s.begin_borrow())
            };
            let Some(v) = borrowed else {
                return Ok(SyncOutcome::default());
            };
            let snapshot: Result<(SyncMeta, Vec<u8>), String> = (|| {
                let mut meta = v.sync_meta().map_err(|e| e.to_string())?;
                meta.device = crate::device::cached(&dir);
                let bytes = std::fs::read(&v.path).map_err(|e| e.to_string())?;
                Ok((meta, bytes))
            })();
            let (local_meta, bytes) = match snapshot {
                Ok(mb) => mb,
                Err(e) => {
                    let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
                    if let Some(s) = reg.get_mut(&id) {
                        s.end_borrow(v);
                    }
                    return Err(e);
                }
            };
            let vp = vault_path.clone();
            let app2 = app.clone();
            let synced = tauri::async_runtime::spawn_blocking(move || {
                gdrive_sync_gathered(&app2, &vp, &local_meta, &bytes, PullMode::Apply)
            })
            .await
            .map_err(spawn_blocking_failed)?;
            let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
            let Some(s) = reg.get_mut(&id) else {
                drop(reg);
                return match synced {
                    Ok(outcome) => Ok(outcome),
                    Err(e) => Err(e),
                };
            };
            s.end_borrow(v);
            match synced {
                Ok(outcome) => {
                    let locked = outcome.requires_reopen;
                    if locked {
                        s.lock();
                    }
                    drop(reg);
                    if locked {
                        crate::nmh::invalidate_confirms(&app);
                    }
                    Ok(outcome)
                }
                Err(e) => {
                    drop(reg);
                    Err(e)
                }
            }
        }
    }
}

/// Background open-time reconcile: push local changes if local wins, else flag
/// `remote_newer` for a non-intrusive banner. Unlike `sync_now` it NEVER takes
/// the vault out of its session (no `begin_borrow`) and never overwrites the
/// local file, so concurrent `list_entries` during the network round-trip still
/// sees the live vault. Best-effort: None/folder targets and every error map to
/// a default outcome.
#[tauri::command]
pub async fn detect_remote_changes(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    vault_id: Option<String>,
) -> CmdResult<SyncOutcome> {
    use tauri::Manager;
    let snap = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let id = match resolve_vault_id(&reg, vault_id.as_deref()) {
            Ok(i) => i,
            Err(_) => return Ok(SyncOutcome::default()),
        };
        let Some(s) = reg.get_mut(&id) else { return Ok(SyncOutcome::default()) };
        let Some(v) = s.vault.as_ref() else { return Ok(SyncOutcome::default()) };
        let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
        if !matches!(
            crate::sync_config::load(&dir, &v.path.to_string_lossy()),
            crate::sync_config::SyncTarget::Gdrive { .. }
        ) {
            return Ok(SyncOutcome::default());
        }
        let mut meta = match v.sync_meta() {
            Ok(m) => m,
            Err(_) => return Ok(SyncOutcome::default()),
        };
        meta.device = crate::device::cached(&dir);
        let bytes = match std::fs::read(&v.path) {
            Ok(b) => b,
            Err(_) => return Ok(SyncOutcome::default()),
        };
        (v.path.to_string_lossy().to_string(), meta, bytes)
    };
    let (vault_path, local_meta, bytes) = snap;
    let app2 = app.clone();
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        gdrive_sync_gathered(&app2, &vault_path, &local_meta, &bytes, PullMode::Detect)
    })
    .await
    .map_err(spawn_blocking_failed)?
    .unwrap_or_default();
    Ok(outcome)
}

/// Restore step 1: OAuth sign-in + list the vault files in appDataFolder.
/// Stashes the refresh_token + file list in AppState (never to the WebView);
/// returns just the file list for the picker.
#[tauri::command]
pub async fn gdrive_restore_signin(state: State<'_, AppState>) -> CmdResult<Vec<crate::gdrive::api::RemoteFile>> {
    let refresh = tauri::async_runtime::spawn_blocking(run_oauth_pkce)
        .await
        .map_err(spawn_blocking_failed)??;
    let refresh2 = refresh.clone();
    let (files, effective_refresh) = tauri::async_runtime::spawn_blocking(move || -> Result<(Vec<crate::gdrive::api::RemoteFile>, String), String> {
        let client = crate::gdrive::api::DriveClient::new(&refresh2, crate::gdrive::api::FILE_NAME)?;
        let files = client.list_appdata_files()?;
        let eff = client.rotated_refresh().map(|s| s.to_string()).unwrap_or(refresh2);
        Ok((files, eff))
    })
    .await
    .map_err(spawn_blocking_failed)??;
    let mut pr = state.pending_restore.lock().map_err(|e| e.to_string())?;
    *pr = Some(crate::state::PendingRestore { refresh_token: effective_refresh, files: files.clone(), chosen_file_id: None });
    Ok(files)
}

/// Restore step 2: download the chosen file's ciphertext to a local path the
/// user picked (already allowlisted by pick_save_path). Records the chosen id
/// for bind. Keeps the pending session alive.
#[tauri::command]
pub async fn gdrive_restore_download(state: State<'_, AppState>, file_id: String, local_path: String) -> CmdResult<()> {
    if !crate::paths::is_allowed(&state.allowed_paths, &local_path) {
        return Err(VaultError::PathNotAllowed.to_string());
    }
    let refresh = {
        let pr = state.pending_restore.lock().map_err(|e| e.to_string())?;
        let p = pr.as_ref().ok_or("restore session expired".to_string())?;
        if !restore_file_known(&p.files, &file_id) {
            return Err("unknown file id".to_string());
        }
        p.refresh_token.clone()
    };
    let fid = file_id.clone();
    let lp = local_path.clone();
    let rotated = tauri::async_runtime::spawn_blocking(move || -> Result<Option<String>, String> {
        let client = crate::gdrive::api::DriveClient::new(&refresh, crate::gdrive::api::FILE_NAME)?;
        let bytes = client.download(&fid)?;
        write_owner_only(&lp, &bytes).map_err(|e| e.to_string())?;
        Ok(client.rotated_refresh().map(|s| s.to_string()))
    })
    .await
    .map_err(spawn_blocking_failed)??;
    let mut pr = state.pending_restore.lock().map_err(|e| e.to_string())?;
    if let Some(p) = pr.as_mut() {
        p.chosen_file_id = Some(file_id);
        if let Some(rot) = rotated { p.refresh_token = rot; }
    }
    Ok(())
}

/// Restore step 3: after the frontend has opened the restored vault via
/// open_vault, bind sync — store the refresh_token in the keyring keyed by the
/// now-known local path, and write the sync.json baseline. remote_name is
/// re-derived from the opened vault's in-vault device_id, so this copy adopts
/// the ONE existing remote file (convergence). baseline rev = the
/// vault's own rev, so the next sync sees InSync (no re-pull loop).
#[tauri::command]
pub async fn gdrive_restore_bind(app: tauri::AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    use tauri::Manager;
    let (id, vault_path, device_id, rev) = {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let id = resolve_vault_id(&reg, None)?;
        let s = reg.get_mut(&id).ok_or_else(|| "no_vault".to_string())?;
        let v = s.vault.as_ref().ok_or(VaultError::NoVaultOpen.to_string())?;
        let device_id = kokos_core::db::get_device_id(&v.conn).map_err(|e| e.to_string())?;
        let rev = v.sync_meta().map_err(|e| e.to_string())?.rev;
        (id, v.path.to_string_lossy().to_string(), device_id, rev)
    };
    let pending = state.pending_restore.lock().map_err(|e| e.to_string())?.take();
    let p = pending.ok_or("restore session expired".to_string())?;
    let refresh = p.refresh_token;
    let file_id = p.chosen_file_id.ok_or("no file chosen".to_string())?;
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    crate::keyring_store::gdrive_store(&vault_path, &refresh).map_err(|e| e.to_string())?;
    crate::sync_config::save(&dir, &vault_path, &crate::sync_config::SyncTarget::Gdrive {
        file_id: Some(file_id),
        rev,
        last_sync: kokos_core::db::now_unix(),
        remote_name: Some(crate::sync_config::remote_name_for_device(&device_id)),
        note: None,
    }).map_err(|e| e.to_string())?;
    {
        let mut reg = state.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(v) = reg.get_mut(&id).and_then(|s| s.vault.as_ref()) {
            let _ = kokos_core::audit::append(&v.conn, "sync_connected", None);
        }
    }
    Ok(())
}

/// Restore cancel: drop the pending session (wizard closed / Escape).
#[tauri::command]
pub async fn gdrive_restore_cancel(state: State<'_, AppState>) -> CmdResult<()> {
    *state.pending_restore.lock().map_err(|e| e.to_string())? = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Regression guard for a gap that made the whole Windows registry arm
    /// dead code: `nmh_home` had no Windows case and returned `None`, so all
    /// four browser-registration commands answered `unsupported_platform`
    /// while `manifest` was perfectly able to write the key. The UI showed
    /// "Browser registration is not available on this platform yet" on a
    /// platform that was, by then, supported.
    ///
    /// Asserts the ROOT, not a joined path: `manifest::dir_for` appends the
    /// bundle identifier and browser leaf itself, so anything pre-joined here
    /// would nest the manifest one level too deep.
    #[cfg(windows)]
    #[test]
    fn nmh_home_is_the_roaming_appdata_root() {
        let home = super::nmh_home().expect("APPDATA is set in any normal session");
        assert_eq!(
            home,
            std::path::PathBuf::from(std::env::var_os("APPDATA").unwrap())
        );
        assert!(
            home.is_absolute(),
            "a relative root would put manifests wherever the app was started from"
        );
    }
    use super::{
        assemble_proposal, browser_for_grant_origin, browser_ids_after_install,
        build_new_entries, built_first_secret, fast_unlock_keyfile_guard, keyfile_was_changed, merge_open_vaults, mode_may_reconcile, parse_browser, plan_reconcile, resolve_commit_folders,
        pull_mode_outcome, sanitize_whitelist_ids, validate_chrome_id, validate_firefox_id,
        CommitEntry, CommitField, CommitProposal, CompromisedFieldDto, EntrySummaryDto,
        FolderSuggestionDto, GenOptsDto, HibpReportDto, KeyfileActionDto, PullMode, SearchFilters, SemanticHitDto,
        TagSuggestionDto, attachment_bytes_dto, import_file_within_cap,
        note_activity_should_advance,
    };
    use kokos_core::sync::SyncDecision;

    #[test]
    fn attachment_bytes_dto_roundtrips_bytes_and_maps_meta() {
        use base64::Engine;
        let a = kokos_core::attachments::Attachment {
            meta: kokos_core::attachments::AttachmentMeta {
                id: "att1".to_string(),
                entry_id: "e1".to_string(),
                filename: "photo.png".to_string(),
                mime_type: Some("image/png".to_string()),
                size: 4,
                created_at: 123,
            },
            data: vec![1u8, 2, 3, 4],
        };
        let dto = attachment_bytes_dto(a);
        assert_eq!(dto.filename, "photo.png");
        assert_eq!(dto.mime.as_deref(), Some("image/png"));
        assert_eq!(dto.size, 4);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&dto.data_base64)
            .unwrap();
        assert_eq!(decoded, vec![1u8, 2, 3, 4], "base64 must round-trip the exact bytes");
    }

    #[test]
    fn assemble_proposal_splits_existing_and_new() {
        use std::collections::HashMap;
        fn unit(x: &[f32]) -> Vec<f32> {
            let n = x.iter().map(|v| v * v).sum::<f32>().sqrt();
            x.iter().map(|v| v / n).collect()
        }
        fn meta(title: &str, domain: Option<&str>, tags: &[&str]) -> kokos_ai::meta::EmbeddingMetadata {
            kokos_ai::meta::EmbeddingMetadata {
                title: title.into(),
                entry_type: "login".into(),
                url_domain: domain.map(|s| s.to_string()),
                folder_name: None,
                tag_names: tags.iter().map(|s| s.to_string()).collect(),
            }
        }

        let mut centroids: HashMap<String, Vec<f32>> = HashMap::new();
        centroids.insert("work".into(), unit(&[1.0, 0.0, 0.0]));
        let mut names: HashMap<String, String> = HashMap::new();
        names.insert("work".into(), "Work".into());

        let unfiled = vec![
            ("e1".into(), meta("Jira", Some("atlassian.net"), &["work"]), unit(&[0.99, 0.02, 0.0])),
            ("e2".into(), meta("Repo A", Some("github.com"), &["dev"]), unit(&[0.0, 1.0, 0.02])),
            ("e3".into(), meta("Repo B", Some("github.com"), &["dev"]), unit(&[0.0, 1.0, 0.0])),
        ];

        let out = assemble_proposal(&centroids, &names, unfiled, 3);
        let existing: Vec<_> = out.groups.iter().filter(|g| g.kind == "existing").collect();
        let new: Vec<_> = out.groups.iter().filter(|g| g.kind == "new").collect();

        assert_eq!(existing.len(), 1);
        assert_eq!(existing[0].folder_id.as_deref(), Some("work"));
        assert_eq!(existing[0].entries.iter().map(|e| e.entry_id.as_str()).collect::<Vec<_>>(), vec!["e1"]);

        assert_eq!(new.len(), 1);
        assert_eq!(new[0].folder_id, None);
        assert_eq!(new[0].name, "github.com", "new folder seeded from dominant domain");
        assert_eq!(new[0].entries.len(), 2);
    }

    #[test]
    fn search_filters_deserializes_snake_case_payload() {
        let f: SearchFilters = serde_json::from_str(
            r#"{"folder_id":"root","tag_id":"t1","favorites_only":true,"regex":true}"#,
        )
        .unwrap();
        assert_eq!(f.folder_id.as_deref(), Some("root"));
        assert_eq!(f.tag_id.as_deref(), Some("t1"));
        assert!(f.favorites_only);
        assert!(f.regex);
    }

    #[test]
    fn search_filters_camelcase_multiword_key_is_silently_ignored() {
        let f: SearchFilters = serde_json::from_str(r#"{"favoritesOnly":true}"#).unwrap();
        assert!(
            !f.favorites_only,
            "camelCase 'favoritesOnly' must NOT set favorites_only — the silent-ignore this contract guards against"
        );
    }

    #[test]
    fn gen_opts_deserializes_snake_case_payload() {
        let o: GenOptsDto = serde_json::from_str(
            r#"{"length":20,"upper":true,"lower":true,"digits":true,"symbols":false,"min_upper":2,"min_lower":3,"min_digits":1,"min_symbols":0}"#,
        )
        .unwrap();
        assert_eq!(o.length, 20);
        assert!(o.upper && o.lower && o.digits && !o.symbols);
        assert_eq!(o.min_upper, 2);
        assert_eq!(o.min_lower, 3);
        assert_eq!(o.min_digits, 1);
        assert_eq!(o.min_symbols, 0);
    }

    #[test]
    fn semantic_hit_dto_serializes_entry_and_score() {
        let dto = SemanticHitDto {
            entry: EntrySummaryDto {
                id: "e1".into(),
                title: "Netflix".into(),
                username: None,
                is_favorite: false,
                has_totp: false,
                has_attachments: false,
                updated_at: 1,
                folder_id: None,
                tags: vec![],
                entry_type: "login".into(),
                password_field_id: None,
            },
            score: 0.5,
        };
        let v = serde_json::to_value(&dto).unwrap();
        assert!(v.get("entry").is_some(), "top-level `entry`");
        assert_eq!(v.get("score").and_then(|s| s.as_f64()), Some(0.5), "top-level `score`");
        assert!(v["entry"].get("is_favorite").is_some(), "nested snake_case preserved");
    }

    #[test]
    fn folder_suggestion_dto_serializes_snake_case() {
        let dto = FolderSuggestionDto {
            folder_id: "f1".into(),
            name: "Work".into(),
            score: 0.42,
        };
        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains("\"folder_id\":\"f1\""), "snake_case folder_id: {json}");
        assert!(json.contains("\"name\":\"Work\""), "name present: {json}");
        assert!(json.contains("\"score\":0.42"), "score present: {json}");
    }

    #[test]
    fn tag_suggestion_dto_serializes_snake_case() {
        let dto = TagSuggestionDto {
            tag_id: "t1".into(),
            name: "work".into(),
            color: Some("#16A34A".into()),
            score: 0.42,
        };
        let v = serde_json::to_value(&dto).unwrap();
        assert_eq!(v["tag_id"], "t1");
        assert_eq!(v["name"], "work");
        assert_eq!(v["color"], "#16A34A");
        assert!((v["score"].as_f64().unwrap() - 0.42).abs() < 1e-6);
        let none = TagSuggestionDto { tag_id: "t2".into(), name: "x".into(), color: None, score: 0.1 };
        assert!(serde_json::to_value(&none).unwrap()["color"].is_null());
    }

    #[test]
    fn gen_opts_camelcase_min_key_is_silently_ignored() {
        let o: GenOptsDto = serde_json::from_str(
            r#"{"length":16,"upper":true,"lower":true,"digits":true,"symbols":true,"minUpper":2}"#,
        )
        .unwrap();
        assert_eq!(
            o.min_upper, 0,
            "camelCase 'minUpper' must NOT set min_upper — the silent-ignore this contract guards against"
        );
    }

    #[test]
    fn restore_file_known_rejects_unstashed_id() {
        use crate::gdrive::api::RemoteFile;
        let files = vec![RemoteFile { id: "A".into(), name: "a".into(), modified_time: "".into(), size: None, vault_name: None, note: None }];
        assert!(super::restore_file_known(&files, "A"));
        assert!(!super::restore_file_known(&files, "Z"));
    }


    #[test]
    fn backup_vault_name_keeps_extension() {
        assert_eq!(super::backup_vault_name("/Users/x/passwords.kokos"), "passwords.kokos");
    }

    #[test]
    fn backup_vault_name_empty_when_no_filename() {
        assert_eq!(super::backup_vault_name("/"), "");
    }

    #[test]
    fn gdrive_set_note_persists_note_preserving_other_fields() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = "/x/passwords.kokos";
        crate::sync_config::save(dir.path(), vault_path, &crate::sync_config::SyncTarget::Gdrive {
            file_id: None, rev: 5, last_sync: 100, remote_name: Some("kokos-abc.kokos".into()), note: None,
        }).unwrap();
        let (file_id, rev, last_sync, remote_name) = match crate::sync_config::load(dir.path(), vault_path) {
            crate::sync_config::SyncTarget::Gdrive { file_id, rev, last_sync, remote_name, .. } => (file_id, rev, last_sync, remote_name),
            _ => panic!("expected gdrive"),
        };
        let note = "From my Macbook".to_string();
        let note_opt = if note.is_empty() { None } else { Some(note.clone()) };
        crate::sync_config::save(dir.path(), vault_path, &crate::sync_config::SyncTarget::Gdrive {
            file_id: file_id.clone(), rev, last_sync, remote_name: remote_name.clone(), note: note_opt,
        }).unwrap();
        match crate::sync_config::load(dir.path(), vault_path) {
            crate::sync_config::SyncTarget::Gdrive { file_id, rev, last_sync, remote_name, note } => {
                assert_eq!(file_id, None);
                assert_eq!(rev, 5);
                assert_eq!(last_sync, 100);
                assert_eq!(remote_name.as_deref(), Some("kokos-abc.kokos"));
                assert_eq!(note.as_deref(), Some("From my Macbook"));
            }
            _ => panic!("expected gdrive"),
        }
    }


    #[test]
    fn detect_reports_remote_newer_without_pull() {
        let outcome = pull_mode_outcome(SyncDecision::PullRemote, PullMode::Detect)
            .expect("PullRemote + Detect must short-circuit without network I/O");
        assert!(outcome.remote_newer, "Detect must flag a newer remote");
        assert!(!outcome.pulled && !outcome.requires_reopen, "Detect must NOT pull or request reopen");
        assert!(!outcome.pushed, "Detect must NOT push either");
    }

    #[test]
    fn skip_mode_pull_remote_is_silent_noop() {
        let outcome = pull_mode_outcome(SyncDecision::PullRemote, PullMode::Skip)
            .expect("PullRemote + Skip must also short-circuit without network I/O");
        assert!(!outcome.remote_newer && !outcome.pulled && !outcome.requires_reopen && !outcome.pushed);
    }

    #[test]
    fn other_combinations_defer_to_real_io() {
        assert!(pull_mode_outcome(SyncDecision::PullRemote, PullMode::Apply).is_none());
        for mode in [PullMode::Skip, PullMode::Detect, PullMode::Apply] {
            assert!(pull_mode_outcome(SyncDecision::PushLocal, mode).is_none());
            assert!(pull_mode_outcome(SyncDecision::InSync, mode).is_none());
        }
    }


    #[test]
    fn mode_may_reconcile_gates_skip_only() {
        assert!(!mode_may_reconcile(PullMode::Skip), "Skip must stop at the baseline shortcut");
        assert!(mode_may_reconcile(PullMode::Detect), "Detect must probe past the baseline shortcut");
        assert!(mode_may_reconcile(PullMode::Apply), "Apply must reconcile past the baseline shortcut");
    }


    #[test]
    fn parse_browser_accepts_both_known_names() {
        assert_eq!(parse_browser("chrome"), Ok(kokos_nmh::origin::Browser::Chrome));
        assert_eq!(parse_browser("firefox"), Ok(kokos_nmh::origin::Browser::Firefox));
    }

    #[test]
    fn parse_browser_rejects_anything_else_with_the_stable_token() {
        for bad in ["safari", "", "Chrome-extension", "  "] {
            assert_eq!(parse_browser(bad), Err("unknown_browser"), "input {bad}");
        }
    }

    #[test]
    fn validate_chrome_id_accepts_a_real_shaped_id() {
        assert_eq!(
            validate_chrome_id("abcdefghijklmnopabcdefghijklmnop"),
            Ok("abcdefghijklmnopabcdefghijklmnop".to_string())
        );
    }

    #[test]
    fn validate_chrome_id_trims_surrounding_whitespace() {
        assert_eq!(
            validate_chrome_id("  abcdefghijklmnopabcdefghijklmnop  "),
            Ok("abcdefghijklmnopabcdefghijklmnop".to_string())
        );
    }

    #[test]
    fn validate_chrome_id_rejects_hostile_and_malformed_shapes() {
        let bad = [
            "",
            "short",
            "abcdefghijklmnopabcdefghijklmnopEXTRA",
            "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP",
            "abcdefghijklmnopabcdefghijklmno1",
            "abcdefghijklmnop/abcdefghijklmnop",
            "../../../../etc/passwd",
            "abcdefghijklmnopabcdefghijklmn\0p",
            "abcdefghijklmnopabcdefghijklmn\np",
            "                                ",
        ];
        for input in bad {
            assert_eq!(
                validate_chrome_id(input),
                Err("bad_chrome_id"),
                "input {input:?} must be rejected"
            );
        }
    }

    #[test]
    fn validate_firefox_id_accepts_real_shaped_ids() {
        assert_eq!(
            validate_firefox_id("kokos@example.org"),
            Ok("kokos@example.org".to_string())
        );
        assert_eq!(
            validate_firefox_id("{12345678-1234-1234-1234-123456789abc}"),
            Ok("{12345678-1234-1234-1234-123456789abc}".to_string())
        );
    }

    #[test]
    fn validate_firefox_id_trims_surrounding_whitespace() {
        assert_eq!(
            validate_firefox_id("  kokos@example.org  "),
            Ok("kokos@example.org".to_string())
        );
    }

    #[test]
    fn validate_firefox_id_preserves_case() {
        assert_eq!(
            validate_firefox_id("Kokos-Stub@Example.ORG"),
            Ok("Kokos-Stub@Example.ORG".to_string())
        );
    }

    #[test]
    fn validate_firefox_id_rejects_the_empty_and_unshaped_strings() {
        for input in ["", "   ", "kokos", "just-a-name", "[kokos]"] {
            assert_eq!(validate_firefox_id(input), Err("bad_firefox_id"), "input {input:?}");
        }
    }

    #[test]
    fn validate_firefox_id_rejects_hostile_characters_even_when_shaped() {
        let bad = [
            "kokos@example.org/../etc/passwd",
            "{../../etc/passwd}",
            "kokos@exa\0mple.org",
            "kokos@exa\nmple.org",
            "kokos@exa\\mple.org",
            "{}",
        ];
        for input in bad {
            assert_eq!(
                validate_firefox_id(input),
                Err("bad_firefox_id"),
                "input {input:?} must be rejected"
            );
        }
    }

    #[test]
    fn validate_firefox_id_rejects_bare_at_and_whitespace_only_braces() {
        let bad = [
            "@",
            "@example.org",
            "kokos@",
            "{}",
            "{ }",
        ];
        for input in bad {
            assert_eq!(
                validate_firefox_id(input),
                Err("bad_firefox_id"),
                "input {input:?} must be rejected"
            );
        }
    }


    #[test]
    fn sanitize_whitelist_ids_drops_malformed_chrome_id_keeps_valid_canonical() {
        let raw = vec![
            "x".to_string(),
            "abcdefghijklmnopabcdefghijklmnop".to_string(),
        ];
        let result = sanitize_whitelist_ids(&raw, validate_chrome_id);
        assert_eq!(result, vec!["abcdefghijklmnopabcdefghijklmnop".to_string()]);
    }

    #[test]
    fn sanitize_whitelist_ids_drops_hostile_firefox_id_keeps_valid() {
        let raw = vec![
            "{../../etc/passwd}".to_string(),
            "name@example.com".to_string(),
        ];
        let result = sanitize_whitelist_ids(&raw, validate_firefox_id);
        assert_eq!(result, vec!["name@example.com".to_string()]);
    }

    #[test]
    fn sanitize_whitelist_ids_trims_surrounding_whitespace() {
        let raw = vec!["  abcdefghijklmnopabcdefghijklmnop  ".to_string()];
        let result = sanitize_whitelist_ids(&raw, validate_chrome_id);
        assert_eq!(result, vec!["abcdefghijklmnopabcdefghijklmnop".to_string()]);
    }

    #[test]
    fn sanitize_whitelist_ids_empty_input_yields_empty_output() {
        let raw: Vec<String> = vec![];
        assert_eq!(sanitize_whitelist_ids(&raw, validate_chrome_id), Vec::<String>::new());
        assert_eq!(sanitize_whitelist_ids(&raw, validate_firefox_id), Vec::<String>::new());
    }


    #[test]
    fn installing_b_after_a_replaces_a_not_appends() {
        let current = vec!["A".to_string()];
        let result = browser_ids_after_install(&current, "B");
        assert_eq!(
            result,
            vec!["B".to_string()],
            "the manifest file only ever trusts the newest id -- the settings \
             whitelist must match, not accumulate"
        );
    }

    #[test]
    fn negative_control_the_old_append_behaviour_would_have_kept_a_present() {
        let current = vec!["A".to_string()];
        let mut appended = current.clone();
        appended.push("B".to_string());
        assert_eq!(appended, vec!["A".to_string(), "B".to_string()]);

        let result = browser_ids_after_install(&current, "B");
        assert_ne!(
            result, appended,
            "installing B must not leave A behind, unlike a naive append"
        );
        assert!(
            !result.contains(&"A".to_string()),
            "A must not still be trusted after installing B"
        );
    }

    #[test]
    fn installing_the_first_id_ever_yields_just_that_id() {
        let result = browser_ids_after_install(&[], "abcdefghijklmnopabcdefghijklmnop");
        assert_eq!(result, vec!["abcdefghijklmnopabcdefghijklmnop".to_string()]);
    }


    #[test]
    fn browser_for_grant_origin_recognises_a_chrome_origin() {
        assert_eq!(
            browser_for_grant_origin("chrome-extension://abcdefghijklmnopabcdefghijklmnop/"),
            "chrome"
        );
    }

    #[test]
    fn browser_for_grant_origin_treats_a_bare_id_as_firefox() {
        assert_eq!(browser_for_grant_origin("kokos@example.org"), "firefox");
        assert_eq!(
            browser_for_grant_origin("{12345678-1234-1234-1234-123456789abc}"),
            "firefox"
        );
    }

    #[test]
    fn hibp_report_dto_serializes_snake_case() {
        let dto = HibpReportDto {
            compromised: vec![CompromisedFieldDto {
                entry_id: "e1".into(),
                title: "Bank".into(),
                field_name: "Password".into(),
                count: 42,
            }],
            checked: true,
            offline: false,
            enabled: true,
        };
        let j = serde_json::to_value(&dto).unwrap();
        assert_eq!(j["compromised"][0]["entry_id"], "e1");
        assert_eq!(j["compromised"][0]["field_name"], "Password");
        assert_eq!(j["compromised"][0]["count"], 42);
        assert_eq!(j["checked"], true);
        assert_eq!(j["offline"], false);
        assert_eq!(j["enabled"], true);
    }

    #[test]
    fn import_file_within_cap_rejects_oversize_and_nonregular() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f.bin");
        std::fs::write(&f, b"hello").unwrap();
        assert!(import_file_within_cap(f.to_str().unwrap(), 1024).unwrap(), "5 bytes <= 1024 is ok");
        assert!(!import_file_within_cap(f.to_str().unwrap(), 4).unwrap(), "5 bytes > 4 must reject");
        assert!(!import_file_within_cap(dir.path().to_str().unwrap(), u64::MAX).unwrap());
    }

    #[test]
    fn reveal_policy_allows_only_protected_fields() {
        assert!(super::reveal_allowed(true));
        assert!(!super::reveal_allowed(false));
    }

    #[test]
    fn note_activity_rate_limits_sub_500ms() {
        let t0 = std::time::Instant::now();
        assert!(!note_activity_should_advance(t0, t0 + std::time::Duration::from_millis(400)));
        assert!(note_activity_should_advance(t0, t0 + std::time::Duration::from_millis(500)));
        assert!(note_activity_should_advance(t0, t0 + std::time::Duration::from_millis(600)));
    }

    #[test]
    fn build_new_entries_maps_every_vault_type_through_create() {
        use kokos_core::entries;
        let conn = kokos_core::db::create_fresh().unwrap();
        let now = kokos_core::db::now_unix();
        let proposal = CommitProposal {
            entries: vec![
                CommitEntry { title: "GitHub".into(), entry_type: "login".into(), fields: vec![
                    CommitField { name: "Username".into(), field_type: "text".into(),  is_protected: false, value: "octocat".into() },
                    CommitField { name: "Password".into(), field_type: "secret".into(), is_protected: true,  value: "hunter2".into() },
                    CommitField { name: "URL".into(),      field_type: "url".into(),    is_protected: false, value: "github.com".into() },
                ], ..Default::default() },
                CommitEntry { title: "TOTP".into(), entry_type: "login".into(), fields: vec![
                    CommitField { name: "TOTP secret".into(), field_type: "otp".into(), is_protected: true, value: "JBSWY3DPEHPK3PXP".into() },
                ], ..Default::default() },
                CommitEntry { title: "Note".into(),  entry_type: "secure_note".into(), fields: vec![
                    CommitField { name: "Note".into(), field_type: "text".into(), is_protected: false, value: "remember".into() },
                ], ..Default::default() },
            ],
        };
        let built = build_new_entries(&proposal, &vec!["root".to_string(); 3]).expect("valid types build");
        assert_eq!(built.len(), 3);
        for ne in built {
            let e = entries::create(&conn, ne, now).expect("create must not trip a DB CHECK");
            assert!(entries::get(&conn, &e.id).unwrap().is_some());
        }
        let secret = built_first_secret(&conn);
        assert_eq!(secret, Some(1));
    }

    #[test]
    fn build_new_entries_accepts_phone_field() {
        use kokos_core::entries;
        let conn = kokos_core::db::create_fresh().unwrap();
        let now = kokos_core::db::now_unix();
        let p = CommitProposal { entries: vec![CommitEntry {
            title: "Contact".into(), entry_type: "login".into(), fields: vec![
                CommitField { name: "Phone".into(), field_type: "phone".into(), is_protected: false, value: "+380000000000".into() },
            ], ..Default::default() }]};
        let built = build_new_entries(&p, &["root".to_string()]).expect("phone is a valid commit field_type");
        for ne in built {
            let e = entries::create(&conn, ne, now).expect("phone field must not trip the DB CHECK");
            assert!(entries::get(&conn, &e.id).unwrap().is_some());
        }
    }

    #[test]
    fn build_new_entries_rejects_bad_types() {
        let bad_entry = CommitProposal { entries: vec![
            CommitEntry { title: "x".into(), entry_type: "api_key".into(), fields: vec![], ..Default::default() },
        ]};
        assert!(build_new_entries(&bad_entry, &["root".to_string()]).is_err());
        let bad_field = CommitProposal { entries: vec![
            CommitEntry { title: "x".into(), entry_type: "login".into(), fields: vec![
                CommitField { name: "n".into(), field_type: "multiline".into(), is_protected: false, value: "v".into() },
            ], ..Default::default() },
        ]};
        assert!(build_new_entries(&bad_field, &["root".to_string()]).is_err());
    }

    #[test]
    fn build_new_entries_forces_protected_on_secret_and_otp() {
        let p = CommitProposal { entries: vec![CommitEntry {
            title: "x".into(), entry_type: "login".into(), fields: vec![
                CommitField { name: "p".into(), field_type: "secret".into(), is_protected: false, value: "s".into() },
                CommitField { name: "t".into(), field_type: "otp".into(),    is_protected: false, value: "o".into() },
                CommitField { name: "u".into(), field_type: "text".into(),   is_protected: false, value: "u".into() },
            ], ..Default::default() }]};
        let built = build_new_entries(&p, &["root".to_string()]).unwrap();
        assert!(built[0].fields[0].is_protected, "secret coerced protected");
        assert!(built[0].fields[1].is_protected, "otp coerced protected");
        assert!(!built[0].fields[2].is_protected, "text stays unprotected");
    }

    #[test]
    fn build_new_entries_binds_each_entry_to_its_own_folder() {
        let p = CommitProposal { entries: vec![
            CommitEntry { title: "a".into(), entry_type: "login".into(), fields: vec![], ..Default::default() },
            CommitEntry { title: "b".into(), entry_type: "login".into(), fields: vec![], ..Default::default() },
        ]};
        let built = build_new_entries(&p, &["fa".to_string(), "fb".to_string()]).unwrap();
        assert_eq!(built[0].folder_id.as_deref(), Some("fa"));
        assert_eq!(built[1].folder_id.as_deref(), Some("fb"));
    }

    #[test]
    fn resolve_commit_folders_dedups_a_shared_new_name() {
        let conn = kokos_core::db::create_fresh().unwrap();
        let now = kokos_core::db::now_unix();
        let p = CommitProposal { entries: vec![
            CommitEntry { title: "a".into(), entry_type: "login".into(), fields: vec![], new_folder_name: Some("Work".into()), ..Default::default() },
            CommitEntry { title: "b".into(), entry_type: "login".into(), fields: vec![], new_folder_name: Some("Work".into()), ..Default::default() },
        ]};
        let ids = resolve_commit_folders(&conn, &p, now).unwrap();
        assert_eq!(ids[0], ids[1], "shared new name → same folder id");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM folders WHERE name = 'Work'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "only one 'Work' folder created");
    }

    #[test]
    fn resolve_commit_folders_mixes_existing_id_and_new_name() {
        let conn = kokos_core::db::create_fresh().unwrap();
        let now = kokos_core::db::now_unix();
        let p = CommitProposal { entries: vec![
            CommitEntry { title: "a".into(), entry_type: "login".into(), fields: vec![], folder_id: Some("root".into()), ..Default::default() },
            CommitEntry { title: "b".into(), entry_type: "login".into(), fields: vec![], new_folder_name: Some("Bank".into()), ..Default::default() },
            CommitEntry { title: "c".into(), entry_type: "login".into(), fields: vec![], new_folder_name: Some("   ".into()), ..Default::default() },
        ]};
        let ids = resolve_commit_folders(&conn, &p, now).unwrap();
        assert_eq!(ids[0], "root");
        assert_ne!(ids[1], "root");
        assert_eq!(ids[2], "root", "blank new name falls back to root");
        let bank = kokos_core::folders::get_folder(&conn, &ids[1]).unwrap().unwrap();
        assert_eq!(bank.name, "Bank");
    }

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn merge_partial_unlock_keeps_locked_restored() {
        let out = merge_open_vaults(&v(&["A", "B", "C"]), &v(&["A"]), &v(&["B", "C"]));
        assert_eq!(out, v(&["A", "B", "C"]));
    }

    #[test]
    fn merge_drops_unlocked_then_closed_tab_no_resurrection() {
        let out = merge_open_vaults(&v(&["A", "B", "C"]), &v(&["A"]), &v(&["C"]));
        assert_eq!(out, v(&["A", "C"]));
    }

    #[test]
    fn merge_appends_newly_opened_tab() {
        let out = merge_open_vaults(&v(&["A", "B"]), &v(&["A", "B", "D"]), &v(&[]));
        assert_eq!(out, v(&["A", "B", "D"]));
    }

    #[test]
    fn merge_follows_skeleton_order_not_reg_order() {
        let out = merge_open_vaults(&v(&["A", "B", "C"]), &v(&["C", "A"]), &v(&["B"]));
        assert_eq!(out, v(&["A", "B", "C"]));
    }

    #[test]
    fn merge_all_locked_preserves_set() {
        let out = merge_open_vaults(&v(&["A", "B", "C"]), &v(&[]), &v(&["A", "B", "C"]));
        assert_eq!(out, v(&["A", "B", "C"]));
    }

    #[test]
    fn fast_unlock_refused_for_keyfile_vault() {
        assert_eq!(
            fast_unlock_keyfile_guard(true).unwrap_err(),
            "fast_unlock_keyfile_unsupported"
        );
    }

    #[test]
    fn fast_unlock_allowed_for_password_only_vault() {
        assert!(fast_unlock_keyfile_guard(false).is_ok());
    }

    #[test]
    fn reconcile_password_only_rewrites_only_present_copies() {
        let ops = plan_reconcile(false, true, true);
        assert!(ops.store_keyring && ops.store_biometric);
        assert!(!ops.delete_keyring && !ops.delete_biometric);

        let ops = plan_reconcile(false, false, true);
        assert!(!ops.store_keyring && ops.store_biometric);

        let ops = plan_reconcile(false, false, false);
        assert!(!ops.store_keyring && !ops.store_biometric);
        assert!(!ops.delete_keyring && !ops.delete_biometric);
    }

    #[test]
    fn keyfile_gate_accepts_none_and_picked_paths_only() {
        let dir = tempfile::tempdir().unwrap();
        let picked = dir.path().join("picked.key");
        let other = dir.path().join("other.key");
        std::fs::write(&picked, b"k").unwrap();
        std::fs::write(&other, b"k").unwrap();
        let set = std::sync::Mutex::new(std::collections::HashSet::new());
        crate::paths::allow(&set, picked.to_str().unwrap());

        assert!(super::ensure_keyfile_allowed(&set, None).is_ok(), "no key file needs no gate");
        assert!(super::ensure_keyfile_allowed(&set, picked.to_str()).is_ok());
        assert!(super::ensure_keyfile_allowed(&set, other.to_str()).is_err(), "never-picked path denied");
        assert!(super::ensure_keyfile_allowed(&set, Some("/dev/zero")).is_err(), "device path denied");
    }

    #[test]
    fn reconcile_keyfile_required_deletes_both_and_stores_neither() {
        let ops = plan_reconcile(true, true, true);
        assert!(ops.delete_keyring && ops.delete_biometric);
        assert!(!ops.store_keyring && !ops.store_biometric);
    }

    #[test]
    fn keyfile_was_changed_covers_all_four_variants() {
        assert!(!keyfile_was_changed(&KeyfileActionDto::Keep), "Keep: nothing rotated");
        assert!(
            keyfile_was_changed(&KeyfileActionDto::Set { path: "a".to_string() }),
            "Set: the file genuinely changed"
        );
        assert!(keyfile_was_changed(&KeyfileActionDto::Remove), "Remove: the file is gone");
        assert!(
            !keyfile_was_changed(&KeyfileActionDto::Resupply { path: "a".to_string() }),
            "Resupply: same file re-proven, not changed — must not file a false keyfile_changed row"
        );
    }

    #[test]
    fn permission_denied_is_explained_not_echoed() {
        use kokos_core::error::VaultError;
        let msg = super::explain_vault_error(
            &VaultError::PermissionDenied,
            "/home/ann/.local/share/passwords.kokos",
            Some("kokos"),
        );
        assert!(msg.contains("hidden folder"), "the snap cause must reach the user: {msg}");
        assert!(
            !msg.contains("permission denied for this file"),
            "the bare variant message is what we are replacing"
        );
    }

    #[test]
    fn other_vault_errors_keep_their_own_message() {
        use kokos_core::error::VaultError;
        let msg = super::explain_vault_error(
            &VaultError::InvalidCredentialsOrCorrupt,
            "/x/passwords.kokos",
            Some("kokos"),
        );
        assert_eq!(msg, VaultError::InvalidCredentialsOrCorrupt.to_string());
    }

    #[test]
    fn a_permission_refusal_is_not_a_failed_password_attempt() {
        use kokos_core::error::VaultError;
        assert!(
            !super::counts_as_failed_attempt(&VaultError::PermissionDenied),
            "bumping here would show a phantom failed-attempt warning on the next \
             successful open, for a file the app never got to read"
        );
        assert!(super::counts_as_failed_attempt(&VaultError::InvalidCredentialsOrCorrupt));
        assert!(super::counts_as_failed_attempt(&VaultError::KeyfileRequired));
    }

    #[test]
    fn record_open_failure_skips_permission_denied_but_bumps_credential_errors() {
        use kokos_core::error::VaultError;
        let dir = tempfile::tempdir().unwrap();
        let path = "/x/passwords.kokos";

        super::record_open_failure(Some(dir.path()), path, &VaultError::PermissionDenied);
        assert_eq!(
            crate::auth_failures::take(dir.path(), path),
            0,
            "a permission refusal must not be counted as a failed password attempt"
        );

        super::record_open_failure(Some(dir.path()), path, &VaultError::InvalidCredentialsOrCorrupt);
        assert_eq!(
            crate::auth_failures::take(dir.path(), path),
            1,
            "a genuine credential failure must still bump the counter"
        );
    }
}

#[cfg(test)]
fn built_first_secret(conn: &rusqlite::Connection) -> Option<i64> {
    conn.query_row(
        "SELECT is_protected FROM entry_fields WHERE field_type = 'secret' LIMIT 1",
        [],
        |r| r.get(0),
    ).ok()
}

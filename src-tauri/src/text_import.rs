//! Generative text-import: the gen-model download/gate/cache and the
//! `ai_text_import_analyze` command. Mirrors the embedding plumbing in
//! `ai.rs`, but for the CPU GGUF `GenExtractor`. Backend-only — the review UI
//! that renders the returned `ImportProposal` lives in the frontend.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tauri::{AppHandle, Emitter, Manager, State};

use kokos_ai::text_import::engine::gen::GenExtractor;
use kokos_ai::text_import::engine::pipeline::analyze_text_with_progress;
use kokos_ai::text_import::engine::registry::resolve_gen;
use kokos_ai::text_import::model::{ImportProposal, ProposedEntry};
use kokos_ai::AiError;
use zeroize::Zeroize;

use crate::state::AppState;

/// The only generative model shipped in v1 (dev-facing, like `ai_model`).
pub const GEN_MODEL_ID: &str = "qwen2.5-1.5b-instruct";
const GGUF_FILE: &str = "model.gguf";
const TOKENIZER_FILE: &str = "tokenizer.json";
/// Hard cap on an imported text file (generous for credential text; bounds
/// memory + inference time).
pub const MAX_TEXT_IMPORT_SIZE: u64 = 4 * 1024 * 1024;
/// Conservative per-chunk BYTE budget. `analyze_text` chunks on block boundaries;
/// this must leave the 8192-token ctx room for the prompt template + few-shot +
/// output. 3000 bytes ≈ ~1k tokens of source, well under budget even for non-ASCII.
const CHUNK_BUDGET_BYTES: usize = 3000;

/// Max entries kept from ONE file and from ONE merged proposal. Each entry costs
/// a review-UI draft + a raw-source preview, so the count must be bounded
/// independently of the input byte caps (a 4 MiB file of tiny blocks could
/// otherwise yield hundreds of thousands of entries). Excess entries are dropped
/// and counted in the audit detail (`entries_dropped`), never silently.
const MAX_ENTRIES_PER_FILE: usize = 500;
const MAX_ENTRIES_PER_PROPOSAL: usize = 2000;
/// Max bytes of raw source kept per entry (`source_text`). The review UI only
/// needs the entry's own block, not the whole file.
const MAX_SOURCE_PREVIEW_BYTES: usize = 8 * 1024;

/// Extensions the folder walker accepts (lowercase, no dot).
const IMPORT_EXTS: [&str; 3] = ["txt", "md", "csv"];
/// Folder-walk caps ("Balanced" preset). Literals — pinned by test.
const MAX_DEPTH: usize = 16;
const MAX_FILE_COUNT: usize = 100;
const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;

/// Per-run caps for `walk_import_dir` (injectable so tests use small literals).
pub struct WalkCaps {
    pub max_depth: usize,
    pub max_files: usize,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
}

impl WalkCaps {
    /// Production caps ("Balanced" preset). Per-file reuses `MAX_TEXT_IMPORT_SIZE`.
    pub fn balanced() -> Self {
        WalkCaps {
            max_depth: MAX_DEPTH,
            max_files: MAX_FILE_COUNT,
            max_total_bytes: MAX_TOTAL_BYTES,
            max_file_bytes: MAX_TEXT_IMPORT_SIZE,
        }
    }
}

/// Per-reason counts of files the walk turned away (surfaced in audit; never silent).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct WalkReport {
    pub wrong_ext: u32,
    pub symlink_dir: u32,
    pub not_under_root: u32,
    pub over_file_size: u32,
    pub over_total_bytes: u32,
    pub over_file_count: u32,
    pub over_depth: u32,
    pub io_error: u32,
    /// The walk hard-stopped before visiting the whole tree (a cap tripped,
    /// possibly at a directory boundary where no per-file counter fired).
    /// Not part of `total()` — it's a flag, not a count.
    pub truncated: bool,
}

impl WalkReport {
    pub fn total(&self) -> u32 {
        self.wrong_ext
            + self.symlink_dir
            + self.not_under_root
            + self.over_file_size
            + self.over_total_bytes
            + self.over_file_count
            + self.over_depth
            + self.io_error
    }
}

pub struct WalkOutcome {
    pub files: Vec<PathBuf>,
    pub dropped: WalkReport,
}

/// Bounded recursive walk of `root` → safe `.txt/.md/.csv` files, each
/// canonicalized and proven to stay under the canonicalized root. SECURITY:
/// symlink-file escaping the tree → dropped (`not_under_root`); a symlinked
/// directory is never followed (`symlink_dir`); dot-directories are skipped;
/// caps bound depth/count/total/size; in-memory only (returns paths).
pub fn walk_import_dir(root: &Path, caps: &WalkCaps) -> WalkOutcome {
    let mut out = WalkOutcome { files: Vec::new(), dropped: WalkReport::default() };
    let canonical_root = match std::fs::canonicalize(root) {
        Ok(r) => r,
        Err(_) => return out,
    };
    let mut total_bytes: u64 = 0;
    let _ = walk_dir(&canonical_root, &canonical_root, 0, caps, &mut out, &mut total_bytes);
    out
}

/// Returns `true` when a hard cap (file count / total bytes) has been hit and
/// the whole walk must stop (work-bounded, not just output-bounded) — the
/// caller propagates this up through every recursive call.
fn walk_dir(
    dir: &Path,
    canonical_root: &Path,
    depth: usize,
    caps: &WalkCaps,
    out: &mut WalkOutcome,
    total_bytes: &mut u64,
) -> bool {
    if out.files.len() >= caps.max_files {
        out.dropped.truncated = true;
        return true;
    }
    if depth > caps.max_depth {
        out.dropped.over_depth += 1;
        return false;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => {
            out.dropped.io_error += 1;
            return false;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                out.dropped.io_error += 1;
                continue;
            }
        };
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => {
                out.dropped.io_error += 1;
                continue;
            }
        };
        let ft = meta.file_type();

        if ft.is_symlink() && path.is_dir() {
            out.dropped.symlink_dir += 1;
            continue;
        }

        if ft.is_dir() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
            if walk_dir(&path, canonical_root, depth + 1, caps, out, total_bytes) {
                return true;
            }
            continue;
        }

        let ext_ok = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| IMPORT_EXTS.contains(&e.to_lowercase().as_str()))
            .unwrap_or(false);
        if !ext_ok {
            out.dropped.wrong_ext += 1;
            continue;
        }
        let canonical = match std::fs::canonicalize(&path) {
            Ok(c) => c,
            Err(_) => {
                out.dropped.io_error += 1;
                continue;
            }
        };
        if !canonical.starts_with(canonical_root) {
            out.dropped.not_under_root += 1;
            continue;
        }
        let len = match std::fs::metadata(&canonical) {
            Ok(m) if m.is_file() => m.len(),
            _ => {
                out.dropped.io_error += 1;
                continue;
            }
        };
        if len > caps.max_file_bytes {
            out.dropped.over_file_size += 1;
            continue;
        }
        if out.files.len() >= caps.max_files {
            out.dropped.over_file_count += 1;
            out.dropped.truncated = true;
            return true;
        }
        if *total_bytes + len > caps.max_total_bytes {
            out.dropped.over_total_bytes += 1;
            out.dropped.truncated = true;
            return true;
        }
        *total_bytes += len;
        out.files.push(canonical);
    }
    false
}

pub fn gen_model_dir(app_local_data_dir: &Path, model_id: &str) -> PathBuf {
    app_local_data_dir.join("models").join(model_id)
}

pub fn gen_model_present(app_local_data_dir: &Path, model_id: &str) -> bool {
    let d = gen_model_dir(app_local_data_dir, model_id);
    d.join(GGUF_FILE).exists() && d.join(TOKENIZER_FILE).exists()
}

/// Prime the gen engine at startup only when the umbrella switch is on AND the
/// model is downloaded (mirrors `ai::should_prime_engine`).
pub fn should_prime_gen_engine(ai_enabled: bool, gen_model_present: bool) -> bool {
    ai_enabled && gen_model_present
}

/// Load the cached `GenExtractor` from disk (blocking; ~1 GB — call off the UI
/// thread). Returns a `String` error (best-effort; a failure just leaves the
/// feature gated off).
pub fn load_gen_engine(handle: &AppHandle, model_id: &str) -> Result<GenExtractor, String> {
    let dir = handle.path().app_local_data_dir().map_err(|e| e.to_string())?;
    let mdir = gen_model_dir(&dir, model_id);
    let def = resolve_gen(model_id).ok_or_else(|| "unknown gen model".to_string())?;
    GenExtractor::load(def, &mdir.join(GGUF_FILE), &mdir.join(TOKENIZER_FILE)).map_err(|e| e.to_string())
}

/// Shared, mutable snapshot of an in-flight gen-model download. Lives in
/// `AppState` behind an `Arc<Mutex<…>>` so the download task's progress callback
/// (running on a `spawn_blocking` thread) and the `ai_gen_model_download_status`
/// query (running on a command thread AFTER the Settings screen has remounted)
/// observe the same state. The FE component state is torn down on unmount; this
/// backend state is not — it is what lets a remounted Settings screen REHYDRATE
/// a download the user navigated away from.
#[derive(Default)]
pub struct GenDownloadState {
    /// A download task is currently running. While true, a 2nd `ai_gen_model_download`
    /// call is REFUSED instead of spawning a competing task (the double-download
    /// jitter / dest-file write race).
    pub active: bool,
    /// Set by `ai_gen_model_download_cancel`; polled by the download loop via
    /// `is_cancelled`. Reset by `begin()` so a new download starts live.
    pub cancelled: bool,
    /// Which artifact is downloading now: "gguf" or "tokenizer".
    pub what: String,
    pub downloaded: u64,
    pub total: u64,
}

impl GenDownloadState {
    /// Claim the download slot. Returns true and marks active when idle; returns
    /// false (caller must NOT spawn a task) when a download is already running.
    /// Resets the byte counters so a stale prior snapshot can't leak into the new run.
    pub fn begin(&mut self) -> bool {
        if self.active {
            return false;
        }
        *self = GenDownloadState { active: true, ..Default::default() };
        true
    }

    /// Release the slot (called on completion, whether success or error).
    pub fn end(&mut self) {
        self.active = false;
    }

    /// Record the latest progress for the status query to serve on rehydrate.
    pub fn note(&mut self, what: &str, downloaded: u64, total: u64) {
        self.what = what.to_string();
        self.downloaded = downloaded;
        self.total = total;
    }
}

/// Release the download slot and emit the terminal `ai_gen_model_done {ok, error}`
/// event (best-effort). Factored out so EVERY exit path — success, download error,
/// setup error — clears `active` and notifies a possibly-remounted Settings screen
/// (whose own `await` lives in the now-unmounted instance and can't update it).
///
/// The failure text travels in the event, not only in the command's `Err`. Both
/// fire on a failure and the event, being asynchronous, tends to arrive last —
/// so a payload carrying nothing but `ok: false` would overwrite whatever the
/// caller had just shown with a message that says nothing.
fn finish_gen_download(
    app: &AppHandle,
    dl: &std::sync::Mutex<GenDownloadState>,
    ok: bool,
    error: Option<&str>,
) {
    if let Ok(mut s) = dl.lock() {
        s.end();
    }
    let _ = app.emit(
        "ai_gen_model_done",
        serde_json::json!({ "ok": ok, "error": error }),
    );
}

/// Opt-in, audited, fail-closed download of the gen model (gguf + tokenizer),
/// then load it into the cache. Requires the `ai_enabled` umbrella. Guarded
/// against a concurrent 2nd call (`gen_download_in_progress`); progress is
/// mirrored into shared `AppState.gen_download` for rehydration, and a terminal
/// `ai_gen_model_done` event is emitted on every exit path.
#[tauri::command]
pub async fn ai_gen_model_download(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {

    {
        let mut g = state.gen_download.lock().map_err(|e| e.to_string())?;
        if !g.begin() {
            return Err("gen_download_in_progress".into());
        }
    }

    let def = match resolve_gen(GEN_MODEL_ID) {
        Some(d) => d,
        None => {
            finish_gen_download(&app, &state.gen_download, false, Some("unknown gen model"));
            return Err("unknown gen model".into());
        }
    };
    let dir = match app.path().app_local_data_dir() {
        Ok(d) => d,
        Err(e) => {
            let msg = e.to_string();
            finish_gen_download(&app, &state.gen_download, false, Some(&msg));
            return Err(msg);
        }
    };
    let mdir = gen_model_dir(&dir, GEN_MODEL_ID);
    if let Err(e) = std::fs::create_dir_all(&mdir) {
        let msg = e.to_string();
        finish_gen_download(&app, &state.gen_download, false, Some(&msg));
        return Err(msg);
    }
    let gguf_dest = mdir.join(GGUF_FILE);
    let tok_dest = mdir.join(TOKENIZER_FILE);

    let app2 = app.clone();
    let dl_move = state.gen_download.clone();
    let dl_result = tauri::async_runtime::spawn_blocking(move || -> Result<(), AiError> {
        let ag = app2.clone();
        let dl_g = dl_move.clone();
        let cancelled_g = dl_move.clone();
        kokos_ai::download::download_verified(def.url, &gguf_dest, def.sha256, "gen model gguf", move |d, t| {
            if let Ok(mut s) = dl_g.lock() {
                s.note("gguf", d, t);
            }
            let _ = ag.emit("ai_gen_model_progress", serde_json::json!({"what":"gguf","downloaded":d,"total":t}));
        }, || cancelled_g.lock().is_ok_and(|s| s.cancelled))?;
        let at = app2.clone();
        let dl_t = dl_move.clone();
        let cancelled_t = dl_move.clone();
        kokos_ai::download::download_verified(def.tokenizer_url, &tok_dest, def.tokenizer_sha256, "gen tokenizer", move |d, t| {
            if let Ok(mut s) = dl_t.lock() {
                s.note("tokenizer", d, t);
            }
            let _ = at.emit("ai_gen_model_progress", serde_json::json!({"what":"tokenizer","downloaded":d,"total":t}));
        }, || cancelled_t.lock().is_ok_and(|s| s.cancelled))?;
        Ok(())
    })
    .await;

    match dl_result {
        Ok(Ok(())) => {}
        Ok(Err(AiError::Cancelled)) => {
            finish_gen_download(&app, &state.gen_download, false, Some("cancelled"));
            return Err("cancelled".into());
        }
        Ok(Err(e)) => {
            let msg = e.to_string();
            finish_gen_download(&app, &state.gen_download, false, Some(&msg));
            return Err(msg);
        }
        Err(e) => {
            let msg = e.to_string();
            finish_gen_download(&app, &state.gen_download, false, Some(&msg));
            return Err(msg);
        }
    }

    crate::ai::audit_active_vault(&state, vec![("ai_gen_model_downloaded", Some(GEN_MODEL_ID.to_string()))]).await;

    match load_gen_engine(&app, GEN_MODEL_ID) {
        Ok(engine) => {
            if let Ok(mut c) = state.gen_engine.lock() {
                *c = Some(Arc::new(engine));
            }
        }
        Err(e) => eprintln!("[gen] load after download failed: {e}"),
    }

    finish_gen_download(&app, &state.gen_download, true, None);
    Ok(())
}

#[derive(serde::Serialize)]
pub struct GenDownloadStatus {
    pub active: bool,
    pub what: String,
    pub downloaded: u64,
    pub total: u64,
}

/// Snapshot of any in-flight gen-model download, so the Settings screen can
/// REHYDRATE the progress bar + busy state after a remount. Reads
/// the shared `AppState.gen_download` the download task keeps updating.
#[tauri::command]
pub fn ai_gen_model_download_status(state: State<'_, AppState>) -> Result<GenDownloadStatus, String> {
    let g = state.gen_download.lock().map_err(|e| e.to_string())?;
    Ok(GenDownloadStatus {
        active: g.active,
        what: g.what.clone(),
        downloaded: g.downloaded,
        total: g.total,
    })
}

/// Stop an in-flight `ai_gen_model_download`. The download loop polls the
/// flag after every chunk, deletes the half-written `.part` file and reports
/// `cancelled`; the awaiting download call then fails with it, and the
/// terminal `ai_gen_model_done` event carries `error: "cancelled"`.
#[tauri::command]
pub fn ai_gen_model_download_cancel(state: State<'_, AppState>) -> Result<(), String> {
    let mut g = state.gen_download.lock().map_err(|e| e.to_string())?;
    g.cancelled = true;
    Ok(())
}

/// Concatenate per-file proposals into one (order preserved), entries and
/// unparsed blocks alike. Pure — unit-tested.
fn merge_proposals(parts: Vec<ImportProposal>) -> ImportProposal {
    let mut merged = ImportProposal { entries: Vec::new(), unparsed: Vec::new(), entries_dropped: 0 };
    for p in parts {
        merged.entries.extend(p.entries);
        merged.unparsed.extend(p.unparsed);
        merged.entries_dropped = merged.entries_dropped.saturating_add(p.entries_dropped);
    }
    merged
}

/// Largest char boundary <= `max` bytes of `s`.
fn floor_boundary(s: &str, max: usize) -> usize {
    let mut i = max.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Raw-source preview for one entry: the blank-line-delimited block of `text`
/// that contains the entry's first field value (the block pre-parse split on),
/// falling back to the head of the file. Always bounded by
/// `MAX_SOURCE_PREVIEW_BYTES`, so memory is entries x constant, not entries x file.
fn source_preview(text: &str, e: &ProposedEntry) -> String {
    let hit = e.fields.iter().map(|f| f.value.as_str()).find(|v| !v.is_empty()).and_then(|v| text.find(v));
    let (start, end) = match hit {
        Some(pos) => {
            let start = text[..pos].rfind("\n\n").map(|i| i + 2).unwrap_or(0);
            let end = text[pos..].find("\n\n").map(|i| pos + i).unwrap_or(text.len());
            (start, end)
        }
        None => (0, text.len()),
    };
    let block = &text[start..end];
    block[..floor_boundary(block, MAX_SOURCE_PREVIEW_BYTES)].trim().to_string()
}

/// Keep at most `max` entries of a proposal; returns how many were dropped.
/// Pure — unit-tested.
fn cap_entries(p: &mut ImportProposal, max: usize) -> usize {
    let dropped = p.entries.len().saturating_sub(max);
    p.entries.truncate(max);
    p.entries_dropped = p.entries_dropped.saturating_add(dropped.try_into().unwrap_or(u32::MAX));
    dropped
}

/// Stamp `source_file` + a bounded `source_text` preview (the entry's own block,
/// see `source_preview`) on every entry (and `source_file` on every unparsed
/// block) of a per-file proposal. kokos-ai only ever sees the text
/// (path-agnostic), so both are attached here — the review UI shows the path as
/// provenance/title and offers a collapsible raw-data view of the entry's source.
/// Both are the user's own imported content, shown in-app only and NEVER logged
/// (the audit records counts, not names/paths/contents). Pure — unit-tested.
fn stamp_source(mut p: ImportProposal, path: &Path, text: &str) -> ImportProposal {
    let sf = path.display().to_string();
    for e in &mut p.entries {
        e.source_file = Some(sf.clone());
        e.source_text = Some(source_preview(text, e));
    }
    for b in &mut p.unparsed {
        b.source_file = Some(sf.clone());
    }
    p
}

/// Count a running analysis as user activity so the idle auto-lock watcher
/// (lib.rs) does not lock the vault mid-import. Called on every progress event
/// of `analyze_paths` only; once analysis ends the normal idle timeout resumes.
fn touch_activity(app: &AppHandle) {
    let st = app.state::<AppState>();
    let mut last = match st.last_activity.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    *last = std::time::Instant::now();
}

/// How long the analysis may go without a single progress event before the
/// heartbeat stops vouching for the user. One chunk is at most 1024 generated
/// tokens (minutes even on a slow CPU); anything past this is a hang, and a
/// hang must not hold an unlocked vault open indefinitely.
const HEARTBEAT_STALL: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Keeps `touch_activity` ticking while an analysis RUNS AND MAKES PROGRESS, so
/// a single slow chunk (no progress event for minutes) cannot trip the idle
/// auto-lock, while a stalled analysis cannot defeat it. Stops when dropped,
/// i.e. exactly when analysis ends; the normal idle timeout then resumes.
struct ActivityHeartbeat {
    stop: Arc<std::sync::atomic::AtomicBool>,
    progress: Arc<std::sync::Mutex<std::time::Instant>>,
}

impl ActivityHeartbeat {
    fn start(app: &AppHandle) -> Self {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let progress = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
        let (flag, last, app) = (stop.clone(), progress.clone(), app.clone());
        std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                let fresh = last.lock().map(|t| t.elapsed() < HEARTBEAT_STALL).unwrap_or(false);
                if fresh {
                    touch_activity(&app);
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        });
        Self { stop, progress }
    }

    /// Record a real progress event (file or chunk boundary).
    fn mark_progress(&self) {
        if let Ok(mut t) = self.progress.lock() {
            *t = std::time::Instant::now();
        }
    }
}

impl Drop for ActivityHeartbeat {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Shared per-file analyze loop (runs inside `spawn_blocking`). Reads each
/// ALREADY-VALIDATED path, size-caps, analyzes, zeroizes the plaintext, merges.
/// Callers guarantee every path is safe (allowlisted, or walked under a
/// canonical root) — there is deliberately no `is_allowed` here. Returns the
/// merged proposal + count of files that produced entries. Emits progress and
/// polls `cancel` between files.
fn analyze_paths(
    app: &AppHandle,
    engine: &GenExtractor,
    cancel: &std::sync::atomic::AtomicBool,
    files: Vec<PathBuf>,
    files_total: u32,
) -> (ImportProposal, u32, usize) {
    let heartbeat = ActivityHeartbeat::start(app);
    let mut parts: Vec<ImportProposal> = Vec::new();
    let mut kept = 0usize;
    let mut entries_dropped = 0usize;
    let mut files_ok = 0u32;
    // Sizes drive the UI's ETA (remaining bytes); unreadable files count as 0.
    let sizes: Vec<u64> = files
        .iter()
        .map(|p| std::fs::metadata(p).ok().filter(|m| m.is_file() && m.len() <= MAX_TEXT_IMPORT_SIZE).map_or(0, |m| m.len()))
        .collect();
    let bytes_total: u64 = sizes.iter().sum();
    let mut bytes_done = 0u64;
    for (i, path) in files.iter().enumerate() {
        if cancel.load(Ordering::SeqCst) {
            break;
        }
        // Base name only; the event stays in-process (webview), never logged.
        let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let file_bytes = sizes[i];
        let emit = |stage: &str, chunk_done: usize, chunk_total: usize| {
            heartbeat.mark_progress();
            touch_activity(app);
            let _ = app.emit(
                "ai_text_import_progress",
                serde_json::json!({
                    "file_index": i, "files_total": files_total, "stage": stage,
                    "file_name": file_name, "file_bytes": file_bytes,
                    "bytes_done": bytes_done, "bytes_total": bytes_total,
                    "chunk_done": chunk_done, "chunk_total": chunk_total,
                }),
            );
        };
        emit("read", 0, 0);
        let per_file: Option<ImportProposal> = (|| {
            // Type and size are checked on the opened handle, so a file
            // swapped after the walk cannot bypass the cap.
            let bytes = crate::paths::safe_io::read_regular_capped_path(path, MAX_TEXT_IMPORT_SIZE).ok()??;
            let mut text = match String::from_utf8(bytes) {
                Ok(t) => t,
                Err(e) => {
                    e.into_bytes().zeroize();
                    return None;
                }
            };
            emit("analyze", 0, 0);
            let res = analyze_text_with_progress(&text, engine, CHUNK_BUDGET_BYTES, &mut |d, t| emit("analyze", d, t)).ok().map(|mut p| {
                // Bound per file AND across the whole proposal before stamping
                // (stamping allocates a preview per surviving entry).
                let allow = MAX_ENTRIES_PER_FILE.min(MAX_ENTRIES_PER_PROPOSAL.saturating_sub(kept));
                entries_dropped += cap_entries(&mut p, allow);
                kept += p.entries.len();
                stamp_source(p, path, &text)
            });
            text.zeroize();
            res
        })();
        match per_file {
            Some(p) => {
                parts.push(p);
                files_ok += 1;
            }
            None => emit("skipped", 0, 0),
        }
        bytes_done += file_bytes;
    }
    (merge_proposals(parts), files_ok, entries_dropped)
}

/// Analyze allowlisted text files into ONE `ImportProposal`. Does NOT touch the
/// vault (committing is a separate step). Files cross as allowlisted PATHS,
/// re-validated + size-capped, read INSIDE `spawn_blocking`. Per-file isolation:
/// a bad file is skipped + reported (progress `stage:"skipped"`), the batch
/// continues.
#[tauri::command]
pub async fn ai_text_import_analyze(
    app: AppHandle,
    state: State<'_, AppState>,
    paths: Vec<String>,
) -> Result<ImportProposal, String> {
    let ai_enabled = state.settings.lock().map_err(|e| e.to_string())?.ai_enabled;
    if !ai_enabled {
        return Err("ai_not_enabled".into());
    }
    let engine = { state.gen_engine.lock().map_err(|e| e.to_string())?.clone() };
    let engine = engine.ok_or("gen_model_not_ready")?;

    for p in &paths {
        if !crate::paths::is_allowed(&state.allowed_paths, p) {
            return Err(kokos_core::error::VaultError::PathNotAllowed.to_string());
        }
    }

    state.gen_import_cancel.store(false, Ordering::SeqCst);
    let cancel = state.gen_import_cancel.clone();
    let files: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
    let files_total = files.len() as u32;
    let app2 = app.clone();

    let (proposal, files_ok, entries_dropped) = tauri::async_runtime::spawn_blocking(move || {
        analyze_paths(&app2, engine.as_ref(), &cancel, files, files_total)
    })
    .await
    .map_err(|e| e.to_string())?;

    crate::ai::audit_active_vault(
        &state,
        vec![("ai_text_import_analyzed", Some(format!("files:{}/{} entries:{} unparsed:{} entries_dropped:{}", files_ok, files_total, proposal.entries.len(), proposal.unparsed.len(), entries_dropped)))],
    )
    .await;

    Ok(proposal)
}

/// Analyze every safe `.txt/.md/.csv` file under an allowlisted ROOT directory
/// into ONE `ImportProposal` (bounded recursive walk). SECURITY: the root
/// must be allowlisted (added by the folder picker); the walk canonicalizes each
/// file under the root, never follows a symlinked dir, and is capped. Reuses the
/// single per-file integrity chokepoint via `analyze_paths`. Does NOT touch the vault.
#[tauri::command]
pub async fn ai_text_import_analyze_folder(
    app: AppHandle,
    state: State<'_, AppState>,
    dir: String,
) -> Result<ImportProposal, String> {
    let ai_enabled = state.settings.lock().map_err(|e| e.to_string())?.ai_enabled;
    if !ai_enabled {
        return Err("ai_not_enabled".into());
    }
    let engine = { state.gen_engine.lock().map_err(|e| e.to_string())?.clone() };
    let engine = engine.ok_or("gen_model_not_ready")?;

    if !crate::paths::is_allowed(&state.allowed_paths, &dir) {
        return Err(kokos_core::error::VaultError::PathNotAllowed.to_string());
    }

    state.gen_import_cancel.store(false, Ordering::SeqCst);
    let cancel = state.gen_import_cancel.clone();

    let dir_for_walk = dir.clone();
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        walk_import_dir(Path::new(&dir_for_walk), &WalkCaps::balanced())
    })
    .await
    .map_err(|e| e.to_string())?;

    let dropped_total = outcome.dropped.total();
    let truncated = outcome.dropped.truncated;
    let files = outcome.files;
    let files_total = files.len() as u32;
    let app2 = app.clone();

    let (proposal, files_ok, entries_dropped) = tauri::async_runtime::spawn_blocking(move || {
        analyze_paths(&app2, engine.as_ref(), &cancel, files, files_total)
    })
    .await
    .map_err(|e| e.to_string())?;

    crate::ai::audit_active_vault(
        &state,
        vec![("ai_text_import_analyzed", Some(format!("folder files:{}/{} dropped:{} truncated:{} entries:{} unparsed:{} entries_dropped:{}", files_ok, files_total, dropped_total, truncated, proposal.entries.len(), proposal.unparsed.len(), entries_dropped)))],
    )
    .await;

    Ok(proposal)
}

/// Cancel an in-flight analyze (polled between files).
#[tauri::command]
pub fn ai_text_import_cancel(state: State<'_, AppState>) {
    state.gen_import_cancel.store(true, Ordering::SeqCst);
}

const PENDING_IMPORT_LABEL: &[u8] = b"kokos:text-import:pending:v1";

/// Seal the frontend's review snapshot (source + edited drafts, a JSON string)
/// with a subkey of the open vault's key and keep only the ciphertext. Called
/// debounced while a review is open, so an idle auto-lock (which drops the
/// webview state) cannot lose the result: after unlocking the same vault,
/// `ai_text_import_restore` opens it again. Memory only, gone on app exit.
#[tauri::command]
pub fn ai_text_import_stash(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    mut payload: String,
) -> Result<(), String> {
    let sealed = (|| {
        let reg = state.sessions.lock().map_err(|e| e.to_string())?;
        let vid = reg.resolve(vault_id.as_deref()).ok_or("no_vault")?.to_string();
        let v = reg.get(&vid).and_then(|s| s.vault.as_ref()).ok_or("vault_locked")?;
        let sk = kokos_core::crypto::derive_subkey(&v.key, PENDING_IMPORT_LABEL);
        let nonce = kokos_core::crypto::random_nonce();
        let ct = kokos_core::crypto::encrypt(&sk, &nonce, payload.as_bytes()).map_err(|e| e.to_string())?;
        Ok::<_, String>((vid, crate::state::SealedImport { nonce, ct }))
    })();
    payload.zeroize();
    let (vid, sealed) = sealed?;
    state.pending_import.lock().map_err(|e| e.to_string())?.insert(vid, sealed);
    Ok(())
}

/// True if a sealed snapshot exists for the vault. Needs no key, so it also
/// answers while the vault is locked.
#[tauri::command]
pub fn ai_text_import_has_stash(state: State<'_, AppState>, vault_id: String) -> Result<bool, String> {
    Ok(state.pending_import.lock().map_err(|e| e.to_string())?.contains_key(&vault_id))
}

/// Open the sealed snapshot of an UNLOCKED vault. A snapshot that no longer
/// decrypts (different vault key) is dropped, never returned.
#[tauri::command]
pub fn ai_text_import_restore(
    state: State<'_, AppState>,
    vault_id: Option<String>,
) -> Result<Option<String>, String> {
    let reg = state.sessions.lock().map_err(|e| e.to_string())?;
    let vid = reg.resolve(vault_id.as_deref()).ok_or("no_vault")?.to_string();
    let v = reg.get(&vid).and_then(|s| s.vault.as_ref()).ok_or("vault_locked")?;
    let mut map = state.pending_import.lock().map_err(|e| e.to_string())?;
    let Some(sealed) = map.get(&vid) else { return Ok(None) };
    let sk = kokos_core::crypto::derive_subkey(&v.key, PENDING_IMPORT_LABEL);
    match kokos_core::crypto::decrypt(&sk, &sealed.nonce, &sealed.ct) {
        Ok(plain) => Ok(String::from_utf8(plain.to_vec()).ok()),
        Err(_) => {
            map.remove(&vid);
            Ok(None)
        }
    }
}

/// Forget the sealed snapshot (import committed, cancelled or closed).
#[tauri::command]
pub fn ai_text_import_discard(state: State<'_, AppState>, vault_id: String) -> Result<(), String> {
    state.pending_import.lock().map_err(|e| e.to_string())?.remove(&vault_id);
    Ok(())
}

#[derive(serde::Serialize)]
pub struct GenModelStatus {
    pub present: bool,
}

/// Whether the gen model (gguf + tokenizer) is on disk — gates the Data-tab
/// import entry point and drives the AI-tab download control's state.
#[tauri::command]
pub fn ai_gen_model_status(app: AppHandle) -> Result<GenModelStatus, String> {
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    Ok(GenModelStatus { present: gen_model_present(&dir, GEN_MODEL_ID) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::fs;
    use tempfile::tempdir;

    use kokos_ai::text_import::model::{EntryKind, FieldType, ImportProposal, ProposedEntry, ProposedField, UnparsedBlock};

    #[test]
    fn gen_download_begin_refuses_a_second_concurrent_call() {
        let mut s = GenDownloadState::default();
        assert!(s.begin(), "first begin claims the slot");
        assert!(s.active);
        assert!(!s.begin(), "second begin must be refused while a download is active");
    }

    #[test]
    fn gen_download_end_frees_the_slot_for_a_later_download() {
        let mut s = GenDownloadState::default();
        assert!(s.begin());
        s.end();
        assert!(!s.active);
        assert!(s.begin(), "after end() a fresh download may begin");
    }

    #[test]
    fn gen_download_begin_resets_stale_counters() {
        let mut s = GenDownloadState::default();
        assert!(s.begin());
        s.note("gguf", 500, 1000);
        s.end();
        assert!(s.begin());
        assert_eq!(s.downloaded, 0);
        assert_eq!(s.total, 0);
        assert_eq!(s.what, "");
    }

    #[test]
    fn gen_download_note_records_progress_for_the_status_query() {
        let mut s = GenDownloadState::default();
        s.begin();
        s.note("tokenizer", 42, 84);
        assert_eq!(s.what, "tokenizer");
        assert_eq!(s.downloaded, 42);
        assert_eq!(s.total, 84);
    }

    fn one(kind: EntryKind, value: &str) -> ImportProposal {
        ImportProposal { entries: vec![ProposedEntry {
            title: None, kind, source_file: None, source_text: None,
            fields: vec![ProposedField { field_type: FieldType::Note, value: value.into(), confidence: 1.0 }],
        }], unparsed: vec![], entries_dropped: 0 }
    }

    #[test]
    fn merge_proposals_concatenates_all_entries_in_order() {
        let merged = merge_proposals(vec![one(EntryKind::Login, "a"), one(EntryKind::ApiKey, "b")]);
        assert_eq!(merged.entries.len(), 2);
        assert_eq!(merged.entries[0].fields[0].value, "a");
        assert_eq!(merged.entries[1].fields[0].value, "b");
    }

    #[test]
    fn stamp_source_sets_the_path_and_own_block_on_every_entry() {
        let p = merge_proposals(vec![one(EntryKind::Login, "a"), one(EntryKind::ApiKey, "b")]);
        let stamped = stamp_source(p, Path::new("/tmp/import/codeanywhere.com.txt"), "user\npass: secret");
        assert_eq!(stamped.entries.len(), 2);
        assert!(stamped
            .entries
            .iter()
            .all(|e| e.source_file.as_deref() == Some("/tmp/import/codeanywhere.com.txt")));
        assert!(stamped
            .entries
            .iter()
            .all(|e| e.source_text.as_deref() == Some("user\npass: secret")));
    }

    #[test]
    fn source_preview_is_the_entry_block_and_bounded() {
        let e = one(EntryKind::Login, "b-secret").entries.remove(0);
        let text = format!("a: 1\n\nuser: x\nb-secret\n\nc: 3{}", "z".repeat(20_000));
        assert_eq!(source_preview(&text, &e), "user: x\nb-secret");
        let big = format!("b-secret{}", "é".repeat(20_000));
        let p = source_preview(&big, &e);
        assert!(p.len() <= MAX_SOURCE_PREVIEW_BYTES);
    }

    #[test]
    fn cap_entries_truncates_and_reports_dropped() {
        let mut p = merge_proposals(vec![one(EntryKind::Login, "a"), one(EntryKind::Login, "b"), one(EntryKind::Login, "c")]);
        assert_eq!(cap_entries(&mut p, 2), 1);
        assert_eq!(p.entries.len(), 2);
        assert_eq!(cap_entries(&mut p, 5), 0);
    }

    #[test]
    fn unparsed_blocks_survive_the_merge_and_carry_their_file() {
        let mut a = one(EntryKind::Login, "a");
        a.unparsed.push(UnparsedBlock { text: "Home wifi".into(), source_file: None });
        let a = stamp_source(a, Path::new("/tmp/import/a.txt"), "x");
        let b = stamp_source(one(EntryKind::Login, "b"), Path::new("/tmp/import/b.txt"), "y");
        let merged = merge_proposals(vec![a, b]);
        assert_eq!(merged.unparsed.len(), 1);
        assert_eq!(merged.unparsed[0].text, "Home wifi");
        assert_eq!(merged.unparsed[0].source_file.as_deref(), Some("/tmp/import/a.txt"));
    }

    #[test]
    fn merge_proposals_of_empty_is_empty() {
        assert!(merge_proposals(vec![]).entries.is_empty());
    }

    #[test]
    fn should_prime_only_when_enabled_and_present() {
        assert!(should_prime_gen_engine(true, true));
        assert!(!should_prime_gen_engine(true, false));
        assert!(!should_prime_gen_engine(false, true));
        assert!(!should_prime_gen_engine(false, false));
    }

    #[test]
    fn gen_model_dir_is_models_slash_id() {
        let d = gen_model_dir(Path::new("/data"), "qwen2.5-1.5b-instruct");
        assert!(d.ends_with("models/qwen2.5-1.5b-instruct"));
    }

    #[test]
    fn gen_model_present_false_when_files_missing() {
        let tmp = std::env::temp_dir().join("kokos_gen_present_test_absent");
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(!gen_model_present(&tmp, "qwen2.5-1.5b-instruct"));
    }

    fn small_caps() -> WalkCaps {
        WalkCaps { max_depth: 1, max_files: 100, max_total_bytes: 1_000_000, max_file_bytes: 1_000_000 }
    }

    #[test]
    fn balanced_caps_are_the_pinned_production_literals() {
        let c = WalkCaps::balanced();
        assert_eq!(c.max_depth, 16);
        assert_eq!(c.max_files, 100);
        assert_eq!(c.max_total_bytes, 32 * 1024 * 1024);
        assert_eq!(c.max_file_bytes, 4 * 1024 * 1024);
    }

    #[test]
    fn collects_matching_extensions_only() {
        let root = tempdir().unwrap();
        for (n, body) in [("a.txt", "a"), ("b.png", "b"), ("c.md", "c"), ("d.csv", "d"), ("e.exe", "e")] {
            fs::write(root.path().join(n), body).unwrap();
        }
        let out = walk_import_dir(root.path(), &small_caps());
        assert_eq!(out.files.len(), 3);
        assert_eq!(out.dropped.wrong_ext, 2);
    }

    #[test]
    fn recurses_into_real_subdirs_and_skips_dot_dirs() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("top.txt"), "t").unwrap();
        fs::create_dir(root.path().join("sub")).unwrap();
        fs::write(root.path().join("sub").join("nested.md"), "n").unwrap();
        fs::create_dir(root.path().join(".git")).unwrap();
        fs::write(root.path().join(".git").join("hidden.txt"), "h").unwrap();
        let out = walk_import_dir(root.path(), &small_caps());
        assert_eq!(out.files.len(), 2);
    }

    #[test]
    fn stops_at_max_depth() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("d0.txt"), "0").unwrap();
        fs::create_dir(root.path().join("s1")).unwrap();
        fs::write(root.path().join("s1").join("d1.txt"), "1").unwrap();
        fs::create_dir(root.path().join("s1").join("s2")).unwrap();
        fs::write(root.path().join("s1").join("s2").join("d2.txt"), "2").unwrap();
        let out = walk_import_dir(root.path(), &small_caps());
        assert_eq!(out.files.len(), 2);
        assert!(out.dropped.over_depth >= 1);
    }

    #[test]
    fn stops_at_max_file_count() {
        let root = tempdir().unwrap();
        for n in ["a.txt", "b.txt", "c.txt", "d.txt"] {
            fs::write(root.path().join(n), "x").unwrap();
        }
        let caps = WalkCaps { max_files: 2, ..small_caps() };
        let out = walk_import_dir(root.path(), &caps);
        assert_eq!(out.files.len(), 2);
        assert!(out.dropped.over_file_count >= 1);
    }

    #[test]
    fn stops_at_max_total_bytes() {
        let root = tempdir().unwrap();
        for n in ["a.txt", "b.txt", "c.txt"] {
            fs::write(root.path().join(n), "aaaaa").unwrap();
        }
        let caps = WalkCaps { max_total_bytes: 10, ..small_caps() };
        let out = walk_import_dir(root.path(), &caps);
        assert_eq!(out.files.len(), 2);
        assert_eq!(out.dropped.over_total_bytes, 1);
    }

    #[test]
    fn drops_files_over_per_file_size() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("small.txt"), "ab").unwrap();
        fs::write(root.path().join("big.txt"), "abcdef").unwrap();
        let caps = WalkCaps { max_file_bytes: 4, ..small_caps() };
        let out = walk_import_dir(root.path(), &caps);
        assert_eq!(out.files.len(), 1);
        assert!(out.files[0].ends_with("small.txt"));
        assert_eq!(out.dropped.over_file_size, 1);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_file_escaping_root() {
        use std::os::unix::fs::symlink;
        let outside = tempdir().unwrap();
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, "TOP-SECRET").unwrap();
        let root = tempdir().unwrap();
        fs::write(root.path().join("ok.txt"), "ok").unwrap();
        symlink(&secret, root.path().join("link.txt")).unwrap();
        let out = walk_import_dir(root.path(), &small_caps());
        assert_eq!(out.files.len(), 1);
        assert!(out.files[0].ends_with("ok.txt"));
        assert_eq!(out.dropped.not_under_root, 1);
        assert!(!out.files.iter().any(|p| p.ends_with("secret.txt")));
    }

    #[cfg(unix)]
    #[test]
    fn does_not_follow_symlinked_directory() {
        use std::os::unix::fs::symlink;
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("evil.txt"), "evil").unwrap();
        let root = tempdir().unwrap();
        fs::write(root.path().join("real.txt"), "real").unwrap();
        symlink(outside.path(), root.path().join("sub")).unwrap();
        let out = walk_import_dir(root.path(), &small_caps());
        assert_eq!(out.files.len(), 1);
        assert_eq!(out.dropped.symlink_dir, 1);
        assert!(!out.files.iter().any(|p| p.ends_with("evil.txt")));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_dir_cycle_does_not_hang() {
        use std::os::unix::fs::symlink;
        let root = tempdir().unwrap();
        fs::write(root.path().join("x.txt"), "x").unwrap();
        symlink(root.path(), root.path().join("loop")).unwrap();
        let out = walk_import_dir(root.path(), &small_caps());
        assert_eq!(out.files.len(), 1);
        assert!(out.dropped.symlink_dir >= 1);
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_is_counted_not_silent() {
        use std::os::unix::fs::symlink;
        let root = tempdir().unwrap();
        symlink(root.path().join("nonexistent-target"), root.path().join("dangling.txt")).unwrap();
        let out = walk_import_dir(root.path(), &small_caps());
        assert!(!out.files.iter().any(|p| p.ends_with("dangling.txt")));
        assert!(out.dropped.io_error >= 1);
        assert!(out.dropped.total() >= 1);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_subdir_is_counted_not_silent() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempdir().unwrap();
        let sub = root.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("a.txt"), "a").unwrap();
        fs::write(sub.join("b.txt"), "b").unwrap();
        fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).unwrap();
        let out = walk_import_dir(root.path(), &small_caps());
        fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(out.dropped.io_error >= 1);
    }

    #[test]
    fn walk_report_total_sums_every_reason() {
        let r = WalkReport {
            wrong_ext: 1,
            symlink_dir: 2,
            not_under_root: 3,
            over_file_size: 4,
            over_total_bytes: 5,
            over_file_count: 6,
            over_depth: 7,
            io_error: 8,
            truncated: false,
        };
        assert_eq!(r.total(), 36);
    }

    #[test]
    fn truncation_is_flagged_across_directory_boundary() {
        let root = tempdir().unwrap();
        fs::create_dir(root.path().join("a")).unwrap();
        fs::write(root.path().join("a").join("a1.txt"), "1").unwrap();
        fs::write(root.path().join("a").join("a2.txt"), "2").unwrap();
        fs::create_dir(root.path().join("b")).unwrap();
        fs::write(root.path().join("b").join("b1.txt"), "3").unwrap();
        let caps = WalkCaps { max_files: 2, ..small_caps() };
        let out = walk_import_dir(root.path(), &caps);
        assert_eq!(out.files.len(), 2);
        assert!(out.dropped.truncated);
    }

    #[test]
    fn file_exactly_at_size_cap_is_accepted() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("exact.txt"), "abcd").unwrap();
        fs::write(root.path().join("over.txt"), "abcde").unwrap();
        let caps = WalkCaps { max_file_bytes: 4, ..small_caps() };
        let out = walk_import_dir(root.path(), &caps);
        assert!(out.files.iter().any(|p| p.ends_with("exact.txt")));
        assert!(!out.files.iter().any(|p| p.ends_with("over.txt")));
        assert_eq!(out.dropped.over_file_size, 1);
    }
}

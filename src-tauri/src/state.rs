use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use crate::session_registry::SessionRegistry;

/// A loaded embedding backend, cached app-lifetime so re-embed-on-write does not
/// reload the ONNX session per keystroke. `embedder` is `Arc<dyn ...>` so it can
/// be cheaply cloned into a `spawn_blocking` closure. Cleared/replaced when the
/// model changes or AI is disabled.
#[derive(Clone)]
pub struct AiEngine {
    pub model_id: String,
    pub dim: u32,
    pub embedder: Arc<dyn kokos_ai::embed::Embedder>,
}

/// A text-import review snapshot sealed with a subkey of the vault key (see
/// `text_import::ai_text_import_stash`). Plaintext never rests here, so it
/// survives a vault lock as ciphertext only and is readable again only after
/// the same vault is unlocked.
pub struct SealedImport {
    pub nonce: [u8; kokos_core::crypto::NONCE_LEN],
    pub ct: Vec<u8>,
}

pub struct AppState {
    pub sessions: Mutex<SessionRegistry>,
    pub allowed_paths: Mutex<HashSet<PathBuf>>,
    pub settings: Mutex<crate::settings::Settings>,
    pub last_activity: Mutex<std::time::Instant>,
    pub pending_open: Mutex<Option<PathBuf>>,
    pub pending_restore: Mutex<Option<PendingRestore>>,
    /// Sealed text-import review snapshots, keyed by vault id. Memory only.
    pub pending_import: Mutex<HashMap<String, SealedImport>>,
    pub nmh: crate::nmh::NmhState,
    /// Per-session HIBP range cache: prefix → raw response body. A range
    /// response is PUBLIC k-anonymity data (anyone may query any prefix), so
    /// caching it app-lifetime leaks nothing; it just avoids re-fetching a
    /// prefix within a session.
    pub hibp_cache: Mutex<HashMap<String, String>>,
    /// Loaded embedding engine (None until `ai_enable` loads the model).
    pub ai_embedder: Mutex<Option<AiEngine>>,
    /// Set by `ai_backfill_cancel`, polled by an in-flight backfill loop.
    pub ai_backfill_cancel: Arc<AtomicBool>,
    /// Set by `ai_model_download_cancel`, polled by an in-flight model download.
    pub ai_download_cancel: Arc<AtomicBool>,
    /// Loaded generative extractor (None until the gen model is downloaded/primed).
    pub gen_engine: Mutex<Option<Arc<kokos_ai::text_import::engine::gen::GenExtractor>>>,
    /// Set by `ai_text_import_cancel`, polled by an in-flight analyze loop.
    pub gen_import_cancel: Arc<AtomicBool>,
    /// Snapshot of any in-flight gen-model download (active flag + progress),
    /// shared with the download task's progress callback so a remounted Settings
    /// screen can rehydrate it. `Arc` so it clones into `spawn_blocking`.
    pub gen_download: Arc<Mutex<crate::text_import::GenDownloadState>>,
    /// Paths restored from `settings.open_vaults` at launch that have NOT yet
    /// been unlocked this session. The frontend seeds them as locked,
    /// `registered:false` tabs; they never enter `sessions` until unlocked, so
    /// `persist_open_vaults` (which derives from the registry) would prune them
    /// the moment a partial subset is unlocked. Seeded at setup from the loaded
    /// settings; a path is removed the first time its vault enters `sessions`
    /// (so a later close correctly drops it — no resurrection). Unioned back in
    /// by `persist_open_vaults` so a partially-unlocked session survives relaunch
    pub restored_locked: Mutex<Vec<String>>,
}

/// Transient, in-memory holder for an in-progress Google Drive restore
/// Lives only between `gdrive_restore_signin` and `_bind`/`_cancel`.
/// Holds the OAuth refresh_token BEFORE a local vault path exists to key the
/// keyring by — so it stays in the backend, never reaches the WebView,
/// and is moved to the keyring at bind. Dropped on app exit.
pub struct PendingRestore {
    pub refresh_token: String,
    pub files: Vec<crate::gdrive::api::RemoteFile>,
    pub chosen_file_id: Option<String>,
}

impl std::fmt::Debug for PendingRestore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRestore")
            .field("refresh_token", &"<redacted>")
            .field("files", &self.files.len())
            .field("chosen_file_id", &self.chosen_file_id)
            .finish()
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(SessionRegistry::new()),
            allowed_paths: Mutex::new(HashSet::new()),
            settings: Mutex::new(crate::settings::Settings::default()),
            last_activity: Mutex::new(std::time::Instant::now()),
            pending_open: Mutex::new(None),
            pending_restore: Mutex::new(None),
            pending_import: Mutex::new(HashMap::new()),
            nmh: crate::nmh::NmhState::default(),
            hibp_cache: Mutex::new(HashMap::new()),
            ai_embedder: Mutex::new(None),
            ai_backfill_cancel: Arc::new(AtomicBool::new(false)),
            ai_download_cancel: Arc::new(AtomicBool::new(false)),
            gen_engine: Mutex::new(None),
            gen_import_cancel: Arc::new(AtomicBool::new(false)),
            gen_download: Arc::new(Mutex::new(crate::text_import::GenDownloadState::default())),
            restored_locked: Mutex::new(Vec::new()),
        }
    }
}

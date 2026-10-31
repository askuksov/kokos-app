use serde::{Deserialize, Serialize};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Settings {
    pub lang: String,
    pub auto_lock_minutes: u32,
    pub lock_on_blur: bool,
    pub lock_on_sleep: bool,
    pub clipboard_seconds: u32,
    pub clear_clipboard_on_exit: bool,
    pub conceal_on_blur: bool,
    pub conceal_seconds: u32,
    pub density: String,
    /// Native-messaging host: master switch. Off = no socket is bound at all.
    pub nmh_enabled: bool,
    /// "always" | "session_domain" | "remember_site" | "trust_extension".
    pub nmh_confirm_mode: String,
    /// Lifetime of a session_domain grant, in minutes.
    pub nmh_session_minutes: u32,
    /// Whitelisted extension origins/ids.
    pub nmh_chrome_ids: Vec<String>,
    pub nmh_firefox_ids: Vec<String>,
    /// HIBP breach check: opt-in, off by default. When true the Health
    /// dashboard may call `hibp_check`, which sends only a 5-char SHA-1 prefix.
    pub hibp_enabled: bool,
    /// Ordered paths of vaults open in tabs, for restore-on-restart (reopened
    /// LOCKED). Paths only — no key/password ever persists here.
    pub open_vaults: Vec<String>,
    /// Which of `open_vaults` was active. Restored as the focused tab.
    pub active_vault: Option<String>,
    /// Local-AI feature master switch. Off by default, audited on toggle.
    pub ai_enabled: bool,
    /// Active embedding model id ("small" | "mid" | "large"). Dev-facing in v1.
    pub ai_model: String,
    /// Getting-started card. App-global, never per vault.
    /// Set only when settings.json is created from scratch, so the card
    /// reaches fresh installs and not existing users on upgrade.
    pub onboarding_eligible: bool,
    /// The user closed the card for good.
    pub onboarding_dismissed: bool,
    /// The card is collapsed to a single line.
    pub onboarding_collapsed: bool,
    /// Sticky: an export succeeded at least once. Backend-written, because
    /// an export leaves no live state to query (the in-vault audit log is
    /// capped at 500 rows and the user can clear it).
    pub onboarding_backup_done: bool,
    /// Sticky: an import succeeded at least once. Same reasoning.
    pub onboarding_import_done: bool,
    /// The user answered "Later" on the sync step, which completes it.
    pub onboarding_sync_deferred: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lang: "en".into(),
            auto_lock_minutes: 15,
            lock_on_blur: false,
            lock_on_sleep: true,
            clipboard_seconds: 30,
            clear_clipboard_on_exit: true,
            conceal_on_blur: true,
            conceal_seconds: 30,
            density: "comfortable".into(),
            nmh_enabled: false,
            nmh_confirm_mode: "always".into(),
            nmh_session_minutes: 5,
            nmh_chrome_ids: Vec::new(),
            nmh_firefox_ids: Vec::new(),
            hibp_enabled: false,
            open_vaults: Vec::new(),
            active_vault: None,
            ai_enabled: false,
            ai_model: "mid".into(),
            onboarding_eligible: false,
            onboarding_dismissed: false,
            onboarding_collapsed: false,
            onboarding_backup_done: false,
            onboarding_import_done: false,
            onboarding_sync_deferred: false,
        }
    }
}

fn file(dir: &Path) -> std::path::PathBuf {
    dir.join("settings.json")
}

/// A readable settings.json — even a corrupt one — means an existing user, so
/// `onboarding_eligible` stays false and the getting-started card never
/// surprises someone mid-upgrade. Only a missing file is a fresh install.
/// Any other read error (permission denied, ACL issues, antivirus locks, etc.)
/// is treated as an existing user whose file we failed to read.
pub fn load(dir: &Path) -> Settings {
    match std::fs::read_to_string(file(dir)) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Settings { onboarding_eligible: true, ..Default::default() },
        Err(_) => Settings::default(),
    }
}

pub fn save(dir: &Path, s: &Settings) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join("settings.json.tmp");
    let data = serde_json::to_string_pretty(s)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(&tmp, data)?;
    #[cfg(unix)]
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, file(dir))?;
    Ok(())
}

/// Overwrite the backend-owned fields of an incoming (WebView-supplied)
/// `Settings` with the trusted `cached` values, so a `set_settings` payload can
/// never clobber them. `open_vaults`/`active_vault` are written only by
/// `persist_open_vaults`; `ai_enabled`/`ai_model` are changed only via
/// `ai_enable`/`ai_disable` (audited download+verify) and the dev config — a
/// direct flip here would bypass that audit.
/// `onboarding_eligible`/`onboarding_backup_done`/`onboarding_import_done` are
/// observations the backend makes, so the WebView cannot forge them; the other
/// `onboarding_*` fields are plain user choices and stay editable.
/// Everything else stays user-editable.
pub fn preserve_backend_managed(incoming: &mut Settings, cached: &Settings) {
    incoming.open_vaults = cached.open_vaults.clone();
    incoming.active_vault = cached.active_vault.clone();
    incoming.ai_enabled = cached.ai_enabled;
    incoming.ai_model = cached.ai_model.clone();
    incoming.onboarding_eligible = cached.onboarding_eligible;
    incoming.onboarding_backup_done = cached.onboarding_backup_done;
    incoming.onboarding_import_done = cached.onboarding_import_done;
}

/// A one-shot event the getting-started card has no live state to query for.
#[derive(Clone, Copy, Debug)]
pub enum OnboardingFact {
    Backup,
    Import,
}

/// Records a one-shot onboarding fact in the cached settings and flushes them
/// to disk. Already-set facts return early, so the common path writes nothing.
/// Callers ignore the error: failing to remember a tick must never fail the
/// export or import that earned it.
pub fn mark_done(dir: &Path, s: &mut Settings, fact: OnboardingFact) -> std::io::Result<()> {
    let slot = match fact {
        OnboardingFact::Backup => &mut s.onboarding_backup_done,
        OnboardingFact::Import => &mut s.onboarding_import_done,
    };
    if *slot {
        return Ok(());
    }
    *slot = true;
    save(dir, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_missing_file_returns_default() {
        let d = tempfile::tempdir().unwrap();
        let s = load(d.path());
        assert_eq!(s.auto_lock_minutes, 15);
        assert_eq!(s.clipboard_seconds, 30);
        assert!(s.lock_on_sleep);
        assert_eq!(s.lang, "en");
    }

    #[test]
    fn save_then_load_roundtrips() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Settings::default();
        s.auto_lock_minutes = 5;
        s.lang = "ru".into();
        save(d.path(), &s).unwrap();
        let got = load(d.path());
        assert_eq!(got.auto_lock_minutes, 5);
        assert_eq!(got.lang, "ru");
    }

    #[test]
    fn corrupt_json_returns_default_not_err() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("settings.json"), b"{ not json").unwrap();
        assert_eq!(load(d.path()).auto_lock_minutes, 15);
    }

    #[test]
    fn save_is_atomic_no_tmp_left() {
        let d = tempfile::tempdir().unwrap();
        save(d.path(), &Settings::default()).unwrap();
        assert!(!d.path().join("settings.json.tmp").exists());
    }

    /// The actual no-migration guarantee: a `settings.json` written by a
    /// build that predates the `nmh_*` fields must still load, and the new
    /// fields must come back as their defaults. `load_missing_file_returns_default`
    /// covers a MISSING file, not an EXISTING file with an older shape.
    #[test]
    fn pre_nmh_settings_json_still_loads_with_nmh_defaults() {
        let d = tempfile::tempdir().unwrap();
        let old_json = r#"{
            "lang": "en",
            "auto_lock_minutes": 15,
            "lock_on_blur": false,
            "lock_on_sleep": true,
            "clipboard_seconds": 30,
            "clear_clipboard_on_exit": true,
            "conceal_on_blur": true,
            "conceal_seconds": 30,
            "density": "comfortable"
        }"#;
        std::fs::write(d.path().join("settings.json"), old_json).unwrap();
        let s = load(d.path());
        assert_eq!(s.lang, "en", "the pre-existing fields still load");
        assert!(!s.nmh_enabled);
        assert_eq!(s.nmh_confirm_mode, "always");
        assert_eq!(s.nmh_session_minutes, 5);
        assert!(s.nmh_chrome_ids.is_empty());
        assert!(s.nmh_firefox_ids.is_empty());
    }

    #[test]
    fn hibp_enabled_defaults_off_and_roundtrips() {
        let d = tempfile::tempdir().unwrap();
        assert!(!load(d.path()).hibp_enabled, "off by default");
        let mut s = Settings::default();
        s.hibp_enabled = true;
        save(d.path(), &s).unwrap();
        assert!(load(d.path()).hibp_enabled, "persists true");
    }

    #[test]
    fn pre_hibp_settings_json_loads_with_hibp_off() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("settings.json"),
            br#"{ "lang": "en", "auto_lock_minutes": 15 }"#,
        )
        .unwrap();
        assert!(!load(d.path()).hibp_enabled);
    }

    #[test]
    fn open_vaults_default_empty_and_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        assert!(load(d.path()).open_vaults.is_empty(), "default empty");
        assert!(load(d.path()).active_vault.is_none());
        let mut s = Settings::default();
        s.open_vaults = vec!["/x/a.kokos".into(), "/y/b.kokos".into()];
        s.active_vault = Some("/y/b.kokos".into());
        save(d.path(), &s).unwrap();
        let got = load(d.path());
        assert_eq!(got.open_vaults, vec!["/x/a.kokos", "/y/b.kokos"]);
        assert_eq!(got.active_vault.as_deref(), Some("/y/b.kokos"));
    }

    #[test]
    fn pre_multivault_settings_json_loads_with_empty_open_vaults() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("settings.json"), br#"{ "lang": "en" }"#).unwrap();
        let s = load(d.path());
        assert!(s.open_vaults.is_empty());
        assert!(s.active_vault.is_none());
    }

    #[test]
    fn ai_defaults_off_mid_and_roundtrips() {
        let d = tempfile::tempdir().unwrap();
        let s = load(d.path());
        assert!(!s.ai_enabled, "AI off by default");
        assert_eq!(s.ai_model, "mid", "default model id (MiniLM)");

        let mut s = Settings::default();
        s.ai_enabled = true;
        s.ai_model = "large".into();
        save(d.path(), &s).unwrap();
        let got = load(d.path());
        assert!(got.ai_enabled);
        assert_eq!(got.ai_model, "large");
    }

    #[test]
    fn pre_ai_settings_json_loads_with_ai_off() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("settings.json"),
            br#"{ "lang": "en", "auto_lock_minutes": 15 }"#,
        )
        .unwrap();
        let s = load(d.path());
        assert!(!s.ai_enabled);
        assert_eq!(s.ai_model, "mid");
    }

    #[test]
    fn preserve_backend_managed_locks_backend_owned_fields() {
        let mut cached = Settings::default();
        cached.ai_enabled = true;
        cached.ai_model = "large".into();
        cached.open_vaults = vec!["/x/a.kokos".into()];
        cached.active_vault = Some("/x/a.kokos".into());

        let mut incoming = Settings::default();
        incoming.ai_enabled = false;
        incoming.ai_model = "small".into();
        incoming.lang = "ru".into();

        preserve_backend_managed(&mut incoming, &cached);

        assert!(incoming.ai_enabled, "ai_enabled is only changed via ai_enable/ai_disable");
        assert_eq!(incoming.ai_model, "large", "ai_model is dev-managed, not WebView-settable");
        assert_eq!(incoming.open_vaults, vec!["/x/a.kokos".to_string()]);
        assert_eq!(incoming.active_vault.as_deref(), Some("/x/a.kokos"));
        assert_eq!(incoming.lang, "ru");
    }

    #[test]
    fn fresh_install_marks_onboarding_eligible() {
        let d = tempfile::tempdir().unwrap();
        let s = load(d.path());
        assert!(s.onboarding_eligible, "a missing settings.json means a fresh install");
        assert!(!s.onboarding_dismissed);
        assert!(!s.onboarding_collapsed);
        assert!(!s.onboarding_backup_done);
        assert!(!s.onboarding_import_done);
        assert!(!s.onboarding_sync_deferred);
    }

    /// The "new users only" guarantee: an existing settings.json predates the
    /// feature, so its owner is not a fresh install and never sees the card.
    #[test]
    fn existing_settings_json_is_not_onboarding_eligible() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("settings.json"), br#"{ "lang": "en" }"#).unwrap();
        assert!(!load(d.path()).onboarding_eligible);
    }

    #[test]
    fn corrupt_settings_json_is_not_onboarding_eligible() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("settings.json"), b"{ not json").unwrap();
        let s = load(d.path());
        assert!(!s.onboarding_eligible, "a corrupt file still means an existing user");
        assert_eq!(s.auto_lock_minutes, 15, "and the rest still falls back to defaults");
    }

    /// A settings.json that exists but cannot be read is an existing user
    /// whose file we failed to open — not a fresh install. Only NotFound
    /// means fresh.
    #[test]
    #[cfg(unix)]
    fn unreadable_settings_json_is_not_onboarding_eligible() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("settings.json");
        std::fs::write(&f, br#"{ "lang": "en" }"#).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
        let s = load(d.path());
        // Restore permissions so the tempdir can clean itself up.
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!s.onboarding_eligible, "an unreadable file is not a fresh install");
    }

    #[test]
    fn onboarding_flags_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Settings::default();
        s.onboarding_eligible = true;
        s.onboarding_collapsed = true;
        s.onboarding_sync_deferred = true;
        save(d.path(), &s).unwrap();
        let got = load(d.path());
        assert!(got.onboarding_eligible);
        assert!(got.onboarding_collapsed);
        assert!(got.onboarding_sync_deferred);
        assert!(!got.onboarding_dismissed);
    }

    #[test]
    fn preserve_backend_managed_locks_onboarding_backend_fields() {
        let mut cached = Settings::default();
        cached.onboarding_eligible = true;
        cached.onboarding_backup_done = true;
        cached.onboarding_import_done = true;

        let mut incoming = Settings::default();
        incoming.onboarding_eligible = false;
        incoming.onboarding_backup_done = false;
        incoming.onboarding_import_done = false;
        incoming.onboarding_dismissed = true;
        incoming.onboarding_collapsed = true;
        incoming.onboarding_sync_deferred = true;

        preserve_backend_managed(&mut incoming, &cached);

        assert!(incoming.onboarding_eligible, "the WebView cannot forge eligibility");
        assert!(incoming.onboarding_backup_done, "backup is backend-observed");
        assert!(incoming.onboarding_import_done, "import is backend-observed");
        assert!(incoming.onboarding_dismissed, "dismiss stays user-editable");
        assert!(incoming.onboarding_collapsed, "collapse stays user-editable");
        assert!(incoming.onboarding_sync_deferred, "deferring sync stays user-editable");
    }

    #[test]
    fn mark_done_sets_the_flag_and_persists() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Settings::default();
        mark_done(d.path(), &mut s, OnboardingFact::Backup).unwrap();
        assert!(s.onboarding_backup_done, "the in-memory cache is updated too");
        assert!(load(d.path()).onboarding_backup_done, "and it survives a reload");
        assert!(!load(d.path()).onboarding_import_done, "other facts are untouched");
    }

    #[test]
    fn mark_done_is_idempotent_and_skips_the_write() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Settings::default();
        s.onboarding_import_done = true;
        mark_done(d.path(), &mut s, OnboardingFact::Import).unwrap();
        assert!(s.onboarding_import_done);
        assert!(
            !d.path().join("settings.json").exists(),
            "an already-set fact writes nothing, so a read-only config dir cannot fail an import"
        );
    }

    /// A failing save must surface as an Err the caller can ignore — never a
    /// panic inside an export/import command.
    #[test]
    fn mark_done_reports_io_error() {
        let d = tempfile::tempdir().unwrap();
        let blocked = d.path().join("settings.json");
        std::fs::create_dir(&blocked).unwrap();
        let mut s = Settings::default();
        let r = mark_done(d.path(), &mut s, OnboardingFact::Backup);
        assert!(r.is_err(), "a directory where the file belongs makes the rename fail");
        assert!(s.onboarding_backup_done, "the cache still reflects the fact");
    }
}

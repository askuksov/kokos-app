//! Where a new vault defaults to, and why an existing one may refuse to open.
//! Both answers change inside a snap, so they live together.
//!
//! Snap is detected through `crate::nmh::snap` and nowhere else — that module
//! asks for exactly one probe in the codebase, and a second one could disagree
//! with it.

use std::path::{Component, Path, PathBuf};

/// Names `xdg-user-dirs` gives the Documents folder across locales, English
/// first. A snap cannot read the real `~/.config/user-dirs.dirs` (the `home`
/// interface grants nothing under a dot-directory) and no portal reports the
/// user's special directories, so the localised name is found by probing the
/// visible top level of `$SNAP_REAL_HOME` — which `home` does allow — for
/// these. A miss is harmless: the caller falls back to the English path and
/// `usable_dir` drops it.
const DOCUMENTS_DIR_NAMES: &[&str] = &[
    "Documents", "Документы", "Документи", "Dokumente", "Documentos", "Documenti", "Documenten",
    "Dokumenty", "Dokument", "Dokumenter", "Dokumenti", "Dokumentai", "Dokumendid", "Dokumentumok",
    "Documente", "Belgeler", "Asiakirjat", "Dokumen", "Tài liệu", "Έγγραφα", "ドキュメント", "文档",
    "文件", "문서", "מסמכים", "المستندات",
];

/// First existing documents folder under a snap's real home, else the English
/// path (which may not exist; `usable_dir` handles that).
fn snap_documents_dir(real_home: &Path) -> PathBuf {
    DOCUMENTS_DIR_NAMES
        .iter()
        .map(|n| real_home.join(n))
        .find(|p| p.is_dir())
        .unwrap_or_else(|| real_home.join("Documents"))
}

/// Directory the "create vault" dialog opens in.
///
/// Inside a snap this has to come from `$SNAP_REAL_HOME`: snapd points `$HOME`
/// at `$SNAP_USER_DATA` (`~/snap/kokos/<revision>`), so the platform's own
/// document directory resolves into a revision-scoped tree that `snap remove`
/// deletes. The localised folder name lives in
/// `$SNAP_REAL_HOME/.config/user-dirs.dirs`, unreadable from the snap, so
/// `snap_documents_dir` probes the known translated names instead. On a
/// folder named outside that table nothing exists at the English path,
/// `usable_dir` drops it, and the dialog falls back to its own default — a
/// soft failure, which is why nothing here creates directories.
///
/// Outside a snap `document_dir` is already the right answer, including the
/// XDG-localised name on Linux.
pub fn default_save_dir_from(
    snap_real_home: Option<&Path>,
    document_dir: Option<&Path>,
) -> Option<PathBuf> {
    match snap_real_home {
        Some(h) => Some(snap_documents_dir(h)),
        None => document_dir.map(Path::to_path_buf),
    }
}

/// Drops a candidate that is not an existing directory. Never creates one:
/// opening a file dialog is not a reason to make a folder in someone's home.
pub fn usable_dir(candidate: Option<PathBuf>) -> Option<PathBuf> {
    candidate.filter(|p| p.is_dir())
}

/// `default_save_dir_from` against the live environment, already filtered by
/// `usable_dir` so the caller can pass the result straight to `set_directory`.
pub fn default_save_dir(app: &tauri::AppHandle) -> Option<PathBuf> {
    use tauri::Manager;
    let doc = app.path().document_dir().ok();
    usable_dir(default_save_dir_from(
        crate::nmh::snap::real_home().as_deref(),
        doc.as_deref(),
    ))
}

/// Buckets an unreachable path by the most plausible reason a strictly
/// confined snap could not reach it, so `explain_permission_denied` can name
/// a cause instead of asserting one it has not established.
///
/// A removable-media mount is checked first because that failure is
/// unconditional once the mount point matches — the plug is either
/// connected or it is not — whereas a dot-component is merely the *usual*
/// reason a `~`-rooted path is refused.
#[derive(Debug, PartialEq, Eq)]
enum UnreachablePathCause {
    /// Under a removable-media mount point (`/media`, `/mnt`, `/run/media`).
    /// `packaging/snap/snapcraft.yaml` declares `removable-media` for
    /// exactly this ("a vault on a USB stick"), but like `personal-files`
    /// that interface never auto-connects — so a USB vault on a fresh
    /// install is a near-certain `EACCES` until the user runs `snap
    /// connect`.
    RemovableMedia,
    /// A dot-prefixed component anywhere in the path (e.g. `~/.local/share`)
    /// — the `home` interface grants nothing under one, unconditionally.
    HiddenDirectory,
    /// Neither of the above: outside `$HOME` entirely, or a document-portal
    /// path (`/run/user/<uid>/doc/<id>/…`) if the portal turns out to hand
    /// those back — still an open question. Naming a specific wrong cause
    /// here would actively mislead; naming none is honest.
    Unknown,
}

fn classify_unreachable_path(path: &str) -> UnreachablePathCause {
    const REMOVABLE_MOUNTS: [&str; 3] = ["/media", "/mnt", "/run/media"];
    let p = Path::new(path);
    if REMOVABLE_MOUNTS.iter().any(|root| p.starts_with(root)) {
        return UnreachablePathCause::RemovableMedia;
    }
    let has_dot_component = p.components().any(|c| match c {
        Component::Normal(s) => s.to_str().is_some_and(|s| s.starts_with('.')),
        _ => false,
    });
    if has_dot_component {
        return UnreachablePathCause::HiddenDirectory;
    }
    UnreachablePathCause::Unknown
}

/// Why a vault file could not be read or written, for the one error the user
/// can act on. Only ever called for `VaultError::PermissionDenied`.
///
/// `snap` is the instance name when confined; off-snap the OS message is
/// already the whole story and no classification runs.
///
/// Says "cannot access" rather than "cannot open", and "choose a folder"
/// rather than "move the vault": `create_vault` reaches this same helper on
/// a write-time `EACCES` too, where the file was never created and so
/// cannot be moved or reopened. The cause named below comes from
/// `classify_unreachable_path` rather than being asserted outright, because
/// `PermissionDenied` alone does not say which of several plausible
/// confinement gaps produced it.
pub fn explain_permission_denied(path: &str, snap: Option<&str>) -> String {
    let Some(instance) = snap else {
        return format!("Kokos cannot access {path}: permission denied by the operating system.");
    };
    match classify_unreachable_path(path) {
        UnreachablePathCause::HiddenDirectory => format!(
            "Kokos cannot access {path}. The Snap package has no access to hidden folders — \
             any path with a dot-prefixed component, such as ~/.local/share. Choose a folder \
             like ~/Documents instead."
        ),
        UnreachablePathCause::RemovableMedia => format!(
            "Kokos cannot access {path}. Removable media is not connected for this Snap \
             package yet — run snap connect {instance}:removable-media, then try again."
        ),
        UnreachablePathCause::Unknown => format!(
            "Kokos cannot access {path}: the Snap package's sandbox cannot reach that \
             location. Choose a folder under your home directory, such as ~/Documents."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn snap_derives_documents_from_the_real_home() {
        let snap = PathBuf::from("/home/ann");
        let doc = PathBuf::from("/home/ann/snap/kokos/x1/Documents");
        assert_eq!(
            default_save_dir_from(Some(&snap), Some(&doc)),
            Some(PathBuf::from("/home/ann/Documents")),
            "inside a snap $HOME is $SNAP_USER_DATA, so document_dir() points into the \
             revision-scoped tree and must lose to $SNAP_REAL_HOME"
        );
    }

    #[test]
    fn snap_wins_even_when_the_platform_dir_is_absent() {
        let snap = PathBuf::from("/home/ann");
        assert_eq!(
            default_save_dir_from(Some(&snap), None),
            Some(PathBuf::from("/home/ann/Documents"))
        );
    }

    #[test]
    fn outside_a_snap_the_platform_dir_is_used_verbatim() {
        let doc = PathBuf::from("/home/ann/Документы");
        assert_eq!(
            default_save_dir_from(None, Some(&doc)),
            Some(PathBuf::from("/home/ann/Документы")),
            "off-snap the XDG-localised name is the right answer and must not be \
             replaced with a hardcoded English one"
        );
    }

    #[test]
    fn a_snap_finds_the_localised_documents_folder() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("Документы")).unwrap();
        assert_eq!(
            default_save_dir_from(Some(home.path()), None),
            Some(home.path().join("Документы"))
        );
    }

    #[test]
    fn a_snap_prefers_english_documents_when_both_exist() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("Documents")).unwrap();
        std::fs::create_dir(home.path().join("Документы")).unwrap();
        assert_eq!(
            default_save_dir_from(Some(home.path()), None),
            Some(home.path().join("Documents"))
        );
    }

    #[test]
    fn a_snap_with_no_known_folder_falls_back_to_the_english_path() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(
            default_save_dir_from(Some(home.path()), None),
            Some(home.path().join("Documents"))
        );
    }

    #[test]
    fn nothing_resolves_to_nothing() {
        assert_eq!(default_save_dir_from(None, None), None);
    }

    #[test]
    fn usable_dir_keeps_an_existing_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(usable_dir(Some(dir.path().to_path_buf())), Some(dir.path().to_path_buf()));
    }

    #[test]
    fn usable_dir_drops_a_missing_path_without_creating_it() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("Documents");
        assert_eq!(usable_dir(Some(missing.clone())), None);
        assert!(!missing.exists(), "a dropped candidate must never be created on the user's disk");
    }

    #[test]
    fn usable_dir_drops_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("Documents");
        std::fs::write(&f, b"not a directory").unwrap();
        assert_eq!(usable_dir(Some(f)), None);
    }

    #[test]
    fn usable_dir_drops_nothing() {
        assert_eq!(usable_dir(None), None);
    }

    #[test]
    fn snap_explanation_names_the_cause_and_the_fix() {
        let msg = explain_permission_denied("/home/ann/.local/share/passwords.kokos", Some("kokos"));
        assert!(msg.contains("/home/ann/.local/share/passwords.kokos"), "must name the file");
        assert!(msg.contains("hidden folder"), "must name the cause");
        assert!(msg.contains("~/Documents"), "must name the fix");
    }

    #[test]
    fn off_snap_explanation_stays_plain() {
        let msg = explain_permission_denied("/x/passwords.kokos", None);
        assert!(msg.contains("/x/passwords.kokos"));
        assert!(!msg.contains("Snap"), "confinement advice off-snap would be a wrong diagnosis");
    }


    #[test]
    fn classifies_a_dot_component_as_a_hidden_directory() {
        assert_eq!(
            classify_unreachable_path("/home/ann/.local/share/passwords.kokos"),
            UnreachablePathCause::HiddenDirectory
        );
    }

    #[test]
    fn classifies_a_media_mount_as_removable_media() {
        assert_eq!(
            classify_unreachable_path("/media/ann/usbstick/passwords.kokos"),
            UnreachablePathCause::RemovableMedia
        );
    }

    #[test]
    fn classifies_a_run_media_mount_as_removable_media() {
        assert_eq!(
            classify_unreachable_path("/run/media/ann/usbstick/passwords.kokos"),
            UnreachablePathCause::RemovableMedia
        );
    }

    #[test]
    fn classifies_a_plain_unreachable_path_as_unknown() {
        assert_eq!(classify_unreachable_path("/srv/vault.kokos"), UnreachablePathCause::Unknown);
    }

    #[test]
    fn classifies_a_document_portal_path_as_unknown() {
        assert_eq!(
            classify_unreachable_path("/run/user/1000/doc/abcd1234/passwords.kokos"),
            UnreachablePathCause::Unknown
        );
    }

    #[test]
    fn removable_media_explanation_names_the_connect_command() {
        let msg = explain_permission_denied("/media/ann/usbstick/passwords.kokos", Some("kokos"));
        assert!(
            msg.contains("snap connect kokos:removable-media"),
            "must name the exact fix, using the given instance name: {msg}"
        );
    }

    #[test]
    fn unknown_cause_explanation_does_not_assert_a_cause_it_has_not_established() {
        let msg = explain_permission_denied("/srv/vault.kokos", Some("kokos"));
        assert!(!msg.contains("hidden folder"), "a plain unreachable path is not a hidden-folder refusal: {msg}");
        assert!(!msg.contains("removable"), "a plain unreachable path is not a removable-media refusal: {msg}");
    }


    #[test]
    fn explanation_wording_does_not_assume_the_file_already_exists() {
        for path in [
            "/home/ann/.local/share/passwords.kokos",
            "/media/ann/usbstick/passwords.kokos",
            "/srv/vault.kokos",
        ] {
            let msg = explain_permission_denied(path, Some("kokos"));
            assert!(!msg.to_lowercase().contains("move"), "advice must not assume the file exists yet: {msg}");
        }
    }
}

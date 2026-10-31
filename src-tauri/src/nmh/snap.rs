//! Snap-confinement seams for the native-messaging install path.
//!
//! Everything here exists because a snapped Kokos and the browser it talks to
//! live on opposite sides of a sandbox boundary, which breaks two of the
//! assumptions `manifest.rs` and the command layer are otherwise entitled to
//! make on Linux:
//!
//!  - **`$HOME` is not the user's home.** snapd remaps it to `$SNAP_USER_DATA`
//!    (`~/snap/kokos/<revision>`). The browser reads its native-messaging
//!    manifest from the *real* home, so writing under `$HOME` would put the
//!    file somewhere no browser ever looks. snapd exports the real one as
//!    `$SNAP_REAL_HOME`.
//!  - **`current_exe()` names a path only the sandbox can resolve.** Inside
//!    the snap the sidecar is `/snap/kokos/<rev>/usr/bin/kokos-nmh`, which the
//!    browser — running in its own mount namespace — cannot execute. snapd
//!    publishes a host-visible wrapper for every declared app as
//!    `/snap/bin/<instance>.<app>`, and that is the only path worth putting in
//!    a manifest.
//!
//! Reaching the real home also needs a `personal-files` plug (see
//! `packaging/snap/snapcraft.yaml`); that interface is not auto-connected, so
//! the write can still fail with `PermissionDenied` even when everything here
//! resolves. That surfaces as the ordinary `internal` install error rather
//! than being special-cased — the Settings UI's job is to report that the
//! install did not happen, and inventing a snap-specific token would not tell
//! the user anything they can act on from inside the app.
//!
//! Following this module's neighbours, the decisions are pure functions taking
//! the environment explicitly; only the thin wrappers at the bottom read the
//! process environment, so the behaviour is testable without a snap.

use std::path::{Path, PathBuf};

/// Name of the `apps:` entry in `snapcraft.yaml` that exposes the sidecar.
/// Must stay in step with `packaging/snap/snapcraft.yaml`: it is half of the
/// wrapper path browsers are handed.
const NMH_APP: &str = "nmh";

/// The real home, given snapd's `$SNAP_REAL_HOME`. `None` outside a snap, and
/// — fail-closed — for a value that is empty or relative: `install` joins the
/// browser's directory tail onto this, and a relative base would silently
/// resolve against the process's cwd instead of a home directory.
///
/// `instance` gates the lookup so a stray `SNAP_REAL_HOME` in a non-snap
/// environment cannot redirect where the manifest is written. That is a
/// tidiness guard, not a privilege boundary — an unconfined process can write
/// wherever the user can regardless — but it keeps a normal desktop build's
/// behaviour independent of variables it has no business honouring.
pub fn real_home_from(instance: Option<&str>, snap_real_home: Option<&Path>) -> Option<PathBuf> {
    instance.filter(|i| !i.is_empty())?;
    let home = snap_real_home?;
    (home.is_absolute() && home.as_os_str().len() > 1).then(|| home.to_path_buf())
}

/// Host-visible path of the sidecar wrapper snapd generates for the `nmh`
/// app, i.e. what belongs in a manifest's `path` field. `None` outside a
/// snap or for an instance name that could not produce a well-formed path.
///
/// The instance name is checked against snapd's own grammar rather than
/// trusted: it lands in a path that is written into a browser's trust store,
/// so a name carrying `/` or `..` must not be able to point the manifest at
/// an arbitrary executable. Snap names are lowercase alphanumerics and
/// hyphens, optionally suffixed `_<instance-key>` for a parallel install.
pub fn host_wrapper_from(instance: Option<&str>) -> Option<PathBuf> {
    let instance = instance.filter(|i| !i.is_empty())?;
    let (name, key) = match instance.split_once('_') {
        Some((n, k)) => (n, Some(k)),
        None => (instance, None),
    };
    let name_ok = !name.is_empty()
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    let key_ok = key.is_none_or(|k| {
        !k.is_empty() && k.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    });
    (name_ok && key_ok).then(|| PathBuf::from(format!("/snap/bin/{instance}.{NMH_APP}")))
}

/// True when this process is running inside a snap. Only `SNAP_INSTANCE_NAME`
/// is consulted, because it is also what both functions above key off — a
/// single source of truth beats three independent snap probes disagreeing.
pub fn instance_name() -> Option<String> {
    std::env::var("SNAP_INSTANCE_NAME").ok().filter(|s| !s.is_empty())
}

/// `real_home_from` against the live environment.
pub fn real_home() -> Option<PathBuf> {
    let instance = instance_name()?;
    let home = std::env::var_os("SNAP_REAL_HOME").map(PathBuf::from)?;
    real_home_from(Some(&instance), Some(&home))
}

/// `host_wrapper_from` against the live environment.
pub fn host_wrapper() -> Option<PathBuf> {
    host_wrapper_from(instance_name().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_home_is_none_outside_a_snap() {
        assert_eq!(real_home_from(None, Some(Path::new("/home/u"))), None);
        assert_eq!(real_home_from(Some(""), Some(Path::new("/home/u"))), None);
    }

    /// Unix-only: `real_home_from` accepts the path only if `is_absolute()`
    /// holds, and `/home/u` is NOT absolute to Windows' `Path` (no drive
    /// prefix), so on Windows this asserts POSIX semantics the platform does
    /// not have. Snap is a Linux packaging format, so there is nothing to
    /// cover on Windows in the first place.
    #[cfg(unix)]
    #[test]
    fn real_home_is_the_snap_real_home_inside_a_snap() {
        assert_eq!(
            real_home_from(Some("kokos"), Some(Path::new("/home/u"))),
            Some(PathBuf::from("/home/u"))
        );
    }

    /// A relative or degenerate base would make `manifest::install` resolve the
    /// browser directory against the cwd, scattering manifests wherever the app
    /// happened to be started from.
    #[test]
    fn real_home_rejects_a_base_that_is_not_a_usable_absolute_path() {
        for bad in ["", "relative/home", "."] {
            assert_eq!(real_home_from(Some("kokos"), Some(Path::new(bad))), None, "{bad}");
        }
        assert_eq!(real_home_from(Some("kokos"), Some(Path::new("/"))), None);
        assert_eq!(real_home_from(Some("kokos"), None), None);
    }

    #[test]
    fn host_wrapper_points_at_the_snapd_generated_wrapper() {
        assert_eq!(
            host_wrapper_from(Some("kokos")),
            Some(PathBuf::from("/snap/bin/kokos.nmh"))
        );
    }

    /// Parallel installs get `<name>_<key>`, and the wrapper keeps the whole
    /// instance name — pointing at plain `kokos.nmh` would hand the browser a
    /// different installation's sidecar.
    #[test]
    fn host_wrapper_keeps_a_parallel_install_key() {
        assert_eq!(
            host_wrapper_from(Some("kokos_two")),
            Some(PathBuf::from("/snap/bin/kokos_two.nmh"))
        );
    }

    /// The result is written into a browser's trust store, so a hostile or
    /// malformed instance name must not be able to steer it elsewhere.
    #[test]
    fn host_wrapper_rejects_names_that_could_escape_the_path() {
        for bad in [
            "", "../evil", "ko/kos", "Kokos", "9kokos", "-kokos", "kokos.nmh", "kokos_", "_two",
            "kokos_TWO", "kokos_a_b",
        ] {
            assert_eq!(host_wrapper_from(Some(bad)), None, "{bad}");
        }
        assert_eq!(host_wrapper_from(None), None);
    }
}

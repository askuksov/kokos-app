//! Where the app's socket lives and how to reach it. The path is DERIVED
//! (not negotiated): both sides compute it from the bundle identifier, so a
//! browser-launched host with no Tauri APIs still finds the running app.
//! Mirrors Tauri's `app_config_dir` layout for macOS and Linux.

#[cfg(not(windows))]
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Native-messaging host name = the bundle identifier (also the manifest file
/// stem and the manifest's `name` field).
pub const HOST_NAME: &str = "dev.kuksov.kokos";
pub const SOCKET_FILE: &str = "nmh.sock";
/// Shared-secret handshake token file (Layer B), sitting beside the
/// socket in the app config dir. The app writes it `0600` at startup; the host
/// reads it to present in `Hello`. Same derived-not-negotiated discipline as
/// `SOCKET_FILE`: both sides compute the path, neither negotiates it.
pub const TOKEN_FILE: &str = "nmh.token";

/// Pure form, for tests: `home` plus the platform's config location.
pub fn config_dir_from(home: &Path, xdg_config_home: Option<&Path>, identifier: &str) -> PathBuf {
    #[cfg(windows)]
    {
        let _ = xdg_config_home;
        home.join(identifier)
    }
    #[cfg(not(windows))]
    {
    #[cfg(target_os = "macos")]
    {
        let _ = xdg_config_home;
        home.join("Library/Application Support").join(identifier)
    }
    #[cfg(not(target_os = "macos"))]
    {
        match xdg_config_home {
            Some(x) => x.join(identifier),
            None => home.join(".config").join(identifier),
        }
    }
    }
}

#[cfg(not(windows))]
pub fn app_config_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    Some(config_dir_from(&home, xdg.as_deref(), HOST_NAME))
}

/// Windows twin. `$HOME` is a unix concept and is normally unset here, so the
/// unix version above would return `None` and take every path that depends on
/// it — the handshake token included — down with it. %APPDATA% is read
/// directly rather than rebuilt from %USERPROFILE% for the reason given in
/// `config_dir_from`.
#[cfg(windows)]
pub fn app_config_dir() -> Option<PathBuf> {
    let appdata = std::env::var_os("APPDATA").map(PathBuf::from)?;
    Some(config_dir_from(&appdata, None, HOST_NAME))
}

/// Directory holding the socket and the handshake token — the ONE derivation
/// both sides use. The app used to compute this itself through Tauri's
/// `app_config_dir()` while the host computed it here; the two agreed only by
/// construction, which is what the `debug_assert` in `nmh::start` was guarding.
/// They now share this function, so there is nothing left to disagree about.
///
/// Under Snap the config dir cannot be used: snapd points `$HOME` at
/// `$SNAP_USER_DATA`, which is *revision*-scoped (`~/snap/kokos/x1`, not
/// `.../current`). App and host agree on it only while both run the same
/// revision — after a refresh a still-running app sits on the old revision
/// while a browser-launched host starts on the new one, and the channel dies
/// silently until the app is restarted. `$XDG_RUNTIME_DIR` is snapd's
/// per-instance directory (`/run/user/1000/snap.kokos`): shared across
/// revisions, on tmpfs, and already `0700`, which is also simply the right
/// place for a unix socket.
///
/// Falls back to the config dir when snapd did not export a runtime dir —
/// degraded (the refresh window comes back) but still working, which beats
/// refusing to open the channel at all.
pub fn socket_dir_from(
    snap_instance: Option<&str>,
    xdg_runtime_dir: Option<&Path>,
    home: &Path,
    xdg_config_home: Option<&Path>,
    identifier: &str,
) -> PathBuf {
    if snap_instance.is_some_and(|i| !i.is_empty()) {
        if let Some(run) = xdg_runtime_dir.filter(|p| p.is_absolute()) {
            return run.to_path_buf();
        }
    }
    config_dir_from(home, xdg_config_home, identifier)
}

/// `socket_dir_from` against the live environment. `None` only when `$HOME` is
/// absent, matching `app_config_dir`.
#[cfg(windows)]
pub fn socket_dir() -> Option<PathBuf> {
    app_config_dir()
}

#[cfg(not(windows))]
pub fn socket_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let instance = std::env::var("SNAP_INSTANCE_NAME").ok();
    let run = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    Some(socket_dir_from(
        instance.as_deref(),
        run.as_deref(),
        &home,
        xdg.as_deref(),
        HOST_NAME,
    ))
}

pub fn socket_path() -> Option<PathBuf> {
    Some(socket_dir()?.join(SOCKET_FILE))
}

pub fn token_path() -> Option<PathBuf> {
    Some(socket_dir()?.join(TOKEN_FILE))
}

/// Reads the app's current handshake token (Layer B). Any failure —
/// no HOME, the file absent (app not running, or a startup race), unreadable —
/// yields an empty string, which the app rejects: the host never fabricates a
/// token, and to it a missing token is indistinguishable from a wrong one.
/// Trimmed of any trailing newline the app might write.
pub fn read_token() -> String {
    token_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// How long the host waits for the app's answer. The four confirm-bearing
/// actions wait on a human, so they get 90 s — but never forever: a wedged
/// app must not hang the browser's port.
pub fn timeout_for(action: &str) -> Duration {
    match action {
        "get_secret" | "get_totp" | "save_login" | "update_login" => Duration::from_secs(90),
        _ => Duration::from_secs(5),
    }
}

#[cfg(unix)]
pub type Conn = std::os::unix::net::UnixStream;

#[cfg(unix)]
pub fn connect() -> io::Result<Conn> {
    let path = socket_path().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "no HOME to derive the socket path")
    })?;
    std::os::unix::net::UnixStream::connect(path)
}

/// Windows twin of the unix socket above: a named pipe. `Conn`, `connect` and
/// the app-side `PipeListener` all come from there, so both halves of this
/// module expose the same names and callers need no cfg of their own.
#[cfg(windows)]
pub mod named_pipe;

#[cfg(windows)]
pub use named_pipe::{connect, pipe_name, Conn, PipeListener, PipeStream};

#[cfg(not(any(unix, windows)))]
pub type Conn = std::net::TcpStream;

#[cfg(not(any(unix, windows)))]
pub fn connect() -> io::Result<Conn> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native messaging transport is not implemented on this platform yet",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_dir_matches_the_tauri_layout() {
        let home = std::path::Path::new("/Users/x");
        let dir = config_dir_from(home, None, HOST_NAME);
        #[cfg(target_os = "macos")]
        assert_eq!(
            dir,
            home.join("Library/Application Support").join(HOST_NAME)
        );
        #[cfg(all(not(target_os = "macos"), not(windows)))]
        assert_eq!(dir, home.join(".config").join(HOST_NAME));
        #[cfg(windows)]
        assert_eq!(dir, home.join(HOST_NAME));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn xdg_config_home_wins_on_linux() {
        let dir = config_dir_from(
            std::path::Path::new("/home/x"),
            Some(std::path::Path::new("/tmp/cfg")),
            HOST_NAME,
        );
        assert_eq!(dir, std::path::Path::new("/tmp/cfg").join(HOST_NAME));
    }

    /// Outside a snap nothing changes: the socket stays in the config dir the
    /// app has always used.
    #[test]
    fn socket_dir_is_the_config_dir_outside_a_snap() {
        let home = Path::new("/home/x");
        assert_eq!(
            socket_dir_from(None, Some(Path::new("/run/user/1000")), home, None, HOST_NAME),
            config_dir_from(home, None, HOST_NAME),
        );
        assert_eq!(
            socket_dir_from(Some(""), Some(Path::new("/run/user/1000")), home, None, HOST_NAME),
            config_dir_from(home, None, HOST_NAME),
        );
    }

    /// The whole point: under snap the path must not carry a revision, or a
    /// refresh splits app and host apart.
    ///
    /// Unix-only, and not because snap is a Linux thing (it is, but that alone
    /// would not break the assertion): `socket_dir_from` accepts the runtime
    /// dir only when `is_absolute()` holds, and a POSIX path like
    /// `/run/user/1000` is NOT absolute to Windows' `Path` — it has no drive
    /// prefix — so on Windows this case silently takes the config-dir fallback
    /// and the test would assert unix path semantics that the platform does
    /// not have.
    #[cfg(unix)]
    #[test]
    fn socket_dir_is_the_runtime_dir_under_snap() {
        assert_eq!(
            socket_dir_from(
                Some("kokos"),
                Some(Path::new("/run/user/1000/snap.kokos")),
                Path::new("/home/x/snap/kokos/x1"),
                None,
                HOST_NAME,
            ),
            PathBuf::from("/run/user/1000/snap.kokos"),
        );
    }

    /// No runtime dir (or a nonsensical one) is a degraded environment, not a
    /// reason to refuse the channel — fall back rather than return nothing.
    #[test]
    fn socket_dir_falls_back_when_snapd_gave_no_usable_runtime_dir() {
        let home = Path::new("/home/x/snap/kokos/x1");
        for run in [None, Some(Path::new("relative/run"))] {
            assert_eq!(
                socket_dir_from(Some("kokos"), run, home, None, HOST_NAME),
                config_dir_from(home, None, HOST_NAME),
            );
        }
    }

    #[test]
    fn socket_file_name_is_stable() {
        assert_eq!(
            SOCKET_FILE, "nmh.sock",
            "the app and the host must agree without negotiation"
        );
    }

    #[test]
    fn token_file_name_is_stable() {
        assert_eq!(
            TOKEN_FILE, "nmh.token",
            "the app writes and the host reads this exact name"
        );
    }

    #[test]
    fn confirm_actions_get_the_long_timeout() {
        assert_eq!(timeout_for("get_logins"), std::time::Duration::from_secs(5));
        for a in ["get_secret", "get_totp", "save_login", "update_login"] {
            assert_eq!(
                timeout_for(a),
                std::time::Duration::from_secs(90),
                "{a} waits on a human"
            );
        }
    }

    #[test]
    fn socket_path_ends_with_host_name_and_socket_file_when_home_is_set() {
        // SAFETY: single-threaded test, no other test in this process reads
        unsafe {
            std::env::set_var("HOME", "/tmp/kokos-nmh-test-home");
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        let path = socket_path().expect("HOME is set");
        let tail: std::path::PathBuf = std::path::Path::new(HOST_NAME).join(SOCKET_FILE);
        assert!(
            path.ends_with(&tail),
            "expected {path:?} to end with {tail:?}"
        );

        let tok_path = token_path().expect("HOME is set");
        let tok_tail: std::path::PathBuf = std::path::Path::new(HOST_NAME).join(TOKEN_FILE);
        assert!(
            tok_path.ends_with(&tok_tail),
            "expected {tok_path:?} to end with {tok_tail:?}"
        );
        let _ = std::fs::remove_file(&tok_path);
        assert_eq!(
            read_token(),
            "",
            "an absent token file must read as empty, never error"
        );
    }

    #[test]
    fn timeout_for_unknown_action_falls_back_to_the_default_branch() {
        assert_eq!(
            timeout_for("some_totally_unknown_action"),
            std::time::Duration::from_secs(5),
            "an unrecognised action must not accidentally get the long wait"
        );
    }
}

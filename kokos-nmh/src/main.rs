//! Browser-launched proxy. Reads framed JSON from stdin, forwards it to the
//! running Kokos app over its local socket, writes the framed answer back to
//! stdout. Deliberately dumb: no crypto, no vault, no policy — and NO
//! logging, because stdout is the protocol channel and a payload must never
//! reach a log.

use std::io;

use kokos_nmh::framing::{read_frame, write_frame};
use kokos_nmh::origin::{from_args, Caller};
use kokos_nmh::protocol::{codes, parse_request, Hello, HelloFrame, Response, PROTOCOL_VERSION};
use kokos_nmh::transport::{connect, read_token, timeout_for, Conn};
use kokos_nmh::HOST_VERSION;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let caller = from_args(&args);
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    let mut conn: Option<Conn> = None;

    while let Ok(Some(frame)) = read_frame(&mut reader) {
        let response = handle(&frame, caller.as_ref(), &mut conn);
        let bytes = serde_json::to_vec(&response)
            .unwrap_or_else(|_| br#"{"id":"","ok":false,"payload":null,"error":{"code":"internal","message":"response serialisation failed"}}"#.to_vec());
        if write_frame(&mut writer, &bytes).is_err() {
            break;
        }
    }
}

fn handle(frame: &[u8], caller: Option<&Caller>, conn: &mut Option<Conn>) -> Response {
    let req = match parse_request(frame) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let is_probe = req.action == "ping" || req.action == "get_status";
    let caller = match caller {
        Some(c) => c,
        None if is_probe => return probe_answer(&req.id, &req.action, false),
        None => {
            return Response::err(
                &req.id,
                codes::DENIED,
                "this host was not launched by a browser",
            )
        }
    };

    if conn.is_none() {
        match connect() {
            Ok(c) => {
                let hello = HelloFrame {
                    hello: Hello {
                        browser: caller.browser.as_str().to_string(),
                        origin: caller.origin.clone(),
                        host_version: HOST_VERSION.to_string(),
                        token: read_token(),
                    },
                };
                let bytes = serde_json::to_vec(&hello).expect("hello always serialises");
                let mut c = c;
                let _ = c.set_write_timeout(Some(timeout_for(&req.action)));
                if write_frame(&mut c, &bytes).is_ok() {
                    *conn = Some(c);
                }
            }
            Err(_) => {
                return no_app(
                    &req.id,
                    &req.action,
                    is_probe,
                    false,
                    codes::APP_NOT_RUNNING,
                    "Kokos is not running",
                );
            }
        }
    }

    let c = match conn.as_mut() {
        Some(c) => c,
        None => {
            return no_app(
                &req.id,
                &req.action,
                is_probe,
                true,
                codes::APP_NOT_RUNNING,
                "Kokos is not running",
            );
        }
    };

    let dur = Some(timeout_for(&req.action));
    let _ = c.set_read_timeout(dur);
    let _ = c.set_write_timeout(dur);
    let out = serde_json::to_vec(&req).expect("a parsed request re-serialises");
    if write_frame(c, &out).is_err() {
        *conn = None;
        return no_app(
            &req.id,
            &req.action,
            is_probe,
            true,
            codes::APP_NOT_RUNNING,
            "lost the connection to Kokos",
        );
    }
    match read_frame(c) {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            *conn = None;
            no_app(
                &req.id,
                &req.action,
                is_probe,
                true,
                codes::INTERNAL,
                "unreadable answer from Kokos",
            )
        }),
        Ok(None) => {
            *conn = None;
            no_app(
                &req.id,
                &req.action,
                is_probe,
                true,
                codes::APP_NOT_RUNNING,
                "Kokos closed the connection",
            )
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            *conn = None;
            no_app(
                &req.id,
                &req.action,
                is_probe,
                true,
                codes::TIMEOUT,
                "Kokos did not answer in time",
            )
        }
        Err(_) => {
            *conn = None;
            no_app(
                &req.id,
                &req.action,
                is_probe,
                true,
                codes::INTERNAL,
                "transport failure",
            )
        }
    }
}

/// Every "the app is unreachable, or a live exchange with it just failed"
/// branch funnels through here so the rule cannot be forgotten in a future
/// one: a probe action (`ping`/`get_status`) NEVER answers with an error —
/// it always gets the probe object, with `running` set to `connected` (the
/// only thing the host actually knows: whether a socket connection was ever
/// established). A non-probe action is unaffected: it keeps answering with
/// `code`/`message`, exactly as before. `action` is forwarded to
/// `probe_answer` unchanged so the probe shape stays action-specific even on
/// this unreachable-app path.
fn no_app(
    req_id: &str,
    action: &str,
    is_probe: bool,
    connected: bool,
    code: &str,
    message: &str,
) -> Response {
    if is_probe {
        probe_answer(req_id, action, connected)
    } else {
        Response::err(req_id, code, message)
    }
}

/// `ping`/`get_status` answer shape when the app is unreachable. Both
/// actions carry `locked`/`running`, but `ping` additionally carries
/// `app_version`/`protocol_version` — mirroring the app-side handler's own
/// per-action shape (`handlers::status`) exactly, so an extension sees ONE
/// contract per action regardless of whether the app happened to be
/// reachable, instead of `get_status` gaining two extra fields only when the
/// app is down. `app_version` here is the HOST's own version (workspace-wide
/// `HOST_VERSION`), since the real app cannot be asked. `locked` stays
/// `true` in every fallback: the host cannot know the real lock state, so it
/// must fail closed.
fn probe_answer(id: &str, action: &str, running: bool) -> Response {
    if action == "ping" {
        Response::ok(
            id,
            serde_json::json!({
                "app_version": HOST_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "locked": true,
                "running": running,
            }),
        )
    } else {
        Response::ok(
            id,
            serde_json::json!({
                "locked": true,
                "running": running,
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use kokos_nmh::origin::Browser;

    #[cfg(unix)]
    fn caller() -> Caller {
        Caller {
            browser: Browser::Chrome,
            origin: "chrome-extension://abc/".into(),
        }
    }

    #[cfg(unix)]
    fn req(id: &str, action: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": id,
            "version": PROTOCOL_VERSION,
            "action": action,
            "payload": null,
        }))
        .unwrap()
    }

    /// Pure-function layer: `no_app` is the single point every
    /// app-unreachable branch funnels through, so its rule is directly
    /// assertable without a socket at all — a probe never errors and its
    /// `running` field is exactly the `connected` flag it was given; a
    /// non-probe keeps its own error code/message untouched.
    #[test]
    fn no_app_probe_reflects_connected_flag_nonprobe_keeps_its_code() {
        let probe_disconnected = no_app("r1", "ping", true, false, codes::APP_NOT_RUNNING, "x");
        assert!(
            probe_disconnected.ok,
            "a probe must never be an error response"
        );
        assert_eq!(probe_disconnected.payload.unwrap()["running"], false);

        let probe_connected = no_app("r2", "ping", true, true, codes::APP_NOT_RUNNING, "x");
        assert!(
            probe_connected.ok,
            "a probe must never be an error response"
        );
        assert_eq!(probe_connected.payload.unwrap()["running"], true);

        let non_probe = no_app("r3", "get_logins", false, true, codes::TIMEOUT, "slow");
        assert!(!non_probe.ok, "a non-probe action keeps its error shape");
        assert_eq!(non_probe.error.unwrap().code, codes::TIMEOUT);
    }

    /// `get_status` and `ping` must answer with the
    /// SAME shape whether the app is reachable or not. The app-side
    /// `handlers::status` emits `{locked, running}` for `get_status` (no
    /// `app_version`/`protocol_version`) and all four fields for `ping`; this
    /// pins that `probe_answer` — the host's own fallback — matches exactly,
    /// so an extension branching on payload shape never sees two different
    /// contracts for the same action.
    #[test]
    fn get_status_probe_answer_has_no_app_version_key() {
        let resp = probe_answer("r4", "get_status", true);
        assert!(resp.ok);
        let payload = resp.payload.unwrap();
        assert!(
            payload.get("app_version").is_none(),
            "get_status must not gain app_version just because the app is unreachable"
        );
        assert!(payload.get("protocol_version").is_none());
        assert_eq!(payload["locked"], true);
        assert_eq!(payload["running"], true);
    }

    #[test]
    fn ping_probe_answer_still_carries_all_four_fields() {
        let resp = probe_answer("r5", "ping", false);
        assert!(resp.ok);
        let payload = resp.payload.unwrap();
        assert_eq!(payload["app_version"], HOST_VERSION);
        assert_eq!(payload["protocol_version"], PROTOCOL_VERSION);
        assert_eq!(payload["locked"], true);
        assert_eq!(payload["running"], false);
    }

    // SAFETY: single-threaded within this function; no other test in the
    #[cfg(unix)]
    #[test]
    fn app_unreachable_and_timeout_semantics_across_the_real_branches() {
        let tmp = std::path::PathBuf::from(format!(
            "/tmp/k{}{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                % 100_000
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
        }

        let mut conn: Option<Conn> = None;
        let ping = handle(&req("p1", "ping"), Some(&caller()), &mut conn);
        assert!(ping.ok, "ping must never be an error response");
        assert_eq!(
            ping.payload.unwrap()["running"],
            false,
            "no socket at all -> the host could not connect -> running:false"
        );

        let mut conn2: Option<Conn> = None;
        let get_logins = handle(&req("g1", "get_logins"), Some(&caller()), &mut conn2);
        assert!(!get_logins.ok);
        assert_eq!(get_logins.error.unwrap().code, codes::APP_NOT_RUNNING);

        let dir = kokos_nmh::transport::app_config_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join(kokos_nmh::transport::SOCKET_FILE);
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        let server = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = kokos_nmh::framing::read_frame(&mut stream);
            }
        });

        let mut conn3: Option<Conn> = None;
        let ping2 = handle(&req("p2", "ping"), Some(&caller()), &mut conn3);
        assert!(ping2.ok, "ping must never be an error response");
        assert_eq!(
            ping2.payload.unwrap()["running"],
            true,
            "a connection was established -> running:true even though the exchange then failed"
        );
        server.join().unwrap();

        let mut conn4: Option<Conn> = None;
        let get_logins2 = handle(&req("g2", "get_logins"), Some(&caller()), &mut conn4);
        assert!(!get_logins2.ok);
        assert_eq!(
            get_logins2.error.unwrap().code,
            codes::APP_NOT_RUNNING,
            "a non-probe action still yields its error code, unchanged"
        );
        let _ = std::fs::remove_file(&sock_path);

        let listener3 = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        let server3 = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener3.accept() {
                let _ = kokos_nmh::framing::read_frame(&mut stream);
                let _ = kokos_nmh::framing::read_frame(&mut stream);
                let resp = Response::ok("t3", serde_json::json!({"running": true}));
                let bytes = serde_json::to_vec(&resp).unwrap();
                let _ = kokos_nmh::framing::write_frame(&mut stream, &bytes);
            }
        });

        let mut conn5: Option<Conn> = None;
        let answered = handle(&req("t3", "ping"), Some(&caller()), &mut conn5);
        assert!(answered.ok, "the fake app answered successfully");
        server3.join().unwrap();
        let _ = std::fs::remove_file(&sock_path);

        let live = conn5
            .as_ref()
            .expect("a successful exchange keeps the connection alive");
        let expected = Some(kokos_nmh::transport::timeout_for("ping"));
        assert_eq!(
            live.read_timeout().unwrap(),
            expected,
            "read timeout must be set from timeout_for(action)"
        );
        assert_eq!(
            live.write_timeout().unwrap(),
            expected,
            "write timeout must ALSO be set from timeout_for(action), or a wedged app can hang the port forever"
        );
    }
}

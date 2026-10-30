//! Browserless end-to-end test for the REAL `kokos-nmh` binary.
//!
//! This is the only place in the project that exercises the wire contract
//! against the actual compiled host process, over the actual piped-stdio +
//! Unix-socket transport, with no browser and no vault involved: a FAKE app
//! is bound on the socket the host dials, and framed JSON is spoken at both
//! ends.
//!
//! Design rules this harness follows:
//! - This test process's own env is NEVER mutated; `HOME` is set on each
//!   CHILD process only, and the same path is computed in-test with the pure
//!   `transport::config_dir_from`.
//! - Every tempdir is a short, hand-rolled-length path directly under `/tmp`
//!   (not `std::env::temp_dir()`), because `sockaddr_un::sun_path` is only
//!   ~104 bytes on macOS and the derived suffix already eats about half of
//!   that budget.
//! - The fake app's listener is always bound BEFORE the child is spawned, so
//!   the host can never lose a connect race.
//! - Every wait is bounded: reading the child's stdout runs through a
//!   background thread + `recv_timeout` (a `ChildStdout` has no socket-style
//!   read timeout of its own), accepting a connection uses the same
//!   technique, and proving a connection did NOT happen uses
//!   `set_nonblocking` plus a short deadline poll — never a bare `accept()`.
//! - Every spawned child is killed and reaped even on a failing assertion,
//!   via `Drop`.

#![cfg(unix)]

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use kokos_nmh::framing::{read_frame, write_frame, MAX_FRAME};
use kokos_nmh::protocol::{codes, HelloFrame, Request, Response, PROTOCOL_VERSION};
use kokos_nmh::transport::{config_dir_from, timeout_for, HOST_NAME, SOCKET_FILE};
use kokos_nmh::HOST_VERSION;

/// The generous default bound for a purely-local accept/read/write — there is
/// no real I/O latency anywhere in this test, so a couple of seconds is
/// already a large margin over what a healthy exchange needs.
const WAIT: Duration = Duration::from_secs(2);

/// The bound used to prove a connection did NOT happen. Short on purpose: a
/// negative check should fail fast, not eat the same budget as a positive
/// one.
const NEGATIVE_CHECK: Duration = Duration::from_millis(300);

const CHROME_ID: &str = "abcdefghijklmnopabcdefghijklmnop";

fn chrome_arg() -> String {
    format!("chrome-extension://{CHROME_ID}/")
}

fn make_request(id: &str, action: &str, payload: serde_json::Value) -> Request {
    Request {
        id: id.to_string(),
        version: PROTOCOL_VERSION,
        action: action.to_string(),
        payload,
    }
}

/// One test's throwaway `HOME` + the socket path the host will derive from
/// it. Kept alive for the whole test via the `TempDir` guard; dropping it
/// recursively removes the directory (and thus the socket file).
struct Fixture {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    sock_path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::Builder::new()
            .prefix("k")
            .tempdir_in("/tmp")
            .expect("a short tempdir under /tmp");
        let home = tmp.path().to_path_buf();
        let dir = config_dir_from(&home, None, HOST_NAME);
        std::fs::create_dir_all(&dir).expect("create the config dir");
        let sock_path = dir.join(SOCKET_FILE);
        Fixture {
            _tmp: tmp,
            home,
            sock_path,
        }
    }

    fn bind_listener(&self) -> UnixListener {
        UnixListener::bind(&self.sock_path).expect("bind the fake app socket")
    }

    /// Spawns the real `kokos-nmh` binary with piped stdio. `HOME` is set on
    /// the CHILD only — this test process's own env is never touched, since
    /// cargo runs integration tests multi-threaded in one binary and a
    /// process-global `set_var` would race with every other test.
    fn spawn_host(&self, extra_args: &[&str]) -> SpawnedHost {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kokos-nmh"))
            .args(extra_args)
            .env("HOME", &self.home)
            .env_remove("XDG_CONFIG_HOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the kokos-nmh binary");
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let stdout_rx = spawn_frame_reader(stdout);
        SpawnedHost {
            child,
            stdin: Some(stdin),
            stdout_rx,
            stderr: Some(stderr),
        }
    }
}

/// Reads frames from `r` on a background thread and forwards each one (or
/// the terminal EOF/error) over a channel, so the test thread can bound its
/// wait with `recv_timeout` instead of blocking forever on a `ChildStdout`,
/// which has no socket-style read timeout of its own.
fn spawn_frame_reader<R: Read + Send + 'static>(
    mut r: R,
) -> mpsc::Receiver<io::Result<Option<Vec<u8>>>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || loop {
        let result = read_frame(&mut r);
        let done = !matches!(result, Ok(Some(_)));
        if tx.send(result).is_err() || done {
            break;
        }
    });
    rx
}

fn expect_frame(rx: &mpsc::Receiver<io::Result<Option<Vec<u8>>>>, timeout: Duration) -> Vec<u8> {
    match rx.recv_timeout(timeout) {
        Ok(Ok(Some(bytes))) => bytes,
        Ok(Ok(None)) => panic!("expected a frame, got a clean EOF instead"),
        Ok(Err(e)) => panic!("expected a frame, got an I/O error instead: {e}"),
        Err(_) => panic!("timed out after {timeout:?} waiting for a frame"),
    }
}

fn expect_stdout_eof(rx: &mpsc::Receiver<io::Result<Option<Vec<u8>>>>, timeout: Duration) {
    match rx.recv_timeout(timeout) {
        Ok(Ok(None)) => {}
        Ok(Ok(Some(bytes))) => panic!("expected EOF, got a {}-byte frame instead", bytes.len()),
        Ok(Err(e)) => panic!("expected EOF, got an I/O error instead: {e}"),
        Err(_) => panic!("timed out after {timeout:?} waiting for EOF"),
    }
}

/// A running `kokos-nmh` child, with its stdout already being drained by a
/// background reader thread (see `spawn_frame_reader`). Killed and reaped on
/// `Drop`, including on a panicking assertion, so a failing test can never
/// leak a process holding the socket.
struct SpawnedHost {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout_rx: mpsc::Receiver<io::Result<Option<Vec<u8>>>>,
    stderr: Option<ChildStderr>,
}

impl SpawnedHost {
    fn send_request(&mut self, req: &Request) {
        let bytes = serde_json::to_vec(req).expect("request serialises");
        write_frame(self.stdin.as_mut().expect("stdin still open"), &bytes)
            .expect("write the request frame to the child's stdin");
    }

    /// Writes an already-encoded frame body (used by the oversize-frame test
    /// to hand-craft a corrupt length prefix, and by the exact-`MAX_FRAME`
    /// positive control).
    fn send_raw_frame_prefix_and_body(&mut self, len_prefix: u32, body: &[u8]) {
        let w = self.stdin.as_mut().expect("stdin still open");
        w.write_all(&len_prefix.to_ne_bytes())
            .expect("write the length prefix");
        w.write_all(body).expect("write the frame body");
        w.flush().expect("flush stdin");
    }

    fn close_stdin(&mut self) {
        self.stdin = None;
    }

    fn expect_response(&self, timeout: Duration) -> Response {
        let bytes = expect_frame(&self.stdout_rx, timeout);
        serde_json::from_slice(&bytes).expect("response parses")
    }

    fn expect_no_response(&self, timeout: Duration) {
        expect_stdout_eof(&self.stdout_rx, timeout);
    }

    fn wait_bounded(&mut self, timeout: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status;
            }
            if Instant::now() >= deadline {
                panic!("the child did not exit within {timeout:?}");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Kills the child, waits for it to exit, then reads whatever it wrote to
    /// stderr. The host must log NOTHING (stdout is the protocol
    /// channel), so this is how at least one test proves stderr came back
    /// empty.
    fn kill_and_collect_stderr(&mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut buf = String::new();
        if let Some(mut stderr) = self.stderr.take() {
            stderr
                .read_to_string(&mut buf)
                .expect("read stderr after exit");
        }
        buf
    }
}

impl Drop for SpawnedHost {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Kills `host` and asserts its stderr came back empty. The host must log
/// NOTHING (stdout is the protocol channel), and a stray
/// `eprintln!` or panic message is most likely to appear on an ERROR
/// branch, not the shallow local-probe path — so this belongs at the end of
/// any branch-exercising test, not just one of them.
/// Factored out to keep each call site to one line.
fn assert_no_stderr(host: &mut SpawnedHost) {
    let stderr = host.kill_and_collect_stderr();
    assert!(
        stderr.is_empty(),
        "the host must never write to stderr, got: {stderr:?}"
    );
}

/// The fake app side of the socket: binds (via `Fixture::bind_listener`,
/// always BEFORE the child is spawned) and answers with hand-written frames.
struct FakeApp {
    listener: UnixListener,
}

impl FakeApp {
    fn bind(fixture: &Fixture) -> Self {
        FakeApp {
            listener: fixture.bind_listener(),
        }
    }

    /// Accepts exactly one connection (bounded — a background thread drives
    /// the actual `accept()`, so a host that never connects fails the test
    /// instead of hanging the suite), then reads and parses the hello frame.
    /// The fake app must never answer before it has read: this proves the
    /// hello arrived, and only the hello, before anything is sent back.
    fn accept_and_read_hello(&self, timeout: Duration) -> (UnixStream, HelloFrame) {
        let cloned = self
            .listener
            .try_clone()
            .expect("clone the listener for a bounded accept");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(cloned.accept());
        });
        let (mut stream, _addr) = rx
            .recv_timeout(timeout)
            .unwrap_or_else(|_| panic!("the host did not connect within {timeout:?}"))
            .expect("accept() succeeded");
        stream
            .set_read_timeout(Some(timeout))
            .expect("set_read_timeout");
        stream
            .set_write_timeout(Some(timeout))
            .expect("set_write_timeout");
        let bytes = read_frame(&mut stream)
            .expect("read the hello frame")
            .expect("hello frame present, not an immediate EOF");
        let hello: HelloFrame = serde_json::from_slice(&bytes)
            .expect("hello frame parses as HelloFrame, not a Request");
        (stream, hello)
    }

    /// Proves the host never dialled the socket at all. Uses
    /// `set_nonblocking` plus a bounded poll rather than a blocking
    /// `accept()`, so a regression that DOES connect fails the assertion
    /// instead of hanging forever on an accept that was never supposed to
    /// happen.
    fn assert_no_connection_within(&self, timeout: Duration) {
        self.listener
            .set_nonblocking(true)
            .expect("set_nonblocking");
        let deadline = Instant::now() + timeout;
        loop {
            match self.listener.accept() {
                Ok(_) => panic!("the host connected to the app socket; it must not have"),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("unexpected accept() error while polling: {e}"),
            }
        }
    }
}

fn read_app_request(stream: &mut UnixStream) -> Request {
    let bytes = read_frame(stream)
        .expect("read the request frame")
        .expect("request frame present, not an immediate EOF");
    serde_json::from_slice(&bytes).expect("request parses")
}

fn write_app_response(stream: &mut UnixStream, resp: &Response) {
    let bytes = serde_json::to_vec(resp).expect("response serialises");
    write_frame(stream, &bytes).expect("write the response frame");
}

/// A valid `get_status` request whose serialised body is exactly `MAX_FRAME`
/// bytes — built by padding the payload string with plain ASCII (so no
/// escaping changes the byte count) until the target length is hit exactly.
fn max_size_request_body(id: &str) -> Vec<u8> {
    let base = serde_json::json!({
        "id": id,
        "version": PROTOCOL_VERSION,
        "action": "get_status",
        "payload": "",
    });
    let base_len = serde_json::to_vec(&base).unwrap().len();
    let pad_len = MAX_FRAME - base_len;
    let padded = serde_json::json!({
        "id": id,
        "version": PROTOCOL_VERSION,
        "action": "get_status",
        "payload": "x".repeat(pad_len),
    });
    let bytes = serde_json::to_vec(&padded).unwrap();
    assert_eq!(
        bytes.len(),
        MAX_FRAME,
        "padding must land exactly on the cap"
    );
    bytes
}


#[test]
fn ping_without_an_app_reports_not_running() {
    let fixture = Fixture::new();
    let arg = chrome_arg();
    let mut host = fixture.spawn_host(&[arg.as_str()]);

    host.send_request(&make_request("ping-1", "ping", serde_json::Value::Null));
    let resp = host.expect_response(WAIT);

    assert_eq!(resp.id, "ping-1");
    assert!(resp.ok, "a probe must never be an error response");
    let payload = resp.payload.expect("ping always carries a payload");
    assert_eq!(payload["running"], false);
    assert_eq!(payload["locked"], true);
    assert_eq!(payload["app_version"], HOST_VERSION);
    assert_eq!(payload["protocol_version"], PROTOCOL_VERSION);

    assert_no_stderr(&mut host);
}

#[test]
fn ping_is_forwarded_and_answered_when_the_app_is_up() {
    let fixture = Fixture::new();
    let app = FakeApp::bind(&fixture);
    let arg = chrome_arg();
    let mut host = fixture.spawn_host(&[arg.as_str()]);

    host.send_request(&make_request("ping-2", "ping", serde_json::Value::Null));

    let (mut stream, hello) = app.accept_and_read_hello(WAIT);
    assert_eq!(hello.hello.browser, "chrome");
    assert_eq!(hello.hello.origin, chrome_arg());

    let req = read_app_request(&mut stream);
    assert_eq!(req.id, "ping-2");
    assert_eq!(req.action, "ping");

    write_app_response(
        &mut stream,
        &Response::ok(
            &req.id,
            serde_json::json!({"running": true, "locked": false, "app_version": "9.9.9"}),
        ),
    );

    let resp = host.expect_response(WAIT);
    assert_eq!(resp.id, "ping-2");
    assert!(resp.ok);
    let payload = resp.payload.expect("payload present");
    assert_eq!(
        payload["app_version"], "9.9.9",
        "this value only exists on the app's canned answer, never on the host's local fallback"
    );
    assert_eq!(payload["locked"], false);
}

#[test]
fn hello_frame_carries_browser_and_origin() {
    {
        let fixture = Fixture::new();
        let app = FakeApp::bind(&fixture);
        let arg = chrome_arg();
        let mut host = fixture.spawn_host(&[arg.as_str()]);
        host.send_request(&make_request("h-chrome", "ping", serde_json::Value::Null));

        let (_stream, hello) = app.accept_and_read_hello(WAIT);
        assert_eq!(hello.hello.browser, "chrome");
        assert_eq!(
            hello.hello.origin,
            format!("chrome-extension://{CHROME_ID}/")
        );
        assert_eq!(hello.hello.host_version, HOST_VERSION);
    }

    {
        let fixture = Fixture::new();
        let app = FakeApp::bind(&fixture);
        let manifest_path = fixture.home.join("dev.kuksov.kokos.json");
        let manifest_arg = manifest_path.to_str().unwrap().to_string();
        let ext_id = "kokos-stub@example.org";
        let mut host = fixture.spawn_host(&[manifest_arg.as_str(), ext_id]);
        host.send_request(&make_request("h-firefox", "ping", serde_json::Value::Null));

        let (_stream, hello) = app.accept_and_read_hello(WAIT);
        assert_eq!(hello.hello.browser, "firefox");
        assert_eq!(hello.hello.origin, ext_id);
        assert_eq!(hello.hello.host_version, HOST_VERSION);
    }
}

#[test]
fn every_action_round_trips() {
    let fixture = Fixture::new();
    let app = FakeApp::bind(&fixture);
    let arg = chrome_arg();
    let mut host = fixture.spawn_host(&[arg.as_str()]);

    let actions = [
        "ping",
        "get_status",
        "get_logins",
        "get_secret",
        "get_totp",
        "save_login",
        "update_login",
        "generate_password",
    ];

    host.send_request(&make_request("a-0", actions[0], serde_json::Value::Null));
    let (mut stream, _hello) = app.accept_and_read_hello(WAIT);

    for (i, action) in actions.iter().enumerate() {
        let id = format!("a-{i}");
        if i != 0 {
            host.send_request(&make_request(&id, action, serde_json::Value::Null));
        }

        let req = read_app_request(&mut stream);
        assert_eq!(req.id, id);
        assert_eq!(&req.action, action);

        let marker = format!("{action}-marker");
        write_app_response(
            &mut stream,
            &Response::ok(&req.id, serde_json::json!({"marker": marker})),
        );

        let resp = host.expect_response(WAIT);
        assert_eq!(resp.id, id);
        assert!(resp.ok);
        assert_eq!(resp.payload.unwrap()["marker"], format!("{action}-marker"));
    }

    app.assert_no_connection_within(NEGATIVE_CHECK);
}

#[test]
fn app_error_codes_pass_through_untouched() {
    let fixture = Fixture::new();
    let app = FakeApp::bind(&fixture);
    let arg = chrome_arg();
    let mut host = fixture.spawn_host(&[arg.as_str()]);

    let cases = [
        (codes::LOCKED, "vault is locked, unlock Kokos first"),
        (
            codes::NOT_IN_SCOPE,
            "this origin is not allowed for that entry",
        ),
        (codes::DENIED, "the user denied this request"),
        (codes::ENTRY_NOT_FOUND, "no entry with that id exists"),
    ];

    host.send_request(&make_request("e-0", "get_logins", serde_json::Value::Null));
    let (mut stream, _hello) = app.accept_and_read_hello(WAIT);

    for (i, (code, message)) in cases.iter().enumerate() {
        if i != 0 {
            let id = format!("e-{i}");
            host.send_request(&make_request(&id, "get_logins", serde_json::Value::Null));
        }
        let req = read_app_request(&mut stream);

        write_app_response(&mut stream, &Response::err(&req.id, code, message));
        let resp = host.expect_response(WAIT);

        assert_eq!(resp.id, req.id);
        assert!(!resp.ok);
        let err = resp.error.expect("error response carries an ErrorObj");
        assert_eq!(
            &err.code, code,
            "the host must not rewrite the app's error code"
        );
        assert_eq!(
            &err.message, message,
            "the host must not rewrite the app's error message"
        );
    }
}

#[test]
fn version_two_is_rejected_by_the_host_without_reaching_the_app() {
    let fixture = Fixture::new();
    let app = FakeApp::bind(&fixture);
    let arg = chrome_arg();
    let mut host = fixture.spawn_host(&[arg.as_str()]);

    let req = Request {
        id: "v2".to_string(),
        version: 2,
        action: "ping".to_string(),
        payload: serde_json::Value::Null,
    };
    host.send_request(&req);

    let resp = host.expect_response(WAIT);
    assert_eq!(resp.id, "v2");
    assert!(!resp.ok);
    assert_eq!(resp.error.unwrap().code, codes::UNSUPPORTED_VERSION);

    app.assert_no_connection_within(NEGATIVE_CHECK);
}

#[test]
fn oversize_request_frame_is_refused() {
    {
        let fixture = Fixture::new();
        let arg = chrome_arg();
        let mut host = fixture.spawn_host(&[arg.as_str()]);

        host.send_raw_frame_prefix_and_body((MAX_FRAME + 1) as u32, b"xx");
        host.close_stdin();

        host.expect_no_response(WAIT);
        let status = host.wait_bounded(WAIT);
        assert!(
            status.success(),
            "the host exits normally, it does not crash"
        );
    }

    {
        let fixture = Fixture::new();
        let app = FakeApp::bind(&fixture);
        let arg = chrome_arg();
        let mut host = fixture.spawn_host(&[arg.as_str()]);

        let body = max_size_request_body("pad-1");
        write_frame(host.stdin.as_mut().expect("stdin open"), &body)
            .expect("write the max-size frame");

        let (mut stream, _hello) = app.accept_and_read_hello(WAIT);
        let req = read_app_request(&mut stream);
        assert_eq!(req.id, "pad-1");
        assert_eq!(req.action, "get_status");

        write_app_response(
            &mut stream,
            &Response::ok(&req.id, serde_json::json!({"marker": "padded-ok"})),
        );
        let resp = host.expect_response(WAIT);
        assert_eq!(resp.id, "pad-1");
        assert!(resp.ok);
        assert_eq!(resp.payload.unwrap()["marker"], "padded-ok");
    }
}

#[test]
fn a_silent_app_yields_timeout_not_a_hang() {
    let fixture = Fixture::new();
    let app = FakeApp::bind(&fixture);
    let arg = chrome_arg();
    let mut host = fixture.spawn_host(&[arg.as_str()]);

    host.send_request(&make_request(
        "silent-1",
        "get_logins",
        serde_json::Value::Null,
    ));

    let (mut stream, _hello) = app.accept_and_read_hello(WAIT);
    let req = read_app_request(&mut stream);
    assert_eq!(req.id, "silent-1");

    let host_timeout = timeout_for("get_logins");
    let bound = host_timeout + Duration::from_secs(2);
    let resp = host.expect_response(bound);

    assert_eq!(resp.id, "silent-1");
    assert!(!resp.ok);
    assert_eq!(resp.error.unwrap().code, codes::TIMEOUT);

    drop(stream);

    assert_no_stderr(&mut host);
}

#[test]
fn a_bare_launch_with_no_browser_argv_denies_everything_but_probes() {
    let fixture = Fixture::new();
    let mut host = fixture.spawn_host(&[]);

    host.send_request(&make_request("bare-ping", "ping", serde_json::Value::Null));
    let ping_resp = host.expect_response(WAIT);
    assert!(
        ping_resp.ok,
        "a probe must never be an error response, even with no caller"
    );
    assert_eq!(ping_resp.payload.unwrap()["running"], false);

    host.send_request(&make_request(
        "bare-logins",
        "get_logins",
        serde_json::Value::Null,
    ));
    let logins_resp = host.expect_response(WAIT);
    assert!(!logins_resp.ok);
    let err = logins_resp
        .error
        .expect("non-probe denial carries an ErrorObj");
    assert_eq!(err.code, codes::DENIED);
    assert!(
        err.message.contains("browser"),
        "the message should name the cause (no recognised browser launch), got: {:?}",
        err.message
    );

    assert_no_stderr(&mut host);
}

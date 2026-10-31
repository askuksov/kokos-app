//! App-side native-messaging server. All policy lives here and in
//! `handlers`; the host binary (`kokos-nmh`) is only a pipe between the
//! browser's stdio and this channel. A plain `std::thread` (same
//! pattern as the auto-lock watcher in `lib.rs`) accepts connections on a
//! unix socket under the app's config dir — or, on Windows, on the named pipe
//! `\\.\pipe\dev.kuksov.kokos`; each connection is one browser-launched
//! host process, i.e. one extension.
//!
//! ## One state machine, two transports
//!
//! `start`/`stop`/`serve` exist once per transport, because binding, waking a
//! parked accept, and identifying a peer have no portable spelling. Everything
//! ABOVE the transport is shared verbatim: `serve_session` (the handshake and
//! the request loop) is generic over `Read + Write`, and the listener
//! bookkeeping — generation counter, `enabled`/`running`/`token` publication
//! order, the fail-closed-on-poison discipline — lives in the
//! `#[cfg(any(unix, windows))]` helpers just above `start`. That is deliberate:
//! the invariants those helpers encode each close a real bug (see their doc
//! comments), and a second hand-copied listener would be a
//! second place for them to rot. The per-platform half is kept as thin as the
//! OS allows.

use std::sync::Mutex;

use kokos_nmh::origin::Caller;
use kokos_nmh::protocol::{codes, Request, Response};

use tauri::Manager;

#[cfg(any(unix, windows, test))]
use kokos_nmh::protocol::HelloFrame;

#[cfg(any(unix, windows))]
use kokos_nmh::framing::{read_frame, write_frame};
#[cfg(any(unix, windows))]
use kokos_nmh::origin::Browser;
#[cfg(any(unix, windows))]
use kokos_nmh::protocol::parse_request;
#[cfg(any(unix, windows))]
use std::io::{Read, Write};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

pub mod handlers;
pub mod grants;
pub mod manifest;
pub mod snap;

/// Native-messaging listener state, held on `AppState.nmh`.
#[derive(Default)]
pub struct NmhState {
    /// User setting mirror: whether the listener should be (or is) running.
    pub enabled: Mutex<bool>,
    /// Whether the accept loop is currently up.
    pub running: Mutex<bool>,
    /// Bumped by every `start()` call, which captures the new value before
    /// spawning its accept-loop thread. That thread only clears `running` on
    /// exit if this counter still equals the value it captured — otherwise a
    /// stale loop from an earlier
    /// stop()->start() cycle, exiting late, could clobber a newer listener's
    /// `running = true` with a stale `false`.
    pub generation: Mutex<u64>,
    /// Last refused origin + when, so a host that reconnects per request does
    /// not write one `extension_denied` audit row per request (see
    /// `should_audit_denial`). Not security state — purely log hygiene.
    pub last_denied: Mutex<Option<(String, std::time::Instant)>>,
    /// Global per-window cap on `extension_denied` audit rows (see
    /// `DenyBudget`). Independent of the single-slot `last_denied` dedupe,
    /// which alternating keys can defeat. Not security state -- log hygiene.
    pub deny_budget: Mutex<DenyBudget>,
    /// Last granted-release dedupe key + when, covering
    /// `extension_secret_granted`/`extension_totp_granted`
    /// (`audit_grant_release`). Deliberately a SEPARATE slot from
    /// `last_denied` above -- NEVER shared: a single shared slot would let a
    /// release and a denial for the SAME `{action}@{domain}` evict each
    /// other's cached key, so alternating one release then one denial (or
    /// vice versa) would write a row every single time regardless of either
    /// window, reopening exactly the audit-flood hole the denial dedupe
    /// closes (see `audit_denial`'s doc comment). Not security state -- purely
    /// log hygiene, same as `last_denied`.
    pub last_granted: Mutex<Option<(String, std::time::Instant)>>,
    /// Pending browser-extension confirmations, keyed by request id. A
    /// socket thread parks on the receiver; `nmh_confirm_reply` answers.
    pub confirms: grants::Registry,
    /// Live "once per site per session" grants (`nmh_confirm_mode =
    /// session_domain`).
    pub grants: grants::Grants,
    /// Current handshake token (Layer B), minted on each `start()`
    /// and mirrored to the `nmh.token` file the host reads — `0600` on unix,
    /// and on Windows protected only by the profile ACL it inherits (a real
    /// downgrade, argued in the Windows `start`'s doc comment). `None` when
    /// the listener is down. Compared against `Hello.token` at the handshake
    /// via `token_matches`; rotated every start, cleared by `stop()`.
    pub token: Mutex<Option<String>>,
    /// The live Windows listener, shared between `start`'s accept thread and
    /// `stop()`. `None` while the listener is down.
    ///
    /// Windows-only, and deliberately WITHOUT a unix twin -- this is not a
    /// cfg-pairing omission. On unix `stop()` wakes a thread parked in
    /// `accept()` by dialing the socket PATH (`UnixStream::connect`), and a
    /// path is a global name it can rederive from `transport::socket_dir()`
    /// without holding anything. A named pipe's shutdown signal is an event
    /// OWNED BY the `PipeListener` object (`PipeListener::shutdown`), so
    /// `stop()` can only reach it through a live reference -- hence a slot,
    /// and hence an `Arc`: the accept thread and `stop()` genuinely co-own it,
    /// and `shutdown()` is explicitly documented as safe to call from another
    /// thread while the owner is parked in the kernel.
    ///
    /// Generation discipline (same rule as `running`, see `generation`): the
    /// slot is written ONLY by `start`, after its bind succeeded and after
    /// `publish_start_state` bumped the counter, and cleared ONLY by `stop()`
    /// -- never by an accept loop on its own exit. A stale loop exiting late
    /// must not be able to drop a NEWER listener out of this slot, which is
    /// exactly what "the exiting thread clears it" would do.
    ///
    /// Clearing the slot also matters for more than tidiness: the listener's
    /// idle pipe instance is closed when the last `Arc` drops, and while ANY
    /// instance of the name survives, `FILE_FLAG_FIRST_PIPE_INSTANCE` makes a
    /// fresh `bind()` fail with `AddrInUse` (see `create_instance`'s doc
    /// comment in `kokos-nmh`). Holding a dead listener here would therefore
    /// break the next `start()`, not merely leak.
    #[cfg(windows)]
    pub listener: Mutex<Option<std::sync::Arc<kokos_nmh::transport::PipeListener>>>,
}

/// True when the accept loop that captured `my_generation` at start-up
/// should still clear `running` on its own exit — i.e. no later `start()`
/// call has bumped `NmhState.generation` since. Kept as a pure function,
/// separate from the mutex plumbing around it, so the comparison itself is
/// directly testable without a real listener thread. Only ever called from `clear_running_if_current` — the tail every
/// platform's accept loop ends with — plus this file's own tests, so it is
/// cfg-gated the same way `is_hello_frame` and `truncate_id` further down this
/// file are.
#[cfg(any(unix, windows, test))]
fn is_current_generation(current: u64, my_generation: u64) -> bool {
    current == my_generation
}

/// Reduces a stored Chrome whitelist entry or an incoming origin to a
/// canonical comparison key: trim, lowercase, and — for the
/// `chrome-extension://` form — take only the id, cut at the first `/`, `?`
/// or `#` (the same rule `origin::from_args` uses to build the origin in the
/// first place). A bare id (no scheme) is used as-is. `None` when the result
/// is empty or still contains a separator, so a malformed entry is simply
/// unmatchable rather than acting as a wildcard.
fn chrome_key(s: &str) -> Option<String> {
    let lower = s.trim().to_ascii_lowercase();
    let candidate = match lower.strip_prefix("chrome-extension://") {
        Some(rest) => rest.split(['/', '?', '#']).next().unwrap_or(""),
        None => lower.as_str(),
    };
    if candidate.is_empty() || candidate.contains(['/', '?', '#']) {
        None
    } else {
        Some(candidate.to_string())
    }
}

/// Firefox ids have no path structure (`name@domain` or `{uuid}`) — trim
/// only, and compare case-SENSITIVELY.
///
/// This is a CORRECTNESS fix, not a security one. Under this project's own
/// threat model the extension id is not a secret — any local process can
/// already dial the 0600 socket directly, and `handshake_denial_detail`
/// deliberately writes the id into the audit log on the grounds that an
/// origin/id is not sensitive — so an attacker able to present a case
/// variant could equally present the exact bytes; case-sensitivity narrows
/// nothing. What it actually buys is agreement: Firefox itself matches its
/// manifest's `allowed_extensions` entry against the connecting extension's
/// `gecko.id` case-sensitively, and `nmh_install` writes the byte-identical
/// id into both the manifest and this whitelist Vec in the same call — so
/// comparing those bytes exactly here is what makes a mixed-case `gecko.id`
/// work end to end. Normalising case at this gate would only create a
/// second, looser identity for the same extension, one Firefox itself would
/// never route a real connection under.
///
/// `chrome_key` (below) still lowercases, and that is not an inconsistency:
/// `validate_chrome_id` restricts a stored Chrome id to 32 lowercase `a`-`p`
/// characters, so lowercasing there is a no-op on the only values that can
/// ever reach it, not a design choice this function departs from. See
/// `is_allowed_origin`'s tests below for the exact case-variant behaviour
/// this preserves.
fn firefox_key(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Whitelist decision AND canonicalisation in one step — THE security gate
/// every connection passes through. Both the stored entry and the incoming origin are reduced
/// to a canonical key before comparing (never compare raw strings): a stored
/// bare id like `abcdefghijklmnop` must NOT be matched by
/// `chrome-extension://evil/abcdefghijklmnop` just because that id appears as
/// a trailing path segment — that would let any extension impersonate a
/// whitelisted one by appending its id as a path.
///
/// Returns the CANONICAL origin string when `browser`+`origin` matches an
/// entry in the whitelist — `chrome-extension://<id>/` (id lowercased) for
/// Chrome, the trimmed-only id for Firefox — the exact same shape
/// `whitelist_removed_origins` (below) computes, and therefore the exact
/// shape `cascade_forget_origins` purges by. `None` when it doesn't match
/// (unparsable or simply absent from the list).
///
/// This is now the single source of truth `is_allowed_origin` (just below)
/// delegates to, so acceptance and the string a caller stores as the
/// connection's origin can never diverge. Before this existed, `serve`
/// stored `hello_frame.hello.origin` unmodified even though this gate
/// normalised before comparing: a crafted hello origin like
/// `chrome-extension://ABCDEF.../popup.html` — the shape a local process
/// dialing the socket directly (bypassing the host binary's own
/// `origin::from_args` normalisation) could send — passed the whitelist
/// (this function lowercases + strips the path before comparing) yet was
/// kept raw, so a later whitelist removal computed the NORMALISED origin to
/// purge and found no matching row: an orphaned grant that kept
/// auto-releasing forever. `serve` now calls this function instead, and
/// keeps ITS return value as `Caller.origin` for the rest of the
/// connection's lifetime, so mint, lookup, audit, and the cascade all agree
/// on the same bytes.
pub fn canonical_origin(
    browser: &str,
    origin: &str,
    chrome_ids: &[String],
    firefox_ids: &[String],
) -> Option<String> {
    match browser.trim().to_ascii_lowercase().as_str() {
        "chrome" => {
            let candidate = chrome_key(origin)?;
            chrome_ids
                .iter()
                .any(|id| chrome_key(id).as_deref() == Some(candidate.as_str()))
                .then(|| format!("chrome-extension://{candidate}/"))
        }
        "firefox" => {
            let candidate = firefox_key(origin)?;
            firefox_ids
                .iter()
                .any(|id| firefox_key(id).as_deref() == Some(candidate.as_str()))
                .then_some(candidate)
        }
        _ => None,
    }
}

/// Thin boolean wrapper over `canonical_origin` (above) — kept as its own
/// function because most callers (the per-request live re-checks further
/// down this file, in `serve`'s loop) only need the yes/no answer, never the
/// canonical string itself.
pub fn is_allowed_origin(
    browser: &str,
    origin: &str,
    chrome_ids: &[String],
    firefox_ids: &[String],
) -> bool {
    canonical_origin(browser, origin, chrome_ids, firefox_ids).is_some()
}

/// True when the socket peer's effective uid is our own (Layer A).
/// Fail-closed: `None` — meaning the `getpeereid` syscall itself failed — is
/// NOT self. The `0600` socket already blocks OTHER users from connecting at
/// all; this additionally rejects a same-path peer whose euid differs from
/// ours, the only realistic instance of which is a `root` process that bypassed
/// the file permissions. Such a process already owns the machine, so this is
/// defense-in-depth, not a gap-closer (docs/THREAT-MODEL.md). Kept as a pure
/// function, separate from the `getpeereid` syscall wrapper, so the decision is
/// directly testable without a real socket. Gated `any(unix, test)` — its only
/// non-test caller is `serve` (`#[cfg(unix)]`), same as `is_hello_frame` below.
#[cfg(any(unix, test))]
fn peer_is_self(peer: Option<u32>, me: u32) -> bool {
    peer == Some(me)
}

/// True when the token a peer presented in `Hello` matches the app's current
/// handshake token (Layer B). Fail-closed on BOTH sides: an empty
/// presented token, or a `None`/empty current token (the listener minted
/// none), never matches — a missing token must never authenticate. Plain byte
/// comparison is deliberate, NOT an oversight: the token file is `0600`, so a
/// same-user attacker can read the token outright, making a timing side channel
/// across this compare moot — a constant-time compare would defend nothing here
/// (docs/THREAT-MODEL.md).
///
/// Pure, and — unlike `peer_is_self` above, which decides a unix syscall's
/// answer and stays unix-gated — gated for BOTH real transports: Layer B is
/// platform-independent, and `serve_session` runs this identical check on the
/// unix socket and on the Windows named pipe. The Windows token file is NOT
/// `0600` (Windows has no such mode; see `start`'s Windows arm for what it is
/// instead), which changes who can read the token, not what this comparison
/// does with it.
#[cfg(any(unix, windows, test))]
fn token_matches(presented: &str, current: Option<&str>) -> bool {
    match current {
        Some(cur) if !cur.is_empty() => presented == cur,
        _ => false,
    }
}

/// Peer-credential wrapper (Layer A): the effective uid of the
/// process on the other end of `fd`, or `None` if the syscall fails. Kept
/// apart from the pure `peer_is_self` decision above so that decision is
/// testable without a real socket; this wrapper itself is exercised by a
/// `UnixStream::pair()` test below. `#[cfg(unix)]` — the whole native-messaging
/// listener is unix-only, and its only caller (`serve`) is too.
///
/// The syscall differs per platform and there is no portable spelling:
/// `getpeereid(3)` is a BSD/macOS interface absent from glibc, while Linux
/// exposes the same information through the `SO_PEERCRED` socket option. Both
/// arms return the peer's *effective* uid, which is all `peer_is_self` needs,
/// so the split stops at this function.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn peer_uid(fd: std::os::unix::io::RawFd) -> Option<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `fd` is a live, connected Unix-domain socket fd owned by the
    let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if rc == 0 {
        Some(uid as u32)
    } else {
        None
    }
}

/// Linux/Android counterpart of the wrapper above — see its docs. `SO_PEERCRED`
/// fills a `struct ucred` (pid/uid/gid) captured at `connect(2)` time; only the
/// uid is used here.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid(fd: std::os::unix::io::RawFd) -> Option<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `fd` is a live, connected Unix-domain socket fd owned by the
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        Some(cred.uid as u32)
    } else {
        None
    }
}

/// Windows counterpart of the `peer_uid` + `peer_is_self` pair above
/// (Layer A) — and the honest version of it, which is smaller than
/// the unix one. Read this together with the residual it documents.
///
/// **What actually holds the line on Windows is the pipe's DACL, not this
/// function.** `PipeListener::bind` creates every instance with a protected,
/// single-ACE descriptor — `D:P(A;;GA;;;<our SID>)`, no SYSTEM, no
/// Administrators, no Everyone — plus `PIPE_REJECT_REMOTE_CLIENTS`, and it
/// fails rather than falling back to a weaker one (see
/// `user_only_security_descriptor` in `kokos-nmh`). That is the structural
/// equivalent of the `0600` socket, and it is enforced by the kernel on every
/// `CreateFileW`, before a single byte of ours runs. `FILE_FLAG_FIRST_PIPE_INSTANCE`
/// covers the other half a file path gets for free: nobody can pre-create the
/// name and collect our handshakes, because an occupied name is refused
/// outright instead of silently joined.
///
/// **What this function adds** is the fail-closed shape the unix gate has:
/// there, a failed `getpeereid` is NOT self (`peer_is_self(None, _) == false`)
/// — "could not identify the peer" must never read as "peer is fine".
/// `GetNamedPipeClientProcessId` is the one peer question answerable here
/// without new FFI, and it is answerable ONLY on a genuine server end of a
/// connected pipe, so a stream that cannot name its client is not one we
/// accepted from our own listener in a healthy state. Refuse it, exactly as
/// the unix side refuses a `None` uid.
///
/// **What it deliberately does NOT do**, so nobody mistakes it for more than
/// it is: it does not compare the client's user. The unix euid check exists to
/// catch a peer that bypassed the file mode — realistically `root`. The
/// Windows twin of that peer is a SYSTEM/administrator process that opened the
/// pipe by impersonating us or by rewriting its DACL, and catching it needs
/// the client's TOKEN, not its PID: `OpenProcess` + `OpenProcessToken` +
/// `GetTokenInformation(TokenUser)`, or better `ImpersonateNamedPipeClient` on
/// the thread token (a PID is reusable and names a process, not a user — the
/// caveat `client_process_id`'s own doc comment states). Every one of those
/// entry points lives behind `windows-sys` features (`Win32_System_Threading`,
/// `Win32_Security`) that THIS crate does not declare; `kokos-nmh` does, which
/// is also where the pipe's FFI discipline already lives. So the check belongs
/// in `transport::named_pipe` as a `client_is_same_user()` next to
/// `client_process_id`, not smuggled in here on features that only resolve
/// through cross-crate unification.
///
/// The residual is therefore: on Windows an already-elevated process can reach
/// this listener where on unix `root` would be caught by Layer A. Both start
/// from "the attacker already owns the machine" (docs/THREAT-MODEL.md), and on
/// both platforms Layer B still applies — but this is one notch weaker than
/// unix, not equal to it, and it is written down here rather than papered over.
#[cfg(windows)]
fn peer_is_identifiable(stream: &kokos_nmh::transport::Conn) -> bool {
    stream.client_process_id().is_ok()
}

/// True when `bytes` parses as a `HelloFrame`. Used to reject a stray hello
/// arriving mid-stream: our own host never sends a second one, but any local
/// process can dial the 0600 socket directly, and re-handshaking mid-stream
/// must not be a way to swap identity.
///
/// Only called from `serve_session` (`#[cfg(any(unix, windows))]`) plus this
/// file's own tests, so it is cfg-gated the same way — a build with no
/// transport at all and no tests has no caller for it and `dead_code` would
/// otherwise fire.
#[cfg(any(unix, windows, test))]
fn is_hello_frame(bytes: &[u8]) -> bool {
    serde_json::from_slice::<HelloFrame>(bytes).is_ok()
}

/// Upper bound on the `id` echoed back inside a `too_large` fallback
/// response. `Request.id`/`Response.id` are attacker-controlled and bounded
/// only by the *incoming* frame cap (`MAX_FRAME`, ~1 MiB) — echoing an id that
/// size back verbatim would make the fallback response itself exceed
/// `MAX_FRAME`, defeating the whole point of this function (see
/// `encode_response`). Real ids are UUID-sized (`"req-<uuid>"`), far under
/// this bound, so truncation only ever bites a hostile or malformed id.
#[cfg(any(unix, windows, test))]
const TOO_LARGE_ID_CAP: usize = 128;

/// Truncates `s` to at most `max` bytes, backing off to the nearest char
/// boundary so a multi-byte UTF-8 sequence is never sliced through the
/// middle. `id` is arbitrary attacker-supplied text, so a naive `&s[..max]`
/// is a reachable panic (that would kill the connection thread) whenever the
/// cut happens to land inside a multi-byte character.
#[cfg(any(unix, windows, test))]
fn truncate_id(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Builds the audit detail for a handshake-time whitelist refusal: the
/// browser name plus the refused origin -- `handshake@{browser}` alone discarded the one actionable datum a user
/// reading the security log needs. The origin is attacker-controlled argv,
/// bounded only by `MAX_FRAME` upstream, so it is truncated on a char
/// boundary via the same `truncate_id`/`TOO_LARGE_ID_CAP` machinery
/// `encode_response` uses, so a hostile handshake cannot use this to write
/// an oversized audit row. Factored out of `serve_session` so the truncation
/// is directly testable without a live `AppHandle`.
#[cfg(any(unix, windows, test))]
fn handshake_denial_detail(browser: &str, origin: &str) -> String {
    format!(
        "handshake@{browser}:{}",
        truncate_id(origin, TOO_LARGE_ID_CAP)
    )
}

/// Serialises a response, substituting `too_large` when the body would
/// exceed the 1 MiB frame limit (attachments never travel this channel, so an over-cap answer is a bug or an abuse, not a normal case).
/// The id is preserved — truncated to `TOO_LARGE_ID_CAP` bytes on a char
/// boundary when it's larger than that — so the extension can still
/// correlate the answer even when an oversized id was itself what pushed the
/// response over the cap.
#[cfg(any(unix, windows, test))]
fn encode_response(resp: &Response) -> Vec<u8> {
    match serde_json::to_vec(resp) {
        Ok(bytes) if bytes.len() <= kokos_nmh::framing::MAX_FRAME => bytes,
        _ => serde_json::to_vec(&Response::err(
            &truncate_id(&resp.id, TOO_LARGE_ID_CAP),
            codes::TOO_LARGE,
            "response exceeds the frame size limit",
        ))
        .expect("a too_large fallback with a bounded id cannot itself overflow"),
    }
}

/// Dedup window for `extension_denied` audit rows, covering every
/// handler-side denial too, not only the handshake: every host-side failure
/// arm nulls its cached connection, so a non-whitelisted extension
/// reconnects — and therefore re-handshakes — on every request. Without
/// dedupe that is one audit row per request.
///
/// Unconditional: `audit_denial` (below) is called from `handlers.rs`, which
/// compiles on every platform, so this constant needs a non-unix consumer
/// too — no longer `#[cfg(any(unix, test))]`.
const DENY_AUDIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// Max `extension_denied` rows written per `DENY_BUDGET_WINDOW`, across ALL
/// denial keys. The single-slot `last_denied` dedupe only collapses
/// consecutive repeats of ONE key, so a peer alternating keys would otherwise
/// write a row per attempt and, via `audit::append`'s prune-to-500, push real
/// history out of the journal. Suppressed denials are counted and summarized
/// in ONE aggregate row when the next window opens.
const DENY_BUDGET_MAX: u32 = 20;
const DENY_BUDGET_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// Window state for the global denial-row cap.
#[derive(Default)]
pub struct DenyBudget {
    window_start: Option<std::time::Instant>,
    written: u32,
    suppressed: u32,
}

/// Outcome of `DenyBudget::take`.
#[derive(Debug, PartialEq)]
pub enum DenyBudgetVerdict {
    /// Write the row; when `Some(n)`, first write one aggregate row saying `n`
    /// denials were suppressed in the previous window.
    Allow(Option<u32>),
    /// Over budget: skip the row (already counted).
    Suppress,
}

impl DenyBudget {
    fn take(&mut self, now: std::time::Instant) -> DenyBudgetVerdict {
        let expired = match self.window_start {
            None => true,
            Some(s) => now.saturating_duration_since(s) >= DENY_BUDGET_WINDOW,
        };
        let mut summary = None;
        if expired {
            if self.suppressed > 0 {
                summary = Some(self.suppressed);
            }
            self.window_start = Some(now);
            self.written = 0;
            self.suppressed = 0;
        }
        if self.written >= DENY_BUDGET_MAX {
            self.suppressed = self.suppressed.saturating_add(1);
            return DenyBudgetVerdict::Suppress;
        }
        self.written += 1;
        DenyBudgetVerdict::Allow(summary)
    }
}

/// True when this denial should be written to the audit log: the first
/// refusal of this `key`, or a repeat after the window. Log hygiene only —
/// the denial itself (closing the connection, or answering an error on the
/// wire) is unconditional. Shared by every `extension_denied` write through
/// `audit_denial` below — `key` is the caller's origin for a
/// handshake/live-revocation refusal, `format!("{action}@{domain}")` for a
/// handler-side one; a DIFFERENT key always logs, so one noisy denial can
/// never mask a different one's first occurrence.
///
/// Unconditional for the same reason as `DENY_AUDIT_WINDOW` above.
fn should_audit_denial(
    last: Option<&(String, std::time::Instant)>,
    key: &str,
    now: std::time::Instant,
    window: std::time::Duration,
) -> bool {
    match last {
        None => true,
        Some((last_key, at)) => last_key != key || now.saturating_duration_since(*at) >= window,
    }
}

/// Writes an `extension_denied` audit row, routed through the dedupe
/// machinery above. Every handler-side denial in `handlers.rs` (`not_in_scope`, a refused
/// `confirm()`) used to write an unconditional row -- before any anchoring
/// or confirmation ever ran, so a whitelisted-but-compromised extension could
/// evict the ENTIRE audit log (`kokos_core::audit::append` prunes to 500
/// rows) with a few hundred free requests, silently erasing every real
/// security event (unlock, lock, failed attempts, `extension_connected`).
/// The handshake denial already had this dedupe; this function is the
/// one shared path every `extension_denied` write now goes through.
///
/// `key` identifies the denial for dedupe purposes -- the caller's origin
/// for a handshake or live-revocation refusal, `format!("{action}@{domain}")`
/// for a PRE-confirm handler-side denial (`secret_gate`'s `not_in_scope`, and
/// its post-confirm re-anchor equivalent in `update_login` -- the two are
/// deliberately kept in the SAME key-space, see the parity note at that call
/// site). `detail` is the string actually written to the audit row; kept as a
/// separate parameter because several callers dedupe on a DIFFERENT string
/// than the one they log: the handshake/revocation denials dedupe on a bare
/// origin but log a differently-shaped string (`"handshake@{browser}:{origin}"`,
/// origin truncated / `"revoked@{browser}"`).
///
/// A POST-CONFIRM denial -- i.e. one
/// that only happens after a real human had up to 60s to answer `confirm()`
/// -- uses `key = format!("confirm:{action}@{domain}")` while `detail` stays
/// the plain `format!("{action}@{domain}")` (unchanged on the wire and in the
/// log). Without the `"confirm:"` prefix this key would collide with the
/// PRE-confirm `not_in_scope` denial above, which fires before any anchoring
/// or human interaction at all and is trivially repeatable by an attacker: an
/// extension could send one unanchored `get_secret` (seeding the dedupe slot)
/// immediately before an anchored one a human explicitly Denies, and the
/// human's decision would then leave no row in the security log at all. The
/// residual limitation is accepted: two denials that both go through the
/// SAME `"confirm:"`-prefixed key (e.g. two human Denies for the same
/// action+domain within the 60s window) still collapse into one row -- kept
/// because a timeout denial (not human-driven) flows through this identical
/// path and must not be able to flood the pruning log either.
///
/// The denial ITSELF -- closing the connection, or answering `denied`/
/// `not_in_scope` on the wire -- is always unconditional; this only decides
/// whether an audit ROW is written.
///
/// Not cfg-gated: handler-side callers live in `handlers.rs`, which compiles
/// on every platform (see that file's own cfg-pairing note), so this
/// function needs a non-unix consumer too, same as `should_audit_denial`/
/// `DENY_AUDIT_WINDOW` above.
fn audit_denial(app: &tauri::AppHandle, key: &str, detail: &str) {
    let st = app.state::<crate::state::AppState>();
    let now = std::time::Instant::now();
    if st.nmh.take_denial_log(key, now) {
        match st.nmh.take_deny_budget(now) {
            DenyBudgetVerdict::Allow(summary) => {
                if let Some(n) = summary {
                    handlers::audit_event(app, "extension_denied", Some(&format!("suppressed:{n}")));
                }
                handlers::audit_event(app, "extension_denied", Some(detail));
            }
            DenyBudgetVerdict::Suppress => {}
        }
    }
}

/// Dedupe key for a handshake whose origin failed `canonical_origin`. The
/// origin is peer-controlled, so it must NEVER become a key (rotating origins
/// would defeat the dedupe); the key is a fixed per-browser bucket instead.
#[cfg(any(unix, windows, test))]
fn invalid_origin_key(browser: &str) -> String {
    format!("invalid_origin@{browser}")
}

/// Dedup window for `extension_secret_granted`/`extension_totp_granted`
/// audit rows -- separate from `DENY_AUDIT_WINDOW` and routed through its
/// own `last_granted` slot (see that field's doc comment for why sharing
/// `last_denied` would reopen the audit-flood hole the denial dedupe
/// closes). Wider than the 60s denial window: a granted release is not an
/// attack signal by definition, so 5 minutes is enough to stop a hot polling
/// extension in `session_domain`/`remember_site`/`trust_extension` mode from
/// writing one row per request, without burying a later, genuinely new
/// site's first release under an excessively long window.
const GRANT_AUDIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// Writes an `extension_secret_granted`/`extension_totp_granted` audit row
/// for a `confirm()` call that skipped the human prompt entirely -- a live
/// `session_domain` grant, a live `remember_site` persistent grant, and
/// `trust_extension` mode all fall through the SAME early-return branch (see
/// `handlers::confirm`'s call site), so this is the only place any of the
/// three becomes observable to a security-log reader. `action` picks the
/// event name (`"get_totp"` -> `extension_totp_granted`, else
/// `extension_secret_granted` -- `confirm` is never reached by a write
/// action, see `handlers::should_capture_grant`'s doc comment for why);
/// `domain` is the eTLD+1, exactly the `detail` shape `extension_secret`/
/// `extension_totp` already use for the human-approved path, so a log reader
/// sees the same shape regardless of which path produced the row.
///
/// Routed through `should_audit_denial` -- a generic "was this key seen
/// inside the window" predicate despite its name, reused rather than
/// duplicated (so the two dedupe key-spaces are proven disjoint through this
/// exact shared helper) -- but through the
/// SEPARATE `last_granted` slot and `GRANT_AUDIT_WINDOW`, keyed
/// `format!("grant:{action}@{domain}")`. NEVER `last_denied`/
/// `DENY_AUDIT_WINDOW` (see `NmhState::last_granted`'s doc comment for why
/// sharing would reopen the audit-flood hole).
fn audit_grant_release(app: &tauri::AppHandle, action: &str, domain: &str) {
    let event = if action == "get_totp" {
        "extension_totp_granted"
    } else {
        "extension_secret_granted"
    };
    let st = app.state::<crate::state::AppState>();
    let now = std::time::Instant::now();
    if st.nmh.take_grant_release_log(action, domain, now) {
        handlers::audit_event(app, event, Some(domain));
    }
}

impl NmhState {
    /// Pure denial dedupe decision -- needs no `AppHandle`: locks
    /// `last_denied` and, atomically under that SAME lock, updates the slot
    /// when the caller should log, returning whether it should. `key` is
    /// already built by the caller (`audit_denial`'s callers pass
    /// differently-shaped keys: a bare origin for a handshake/live-revocation
    /// denial, `format!("{action}@{domain}")` or
    /// `format!("confirm:{action}@{domain}")` for a handler-side one -- see
    /// `audit_denial`'s own doc comment). Never reads or writes
    /// `last_granted`.
    ///
    /// Factored out of `audit_denial`: the previous shape computed the
    /// decision and updated the slot inline inside `audit_denial` itself,
    /// which needs a real `tauri::AppHandle` to even call -- so the
    /// slot-separation property (this method vs `take_grant_release_log`
    /// below never touching each other's `Mutex`) could only be tested
    /// indirectly, via hand-built tuples fed to the pure `should_audit_denial`
    /// helper. That proved the two KEY STRINGS differ; it never proved the
    /// two SLOTS stay separate -- a mutation routing `take_grant_release_log`
    /// through `last_denied` instead of `last_granted` ran green against that
    /// suite. `NmhState` needs no `AppHandle` to construct (`#[derive(Default)]`,
    /// every field a bare `Mutex`), so factoring the locking + decision onto
    /// `&self` methods makes the slot itself directly testable (see
    /// `a_grant_release_between_two_denials_for_the_same_key_does_not_evict_last_denied`
    /// and its mirror, below).
    ///
    /// Also, incidentally, closes a narrow TOCTOU gap the previous shape had:
    /// that version dropped the lock between computing `should_audit` and
    /// (if true) re-acquiring it to write the new value, so two threads
    /// racing the same key could both observe "should log" before either
    /// wrote back. This version holds one lock across the read-then-write,
    /// so the decision and the update are atomic. Not a behavioural change
    /// under any non-racing (i.e. normal single-threaded-per-connection)
    /// usage this codebase actually has today.
    fn take_denial_log(&self, key: &str, now: std::time::Instant) -> bool {
        let mut last = match self.last_denied.lock() {
            Ok(l) => l,
            Err(_) => return false,
        };
        let should_log = should_audit_denial(last.as_ref(), key, now, DENY_AUDIT_WINDOW);
        if should_log {
            *last = Some((key.to_string(), now));
        }
        should_log
    }

    /// Global denial-row cap decision (see `DenyBudget`). A poisoned lock
    /// suppresses, like the other `take_*` methods.
    fn take_deny_budget(&self, now: std::time::Instant) -> DenyBudgetVerdict {
        match self.deny_budget.lock() {
            Ok(mut b) => b.take(now),
            Err(_) => DenyBudgetVerdict::Suppress,
        }
    }

    /// Pure grant-release dedupe decision -- needs no `AppHandle`: locks
    /// `last_granted`, builds the `format!("grant:{action}@{domain}")` key,
    /// and -- atomically under that SAME lock -- updates the slot when the
    /// caller should log, returning whether it should. Never reads or writes
    /// `last_denied` (see `NmhState::last_granted`'s doc comment for why the
    /// two must stay separate). Mirrors `take_denial_log` above; see that
    /// method's doc comment for the full rationale (this is the other half
    /// of the same slot-separation fix).
    fn take_grant_release_log(&self, action: &str, domain: &str, now: std::time::Instant) -> bool {
        let key = format!("grant:{action}@{domain}");
        let mut last = match self.last_granted.lock() {
            Ok(l) => l,
            Err(_) => return false,
        };
        let should_log = should_audit_denial(last.as_ref(), &key, now, GRANT_AUDIT_WINDOW);
        if should_log {
            *last = Some((key, now));
        }
        should_log
    }
}

/// Invalidates every confirmation-related piece of state: denies all
/// pending prompts and drops all session grants. Call this from EVERY path
/// that locks, closes, or otherwise revokes the vault or the
/// browser-integration settings — a grant must never outlive the key, and a
/// prompt must never outlive the session it was asked about (the frontend
/// confirm modal closes itself on the `nmh-confirm-cancel` event this emits).
///
/// Order matters: grants first, then
/// pending prompts, then the frontend event, with neither of `grants`'s nor
/// `confirms`'s own mutex held across the emit. `req_id: null` in the
/// payload means "close whatever confirm dialog is currently open", since a
/// mass-cancel (unlike a single `reply`) has no one particular id to name.
/// The emit's result is ignored: a torn-down or not-yet-created window is
/// not a reason to fail whatever lock/close/settings-change triggered this.
pub fn invalidate_confirms(app: &tauri::AppHandle) {
    use tauri::Emitter;
    let st = app.state::<crate::state::AppState>();
    st.nmh.grants.clear();
    st.nmh.confirms.cancel_all();
    let _ = app.emit("nmh-confirm-cancel", serde_json::json!({ "req_id": null }));
}

/// The whitelist entries REMOVED between `old` and `new` (present in `old`,
/// absent from `new`), each reduced to the exact origin string a live
/// connection's persistent grant would have been stored under. Chrome
/// entries are run through `chrome_key` and rewrapped as
/// `chrome-extension://<id>/` -- reusing `chrome_key`'s existing parsing
/// (bare id, full origin, trailing path/query/fragment: all already handled
/// there) rather than re-deriving the id some new way, so a removed entry
/// stored in any shape `chrome_key` accepts still resolves to the IDENTICAL
/// origin a live handshake would have produced; an entry `chrome_key` cannot
/// parse (`None`) is skipped -- it could never have authenticated a real
/// connection either, so no grant could exist under it to forget. Firefox
/// entries are taken bare, unchanged (matching how a Firefox `Caller.origin`
/// is stored -- see `kokos_nmh::origin`'s doc comment). `browser` is
/// `"chrome"` or `"firefox"`; anything else yields no origins.
///
/// Pure and independent of any live `AppHandle`/vault, so the diffing this
/// needs -- a whitelist edit can add, remove, clear, or leave a browser's
/// list unchanged -- is directly testable without a database. Used by
/// `commands::nmh_install`,
/// `commands::nmh_uninstall`, and `commands::set_settings` -- the three
/// writers of `nmh_chrome_ids`/`nmh_firefox_ids` -- to compute
/// `cascade_forget_origins`'s `removed` argument BEFORE the new whitelist is
/// persisted (the old ids are gone from `AppState` the moment the new ones
/// are written, so the caller must capture `old` first).
pub fn whitelist_removed_origins(old: &[String], new: &[String], browser: &str) -> Vec<String> {
    old.iter()
        .filter(|id| !new.contains(id))
        .filter_map(|id| match browser {
            "chrome" => chrome_key(id).map(|bare_id| format!("chrome-extension://{bare_id}/")),
            "firefox" => firefox_key(id),
            _ => None,
        })
        .collect()
}

/// Deletes every persistent `nmh_grants` row for each origin in `removed`
/// (the output of `whitelist_removed_origins`), returning how many rows were
/// actually removed across the whole batch. This is the security-load-bearing
/// half of the whitelist-removal cascade: a removed extension must not retain
/// a `remember_site` grant it can no longer even reach. Called wherever a
/// browser's whitelist SHRINKS -- `commands::nmh_uninstall` (clears a
/// browser's whole list) and `commands::set_settings` (a wholesale whitelist
/// edit), PLUS `commands::nmh_install`: that command REPLACES a browser's
/// whitelist wholesale rather than appending
/// (`browser_ids_after_install`'s own doc comment), so installing a new id
/// silently drops whichever old id was previously trusted -- the exact same
/// gap this cascade exists to close, even though the list's total LENGTH
/// never shrinks there.
///
/// Deliberately does NOT audit itself: the caller already knows which
/// browser's removed set it just passed in (every call site above operates
/// on one browser at a time), so it writes the single `extension_grant_revoked`
/// row itself, with `detail` = that browser's name, when this returns > 0.
///
/// A closed or locked vault has no `nmh_grants` table reachable at all
/// (persistent grants live inside the encrypted vault) -- it is skipped
/// silently rather than erroring or panicking (an accepted residual: an
/// extension removed from the whitelist while a vault is locked keeps
/// whatever persistent grant it had until that vault is next opened and some
/// cascade or a manual "Forget" actually runs).
pub fn cascade_forget_origins(app: &tauri::AppHandle, removed: &[String]) -> usize {
    if removed.is_empty() {
        return 0;
    }
    let st = app.state::<crate::state::AppState>();
    let Ok(mut reg) = st.sessions.lock() else {
        return 0;
    };
    // Every open session, not just the active one: an inactive-but-open vault
    // keeps its own `nmh_grants` rows, and a stale row would suppress the
    // confirmation prompt once that origin is re-allowed and the vault is
    // selected again.
    let mut total = 0;
    for s in reg.iter_mut() {
        let Some(v) = s.vault.as_ref() else {
            continue;
        };
        total += removed
            .iter()
            .filter_map(|origin| kokos_core::nmh_grants::delete_by_origin(&v.conn, origin).ok())
            .sum::<usize>();
    }
    total
}

pub fn dispatch(
    app: &tauri::AppHandle,
    caller: &Caller,
    scope: &mut handlers::ConnScope,
    req: Request,
) -> Response {
    match req.action.as_str() {
        "ping" | "get_status" => handlers::status(app, &req),
        "get_logins" => handlers::get_logins(app, &req, scope),
        "get_secret" => handlers::get_secret(app, &req, scope, &caller.origin),
        "get_totp" => handlers::get_totp(app, &req, scope, &caller.origin),
        "save_login" => handlers::save_login(app, &req, &caller.origin),
        "update_login" => handlers::update_login(app, &req, scope, &caller.origin),
        "generate_password" => handlers::generate_password(&req),
        _ => Response::err(
            &req.id,
            codes::UNKNOWN_ACTION,
            &format!("unknown action '{}'", req.action),
        ),
    }
}

/// Longer than the host's own 90 s confirm-wait timeout
/// (`transport::timeout_for`), so the app never times out a request the host
/// is still legitimately waiting on a human to answer. Applies to both
/// directions: a read timeout alone still lets a wedged peer block a write
/// forever.
///
/// Both transports honour it for real: `UnixStream` maps it onto
/// `SO_RCVTIMEO`/`SO_SNDTIMEO`, and `PipeStream` onto overlapped I/O with a
/// `WaitForSingleObject` deadline plus a `CancelIo`-and-reap — a named pipe
/// has no socket timeout option at all, which is precisely why that module is
/// written the way it is (see `kokos-nmh`'s `named_pipe` module doc).
#[cfg(any(unix, windows))]
const CONN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Mints this listener generation's Layer B handshake token: two
/// v4 UUIDs, ~244 bits from the OS CSPRNG, reusing the `uuid` dep the app
/// already carries rather than introducing a second RNG. Shared by both
/// transports so the token's entropy and shape can never drift between
/// platforms — only WHERE the file lands, and what protects it there, is
/// platform business (see each `start` arm).
#[cfg(any(unix, windows))]
fn mint_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Reads the `enabled` mirror, fail-closed: a poisoned mutex is "can't
/// decide", and the only safe answer to that is "not enabled" — never keep
/// serving on an undecidable state (same discipline as the auto-lock watcher
/// in `lib.rs`). Factored out because this exact read happens in four places
/// (each accept loop's post-accept check, plus twice per iteration of
/// `serve_session`'s request loop) and every one of them must fail the same
/// way; inlined copies are how one of them eventually stops.
#[cfg(any(unix, windows))]
fn nmh_enabled(app: &tauri::AppHandle) -> bool {
    match app.state::<crate::state::AppState>().nmh.enabled.lock() {
        Ok(e) => *e,
        Err(_) => false,
    }
}

/// Publishes a freshly bound listener's state and returns the generation its
/// accept thread must capture — or `None`, meaning "do not start at all".
///
/// The ORDER is load-bearing, identical on every transport, and is the reason
/// this is one function rather than one copy per platform:
///
/// 1. `generation` is bumped FIRST and its new value captured, so the accept
///    thread that is about to be spawned can tell, on its own exit, whether it
///    is still the current listener.
///    Poisoned -> we cannot safely bump, let alone later compare, a generation
///    counter; fail closed by refusing to start rather than risk two loops
///    both believing they are current.
/// 2. `enabled` then `running`, so a caller reading `nmh_status()` right after
///    `start()` already sees the listener as up.
/// 3. `token` LAST, but still BEFORE the accept thread exists — so every peer
///    this listener ever serves is checked against a token that is already
/// present, never against a spurious `None` (Layer B).
///
/// Every failure path is a poisoned mutex and every one returns `None`: this
/// runs inside tauri's `setup()`, where a panic kills app startup, and a
/// listener whose token can never be matched is worse than no listener.
/// Callers must treat `None` as "do not spawn, and undo whatever was already
/// published" — see each `start` arm.
#[cfg(any(unix, windows))]
fn publish_start_state(app: &tauri::AppHandle, token: String) -> Option<u64> {
    let app_state = app.state::<crate::state::AppState>();
    let my_generation = match app_state.nmh.generation.lock() {
        Ok(mut g) => {
            *g += 1;
            *g
        }
        Err(_) => return None,
    };
    match app_state.nmh.enabled.lock() {
        Ok(mut enabled) => *enabled = true,
        Err(_) => return None,
    }
    match app_state.nmh.running.lock() {
        Ok(mut running) => *running = true,
        Err(_) => return None,
    }
    match app_state.nmh.token.lock() {
        Ok(mut t) => *t = Some(token),
        Err(_) => return None,
    }
    Some(my_generation)
}

/// The tail every accept loop ends with: only clear `running` if THIS loop's
/// generation is still the current one. A
/// stale loop from an earlier stop()->start() cycle — on unix, one still
/// blocked in `accept()` on a since-unlinked path; on Windows, one whose
/// `PipeListener` was shut down while a newer one is already bound — exiting
/// late must not clobber a newer listener's `running = true`. `stop()` already
/// writes `running = false` directly for the prompt-feedback case; this arm
/// only matters for a loop's own natural exit.
#[cfg(any(unix, windows))]
fn clear_running_if_current(app: &tauri::AppHandle, my_generation: u64) {
    let is_current = match app.state::<crate::state::AppState>().nmh.generation.lock() {
        Ok(g) => is_current_generation(*g, my_generation),
        Err(_) => false,
    };
    if is_current {
        if let Ok(mut running) = app.state::<crate::state::AppState>().nmh.running.lock() {
            *running = false;
        }
    }
}

/// The in-memory half of `stop()` — identical on every transport, and ordered
/// the way both `stop` arms depend on:
///
/// 1. `enabled = false` FIRST, so an accept loop's post-accept check already
///    sees false by the time the transport-specific wake-up lands, and a
///    connection already inside `serve_session`'s loop dies at its next check.
/// 2. `running = false` written DIRECTLY rather than left to the accept loop's
///    own (generation-guarded) exit — that loop may stay parked for a while
///    after this returns, and a caller reading `nmh_status()` right after
///    `stop()` must see the listener as down immediately.
/// 3. `token = None`, so a connection that races past the `enabled` check
///    still fails the Layer B gate (a `None` current token never matches).
///    The token FILE is removed by the caller, AFTER its wake-up step.
///
/// Every write is best-effort on a poisoned mutex: `stop()` is reachable from
/// a tauri command (`nmh_set_enabled`) and must never panic, and a poisoned
/// lock here already means another thread died holding it.
#[cfg(any(unix, windows))]
fn clear_stop_state(app: &tauri::AppHandle) {
    if let Ok(mut enabled) = app.state::<crate::state::AppState>().nmh.enabled.lock() {
        *enabled = false;
    }
    if let Ok(mut running) = app.state::<crate::state::AppState>().nmh.running.lock() {
        *running = false;
    }
    if let Ok(mut t) = app.state::<crate::state::AppState>().nmh.token.lock() {
        *t = None;
    }
}

/// Binds the native-messaging socket and starts accepting connections. Every
/// failure here must return quietly (never unwrap/panic): this runs inside
/// `setup()`, and a panic there kills app startup. A poisoned mutex is
/// treated as "can't decide" — same discipline as the auto-lock watcher —
/// not a reason to crash.
#[cfg(unix)]
pub fn start(app: tauri::AppHandle) {
    debug_assert_eq!(
        app.config().identifier,
        kokos_nmh::transport::HOST_NAME,
        "tauri.conf.json identifier and transport::HOST_NAME must match or the socket path splits"
    );

    let Some(dir) = kokos_nmh::transport::socket_dir() else {
        return;
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    if std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).is_err() {
        return;
    }

    let token = mint_token();
    let token_path = dir.join(kokos_nmh::transport::TOKEN_FILE);
    if std::fs::write(&token_path, &token).is_err() {
        return;
    }
    if std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).is_err() {
        return;
    }

    let path = dir.join(kokos_nmh::transport::SOCKET_FILE);
    let _ = std::fs::remove_file(&path);

    let Ok(listener) = UnixListener::bind(&path) else {
        return;
    };
    if std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).is_err() {
        return;
    }

    let Some(my_generation) = publish_start_state(&app, token) else {
        return;
    };

    let handle = app.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if !nmh_enabled(&handle) {
                        drop(stream);
                        break;
                    }
                    let app = handle.clone();
                    std::thread::spawn(move || serve(app, stream));
                }
                Err(_) => break,
            }
        }
        clear_running_if_current(&handle, my_generation);
    });
}

/// Windows twin of `start` above: the same state machine over a named pipe.
/// Read the two side by side — every difference below is forced by the OS, and
/// each one is argued where it appears.
///
/// ## Token file: an honest downgrade, not an equivalent
///
/// The unix arm chmods the directory `0700` and the token `0600`. Windows has
/// no such mode and there is no equivalent call made here at all: the token
/// lands in `%APPDATA%\dev.kuksov.kokos\nmh.token` and inherits the ACL of
/// the user's roaming profile — which grants the user, SYSTEM, and the local
/// Administrators group. That is genuinely WEAKER than `0600`, which grants
/// exactly one uid, and it is worth naming rather than glossing: on unix root
/// has to bypass the mode to read the token; on Windows any administrator can
/// simply read it.
///
/// Tightening it to a single-ACE DACL is possible in principle
/// (`SetNamedSecurityInfoW` with a `D:P(A;;FA;;;<our SID>)` descriptor — the
/// file counterpart of what `PipeListener::bind` already does for the pipe),
/// and it is deliberately NOT done here, for the same reason the peer check is
/// not (see `peer_is_identifiable`): those entry points live behind
/// `windows-sys` features this crate does not declare, and quietly borrowing
/// them through cross-crate feature unification is not something a security
/// file should do. The place for it is `kokos-nmh`'s `transport` module,
/// beside the DACL code that already exists, as something like
/// `protect_token_file(&Path)`.
///
/// What the residual costs is bounded by what the token is FOR. Layer B
/// authenticates "a process that can read the app's config dir" — it stops an
/// unprivileged stranger, not the machine's owner. An administrator who reads
/// the token still has to get past the pipe's DACL to use it, and an
/// administrator is already inside the "the attacker owns the machine" case
/// both platforms concede (docs/THREAT-MODEL.md). One notch weaker than unix,
/// then; not a different threat model, and written down rather than assumed
/// away.
///
/// ## Bind before publish, and what an occupied name means
///
/// `PipeListener::bind` refuses an occupied name (`AddrInUse`) instead of
/// joining the existing pipe — that refusal IS the anti-squatting guarantee,
/// see `create_instance` in `kokos-nmh` — and the practical consequence is
/// worth knowing before somebody debugs it: a `stop()` immediately followed by
/// a `start()` fails to bind while ANY instance of the old pipe still exists,
/// most commonly a connection that is still being served. Unix gets to
/// `unlink` and rebind; we do not.
///
/// The user-visible shape of that, concretely: turn Browser integration off
/// and back on while an extension is connected, and this `start()` can return
/// having done nothing. `stop()` wakes the accept loop immediately, but a
/// `serve` thread parked in `read_frame` keeps its instance until the peer
/// speaks or `CONN_TIMEOUT` (120 s) expires, and the name lives as long as
/// that instance does. The state stays consistent — `enabled`/`running` are
/// left false and the token file removed, so `nmh_set_enabled`'s `!running`
/// guard lets a later toggle try again, and a retry succeeds once the
/// instances have drained.
///
/// This function deliberately does NOT retry on its own. `start` runs inside
/// tauri's `setup()` and both `start` and `stop` run from a tauri command
/// (`nmh_set_enabled`), i.e. on threads that must not block, so a sleep-retry
/// loop here would stall the UI for exactly as long as the wedged peer chose
/// to stay silent. Retrying on a background thread is possible but is a real
/// design change, not a tweak: the generation bump, the `enabled`/`running`
/// publication and the listener slot would all have to move onto that thread
/// (see `publish_start_state` for why their ORDER is load-bearing), and a
/// retry that eventually gives up would still need somewhere to say so.
#[cfg(windows)]
pub fn start(app: tauri::AppHandle) {
    debug_assert_eq!(
        app.config().identifier,
        kokos_nmh::transport::HOST_NAME,
        "tauri.conf.json identifier and transport::HOST_NAME must match or the token path splits"
    );

    let Some(dir) = kokos_nmh::transport::socket_dir() else {
        return;
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }

    let token = mint_token();
    let token_path = dir.join(kokos_nmh::transport::TOKEN_FILE);
    if std::fs::write(&token_path, &token).is_err() {
        return;
    }

    let Ok(listener) = kokos_nmh::transport::PipeListener::bind() else {
        let _ = std::fs::remove_file(&token_path);
        return;
    };
    let listener = std::sync::Arc::new(listener);

    let Some(my_generation) = publish_start_state(&app, token) else {
        let _ = listener.shutdown();
        let _ = std::fs::remove_file(&token_path);
        return;
    };

    match app.state::<crate::state::AppState>().nmh.listener.lock() {
        Ok(mut slot) => *slot = Some(std::sync::Arc::clone(&listener)),
        Err(_) => {
            let _ = listener.shutdown();
            clear_stop_state(&app);
            let _ = std::fs::remove_file(&token_path);
            return;
        }
    }

    let handle = app.clone();
    let accepting = std::sync::Arc::clone(&listener);
    std::thread::spawn(move || {
        loop {
            match accepting.accept() {
                Ok(stream) => {
                    if !nmh_enabled(&handle) {
                        drop(stream);
                        break;
                    }
                    let app = handle.clone();
                    std::thread::spawn(move || serve(app, stream));
                }
                Err(_) => break,
            }
        }
        clear_running_if_current(&handle, my_generation);
    });
}

#[cfg(not(any(unix, windows)))]
pub fn start(_app: tauri::AppHandle) {
}

/// Best-effort tear-down: `nmh_set_enabled` is the intended caller.
///
/// Ordering matters and must not be "tidied" back: (1) `enabled` is flipped
/// false FIRST (inside `clear_stop_state`), so the accept loop's post-accept
/// check (see `start`) already sees false by the time the wake-up connection
/// below lands; (2) the wake-up connect happens WHILE the socket file still
/// exists — connecting to a path that has already been unlinked is an
/// immediate ENOENT no-op, which would leave a blocked `accept()` with no way
/// to wake up, leaking the thread forever; (3) only THEN is the socket file
/// removed. Swapping (2) and (3) silently reintroduces the "stop() can never
/// actually terminate the accept loop" defect this ordering exists to fix.
#[cfg(unix)]
pub fn stop(app: &tauri::AppHandle) {
    clear_stop_state(app);

    let Some(dir) = kokos_nmh::transport::socket_dir() else {
        return;
    };
    let path = dir.join(kokos_nmh::transport::SOCKET_FILE);

    let _ = UnixStream::connect(&path);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(dir.join(kokos_nmh::transport::TOKEN_FILE));
}

/// Windows twin of `stop` above: the same three steps in the same order, with
/// the middle one done properly instead of by trick.
///
/// 1. `clear_stop_state` — `enabled` false first, then `running`, then the
///    in-memory token, exactly as on unix.
/// 2. Wake the accept loop. Unix has to fake a client (`UnixStream::connect`
///    to its own socket) because there is no other way to unblock `accept(2)`,
///    which is why the unix arm carries that brittle "connect BEFORE unlink"
///    ordering note. `PipeListener::shutdown()` is a real, idempotent signal:
///    it makes the parked `accept` return `ConnectionAborted`, and every later
///    one too, with no bogus connection to filter out. So there is no ordering
///    hazard to preserve here — but the `enabled` check in the accept loop
///    stays anyway, because a genuine client can still arrive in the window
///    between step 1 and this step.
/// 3. Remove the token file. There is no socket file to remove: the channel is
///    a kernel object and it ceases to exist when its last instance handle
///    closes — which dropping the `Arc` taken out of the slot below begins,
///    and the accept thread finishes when it drops its own.
///
/// Dropping the listener out of the slot is not tidiness. While any instance
/// of the pipe name survives, the next `start()` cannot bind it
/// (`FILE_FLAG_FIRST_PIPE_INSTANCE`, see `NmhState::listener`), so a `stop()`
/// that merely signalled and kept the handle would break the following
/// `start()`.
#[cfg(windows)]
pub fn stop(app: &tauri::AppHandle) {
    clear_stop_state(app);

    let listener = match app.state::<crate::state::AppState>().nmh.listener.lock() {
        Ok(mut slot) => slot.take(),
        Err(_) => None,
    };
    if let Some(listener) = listener {
        let _ = listener.shutdown();
        drop(listener);
    }

    let Some(dir) = kokos_nmh::transport::socket_dir() else {
        return;
    };
    let _ = std::fs::remove_file(dir.join(kokos_nmh::transport::TOKEN_FILE));
}

#[cfg(not(any(unix, windows)))]
pub fn stop(_app: &tauri::AppHandle) {
}

/// Unix connection entry point: Layer A, the two timeouts, then the shared
/// session. Everything transport-specific about serving a connection lives in
/// these few lines; the protocol itself is in `serve_session`.
#[cfg(unix)]
fn serve(app: tauri::AppHandle, mut stream: UnixStream) {
    // SAFETY: `geteuid` takes no arguments, has no preconditions, and cannot
    let me = unsafe { libc::geteuid() } as u32;
    if !peer_is_self(peer_uid(stream.as_raw_fd()), me) {
        audit_denial(&app, "peercred", "peer_uid_mismatch");
        return;
    }

    if stream.set_read_timeout(Some(CONN_TIMEOUT)).is_err() {
        return;
    }
    if stream.set_write_timeout(Some(CONN_TIMEOUT)).is_err() {
        return;
    }

    serve_session(app, &mut stream);
}

/// Windows connection entry point — the same three steps as the unix `serve`
/// above, in the same order, so the two can be diffed line by line.
///
/// Step one is where they genuinely differ, and `peer_is_identifiable`'s doc
/// comment is where that difference is argued: the pipe's DACL is what
/// actually keeps other users out, and the PID query here supplies only the
/// fail-closed "if I cannot identify the peer at all, I refuse" half of the
/// unix check — not its identity comparison. The audit detail is deliberately
/// `peer_pid_unavailable` rather than the unix `peer_uid_mismatch`: a log
/// reader must be able to tell which question was actually asked. The dedupe
/// KEY stays `"peercred"`, so a peer that reconnects in a loop cannot flood
/// the audit log (see `audit_denial`).
///
/// The timeouts are real here too, not decorative — `PipeStream` implements
/// them with overlapped I/O rather than storing them and hoping (see
/// `CONN_TIMEOUT`).
#[cfg(windows)]
fn serve(app: tauri::AppHandle, mut stream: kokos_nmh::transport::Conn) {
    if !peer_is_identifiable(&stream) {
        audit_denial(&app, "peercred", "peer_pid_unavailable");
        return;
    }

    if stream.set_read_timeout(Some(CONN_TIMEOUT)).is_err() {
        return;
    }
    if stream.set_write_timeout(Some(CONN_TIMEOUT)).is_err() {
        return;
    }

    serve_session(app, &mut stream);
}

/// The protocol half of a connection: the handshake (Layer B, then the
/// whitelist gate) and then the request loop with its per-request live
/// re-checks.
///
/// Generic over `Read + Write`, and therefore shared VERBATIM by both
/// transports — which is the point. Every decision below closes a real bug,
/// and several of them (rejecting a mid-stream hello, the
/// SECOND post-read revocation check, canonicalising the origin exactly once
/// at the trust boundary) are precisely the kind a hand-copied second
/// implementation gets subtly wrong. The caller has already applied its
/// transport's peer gate and set `CONN_TIMEOUT` in both directions; from here
/// down nothing knows or cares which transport it is speaking over.
#[cfg(any(unix, windows))]
fn serve_session<S: Read + Write>(app: tauri::AppHandle, stream: &mut S) {
    let Ok(Some(bytes)) = read_frame(stream) else {
        return;
    };
    let Ok(hello_frame) = serde_json::from_slice::<HelloFrame>(&bytes) else {
        return;
    };

    let current_token = match app.state::<crate::state::AppState>().nmh.token.lock() {
        Ok(t) => t.clone(),
        Err(_) => None,
    };
    if !token_matches(&hello_frame.hello.token, current_token.as_deref()) {
        audit_denial(&app, "token", "handshake_token_mismatch");
        return;
    }

    let Some(browser) = Browser::from_name(&hello_frame.hello.browser) else {
        return;
    };
    let caller = Caller {
        browser,
        origin: hello_frame.hello.origin,
    };

    let (chrome_ids, firefox_ids) = {
        let app_state = app.state::<crate::state::AppState>();
        let Ok(settings) = app_state.settings.lock() else {
            return;
        };
        (
            settings.nmh_chrome_ids.clone(),
            settings.nmh_firefox_ids.clone(),
        )
    };

    let Some(canonical) = canonical_origin(
        caller.browser.as_str(),
        &caller.origin,
        &chrome_ids,
        &firefox_ids,
    ) else {
        audit_denial(
            &app,
            &invalid_origin_key(caller.browser.as_str()),
            &handshake_denial_detail(caller.browser.as_str(), &caller.origin),
        );
        return;
    };
    let caller = Caller {
        browser: caller.browser,
        origin: canonical,
    };

    handlers::audit_event(&app, "extension_connected", Some(caller.browser.as_str()));

    let mut scope = handlers::ConnScope::default();
    loop {
        if !nmh_enabled(&app) {
            break;
        }
        let (chrome_ids, firefox_ids) = {
            let st = app.state::<crate::state::AppState>();
            let Ok(settings) = st.settings.lock() else {
                break;
            };
            (
                settings.nmh_chrome_ids.clone(),
                settings.nmh_firefox_ids.clone(),
            )
        };
        if !is_allowed_origin(
            caller.browser.as_str(),
            &caller.origin,
            &chrome_ids,
            &firefox_ids,
        ) {
            audit_denial(
                &app,
                &caller.origin,
                &format!("revoked@{}", caller.browser.as_str()),
            );
            break;
        }

        let bytes = match read_frame(stream) {
            Ok(Some(b)) => b,
            Ok(None) => break,
            Err(_) => break,
        };

        if !nmh_enabled(&app) {
            break;
        }
        let (chrome_ids, firefox_ids) = {
            let st = app.state::<crate::state::AppState>();
            let Ok(settings) = st.settings.lock() else {
                break;
            };
            (
                settings.nmh_chrome_ids.clone(),
                settings.nmh_firefox_ids.clone(),
            )
        };
        if !is_allowed_origin(
            caller.browser.as_str(),
            &caller.origin,
            &chrome_ids,
            &firefox_ids,
        ) {
            audit_denial(
                &app,
                &caller.origin,
                &format!("revoked@{}", caller.browser.as_str()),
            );
            break;
        }

        if is_hello_frame(&bytes) {
            break;
        }

        let resp = match parse_request(&bytes) {
            Ok(req) => dispatch(&app, &caller, &mut scope, req),
            Err(resp) => resp,
        };
        if write_frame(stream, &encode_response(&resp)).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn chrome_origin_must_be_whitelisted_exactly() {
        let chrome = vec!["chrome-extension://abcdefghijklmnop/".to_string()];
        assert!(is_allowed_origin(
            "chrome",
            "chrome-extension://abcdefghijklmnop/",
            &chrome,
            &[]
        ));
        assert!(!is_allowed_origin(
            "chrome",
            "chrome-extension://ZZZZ/",
            &chrome,
            &[]
        ));
        assert!(
            !is_allowed_origin("chrome", "chrome-extension://abcdefghijklmnop/", &[], &[]),
            "empty whitelist denies"
        );
    }

    #[test]
    fn stored_chrome_id_without_the_url_form_still_matches() {
        let chrome = vec!["abcdefghijklmnop".to_string()];
        assert!(is_allowed_origin(
            "chrome",
            "chrome-extension://abcdefghijklmnop/",
            &chrome,
            &[]
        ));
    }

    #[test]
    fn firefox_ids_match_the_exact_stored_id_after_trimming() {
        let ff = vec!["  Kokos@Example.ORG ".to_string()];
        assert!(is_allowed_origin("firefox", "Kokos@Example.ORG", &[], &ff));
        assert!(!is_allowed_origin("firefox", "other@example.org", &[], &ff));
    }

    #[test]
    fn an_all_lowercase_id_like_the_stub_extensions_is_unaffected_by_the_case_sensitive_gate() {
        let ff = vec!["kokos-stub@example.org".to_string()];
        assert!(is_allowed_origin(
            "firefox",
            "kokos-stub@example.org",
            &[],
            &ff
        ));
    }

    #[test]
    fn a_browser_cannot_borrow_the_other_browsers_whitelist() {
        let chrome = vec!["abcdefghijklmnop".to_string()];
        assert!(!is_allowed_origin(
            "firefox",
            "abcdefghijklmnop",
            &chrome,
            &[]
        ));
    }

    #[test]
    fn appending_the_whitelisted_id_as_a_path_must_not_impersonate_it() {
        let chrome = vec!["abcdefghijklmnop".to_string()];
        assert!(
            !is_allowed_origin(
                "chrome",
                "chrome-extension://evil/abcdefghijklmnop",
                &chrome,
                &[]
            ),
            "a foreign extension must not borrow an id by path"
        );
    }

    #[test]
    fn a_longer_id_sharing_a_prefix_is_not_a_match() {
        let chrome = vec!["abcdefghijklmnop".to_string()];
        assert!(!is_allowed_origin(
            "chrome",
            "chrome-extension://abcdefghijklmnopEXTRA/",
            &chrome,
            &[]
        ));
    }

    #[test]
    fn a_full_stored_origin_matches_a_bare_incoming_id_case_insensitively() {
        let chrome = vec!["chrome-extension://ABC/popup.html".to_string()];
        assert!(is_allowed_origin(
            "chrome",
            "chrome-extension://abc/",
            &chrome,
            &[]
        ));
    }

    #[test]
    fn a_stored_bare_id_matches_an_incoming_origin_with_query_and_fragment() {
        let chrome = vec!["abc".to_string()];
        assert!(is_allowed_origin(
            "chrome",
            "chrome-extension://abc/popup.html?x=1#y",
            &chrome,
            &[]
        ));
    }

    #[test]
    fn an_empty_or_blank_whitelist_entry_is_never_a_wildcard() {
        for entry in ["", "   "] {
            let chrome = vec![entry.to_string()];
            assert!(!is_allowed_origin(
                "chrome",
                "chrome-extension://abc/",
                &chrome,
                &[]
            ));
        }
    }

    #[test]
    fn an_empty_origin_is_denied_even_against_a_matching_entry() {
        let chrome = vec!["abc".to_string()];
        assert!(!is_allowed_origin("chrome", "", &chrome, &[]));
    }

    #[test]
    fn chrome_whitelist_never_authorises_a_firefox_connection() {
        let chrome = vec!["abcdefghijklmnop".to_string()];
        assert!(!is_allowed_origin(
            "firefox",
            "abcdefghijklmnop",
            &chrome,
            &[]
        ));
    }

    #[test]
    fn browser_selector_is_trimmed_and_case_insensitive() {
        let chrome = vec!["abc".to_string()];
        for b in ["CHROME", " chrome ", "Chrome"] {
            assert!(is_allowed_origin(
                b,
                "chrome-extension://abc/",
                &chrome,
                &[]
            ));
        }
    }

    #[test]
    fn an_unrecognised_browser_selector_denies() {
        let chrome = vec!["abc".to_string()];
        for b in ["safari", ""] {
            assert!(!is_allowed_origin(
                b,
                "chrome-extension://abc/",
                &chrome,
                &[]
            ));
        }
    }

    #[test]
    fn a_case_variant_of_the_stored_firefox_id_is_now_denied() {
        let ff = vec!["Kokos@Example.ORG".to_string()];
        assert!(!is_allowed_origin("firefox", "KOKOS@EXAMPLE.ORG", &[], &ff));
    }

    #[test]
    fn firefox_ids_reject_a_different_address() {
        let ff = vec!["kokos@example.org".to_string()];
        assert!(!is_allowed_origin("firefox", "evil@example.org", &[], &ff));
    }


    /// The exact bypass scenario: a crafted hello origin -- a
    /// mixed-case id with a trailing path -- passes the whitelist (Chrome
    /// comparison lowercases + strips the path) but is byte-different from
    /// its canonical form. `canonical_origin` must return that CANONICAL
    /// form, not the raw input, so a caller storing its return value (rather
    /// than the raw hello string) can never diverge from what the cascade
    /// later purges.
    #[test]
    fn canonical_origin_reduces_a_non_canonical_but_whitelisted_chrome_origin_to_its_canonical_form() {
        let chrome = vec!["abcdefghijklmnop".to_string()];
        assert_eq!(
            canonical_origin(
                "chrome",
                "chrome-extension://ABCDEFGHIJKLMNOP/popup.html",
                &chrome,
                &[]
            ),
            Some("chrome-extension://abcdefghijklmnop/".to_string())
        );
    }

    /// Idempotency: re-running the canonicalisation on an already-canonical
    /// origin must be a no-op -- this is what makes the per-request live
    /// re-checks in `serve`'s loop safe to leave unchanged after `caller.origin`
    /// becomes canonical at the handshake (they call `is_allowed_origin`,
    /// which now delegates through this same function).
    #[test]
    fn canonical_origin_is_idempotent_on_an_already_canonical_origin() {
        let chrome = vec!["abcdefghijklmnop".to_string()];
        assert_eq!(
            canonical_origin(
                "chrome",
                "chrome-extension://abcdefghijklmnop/",
                &chrome,
                &[]
            ),
            Some("chrome-extension://abcdefghijklmnop/".to_string())
        );

        let ff = vec!["kokos@example.org".to_string()];
        assert_eq!(
            canonical_origin("firefox", "kokos@example.org", &[], &ff),
            Some("kokos@example.org".to_string())
        );
    }

    /// Firefox ids are trimmed only, never lowercased --
    /// `canonical_origin` must preserve that, not silently fold case the way
    /// the Chrome arm does.
    #[test]
    fn canonical_origin_trims_a_firefox_id_without_lowercasing_it() {
        let ff = vec!["Kokos@Example.ORG".to_string()];
        assert_eq!(
            canonical_origin("firefox", " Kokos@Example.ORG ", &[], &ff),
            Some("Kokos@Example.ORG".to_string())
        );
    }

    /// Negative control: without this, the positive tests above prove
    /// nothing -- an origin the whitelist does not cover must canonicalise to
    /// `None`, same as `is_allowed_origin` denies it.
    #[test]
    fn canonical_origin_is_none_for_an_origin_the_whitelist_does_not_cover() {
        let chrome = vec!["abcdefghijklmnop".to_string()];
        assert_eq!(
            canonical_origin(
                "chrome",
                "chrome-extension://zzzzzzzzzzzzzzzz/",
                &chrome,
                &[]
            ),
            None
        );
    }

    /// THE regression this guards: the string a grant would be
    /// MINTED under (`canonical_origin`, called from `serve` at handshake
    /// time) must be byte-identical to the string `whitelist_removed_origins`
    /// computes for the same stored id when it is later removed -- the exact
    /// origin `cascade_forget_origins` then calls `delete_by_origin` with.
    /// Before this fix, `serve` kept the RAW hello string as `Caller.origin`,
    /// so a non-canonical (but whitelisted) hello origin minted a grant under
    /// one string while the cascade purged under another -- the grant was
    /// orphaned and kept auto-releasing forever. Driven through the pure
    /// helpers directly, because no `AppHandle`/socket harness exists in
    /// this repo.
    #[test]
    fn canonical_origin_agrees_with_whitelist_removed_origins_so_the_cascade_can_always_find_a_minted_grant() {
        let old = vec!["abcdefghijklmnop".to_string()];
        let new: Vec<String> = vec![];

        let minted = canonical_origin(
            "chrome",
            "chrome-extension://ABCDEFGHIJKLMNOP/popup.html",
            &old,
            &[],
        )
        .expect("a whitelisted origin must canonicalise to Some");

        let cascade = whitelist_removed_origins(&old, &new, "chrome");

        assert_eq!(
            cascade,
            vec![minted],
            "the origin a grant is minted under must equal the one the cascade purges, \
             or a grant minted from a non-canonical hello origin is orphaned"
        );
    }


    #[test]
    fn peer_is_self_only_for_a_matching_euid() {
        assert!(peer_is_self(Some(501), 501));
        assert!(!peer_is_self(Some(0), 501), "a root peer (euid 0) is not us");
        assert!(!peer_is_self(Some(502), 501), "a different user's euid is denied");
        assert!(
            !peer_is_self(None, 501),
            "a failed getpeereid must fail closed, never match"
        );
    }

    #[test]
    fn token_matches_is_fail_closed_on_empty_or_absent() {
        assert!(token_matches("abc123", Some("abc123")), "exact match authenticates");
        assert!(!token_matches("abc123", Some("different")), "a wrong token is denied");
        assert!(
            !token_matches("", Some("abc123")),
            "an empty presented token never matches a real one"
        );
        assert!(
            !token_matches("abc123", None),
            "no current token (listener minted none) never authenticates"
        );
        assert!(!token_matches("", None));
        assert!(
            !token_matches("", Some("")),
            "an empty current token never authenticates either — fail closed both sides"
        );
    }

    /// Exercises the real `getpeereid` syscall wrapper the pure `peer_is_self`
    /// decision sits on top of, using an in-process `UnixStream::pair()` — no
    /// filesystem, no env, both ends owned by this test process — so the peer's
    /// reported euid must be our own.
    #[cfg(unix)]
    #[test]
    fn peer_uid_of_a_socketpair_end_is_our_own_euid() {
        use std::os::unix::io::AsRawFd;
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let me = unsafe { libc::geteuid() } as u32;
        assert_eq!(
            peer_uid(a.as_raw_fd()),
            Some(me),
            "getpeereid on a same-process socket pair reports our own euid"
        );
    }


    #[test]
    fn is_hello_frame_true_for_a_real_hello_false_for_a_normal_request() {
        let hello = HelloFrame {
            hello: kokos_nmh::protocol::Hello {
                browser: "chrome".into(),
                origin: "chrome-extension://abc/".into(),
                host_version: "0.1.0".into(),
                token: "tok".into(),
            },
        };
        let hello_bytes = serde_json::to_vec(&hello).unwrap();
        assert!(is_hello_frame(&hello_bytes));

        let req_bytes = br#"{"id":"1","version":1,"action":"ping"}"#;
        assert!(!is_hello_frame(req_bytes));
    }


    #[test]
    fn is_current_generation_true_when_no_newer_start_has_run() {
        assert!(is_current_generation(1, 1));
    }

    #[test]
    fn is_current_generation_false_for_a_stale_loop_after_a_restart() {
        assert!(!is_current_generation(2, 1));
    }


    #[test]
    fn handshake_denial_detail_includes_the_refused_origin() {
        let detail = handshake_denial_detail("chrome", "chrome-extension://abcdefghijklmnop/");
        assert_eq!(
            detail,
            "handshake@chrome:chrome-extension://abcdefghijklmnop/"
        );
    }

    #[test]
    fn handshake_denial_detail_truncates_a_hostile_origin_on_a_char_boundary() {
        let mut huge_origin = "a".repeat(TOO_LARGE_ID_CAP - 1);
        huge_origin.push('é');
        huge_origin.push_str(&"b".repeat(1000));

        let detail = handshake_denial_detail("chrome", &huge_origin);

        assert!(
            detail.len() <= "handshake@chrome:".len() + TOO_LARGE_ID_CAP,
            "the detail must not grow with the attacker-supplied origin"
        );
        let origin_part = detail.strip_prefix("handshake@chrome:").unwrap();
        assert!(
            huge_origin.starts_with(origin_part),
            "the truncated origin must be a prefix of the real one, not garbled"
        );
    }


    #[test]
    fn encode_response_round_trips_a_small_response_unchanged() {
        let resp = Response::ok("req-1", serde_json::json!({ "locked": false }));
        let bytes = encode_response(&resp);
        let back: Response = serde_json::from_slice(&bytes).unwrap();
        assert!(back.ok);
        assert_eq!(back.id, "req-1");
        assert_eq!(back.payload.unwrap()["locked"], false);
    }

    #[test]
    fn encode_response_substitutes_too_large_over_the_cap_but_keeps_the_id() {
        let big = "x".repeat(kokos_nmh::framing::MAX_FRAME + 10);
        let resp = Response::ok("req-2", serde_json::json!({ "value": big }));
        let bytes = encode_response(&resp);
        assert!(bytes.len() < kokos_nmh::framing::MAX_FRAME);
        let back: Response = serde_json::from_slice(&bytes).unwrap();
        assert!(!back.ok);
        assert_eq!(
            back.id, "req-2",
            "the extension must still be able to correlate the answer"
        );
        assert_eq!(back.error.unwrap().code, codes::TOO_LARGE);
    }

    #[test]
    fn encode_response_truncates_an_oversized_id_in_the_too_large_fallback() {
        let huge_id = "i".repeat(kokos_nmh::framing::MAX_FRAME);
        let big_payload = "x".repeat(kokos_nmh::framing::MAX_FRAME + 10);
        let resp = Response::ok(&huge_id, serde_json::json!({ "value": big_payload }));

        let bytes = encode_response(&resp);

        assert!(
            bytes.len() < kokos_nmh::framing::MAX_FRAME,
            "the fallback itself must stay under the cap even for a huge id"
        );
        let back: Response = serde_json::from_slice(&bytes).unwrap();
        assert!(!back.ok);
        assert_eq!(back.error.unwrap().code, codes::TOO_LARGE);
        assert!(
            back.id.len() <= TOO_LARGE_ID_CAP,
            "the echoed id must be bounded, not verbatim"
        );
        assert!(
            huge_id.starts_with(&back.id),
            "the truncated id must be a prefix of the original so it stays partially correlatable"
        );
    }

    #[test]
    fn encode_response_truncation_never_splits_a_multi_byte_char() {
        let mut huge_id = "a".repeat(TOO_LARGE_ID_CAP - 1);
        huge_id.push('é');
        assert!(
            !huge_id.is_char_boundary(TOO_LARGE_ID_CAP),
            "test setup check: the cap must actually land mid-character"
        );
        let big_payload = "x".repeat(kokos_nmh::framing::MAX_FRAME + 10);
        let resp = Response::ok(&huge_id, serde_json::json!({ "value": big_payload }));

        let bytes = encode_response(&resp);

        assert!(bytes.len() < kokos_nmh::framing::MAX_FRAME);
        let back: Response = serde_json::from_slice(&bytes).unwrap();
        assert!(!back.ok);
        assert!(back.id.len() <= TOO_LARGE_ID_CAP);
        assert!(std::str::from_utf8(back.id.as_bytes()).is_ok());
    }


    #[test]
    fn deny_budget_caps_rows_per_window_and_summarizes_once() {
        let t0 = std::time::Instant::now();
        let mut b = DenyBudget::default();
        for _ in 0..DENY_BUDGET_MAX {
            assert_eq!(b.take(t0), DenyBudgetVerdict::Allow(None));
        }
        assert_eq!(b.take(t0), DenyBudgetVerdict::Suppress);
        assert_eq!(b.take(t0), DenyBudgetVerdict::Suppress);
        let t1 = t0 + DENY_BUDGET_WINDOW;
        assert_eq!(b.take(t1), DenyBudgetVerdict::Allow(Some(2)));
        assert_eq!(b.take(t1), DenyBudgetVerdict::Allow(None));
    }

    #[test]
    fn invalid_origin_key_ignores_the_peer_origin() {
        assert_eq!(invalid_origin_key("chrome"), "invalid_origin@chrome");
    }

    #[test]
    fn should_audit_denial_is_true_the_first_time() {
        assert!(should_audit_denial(
            None,
            "chrome-extension://evil/",
            std::time::Instant::now(),
            DENY_AUDIT_WINDOW
        ));
    }

    #[test]
    fn should_audit_denial_dedupes_the_same_origin_within_the_window() {
        let now = std::time::Instant::now();
        let last = ("chrome-extension://evil/".to_string(), now);
        let later = now.checked_add(std::time::Duration::from_secs(1)).unwrap();
        assert!(!should_audit_denial(
            Some(&last),
            "chrome-extension://evil/",
            later,
            DENY_AUDIT_WINDOW
        ));
    }

    #[test]
    fn should_audit_denial_fires_again_after_the_window() {
        let now = std::time::Instant::now();
        let last = ("chrome-extension://evil/".to_string(), now);
        let later = now.checked_add(std::time::Duration::from_secs(61)).unwrap();
        assert!(should_audit_denial(
            Some(&last),
            "chrome-extension://evil/",
            later,
            DENY_AUDIT_WINDOW
        ));
    }

    #[test]
    fn should_audit_denial_never_masks_a_different_origins_first_refusal() {
        let now = std::time::Instant::now();
        let last = ("chrome-extension://evil/".to_string(), now);
        let later = now.checked_add(std::time::Duration::from_secs(1)).unwrap();
        assert!(should_audit_denial(
            Some(&last),
            "chrome-extension://other/",
            later,
            DENY_AUDIT_WINDOW
        ));
    }


    #[test]
    fn should_audit_denial_dedupes_a_handler_style_key_within_the_window() {
        let now = std::time::Instant::now();
        let last = ("get_secret@bank.com".to_string(), now);
        let later = now.checked_add(std::time::Duration::from_secs(1)).unwrap();
        assert!(!should_audit_denial(
            Some(&last),
            "get_secret@bank.com",
            later,
            DENY_AUDIT_WINDOW
        ));
    }

    #[test]
    fn should_audit_denial_fires_again_for_a_handler_style_key_after_the_window() {
        let now = std::time::Instant::now();
        let last = ("get_secret@bank.com".to_string(), now);
        let later = now.checked_add(std::time::Duration::from_secs(61)).unwrap();
        assert!(should_audit_denial(
            Some(&last),
            "get_secret@bank.com",
            later,
            DENY_AUDIT_WINDOW
        ));
    }

    #[test]
    fn should_audit_denial_never_masks_a_different_handler_style_key() {
        let now = std::time::Instant::now();
        let last = ("get_secret@bank.com".to_string(), now);
        let later = now.checked_add(std::time::Duration::from_secs(1)).unwrap();
        assert!(should_audit_denial(
            Some(&last),
            "get_totp@bank.com",
            later,
            DENY_AUDIT_WINDOW
        ));
        assert!(should_audit_denial(
            Some(&last),
            "get_secret@other.com",
            later,
            DENY_AUDIT_WINDOW
        ));
    }


    #[test]
    fn a_grant_release_key_is_not_suppressed_by_a_denial_recorded_for_the_bare_key() {
        let now = std::time::Instant::now();
        let last_denied = ("get_secret@bank.com".to_string(), now);
        let later = now.checked_add(std::time::Duration::from_millis(1)).unwrap();
        assert!(
            should_audit_denial(
                Some(&last_denied),
                "grant:get_secret@bank.com",
                later,
                GRANT_AUDIT_WINDOW
            ),
            "a grant-release key must not share a slot with a denial recorded under the bare action@domain key"
        );
    }

    #[test]
    fn a_denial_key_is_not_suppressed_by_a_grant_release_recorded_for_the_prefixed_key() {
        let now = std::time::Instant::now();
        let last_granted = ("grant:get_secret@bank.com".to_string(), now);
        let later = now.checked_add(std::time::Duration::from_millis(1)).unwrap();
        assert!(
            should_audit_denial(
                Some(&last_granted),
                "get_secret@bank.com",
                later,
                DENY_AUDIT_WINDOW
            ),
            "a denial key must not share a slot with a grant-release recorded under the grant:-prefixed key"
        );
    }


    #[test]
    fn a_grant_release_between_two_denials_for_the_same_key_does_not_evict_last_denied() {
        let state = NmhState::default();
        let t0 = std::time::Instant::now();
        assert!(state.take_denial_log("x@y", t0));
        let t1 = t0.checked_add(std::time::Duration::from_secs(1)).unwrap();
        assert!(state.take_grant_release_log("x", "y", t1));
        let t2 = t0.checked_add(std::time::Duration::from_secs(2)).unwrap();
        assert!(
            !state.take_denial_log("x@y", t2),
            "a grant-release for the same action@domain must not evict last_denied's own slot"
        );
    }

    #[test]
    fn a_denial_between_two_grant_releases_for_the_same_key_does_not_evict_last_granted() {
        let state = NmhState::default();
        let t0 = std::time::Instant::now();
        assert!(state.take_grant_release_log("x", "y", t0));
        let t1 = t0.checked_add(std::time::Duration::from_secs(1)).unwrap();
        assert!(state.take_denial_log("x@y", t1));
        let t2 = t0.checked_add(std::time::Duration::from_secs(2)).unwrap();
        assert!(
            !state.take_grant_release_log("x", "y", t2),
            "a denial for the same action@domain must not evict last_granted's own slot"
        );
    }


    #[test]
    fn grant_release_key_is_true_the_first_time() {
        assert!(should_audit_denial(
            None,
            "grant:get_secret@bank.com",
            std::time::Instant::now(),
            GRANT_AUDIT_WINDOW
        ));
    }

    #[test]
    fn grant_release_key_dedupes_within_the_window() {
        let now = std::time::Instant::now();
        let last = ("grant:get_secret@bank.com".to_string(), now);
        let later = now.checked_add(std::time::Duration::from_secs(1)).unwrap();
        assert!(!should_audit_denial(
            Some(&last),
            "grant:get_secret@bank.com",
            later,
            GRANT_AUDIT_WINDOW
        ));
    }

    #[test]
    fn grant_release_key_fires_again_after_the_window() {
        let now = std::time::Instant::now();
        let last = ("grant:get_secret@bank.com".to_string(), now);
        let later = now
            .checked_add(GRANT_AUDIT_WINDOW + std::time::Duration::from_secs(1))
            .unwrap();
        assert!(should_audit_denial(
            Some(&last),
            "grant:get_secret@bank.com",
            later,
            GRANT_AUDIT_WINDOW
        ));
    }

    #[test]
    fn a_different_domains_grant_release_always_logs_its_first_occurrence() {
        let now = std::time::Instant::now();
        let last = ("grant:get_secret@bank.com".to_string(), now);
        let later = now.checked_add(std::time::Duration::from_secs(1)).unwrap();
        assert!(should_audit_denial(
            Some(&last),
            "grant:get_secret@other.com",
            later,
            GRANT_AUDIT_WINDOW
        ));
    }


    #[test]
    fn whitelist_removed_origins_chrome_a_removed_id_becomes_its_normalised_origin() {
        let old = vec!["aaaaaaaaaaaaaaaa".to_string(), "bbbbbbbbbbbbbbbb".to_string()];
        let new = vec!["bbbbbbbbbbbbbbbb".to_string()];
        assert_eq!(
            whitelist_removed_origins(&old, &new, "chrome"),
            vec!["chrome-extension://aaaaaaaaaaaaaaaa/".to_string()]
        );
    }

    #[test]
    fn whitelist_removed_origins_chrome_an_added_id_purges_nothing() {
        let old = vec!["aaaaaaaaaaaaaaaa".to_string()];
        let new = vec![
            "aaaaaaaaaaaaaaaa".to_string(),
            "bbbbbbbbbbbbbbbb".to_string(),
        ];
        assert!(whitelist_removed_origins(&old, &new, "chrome").is_empty());
    }

    #[test]
    fn whitelist_removed_origins_chrome_list_cleared_purges_every_old_id() {
        let old = vec!["aaaaaaaaaaaaaaaa".to_string(), "bbbbbbbbbbbbbbbb".to_string()];
        let new: Vec<String> = vec![];
        let mut removed = whitelist_removed_origins(&old, &new, "chrome");
        removed.sort();
        assert_eq!(
            removed,
            vec![
                "chrome-extension://aaaaaaaaaaaaaaaa/".to_string(),
                "chrome-extension://bbbbbbbbbbbbbbbb/".to_string(),
            ]
        );
    }

    #[test]
    fn whitelist_removed_origins_chrome_unchanged_list_is_a_no_op() {
        let old = vec!["aaaaaaaaaaaaaaaa".to_string()];
        let new = old.clone();
        assert!(whitelist_removed_origins(&old, &new, "chrome").is_empty());
    }

    #[test]
    fn whitelist_removed_origins_firefox_a_removed_id_is_taken_bare() {
        let old = vec![
            "kokos@example.org".to_string(),
            "other@example.org".to_string(),
        ];
        let new = vec!["other@example.org".to_string()];
        assert_eq!(
            whitelist_removed_origins(&old, &new, "firefox"),
            vec!["kokos@example.org".to_string()],
            "Firefox ids are taken bare, never wrapped in a chrome-style prefix"
        );
    }

    #[test]
    fn whitelist_removed_origins_firefox_an_added_id_purges_nothing() {
        let old = vec!["kokos@example.org".to_string()];
        let new = vec![
            "kokos@example.org".to_string(),
            "other@example.org".to_string(),
        ];
        assert!(whitelist_removed_origins(&old, &new, "firefox").is_empty());
    }

    #[test]
    fn whitelist_removed_origins_firefox_list_cleared_purges_every_old_id() {
        let old = vec![
            "kokos@example.org".to_string(),
            "other@example.org".to_string(),
        ];
        let new: Vec<String> = vec![];
        let mut removed = whitelist_removed_origins(&old, &new, "firefox");
        removed.sort();
        assert_eq!(
            removed,
            vec![
                "kokos@example.org".to_string(),
                "other@example.org".to_string()
            ]
        );
    }

    #[test]
    fn whitelist_removed_origins_firefox_unchanged_list_is_a_no_op() {
        let old = vec!["kokos@example.org".to_string()];
        let new = old.clone();
        assert!(whitelist_removed_origins(&old, &new, "firefox").is_empty());
    }

    #[test]
    fn whitelist_removed_origins_unrecognised_browser_yields_nothing() {
        let old = vec!["aaaaaaaaaaaaaaaa".to_string()];
        assert!(whitelist_removed_origins(&old, &[], "safari").is_empty());
    }

    #[test]
    fn whitelist_removed_origins_skips_a_chrome_entry_it_cannot_parse() {
        let old = vec!["   ".to_string()];
        assert!(whitelist_removed_origins(&old, &[], "chrome").is_empty());
    }


    /// Layer B's entropy is the one part of the token that must not quietly
    /// weaken, and it is shared by both transports (`mint_token`), so pin its
    /// shape here rather than trusting the two `start` arms to keep agreeing.
    /// 64 lowercase hex characters = two v4 UUIDs' worth of `simple()` output,
    /// ~244 bits from the OS CSPRNG.
    #[cfg(any(unix, windows))]
    #[test]
    fn mint_token_yields_two_uuids_of_hex_and_never_repeats_itself() {
        let a = mint_token();
        let b = mint_token();
        assert_eq!(
            a.len(),
            64,
            "two `Uuid::simple()` renderings, no separators"
        );
        assert!(
            a.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "the host compares the file's bytes verbatim, so the alphabet is part of the contract: {a}"
        );
        assert_ne!(
            a, b,
            "a token that repeats across generations would defeat rotation entirely"
        );
    }

    /// The Windows half of `start`/`stop`/`serve`, exercised over the REAL
    /// transport — bound under the REAL derived pipe name, dialled with the
    /// REAL `transport::connect()` the host binary uses, not a test-only
    /// stand-in.
    ///
    /// What it covers, in the order `serve` and `serve_session` run it:
    /// `PipeListener::bind()`; `accept()`; `peer_is_identifiable` (Layer A on
    /// this platform); the two `CONN_TIMEOUT` setters; `read_frame` of the
    /// hello; `token_matches` (Layer B); `canonical_origin` (the whitelist
    /// gate, whose RETURN VALUE — not a bool — is what a real connection
    /// carries onward); `is_hello_frame` on the next frame; `parse_request`;
    /// and `encode_response` + `write_frame` back. Then the `stop()` half:
    /// `shutdown()` must unpark a thread already inside `accept`, and must
    /// keep every later `accept` refused.
    ///
    /// What it deliberately does NOT cover: `serve_session` itself. Every step
    /// of it that this test skips (`audit_denial`, the settings lock,
    /// `dispatch`) needs a live `tauri::AppHandle`, and `tauri::test::mock_app`
    /// sits behind a feature this crate does not enable — inventing a mock
    /// `AppState` purely to reach it would test the mock. So the gate ORDER
    /// below is a hand-kept mirror of `serve_session`'s, not a call into it:
    /// if that order changes, this changes with it.
    #[cfg(windows)]
    #[test]
    fn a_windows_listener_serves_a_handshake_and_then_stops_on_shutdown() {
        use std::sync::Arc;
        use std::time::Duration;

        let listener = match kokos_nmh::transport::PipeListener::bind() {
            Ok(l) => Arc::new(l),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => return,
            Err(e) => panic!("PipeListener::bind failed for an unexpected reason: {e}"),
        };

        const TOKEN: &str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        const EXT_ID: &str = "abcdefghijklmnop";

        let server = {
            let listener = Arc::clone(&listener);
            std::thread::spawn(move || -> Result<String, String> {
                let mut conn = listener.accept().map_err(|e| format!("accept: {e}"))?;

                if !peer_is_identifiable(&conn) {
                    return Err("the server end could not identify its client".into());
                }
                conn.set_read_timeout(Some(CONN_TIMEOUT))
                    .map_err(|e| format!("read timeout: {e}"))?;
                conn.set_write_timeout(Some(CONN_TIMEOUT))
                    .map_err(|e| format!("write timeout: {e}"))?;

                let bytes = read_frame(&mut conn)
                    .map_err(|e| format!("hello read: {e}"))?
                    .ok_or("EOF where the hello frame should be")?;
                let hello: HelloFrame =
                    serde_json::from_slice(&bytes).map_err(|e| format!("hello parse: {e}"))?;
                if !token_matches(&hello.hello.token, Some(TOKEN)) {
                    return Err("Layer B refused a token it minted itself".into());
                }
                let canonical = canonical_origin(
                    &hello.hello.browser,
                    &hello.hello.origin,
                    &[EXT_ID.to_string()],
                    &[],
                )
                .ok_or("the whitelist gate refused a whitelisted origin")?;

                let req_bytes = read_frame(&mut conn)
                    .map_err(|e| format!("request read: {e}"))?
                    .ok_or("EOF where the request frame should be")?;
                if is_hello_frame(&req_bytes) {
                    return Err("a plain request must not look like a mid-stream hello".into());
                }
                let req =
                    parse_request(&req_bytes).map_err(|r| format!("parse_request: {}", r.id))?;
                let resp = Response::ok(&req.id, serde_json::json!({ "echoed": req.action }));
                write_frame(&mut conn, &encode_response(&resp))
                    .map_err(|e| format!("response write: {e}"))?;

                let _ = read_frame(&mut conn);
                Ok(canonical)
            })
        };

        let mut client = kokos_nmh::transport::connect().expect("dial our own listener");
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("client read timeout");
        client
            .set_write_timeout(Some(Duration::from_secs(10)))
            .expect("client write timeout");

        let hello = HelloFrame {
            hello: kokos_nmh::protocol::Hello {
                browser: "chrome".into(),
                origin: format!("chrome-extension://{EXT_ID}/"),
                host_version: "0.1.0".into(),
                token: TOKEN.into(),
            },
        };
        write_frame(
            &mut client,
            &serde_json::to_vec(&hello).expect("hello encodes"),
        )
        .expect("write hello");
        write_frame(
            &mut client,
            br#"{"id":"req-1","version":1,"action":"ping"}"#,
        )
        .expect("write request");

        let answer = read_frame(&mut client)
            .expect("read the answer")
            .expect("a response frame, not EOF");
        let resp: Response = serde_json::from_slice(&answer).expect("the response parses");
        assert!(
            resp.ok,
            "a whitelisted, correctly-tokened ping must succeed"
        );
        assert_eq!(resp.id, "req-1", "the extension correlates answers by id");
        assert_eq!(resp.payload.expect("payload")["echoed"], "ping");
        drop(client);

        let canonical = server
            .join()
            .expect("the server thread must not panic")
            .expect("every handshake gate must pass for a legitimate peer");
        assert_eq!(
            canonical,
            format!("chrome-extension://{EXT_ID}/"),
            "the canonical origin is what every grant, audit row and cascade keys off"
        );

        let waiter = Arc::clone(&listener);
        let parked = std::thread::spawn(move || waiter.accept().map(|_| ()));
        std::thread::sleep(Duration::from_millis(100));
        listener
            .shutdown()
            .expect("shutdown must reach a parked accept");
        let err = parked
            .join()
            .expect("the parked thread must not panic")
            .expect_err("a shut-down listener must not hand out a connection");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::ConnectionAborted,
            "the accept loop breaks on this Err arm; a different kind would still break it, \
             but this is the one `stop()` actually produces"
        );
        assert!(
            listener.accept().is_err(),
            "shutdown is permanent — a listener that woke once must never go back to serving"
        );
    }


    /// The two spellings are independent sources of truth; a drift is silent
    /// and unfindable at runtime, so pin it at compile/test time.
    #[test]
    fn the_bundle_identifier_and_the_host_name_agree() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../../tauri.conf.json")).unwrap();
        assert_eq!(
            conf["identifier"].as_str().unwrap(),
            kokos_nmh::transport::HOST_NAME,
            "tauri.conf.json identifier and transport::HOST_NAME must match or the socket path splits"
        );
    }
}

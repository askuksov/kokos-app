//! Windows twin of the Unix-domain socket: a named pipe at
//! `\\.\pipe\dev.kuksov.kokos`, spoken by the app (server) and the
//! browser-launched host (client).
//!
//! Why this is hand-rolled on `windows-sys` rather than an `interprocess`-style
//! wrapper: the channel carries vault secrets, so the pieces that make it safe
//! — the DACL on the pipe, `PIPE_REJECT_REMOTE_CLIENTS`, and the client-side
//! impersonation clamp — must be visible in *this* file, auditable line by
//! line, not buried behind a dependency's defaults. That is also why nothing
//! here degrades: every failure path returns an error, never a pipe with
//! weaker protection than intended (fail closed).
//!
//! ## How the Unix guarantees map onto Windows
//!
//! | Unix                              | Here                                        |
//! |-----------------------------------|---------------------------------------------|
//! | socket dir `0700`, socket `0600`  | explicit DACL: one ACE, `GA` to our own SID |
//! | `AF_UNIX` is local by definition  | `PIPE_REJECT_REMOTE_CLIENTS`                |
//! | `SO_RCVTIMEO`/`SO_SNDTIMEO`       | overlapped I/O + `WaitForSingleObject`      |
//! | peer `euid` check (`SO_PEERCRED`) | `GetNamedPipeClientProcessId` (app-side)    |
//!
//! Two things deliberately do NOT have an equivalent, and both are the same
//! gap the Unix side has (see `docs/THREAT-MODEL.md`): a *same-user* attacker
//! can read the `0600` token file on Unix, and on Windows can likewise open
//! this pipe, because the DACL grants our own SID. The DACL raises the bar
//! against *other* users and against the network; it does not pretend to
//! separate us from ourselves.
//!
//! ## Timeouts
//!
//! A named pipe has no `SO_RCVTIMEO`. The only way to bound a read or a write
//! is to issue it overlapped, wait on its event with a deadline, and
//! `CancelIo` when the deadline passes. Every handle this module creates
//! therefore carries `FILE_FLAG_OVERLAPPED`, and every operation allocates its
//! own event + `OVERLAPPED` on the stack. Per-operation events cost one cheap
//! kernel object per call, and buy something worth far more: two threads may
//! use the same `PipeStream` concurrently without sharing I/O state, which is
//! what makes the `Send + Sync` impls below sound.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use windows_sys::core::{PCWSTR, PWSTR};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER,
    ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, WaitNamedPipeW,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcessToken, SetEvent, WaitForMultipleObjects,
    WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::System::IO::{CancelIo, GetOverlappedResult, OVERLAPPED};

use super::HOST_NAME;

/// In/out kernel buffer hint per pipe instance. Not a limit on frame size —
/// the 1 MiB `framing::MAX_FRAME` cap is enforced in `framing`, and anything
/// larger than this buffer simply blocks until the peer drains it. 64 KiB
/// comfortably swallows every realistic request/response in one go.
const PIPE_BUFFER: u32 = 64 * 1024;

/// `connect()` retry budget when every pipe instance is busy. 20 x 250 ms
/// bounds the wait at ~5 s, matching the short `timeout_for` default: a host
/// that cannot get an instance in that window reports "not running" rather
/// than holding the browser's port open indefinitely. Deliberately finite —
/// an unbounded `WaitNamedPipeW`/retry loop is exactly how a wedged app hangs
/// a browser.
const CONNECT_ATTEMPTS: u32 = 20;
const CONNECT_WAIT_MS: u32 = 250;

/// `\\.\pipe\` + the bundle identifier. Derived, never negotiated — same
/// discipline as the Unix socket path: both sides compute it from `HOST_NAME`,
/// so a browser-launched host with no Tauri APIs still finds the running app.
/// `\\.\pipe\` (not `\\<server>\pipe\`) is the local-machine namespace; the
/// server additionally refuses remote clients outright, see `create_instance`.
pub fn pipe_name() -> String {
    format!(r"\\.\pipe\{HOST_NAME}")
}

/// The host's end of the channel. Mirrors the `UnixStream` surface the rest of
/// the crate uses: `Read`, `Write`, and the four timeout accessors.
pub type Conn = PipeStream;


/// A `HANDLE` closed on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a Win32 creator function that returned
        unsafe {
            CloseHandle(self.0);
        }
    }
}

// SAFETY: a Win32 HANDLE is a process-wide kernel-object reference, not a
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

/// An unnamed manual-reset event, closed on drop. One is created per I/O
/// operation (see the module doc); `PipeListener` also keeps one for the
/// lifetime of the listener as its shutdown signal.
struct Event(OwnedHandle);

impl Event {
    fn new() -> io::Result<Event> {
        // SAFETY: all four arguments are the documented "unnamed, default
        let h = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Event(OwnedHandle(h)))
    }

    fn raw(&self) -> HANDLE {
        self.0 .0
    }

    fn set(&self) -> io::Result<()> {
        // SAFETY: `self.0` is a live event handle owned by this struct.
        if unsafe { SetEvent(self.raw()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// A `PSECURITY_DESCRIPTOR` allocated by
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW`, freed on drop. That
/// function documents `LocalFree` as the matching deallocator — not `free`,
/// not `HeapFree`.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: `self.0` is the non-null pointer the converter returned and
        unsafe {
            LocalFree(self.0 as HLOCAL);
        }
    }
}

// SAFETY: the descriptor is an immutable blob after construction — this module
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}


/// NUL-terminated UTF-16, the only string form the `*W` entry points accept.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The raw Win32 code behind an `io::Error`, for the branches that must tell
/// "pending"/"busy"/"peer went away" apart from a genuine failure. `0`
/// (`ERROR_SUCCESS`) for an error that carries no OS code, which no caller
/// treats as one of the interesting cases.
fn code_of(e: &io::Error) -> u32 {
    e.raw_os_error().unwrap_or(0) as u32
}

/// A closed peer. On a byte-mode pipe both codes mean the same thing the
/// `read(2)` return of 0 means on a socket: there will never be more data.
fn is_eof(code: u32) -> bool {
    code == ERROR_BROKEN_PIPE || code == ERROR_PIPE_NOT_CONNECTED
}

/// Encodes a `set_*_timeout` argument as the millisecond value
/// `WaitForSingleObject` takes, `INFINITE` meaning "block forever".
///
/// Semantics copied from `UnixStream` deliberately, down to the error: a zero
/// duration is rejected with `InvalidInput` there (a `timeval` of 0 means "no
/// timeout" to the kernel, so accepting it would silently mean the opposite of
/// what the caller asked), and rejecting it here keeps one contract across both
/// platforms. Sub-millisecond durations round UP to 1 ms rather than down to
/// "return immediately", for the same reason.
fn encode_timeout(d: Option<Duration>) -> io::Result<u32> {
    let Some(d) = d else {
        return Ok(INFINITE);
    };
    if d.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot set a 0 duration timeout",
        ));
    }
    Ok(d.as_millis().clamp(1, (INFINITE - 1) as u128) as u32)
}

fn decode_timeout(ms: u32) -> Option<Duration> {
    if ms == INFINITE {
        None
    } else {
        Some(Duration::from_millis(ms as u64))
    }
}

/// The tail every overlapped operation shares: the call has already been
/// issued and returned `FALSE`, so either it is pending (wait for it, with a
/// deadline) or it failed outright.
///
/// Returns the number of bytes transferred. A *partial* transfer that was cut
/// short by the deadline is reported as success, not as a timeout — that is
/// what `recv`/`send` under `SO_RCVTIMEO` do, and it matters: those bytes have
/// already left the pipe's buffer, so reporting `TimedOut` and discarding the
/// count would lose them silently.
///
/// # Safety
///
/// `handle` must be a live overlapped-mode handle, `ov` must be the exact
/// `OVERLAPPED` passed to the issuing call and must stay alive and pinned
/// until this function returns, and `ov.hEvent` must be `event`. On every exit
/// path this function guarantees the kernel is finished with `ov` (and with
/// the caller's buffer), so the caller may drop both immediately afterwards.
unsafe fn await_overlapped(
    handle: HANDLE,
    ov: &mut OVERLAPPED,
    event: HANDLE,
    timeout_ms: u32,
) -> io::Result<u32> {
    let pending = io::Error::last_os_error();
    if code_of(&pending) != ERROR_IO_PENDING {
        return Err(pending);
    }

    match WaitForSingleObject(event, timeout_ms) {
        WAIT_OBJECT_0 => {
            let mut n: u32 = 0;
            if GetOverlappedResult(handle, ov, &mut n, 0) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n)
        }
        WAIT_TIMEOUT => {
            CancelIo(handle);
            let mut n: u32 = 0;
            GetOverlappedResult(handle, ov, &mut n, 1);
            if n > 0 {
                return Ok(n);
            }
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the named pipe peer did not answer in time",
            ))
        }
        _ => {
            let e = io::Error::last_os_error();
            CancelIo(handle);
            let mut n: u32 = 0;
            GetOverlappedResult(handle, ov, &mut n, 1);
            Err(e)
        }
    }
}


/// Dials the running app. `ErrorKind::NotFound` when the app is not listening,
/// which is the case `main.rs` turns into `app_not_running`.
pub fn connect() -> io::Result<Conn> {
    connect_at(&pipe_name())
}

/// `connect` against an arbitrary pipe name. Private: the real channel's name
/// is derived, not chosen. Exists so the tests can run against unique names
/// instead of fighting each other (and a possibly-running real app) over the
/// one true pipe.
fn connect_at(name: &str) -> io::Result<PipeStream> {
    let wname = wide(name);
    for _ in 0..CONNECT_ATTEMPTS {
        // SAFETY: `wname` is NUL-terminated and outlives the call; the
        let handle = unsafe {
            CreateFileW(
                wname.as_ptr() as PCWSTR,
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return Ok(PipeStream::new(OwnedHandle(handle)));
        }

        let err = io::Error::last_os_error();
        if code_of(&err) != ERROR_PIPE_BUSY {
            return Err(err);
        }

        // SAFETY: `wname` is NUL-terminated and outlives the call.
        unsafe {
            WaitNamedPipeW(wname.as_ptr() as PCWSTR, CONNECT_WAIT_MS);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "every instance of the Kokos native-messaging pipe stayed busy",
    ))
}

/// One end of a connected named pipe: the `UnixStream` stand-in.
///
/// The timeouts are stored as the millisecond value the wait takes, with
/// `INFINITE` standing for `None`, so the hot path does no conversion. They
/// are atomics rather than plain fields because `set_read_timeout` takes
/// `&self` (as `UnixStream`'s does), and `Relaxed` is sufficient: a timeout is
/// advisory metadata, not a value another operation's correctness is ordered
/// against.
pub struct PipeStream {
    handle: OwnedHandle,
    read_timeout_ms: AtomicU32,
    write_timeout_ms: AtomicU32,
}

impl PipeStream {
    fn new(handle: OwnedHandle) -> PipeStream {
        PipeStream {
            handle,
            read_timeout_ms: AtomicU32::new(INFINITE),
            write_timeout_ms: AtomicU32::new(INFINITE),
        }
    }

    /// `None` blocks forever; a zero duration is rejected. Same contract as
    /// `UnixStream::set_read_timeout`.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.read_timeout_ms
            .store(encode_timeout(dur)?, Ordering::Relaxed);
        Ok(())
    }

    /// `None` blocks forever; a zero duration is rejected. Same contract as
    /// `UnixStream::set_write_timeout`.
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.write_timeout_ms
            .store(encode_timeout(dur)?, Ordering::Relaxed);
        Ok(())
    }

    /// Reports what was set, rounded to the millisecond the wait actually
    /// uses. `io::Result` only for signature parity with `UnixStream`, whose
    /// getter has to ask the kernel; this one cannot fail.
    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(decode_timeout(self.read_timeout_ms.load(Ordering::Relaxed)))
    }

    /// See `read_timeout`.
    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(decode_timeout(self.write_timeout_ms.load(Ordering::Relaxed)))
    }

    /// PID of the process on the other end — the Windows counterpart of the
    /// Unix `SO_PEERCRED` check in `nmh::serve`, offered so the app side can
    /// gate a connection on who opened it before reading a single byte.
    ///
    /// Only meaningful on a stream obtained from `PipeListener::accept`: the
    /// *client* end of a pipe has no client to ask about, and the call fails
    /// there. Note the same caveat the Unix check carries — a PID identifies a
    /// process, not a user, and PIDs are reusable, so treat this as evidence
    /// to open a token with, not as an identity by itself.
    pub fn client_process_id(&self) -> io::Result<u32> {
        let mut pid: u32 = 0;
        // SAFETY: live handle owned by `self`; `pid` is a valid out-param.
        if unsafe { GetNamedPipeClientProcessId(self.handle.0, &mut pid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(pid)
    }
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let event = Event::new()?;
        let mut ov = OVERLAPPED {
            hEvent: event.raw(),
            ..Default::default()
        };
        let len = buf.len().min(u32::MAX as usize) as u32;
        let mut n: u32 = 0;

        // SAFETY: `buf` is valid for `len` writable bytes and stays alive for
        let result = unsafe {
            if ReadFile(self.handle.0, buf.as_mut_ptr(), len, &mut n, &mut ov) != 0 {
                Ok(n)
            } else {
                await_overlapped(
                    self.handle.0,
                    &mut ov,
                    event.raw(),
                    self.read_timeout_ms.load(Ordering::Relaxed),
                )
            }
        };

        match result {
            Ok(n) => Ok(n as usize),
            Err(e) if is_eof(code_of(&e)) => Ok(0),
            Err(e) => Err(e),
        }
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let event = Event::new()?;
        let mut ov = OVERLAPPED {
            hEvent: event.raw(),
            ..Default::default()
        };
        let len = buf.len().min(u32::MAX as usize) as u32;
        let mut n: u32 = 0;

        // SAFETY: as in `read`, with `buf` merely readable rather than
        let result = unsafe {
            if WriteFile(self.handle.0, buf.as_ptr(), len, &mut n, &mut ov) != 0 {
                Ok(n)
            } else {
                await_overlapped(
                    self.handle.0,
                    &mut ov,
                    event.raw(),
                    self.write_timeout_ms.load(Ordering::Relaxed),
                )
            }
        };
        result.map(|n| n as usize)
    }

    /// A no-op, exactly as `UnixStream::flush` is: `write` above hands bytes
    /// straight to the kernel, so there is nothing buffered on this side.
    ///
    /// Explicitly NOT `FlushFileBuffers`: on a named pipe that blocks until
    /// the *peer* has drained everything written, which would turn the
    /// unconditional `flush()` at the end of `framing::write_frame` into an
    /// unbounded wait on the other process — the precise failure the timeouts
    /// in this module exist to prevent.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


/// The app's end: a `UnixListener` stand-in.
///
/// A named pipe instance serves exactly one client and cannot be reused, so
/// "the listener" is really a rolling supply of instances. `PipeListener`
/// keeps one idle instance parked at all times and mints its replacement as
/// part of `accept`, so a caller writes the ordinary loop:
///
/// ```ignore
/// let listener = PipeListener::bind()?;
/// loop {
///     match listener.accept() {
///         Ok(stream) => { /* serve it */ }
///         Err(_) => break,
///     }
/// }
/// ```
///
/// Waking a thread parked in `accept`: `shutdown()` is the explicit method,
/// and it is the better one — it makes every present and future `accept`
/// return `ConnectionAborted` immediately, with no bogus connection to filter
/// out. The Unix trick of connecting to your own socket also works verbatim
/// (`transport::connect()` from another thread completes the pending
/// `ConnectNamedPipe`), so an app that wants to keep one shutdown path across
/// platforms can; it just has to keep the Unix side's discipline of dropping
/// the woken connection when the listener is no longer enabled.
pub struct PipeListener {
    /// The idle, not-yet-connected instance the next `accept` will hand to a
    /// client. `None` once the listener is broken or shut down — see `accept`
    /// for why that state is permanent rather than self-healing.
    idle: Mutex<Option<OwnedHandle>>,
    /// Kept for the listener's lifetime because every replacement instance is
    /// created from it.
    security: SecurityDescriptor,
    shutdown: Event,
    name: Vec<u16>,
}

/// Manual rather than derived: every field wraps a raw `HANDLE` or a
/// `PSECURITY_DESCRIPTOR`, none of which implement `Debug` and none of which
/// mean anything printed. The pipe name is the one part worth showing, and
/// some `Debug` impl has to exist because callers (the tests below included)
/// `unwrap()` an `io::Result<PipeListener>`.
impl std::fmt::Debug for PipeListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeListener")
            .field(
                "name",
                &String::from_utf16_lossy(&self.name).trim_end_matches('\0'),
            )
            .finish_non_exhaustive()
    }
}

impl PipeListener {
    /// Creates the pipe and parks its first instance. Fails rather than
    /// weakening anything: if the current user's SID cannot be resolved or the
    /// DACL cannot be built, no pipe is created at all.
    ///
    /// `ErrorKind::AddrInUse` when the name already exists — mirroring
    /// `UnixListener::bind` on an occupied path. See `create_instance` for why
    /// that case must never fall back to joining the existing pipe.
    pub fn bind() -> io::Result<PipeListener> {
        bind_at(&pipe_name())
    }

    /// Blocks until a client connects, then returns its stream. Same contract
    /// as `UnixListener::accept`.
    pub fn accept(&self) -> io::Result<Conn> {
        let mut idle = self.idle.lock().map_err(|_| {
            io::Error::new(
                io::ErrorKind::Other,
                "the native-messaging pipe listener state is poisoned",
            )
        })?;

        let Some(instance) = idle.take() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the native-messaging pipe listener is shut down",
            ));
        };

        self.wait_for_client(instance.0)?;

        let next = create_instance(&self.name, &self.security, false)?;
        *idle = Some(next);
        Ok(PipeStream::new(instance))
    }

    /// Unblocks any thread parked in `accept` and keeps every later `accept`
    /// from parking again. Idempotent (the event is manual-reset), and safe to
    /// call from another thread — which is the point: `stop()` runs on the UI
    /// thread while the accept loop is parked in the kernel.
    pub fn shutdown(&self) -> io::Result<()> {
        self.shutdown.set()
    }

    /// Parks on this instance until a client shows up, the listener is shut
    /// down, or the connect fails.
    fn wait_for_client(&self, handle: HANDLE) -> io::Result<()> {
        let event = Event::new()?;
        let mut ov = OVERLAPPED {
            hEvent: event.raw(),
            ..Default::default()
        };

        // SAFETY: `handle` is the live idle instance owned by the caller;
        unsafe {
            if ConnectNamedPipe(handle, &mut ov) != 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            match code_of(&err) {
                ERROR_PIPE_CONNECTED => return Ok(()),
                ERROR_NO_DATA => return Ok(()),
                ERROR_IO_PENDING => {}
                _ => return Err(err),
            }

            let handles = [event.raw(), self.shutdown.raw()];
            let waited = WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE);
            if waited == WAIT_OBJECT_0 {
                let mut n: u32 = 0;
                if GetOverlappedResult(handle, &ov, &mut n, 0) == 0 {
                    let e = io::Error::last_os_error();
                    if is_eof(code_of(&e)) || code_of(&e) == ERROR_NO_DATA {
                        return Ok(());
                    }
                    return Err(e);
                }
                return Ok(());
            }

            let e = if waited == WAIT_OBJECT_0 + 1 {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "the native-messaging pipe listener was shut down",
                )
            } else {
                io::Error::last_os_error()
            };
            CancelIo(handle);
            let mut n: u32 = 0;
            GetOverlappedResult(handle, &ov, &mut n, 1);
            Err(e)
        }
    }
}

/// `PipeListener::bind` against an arbitrary name. Private for the same reason
/// as `connect_at`.
fn bind_at(name: &str) -> io::Result<PipeListener> {
    let security = user_only_security_descriptor()?;
    let shutdown = Event::new()?;
    let wname = wide(name);
    let first = create_instance(&wname, &security, true)?;
    Ok(PipeListener {
        idle: Mutex::new(Some(first)),
        security,
        shutdown,
        name: wname,
    })
}

/// Creates one instance of the pipe.
///
/// `first` selects `FILE_FLAG_FIRST_PIPE_INSTANCE`, and that flag is the
/// anti-squatting guarantee: without it, `CreateNamedPipeW` on a name that
/// already exists silently joins the *existing* pipe as an extra instance —
/// inheriting whatever DACL its creator chose and ignoring the
/// `lpSecurityAttributes` passed here. An attacker who created the name first
/// would then be handed every subsequent handshake, on a pipe we believe we
/// secured. So `bind_at` always passes `true` and there is deliberately NO
/// fallback: an occupied name is reported as `AddrInUse` and the listener
/// simply does not start.
///
/// The practical consequence, worth knowing before debugging it: a `stop()`
/// followed immediately by a `start()` fails to bind while any instance of the
/// old pipe survives — most commonly a connection that is still being served.
/// That is the correct trade (Unix gets to `unlink` and rebind; we do not),
/// and the caller should treat it as "not torn down yet", not retry-forever.
fn create_instance(
    name: &[u16],
    security: &SecurityDescriptor,
    first: bool,
) -> io::Result<OwnedHandle> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.0,
        bInheritHandle: 0,
    };

    let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }

    let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

    // SAFETY: `name` is NUL-terminated (built by `wide`) and outlives the
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr() as PCWSTR,
            open_mode,
            pipe_mode,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER,
            PIPE_BUFFER,
            0,
            &sa,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let err = io::Error::last_os_error();
        if code_of(&err) == ERROR_ACCESS_DENIED {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "the Kokos native-messaging pipe name is already taken",
            ));
        }
        return Err(err);
    }
    Ok(OwnedHandle(handle))
}

/// Builds the pipe's DACL: one ACE, generic-all to the SID this process runs
/// as, and nothing else.
///
/// This is the whole of the access control, so it is worth being explicit
/// about what the SDDL says. `D:` introduces the DACL; `P` marks it protected,
/// which blocks inherited ACEs from ever widening it; `(A;;GA;;;<sid>)` is a
/// single allow-ACE granting GENERIC_ALL to us. Nothing else appears — not
/// SYSTEM, not Administrators, not Everyone. A missing DACL would be far worse
/// than a restrictive one: a NULL DACL grants *everyone* full access, so
/// "couldn't build it, carry on without" is the one outcome this function must
/// never produce, and every branch below returns an error instead.
fn user_only_security_descriptor() -> io::Result<SecurityDescriptor> {
    let sid = current_user_sid()?;
    let sddl = wide(&format!("D:P(A;;GA;;;{sid})"));
    let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();

    // SAFETY: `sddl` is NUL-terminated and outlives the call; `psd` is a valid
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr() as PCWSTR,
            SDDL_REVISION_1,
            &mut psd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if psd.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "the security descriptor for the native-messaging pipe came back empty",
        ));
    }
    Ok(SecurityDescriptor(psd))
}

/// The current process's user SID in string form (`S-1-5-21-...`), for the
/// SDDL above.
fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle(token);

    let mut needed: u32 = 0;
    // SAFETY: a null buffer with length 0 is the documented sizing form.
    unsafe {
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    let err = io::Error::last_os_error();
    if needed == 0 || code_of(&err) != ERROR_INSUFFICIENT_BUFFER {
        return Err(err);
    }

    let words = needed.div_ceil(8) as usize;
    let mut buf = vec![0u64; words.max(1)];
    let cap = (words.max(1) * 8) as u32;
    // SAFETY: `buf` is `cap` writable, 8-byte-aligned bytes.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buf.as_mut_ptr().cast(),
            cap,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut raw: PWSTR = std::ptr::null_mut();
    // SAFETY: the kernel just filled `buf` with a `TOKEN_USER` (checked
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    // SAFETY: `user.User.Sid` points into `buf` and is a valid SID; `raw` is a
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if raw.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "could not render the current user's SID",
        ));
    }

    // SAFETY: `raw` is a NUL-terminated UTF-16 string allocated by
    let sid = unsafe {
        let mut len = 0usize;
        while *raw.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(raw, len));
        LocalFree(raw as HLOCAL);
        s
    };
    Ok(sid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every test that binds needs its own pipe name: the real one is fixed
    /// and derived, so two parallel tests (or a Kokos build actually running
    /// on this machine) would collide on it.
    fn unique_name(tag: &str) -> String {
        format!(
            r"\\.\pipe\kokos-nmh-test-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        )
    }

    #[test]
    fn pipe_name_is_the_local_namespace_plus_the_host_name() {
        assert_eq!(
            pipe_name(),
            format!(r"\\.\pipe\{HOST_NAME}"),
            "the app and the host must derive the same name without negotiating it"
        );
        assert!(
            pipe_name().starts_with(r"\\.\pipe\"),
            "must stay in the LOCAL namespace, never \\\\<server>\\pipe\\"
        );
    }

    #[test]
    fn a_zero_timeout_is_rejected_exactly_as_unixstream_rejects_it() {
        assert_eq!(
            encode_timeout(None).unwrap(),
            INFINITE,
            "None must mean block forever"
        );
        let e = encode_timeout(Some(Duration::ZERO))
            .expect_err("a 0 duration must not silently mean 'no timeout'");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(encode_timeout(Some(Duration::from_micros(1))).unwrap(), 1);
        assert_eq!(encode_timeout(Some(Duration::from_secs(90))).unwrap(), 90_000);
        assert_eq!(
            decode_timeout(encode_timeout(Some(Duration::from_secs(5))).unwrap()),
            Some(Duration::from_secs(5)),
            "the value main.rs sets from timeout_for() must round-trip exactly"
        );
    }

    /// The whole channel in miniature: bind, connect, and pass a frame each
    /// way over a real kernel pipe.
    #[test]
    fn frames_round_trip_over_a_real_pipe() {
        let name = unique_name("roundtrip");
        let listener = bind_at(&name).expect("bind");
        let server = std::thread::spawn(move || {
            let mut conn = listener.accept().expect("accept");
            let got = crate::framing::read_frame(&mut conn)
                .expect("read")
                .expect("a frame, not EOF");
            crate::framing::write_frame(&mut conn, &got).expect("echo");
            let _ = crate::framing::read_frame(&mut conn);
        });

        let mut client = connect_at(&name).expect("connect");
        client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        crate::framing::write_frame(&mut client, br#"{"id":"a"}"#).expect("write");
        let echoed = crate::framing::read_frame(&mut client)
            .expect("read")
            .expect("a frame, not EOF");
        assert_eq!(echoed, br#"{"id":"a"}"#);
        drop(client);
        server.join().expect("server thread");
    }

    /// A closed peer must surface as EOF (`Ok(None)`), not as a transport
    /// error — `main.rs` distinguishes the two and answers differently.
    #[test]
    fn a_closed_peer_reads_as_clean_eof() {
        let name = unique_name("eof");
        let listener = bind_at(&name).expect("bind");
        let server = std::thread::spawn(move || {
            let conn = listener.accept().expect("accept");
            drop(conn);
        });
        let mut client = connect_at(&name).expect("connect");
        client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        assert!(
            crate::framing::read_frame(&mut client)
                .expect("a closed peer is not an error")
                .is_none(),
            "a closed peer must be Ok(None), the clean-shutdown signal"
        );
        server.join().expect("server thread");
    }

    /// The reason this module uses overlapped I/O at all: a read on a silent
    /// but OPEN peer must come back at the deadline, not hang.
    #[test]
    fn a_read_from_a_silent_peer_times_out_near_the_deadline() {
        let name = unique_name("timeout");
        let listener = bind_at(&name).expect("bind");
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let conn = listener.accept().expect("accept");
            let _ = release_rx.recv();
            drop(conn);
        });

        let mut client = connect_at(&name).expect("connect");
        client
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let started = std::time::Instant::now();
        let mut buf = [0u8; 8];
        let err = client
            .read(&mut buf)
            .expect_err("a silent peer must not block forever");
        let elapsed = started.elapsed();
        assert!(
            err.kind() == io::ErrorKind::TimedOut || err.kind() == io::ErrorKind::WouldBlock,
            "main.rs branches on exactly these two kinds, got {:?}",
            err.kind()
        );
        assert!(
            elapsed >= Duration::from_millis(250),
            "returned after {elapsed:?}, well before the 300 ms deadline"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "took {elapsed:?}; the deadline was not honoured"
        );

        client.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        assert!(client.read(&mut buf).is_err(), "second read times out too");

        let _ = release_tx.send(());
        server.join().expect("server thread");
    }

    /// `set_*_timeout` must actually stick — `main.rs` sets them on every
    /// operation and the app's `serve` relies on them being real.
    #[test]
    fn timeouts_round_trip_through_a_live_stream() {
        let name = unique_name("getters");
        let listener = bind_at(&name).expect("bind");
        let server = std::thread::spawn(move || {
            let conn = listener.accept().expect("accept");
            std::thread::sleep(Duration::from_millis(50));
            drop(conn);
        });
        let client = connect_at(&name).expect("connect");
        assert_eq!(
            client.read_timeout().unwrap(),
            None,
            "a fresh connection blocks forever until told otherwise"
        );
        client.set_read_timeout(Some(Duration::from_secs(90))).unwrap();
        client.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(
            client.read_timeout().unwrap(),
            Some(Duration::from_secs(90))
        );
        assert_eq!(client.write_timeout().unwrap(), Some(Duration::from_secs(5)));
        client.set_read_timeout(None).unwrap();
        assert_eq!(client.read_timeout().unwrap(), None);
        drop(client);
        server.join().expect("server thread");
    }

    /// `stop()` must be able to unpark the accept loop.
    #[test]
    fn shutdown_unblocks_a_parked_accept() {
        let name = unique_name("shutdown");
        let listener = std::sync::Arc::new(bind_at(&name).expect("bind"));
        let waiter = std::sync::Arc::clone(&listener);
        let accepting = std::thread::spawn(move || waiter.accept().map(|_| ()));
        std::thread::sleep(Duration::from_millis(100));
        listener.shutdown().expect("shutdown");
        let err = accepting
            .join()
            .expect("accept thread")
            .expect_err("a shut-down listener must not return a connection");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);

        assert!(listener.accept().is_err(), "shutdown is permanent");
    }

    /// The anti-squatting guarantee: while the name exists, nobody — not even
    /// us — gets to create it again.
    #[test]
    fn binding_an_occupied_name_is_refused_rather_than_joined() {
        let name = unique_name("occupied");
        let _held = bind_at(&name).expect("first bind");
        let err = bind_at(&name).expect_err("a second bind must not silently join the pipe");
        assert_eq!(
            err.kind(),
            io::ErrorKind::AddrInUse,
            "an occupied name must look like UnixListener::bind on an existing path"
        );
    }

    /// The DACL is the whole access-control story, so at minimum prove it is
    /// built from a real SID and never silently skipped.
    #[test]
    fn the_pipe_dacl_names_this_users_sid() {
        let sid = current_user_sid().expect("the current process always has a user SID");
        assert!(
            sid.starts_with("S-1-"),
            "expected a string SID, got {sid:?}"
        );
        let sd = user_only_security_descriptor().expect("the DACL must be buildable");
        assert!(!sd.0.is_null());
    }

    /// The app-side peer check has something to work with.
    #[test]
    fn the_server_end_can_identify_its_client() {
        let name = unique_name("pid");
        let listener = bind_at(&name).expect("bind");
        let (tx, rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let conn = listener.accept().expect("accept");
            let _ = tx.send(conn.client_process_id());
        });
        let client = connect_at(&name).expect("connect");
        let pid = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the server answered")
            .expect("a connected client always has a PID");
        assert_eq!(
            pid,
            std::process::id(),
            "the client here IS this process, so the PIDs must match"
        );
        drop(client);
        server.join().expect("server thread");
    }
}

//! Idle exit. The host normally ends on stdin EOF, which the browser sends
//! when the extension disconnects its port. An extension that never
//! disconnects would otherwise leave one host per port alive for as long as
//! the browser runs, so the host also exits on its own after a stretch with
//! no frame and no request in flight. The extension sees an ordinary port
//! disconnect and reconnects on its next request.

use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

/// Idle time after which the host exits.
pub const IDLE_EXIT: Duration = Duration::from_secs(10 * 60);

/// How often the watchdog looks at the activity state.
pub const IDLE_TICK: Duration = Duration::from_secs(15);

struct State {
    busy: bool,
    last: Instant,
    shutting_down: bool,
}

/// Shared between the request loop and the watchdog thread. One lock covers
/// both request admission and the shutdown decision, so the watchdog can
/// never exit the process while a request is being handled.
pub struct Activity {
    state: Mutex<State>,
}

impl Activity {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                busy: false,
                last: Instant::now(),
                shutting_down: false,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A frame arrived. Returns false once shutdown is committed: the caller
    /// must drop the frame unhandled, so nothing reaches the app half-done.
    /// While busy (a confirm prompt in the app can take minutes) the host is
    /// never idle.
    pub fn begin(&self) -> bool {
        let mut s = self.lock();
        if s.shutting_down {
            return false;
        }
        s.busy = true;
        s.last = Instant::now();
        true
    }

    /// The answer was written: idle time counts from now.
    pub fn end(&self) {
        let mut s = self.lock();
        s.busy = false;
        s.last = Instant::now();
    }

    /// If the host has been idle (nothing in flight) for `limit`, commits to
    /// shutting down and returns true; from then on `begin` refuses.
    pub fn try_commit_shutdown(&self, limit: Duration) -> bool {
        let mut s = self.lock();
        if s.shutting_down {
            return true;
        }
        if s.busy || s.last.elapsed() < limit {
            return false;
        }
        s.shutting_down = true;
        true
    }
}

/// Starts a detached thread that calls `on_idle` once the host has been idle
/// for `limit`, checking every `tick`. The binary passes a process exit.
pub fn spawn_watchdog<F>(activity: Arc<Activity>, limit: Duration, tick: Duration, on_idle: F)
where
    F: FnOnce() + Send + 'static,
{
    thread::spawn(move || loop {
        thread::sleep(tick);
        if activity.try_commit_shutdown(limit) {
            on_idle();
            return;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn fresh_activity_is_not_idle_before_the_limit() {
        let a = Activity::new();
        assert!(!a.try_commit_shutdown(Duration::from_secs(60)));
    }

    #[test]
    fn idle_after_the_limit_with_nothing_in_flight() {
        let a = Activity::new();
        thread::sleep(Duration::from_millis(30));
        assert!(a.try_commit_shutdown(Duration::from_millis(20)));
    }

    #[test]
    fn a_request_in_flight_is_never_idle() {
        let a = Activity::new();
        assert!(a.begin());
        thread::sleep(Duration::from_millis(30));
        assert!(
            !a.try_commit_shutdown(Duration::from_millis(20)),
            "a host waiting on the app (e.g. a confirm prompt) must not exit"
        );
    }

    #[test]
    fn idle_time_restarts_when_a_request_ends() {
        let a = Activity::new();
        thread::sleep(Duration::from_millis(30));
        assert!(a.begin());
        a.end();
        assert!(!a.try_commit_shutdown(Duration::from_millis(20)));
    }

    #[test]
    fn no_request_is_admitted_after_shutdown_is_committed() {
        let a = Activity::new();
        thread::sleep(Duration::from_millis(30));
        assert!(a.try_commit_shutdown(Duration::from_millis(20)));
        assert!(
            !a.begin(),
            "a frame read after the exit decision must be dropped, not handled"
        );
    }

    #[test]
    fn watchdog_fires_once_idle() {
        let a = Activity::new();
        let (tx, rx) = mpsc::channel();
        spawn_watchdog(
            a,
            Duration::from_millis(20),
            Duration::from_millis(5),
            move || {
                let _ = tx.send(());
            },
        );
        assert!(rx.recv_timeout(Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn watchdog_holds_while_busy() {
        let a = Activity::new();
        assert!(a.begin());
        let (tx, rx) = mpsc::channel();
        spawn_watchdog(
            a.clone(),
            Duration::from_millis(20),
            Duration::from_millis(5),
            move || {
                let _ = tx.send(());
            },
        );
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
        a.end();
        assert!(rx.recv_timeout(Duration::from_secs(2)).is_ok());
    }
}

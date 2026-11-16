//! Idle exit. The host normally ends on stdin EOF, which the browser sends
//! when the extension disconnects its port. An extension that never
//! disconnects would otherwise leave one host per port alive for as long as
//! the browser runs, so the host also exits on its own after a stretch with
//! no frame and no request in flight. The extension sees an ordinary port
//! disconnect and reconnects on its next request.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Idle time after which the host exits.
pub const IDLE_EXIT: Duration = Duration::from_secs(10 * 60);

/// How often the watchdog looks at the activity state.
pub const IDLE_TICK: Duration = Duration::from_secs(15);

/// Shared between the request loop and the watchdog thread.
pub struct Activity {
    busy: AtomicBool,
    last: Mutex<Instant>,
}

impl Activity {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            busy: AtomicBool::new(false),
            last: Mutex::new(Instant::now()),
        })
    }

    /// A frame arrived: the host is handling it (a confirm prompt in the app
    /// can keep it here for minutes, which must not count as idle).
    pub fn begin(&self) {
        self.busy.store(true, Ordering::SeqCst);
        self.touch();
    }

    /// The answer was written: idle time counts from now.
    pub fn end(&self) {
        self.touch();
        self.busy.store(false, Ordering::SeqCst);
    }

    fn touch(&self) {
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        *last = Instant::now();
    }

    /// True once the host has been idle (nothing in flight) for `limit`.
    pub fn is_idle_for(&self, limit: Duration) -> bool {
        if self.busy.load(Ordering::SeqCst) {
            return false;
        }
        let last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        last.elapsed() >= limit
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
        if activity.is_idle_for(limit) {
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
        assert!(!a.is_idle_for(Duration::from_secs(60)));
    }

    #[test]
    fn idle_after_the_limit_with_nothing_in_flight() {
        let a = Activity::new();
        thread::sleep(Duration::from_millis(30));
        assert!(a.is_idle_for(Duration::from_millis(20)));
    }

    #[test]
    fn a_request_in_flight_is_never_idle() {
        let a = Activity::new();
        a.begin();
        thread::sleep(Duration::from_millis(30));
        assert!(
            !a.is_idle_for(Duration::from_millis(20)),
            "a host waiting on the app (e.g. a confirm prompt) must not exit"
        );
    }

    #[test]
    fn idle_time_restarts_when_a_request_ends() {
        let a = Activity::new();
        thread::sleep(Duration::from_millis(30));
        a.begin();
        a.end();
        assert!(!a.is_idle_for(Duration::from_millis(20)));
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
        a.begin();
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

//! `request_unlock`: the browser extension asks the app to show its unlock
//! dialog. The master password never crosses the native-messaging channel;
//! the extension only learns whether a vault became readable.
//!
//! At most one dialog exists at a time. A request arriving while one is open
//! joins it and gets the same outcome, so a page cannot stack dialogs. After
//! the human cancels, further requests are refused for `CANCEL_COOLDOWN`, so a
//! site that keeps asking cannot keep pulling the window forward.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// How long a request waits for the human. Shorter than the host's 90 s
/// relay timeout for `request_unlock`, so the app always answers first.
pub const UNLOCK_TIMEOUT: Duration = Duration::from_secs(80);

/// After a cancel, new requests are refused for this long.
pub const CANCEL_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Unlocked,
    Cancelled,
    TimedOut,
}

/// One open dialog, shared by every request waiting on it.
pub struct Slot {
    pub req_id: String,
    outcome: Mutex<Option<Outcome>>,
    cv: Condvar,
    keep_open: AtomicBool,
    was_hidden: AtomicBool,
    restore_taken: AtomicBool,
}

impl Slot {
    fn new(req_id: String, keep_open: bool) -> Self {
        Self {
            req_id,
            outcome: Mutex::new(None),
            cv: Condvar::new(),
            keep_open: AtomicBool::new(keep_open),
            was_hidden: AtomicBool::new(false),
            restore_taken: AtomicBool::new(false),
        }
    }

    /// Records whether the window was hidden (in the tray) when the dialog
    /// was raised, so it can go back there afterwards.
    pub fn set_was_hidden(&self, hidden: bool) {
        self.was_hidden.store(hidden, Ordering::SeqCst);
    }

    /// True for exactly one caller, and only when the window should go back
    /// to the tray: it was hidden before, and no joined request asked to keep
    /// it open after a successful unlock (a save still needs its confirm).
    pub fn take_rehide(&self, outcome: Outcome) -> bool {
        if self.restore_taken.swap(true, Ordering::SeqCst) {
            return false;
        }
        should_rehide(
            self.was_hidden.load(Ordering::SeqCst),
            self.keep_open.load(Ordering::SeqCst),
            outcome,
        )
    }

    /// Whether the dialog is still waiting for an answer.
    pub fn is_open(&self) -> bool {
        self.outcome.lock().map(|g| g.is_none()).unwrap_or(false)
    }

    fn set(&self, outcome: Outcome) -> bool {
        let Ok(mut g) = self.outcome.lock() else {
            return false;
        };
        if g.is_some() {
            return false;
        }
        *g = Some(outcome);
        self.cv.notify_all();
        true
    }
}

/// Pure re-hide rule, see `Slot::take_rehide`.
pub fn should_rehide(was_hidden: bool, keep_open: bool, outcome: Outcome) -> bool {
    was_hidden && !(keep_open && outcome == Outcome::Unlocked)
}

pub enum Join {
    /// A new dialog: the caller raises it.
    New(Arc<Slot>),
    /// A dialog is already open: wait on it.
    Joined(Arc<Slot>),
    /// The human cancelled recently.
    CoolingDown,
}

#[derive(Default)]
struct Inner {
    current: Option<Arc<Slot>>,
    cooldown_until: Option<Instant>,
}

#[derive(Default)]
pub struct UnlockGate {
    inner: Mutex<Inner>,
}

impl UnlockGate {
    pub fn join(&self, keep_open: bool, now: Instant) -> Join {
        let Ok(mut g) = self.inner.lock() else {
            return Join::CoolingDown;
        };
        if let Some(slot) = g.current.as_ref() {
            if keep_open {
                slot.keep_open.store(true, Ordering::SeqCst);
            }
            return Join::Joined(slot.clone());
        }
        if g.cooldown_until.is_some_and(|t| now < t) {
            return Join::CoolingDown;
        }
        let slot = Arc::new(Slot::new(uuid::Uuid::new_v4().to_string(), keep_open));
        g.current = Some(slot.clone());
        Join::New(slot)
    }

    /// Answers the open dialog. An unknown or stale id is a no-op. A cancel
    /// starts the cooldown. Returns whether the id was the open dialog.
    ///
    /// The outcome is recorded before the slot leaves the gate, both under
    /// the gate lock: a waiter that finds no open slot always finds the
    /// outcome, so every joined request gets the same answer. Lock order is
    /// gate, then slot; `wait` never holds the slot lock while taking the
    /// gate lock.
    pub fn resolve(&self, req_id: &str, outcome: Outcome, now: Instant) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        let Some(slot) = g.current.as_ref().filter(|s| s.req_id == req_id).cloned() else {
            return false;
        };
        if outcome == Outcome::Cancelled {
            g.cooldown_until = Some(now + CANCEL_COOLDOWN);
        }
        let recorded = slot.set(outcome);
        g.current = None;
        recorded
    }

    /// Whether some dialog is open right now. A request that finished must
    /// not send the window back to the tray over a newer dialog.
    pub fn has_open(&self) -> bool {
        self.inner
            .lock()
            .map(|g| g.current.is_some())
            .unwrap_or(false)
    }

    /// Cancels whatever dialog is open (the window went to the tray, the
    /// integration was turned off). Returns the id that was cancelled.
    pub fn cancel_current(&self, now: Instant) -> Option<String> {
        let id = self
            .inner
            .lock()
            .ok()
            .and_then(|g| g.current.as_ref().map(|s| s.req_id.clone()))?;
        self.resolve(&id, Outcome::Cancelled, now).then_some(id)
    }

    /// Parks until the dialog is answered or `deadline` passes; the first
    /// waiter to reach the deadline closes the dialog as timed out.
    pub fn wait(&self, slot: &Slot, deadline: Instant) -> Outcome {
        loop {
            {
                let Ok(g) = slot.outcome.lock() else {
                    return Outcome::Cancelled;
                };
                if let Some(o) = *g {
                    return o;
                }
                let now = Instant::now();
                if now < deadline {
                    let Ok((g, _)) = slot.cv.wait_timeout(g, deadline - now) else {
                        return Outcome::Cancelled;
                    };
                    if let Some(o) = *g {
                        return o;
                    }
                    continue;
                }
            }
            // Deadline passed. Another waiter or a late reply may win the
            // race; whatever got recorded first is the outcome.
            self.resolve(&slot.req_id, Outcome::TimedOut, Instant::now());
            return slot
                .outcome
                .lock()
                .ok()
                .and_then(|g| *g)
                .unwrap_or(Outcome::TimedOut);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot_of(j: Join) -> Arc<Slot> {
        match j {
            Join::New(s) | Join::Joined(s) => s,
            Join::CoolingDown => panic!("unexpected cooldown"),
        }
    }

    #[test]
    fn a_second_request_joins_the_open_dialog() {
        let g = UnlockGate::default();
        let now = Instant::now();
        let a = match g.join(false, now) {
            Join::New(s) => s,
            _ => panic!("first request opens a dialog"),
        };
        let b = match g.join(false, now) {
            Join::Joined(s) => s,
            _ => panic!("second request joins"),
        };
        assert_eq!(a.req_id, b.req_id);
    }

    #[test]
    fn a_cancel_refuses_new_requests_until_the_cooldown_ends() {
        let g = UnlockGate::default();
        let now = Instant::now();
        let s = slot_of(g.join(false, now));
        assert!(g.resolve(&s.req_id, Outcome::Cancelled, now));
        assert!(matches!(
            g.join(false, now + Duration::from_secs(1)),
            Join::CoolingDown
        ));
        assert!(matches!(g.join(false, now + CANCEL_COOLDOWN), Join::New(_)));
    }

    #[test]
    fn an_unlock_does_not_start_a_cooldown() {
        let g = UnlockGate::default();
        let now = Instant::now();
        let s = slot_of(g.join(false, now));
        assert!(g.resolve(&s.req_id, Outcome::Unlocked, now));
        assert!(matches!(g.join(false, now), Join::New(_)));
    }

    #[test]
    fn a_stale_id_is_ignored() {
        let g = UnlockGate::default();
        let now = Instant::now();
        let s = slot_of(g.join(false, now));
        assert!(!g.resolve("other", Outcome::Unlocked, now));
        assert!(g.resolve(&s.req_id, Outcome::Unlocked, now));
        assert!(
            !g.resolve(&s.req_id, Outcome::Cancelled, now),
            "answered once only"
        );
    }

    #[test]
    fn wait_returns_the_answer_and_times_out_otherwise() {
        let g = Arc::new(UnlockGate::default());
        let s = slot_of(g.join(false, Instant::now()));
        let (g2, id) = (g.clone(), s.req_id.clone());
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            g2.resolve(&id, Outcome::Unlocked, Instant::now());
        });
        assert_eq!(
            g.wait(&s, Instant::now() + Duration::from_secs(5)),
            Outcome::Unlocked
        );
        t.join().unwrap();

        let s = slot_of(g.join(false, Instant::now()));
        assert_eq!(
            g.wait(&s, Instant::now() + Duration::from_millis(20)),
            Outcome::TimedOut
        );
        assert!(
            matches!(g.join(false, Instant::now()), Join::New(_)),
            "a timeout is not a cancel"
        );
    }

    #[test]
    fn cancel_current_closes_the_open_dialog() {
        let g = UnlockGate::default();
        let now = Instant::now();
        assert_eq!(g.cancel_current(now), None);
        let s = slot_of(g.join(false, now));
        assert_eq!(g.cancel_current(now).as_deref(), Some(s.req_id.as_str()));
        assert_eq!(g.wait(&s, now), Outcome::Cancelled);
    }

    #[test]
    fn the_window_goes_back_to_the_tray_once() {
        let g = UnlockGate::default();
        let s = slot_of(g.join(false, Instant::now()));
        s.set_was_hidden(true);
        assert!(s.take_rehide(Outcome::Unlocked));
        assert!(
            !s.take_rehide(Outcome::Unlocked),
            "only one waiter restores the window"
        );
    }

    #[test]
    fn a_waiter_past_its_deadline_gets_the_outcome_already_recorded() {
        let g = UnlockGate::default();
        let now = Instant::now();
        let s = slot_of(g.join(false, now));
        assert!(s.is_open());
        assert!(g.has_open());
        assert!(g.resolve(&s.req_id, Outcome::Cancelled, now));
        assert!(!s.is_open());
        assert!(!g.has_open());
        assert_eq!(g.wait(&s, now), Outcome::Cancelled, "not TimedOut");
    }

    #[test]
    fn rehide_rule() {
        assert!(
            !should_rehide(false, false, Outcome::Unlocked),
            "a visible window stays"
        );
        assert!(should_rehide(true, false, Outcome::Unlocked));
        assert!(
            !should_rehide(true, true, Outcome::Unlocked),
            "a save still needs its confirm"
        );
        assert!(should_rehide(true, true, Outcome::Cancelled));
        assert!(should_rehide(true, false, Outcome::TimedOut));
    }

    #[test]
    fn a_joined_keep_open_request_keeps_the_window_open() {
        let g = UnlockGate::default();
        let now = Instant::now();
        let s = slot_of(g.join(false, now));
        s.set_was_hidden(true);
        let _ = g.join(true, now);
        assert!(!s.take_rehide(Outcome::Unlocked));
    }
}

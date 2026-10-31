//! Confirmation plumbing for the human-confirmation gate, carrying a
//! "remember this site" bit alongside Allow/Deny. Two pieces of
//! session-scoped, in-memory state live here:
//!
//! - [`Registry`]: pending confirmations a socket thread is waiting on. A
//!   fresh request id is minted by `open()`; the caller (a `serve` thread in
//!   `nmh::mod`) parks on the returned `mpsc::Receiver<ConfirmAnswer>` while
//!   the frontend modal answers by request id through `reply()` (the
//!   `nmh_confirm_reply` command). [`ConfirmAnswer`]'s `remember`
//!   field is never trusted on its own -- see `handlers::should_persist_grant`
//!   -- but it has to reach `confirm()` somehow, and this channel is the only
//!   path from the modal back to the waiting connection thread.
//! - [`Grants`]: live "once per site per session" grants for
//!   `nmh_confirm_mode = "session_domain"`. Keyed on `(vault_id, origin,
//!   domain)`, not the bare eTLD+1 — see the doc comment on `Grants` for why
//!   (the `vault_id` half is the structural cross-vault scoping). The OTHER,
//!   PERSISTENT tier (`nmh_confirm_mode = "remember_site"`) is
//!   `kokos_core::nmh_grants` -- a separate, disk-backed store this module
//!   does not touch; `handlers::confirm` reads and writes it directly.
//!
//! Both are wiped together by `super::invalidate_confirms` on every path
//! that locks, closes, or otherwise revokes the vault or the
//! browser-integration settings. (`kokos_core::nmh_grants` rows are
//! deliberately NOT part of that sweep -- surviving a lock/close is the
//! entire point of `remember_site`; only a later revocation UI removes one.)
//!
//! LOCK ORDERING — hold this invariant everywhere in this file: never
//! acquire the session mutex, the settings mutex, or call
//! anything that audits (`kokos_core::audit::append`, `handlers::audit_event`)
//! while holding `Registry`'s or `Grants`' own mutex. Both mutexes here are
//! leaves. Every critical section below is map manipulation only; a `send()`
//! always happens after the entries have already been taken out of the map.

use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One human answer to an `nmh-confirm-request` prompt. `allowed` is the
/// existing Allow/Deny; `remember` is the modal's "remember this site"
/// checkbox -- meaningful ONLY when the live mode is `"remember_site"`;
/// `handlers::confirm` and `handlers::should_persist_grant` re-check that
/// server-side rather than trusting this bit (the frontend is never the
/// authority). `cancel_all` and a timed-out wait both answer
/// `ConfirmAnswer { allowed: false, remember: false }` -- a denial by
/// construction never remembers anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmAnswer {
    pub allowed: bool,
    pub remember: bool,
}

/// Pending browser-extension confirmations, keyed by a fresh request id
/// minted by [`Registry::open`]. A socket thread parks on the `Receiver`
/// `open()` returns; [`Registry::reply`] (the `nmh_confirm_reply`
/// command) answers it exactly once. [`Registry::forget`] and
/// [`Registry::cancel_all`] are the two other ways an entry can leave the
/// map without ever being genuinely answered by a human.
pub struct Registry {
    pending: Mutex<HashMap<String, mpsc::Sender<ConfirmAnswer>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Registers a new pending confirmation. Returns its fresh request id
    /// and the receiver the socket thread parks on.
    ///
    /// A poisoned mutex here is "can't record the pending entry" — the id
    /// and receiver are still handed back so the caller has something to
    /// wait on (and time out on after 60s), rather than making `open()`
    /// itself fallible. Same fail-closed-without-panicking discipline as
    /// `is_allowed_origin`/`audit_denial` elsewhere in this module.
    pub fn open(&self) -> (String, mpsc::Receiver<ConfirmAnswer>) {
        let id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = mpsc::channel();
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(id.clone(), tx);
        }
        (id, rx)
    }

    /// Answers a pending confirmation exactly once. Returns whether the id
    /// was actually pending (an unknown or already-answered id is a no-op,
    /// never a panic).
    ///
    /// Removes the sender from the map BEFORE sending — this is what makes a
    /// second `reply` for the same id a no-op rather than a double-send: the
    /// entry is gone from the map by the time the first send happens.
    /// `SendError` (the waiter already timed out and dropped its receiver) is
    /// ignored — the id was still genuinely pending, so this still returns
    /// `true`.
    pub fn reply(&self, req_id: &str, answer: ConfirmAnswer) -> bool {
        let sender = match self.pending.lock() {
            Ok(mut pending) => pending.remove(req_id),
            Err(_) => None,
        };
        match sender {
            Some(tx) => {
                let _ = tx.send(answer);
                true
            }
            None => false,
        }
    }

    /// Removes a pending entry without answering it (used by the waiter
    /// itself when its own 60s deadline expires, so a late reply cannot
    /// resurrect it). Returns whether it existed.
    pub fn forget(&self, req_id: &str) -> bool {
        match self.pending.lock() {
            Ok(mut pending) => pending.remove(req_id).is_some(),
            Err(_) => false,
        }
    }

    /// Denies every pending confirmation (lock / close / integration turned
    /// off). Drains the whole map under the lock, then sends outside it —
    /// the lock-ordering rule that the critical section is map manipulation
    /// only.
    pub fn cancel_all(&self) {
        let drained: Vec<mpsc::Sender<ConfirmAnswer>> = match self.pending.lock() {
            Ok(mut pending) => pending.drain().map(|(_, tx)| tx).collect(),
            Err(_) => Vec::new(),
        };
        for tx in drained {
            let _ = tx.send(ConfirmAnswer {
                allowed: false,
                remember: false,
            });
        }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Live "once per site per session" grants (`nmh_confirm_mode =
/// "session_domain"`).
///
/// Keyed on `(vault_id, origin, domain)` — NOT the bare eTLD+1. `Grants`
/// lives on the process-global `AppState`, so two separate leaks are closed
/// by putting the right things in the key:
///
/// - the `origin` half: a bare-domain key would let a grant earned by
///   browser extension A silently authorise extension B on the same site.
///   `origin` is the caller's whitelisted extension origin the handshake
///   already authenticated (`chrome-extension://<id>/` for Chrome, the bare
///   extension id for Firefox), so this keeps the "ask at most once per site
///   per session" property while closing that cross-extension leak.
/// - the `vault_id` half: the store is process-global but a grant
///   is only ever meaningful for the vault whose secrets it authorises a read
///   against. Without the vault dimension a grant approved while vault A was
///   active would authorise the SAME `(origin, domain)` read while a
///   DIFFERENT vault B is active — and the ONLY thing preventing that was
///   remembering to call `super::invalidate_confirms` on every active-vault
///   change. `vault_id` in the key makes that invariant STRUCTURAL: a grant
///   minted against vault A can never match a lookup performed while B is
///   active, no matter what a future active-vault-changing command forgets to
///   do. (`super::invalidate_confirms` still clears the whole store on
///   lock/close/switch/settings-change — defense in depth on top of the key,
///   and still required for the lock/close/settings cases where a grant must
///   not survive at all.) The caller supplies the canonical vault path
///   (`SessionRegistry::active_id`) — the same identity the keychain/TouchID
///   and registry already key vaults by — captured once per `confirm()` and
///   used for both the lookup and the insert; see `handlers::confirm`.
///
/// The key is a real tuple, `HashMap<(String, String, String), Instant>` —
/// never a `format!("{vault_id}|{origin}|{domain}")` concatenation. A
/// concatenated key would let a crafted triple collide with an unrelated one
/// across a separator: e.g. origin `"a"` + domain `"b|c"` produces the same
/// string as origin `"a|b"` + domain `"c"`. A real tuple has no such
/// collision, because Rust compares the fields independently rather than
/// joining them into one string first.
///
/// NORMALISATION CONTRACT:
/// `allow`/`is_granted` do NO normalisation of ANY key field — comparison is
/// raw `String` equality (via the tuple's derived `Eq`/`Hash`), with no
/// case-folding, no trailing-dot stripping, and no eTLD+1 reduction. That is
/// entirely the CALLER's job: `handlers::domain_for` already reduces `domain`
/// through `kokos_core::url_match::etld_plus_one` before any caller reaches
/// `Grants`, `origin` is compared exactly as the handshake authenticated it,
/// and `vault_id` is taken verbatim from `SessionRegistry::active_id` (the
/// canonical path the registry itself stores) so the lookup and insert always
/// present byte-identical vault ids. A future caller that reaches `Grants`
/// directly — bypassing `domain_for` / `active_id` — MUST reproduce the same
/// derivation itself, or e.g. `"Example.com"` and `"example.com."` will be
/// treated as two unrelated sites instead of the one grant a user approved.
pub struct Grants {
    until: Mutex<HashMap<(String, String, String), Instant>>,
}

impl Grants {
    pub fn new() -> Self {
        Self {
            until: Mutex::new(HashMap::new()),
        }
    }

    /// Inserts or overwrites the grant for `(vault_id, origin, domain)`,
    /// expiring at `now + ttl`.
    pub fn allow(&self, vault_id: &str, origin: &str, domain: &str, ttl: Duration, now: Instant) {
        if let Ok(mut until) = self.until.lock() {
            until.insert(
                (vault_id.to_string(), origin.to_string(), domain.to_string()),
                now + ttl,
            );
        }
    }

    /// True only when a deadline exists for `(origin, domain)` and `now` is
    /// STRICTLY before it — a grant is dead exactly at its deadline, not
    /// merely after it. Prunes every expired entry it finds while it holds
    /// the lock, so the map cannot grow unboundedly across a long-lived
    /// session with many distinct sites.
    pub fn is_granted(&self, vault_id: &str, origin: &str, domain: &str, now: Instant) -> bool {
        let mut until = match self.until.lock() {
            Err(_) => return false,
            Ok(g) => g,
        };
        until.retain(|_, deadline| *deadline > now);
        until.contains_key(&(vault_id.to_string(), origin.to_string(), domain.to_string()))
    }

    /// Empties the map (lock / close / integration off / confirm-mode
    /// change).
    pub fn clear(&self) {
        if let Ok(mut until) = self.until.lock() {
            until.clear();
        }
    }
}

impl Default for Grants {
    fn default() -> Self {
        Self::new()
    }
}

/// Pure confirmation-mode decision, covering all four `nmh_confirm_mode`
/// values. `save_login`/`update_login` always confirm in EVERY mode,
/// including `trust_extension` -- a write is never covered by a
/// grant, session or persistent. This is enforced by WHITELISTING the two
/// known reads (`get_secret`/`get_totp`) rather than blacklisting the two
/// known writes: any action this predicate has not been taught about -- a
/// write added later, or a read added later before this function learns of
/// it -- falls through to `true`, fail closed, with nothing here needing an
/// update.
///
/// For a whitelisted read, the mode decides:
/// - `"trust_extension"` -- never confirms; the user opted the whole
///   extension out of prompting.
/// - `"session_domain"` -- confirms unless `session_granted` (a live
///   [`Grants`] entry already covers this `(origin, domain)` for this run
///   of the app).
/// - `"remember_site"` -- confirms unless `persistent_granted` (a
///   `kokos_core::nmh_grants` row already covers this `(origin, domain)`,
///   surviving an app restart).
/// - anything else (`"always"`, an unrecognised string, or the empty
///   string) -- always confirms.
///
/// `session_granted` and `persistent_granted` are deliberately two
/// INDEPENDENT parameters, never merged into one bool: a session grant must
/// NOT satisfy `remember_site`, and a persistent grant must NOT satisfy
/// `session_domain` -- each mode consults only its own tier. An unrecognised
/// mode string — including the empty string — behaves like `"always"`: fail
/// closed to the STRONGEST behaviour, never silently treated as one of the
/// three weaker, grant-consulting modes above.
pub fn needs_confirm(
    action: &str,
    mode: &str,
    session_granted: bool,
    persistent_granted: bool,
) -> bool {
    if !matches!(action, "get_secret" | "get_totp") {
        return true;
    }
    match mode {
        "trust_extension" => false,
        "session_domain" => !session_granted,
        "remember_site" => !persistent_granted,
        _ => true,
    }
}

/// True when a settings change must invalidate every live grant AND cancel
/// every pending prompt (an earlier version kept two predicates,
/// `settings_invalidate_grants` and `settings_cancel_pending`; see below for
/// why keeping them separate was itself a defect). Fires on: the
/// confirmation mode changed, the session length changed, either whitelist
/// changed, or the integration was turned off. Grants are cleared on
/// lock/close/mode change — this is the "mode change" half of that rule,
/// generalised to every setting that changes what a grant OR a pending
/// prompt is allowed to mean:
///
/// - a whitelist edit can swap which extension a stored `(origin, domain)`
///   grant actually refers to, and can also mean a prompt currently on
///   screen was asked on behalf of an extension that is no longer
///   whitelisted at all;
/// - a shorter session length must not be satisfied by a grant minted under
///   the old, longer one;
/// - the mode changing away from `session_domain` must not leave a stale
///   grant reachable if the mode is later switched back;
/// - the integration being turned off tears down the whole listener
///   (`nmh::stop`), so anything still parked on an answer must not linger.
///
/// Why one predicate, not two: the two-predicate split this replaces let a
/// whitelist edit invalidate grants but leave a pending prompt on screen.
/// `origin` is deliberately never in the `nmh-confirm-request` payload, so
/// the human looking at that prompt cannot tell WHICH extension asked — clicking Allow after removing extension X from the
/// whitelist would still hand the secret to X's now-revoked connection (the
/// serve loop's own live re-check only fires on the NEXT request, not on an
/// already-parked one). A prompt must never be allowed to outlive the
/// settings state that justified showing it, for exactly the same reason a
/// grant must never outlive the key.
pub fn settings_invalidate_grants(
    old: &crate::settings::Settings,
    new: &crate::settings::Settings,
) -> bool {
    old.nmh_confirm_mode != new.nmh_confirm_mode
        || old.nmh_session_minutes != new.nmh_session_minutes
        || old.nmh_chrome_ids != new.nmh_chrome_ids
        || old.nmh_firefox_ids != new.nmh_firefox_ids
        || (old.nmh_enabled && !new.nmh_enabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_settings() -> crate::settings::Settings {
        crate::settings::Settings::default()
    }


    #[test]
    fn a_reply_reaches_the_waiter() {
        let reg = Registry::new();
        let (id, rx) = reg.open();
        assert!(reg.reply(
            &id,
            ConfirmAnswer {
                allowed: true,
                remember: false
            }
        ));
        let answer = rx.recv_timeout(Duration::from_millis(200)).unwrap();
        assert!(answer.allowed);
        assert!(!answer.remember);
    }

    /// `remember` rides through `reply()` to the waiter exactly like
    /// `allowed` does -- the channel now carries the
    /// whole [`ConfirmAnswer`], not just a bare Allow/Deny bool.
    #[test]
    fn a_reply_carries_remember_through_to_the_waiter() {
        let reg = Registry::new();
        let (id, rx) = reg.open();
        assert!(reg.reply(
            &id,
            ConfirmAnswer {
                allowed: true,
                remember: true
            }
        ));
        let answer = rx.recv_timeout(Duration::from_millis(200)).unwrap();
        assert!(answer.allowed);
        assert!(answer.remember, "remember must reach the waiter unchanged");
    }

    #[test]
    fn an_unknown_or_repeated_reply_is_ignored() {
        let reg = Registry::new();
        assert!(
            !reg.reply(
                "nope",
                ConfirmAnswer {
                    allowed: true,
                    remember: false
                }
            ),
            "an unknown id is a no-op"
        );

        let (id, rx) = reg.open();
        assert!(
            reg.reply(
                &id,
                ConfirmAnswer {
                    allowed: true,
                    remember: false
                }
            ),
            "the known id's first reply succeeds"
        );
        assert!(
            !reg.reply(
                &id,
                ConfirmAnswer {
                    allowed: false,
                    remember: false
                }
            ),
            "a second reply for the same id is a no-op"
        );
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).unwrap().allowed,
            "only the first reply's value ever reached the waiter"
        );
    }

    #[test]
    fn cancel_all_unblocks_every_waiter_as_a_denial() {
        let reg = Registry::new();
        let (_id, rx) = reg.open();
        reg.cancel_all();
        let answer = rx.recv_timeout(Duration::from_millis(200)).unwrap();
        assert!(!answer.allowed);
        assert!(
            !answer.remember,
            "a cancelled prompt must never carry remember: true"
        );
    }

    #[test]
    fn cancel_all_empties_the_map() {
        let reg = Registry::new();
        let (id, _rx) = reg.open();
        reg.cancel_all();
        assert!(
            !reg.reply(
                &id,
                ConfirmAnswer {
                    allowed: true,
                    remember: false
                }
            ),
            "a reply for an id cancel_all already drained is a no-op"
        );
    }

    #[test]
    fn forget_makes_a_later_reply_a_no_op() {
        let reg = Registry::new();
        assert!(!reg.forget("nope"), "forgetting an unknown id is a no-op");

        let (id, _rx) = reg.open();
        assert!(reg.forget(&id), "positive control: the id was pending");
        assert!(
            !reg.reply(
                &id,
                ConfirmAnswer {
                    allowed: true,
                    remember: false
                }
            ),
            "a reply after forget is a no-op, not a resurrection"
        );
    }

    #[test]
    fn a_dropped_receiver_does_not_panic() {
        let reg = Registry::new();
        let (id, rx) = reg.open();
        drop(rx);
        assert!(
            reg.reply(
                &id,
                ConfirmAnswer {
                    allowed: true,
                    remember: false
                }
            ),
            "the id was pending even though the send necessarily failed"
        );
    }


    #[test]
    fn two_concurrent_waiters_are_independent() {
        let reg = Registry::new();
        let (id1, rx1) = reg.open();
        let (id2, rx2) = reg.open();

        assert!(reg.reply(
            &id2,
            ConfirmAnswer {
                allowed: true,
                remember: false
            }
        ));
        assert!(rx2.recv_timeout(Duration::from_millis(200)).unwrap().allowed);
        assert!(
            rx1.recv_timeout(Duration::from_millis(50)).is_err(),
            "the first waiter must still be unanswered"
        );

        reg.cancel_all();
        assert!(
            !rx1.recv_timeout(Duration::from_millis(200)).unwrap().allowed,
            "cancel_all denies the still-pending first waiter"
        );
        let _ = id1;
    }


    #[test]
    fn grants_expire_and_are_per_domain() {
        let grants = Grants::new();
        let t0 = Instant::now();
        grants.allow(
            "/vault/a.kokos",
            "chrome-extension://aaa/",
            "example.com",
            Duration::from_secs(300),
            t0,
        );
        assert!(grants.is_granted(
            "/vault/a.kokos",
            "chrome-extension://aaa/",
            "example.com",
            t0 + Duration::from_secs(299)
        ));
        assert!(!grants.is_granted(
            "/vault/a.kokos",
            "chrome-extension://aaa/",
            "example.com",
            t0 + Duration::from_secs(301)
        ));
        assert!(
            !grants.is_granted("/vault/a.kokos", "chrome-extension://aaa/", "other.com", t0),
            "a grant for one domain never covers a different one"
        );
    }

    #[test]
    fn exact_expiry_boundary_is_dead() {
        let grants = Grants::new();
        let t0 = Instant::now();
        let ttl = Duration::from_secs(300);
        grants.allow("/vault/a.kokos", "origin", "example.com", ttl, t0);
        assert!(
            grants.is_granted("/vault/a.kokos", "origin", "example.com", t0 + Duration::from_secs(299)),
            "positive control: still within ttl"
        );
        assert!(
            !grants.is_granted("/vault/a.kokos", "origin", "example.com", t0 + ttl),
            "a grant is dead exactly AT its deadline, not only after it"
        );
    }

    #[test]
    fn a_grant_never_leaks_across_extensions() {
        let grants = Grants::new();
        let now = Instant::now();
        grants.allow(
            "/vault/a.kokos",
            "chrome-extension://aaa/",
            "example.com",
            Duration::from_secs(300),
            now,
        );
        assert!(
            grants.is_granted("/vault/a.kokos", "chrome-extension://aaa/", "example.com", now),
            "positive control: the granting extension itself is covered"
        );
        assert!(
            !grants.is_granted("/vault/a.kokos", "chrome-extension://bbb/", "example.com", now),
            "a different extension on the same site must not inherit the grant"
        );
    }

    /// the in-memory session grant is intrinsically scoped to the
    /// vault it was minted against. Before this, `Grants` was keyed only on
    /// `(origin, domain)` and lived on the process-global `AppState`, so a
    /// grant approved while vault A was active would silently authorise the
    /// SAME `(origin, domain)` read while a DIFFERENT vault B was active --
    /// the invariant was upheld only by remembering to call
    /// `invalidate_confirms` on every active-vault change, not by structure.
    /// With `vault_id` in the key that leak is impossible regardless of any
    /// future command forgetting to invalidate.
    #[test]
    fn a_grant_is_scoped_to_the_vault_it_was_minted_against() {
        let grants = Grants::new();
        let now = Instant::now();
        grants.allow(
            "/vault/a.kokos",
            "chrome-extension://aaa/",
            "example.com",
            Duration::from_secs(300),
            now,
        );
        assert!(
            grants.is_granted("/vault/a.kokos", "chrome-extension://aaa/", "example.com", now),
            "positive control: the vault the grant was minted against is covered"
        );
        assert!(
            !grants.is_granted("/vault/b.kokos", "chrome-extension://aaa/", "example.com", now),
            "a grant minted while vault A was active must NEVER authorise a read while vault B is active"
        );
    }

    #[test]
    fn clear_drops_all_grants() {
        let grants = Grants::new();
        let now = Instant::now();
        grants.allow("/vault/a.kokos", "origin", "example.com", Duration::from_secs(300), now);
        assert!(
            grants.is_granted("/vault/a.kokos", "origin", "example.com", now),
            "positive control before clear"
        );
        grants.clear();
        assert!(!grants.is_granted("/vault/a.kokos", "origin", "example.com", now));
    }


    const ALL_MODES: [&str; 4] = [
        "always",
        "session_domain",
        "remember_site",
        "trust_extension",
    ];

    #[test]
    fn writes_always_confirm_in_every_mode_regardless_of_either_grant() {
        for mode in ALL_MODES {
            for session_granted in [false, true] {
                for persistent_granted in [false, true] {
                    assert!(
                        needs_confirm("save_login", mode, session_granted, persistent_granted),
                        "save_login must confirm in mode {mode} (session={session_granted}, persistent={persistent_granted})"
                    );
                    assert!(
                        needs_confirm("update_login", mode, session_granted, persistent_granted),
                        "update_login must confirm in mode {mode} (session={session_granted}, persistent={persistent_granted})"
                    );
                }
            }
        }
    }

    #[test]
    fn trust_extension_never_confirms_a_read_regardless_of_either_grant() {
        for action in ["get_secret", "get_totp"] {
            for session_granted in [false, true] {
                for persistent_granted in [false, true] {
                    assert!(
                        !needs_confirm(action, "trust_extension", session_granted, persistent_granted),
                        "{action} must never confirm in trust_extension mode (session={session_granted}, persistent={persistent_granted})"
                    );
                }
            }
        }
    }

    #[test]
    fn always_mode_always_confirms_a_read_regardless_of_either_grant() {
        for action in ["get_secret", "get_totp"] {
            for session_granted in [false, true] {
                for persistent_granted in [false, true] {
                    assert!(
                        needs_confirm(action, "always", session_granted, persistent_granted),
                        "{action} must always confirm in always mode (session={session_granted}, persistent={persistent_granted})"
                    );
                }
            }
        }
    }

    #[test]
    fn session_domain_consults_only_the_session_grant() {
        for action in ["get_secret", "get_totp"] {
            assert!(!needs_confirm(action, "session_domain", true, false));
            assert!(!needs_confirm(action, "session_domain", true, true));
            assert!(
                needs_confirm(action, "session_domain", false, true),
                "{action}: a persistent grant alone must not satisfy session_domain"
            );
            assert!(needs_confirm(action, "session_domain", false, false));
        }
    }

    #[test]
    fn remember_site_consults_only_the_persistent_grant() {
        for action in ["get_secret", "get_totp"] {
            assert!(!needs_confirm(action, "remember_site", false, true));
            assert!(!needs_confirm(action, "remember_site", true, true));
            assert!(
                needs_confirm(action, "remember_site", true, false),
                "{action}: a session grant alone must not satisfy remember_site"
            );
            assert!(needs_confirm(action, "remember_site", false, false));
        }
    }

    #[test]
    fn an_unknown_action_confirms_in_every_mode_even_when_both_grants_are_live() {
        for action in ["get_logins", "future_read", "generate_password"] {
            for mode in ALL_MODES {
                assert!(
                    needs_confirm(action, mode, true, true),
                    "unknown action {action} must confirm in mode {mode}"
                );
            }
        }
    }

    #[test]
    fn needs_confirm_treats_an_unknown_or_empty_mode_as_always() {
        assert!(needs_confirm("get_secret", "bogus_mode", true, true));
        assert!(needs_confirm("get_secret", "", true, true));
    }


    #[test]
    fn a_mode_change_invalidates_grants_and_pending() {
        let old = base_settings();
        let mut new = base_settings();
        new.nmh_confirm_mode = "session_domain".to_string();
        assert!(settings_invalidate_grants(&old, &new));
    }

    #[test]
    fn a_session_minutes_change_invalidates_grants_and_pending() {
        let old = base_settings();
        let mut new = base_settings();
        new.nmh_session_minutes = old.nmh_session_minutes + 1;
        assert!(settings_invalidate_grants(&old, &new));
    }

    #[test]
    fn a_whitelist_change_invalidates_grants_and_pending() {
        let old = base_settings();

        let mut new_chrome = base_settings();
        new_chrome.nmh_chrome_ids = vec!["abcdefghijklmnop".to_string()];
        assert!(settings_invalidate_grants(&old, &new_chrome));

        let mut new_firefox = base_settings();
        new_firefox.nmh_firefox_ids = vec!["kokos@example.org".to_string()];
        assert!(settings_invalidate_grants(&old, &new_firefox));
    }

    #[test]
    fn turning_integration_off_invalidates_grants_and_pending() {
        let mut old = base_settings();
        old.nmh_enabled = true;
        let mut new = old.clone();
        new.nmh_enabled = false;
        assert!(settings_invalidate_grants(&old, &new));
    }

    #[test]
    fn turning_integration_on_does_not_invalidate_anything() {
        let mut old = base_settings();
        old.nmh_enabled = false;
        let mut new = old.clone();
        new.nmh_enabled = true;
        assert!(!settings_invalidate_grants(&old, &new));
    }

    #[test]
    fn an_unrelated_change_invalidates_nothing() {
        let old = base_settings();
        let mut new = base_settings();
        new.auto_lock_minutes = old.auto_lock_minutes + 1;
        assert!(!settings_invalidate_grants(&old, &new));
    }
}

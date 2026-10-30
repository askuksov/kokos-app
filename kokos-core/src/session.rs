//! Session state: the derived key and the decrypted database live here and
//! are wiped on lock/close.
//!
//! Long-running commands (`change_master_password`, `save_vault`) do their
//! heavy work in `spawn_blocking`, which needs an owned `OpenVault` — neither
//! a `std::sync::MutexGuard` nor a live `&mut OpenVault` can cross an
//! `.await`. So the vault has to leave `Session::vault` for the duration of
//! the call. While it is out, the session must not simply look empty: a sync
//! command like `lock_vault`/`close_vault`, dispatched straight from the UI
//! thread, can land in exactly that window. Without tracking it, that
//! command finds `vault == None`, no-ops, and the borrowing command then
//! puts the (still live, unwiped) key right back when it finishes — the UI
//! believes the vault is locked or closed while the backend still holds the
//! key. `begin_borrow`/`end_borrow` close that window: a lock/close
//! requested while the vault is on loan is recorded instead of dropped, and
//! `end_borrow` honors it — dropping the returned vault instead of
//! restoring it — rather than leaving `lock`/`close` to no-op against an
//! empty `Option`.

use std::path::PathBuf;

use crate::crypto::KEY_LEN;
use crate::format::header::Header;
use crate::vault::OpenVault;

/// What `end_borrow` should do with the vault it gets back, if a lock or
/// close was requested while it was on loan. `Close` always wins over
/// `Lock` regardless of request order: it is the strictly more final of the
/// two (it also forgets `last_path`, so there is nothing left to unlock).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseKind {
    Lock,
    Close,
}

pub struct Session {
    pub vault: Option<OpenVault>,
    /// Kept while locked so the UI can offer to unlock the same file.
    pub last_path: Option<PathBuf>,
    pub last_header: Option<Header>,
    /// True between `begin_borrow` and `end_borrow`: the vault is out on
    /// loan to a `spawn_blocking` call, not actually absent.
    borrowed: bool,
    /// Set by `lock`/`close` when called while `borrowed` is true; consumed
    /// and applied by `end_borrow`.
    close_requested: Option<CloseKind>,
    /// The path/header of the vault currently on loan (Some only while
    /// `borrowed`), so `vault_status` can report `open` during the window.
    borrowed_path: Option<PathBuf>,
    borrowed_header: Option<Header>,
}

impl Session {
    pub fn new() -> Self {
        Self {
            vault: None,
            last_path: None,
            last_header: None,
            borrowed: false,
            close_requested: None,
            borrowed_path: None,
            borrowed_header: None,
        }
    }

    /// True once a vault is open, or is temporarily on loan to a
    /// `spawn_blocking` call. `create_vault`/`open_vault`/`unlock_vault` must
    /// refuse (`VaultError::AlreadyOpen`) in both cases rather than silently
    /// discard whatever is there.
    pub fn is_open_or_borrowed(&self) -> bool {
        self.vault.is_some() || self.borrowed
    }

    /// `vault == None` alone is not the full story while `borrowed`: the key
    /// is still live, just outside the session for a moment — unless a lock
    /// was requested, in which case it is *committed* to being wiped even
    /// though `end_borrow` hasn't run yet, so this must already report true.
    pub fn is_locked(&self) -> bool {
        if self.borrowed {
            self.close_requested == Some(CloseKind::Lock)
        } else {
            self.vault.is_none() && self.last_path.is_some()
        }
    }

    /// Drops the key and the in-memory database; the path stays for unlock.
    /// If the vault is currently on loan to a `spawn_blocking` call, records
    /// the request instead of no-oping: `end_borrow` applies it once the
    /// vault comes back, instead of letting that call resurrect it.
    pub fn lock(&mut self) {
        if self.borrowed {
            self.close_requested.get_or_insert(CloseKind::Lock);
            return;
        }
        if let Some(v) = self.vault.take() {
            self.last_path = Some(v.path.clone());
            self.last_header = Some(v.header.clone());
            drop(v);
        }
    }

    /// Drops the key, the in-memory database, and the remembered path/header.
    /// Deferred the same way as `lock` when the vault is on loan; always
    /// wins over a pending lock request (see `CloseKind`).
    pub fn close(&mut self) {
        if self.borrowed {
            self.close_requested = Some(CloseKind::Close);
            return;
        }
        self.vault = None;
        self.last_path = None;
        self.last_header = None;
    }

    /// Takes the vault out for a `spawn_blocking` call and marks the session
    /// borrowed. Returns `None` if there is nothing to lend — no vault is
    /// open, or it is already on loan to another in-flight command — which
    /// callers should treat the same as "no vault is open".
    pub fn begin_borrow(&mut self) -> Option<OpenVault> {
        let v = self.vault.take()?;
        self.borrowed = true;
        self.borrowed_path = Some(v.path.clone());
        self.borrowed_header = Some(v.header.clone());
        Some(v)
    }

    /// Returns a vault obtained from `begin_borrow` once its `spawn_blocking`
    /// call is done. If a lock or close was requested in the meantime, that
    /// wins: `v` is dropped here — wiping its key — instead of being
    /// restored, and the deferred lock/close is applied now, reading `v`'s
    /// own path/header since the session's fields couldn't hold them while
    /// the vault was out. Otherwise `v` is put back and the session ends up
    /// exactly as if it had never left.
    pub fn end_borrow(&mut self, v: OpenVault) {
        self.borrowed = false;
        self.borrowed_path = None;
        self.borrowed_header = None;
        match self.close_requested.take() {
            Some(CloseKind::Lock) => {
                self.last_path = Some(v.path.clone());
                self.last_header = Some(v.header.clone());
                drop(v);
            }
            Some(CloseKind::Close) => {
                self.vault = None;
                self.last_path = None;
                self.last_header = None;
                drop(v);
            }
            None => self.vault = Some(v),
        }
    }

    /// The path/header of the vault currently on loan, if any. `Some` only
    /// while `borrowed` is true and both were stashed by `begin_borrow` —
    /// lets `vault_status` report `open` during a `spawn_blocking` mutation
    /// instead of seeing an empty `Session::vault` and routing to Welcome.
    pub fn borrow_identity(&self) -> Option<(&PathBuf, &Header)> {
        match (self.borrowed, &self.borrowed_path, &self.borrowed_header) {
            (true, Some(p), Some(h)) => Some((p, h)),
            _ => None,
        }
    }

    pub fn key_len_sanity(&self) -> usize {
        KEY_LEN
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2Params;

    const FAST: Argon2Params = Argon2Params { memory_kib: 19_456, time_cost: 2, parallelism: 1 };

    /// A real `OpenVault`, not a mock: `Session` only ever holds the real
    /// type. `vault::create` is cheap at `FAST` params, so building one per
    /// test is fine. The returned `TempDir` must outlive the `OpenVault` —
    /// callers must bind it (e.g. `let _dir = ...`), not drop it immediately.
    fn open_test_vault() -> (tempfile::TempDir, OpenVault) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let v = crate::vault::create(&path, b"password", "hint", FAST, None).unwrap();
        (dir, v)
    }

    #[test]
    fn begin_borrow_then_end_borrow_restores_normally() {
        let (_dir, v) = open_test_vault();
        let mut s = Session::new();
        s.vault = Some(v);

        let v = s.begin_borrow().expect("a vault was open, so there should be one to borrow");
        assert!(s.vault.is_none(), "the vault must actually leave the session while borrowed");
        assert!(!s.is_locked(), "a plain borrow with nothing requested is not a lock");

        s.end_borrow(v);

        assert!(s.vault.is_some(), "end_borrow must restore the vault when nothing was requested");
        assert!(!s.is_locked());
        assert!(s.last_path.is_none());
    }

    #[test]
    fn lock_while_borrowed_defers_and_end_borrow_does_not_restore() {
        let (_dir, v) = open_test_vault();
        let mut s = Session::new();
        s.vault = Some(v);

        let v = s.begin_borrow().unwrap();
        s.lock();
        assert!(s.vault.is_none());
        assert!(
            s.is_locked(),
            "is_locked() must report true as soon as the lock is requested, not only after end_borrow runs"
        );

        s.end_borrow(v);

        assert!(s.vault.is_none(), "end_borrow must NOT resurrect a vault that was locked while on loan");
        assert!(s.is_locked());
        assert!(s.last_path.is_some(), "last_path must be set so the UI can offer to unlock the same file");
    }

    #[test]
    fn close_while_borrowed_defers_and_end_borrow_clears_everything() {
        let (_dir, v) = open_test_vault();
        let mut s = Session::new();
        s.vault = Some(v);

        let v = s.begin_borrow().unwrap();
        s.close();
        assert!(s.vault.is_none());

        s.end_borrow(v);

        assert!(s.vault.is_none(), "nothing must be restored after a deferred close");
        assert!(s.last_path.is_none(), "close forgets the path too — there is nothing left to unlock");
        assert!(s.last_header.is_none());
        assert!(!s.is_locked(), "a closed session is not \"locked\": there is nothing to unlock");
    }

    #[test]
    fn lock_while_not_borrowed_behaves_as_before() {
        let (_dir, v) = open_test_vault();
        let mut s = Session::new();
        s.vault = Some(v);

        s.lock();

        assert!(s.vault.is_none());
        assert!(s.is_locked());
        assert!(s.last_path.is_some());
    }

    #[test]
    fn borrow_identity_visible_during_borrow_and_cleared_after() {
        let (_dir, v) = open_test_vault();
        let path = v.path.clone();
        let mut s = Session::new();
        s.vault = Some(v);

        assert!(s.borrow_identity().is_none(), "not borrowed yet -> no identity");
        let v = s.begin_borrow().unwrap();
        let (p, h) = s.borrow_identity().expect("identity must be visible during the borrow");
        assert_eq!(p, &path, "borrowed path is the vault's path");
        assert_eq!(h, &v.header, "borrowed header is the vault's header");
        s.end_borrow(v);
        assert!(s.borrow_identity().is_none(), "identity cleared after end_borrow");
    }
}

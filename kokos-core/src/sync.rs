//! Provider-agnostic sync core. Whole-file vault sync with LWW-only
//! conflict resolution. This module holds NO network/OS code — only the
//! ordering logic (`resolve_lww`) and the `SyncRemote` transport trait that
//! the Tauri shell implements per provider (folder / Google Drive).
//!
//! Ordering triple `SyncMeta{rev,modified,device}`: `rev` is the monotonic
//! per-device `sync_revision` (bumped every `vault::save`); ties break by
//! `modified` (newer wins) then `device` (lexicographic, deterministic).
//! LWW is deliberately lossy on true concurrent divergence (the
//! simplest model; the loser is preserved as a fresh `.bak` before overwrite).

use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncMeta {
    pub rev: u64,
    pub modified: i64,
    pub device: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncDecision {
    InSync,
    PushLocal,
    PullRemote,
}

/// Decide push/pull/in-sync from the two ordering triples. `remote == None`
/// means the remote has no copy yet → push. See module docs for tie-breaks.
pub fn resolve_lww(local: &SyncMeta, remote: Option<&SyncMeta>) -> SyncDecision {
    let remote = match remote {
        None => return SyncDecision::PushLocal,
        Some(r) => r,
    };
    use std::cmp::Ordering::*;
    match remote.rev.cmp(&local.rev) {
        Greater => SyncDecision::PullRemote,
        Less => SyncDecision::PushLocal,
        Equal => match remote.modified.cmp(&local.modified) {
            Greater => SyncDecision::PullRemote,
            Less => SyncDecision::PushLocal,
            Equal => match remote.device.cmp(&local.device) {
                Greater => SyncDecision::PullRemote,
                Less => SyncDecision::PushLocal,
                Equal => SyncDecision::InSync,
            },
        },
    }
}

/// Transport a provider must implement. Bytes are the encrypted vault
/// container (ciphertext) — the trait never sees plaintext.
pub trait SyncRemote {
    /// Cheap metadata probe (Drive appProperties / folder file stat). `None`
    /// = remote has no copy yet.
    fn remote_meta(&self) -> Result<Option<SyncMeta>>;
    /// Download the remote ciphertext blob.
    fn pull(&self) -> Result<Vec<u8>>;
    /// Upload the ciphertext blob + stamp `meta`.
    fn push(&self, bytes: &[u8], meta: &SyncMeta) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(rev: u64, modified: i64, device: &str) -> SyncMeta {
        SyncMeta { rev, modified, device: device.into() }
    }

    #[test]
    fn no_remote_pushes_local() {
        assert!(matches!(resolve_lww(&m(0, 10, "A"), None), SyncDecision::PushLocal));
    }
    #[test]
    fn higher_remote_rev_pulls() {
        assert!(matches!(resolve_lww(&m(3, 10, "A"), Some(&m(4, 5, "B"))), SyncDecision::PullRemote));
    }
    #[test]
    fn higher_local_rev_pushes() {
        assert!(matches!(resolve_lww(&m(5, 1, "A"), Some(&m(4, 99, "B"))), SyncDecision::PushLocal));
    }
    #[test]
    fn equal_rev_newer_modified_wins() {
        assert!(matches!(resolve_lww(&m(6, 10, "A"), Some(&m(6, 20, "B"))), SyncDecision::PullRemote));
        assert!(matches!(resolve_lww(&m(6, 30, "A"), Some(&m(6, 20, "B"))), SyncDecision::PushLocal));
    }
    #[test]
    fn equal_rev_and_modified_breaks_by_device_deterministically() {
        assert!(matches!(resolve_lww(&m(6, 10, "A"), Some(&m(6, 10, "B"))), SyncDecision::PullRemote));
        assert!(matches!(resolve_lww(&m(6, 10, "B"), Some(&m(6, 10, "A"))), SyncDecision::PushLocal));
    }
    #[test]
    fn identical_meta_is_in_sync() {
        assert!(matches!(resolve_lww(&m(6, 10, "A"), Some(&m(6, 10, "A"))), SyncDecision::InSync));
    }

    struct FakeRemote { meta: Option<SyncMeta>, blob: Vec<u8> }
    impl SyncRemote for FakeRemote {
        fn remote_meta(&self) -> Result<Option<SyncMeta>> { Ok(self.meta.clone()) }
        fn pull(&self) -> Result<Vec<u8>> { Ok(self.blob.clone()) }
        fn push(&self, _bytes: &[u8], _meta: &SyncMeta) -> Result<()> { Ok(()) }
    }
    #[test]
    fn trait_is_usable_via_dyn() {
        let r: Box<dyn SyncRemote> = Box::new(FakeRemote { meta: Some(m(2, 5, "X")), blob: vec![1, 2, 3] });
        assert_eq!(r.remote_meta().unwrap().unwrap().rev, 2);
        assert_eq!(r.pull().unwrap(), vec![1, 2, 3]);
        assert!(r.push(&[0u8], &m(3, 6, "X")).is_ok());
    }
}

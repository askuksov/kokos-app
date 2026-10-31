//! N concurrently-open vault sessions, keyed by canonical path (the same key
//! the keychain uses). One entry is `active`; commands with no explicit
//! `vault_id` operate on it. Dep-free `Vec` backing: N is a handful, so linear
//! scans are cheaper than pulling in a map crate and churning the MSRV policy.
use kokos_core::session::Session;

pub type VaultId = String;

struct Entry {
    id: VaultId,
    session: Session,
}

pub struct SessionRegistry {
    entries: Vec<Entry>,
    active: Option<VaultId>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self { entries: Vec::new(), active: None }
    }

    fn pos(&self, id: &str) -> Option<usize> {
        self.entries.iter().position(|e| e.id == id)
    }

    pub fn contains(&self, id: &str) -> bool {
        self.pos(id).is_some()
    }

    /// Add or replace by id; a genuinely new id is appended (tab order) and
    /// becomes active. Re-inserting an existing id swaps its session in place
    /// and does NOT change order or active.
    pub fn insert(&mut self, id: VaultId, session: Session) {
        match self.pos(&id) {
            Some(i) => self.entries[i].session = session,
            None => {
                self.active = Some(id.clone());
                self.entries.push(Entry { id, session });
            }
        }
    }

    pub fn get(&self, id: &str) -> Option<&Session> {
        self.pos(id).map(|i| &self.entries[i].session)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Session> {
        self.pos(id).map(|i| &mut self.entries[i].session)
    }

    pub fn active_id(&self) -> Option<&str> {
        self.active.as_deref()
    }

    pub fn set_active(&mut self, id: &str) -> bool {
        if self.contains(id) {
            self.active = Some(id.to_string());
            true
        } else {
            false
        }
    }

    /// `id` when present AND known, else the active id. An unknown explicit id
    /// resolves to `None` (fail closed) rather than silently using active.
    pub fn resolve<'a>(&'a self, id: Option<&'a str>) -> Option<&'a str> {
        match id {
            Some(i) => self.contains(i).then_some(i),
            None => self.active_id(),
        }
    }

    pub fn active_mut(&mut self) -> Option<&mut Session> {
        let id = self.active.clone()?;
        self.get_mut(&id)
    }

    /// Drops the entry (its `Session` is zeroized on drop). If it was active,
    /// active moves to the now-previous entry, or `None` when the set is empty.
    pub fn remove(&mut self, id: &str) -> Option<Session> {
        let i = self.pos(id)?;
        let entry = self.entries.remove(i);
        if self.active.as_deref() == Some(id) {
            let prev = i.saturating_sub(1);
            self.active = self.entries.get(prev).map(|e| e.id.clone());
        }
        Some(entry.session)
    }

    pub fn lock_one(&mut self, id: &str) -> bool {
        match self.get_mut(id) {
            Some(s) => {
                s.lock();
                true
            }
            None => false,
        }
    }

    pub fn lock_all(&mut self) {
        for e in &mut self.entries {
            e.session.lock();
        }
    }

    pub fn open_paths(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.id.clone()).collect()
    }

    /// Reorder `entries` so ids listed in `ordered_ids` come first in that
    /// relative order; ids not mentioned keep their current relative order,
    /// appended after. Unknown ids in `ordered_ids` are ignored. `active` is
    /// untouched — tab order is independent of which vault is selected. Returns
    /// `true` iff the entry order actually changed, so the caller can skip a
    /// needless (and, for an empty/no-op registry, destructive) re-persist.
    pub fn reorder(&mut self, ordered_ids: &[String]) -> bool {
        let before: Vec<VaultId> = self.entries.iter().map(|e| e.id.clone()).collect();
        self.entries.sort_by_key(|e| {
            ordered_ids.iter().position(|o| o == &e.id).unwrap_or(usize::MAX)
        });
        self.entries.iter().zip(before.iter()).any(|(e, b)| &e.id != b)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Session> {
        self.entries.iter_mut().map(|e| &mut e.session)
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kokos_core::session::Session;

    fn reg_with(ids: &[&str]) -> SessionRegistry {
        let mut r = SessionRegistry::new();
        for id in ids {
            r.insert((*id).to_string(), Session::new());
        }
        r
    }

    #[test]
    fn insert_sets_active_and_preserves_order() {
        let r = reg_with(&["/a", "/b", "/c"]);
        assert_eq!(r.open_paths(), vec!["/a", "/b", "/c"]);
        assert_eq!(r.active_id(), Some("/c"), "the last inserted is active");
    }

    #[test]
    fn insert_existing_id_replaces_without_duplicating_order() {
        let mut r = reg_with(&["/a", "/b"]);
        r.insert("/a".to_string(), Session::new());
        assert_eq!(r.open_paths(), vec!["/a", "/b"], "re-insert must not duplicate the id");
        assert_eq!(r.active_id(), Some("/b"), "re-inserting an existing id must not change which vault is active");
    }

    #[test]
    fn contains_reports_membership() {
        let r = reg_with(&["/a"]);
        assert!(r.contains("/a"));
        assert!(!r.contains("/missing"));
    }

    #[test]
    fn resolve_prefers_explicit_id_then_falls_back_to_active() {
        let r = reg_with(&["/a", "/b"]);
        assert_eq!(r.resolve(Some("/a")), Some("/a"), "explicit known id wins");
        assert_eq!(r.resolve(None), Some("/b"), "None falls back to active");
        assert_eq!(r.resolve(Some("/missing")), None, "an unknown explicit id resolves to None, not active");
    }

    #[test]
    fn set_active_switches_only_to_a_known_id() {
        let mut r = reg_with(&["/a", "/b"]);
        assert!(r.set_active("/a"));
        assert_eq!(r.active_id(), Some("/a"));
        assert!(!r.set_active("/missing"));
        assert_eq!(r.active_id(), Some("/a"), "a failed switch leaves active unchanged");
    }

    #[test]
    fn remove_active_moves_active_to_previous_entry() {
        let mut r = reg_with(&["/a", "/b", "/c"]);
        assert!(r.remove("/c").is_some());
        assert_eq!(r.active_id(), Some("/b"), "removing active moves to the previous in order");
        assert_eq!(r.open_paths(), vec!["/a", "/b"]);
    }

    #[test]
    fn remove_last_clears_active() {
        let mut r = reg_with(&["/a"]);
        r.remove("/a");
        assert_eq!(r.active_id(), None);
        assert!(r.open_paths().is_empty());
    }

    #[test]
    fn lock_one_locks_only_that_session_lock_all_locks_every() {
        let mut r = reg_with(&["/a", "/b"]);
        assert!(r.lock_one("/a"));
        assert!(!r.lock_one("/missing"));
        r.lock_all();
    }

    #[test]
    fn lock_all_then_reinsert_unlocks_only_the_reopened_one() {
        let mut r = SessionRegistry::new();
        r.insert("/a".into(), Session::new());
        r.insert("/b".into(), Session::new());
        r.lock_all();
        r.insert("/a".into(), Session::new());
        assert!(r.contains("/a") && r.contains("/b"), "both remain present after a single-vault unlock");
    }

    #[test]
    fn reorder_applies_the_given_order() {
        let mut r = reg_with(&["/a", "/b", "/c"]);
        r.reorder(&["/c".into(), "/a".into(), "/b".into()]);
        assert_eq!(r.open_paths(), vec!["/c", "/a", "/b"]);
    }

    #[test]
    fn reorder_puts_unlisted_ids_after_listed_keeping_their_order() {
        let mut r = reg_with(&["/a", "/b", "/c", "/d"]);
        r.reorder(&["/c".into(), "/a".into()]);
        assert_eq!(r.open_paths(), vec!["/c", "/a", "/b", "/d"]);
    }

    #[test]
    fn reorder_ignores_unknown_ids() {
        let mut r = reg_with(&["/a", "/b"]);
        r.reorder(&["/x".into(), "/b".into(), "/a".into()]);
        assert_eq!(r.open_paths(), vec!["/b", "/a"], "unknown /x is ignored, present ids reorder");
    }

    #[test]
    fn reorder_leaves_active_unchanged() {
        let mut r = reg_with(&["/a", "/b", "/c"]);
        r.reorder(&["/c".into(), "/b".into(), "/a".into()]);
        assert_eq!(r.active_id(), Some("/c"), "reorder is order-only, never touches selection");
    }

    #[test]
    fn reorder_with_empty_list_is_a_noop() {
        let mut r = reg_with(&["/a", "/b", "/c"]);
        r.reorder(&[]);
        assert_eq!(r.open_paths(), vec!["/a", "/b", "/c"]);
    }

    #[test]
    fn reorder_reports_true_when_order_changes() {
        let mut r = reg_with(&["/a", "/b", "/c"]);
        assert!(r.reorder(&["/c".into(), "/b".into(), "/a".into()]), "a real permutation reports changed");
    }

    #[test]
    fn reorder_reports_false_when_order_unchanged() {
        let mut r = reg_with(&["/a", "/b", "/c"]);
        assert!(!r.reorder(&["/a".into(), "/b".into(), "/c".into()]), "identical order reports no change");
    }

    #[test]
    fn reorder_on_empty_registry_reports_no_change() {
        let mut r = SessionRegistry::new();
        assert!(!r.reorder(&["/a".into(), "/b".into()]), "empty registry can't change — caller must skip persist");
        assert!(r.open_paths().is_empty());
    }
}

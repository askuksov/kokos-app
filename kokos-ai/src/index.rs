//! Invalidation + backfill core. Pure over an injected `Embedder`, so CI runs
//! it with `FakeEmbedder` and never touches ONNX. Model change is handled
//! upstream by `VectorStore::open` (a stale `model_id` opens empty), so nothing
//! here needs to know the model.

use std::collections::HashSet;

use crate::embed::Embedder;
use crate::meta::EntryMeta;
use crate::store::{VectorRecord, VectorStore};
use crate::AiError;

pub struct BackfillPlan {
    /// Indices into the `wanted` slice needing (re)embedding.
    pub to_embed: Vec<usize>,
    /// Stored entry_ids no longer live (entry deleted/trashed) — drop them.
    pub to_remove: Vec<String>,
}

/// Diff the store against the live set: embed missing or content-changed
/// entries; remove records whose entry is gone. Preserves `wanted` order for
/// `to_embed`; `to_remove` order is unspecified (caller sorts if needed).
pub fn plan_backfill(store: &VectorStore, wanted: &[EntryMeta]) -> BackfillPlan {
    let live: HashSet<&str> = wanted.iter().map(|m| m.entry_id.as_str()).collect();
    let to_embed = wanted
        .iter()
        .enumerate()
        .filter(|(_, m)| match store.records.get(&m.entry_id) {
            Some(rec) => rec.content_hash != m.content_hash,
            None => true,
        })
        .map(|(i, _)| i)
        .collect();
    let to_remove = store
        .records
        .keys()
        .filter(|id| !live.contains(id.as_str()))
        .cloned()
        .collect();
    BackfillPlan { to_embed, to_remove }
}

/// Apply a plan: drop stale records, then embed each needed entry (batch_size =
/// 1). `progress(done, total)` fires after each embed; `cancel()` returning
/// true stops early — the store keeps what it has (a partial index is valid;
/// the remainder is caught on the next run). Returns the count embedded.
pub fn run_backfill(
    store: &mut VectorStore,
    wanted: &[EntryMeta],
    embedder: &dyn Embedder,
    mut progress: impl FnMut(usize, usize),
    cancel: impl Fn() -> bool,
) -> Result<usize, AiError> {
    let plan = plan_backfill(store, wanted);
    for id in &plan.to_remove {
        store.records.remove(id);
    }
    let total = plan.to_embed.len();
    let mut done = 0;
    for &i in &plan.to_embed {
        if cancel() {
            break;
        }
        let m = &wanted[i];
        let vec = embedder.embed(&m.input)?;
        store.records.insert(
            m.entry_id.clone(),
            VectorRecord { content_hash: m.content_hash.clone(), vec },
        );
        done += 1;
        progress(done, total);
    }
    Ok(done)
}

/// Re-embed exactly one entry (create/edit path). No-op if the stored hash
/// already matches — an idempotent create-then-immediate-save can't thrash.
pub fn upsert_one(store: &mut VectorStore, m: &EntryMeta, embedder: &dyn Embedder) -> Result<(), AiError> {
    if store.records.get(&m.entry_id).map(|r| r.content_hash.as_str()) == Some(m.content_hash.as_str()) {
        return Ok(());
    }
    let vec = embedder.embed(&m.input)?;
    store.records.insert(
        m.entry_id.clone(),
        VectorRecord { content_hash: m.content_hash.clone(), vec },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embed::FakeEmbedder;
    use crate::meta::EntryMeta;
    use crate::store::{VectorRecord, VectorStore};
    use std::cell::Cell;

    fn meta(id: &str, hash: &str) -> EntryMeta {
        EntryMeta { entry_id: id.into(), input: format!("in-{id}"), content_hash: hash.into() }
    }

    #[test]
    fn plan_embeds_missing_and_changed_skips_unchanged_removes_stale() {
        let mut store = VectorStore::empty("mid", 4);
        store.records.insert("keep".into(), VectorRecord { content_hash: "h-keep".into(), vec: vec![0.0; 4] });
        store.records.insert("changed".into(), VectorRecord { content_hash: "OLD".into(), vec: vec![0.0; 4] });
        store.records.insert("stale".into(), VectorRecord { content_hash: "h-stale".into(), vec: vec![0.0; 4] });

        let wanted = vec![meta("keep", "h-keep"), meta("changed", "NEW"), meta("new", "h-new")];
        let plan = plan_backfill(&store, &wanted);

        let embed_ids: Vec<&str> = plan.to_embed.iter().map(|&i| wanted[i].entry_id.as_str()).collect();
        assert_eq!(embed_ids, vec!["changed", "new"], "missing + changed only");
        assert_eq!(plan.to_remove, vec!["stale".to_string()], "entry gone -> remove");
    }

    #[test]
    fn run_backfill_fills_store_removes_stale_and_reports_progress() {
        let mut store = VectorStore::empty("mid", 8);
        store.records.insert("stale".into(), VectorRecord { content_hash: "x".into(), vec: vec![0.0; 8] });
        let wanted = vec![meta("a", "ha"), meta("b", "hb")];
        let emb = FakeEmbedder { dim: 8 };
        let seen: Cell<(usize, usize)> = Cell::new((0, 0));
        let done = run_backfill(&mut store, &wanted, &emb, |d, t| seen.set((d, t)), || false).unwrap();
        assert_eq!(done, 2);
        assert!(!store.records.contains_key("stale"), "stale removed");
        assert_eq!(store.records.len(), 2);
        assert_eq!(store.records["a"].vec.len(), 8);
        assert_eq!(seen.get(), (2, 2), "progress reached done==total");
    }

    #[test]
    fn run_backfill_stops_early_on_cancel_leaving_a_valid_partial() {
        let mut store = VectorStore::empty("mid", 8);
        let wanted = vec![meta("a", "ha"), meta("b", "hb"), meta("c", "hc")];
        let emb = FakeEmbedder { dim: 8 };
        let calls = Cell::new(0);
        let done = run_backfill(&mut store, &wanted, &emb, |_, _| {}, || {
            let n = calls.get(); calls.set(n + 1); n >= 1
        }).unwrap();
        assert_eq!(done, 1, "one embedded, then cancelled");
        assert_eq!(store.records.len(), 1);
    }

    #[test]
    fn upsert_one_is_idempotent_on_unchanged_hash() {
        let mut store = VectorStore::empty("mid", 8);
        let emb = FakeEmbedder { dim: 8 };
        let m = meta("a", "ha");
        upsert_one(&mut store, &m, &emb).unwrap();
        let v1 = store.records["a"].vec.clone();
        upsert_one(&mut store, &m, &emb).unwrap();
        assert_eq!(store.records["a"].vec, v1);
        assert_eq!(store.records.len(), 1);
    }
}

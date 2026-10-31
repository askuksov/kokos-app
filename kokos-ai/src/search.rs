//! Cosine top-k over the encrypted vector sidecar. Pure and offline: the query
//! vector is produced by the same `Embedder` that built the store, so CI drives
//! this with `FakeEmbedder` (no ONNX). Stored + query vectors are already
//! L2-normalized (so cosine == dot), but this computes TRUE cosine — dividing by
//! the norms and guarding a zero norm — so a stray non-unit or wrong-dimension
//! record can never panic or skew the ranking; a dimension mismatch is skipped.

use crate::store::VectorStore;

/// Rank the store against `query` by cosine similarity. Returns up to `k`
/// `(entry_id, score)` pairs, highest score first, keeping only scores
/// `>= min_score`. A record whose vector length differs from `query` (a stale
/// dimension from a model change) or whose norm is zero is skipped; an empty or
/// zero-norm query returns nothing. Ties break by `entry_id` ascending so the
/// order is deterministic regardless of the underlying `HashMap` iteration.
pub fn top_k(query: &[f32], store: &VectorStore, k: usize, min_score: f32) -> Vec<(String, f32)> {
    let q_norm = norm(query);
    if query.is_empty() || q_norm == 0.0 {
        return Vec::new();
    }
    let mut scored: Vec<(String, f32)> = store
        .records
        .iter()
        .filter_map(|(id, rec)| {
            if rec.vec.len() != query.len() {
                return None;
            }
            let v_norm = norm(&rec.vec);
            if v_norm == 0.0 {
                return None;
            }
            let dot: f32 = query.iter().zip(&rec.vec).map(|(a, b)| a * b).sum();
            let score = dot / (q_norm * v_norm);
            (score >= min_score).then(|| (id.clone(), score))
        })
        .collect();
    scored.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    scored.truncate(k);
    scored
}

fn norm(v: &[f32]) -> f32 {
    v.iter().map(|x| x * x).sum::<f32>().sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embed::{Embedder, FakeEmbedder};
    use crate::store::{VectorRecord, VectorStore};

    fn store_with(vecs: &[(&str, Vec<f32>)]) -> VectorStore {
        let mut s = VectorStore::empty("mid", 3);
        for (id, v) in vecs {
            s.records.insert((*id).into(), VectorRecord { content_hash: "h".into(), vec: v.clone() });
        }
        s
    }

    #[test]
    fn ranks_by_cosine_and_applies_threshold() {
        let store = store_with(&[
            ("a", vec![1.0, 0.0, 0.0]),
            ("b", vec![0.0, 1.0, 0.0]),
            ("c", vec![1.0, 1.0, 0.0]),
        ]);
        let hits = top_k(&[1.0, 0.0, 0.0], &store, 10, 0.5);
        let ids: Vec<&str> = hits.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, vec!["a", "c"], "a first (1.0), c second (~0.707), b dropped (<0.5)");
        assert!((hits[0].1 - 1.0).abs() < 1e-5, "a scores 1.0");
        assert!((hits[1].1 - 0.70710677).abs() < 1e-4, "c scores ~0.707");
    }

    #[test]
    fn caps_at_k() {
        let store = store_with(&[("a", vec![1.0, 0.0, 0.0]), ("c", vec![1.0, 1.0, 0.0])]);
        let hits = top_k(&[1.0, 0.0, 0.0], &store, 1, 0.0);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "a");
    }

    #[test]
    fn skips_dimension_mismatch_without_panicking() {
        let store = store_with(&[("good", vec![1.0, 0.0, 0.0]), ("bad", vec![1.0, 0.0])]);
        let hits = top_k(&[1.0, 0.0, 0.0], &store, 10, 0.0);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "good");
    }

    #[test]
    fn empty_store_and_empty_query_yield_nothing() {
        let empty = VectorStore::empty("mid", 3);
        assert!(top_k(&[1.0, 0.0, 0.0], &empty, 10, 0.0).is_empty());
        let store = store_with(&[("a", vec![1.0, 0.0, 0.0])]);
        assert!(top_k(&[], &store, 10, 0.0).is_empty(), "empty query -> nothing");
        assert!(top_k(&[0.0, 0.0, 0.0], &store, 10, 0.0).is_empty(), "zero query -> nothing");
    }

    #[test]
    fn ties_break_by_id_for_determinism() {
        let store = store_with(&[("zeta", vec![1.0, 0.0, 0.0]), ("alpha", vec![1.0, 0.0, 0.0])]);
        let hits = top_k(&[1.0, 0.0, 0.0], &store, 10, 0.0);
        assert_eq!(hits.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(), vec!["alpha", "zeta"]);
    }

    #[test]
    fn same_fake_embedder_pipeline_ranks_the_match_first() {
        let emb = FakeEmbedder { dim: 16 };
        let mut store = VectorStore::empty("mid", 16);
        for text in ["netflix.com", "spotify.com", "github.com"] {
            store.records.insert(text.into(), VectorRecord { content_hash: "h".into(), vec: emb.embed(text).unwrap() });
        }
        let q = emb.embed("netflix.com").unwrap();
        let hits = top_k(&q, &store, 3, 0.0);
        assert_eq!(hits[0].0, "netflix.com", "exact re-embed ranks first");
        assert!((hits[0].1 - 1.0).abs() < 1e-4, "identical vector -> cosine ~1.0");
    }
}

//! Folder-suggestion ranking. Pure and offline: given each folder's
//! member entry vectors (read from the encrypted sidecar) it builds an
//! L2-normalized centroid per folder, then ranks folders by cosine similarity
//! to a target entry vector. Ranking reuses `search::top_k` by viewing the
//! folder centroids as a `VectorStore`, so the cosine + threshold + tie-break
//! guarantees are shared, not re-implemented. CI drives this with hand-built
//! vectors and `FakeEmbedder`; there is no ONNX and no DB access here.

use std::collections::HashMap;

use crate::search::top_k;
use crate::store::{VectorRecord, VectorStore};

/// L2-normalized mean of the member vectors. Vectors whose length differs from
/// `dim` are skipped (a stale dimension from a model change). Returns `None` if
/// no usable member remains, or the mean has zero norm and cannot be
/// normalized. The result is a unit vector so it lives in the same space as the
/// L2-normalized entry vectors it will be compared against.
pub fn centroid(members: &[&[f32]], dim: usize) -> Option<Vec<f32>> {
    if dim == 0 {
        return None;
    }
    let mut acc = vec![0.0f32; dim];
    let mut n = 0usize;
    for v in members {
        if v.len() != dim {
            continue;
        }
        for (a, x) in acc.iter_mut().zip(*v) {
            *a += *x;
        }
        n += 1;
    }
    if n == 0 {
        return None;
    }
    let inv = 1.0 / n as f32;
    for a in acc.iter_mut() {
        *a *= inv;
    }
    let norm = acc.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm == 0.0 {
        return None;
    }
    for a in acc.iter_mut() {
        *a /= norm;
    }
    Some(acc)
}

/// Rank candidates (folders or tags) by cosine(`entry_vec`, candidate centroid). `centroids` maps
/// `candidate_id -> centroid` (each already unit-length). Reuses `top_k`'s cosine,
/// threshold, k-cap, and deterministic tie-break by viewing the centroids as a
/// `VectorStore` — no ranking math is duplicated here. Returns up to `k`
/// `(candidate_id, score)` pairs, highest first, keeping only `score >= min_score`.
pub fn rank_candidates(
    entry_vec: &[f32],
    centroids: &HashMap<String, Vec<f32>>,
    k: usize,
    min_score: f32,
) -> Vec<(String, f32)> {
    let mut store = VectorStore::empty("centroids", entry_vec.len() as u32);
    for (fid, c) in centroids {
        store
            .records
            .insert(fid.clone(), VectorRecord { content_hash: String::new(), vec: c.clone() });
    }
    top_k(entry_vec, &store, k, min_score)
}

/// Greedy single-link clustering over UNIT vectors by cosine similarity
/// (== dot product for unit vectors). Walks `items` in order: the first
/// unassigned item seeds a cluster and pulls in every later unassigned item
/// whose cosine to the seed is `>= min_cosine`. Clusters smaller than
/// `min_size` are dropped (their items simply do not appear — the caller keeps
/// them unfiled). Deterministic: clusters are emitted in seed order, members in
/// input order. Vectors whose length differs from the seed's are treated as
/// non-matching (a stale dimension never merges).
pub fn cluster_greedy(items: &[(String, Vec<f32>)], min_cosine: f32, min_size: usize) -> Vec<Vec<String>> {
    let n = items.len();
    let mut assigned = vec![false; n];
    let mut out: Vec<Vec<String>> = Vec::new();
    for i in 0..n {
        if assigned[i] {
            continue;
        }
        assigned[i] = true;
        let seed = &items[i].1;
        let mut group = vec![items[i].0.clone()];
        for j in (i + 1)..n {
            if assigned[j] {
                continue;
            }
            let v = &items[j].1;
            if v.len() != seed.len() {
                continue;
            }
            let dot: f32 = seed.iter().zip(v).map(|(a, b)| a * b).sum();
            if dot >= min_cosine {
                assigned[j] = true;
                group.push(items[j].0.clone());
            }
        }
        if group.len() >= min_size {
            out.push(group);
        }
    }
    out
}

/// Which rule produced a seeded new-folder name (for transparency/telemetry).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NameSource {
    Domain,
    Tag,
    Title,
}

/// A cluster member's whitelist metadata used ONLY to seed a folder name.
/// Every field is already-whitelisted (`title` / `url_domain` / `tags`) — no
/// secret value can reach here.
#[derive(Debug, Clone)]
pub struct NamingInput {
    pub title: String,
    pub domain: Option<String>,
    pub tags: Vec<String>,
}

/// Seed a NEW-folder name WITHOUT any generative model (kokos-ai is
/// embeddings-only). Rules, in order:
///   1. the cluster's dominant eTLD+1 domain — the most common `domain`, if it
///      covers `>= domain_min_fraction` of ALL cluster members;
///   2. else the most common non-empty tag across all members;
///   3. else the title of member `rep_idx` (the representative, nearest the
///      cluster centroid — chosen by the caller).
/// Ties break toward the first-seen value; a blank result falls through to the
/// representative title. The name is a SEED only — always user-editable in the
/// review UI.
pub fn seed_folder_name(members: &[NamingInput], rep_idx: usize, domain_min_fraction: f32) -> (String, NameSource) {
    let rep_title = || -> String {
        members
            .get(rep_idx)
            .map(|m| m.title.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| members.iter().map(|m| m.title.trim().to_string()).find(|s| !s.is_empty()))
            .unwrap_or_default()
    };

    let domains: Vec<&str> = members
        .iter()
        .filter_map(|m| m.domain.as_deref())
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .collect();
    if !domains.is_empty() {
        if let Some((top, count)) = mode(&domains) {
            let frac = count as f32 / members.len() as f32;
            if frac >= domain_min_fraction {
                return (top, NameSource::Domain);
            }
        }
    }

    let tags: Vec<&str> = members
        .iter()
        .flat_map(|m| m.tags.iter())
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .collect();
    if !tags.is_empty() {
        if let Some((top, _)) = mode(&tags) {
            return (top, NameSource::Tag);
        }
    }

    (rep_title(), NameSource::Title)
}

/// Most frequent value + its count, ties broken toward first appearance.
fn mode(values: &[&str]) -> Option<(String, usize)> {
    use std::collections::HashMap;
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let mut best: Option<(&str, usize, usize)> = None;
    for (i, v) in values.iter().enumerate() {
        let c = counts.entry(v).or_insert(0);
        *c += 1;
        let cnt = *c;
        match best {
            Some((_, bc, _)) if cnt > bc => best = Some((v, cnt, i)),
            None => best = Some((v, cnt, i)),
            _ => {}
        }
    }
    best.map(|(v, c, _)| (v.to_string(), c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embed::{Embedder, FakeEmbedder};

    #[test]
    fn centroid_is_the_renormalized_mean() {
        let a: &[f32] = &[1.0, 0.0];
        let b: &[f32] = &[0.0, 1.0];
        let c = centroid(&[a, b], 2).unwrap();
        let inv = 1.0 / 2f32.sqrt();
        assert!((c[0] - inv).abs() < 1e-6 && (c[1] - inv).abs() < 1e-6, "got {c:?}");
        let norm = (c[0] * c[0] + c[1] * c[1]).sqrt();
        assert!((norm - 1.0).abs() < 1e-6, "renormalized to unit length");
    }

    #[test]
    fn centroid_skips_wrong_dimension_and_handles_empty() {
        let good: &[f32] = &[1.0, 0.0];
        let stray: &[f32] = &[1.0, 2.0, 3.0];
        let c = centroid(&[good, stray], 2).unwrap();
        assert!((c[0] - 1.0).abs() < 1e-6 && c[1].abs() < 1e-6, "only `good` counted: {c:?}");
        assert!(centroid(&[], 2).is_none(), "no members -> None");
        assert!(centroid(&[stray], 2).is_none(), "all-wrong-dim -> None");
        let zero: &[f32] = &[0.0, 0.0];
        assert!(centroid(&[zero], 2).is_none(), "zero-norm mean -> None (can't normalize)");
    }

    #[test]
    fn rank_candidates_orders_by_cosine_and_applies_threshold() {
        let mut centroids: HashMap<String, Vec<f32>> = HashMap::new();
        centroids.insert("work".into(), vec![1.0, 0.0, 0.0]);
        centroids.insert("media".into(), vec![1.0, 1.0, 0.0]);
        centroids.insert("ortho".into(), vec![0.0, 1.0, 0.0]);
        let ranked = rank_candidates(&[1.0, 0.0, 0.0], &centroids, 10, 0.5);
        let ids: Vec<&str> = ranked.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, vec!["work", "media"], "work first, media second, ortho dropped");
        assert!((ranked[0].1 - 1.0).abs() < 1e-5);
    }

    #[test]
    fn rank_candidates_caps_at_k_and_is_empty_for_empty_inputs() {
        let mut centroids: HashMap<String, Vec<f32>> = HashMap::new();
        centroids.insert("a".into(), vec![1.0, 0.0]);
        centroids.insert("b".into(), vec![1.0, 0.0]);
        assert_eq!(rank_candidates(&[1.0, 0.0], &centroids, 1, 0.0).len(), 1, "capped at k");
        assert!(rank_candidates(&[1.0, 0.0], &HashMap::new(), 5, 0.0).is_empty(), "no folders -> empty");
        assert!(rank_candidates(&[], &centroids, 5, 0.0).is_empty(), "empty query -> empty");
    }

    #[test]
    fn end_to_end_with_fake_embedder_ranks_the_matching_folder_first() {
        let emb = FakeEmbedder { dim: 16 };
        let mean = |texts: &[&str]| -> Vec<f32> {
            let vs: Vec<Vec<f32>> = texts.iter().map(|t| emb.embed(t).unwrap()).collect();
            let refs: Vec<&[f32]> = vs.iter().map(|v| v.as_slice()).collect();
            centroid(&refs, 16).unwrap()
        };
        let mut centroids: HashMap<String, Vec<f32>> = HashMap::new();
        centroids.insert("work".into(), mean(&["github.com", "gitlab.com"]));
        centroids.insert("media".into(), mean(&["netflix.com", "spotify.com"]));
        let target = emb.embed("github.com").unwrap();
        let ranked = rank_candidates(&target, &centroids, 2, 0.0);
        assert_eq!(ranked[0].0, "work", "github target ranks the work folder first");
    }


    /// Build a unit vector from raw components (clustering compares cosine of
    /// unit vectors == dot product). FakeEmbedder is hash-based (NOT semantic),
    /// so cluster geometry is exercised with hand-built vectors instead.
    fn unit(x: &[f32]) -> Vec<f32> {
        let n = x.iter().map(|v| v * v).sum::<f32>().sqrt();
        x.iter().map(|v| v / n).collect()
    }

    #[test]
    fn cluster_greedy_groups_near_and_drops_singletons() {
        let items = vec![
            ("a".to_string(), unit(&[1.0, 0.02, 0.0])),
            ("b".to_string(), unit(&[1.0, 0.0, 0.02])),
            ("z".to_string(), unit(&[0.0, 1.0, 0.0])),
        ];
        let clusters = cluster_greedy(&items, 0.9, 2);
        assert_eq!(clusters, vec![vec!["a".to_string(), "b".to_string()]],
            "near pair clusters; orthogonal singleton dropped");
    }

    #[test]
    fn cluster_greedy_preserves_seed_order_and_is_deterministic() {
        let items = vec![
            ("x1".to_string(), unit(&[1.0, 0.0])),
            ("y1".to_string(), unit(&[0.0, 1.0])),
            ("x2".to_string(), unit(&[0.98, 0.02])),
            ("y2".to_string(), unit(&[0.02, 0.98])),
        ];
        let clusters = cluster_greedy(&items, 0.9, 2);
        assert_eq!(
            clusters,
            vec![
                vec!["x1".to_string(), "x2".to_string()],
                vec!["y1".to_string(), "y2".to_string()],
            ],
            "clusters emitted in seed order; members in input order"
        );
    }

    #[test]
    fn cluster_greedy_empty_input_is_empty() {
        let items: Vec<(String, Vec<f32>)> = Vec::new();
        assert!(cluster_greedy(&items, 0.5, 2).is_empty());
    }


    #[test]
    fn seed_name_prefers_dominant_domain() {
        let members = vec![
            NamingInput { title: "Repo A".into(), domain: Some("github.com".into()), tags: vec!["dev".into()] },
            NamingInput { title: "Repo B".into(), domain: Some("github.com".into()), tags: vec!["dev".into()] },
            NamingInput { title: "Random".into(), domain: None, tags: vec!["misc".into()] },
        ];
        let (name, src) = seed_folder_name(&members, 0, 0.5);
        assert_eq!(name, "github.com");
        assert_eq!(src, NameSource::Domain);
    }

    #[test]
    fn seed_name_falls_back_to_most_common_tag() {
        let members = vec![
            NamingInput { title: "One".into(), domain: None, tags: vec!["work".into(), "x".into()] },
            NamingInput { title: "Two".into(), domain: None, tags: vec!["work".into()] },
        ];
        let (name, src) = seed_folder_name(&members, 0, 0.5);
        assert_eq!(name, "work");
        assert_eq!(src, NameSource::Tag);
    }

    #[test]
    fn seed_name_falls_back_to_representative_title() {
        let members = vec![
            NamingInput { title: "Alpha".into(), domain: None, tags: vec![] },
            NamingInput { title: "Bravo".into(), domain: None, tags: vec![] },
        ];
        let (name, src) = seed_folder_name(&members, 1, 0.5);
        assert_eq!(name, "Bravo", "rep_idx picks the representative title");
        assert_eq!(src, NameSource::Title);
    }

    #[test]
    fn seed_name_domain_below_fraction_falls_through_to_tag() {
        let members = vec![
            NamingInput { title: "One".into(), domain: Some("x.com".into()), tags: vec!["group".into()] },
            NamingInput { title: "Two".into(), domain: None, tags: vec!["group".into()] },
            NamingInput { title: "Three".into(), domain: None, tags: vec!["group".into()] },
        ];
        let (name, src) = seed_folder_name(&members, 0, 0.5);
        assert_eq!(name, "group");
        assert_eq!(src, NameSource::Tag);
    }
}

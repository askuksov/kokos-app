//! Splits a file into chunks on pre-parser block boundaries so a chunk never straddles a
//! blank-line block (one entry = one block, so grouping survives). Each chunk is
//! a byte span; a single block larger than the budget becomes its own chunk
//! (never split a block mid-way). If that chunk does not fit the model context,
//! the extractor returns no drafts for it and the heuristic floor covers it.

use crate::text_import::model::Span;

/// Group consecutive `blocks` into chunk spans, each ≤ `budget` bytes when it can
/// be (a lone oversized block is emitted as-is). `budget` is a byte proxy for the
/// model's token context window, computed by the caller.
pub fn chunk_blocks(blocks: &[Span], budget: usize) -> Vec<Span> {
    let mut chunks = Vec::new();
    let mut cur: Option<Span> = None;
    for &b in blocks {
        cur = match cur {
            Some(c) if b.end.saturating_sub(c.start) <= budget => Some(Span { start: c.start, end: b.end }),
            Some(c) => {
                chunks.push(c);
                Some(b)
            }
            None => Some(b),
        };
    }
    if let Some(c) = cur {
        chunks.push(c);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text_import::model::Span;

    fn s(a: usize, b: usize) -> Span { Span { start: a, end: b } }

    #[test]
    fn groups_blocks_up_to_budget_without_splitting() {
        let blocks = vec![s(0, 10), s(12, 20), s(22, 40)];
        let chunks = chunk_blocks(&blocks, 25);
        assert_eq!(chunks, vec![s(0, 20), s(22, 40)]);
    }

    #[test]
    fn a_single_oversized_block_is_its_own_chunk() {
        let blocks = vec![s(0, 100)];
        assert_eq!(chunk_blocks(&blocks, 10), vec![s(0, 100)]);
    }

    #[test]
    fn empty_blocks_yield_no_chunks() {
        assert!(chunk_blocks(&[], 10).is_empty());
    }
}

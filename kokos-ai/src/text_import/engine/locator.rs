//! The locator (security-core): turns the extractor's verbatim-text drafts into
//! source spans. Every span is produced by FINDING the exact text in the source
//! (never trusting a model offset); a text not found is dropped (flagged), never
//! approximated. Sets `echoed_value = verbatim_text` so `integrity::validate`
//! independently re-checks `source[span] == verbatim_text`.

use crate::text_import::engine::extractor::{RawEntryDraft, RawFieldDraft};
use crate::text_import::model::{FieldType, RawEntry, RawField, Span};

/// Search context for one chunk: the full `source` (spans are absolute into it),
/// the chunk's byte `window`, and the block spans within the window.
pub struct LocateCtx<'a> {
    pub source: &'a str,
    pub window: Span,
    pub blocks: &'a [Span],
}

/// Confidence stamped on an LLM-located field (heuristic-floor fields keep their
/// own pre-parser confidence; the review-UI shows this).
const LLM_CONFIDENCE: f32 = 0.7;

pub(crate) fn overlaps(a: Span, b: Span) -> bool {
    a.start < b.end && b.start < a.end
}

/// The block span containing byte `pos`, if any.
pub(crate) fn block_of(blocks: &[Span], pos: usize) -> Option<Span> {
    blocks.iter().copied().find(|b| pos >= b.start && pos < b.end)
}

/// Characters that continue a credential-like token (`ivan.petrov@mail.ru`).
fn continues_token(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '_' | '@' | '-' | '+' | '%')
}

/// `cand` covers a whole token: the neighbouring characters do not continue it.
/// A value the model cut short would otherwise claim the head of the real one.
fn is_whole(source: &str, cand: Span) -> bool {
    let before = source[..cand.start].chars().next_back();
    let after = source[cand.end..].chars().next();
    !before.is_some_and(continues_token) && !after.is_some_and(continues_token)
}

/// Find the first occurrence of `needle` within `region` that is a whole token
/// and does not overlap an already-consumed span. `region` is char-aligned (a
/// block or the chunk window), so the returned span is char-aligned. Returns
/// `None` for an empty needle or no free occurrence.
fn find_in(source: &str, needle: &str, region: Span, consumed: &[Span]) -> Option<Span> {
    if needle.is_empty() || region.end > source.len() || region.start > region.end {
        return None;
    }
    let hay = &source[region.start..region.end];
    let mut from = 0usize;
    while let Some(rel) = hay[from..].find(needle) {
        let start = region.start + from + rel;
        let cand = Span { start, end: start + needle.len() };
        if is_whole(source, cand) && !consumed.iter().any(|c| overlaps(*c, cand)) {
            return Some(cand);
        }
        from += rel + needle.chars().next().map_or(1, |c| c.len_utf8());
        if from > hay.len() {
            break;
        }
    }
    None
}

/// The index of the entry's anchor field: prefer a URL, else the first field.
fn anchor_index(draft: &RawEntryDraft) -> Option<usize> {
    if let Some(i) = draft.fields.iter().position(|f| f.field_type == FieldType::Url) {
        return Some(i);
    }
    if draft.fields.is_empty() {
        None
    } else {
        Some(0)
    }
}

fn located_field(f: &RawFieldDraft, span: Span) -> RawField {
    RawField {
        field_type: f.field_type,
        span,
        echoed_value: Some(f.verbatim_text.clone()),
        confidence: LLM_CONFIDENCE,
    }
}

pub fn locate(ctx: &LocateCtx, drafts: &[RawEntryDraft]) -> Vec<RawEntry> {
    let mut out = Vec::new();
    // Shared across drafts: a source span is one field of one entry. Reset per
    // draft, a value two accounts share (one e-mail) resolved to its first
    // occurrence for both, and the second account's block came out empty.
    let mut consumed: Vec<Span> = Vec::new();
    for draft in drafts {
        let mut fields: Vec<(usize, RawField)> = Vec::new();
        let anchor = anchor_index(draft);

        let region = match anchor {
            Some(ai) => {
                let a = &draft.fields[ai];
                match find_in(ctx.source, &a.verbatim_text, ctx.window, &consumed) {
                    Some(sp) => {
                        consumed.push(sp);
                        fields.push((ai, located_field(a, sp)));
                        block_of(ctx.blocks, sp.start).unwrap_or(ctx.window)
                    }
                    None => ctx.window,
                }
            }
            None => ctx.window,
        };

        for (i, f) in draft.fields.iter().enumerate() {
            if Some(i) == anchor {
                continue;
            }
            let span = find_in(ctx.source, &f.verbatim_text, region, &consumed)
                .or_else(|| find_in(ctx.source, &f.verbatim_text, ctx.window, &consumed));
            if let Some(sp) = span {
                consumed.push(sp);
                fields.push((i, located_field(f, sp)));
            }
        }

        if fields.is_empty() {
            continue;
        }
        fields.sort_by_key(|(i, _)| *i);
        out.push(RawEntry {
            title: draft.title.clone(),
            kind: draft.kind,
            fields: fields.into_iter().map(|(_, rf)| rf).collect(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text_import::model::{EntryKind, FieldType, Span};
    use crate::text_import::preparse::split_blocks;
    use crate::text_import::engine::extractor::{RawEntryDraft, RawFieldDraft};

    fn draft(kind: EntryKind, fields: &[(FieldType, &str)]) -> RawEntryDraft {
        RawEntryDraft {
            title: None,
            kind,
            fields: fields.iter().map(|(t, v)| RawFieldDraft { field_type: *t, verbatim_text: (*v).into() }).collect(),
        }
    }
    fn whole(src: &str) -> Span { Span { start: 0, end: src.len() } }

    #[test]
    fn locates_verbatim_fields_and_sets_echoed_value() {
        let src = "user: bob\npass: secret";
        let blocks = split_blocks(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks };
        let d = draft(EntryKind::Login, &[(FieldType::Login, "bob"), (FieldType::Password, "secret")]);
        let entries = locate(&ctx, &[d]);
        assert_eq!(entries.len(), 1);
        for f in &entries[0].fields {
            assert_eq!(&src[f.span.start..f.span.end], f.echoed_value.as_deref().unwrap());
        }
        let pass = entries[0].fields.iter().find(|f| f.field_type == FieldType::Password).unwrap();
        assert_eq!(&src[pass.span.start..pass.span.end], "secret");
    }

    #[test]
    fn repeated_value_in_one_entry_gets_distinct_spans() {
        let src = "pin: 1234\nconfirm: 1234";
        let blocks = split_blocks(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks };
        let d = draft(EntryKind::SecureNote, &[(FieldType::Note, "1234"), (FieldType::Note, "1234")]);
        let entries = locate(&ctx, &[d]);
        assert_eq!(entries[0].fields.len(), 2);
        assert_ne!(entries[0].fields[0].span, entries[0].fields[1].span, "distinct occurrences");
    }

    #[test]
    fn duplicate_value_across_blocks_stays_in_its_own_block() {
        let src = "site: https://a.com\npass: x\n\nsite: https://b.com\npass: x";
        let blocks = split_blocks(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks };
        let d0 = draft(EntryKind::Login, &[(FieldType::Url, "https://a.com"), (FieldType::Password, "x")]);
        let d1 = draft(EntryKind::Login, &[(FieldType::Url, "https://b.com"), (FieldType::Password, "x")]);
        let entries = locate(&ctx, &[d0, d1]);
        let p0 = entries[0].fields.iter().find(|f| f.field_type == FieldType::Password).unwrap();
        let p1 = entries[1].fields.iter().find(|f| f.field_type == FieldType::Password).unwrap();
        assert!(p0.span.start < p1.span.start);
        let a0 = entries[0].fields.iter().find(|f| f.field_type == FieldType::Url).unwrap();
        let a1 = entries[1].fields.iter().find(|f| f.field_type == FieldType::Url).unwrap();
        assert_eq!(block_of(&blocks, p0.span.start), block_of(&blocks, a0.span.start));
        assert_eq!(block_of(&blocks, p1.span.start), block_of(&blocks, a1.span.start));
    }

    #[test]
    fn hallucinated_text_is_flagged_not_guessed() {
        let src = "user: bob\npass: secret";
        let blocks = split_blocks(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks };
        let d = draft(EntryKind::Login, &[(FieldType::Login, "bob"), (FieldType::Password, "hunter3")]);
        let entries = locate(&ctx, &[d]);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].fields.iter().all(|f| f.field_type != FieldType::Password), "hallucinated password dropped");
        assert_eq!(entries[0].fields.len(), 1, "only the real 'bob' survives");
    }

    #[test]
    fn entry_with_no_locatable_field_is_omitted() {
        let src = "nothing useful here";
        let blocks = split_blocks(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks };
        let d = draft(EntryKind::Login, &[(FieldType::Password, "ghost")]);
        assert!(locate(&ctx, &[d]).is_empty());
    }

    #[test]
    fn repeated_non_ascii_value_does_not_panic_and_gets_distinct_spans() {
        let src = "ключ: пароль\nдубль: пароль";
        let blocks = split_blocks(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks };
        let d = draft(EntryKind::SecureNote, &[(FieldType::Note, "пароль"), (FieldType::Note, "пароль")]);
        let entries = locate(&ctx, &[d]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fields.len(), 2);
        assert_ne!(entries[0].fields[0].span, entries[0].fields[1].span, "distinct occurrences");
        for f in &entries[0].fields {
            assert_eq!(&src[f.span.start..f.span.end], "пароль");
        }
    }

    /// One address shared by two accounts: each draft must land on its own
    /// occurrence, not both on the first one (which left the second block
    /// empty and split it off as an untitled floor entry).
    #[test]
    fn same_value_in_two_entries_lands_on_two_occurrences() {
        let src = "GitHub\nlogin: jane@example.com\n\nGoogle\nuser: jane@example.com";
        let blocks = split_blocks(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks };
        let a = draft(EntryKind::Login, &[(FieldType::Login, "jane@example.com")]);
        let b = draft(EntryKind::Login, &[(FieldType::Login, "jane@example.com")]);
        let entries = locate(&ctx, &[a, b]);
        assert_eq!(entries.len(), 2);
        assert_eq!(block_of(&blocks, entries[0].fields[0].span.start), Some(blocks[0]));
        assert_eq!(block_of(&blocks, entries[1].fields[0].span.start), Some(blocks[1]));
    }

    /// A value the model cut short must not claim the head of a longer token:
    /// that span would shadow the real value, which the heuristic floor can then
    /// no longer place (the e-mail vanished from the proposal).
    #[test]
    fn truncated_value_does_not_match_inside_a_longer_token() {
        let src = "логин: ivan.petrov\n\nадрес: ivan.petrov@mail.ru";
        let blocks = split_blocks(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks };
        let a = draft(EntryKind::Login, &[(FieldType::Login, "ivan.petrov")]);
        let b = draft(EntryKind::Login, &[(FieldType::Login, "ivan.petrov")]);
        let entries = locate(&ctx, &[a, b]);
        assert_eq!(entries.len(), 1, "got {entries:?}");
        assert_eq!(block_of(&blocks, entries[0].fields[0].span.start), Some(blocks[0]));
    }

    #[test]
    fn value_bounded_by_punctuation_still_matches() {
        let src = "admin / R0uter-Adm1n!, pass=hunter2";
        let blocks = split_blocks(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks };
        let d = draft(EntryKind::Login, &[(FieldType::Password, "R0uter-Adm1n!"), (FieldType::Password, "hunter2")]);
        let entries = locate(&ctx, &[d]);
        assert_eq!(entries[0].fields.len(), 2);
    }
}

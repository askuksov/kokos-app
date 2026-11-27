//! The locator (security-core): turns the extractor's verbatim-text drafts into
//! source spans. Every span is produced by FINDING the exact text in the source
//! (never trusting a model offset); a text not found is dropped (flagged), never
//! approximated. Sets `echoed_value = verbatim_text` so `integrity::validate`
//! independently re-checks `source[span] == verbatim_text`.

use crate::text_import::engine::extractor::{RawEntryDraft, RawFieldDraft};
use crate::text_import::model::{FieldType, RawEntry, RawField, Span};

/// Search context for one chunk: the full `source` (spans are absolute into it),
/// the chunk's byte `window`, the block spans within the window, and the spans
/// of the pre-parser hints (`extract_hints`) that lie in the window.
pub struct LocateCtx<'a> {
    pub source: &'a str,
    pub window: Span,
    pub blocks: &'a [Span],
    pub hints: &'a [Span],
}

/// Confidence stamped on an LLM-located field (heuristic-floor fields keep their
/// own pre-parser confidence; the review-UI shows this).
const LLM_CONFIDENCE: f32 = 0.7;

/// Confidence of a field bound only by the sentence-final-dot fallback. Kept
/// below the review UI's low-confidence threshold (0.5), so the review flags
/// it: the dot may still belong to the value (`password - Qwerty123.`).
const FALLBACK_CONFIDENCE: f32 = 0.4;

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

/// `cand` is a whole token except for one sentence-final dot right after it
/// (`The password is hunter2.`): the dot is followed by whitespace or the end.
fn is_whole_before_final_dot(source: &str, cand: Span) -> bool {
    let before = source[..cand.start].chars().next_back();
    let mut rest = source[cand.end..].chars();
    !before.is_some_and(continues_token) && rest.next() == Some('.') && rest.next().map_or(true, char::is_whitespace)
}

/// A pre-parser hint claims a different extent over `cand` (`pass: abc.` holds
/// the value `abc.`): cutting the dot off would yield a silently wrong secret.
/// A hint with exactly `cand`'s span confirms the boundary instead.
fn conflicts_with_hint(hints: &[Span], cand: Span) -> bool {
    hints.iter().any(|h| *h != cand && overlaps(*h, cand))
}

/// The first occurrence of `needle` within `region` that starts before
/// `max_start`, does not overlap an already-consumed span and passes `accept`.
fn scan(
    source: &str,
    needle: &str,
    region: Span,
    max_start: usize,
    consumed: &[Span],
    accept: impl Fn(Span) -> bool,
) -> Option<Span> {
    let hay = &source[region.start..region.end];
    let mut from = 0usize;
    while let Some(rel) = hay[from..].find(needle) {
        let start = region.start + from + rel;
        if start >= max_start {
            break;
        }
        let cand = Span { start, end: start + needle.len() };
        if accept(cand) && !consumed.iter().any(|c| overlaps(*c, cand)) {
            return Some(cand);
        }
        from += rel + needle.chars().next().map_or(1, |c| c.len_utf8());
        if from > hay.len() {
            break;
        }
    }
    None
}

/// Find the first occurrence of `needle` within `region` that is a whole token,
/// starts before `max_start`, and does not overlap an already-consumed span.
/// Only when no such occurrence exists, a fallback pass accepts one followed by
/// a sentence-final dot, provided no pre-parser hint reads that text with a
/// different extent. `region` is char-aligned (a block or the chunk window), so
/// the returned span is char-aligned. Returns the span and whether only the
/// fallback found it; `None` for an empty needle or no free occurrence.
fn find_in(
    source: &str,
    needle: &str,
    region: Span,
    max_start: usize,
    consumed: &[Span],
    hints: &[Span],
) -> Option<(Span, bool)> {
    if needle.is_empty() || region.end > source.len() || region.start > region.end {
        return None;
    }
    if let Some(sp) = scan(source, needle, region, max_start, consumed, |c| is_whole(source, c)) {
        return Some((sp, false));
    }
    scan(source, needle, region, max_start, consumed, |c| {
        is_whole_before_final_dot(source, c) && !conflicts_with_hint(hints, c)
    })
    .map(|sp| (sp, true))
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

fn located_field(f: &RawFieldDraft, span: Span, by_fallback: bool) -> RawField {
    RawField {
        field_type: f.field_type,
        span,
        echoed_value: Some(f.verbatim_text.clone()),
        confidence: if by_fallback { FALLBACK_CONFIDENCE } else { LLM_CONFIDENCE },
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
        // The block is the unit of an entry: the first field found (the anchor
        // when it is locatable) binds the draft to its block, and every later
        // field must start inside that block. A field the model took from
        // another block is dropped, never bound (a URL from the next block
        // would otherwise pair a site with someone else's login).
        let mut block: Option<Span> = None;
        let order = anchor.into_iter().chain((0..draft.fields.len()).filter(|i| Some(*i) != anchor));
        for i in order {
            let f = &draft.fields[i];
            // A value may run past its block's end (a note with a blank line),
            // but it has to start inside the block.
            let span = match block {
                Some(b) => find_in(
                    ctx.source,
                    &f.verbatim_text,
                    Span { start: b.start, end: ctx.window.end },
                    b.end,
                    &consumed,
                    ctx.hints,
                ),
                None => find_in(ctx.source, &f.verbatim_text, ctx.window, ctx.window.end, &consumed, ctx.hints),
            };
            if let Some((sp, by_fallback)) = span {
                consumed.push(sp);
                fields.push((i, located_field(f, sp, by_fallback)));
                if block.is_none() {
                    block = Some(block_of(ctx.blocks, sp.start).unwrap_or(sp));
                }
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
    use crate::text_import::preparse::{extract_hints, split_blocks};
    use crate::text_import::engine::extractor::{RawEntryDraft, RawFieldDraft};

    fn draft(kind: EntryKind, fields: &[(FieldType, &str)]) -> RawEntryDraft {
        RawEntryDraft {
            title: None,
            kind,
            fields: fields.iter().map(|(t, v)| RawFieldDraft { field_type: *t, verbatim_text: (*v).into() }).collect(),
        }
    }
    fn whole(src: &str) -> Span { Span { start: 0, end: src.len() } }
    fn hint_spans(src: &str) -> Vec<Span> { extract_hints(src).into_iter().map(|h| h.span).collect() }

    #[test]
    fn locates_verbatim_fields_and_sets_echoed_value() {
        let src = "user: bob\npass: secret";
        let blocks = split_blocks(src);
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
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
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
        let d = draft(EntryKind::SecureNote, &[(FieldType::Note, "1234"), (FieldType::Note, "1234")]);
        let entries = locate(&ctx, &[d]);
        assert_eq!(entries[0].fields.len(), 2);
        assert_ne!(entries[0].fields[0].span, entries[0].fields[1].span, "distinct occurrences");
    }

    #[test]
    fn duplicate_value_across_blocks_stays_in_its_own_block() {
        let src = "site: https://a.com\npass: x\n\nsite: https://b.com\npass: x";
        let blocks = split_blocks(src);
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
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
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
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
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
        let d = draft(EntryKind::Login, &[(FieldType::Password, "ghost")]);
        assert!(locate(&ctx, &[d]).is_empty());
    }

    #[test]
    fn repeated_non_ascii_value_does_not_panic_and_gets_distinct_spans() {
        let src = "ключ: пароль\nдубль: пароль";
        let blocks = split_blocks(src);
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
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
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
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
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
        let a = draft(EntryKind::Login, &[(FieldType::Login, "ivan.petrov")]);
        let b = draft(EntryKind::Login, &[(FieldType::Login, "ivan.petrov")]);
        let entries = locate(&ctx, &[a, b]);
        assert_eq!(entries.len(), 1, "got {entries:?}");
        assert_eq!(block_of(&blocks, entries[0].fields[0].span.start), Some(blocks[0]));
    }

    /// A draft that mixes two blocks keeps only the fields of the block its
    /// first located field sits in; the other block's fields stay unbound.
    #[test]
    fn fields_from_another_block_are_not_bound_to_the_entry() {
        let src = "site: https://a.com\nuser: alice\n\nsite: https://b.com\nuser: bob\npass: b-secret";
        let blocks = split_blocks(src);
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
        let d = draft(
            EntryKind::Login,
            &[(FieldType::Url, "https://a.com"), (FieldType::Login, "bob"), (FieldType::Password, "b-secret"), (FieldType::Login, "alice")],
        );
        let entries = locate(&ctx, &[d]);
        assert_eq!(entries.len(), 1);
        let vals: Vec<&str> = entries[0].fields.iter().map(|f| &src[f.span.start..f.span.end]).collect();
        assert_eq!(vals, ["https://a.com", "alice"], "got {vals:?}");
        assert!(entries[0].fields.iter().all(|f| block_of(&blocks, f.span.start) == Some(blocks[0])));
    }

    /// Without a locatable anchor the first field found binds the block.
    #[test]
    fn unlocatable_anchor_binds_to_the_first_found_field_block() {
        let src = "user: alice\npass: a-secret\n\nsite: https://b.com\nuser: bob";
        let blocks = split_blocks(src);
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
        let d = draft(
            EntryKind::Login,
            &[(FieldType::Url, "https://ghost.example"), (FieldType::Password, "a-secret"), (FieldType::Login, "bob")],
        );
        let entries = locate(&ctx, &[d]);
        assert_eq!(entries.len(), 1);
        let vals: Vec<&str> = entries[0].fields.iter().map(|f| &src[f.span.start..f.span.end]).collect();
        assert_eq!(vals, ["a-secret"], "got {vals:?}");
    }

    /// A multi-line value may run past its block's blank line as long as it
    /// starts inside the entry's block.
    #[test]
    fn value_starting_in_the_block_may_cross_a_blank_line() {
        let src = "site: https://a.com\nnote: line one\n\nline two";
        let blocks = split_blocks(src);
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
        let d = draft(EntryKind::Login, &[(FieldType::Url, "https://a.com"), (FieldType::Note, "line one\n\nline two")]);
        let entries = locate(&ctx, &[d]);
        assert_eq!(entries[0].fields.len(), 2);
    }

    #[test]
    fn value_bounded_by_punctuation_still_matches() {
        let src = "admin / R0uter-Adm1n!, pass=hunter2";
        let blocks = split_blocks(src);
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
        let d = draft(EntryKind::Login, &[(FieldType::Password, "R0uter-Adm1n!"), (FieldType::Password, "hunter2")]);
        let entries = locate(&ctx, &[d]);
        assert_eq!(entries[0].fields.len(), 2);
    }

    /// Prose ends a value with a full stop: with no hint claiming the dot, the
    /// fallback pass binds the draft's text.
    #[test]
    fn value_before_a_sentence_final_dot_is_located() {
        let src = "The password is hunter2.";
        let blocks = split_blocks(src);
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
        let d = draft(EntryKind::Login, &[(FieldType::Password, "hunter2")]);
        let entries = locate(&ctx, &[d]);
        assert_eq!(entries.len(), 1, "got {entries:?}");
        let f = &entries[0].fields[0];
        assert_eq!(&src[f.span.start..f.span.end], "hunter2");
    }

    /// `pass: abc.` holds the value `abc.`: a draft cut short at the dot must
    /// not bind (the floor keeps the full hint instead).
    #[test]
    fn draft_cut_at_a_labelled_value_dot_is_not_bound() {
        let src = "pass: abc.";
        let blocks = split_blocks(src);
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
        let d = draft(EntryKind::Login, &[(FieldType::Password, "abc")]);
        assert!(locate(&ctx, &[d]).is_empty());
    }

    /// The strict pass wins: a whole-token occurrence later in the block is
    /// preferred over an earlier one followed by a dot.
    #[test]
    fn whole_token_occurrence_is_preferred_over_a_dotted_one() {
        let src = "note: try hunter2. then
pass: hunter2";
        let blocks = split_blocks(src);
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
        let d = draft(EntryKind::Login, &[(FieldType::Password, "hunter2")]);
        let entries = locate(&ctx, &[d]);
        let f = &entries[0].fields[0];
        assert_eq!(f.span.start, src.rfind("hunter2").unwrap());
    }

    /// A URL that ends a sentence: the trimmed URL hint confirms the boundary.
    #[test]
    fn url_before_a_full_stop_is_located() {
        let src = "Sign in at https://a.example.com/login.
user: alice";
        let blocks = split_blocks(src);
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
        let d = draft(EntryKind::Login, &[(FieldType::Url, "https://a.example.com/login"), (FieldType::Login, "alice")]);
        let entries = locate(&ctx, &[d]);
        let vals: Vec<&str> = entries[0].fields.iter().map(|f| &src[f.span.start..f.span.end]).collect();
        assert_eq!(vals, ["https://a.example.com/login", "alice"], "got {vals:?}");
    }

    /// No `key: value` hint covers these lines, so the dot fallback binds the
    /// value without its dot. The dot may be part of the secret: the field must
    /// come out below the review's low-confidence threshold (0.5).
    #[test]
    fn dot_fallback_binding_is_flagged_as_low_confidence() {
        for src in [
            "1. password: Qwerty123.",
            "Password (bank): Qwerty123.",
            "Gmail — pass: Qwerty123.",
            "Password - Qwerty123.",
        ] {
            let blocks = split_blocks(src);
            let hints = hint_spans(src);
            let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
            let d = draft(EntryKind::Login, &[(FieldType::Password, "Qwerty123")]);
            let entries = locate(&ctx, &[d]);
            assert_eq!(entries.len(), 1, "{src:?}: got {entries:?}");
            let f = &entries[0].fields[0];
            assert_eq!(&src[f.span.start..f.span.end], "Qwerty123", "{src:?}");
            assert!(f.confidence < 0.5, "{src:?}: confidence {}", f.confidence);
        }
    }

    /// A strict whole-token match keeps the normal model confidence.
    #[test]
    fn strict_binding_keeps_the_model_confidence() {
        let src = "pass: Qwerty123";
        let blocks = split_blocks(src);
        let hints = hint_spans(src);
        let ctx = LocateCtx { source: src, window: whole(src), blocks: &blocks, hints: &hints };
        let d = draft(EntryKind::Login, &[(FieldType::Password, "Qwerty123")]);
        assert_eq!(locate(&ctx, &[d])[0].fields[0].confidence, LLM_CONFIDENCE);
    }
}

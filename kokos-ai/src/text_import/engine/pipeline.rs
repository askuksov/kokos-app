//! Per-file assembly: heuristic pre-parse (blocks + hints) → chunk → extract → locate →
//! merge the deterministic heuristic floor (blocks the extractor dropped) →
//! merge entries split within one block → note blocks that yielded nothing →
//! `integrity::validate` against THIS file's buffer → `ImportProposal`.
//! The multi-file merge lives in the Tauri command; this is one file.

use crate::text_import::engine::chunker::chunk_blocks;
use crate::text_import::engine::extractor::{Extractor, FieldHint};
use crate::text_import::engine::locator::{block_of, locate, overlaps, LocateCtx};
use crate::text_import::engine::reconcile::reconcile;
use crate::text_import::integrity::{materialize, validate};
use crate::text_import::model::{
    EntryKind, FieldType, ImportProposal, RawEntry, RawProposal, Span, UnparsedBlock,
};
use crate::text_import::preparse::{extract_hints, pre_parse, split_blocks};
use crate::AiError;

/// Materialize the pre-parser high-confidence hints whose span falls inside `window`.
pub fn hints_for(source: &str, window: Span) -> Vec<FieldHint> {
    extract_hints(source)
        .into_iter()
        .filter(|h| h.span.start >= window.start && h.span.end <= window.end)
        .filter_map(|h| {
            materialize(source, &h.span)
                .ok()
                .map(|text| FieldHint { field_type: h.field_type, text })
        })
        .collect()
}

/// Analyze one file's text into a validated `ImportProposal`. `chunk_budget` is
/// the byte budget per chunk (the caller derives it from the model ctx window).
pub fn analyze_text(
    source: &str,
    extractor: &dyn Extractor,
    chunk_budget: usize,
) -> Result<ImportProposal, AiError> {
    analyze_text_with_progress(source, extractor, chunk_budget, &mut |_, _| {})
}

/// Same as `analyze_text`, additionally calling `on_chunk(done, total)` before
/// the first chunk (`done == 0`) and after every extracted chunk.
pub fn analyze_text_with_progress(
    source: &str,
    extractor: &dyn Extractor,
    chunk_budget: usize,
    on_chunk: &mut dyn FnMut(usize, usize),
) -> Result<ImportProposal, AiError> {
    let blocks = split_blocks(source);
    let chunks = chunk_blocks(&blocks, chunk_budget.max(1));
    let chunks_total = chunks.len();
    on_chunk(0, chunks_total);

    let mut located: Vec<RawEntry> = Vec::new();
    for (ci, chunk) in chunks.iter().enumerate() {
        let chunk_text = match source.get(chunk.start..chunk.end) {
            Some(t) => t,
            None => continue,
        };
        let hints = hints_for(source, *chunk);
        let drafts = extractor.extract(chunk_text, &hints)?;
        let blocks_in_chunk: Vec<Span> =
            blocks.iter().copied().filter(|b| overlaps(*b, *chunk)).collect();
        let ctx = LocateCtx { source, window: *chunk, blocks: &blocks_in_chunk };
        located.extend(locate(&ctx, &drafts));
        on_chunk(ci + 1, chunks_total);
    }

    keep_labelled_secrets_masked(source, &mut located);

    let mut covered: Vec<Span> = located.iter().flat_map(|e| e.fields.iter().map(|f| f.span)).collect();
    for fe in pre_parse(source).entries {
        let fe_block = fe.fields.first().and_then(|f| block_of(&blocks, f.span.start));
        let block_has_located = fe_block.map_or(false, |b| covered.iter().any(|s| overlaps(*s, b)));
        if !block_has_located {
            for f in &fe.fields {
                covered.push(f.span);
            }
            located.push(fe);
        } else {
            for ff in fe.fields {
                if covered.iter().any(|s| overlaps(*s, ff.span)) {
                    continue;
                }
                covered.push(ff.span);
                if let Some(e) = located
                    .iter_mut()
                    .find(|e| e.fields.iter().any(|lf| block_of(&blocks, lf.span.start) == fe_block))
                {
                    e.fields.push(ff);
                }
            }
        }
    }

    merge_same_block_entries(&mut located, &blocks);
    merge_orphan_url_entries(&mut located, &blocks);
    let unparsed = unparsed_blocks(source, &blocks, &located);

    let mut proposal = validate(source, RawProposal { entries: located }).map_err(|e| {
        use crate::text_import::integrity::IntegrityError;
        let msg = match &e {
            IntegrityError::SpanOutOfBounds { start, end, len } => {
                format!("integrity: span out of bounds ({start}..{end}, len {len})")
            }
            IntegrityError::NotCharBoundary { start, end } => {
                format!("integrity: span not on a char boundary ({start}..{end})")
            }
            IntegrityError::ValueNotVerbatim { field_type, .. } => {
                format!("integrity: value not verbatim in source (field_type {field_type:?})")
            }
        };
        AiError::Backend(msg)
    })?;
    proposal.unparsed = unparsed;
    reconcile(&mut proposal);
    Ok(proposal)
}

/// An SSID is shown in the clear. Where the model calls a value an SSID but its
/// label reads as a secret ("network password is: X"), the secret type wins.
fn keep_labelled_secrets_masked(source: &str, located: &mut [RawEntry]) {
    let hints = extract_hints(source);
    for f in located.iter_mut().flat_map(|e| e.fields.iter_mut()) {
        if f.field_type != FieldType::Ssid {
            continue;
        }
        if let Some(h) = hints.iter().find(|h| overlaps(h.span, f.span) && is_secret(h.field_type)) {
            f.field_type = h.field_type;
        }
    }
}

fn is_secret(ft: FieldType) -> bool {
    matches!(
        ft,
        FieldType::Password | FieldType::ApiKey | FieldType::TotpSecret | FieldType::SecurityAnswer
    )
}

/// Field types one account holds at most once. Two entries that both carry one
/// of these are two accounts, not halves of one; URLs and notes repeat freely.
fn is_single_valued(ft: FieldType) -> bool {
    !matches!(ft, FieldType::Url | FieldType::Note)
}

fn normalized_title(e: &RawEntry) -> Option<String> {
    e.title.as_deref().map(|t| t.trim().to_lowercase()).filter(|t| !t.is_empty())
}

/// The one block every field of `e` lies in; `None` if the fields straddle
/// blocks or there are none.
fn sole_block(blocks: &[Span], e: &RawEntry) -> Option<Span> {
    let first = block_of(blocks, e.fields.first()?.span.start)?;
    e.fields
        .iter()
        .all(|f| block_of(blocks, f.span.start) == Some(first))
        .then_some(first)
}

/// Fold together entries the extractor split out of ONE block (login in one,
/// password in the other). "One block = one entry" is unsafe — a block without
/// blank lines may hold two accounts — so a pair merges only when both lie
/// wholly in the same block, their titles match (case-insensitive, both absent
/// counts as a match) and no single-valued field type appears in both. Spans are
/// moved, never rewritten, so the verbatim chokepoint still sees source slices.
fn merge_same_block_entries(located: &mut Vec<RawEntry>, blocks: &[Span]) {
    let mut i = 0;
    while i < located.len() {
        let Some(block) = sole_block(blocks, &located[i]) else {
            i += 1;
            continue;
        };
        let mut j = i + 1;
        while j < located.len() {
            let (a, b) = (&located[i], &located[j]);
            let conflict = b
                .fields
                .iter()
                .any(|f| is_single_valued(f.field_type) && a.fields.iter().any(|g| g.field_type == f.field_type));
            if sole_block(blocks, b) == Some(block) && normalized_title(a) == normalized_title(b) && !conflict {
                let other = located.remove(j);
                let target = &mut located[i];
                if target.kind == EntryKind::SecureNote {
                    target.kind = other.kind;
                }
                target.fields.extend(other.fields);
                target.fields.sort_by_key(|f| f.span.start);
            } else {
                j += 1;
            }
        }
        i += 1;
    }
}

/// Blocks no located field falls in, sliced verbatim — the part of the file the
/// review UI must flag as not parsed instead of showing a clean result.
fn unparsed_blocks(source: &str, blocks: &[Span], located: &[RawEntry]) -> Vec<UnparsedBlock> {
    blocks
        .iter()
        .filter(|b| !located.iter().any(|e| e.fields.iter().any(|f| overlaps(f.span, **b))))
        .filter_map(|b| source.get(b.start..b.end))
        .map(|text| UnparsedBlock { text: text.to_string(), source_file: None })
        .collect()
}

/// Fold an entry whose fields are ALL URLs — a bare-URL block the file separated
/// from its login by a blank line — into the nearest preceding entry
/// (by source position) that carries a credential field in the same block or
/// the block right above. Only pure-URL orphans move, so a note or a standalone
/// bookmark list (no credential entry next to it) is never over-merged, and a
/// URL never jumps over a block to land in an unrelated account. Operates on
/// located `RawEntry`s (spans intact) BEFORE the verbatim chokepoint, so the
/// moved fields stay verbatim-materializable.
fn merge_orphan_url_entries(located: &mut Vec<RawEntry>, blocks: &[Span]) {
    let start_of = |e: &RawEntry| e.fields.iter().map(|f| f.span.start).min().unwrap_or(usize::MAX);
    let is_url_only = |e: &RawEntry| !e.fields.is_empty() && e.fields.iter().all(|f| f.field_type == FieldType::Url);
    let has_credential = |e: &RawEntry| {
        e.fields.iter().any(|f| {
            matches!(
                f.field_type,
                FieldType::Login | FieldType::Password | FieldType::Email | FieldType::TotpSecret | FieldType::ApiKey
            )
        })
    };

    let block_index = |pos: usize| blocks.iter().position(|b| pos >= b.start && pos < b.end);
    let near = |e: &RawEntry, orphan_block: Option<usize>| {
        let Some(ob) = orphan_block else { return false };
        e.fields
            .iter()
            .filter_map(|f| block_index(f.span.start))
            .any(|b| b == ob || b + 1 == ob)
    };

    let n = located.len();
    let starts: Vec<usize> = located.iter().map(|e| start_of(e)).collect();
    let mut target: Vec<Option<usize>> = vec![None; n];
    for i in 0..n {
        if !is_url_only(&located[i]) {
            continue;
        }
        let mut best: Option<usize> = None;
        for j in 0..n {
            if j == i
                || starts[j] >= starts[i]
                || !has_credential(&located[j])
                || !near(&located[j], block_index(starts[i]))
            {
                continue;
            }
            if best.map_or(true, |b| starts[j] > starts[b]) {
                best = Some(j);
            }
        }
        target[i] = best;
    }
    let mut removed = vec![false; n];
    for i in 0..n {
        if let Some(t) = target[i] {
            let fields = std::mem::take(&mut located[i].fields);
            located[t].fields.extend(fields);
            removed[i] = true;
        }
    }
    let mut idx = 0;
    located.retain(|_| {
        let keep = !removed[idx];
        idx += 1;
        keep
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text_import::engine::extractor::{FakeExtractor, RawEntryDraft, RawFieldDraft};
    use crate::text_import::model::{EntryKind, FieldType};

    fn draft(kind: EntryKind, fields: &[(FieldType, &str)]) -> RawEntryDraft {
        RawEntryDraft {
            title: None,
            kind,
            fields: fields.iter().map(|(t, v)| RawFieldDraft { field_type: *t, verbatim_text: (*v).into() }).collect(),
        }
    }

    fn titled(title: &str, kind: EntryKind, fields: &[(FieldType, &str)]) -> RawEntryDraft {
        RawEntryDraft { title: Some(title.into()), ..draft(kind, fields) }
    }

    /// A real-world test file: the extractor split each login block in two.
    const THREE_BLOCKS: &str = "Netflix\nuser: anna.k@example.com\npassword: Rw8kzQ2pLm\n\n\
        Bank of Nowhere\nuser: anna_k\npassword: 7HdttQ9vvz\nhttps://bank.example.com\n\n\
        Home wifi\nnetwork: Casa\nkey: sunflower-42-orange";

    #[test]
    fn entries_split_out_of_one_block_are_merged_back() {
        let fake = FakeExtractor {
            scripted: vec![
                titled("Netflix", EntryKind::Login, &[(FieldType::Login, "anna.k@example.com")]),
                titled("Netflix", EntryKind::Login, &[(FieldType::Password, "Rw8kzQ2pLm")]),
                titled("Bank of Nowhere", EntryKind::Login, &[
                    (FieldType::Login, "anna_k"),
                    (FieldType::Url, "https://bank.example.com"),
                ]),
                titled("Bank of Nowhere", EntryKind::Login, &[(FieldType::Password, "7HdttQ9vvz")]),
            ],
        };
        let proposal = analyze_text(THREE_BLOCKS, &fake, 4096).unwrap();
        let logins: Vec<_> = proposal.entries.iter().filter(|e| e.kind == EntryKind::Login).collect();
        assert_eq!(logins.len(), 2, "one login per block, got {:?}", proposal.entries);
        for (title, pw) in [("Netflix", "Rw8kzQ2pLm"), ("Bank of Nowhere", "7HdttQ9vvz")] {
            let e = logins.iter().find(|e| e.title.as_deref() == Some(title)).unwrap();
            assert!(e.fields.iter().any(|f| f.field_type == FieldType::Password && f.value == pw));
            assert!(e.fields.iter().any(|f| f.field_type == FieldType::Login));
        }
        assert!(
            proposal.entries.iter().any(|e| e.kind == EntryKind::Wifi),
            "the wifi block is recovered by the floor"
        );
        assert!(proposal.unparsed.is_empty(), "every block produced an entry");
    }

    #[test]
    fn two_accounts_in_one_block_are_not_merged() {
        let src = "Shared\nuser: alice\npass: a1ice-pw\nuser: bob\npass: b0b-pw";
        let fake = FakeExtractor {
            scripted: vec![
                titled("Shared", EntryKind::Login, &[(FieldType::Login, "alice"), (FieldType::Password, "a1ice-pw")]),
                titled("Shared", EntryKind::Login, &[(FieldType::Login, "bob"), (FieldType::Password, "b0b-pw")]),
            ],
        };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        assert_eq!(proposal.entries.len(), 2, "same title, but both carry a login and a password");
    }

    #[test]
    fn same_block_entries_with_different_titles_are_not_merged() {
        let src = "user: alice\npass: a1ice-pw";
        let fake = FakeExtractor {
            scripted: vec![
                titled("Mail", EntryKind::Login, &[(FieldType::Login, "alice")]),
                titled("Forum", EntryKind::Login, &[(FieldType::Password, "a1ice-pw")]),
            ],
        };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        assert_eq!(proposal.entries.len(), 2);
    }

    #[test]
    fn entries_from_different_blocks_are_not_merged() {
        let src = "Netflix\nuser: anna\n\nNetflix\npass: Rw8kzQ2pLm";
        let fake = FakeExtractor {
            scripted: vec![
                titled("Netflix", EntryKind::Login, &[(FieldType::Login, "anna")]),
                titled("Netflix", EntryKind::Login, &[(FieldType::Password, "Rw8kzQ2pLm")]),
            ],
        };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        assert_eq!(proposal.entries.len(), 2, "a blank line is a boundary the merge never crosses");
    }

    #[test]
    fn a_block_that_yields_nothing_is_reported_verbatim() {
        let src = "user: bob\npass: s3cret!\n\nremember to renew the domain\nbefore March";
        let fake = FakeExtractor {
            scripted: vec![draft(EntryKind::Login, &[(FieldType::Login, "bob"), (FieldType::Password, "s3cret!")])],
        };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        assert_eq!(proposal.entries.len(), 1);
        assert_eq!(proposal.unparsed.len(), 1);
        assert_eq!(proposal.unparsed[0].text, "remember to renew the domain\nbefore March");
        assert!(proposal.unparsed[0].source_file.is_none(), "the app stamps the file, not kokos-ai");
    }

    #[test]
    fn every_value_in_the_proposal_is_a_verbatim_source_substring() {
        let src = "site: https://gh.com\nuser: octocat\npass: hunter2";
        let fake = FakeExtractor {
            scripted: vec![draft(EntryKind::Login, &[
                (FieldType::Url, "https://gh.com"),
                (FieldType::Login, "octocat"),
                (FieldType::Password, "hunter2"),
            ])],
        };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        assert!(!proposal.entries.is_empty());
        for e in &proposal.entries {
            for f in &e.fields {
                assert!(src.contains(&f.value), "value {:?} not verbatim in source", f.value);
            }
        }
    }

    #[test]
    fn hallucinated_field_is_dropped_and_proposal_still_validates() {
        let src = "user: bob\npass: secret";
        let fake = FakeExtractor {
            scripted: vec![draft(EntryKind::Login, &[
                (FieldType::Login, "bob"),
                (FieldType::Password, "TOTALLY-MADE-UP"),
            ])],
        };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        for e in &proposal.entries {
            for f in &e.fields {
                assert!(src.contains(&f.value));
                assert_ne!(f.value, "TOTALLY-MADE-UP");
            }
        }
    }

    /// Bench regression: the model read "guest network password is:
    /// X" as a network name. The label says password; an SSID is shown in the
    /// clear, so a secret must never be relabelled into one.
    #[test]
    fn model_ssid_does_not_unmask_a_labelled_password() {
        let src = "The guest\nnetwork password is: Guest-Wifi-2026";
        let fake = FakeExtractor { scripted: vec![draft(EntryKind::Wifi, &[(FieldType::Ssid, "Guest-Wifi-2026")])] };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        let f = proposal.entries.iter().flat_map(|e| &e.fields).find(|f| f.value == "Guest-Wifi-2026").unwrap();
        assert_eq!(f.field_type, FieldType::Password);
    }

    #[test]
    fn model_ssid_stays_when_the_label_names_the_network() {
        let src = "Home\nwifi: Kovalenko_5G\nпароль: kiwi-lamp-7731";
        let fake = FakeExtractor {
            scripted: vec![draft(EntryKind::Wifi, &[
                (FieldType::Ssid, "Kovalenko_5G"),
                (FieldType::Password, "kiwi-lamp-7731"),
            ])],
        };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        let f = proposal.entries.iter().flat_map(|e| &e.fields).find(|f| f.value == "Kovalenko_5G").unwrap();
        assert_eq!(f.field_type, FieldType::Ssid);
    }

    #[test]
    fn heuristic_floor_fills_a_block_the_extractor_dropped() {
        let src = "api key: sk-live-abc123";
        let fake = FakeExtractor { scripted: vec![] };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        assert!(
            proposal.entries.iter().any(|e| e.fields.iter().any(|f| f.value == "sk-live-abc123")),
            "floor recovered the dropped block"
        );
    }

    #[test]
    fn floor_recovers_a_pw_abbreviated_secret_the_extractor_dropped() {
        let src = "Netflix\nemail netflix.family@example.com\npw: N3tfl1x#share";
        let fake = FakeExtractor {
            scripted: vec![draft(EntryKind::Login, &[(FieldType::Email, "netflix.family@example.com")])],
        };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        assert!(
            proposal.entries.iter().any(|e| e.fields.iter().any(|f| f.value == "N3tfl1x#share")),
            "the pw: secret must survive via the heuristic floor"
        );
        for e in &proposal.entries {
            for f in &e.fields {
                assert!(src.contains(&f.value));
            }
        }
    }

    #[test]
    fn partially_covered_block_recovers_the_dropped_real_field() {
        let src = "user: bob\npass: secret";
        let fake = FakeExtractor {
            scripted: vec![draft(EntryKind::Login, &[
                (FieldType::Login, "bob"),
                (FieldType::Password, "TOTALLY-MADE-UP"),
            ])],
        };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        assert!(
            proposal.entries.iter().any(|e| e.fields.iter().any(|f| f.value == "secret")),
            "real password recovered from the partially-covered block"
        );
        assert!(proposal.entries.iter().any(|e| e.fields.iter().any(|f| f.value == "bob")));
        for e in &proposal.entries {
            for f in &e.fields {
                assert!(src.contains(&f.value));
                assert_ne!(f.value, "TOTALLY-MADE-UP");
            }
        }
    }

    #[test]
    fn merges_bare_urls_and_relabels_lone_password() {
        let src = "jane.doe@example.com\nTest123!\n\n\nhttps://devs.keenthemes.com/\nhttps://themes.getbootstrap.com/signin/";
        let fake = FakeExtractor {
            scripted: vec![draft(EntryKind::Login, &[
                (FieldType::Email, "jane.doe@example.com"),
                (FieldType::Note, "Test123!"),
            ])],
        };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        assert_eq!(proposal.entries.len(), 1, "the orphan URL block merges into the login");
        let e = &proposal.entries[0];
        assert_eq!(e.kind, EntryKind::Login);
        assert!(e.fields.iter().any(|f| f.field_type == FieldType::Email && f.value == "jane.doe@example.com"));
        assert!(
            e.fields.iter().any(|f| f.field_type == FieldType::Password && f.value == "Test123!"),
            "the lone secret-shaped note became a Password"
        );
        assert!(
            e.fields.iter().any(|f| f.field_type == FieldType::Url && f.value == "https://themes.getbootstrap.com/signin/"),
            "the bare URLs are recovered and merged in"
        );
        for f in &e.fields {
            assert!(src.contains(&f.value), "value {:?} not verbatim", f.value);
        }
    }

    #[test]
    fn orphan_url_block_without_a_preceding_credential_stays_separate() {
        let src = "https://a.com\n\nhttps://b.com";
        let fake = FakeExtractor { scripted: vec![] };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        let urls = proposal
            .entries
            .iter()
            .flat_map(|e| e.fields.iter())
            .filter(|f| f.field_type == FieldType::Url)
            .count();
        assert_eq!(urls, 2, "both URLs recovered");
        assert!(proposal.entries.len() >= 2, "no over-merge without a credential target");
    }

    #[test]
    fn orphan_url_does_not_jump_over_a_block() {
        let src = "user: bob\npass: s3cret!\n\nремонт машины в четверг\n\nhttps://bank.example.com";
        let fake = FakeExtractor { scripted: vec![] };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        let bob = proposal
            .entries
            .iter()
            .find(|e| e.fields.iter().any(|f| f.value == "bob"))
            .unwrap();
        assert!(
            !bob.fields.iter().any(|f| f.field_type == FieldType::Url),
            "the URL sits two blocks away, got {:?}",
            proposal.entries
        );
    }

    /// A real-world test file with the extractor returning nothing (what a
    /// malformed model reply used to amount to): the floor alone must keep every
    /// block's fields in that block's entry.
    #[test]
    fn floor_alone_keeps_each_block_whole_on_a_russian_file() {
        let src = "GitHub\nlogin: jane.doe@example.com\npassword: Tr0ub4dor&3-horse\nhttps://github.com/login\n\n\
            Домашний роутер\nwifi: Kovalenko_5G\nпароль: kiwi-lamp-7731\n\n\
            Сбербанк онлайн\nлогин: ivan_petrov\nпароль: Zx9!mQ2#vL\nтел: +380 67 123 45 67\nhttps://online.example-bank.com";
        let fake = FakeExtractor { scripted: vec![] };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        let entry_with = |v: &str| {
            proposal.entries.iter().find(|e| e.fields.iter().any(|f| f.value == v)).unwrap_or_else(|| {
                panic!("{v:?} not in any entry: {:?}", proposal.entries)
            })
        };
        let github = entry_with("Tr0ub4dor&3-horse");
        assert!(!github.fields.iter().any(|f| f.value.contains("example-bank")), "bank URL leaked into GitHub");
        assert_eq!(entry_with("kiwi-lamp-7731").kind, EntryKind::Wifi);
        let bank = entry_with("Zx9!mQ2#vL");
        for v in ["ivan_petrov", "+380 67 123 45 67", "https://online.example-bank.com"] {
            assert!(bank.fields.iter().any(|f| f.value == v), "{v:?} missing from bank entry {bank:?}");
        }
        assert!(proposal.unparsed.is_empty(), "unparsed: {:?}", proposal.unparsed);
    }

    #[test]
    fn pipeline_reconciles_phone_and_lone_answer() {
        use crate::text_import::model::FieldType;
        let src = "phone: +380000000000\nanswer: hunter2";
        let fake = FakeExtractor {
            scripted: vec![draft(EntryKind::Login, &[
                (FieldType::TotpSecret, "+380000000000"),
                (FieldType::SecurityAnswer, "hunter2"),
            ])],
        };
        let proposal = analyze_text(src, &fake, 4096).unwrap();
        let types: Vec<FieldType> =
            proposal.entries.iter().flat_map(|e| e.fields.iter().map(|f| f.field_type)).collect();
        assert!(types.contains(&FieldType::Phone), "phone reclassified away from TotpSecret");
        assert!(!types.contains(&FieldType::TotpSecret), "no TotpSecret survives for a phone value");
        assert!(types.contains(&FieldType::Password), "lone SecurityAnswer became Password");
        for e in &proposal.entries {
            for f in &e.fields {
                assert!(src.contains(&f.value));
            }
        }
    }
}

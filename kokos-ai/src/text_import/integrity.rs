//! The integrity guard — the single chokepoint enforcing the verbatim-span
//! invariant. Field values are produced ONLY by slicing the
//! source; any span that is out of bounds, off a char boundary, or whose
//! `echoed_value` disagrees with `source[span]` is rejected. Both the
//! heuristics and the LLM pass their `RawProposal` through `validate` before
//! anything reaches the review-UI or the vault.

use crate::text_import::model::{
    FieldType, ImportProposal, ProposedEntry, ProposedField, RawProposal, Span,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityError {
    SpanOutOfBounds { start: usize, end: usize, len: usize },
    NotCharBoundary { start: usize, end: usize },
    /// The extractor claimed a value that is not what the source span holds.
    /// `echoed` is retained for the error path only (already in memory); it is
    /// never logged or persisted (Global Constraints).
    ValueNotVerbatim { field_type: FieldType, echoed: String },
}

/// Slice `source[span]` verbatim, or fail. Uses `str::get` so a bad range is an
/// error, never a panic (offsets may land mid-UTF-8).
pub fn materialize(source: &str, span: &Span) -> Result<String, IntegrityError> {
    if span.start > span.end || span.end > source.len() {
        return Err(IntegrityError::SpanOutOfBounds { start: span.start, end: span.end, len: source.len() });
    }
    match source.get(span.start..span.end) {
        Some(s) => Ok(s.to_string()),
        None => Err(IntegrityError::NotCharBoundary { start: span.start, end: span.end }),
    }
}

/// Validate an extractor's raw proposal against the source and materialize every
/// value verbatim. Rejects the whole proposal on the first violation — a
/// tampered/hallucinated field fails closed rather than importing a bad secret.
pub fn validate(source: &str, raw: RawProposal) -> Result<ImportProposal, IntegrityError> {
    let mut entries = Vec::with_capacity(raw.entries.len());
    for re in raw.entries {
        let mut fields = Vec::with_capacity(re.fields.len());
        for rf in re.fields {
            let value = materialize(source, &rf.span)?;
            if let Some(echoed) = rf.echoed_value {
                if echoed != value {
                    return Err(IntegrityError::ValueNotVerbatim { field_type: rf.field_type, echoed });
                }
            }
            fields.push(ProposedField { field_type: rf.field_type, value, confidence: rf.confidence });
        }
        entries.push(ProposedEntry { title: re.title, kind: re.kind, source_file: None, source_text: None, fields });
    }
    Ok(ImportProposal { entries, unparsed: Vec::new(), entries_dropped: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text_import::model::*;
    use crate::text_import::preparse::pre_parse;

    #[test]
    fn materialize_returns_verbatim_substring() {
        let src = "pass: hunter2";
        let v = materialize(src, &Span { start: 6, end: 13 }).unwrap();
        assert_eq!(v, "hunter2");
    }

    #[test]
    fn materialize_rejects_out_of_bounds() {
        let src = "short";
        let err = materialize(src, &Span { start: 0, end: 999 }).unwrap_err();
        assert!(matches!(err, IntegrityError::SpanOutOfBounds { .. }));
    }

    #[test]
    fn materialize_rejects_end_one_past_len() {
        let src = "short";
        let err = materialize(src, &Span { start: 0, end: src.len() + 1 }).unwrap_err();
        assert!(matches!(err, IntegrityError::SpanOutOfBounds { .. }));
    }

    #[test]
    fn materialize_rejects_non_char_boundary() {
        let src = "юзер";
        let err = materialize(src, &Span { start: 0, end: 1 }).unwrap_err();
        assert!(matches!(err, IntegrityError::NotCharBoundary { .. }));
    }

    #[test]
    fn validate_rejects_hallucinated_echoed_value() {
        let src = "pass: hunter2";
        let raw = RawProposal {
            entries: vec![RawEntry {
                title: None,
                kind: EntryKind::Login,
                fields: vec![RawField {
                    field_type: FieldType::Password,
                    span: Span { start: 6, end: 13 },
                    echoed_value: Some("hunter3".into()),
                    confidence: 0.9,
                }],
            }],
        };
        let err = validate(src, raw).unwrap_err();
        assert!(matches!(err, IntegrityError::ValueNotVerbatim { .. }));
    }

    #[test]
    fn validate_passes_matching_echoed_value_and_materializes() {
        let src = "pass: hunter2";
        let raw = RawProposal {
            entries: vec![RawEntry {
                title: None,
                kind: EntryKind::Login,
                fields: vec![RawField {
                    field_type: FieldType::Password,
                    span: Span { start: 6, end: 13 },
                    echoed_value: Some("hunter2".into()),
                    confidence: 0.9,
                }],
            }],
        };
        let ok = validate(src, raw).unwrap();
        assert_eq!(ok.entries[0].fields[0].value, "hunter2");
    }

    #[test]
    fn validate_stores_materialized_value_on_no_echo_path() {
        let src = "pass: hunter2";
        let raw = RawProposal {
            entries: vec![RawEntry {
                title: None,
                kind: EntryKind::Login,
                fields: vec![RawField {
                    field_type: FieldType::Password,
                    span: Span { start: 6, end: 13 },
                    echoed_value: None,
                    confidence: 0.9,
                }],
            }],
        };
        let ok = validate(src, raw).unwrap();
        assert_eq!(ok.entries[0].fields[0].value, &src[6..13]);
    }

    #[test]
    fn pre_parse_output_always_validates() {
        let src = "site: https://github.com\nuser: octocat\npass: hunter2\n\napi key: sk-live-xyz";
        let proposal = validate(src, pre_parse(src)).unwrap();
        assert!(!proposal.entries.is_empty());
        for e in &proposal.entries {
            for f in &e.fields {
                assert!(src.contains(&f.value), "value {:?} must be a source substring", f.value);
            }
        }
    }

    #[test]
    fn validate_leaves_source_file_and_text_none() {
        let src = "user: bob\npass: hunter2";
        let raw = RawProposal {
            entries: vec![RawEntry {
                title: None,
                kind: EntryKind::Login,
                fields: vec![RawField {
                    field_type: FieldType::Password,
                    span: Span { start: 16, end: 23 },
                    echoed_value: None,
                    confidence: 0.9,
                }],
            }],
        };
        let ok = validate(src, raw).unwrap();
        assert_eq!(ok.entries[0].fields[0].value, "hunter2");
        assert_eq!(ok.entries[0].source_file, None);
        assert_eq!(ok.entries[0].source_text, None);
    }
}

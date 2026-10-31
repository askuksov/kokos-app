//! The extractor boundary. `Extractor` produces `RawEntryDraft`s carrying
//! `verbatim_text` strings (NEVER offsets); the locator turns them into spans.
//! `FakeExtractor` is the deterministic CI backend — the real generative runtime
//! is a separate manual dev step.

use serde::Deserialize;

use crate::text_import::model::{EntryKind, FieldType};
use crate::AiError;

/// A high-confidence hint from the heuristic pre-parser, handed to the extractor as
/// steering. `text` is the verbatim source slice of the hint.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldHint {
    pub field_type: FieldType,
    pub text: String,
}

/// One field the extractor claims, as a VERBATIM copy of source text (no offset).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawFieldDraft {
    pub field_type: FieldType,
    pub verbatim_text: String,
}

/// One proposed entry (the grouping unit — its fields belong together). May span
/// more than one source block; the nesting binds the fields regardless.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawEntryDraft {
    #[serde(default)]
    pub title: Option<String>,
    pub kind: EntryKind,
    pub fields: Vec<RawFieldDraft>,
}

/// The generative extractor. Input: a chunk of file text + the pre-parser hints for that
/// chunk. Output: entry drafts with verbatim-text fields. `Send + Sync` so the
/// engine can be cached and handed to `spawn_blocking` (mirrors `Embedder`).
pub trait Extractor: Send + Sync {
    fn extract(&self, chunk: &str, hints: &[FieldHint]) -> Result<Vec<RawEntryDraft>, AiError>;
}

/// Deterministic CI backend: returns its scripted drafts for every chunk. Tests
/// configure `scripted` to exercise the locator/pipeline (including drafts whose
/// text is NOT in the source, to prove the hallucination path is rejected).
pub struct FakeExtractor {
    pub scripted: Vec<RawEntryDraft>,
}

impl Extractor for FakeExtractor {
    fn extract(&self, _chunk: &str, _hints: &[FieldHint]) -> Result<Vec<RawEntryDraft>, AiError> {
        Ok(self.scripted.clone())
    }
}

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FakeExtractor>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text_import::model::{EntryKind, FieldType};

    #[test]
    fn fake_extractor_returns_scripted_drafts() {
        let fake = FakeExtractor {
            scripted: vec![RawEntryDraft {
                title: Some("GitHub".into()),
                kind: EntryKind::Login,
                fields: vec![RawFieldDraft { field_type: FieldType::Password, verbatim_text: "hunter2".into() }],
            }],
        };
        let out = fake.extract("ignored chunk", &[]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].fields[0].verbatim_text, "hunter2");
    }

    #[test]
    fn draft_deserializes_from_model_json_camelcase() {
        let json = r#"[{"title":"GH","kind":"login","fields":[{"fieldType":"password","verbatimText":"pw"}]}]"#;
        let drafts: Vec<RawEntryDraft> = serde_json::from_str(json).unwrap();
        assert_eq!(drafts[0].fields[0].field_type, FieldType::Password);
        assert_eq!(drafts[0].fields[0].verbatim_text, "pw");
    }
}

//! The import proposal data model. Two layers:
//! * `Raw*` — extractor output (the heuristic pre-parser or the LLM). A field is a
//!   `Span` into the source plus an optional `echoed_value` the integrity guard
//!   cross-checks. NO free-form value here — values are never invented.
//! * `Proposed*` / `ImportProposal` — the validated, review-UI-facing result,
//!   where each value has been materialized VERBATIM from the source.

use serde::{Deserialize, Serialize};

/// Byte range `[start, end)` into the source `str`. Always sliced via
/// `str::get` (see `integrity::materialize`) so a bad range fails, never panics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FieldType {
    Login,
    Password,
    Url,
    Email,
    TotpSecret,
    ApiKey,
    SecurityQuestion,
    SecurityAnswer,
    Note,
    Phone,
    /// Wi-Fi network name. Not a secret: it is broadcast.
    Ssid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EntryKind {
    Login,
    ApiKey,
    SecureNote,
    Totp,
    Wifi,
}

/// Extractor output. `echoed_value`, when present, is what the extractor claims
/// the span contains; the integrity guard rejects it if it is not exactly
/// `source[span]`. The heuristics leave it `None` (spans come straight from the
/// source); the LLM sets it so a hallucinated value cannot slip through.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawField {
    pub field_type: FieldType,
    pub span: Span,
    #[serde(default)]
    pub echoed_value: Option<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawEntry {
    pub title: Option<String>,
    pub kind: EntryKind,
    pub fields: Vec<RawField>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawProposal {
    pub entries: Vec<RawEntry>,
}

/// Validated, review-UI-facing. `value` was materialized verbatim from source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposedField {
    pub field_type: FieldType,
    pub value: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposedEntry {
    pub title: Option<String>,
    pub kind: EntryKind,
    /// The source file this entry was extracted from — review-UI provenance +
    /// filename-derived title. kokos-ai is path-agnostic, so this is
    /// `None` here; the Tauri analyze command stamps it per file. Never logged.
    #[serde(default)]
    pub source_file: Option<String>,
    /// The FULL verbatim text of that source file, so the review UI can offer a
    /// collapsible "raw data" view of exactly what produced this entry (
    /// GUI revision). Verbatim user-owned text; `None` here (app stamps it per
    /// file); review-only, never persisted to the vault, never logged.
    #[serde(default)]
    pub source_text: Option<String>,
    pub fields: Vec<ProposedField>,
}

/// A blank-line block of the source that produced no entry. Surfaced so the
/// review UI can say which part of the file was not parsed instead of reporting
/// a clean result. `text` is the block verbatim (user-owned; review-only, never
/// persisted or logged); `source_file` is stamped by the app, like on entries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnparsedBlock {
    pub text: String,
    #[serde(default)]
    pub source_file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportProposal {
    pub entries: Vec<ProposedEntry>,
    #[serde(default)]
    pub unparsed: Vec<UnparsedBlock>,
    /// Entries cut by the app's per-file / per-proposal caps. Set by the app
    /// (kokos-ai never drops), surfaced in review so the cut is not silent.
    #[serde(default)]
    pub entries_dropped: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_and_validated_shapes_construct() {
        let raw = RawProposal {
            entries: vec![RawEntry {
                title: Some("GitHub".into()),
                kind: EntryKind::Login,
                fields: vec![RawField {
                    field_type: FieldType::Password,
                    span: Span { start: 10, end: 18 },
                    echoed_value: None,
                    confidence: 1.0,
                }],
            }],
        };
        assert_eq!(raw.entries.len(), 1);
        assert_eq!(raw.entries[0].fields[0].span, Span { start: 10, end: 18 });
    }

    #[test]
    fn import_proposal_serializes_for_the_frontend() {
        let p = ImportProposal {
            entries: vec![ProposedEntry {
                title: None,
                kind: EntryKind::ApiKey,
                source_file: None,
                source_text: None,
                fields: vec![ProposedField {
                    field_type: FieldType::ApiKey,
                    value: "sk-live-abc".into(),
                    confidence: 0.9,
                }],
            }],
            unparsed: vec![UnparsedBlock { text: "Home wifi".into(), source_file: None }],
            entries_dropped: 0,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"apiKey\""), "field_type serializes camelCase: {json}");
        assert!(json.contains("sk-live-abc"));
        assert!(json.contains("\"unparsed\":[{\"text\":\"Home wifi\",\"sourceFile\":null}]"), "{json}");
    }
}

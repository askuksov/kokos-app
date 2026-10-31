//! Deterministic, LLM-free text-file import. Turns an arbitrary
//! plaintext file into a raw import proposal via block-splitting + regex field
//! hints, then validates it so every field value is a VERBATIM substring of the
//! source (`integrity`). The generative extractor produces the same
//! `RawProposal` shape and passes through the same `integrity::validate` guard.

pub mod integrity;
pub mod model;
pub mod preparse;
pub mod engine;

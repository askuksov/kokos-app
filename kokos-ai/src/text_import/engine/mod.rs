//! Generative-import engine. CI-testable plumbing only — no LLM, no
//! `ort`, no network. The `Extractor` trait is exercised by `FakeExtractor` in
//! the suite; the real `gen::GenExtractor` compiles here but is driven only by
//! the manual dev benchmark + the Tauri app path (no model at build/test time).
//! The model emits `verbatim_text` strings grouped into entries; `locator` turns
//! them into source spans (setting `echoed_value`), and `integrity::validate`
//! is the single chokepoint enforcing the verbatim-span invariant.

pub mod chunker;
pub mod extractor;
pub mod gen;
pub mod locator;
pub mod parse;
pub mod pipeline;
pub mod prompt;
pub mod reconcile;
pub mod registry;

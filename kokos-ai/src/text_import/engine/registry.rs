//! Static catalog of GENERATIVE models (distinct from the embedding `ModelDef` —
//! no dim/pooling/tokenizer.json; instead a context window + chat-template kind).
//! `url`/`sha256` are pinned by the dev in the manual benchmark step, then the
//! real `Extractor` is wired into the app.

/// How to wrap the prompt for the chosen model family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatTemplateKind {
    /// `<|im_start|>role\n…<|im_end|>` (Qwen2.5, many instruct GGUFs).
    ChatMl,
    /// Llama-3 `<|start_header_id|>` style.
    Llama3,
    /// No wrapping — raw system+user concatenation (base models / testing).
    Plain,
}

#[derive(Debug, Clone, Copy)]
pub struct GenModelDef {
    pub id: &'static str,
    /// Pinned GGUF download URL. FILLED in the manual dev step.
    pub url: &'static str,
    /// Lowercase hex SHA-256 of the GGUF. FILLED in the manual dev step.
    pub sha256: &'static str,
    /// Pinned tokenizer.json download URL (a non-LFS git blob in the main
    /// Instruct repo — the GGUF repo has none). FILLED with the gguf.
    pub tokenizer_url: &'static str,
    /// Lowercase hex SHA-256 of tokenizer.json (locally computed; its HF etag is
    /// a git SHA-1, not the sha256, so it can't cross-confirm — the verified
    /// download fails closed on mismatch).
    pub tokenizer_sha256: &'static str,
    /// Model context window in tokens (chunker budget is derived from this).
    pub ctx_window: usize,
    pub chat_template: ChatTemplateKind,
}

/// Candidate generative models. The active one is a developer setting; the real
/// pick + url/sha256 were locked after the CPU benchmark (manual dev step).
///
/// DEFAULT = `qwen2.5-1.5b-instruct` (Apache-2.0). Benchmarked head-to-head with
/// 3B on the benchmark's hard fixtures: identical field-recall (75%), ZERO integrity-
/// guard violations, 100% on the non-ASCII (RU) fixture, and faster on CPU —
/// while staying commercially licensed. Pinned to the official Qwen GGUF (Q4_K_M).
///
/// `qwen2.5-3b-instruct` is a benchmarked candidate left INTENTIONALLY UNPINNED:
/// it ships under the Qwen-Research (non-commercial) license, unlike 1.5B's
/// Apache-2.0, so it is not distributed. A developer may pin + select it locally.
pub const GEN_MODELS: &[GenModelDef] = &[
    GenModelDef {
        id: "qwen2.5-1.5b-instruct",
        url: "https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/91cad51170dc346986eccefdc2dd33a9da36ead9/qwen2.5-1.5b-instruct-q4_k_m.gguf",
        sha256: "6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e",
        tokenizer_url: "https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct/resolve/989aa7980e4cf806f80c7fef2b1adb7bc71aa306/tokenizer.json",
        tokenizer_sha256: "c0382117ea329cdf097041132f6d735924b697924d6f6fc3945713e96ce87539",
        ctx_window: 8192,
        chat_template: ChatTemplateKind::ChatMl,
    },
    GenModelDef {
        id: "qwen2.5-3b-instruct",
        url: "",
        sha256: "",
        tokenizer_url: "",
        tokenizer_sha256: "",
        ctx_window: 8192,
        chat_template: ChatTemplateKind::ChatMl,
    },
];

pub fn resolve_gen(id: &str) -> Option<&'static GenModelDef> {
    GEN_MODELS.iter().find(|m| m.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_known_and_rejects_unknown() {
        assert!(resolve_gen(GEN_MODELS[0].id).is_some());
        assert!(resolve_gen("bogus").is_none());
    }

    #[test]
    fn no_gen_model_is_half_pinned_and_default_is_pinned() {
        for m in GEN_MODELS {
            assert!(m.ctx_window > 0, "{} ctx_window", m.id);
            let all_empty = m.url.is_empty() && m.sha256.is_empty()
                && m.tokenizer_url.is_empty() && m.tokenizer_sha256.is_empty();
            let all_pinned = !m.url.is_empty() && !m.sha256.is_empty()
                && !m.tokenizer_url.is_empty() && !m.tokenizer_sha256.is_empty();
            assert!(all_empty || all_pinned, "{} url/sha/tokenizer must be pinned together or all empty", m.id);
        }
        let default = resolve_gen("qwen2.5-1.5b-instruct").expect("default slot present");
        assert!(!default.url.is_empty() && !default.sha256.is_empty(), "default gen model gguf must be pinned");
        assert_eq!(default.sha256.len(), 64, "sha256 is 64 hex chars");
        assert!(default.sha256.chars().all(|c| c.is_ascii_hexdigit()), "sha256 is lowercase hex");
        assert_eq!(default.tokenizer_sha256.len(), 64, "tokenizer sha256 is 64 hex chars");
        assert!(default.tokenizer_sha256.chars().all(|c| c.is_ascii_hexdigit()), "tokenizer sha256 is lowercase hex");
    }
}

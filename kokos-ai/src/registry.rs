//! Static catalog of embedding models. The active model is a developer
//! setting so all three can be benchmarked; vector dim is per-model, so
//! switching the active model forces a reindex downstream.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pooling {
    Mean,
    Cls,
}

#[derive(Debug, Clone, Copy)]
pub struct ModelDef {
    pub id: &'static str,
    /// Hugging Face download URL, pinned to a commit.
    pub url: &'static str,
    /// Matching `tokenizer.json`, from the same commit.
    pub tokenizer_url: &'static str,
    /// Lowercase hex SHA-256 of the model file.
    pub sha256: &'static str,
    /// Lowercase hex SHA-256 of `tokenizer.json`.
    pub tokenizer_sha256: &'static str,
    pub dim: usize,
    pub max_length: usize,
    pub pooling: Pooling,
}

/// All three are multilingual — entry titles and notes are as often Russian or
/// Ukrainian as English, which rules out the English-only sentence encoders.
///
/// Every URL pins a commit rather than `resolve/main/`, because `main` moves and
/// a moved file would fail the checksum on the next machine that downloads it.
/// The hashes are the files' Git-LFS object ids, which are their SHA-256.
///
/// The `model_*.onnx` exports are deliberate: the `sentence_transformers_*`
/// variants in the same repositories carry their own pooling head, and pooling
/// is done here so it stays consistent across models.
///
/// bge-m3 is taken from the Xenova mirror rather than BAAI's own repository:
/// upstream ships the graph and its 2.27 GB of weights as two files
/// (`model.onnx` + `model.onnx_data`), and a model here is one URL.
pub const MODELS: &[ModelDef] = &[
    ModelDef {
        id: "small",
        url: "https://huggingface.co/Xenova/multilingual-e5-small/resolve/761b726dd34fb83930e26aab4e9ac3899aa1fa78/onnx/model_int8.onnx",
        tokenizer_url: "https://huggingface.co/Xenova/multilingual-e5-small/resolve/761b726dd34fb83930e26aab4e9ac3899aa1fa78/tokenizer.json",
        sha256: "4d24e2bc01a447951524466ef533e52944bf48509e6552810bcee1a2711cb02c",
        tokenizer_sha256: "0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39",
        dim: 384,
        max_length: 512,
        pooling: Pooling::Mean,
    },
    ModelDef {
        id: "mid",
        url: "https://huggingface.co/Xenova/paraphrase-multilingual-MiniLM-L12-v2/resolve/2c4055b12046f11709e9df2c122e59ffbdc2f900/onnx/model.onnx",
        tokenizer_url: "https://huggingface.co/Xenova/paraphrase-multilingual-MiniLM-L12-v2/resolve/2c4055b12046f11709e9df2c122e59ffbdc2f900/tokenizer.json",
        sha256: "185ae63f47e17a7e8d30d0e6a3cde6a6e4b79bc5b81666ecffc279a6856ca113",
        tokenizer_sha256: "b60b6b43406a48bf3638526314f3d232d97058bc93472ff2de930d43686fa441",
        dim: 384,
        max_length: 512,
        pooling: Pooling::Mean,
    },
    ModelDef {
        id: "large",
        url: "https://huggingface.co/Xenova/bge-m3/resolve/4de13258303883538bd53b696b452bf8099f0858/onnx/model_fp16.onnx",
        tokenizer_url: "https://huggingface.co/Xenova/bge-m3/resolve/4de13258303883538bd53b696b452bf8099f0858/tokenizer.json",
        sha256: "4f1a646a3d4f39985589e9991a717044ede8278617fe55e3d246838bc05055e9",
        tokenizer_sha256: "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790",
        dim: 1024,
        max_length: 512,
        pooling: Pooling::Cls,
    },
];

pub fn resolve(id: &str) -> Option<&'static ModelDef> {
    MODELS.iter().find(|m| m.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_the_three_ids_and_rejects_unknown() {
        assert_eq!(resolve("small").map(|m| m.id), Some("small"));
        assert_eq!(resolve("mid").map(|m| m.id), Some("mid"));
        assert_eq!(resolve("large").map(|m| m.id), Some("large"));
        assert!(resolve("bogus").is_none());
    }

    #[test]
    fn dims_are_nonzero_and_max_length_is_512() {
        for m in MODELS {
            assert!(m.dim > 0, "{} dim", m.id);
            assert_eq!(m.max_length, 512, "{} max_length", m.id);
        }
    }

    #[test]
    fn every_model_is_fully_pinned() {
        for m in MODELS {
            assert!(m.url.starts_with("https://"), "{} url", m.id);
            assert!(m.tokenizer_url.starts_with("https://"), "{} tokenizer_url", m.id);
            for (label, sha) in [("sha256", m.sha256), ("tokenizer_sha256", m.tokenizer_sha256)] {
                assert_eq!(sha.len(), 64, "{} {label} is 64 hex chars", m.id);
                assert!(
                    sha.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                    "{} {label} is lowercase hex",
                    m.id
                );
            }
        }
    }

    #[test]
    fn urls_pin_a_commit_not_a_branch() {
        for m in MODELS {
            for url in [m.url, m.tokenizer_url] {
                assert!(!url.contains("/resolve/main/"), "{} pins a branch: {url}", m.id);
                let rev = url
                    .split("/resolve/")
                    .nth(1)
                    .and_then(|rest| rest.split('/').next())
                    .unwrap_or("");
                assert_eq!(rev.len(), 40, "{} revision is not a full commit: {rev}", m.id);
                assert!(rev.chars().all(|c| c.is_ascii_hexdigit()), "{} revision {rev}", m.id);
            }
        }
    }
}

//! Embedding backend. The pure functions (`mean_pool`, `l2_normalize`) and the
//! `FakeEmbedder` are unit-tested and drive CI. The concrete `OrtEmbedder`
//! that runs a real ONNX model is added in a separate manual dev step (it needs
//! a downloaded model + benchmarking); no model is downloaded or run in the
//! automated suite.

use crate::AiError;

pub trait Embedder: Send + Sync {
    fn embed(&self, text: &str) -> Result<Vec<f32>, AiError>;
    fn dim(&self) -> usize;
}

pub fn mean_pool(hidden: &[Vec<f32>], mask: &[i64]) -> Vec<f32> {
    let dim = hidden.first().map(|v| v.len()).unwrap_or(0);
    let mut sum = vec![0f32; dim];
    let mut count = 0f32;
    for (tok, &m) in hidden.iter().zip(mask) {
        if m == 0 {
            continue;
        }
        for (i, &x) in tok.iter().enumerate() {
            sum[i] += x;
        }
        count += 1.0;
    }
    if count > 0.0 {
        for x in &mut sum {
            *x /= count;
        }
    }
    sum
}

pub fn l2_normalize(v: &mut [f32]) {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in v {
            *x /= norm;
        }
    }
}

/// Turn a model output into one sentence vector of length `dim` (not yet
/// normalized). The output rank decides the path: `[1, seq, hidden]` is
/// per-token hidden states and is pooled; `[1, dim]` is already pooled. Any
/// other shape, or a result whose length is not the registry `dim`, is an error
/// rather than a silently wrong vector that search would skip.
pub fn pool_output(
    dims: &[i64],
    data: Vec<f32>,
    mask: &[i64],
    pooling: Pooling,
    dim: usize,
) -> Result<Vec<f32>, AiError> {
    let seq = mask.len();
    let pooled = match dims {
        [1, s, h] if *s as usize == seq && *h > 0 && data.len() == seq * (*h as usize) => {
            let h = *h as usize;
            match pooling {
                Pooling::Cls => data[0..h].to_vec(),
                Pooling::Mean => {
                    let hidden: Vec<Vec<f32>> =
                        (0..seq).map(|t| data[t * h..(t + 1) * h].to_vec()).collect();
                    mean_pool(&hidden, mask)
                }
            }
        }
        [1, n] if *n as usize == data.len() => data,
        other => {
            return Err(AiError::Backend(format!(
                "unexpected embedding output shape {other:?} for {seq} tokens"
            )))
        }
    };
    if pooled.len() != dim {
        return Err(AiError::Backend(format!(
            "embedding has {} dimensions, expected {dim}",
            pooled.len()
        )));
    }
    Ok(pooled)
}

/// Deterministic stand-in: a stable per-dimension hash of the text, L2-
/// normalized. Reused by tests so the whole pipeline is testable with no
/// ONNX. NOT a real semantic model.
pub struct FakeEmbedder {
    pub dim: usize,
}

impl Embedder for FakeEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, AiError> {
        let mut v = vec![0f32; self.dim];
        for (i, slot) in v.iter_mut().enumerate() {
            let mut h: u64 = 1469598103934665603;
            for b in text.bytes() {
                h = (h ^ b as u64).wrapping_mul(1099511628211);
            }
            h ^= (i as u64).wrapping_mul(2654435761);
            *slot = ((h % 1000) as f32) / 1000.0;
        }
        l2_normalize(&mut v);
        Ok(v)
    }
    fn dim(&self) -> usize {
        self.dim
    }
}


use std::path::Path;
use std::sync::Mutex;

use ort::session::{Session, SessionInputValue};
use ort::value::Tensor;
use tokenizers::Tokenizer;

use crate::registry::{ModelDef, Pooling};

/// Real embedding backend over ONNX Runtime (CPU). The single ort-touching
/// type. The session is behind a `Mutex` because `Session::run` needs
/// `&mut self` while the `Embedder` trait exposes `&self`. Adaptive to the
/// model's declared I/O: feeds `token_type_ids` only when the graph asks for it
/// (xlm-roberta e5/bge-m3 don't; BERT-family MiniLM does), and reads the
/// hidden size from the output shape; a vector whose length is not the
/// registry `dim` is an error.
pub struct OrtEmbedder {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    dim: usize,
    pooling: Pooling,
    wants_token_type: bool,
    output_name: String,
}

impl OrtEmbedder {
    pub fn load(def: &ModelDef, model_path: &Path, tokenizer_path: &Path) -> Result<Self, AiError> {
        let mut tokenizer =
            Tokenizer::from_file(tokenizer_path).map_err(|e| AiError::Backend(e.to_string()))?;
        let trunc = tokenizers::TruncationParams {
            max_length: def.max_length,
            ..Default::default()
        };
        tokenizer
            .with_truncation(Some(trunc))
            .map_err(|e| AiError::Backend(e.to_string()))?;

        // Windows links ONNX Runtime at runtime. Load the DLL explicitly so a
        // missing or too-old DLL is an error here; left to ort's lazy loader,
        // it panics on the first API call instead.
        #[cfg(windows)]
        {
            let dylib = std::env::var("ORT_DYLIB_PATH")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "onnxruntime.dll".to_owned());
            let _ = ort::init_from(dylib).map_err(|e| AiError::Backend(e.to_string()))?;
        }

        let session = Session::builder()
            .map_err(|e| AiError::Backend(e.to_string()))?
            .commit_from_file(model_path)
            .map_err(|e| AiError::Backend(e.to_string()))?;

        let wants_token_type = session.inputs().iter().any(|i| i.name() == "token_type_ids");
        let out_names: Vec<String> = session.outputs().iter().map(|o| o.name().to_string()).collect();
        let output_name = out_names
            .iter()
            .find(|n| n.as_str() == "sentence_embedding")
            .or_else(|| out_names.iter().find(|n| n.as_str() == "last_hidden_state" || n.as_str() == "token_embeddings"))
            .cloned()
            .unwrap_or_else(|| out_names[0].clone());

        eprintln!(
            "[ort] {}: inputs={:?} outputs={:?} → pool={:?} output='{}' token_type={}",
            def.id,
            session.inputs().iter().map(|i| i.name()).collect::<Vec<_>>(),
            session.outputs().iter().map(|o| o.name()).collect::<Vec<_>>(),
            def.pooling,
            output_name,
            wants_token_type,
        );

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            dim: def.dim,
            pooling: def.pooling,
            wants_token_type,
            output_name,
        })
    }
}

impl Embedder for OrtEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, AiError> {
        let enc = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| AiError::Backend(e.to_string()))?;
        let ids: Vec<i64> = enc.get_ids().iter().map(|&x| x as i64).collect();
        let mask: Vec<i64> = enc.get_attention_mask().iter().map(|&x| x as i64).collect();
        let seq = ids.len();
        if seq == 0 {
            return Ok(vec![0.0; self.dim]);
        }
        let shape = vec![1i64, seq as i64];

        let mut inputs: Vec<(std::borrow::Cow<'static, str>, SessionInputValue)> = vec![
            (
                std::borrow::Cow::Borrowed("input_ids"),
                SessionInputValue::from(
                    Tensor::from_array((shape.clone(), ids)).map_err(|e| AiError::Backend(e.to_string()))?,
                ),
            ),
            (
                std::borrow::Cow::Borrowed("attention_mask"),
                SessionInputValue::from(
                    Tensor::from_array((shape.clone(), mask.clone()))
                        .map_err(|e| AiError::Backend(e.to_string()))?,
                ),
            ),
        ];
        if self.wants_token_type {
            inputs.push((
                std::borrow::Cow::Borrowed("token_type_ids"),
                SessionInputValue::from(
                    Tensor::from_array((shape.clone(), vec![0i64; seq]))
                        .map_err(|e| AiError::Backend(e.to_string()))?,
                ),
            ));
        }

        let (dims, data): (Vec<i64>, Vec<f32>) = {
            let mut sess = self.session.lock().map_err(|e| AiError::Backend(e.to_string()))?;
            let outputs = sess.run(inputs).map_err(|e| AiError::Backend(e.to_string()))?;
            let (shape, slice) = outputs[self.output_name.as_str()]
                .try_extract_tensor::<f32>()
                .map_err(|e| AiError::Backend(e.to_string()))?;
            (shape.to_vec(), slice.to_vec())
        };

        let mut pooled = pool_output(&dims, data, &mask, self.pooling, self.dim)?;
        l2_normalize(&mut pooled);
        Ok(pooled)
    }

    fn dim(&self) -> usize {
        self.dim
    }
}

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FakeEmbedder>();
    assert_send_sync::<OrtEmbedder>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mean_pool_ignores_masked_tokens() {
        let hidden = vec![vec![1.0, 1.0], vec![3.0, 3.0], vec![100.0, 100.0]];
        let mask = vec![1i64, 1, 0];
        assert_eq!(mean_pool(&hidden, &mask), vec![2.0, 2.0]);
    }

    #[test]
    fn mean_pool_all_masked_is_zero_not_nan() {
        let hidden = vec![vec![5.0, 5.0]];
        let mask = vec![0i64];
        assert_eq!(mean_pool(&hidden, &mask), vec![0.0, 0.0]);
    }

    #[test]
    fn l2_normalize_gives_unit_length() {
        let mut v = vec![3.0f32, 4.0];
        l2_normalize(&mut v);
        let len = (v[0] * v[0] + v[1] * v[1]).sqrt();
        assert!((len - 1.0).abs() < 1e-6, "len was {len}");
    }

    #[test]
    fn l2_normalize_zero_vector_stays_zero() {
        let mut v = vec![0.0f32, 0.0];
        l2_normalize(&mut v);
        assert_eq!(v, vec![0.0, 0.0]);
    }

    #[test]
    fn pool_output_pools_token_states_by_rank() {
        let data = vec![1.0, 1.0, 3.0, 3.0, 100.0, 100.0];
        let mask = [1i64, 1, 0];
        assert_eq!(pool_output(&[1, 3, 2], data.clone(), &mask, Pooling::Mean, 2).unwrap(), vec![2.0, 2.0]);
        assert_eq!(pool_output(&[1, 3, 2], data, &mask, Pooling::Cls, 2).unwrap(), vec![1.0, 1.0]);
    }

    #[test]
    fn pool_output_keeps_an_already_pooled_vector() {
        // 16 values over 4 tokens would divide evenly; rank 2 must still win.
        let data: Vec<f32> = (0..16).map(|i| i as f32).collect();
        let mask = [1i64; 4];
        assert_eq!(pool_output(&[1, 16], data.clone(), &mask, Pooling::Mean, 16).unwrap(), data);
    }

    #[test]
    fn pool_output_rejects_wrong_dim_or_shape() {
        let mask = [1i64; 2];
        assert!(pool_output(&[1, 4], vec![0.0; 4], &mask, Pooling::Mean, 8).is_err(), "dim mismatch");
        assert!(pool_output(&[1, 3, 4], vec![0.0; 12], &mask, Pooling::Mean, 4).is_err(), "seq mismatch");
        assert!(pool_output(&[2, 2, 4], vec![0.0; 16], &mask, Pooling::Mean, 4).is_err(), "batch of 2");
    }

    #[test]
    fn fake_embedder_is_deterministic_and_unit_length() {
        let e = FakeEmbedder { dim: 8 };
        let a = e.embed("Netflix").unwrap();
        let b = e.embed("Netflix").unwrap();
        assert_eq!(a, b, "same text → same vector");
        assert_eq!(a.len(), 8);
        let len = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((len - 1.0).abs() < 1e-6);
        assert_ne!(a, e.embed("Spotify").unwrap(), "different text → different vector");
    }
}

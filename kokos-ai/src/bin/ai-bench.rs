//! Dev benchmark: loads each downloaded model from <base>/<slot>/ and
//! prints cosine similarities so the dev can pick the default embedding model.
//! NOT shipped in the app (separate bin target). No CI.
//!
//! Usage: cargo run -p kokos-ai --bin ai-bench -- /path/to/kokos-models

use std::path::Path;

use kokos_ai::embed::{Embedder, OrtEmbedder};
use kokos_ai::registry;

/// Both vectors are L2-normalized, so the dot product IS the cosine similarity.
fn cosine(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

fn main() {
    let base = match std::env::args().nth(1) {
        Some(b) => b,
        None => {
            eprintln!("usage: ai-bench <models-base-dir>");
            std::process::exit(2);
        }
    };

    let en: &[(&str, &str, &str)] = &[
        ("cloud server hosting", "DigitalOcean", "Netflix"),
        ("streaming subscription", "Netflix", "DigitalOcean"),
        ("email account", "Gmail", "Chase Bank"),
        ("online banking", "Chase Bank", "Spotify"),
        ("password manager", "Bitwarden", "Uber Eats"),
    ];
    let ru: &[(&str, &str, &str)] = &[
        ("облачный хостинг сервера", "DigitalOcean", "Netflix"),
        ("стриминговый сервис", "Netflix", "Сбербанк"),
        ("электронная почта", "Gmail", "Сбербанк"),
        ("онлайн банк", "Сбербанк", "Spotify"),
        ("менеджер паролей", "Bitwarden", "Яндекс Еда"),
    ];
    let groups: &[(&str, &[(&str, &str, &str)])] = &[("EN", en), ("RU", ru)];

    for slot in ["small", "mid", "large"] {
        let dir = format!("{base}/{slot}");
        let model = format!("{dir}/model.onnx");
        let tok = format!("{dir}/tokenizer.json");
        if !Path::new(&model).exists() {
            eprintln!("-- skip {slot}: {model} not found");
            continue;
        }
        let Some(def) = registry::resolve(slot) else { continue };
        let prefix = if slot == "small" { "query: " } else { "" };

        println!("\n===== {slot}  (pooling {:?}, nominal dim {}) =====", def.pooling, def.dim);
        let t0 = std::time::Instant::now();
        let emb = match OrtEmbedder::load(def, Path::new(&model), Path::new(&tok)) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("   load failed: {e}");
                continue;
            }
        };
        eprintln!("   loaded in {:?}", t0.elapsed());

        let embed = |s: &str| emb.embed(&format!("{prefix}{s}")).expect("embed failed");
        for (lang, triples) in groups {
            let mut wins = 0;
            let mut sum_delta = 0.0f32;
            println!("   -- {lang} --");
            for (q, near, far) in *triples {
                let vq = embed(q);
                let cn = cosine(&vq, &embed(near));
                let cf = cosine(&vq, &embed(far));
                let ok = cn > cf;
                wins += ok as i32;
                sum_delta += cn - cf;
                println!(
                    "   [{}] \"{}\"  {}={:.3}  {}={:.3}  Δ={:+.3}",
                    if ok { "OK" } else { "XX" },
                    q,
                    near,
                    cn,
                    far,
                    cf,
                    cn - cf
                );
            }
            println!("   → {lang}: {wins}/{} correct, avg Δ={:+.3}", triples.len(), sum_delta / triples.len() as f32);
        }
    }
}

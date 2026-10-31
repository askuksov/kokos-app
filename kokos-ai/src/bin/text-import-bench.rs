//! Manual dev benchmark for the generative text-import `Extractor`. NOT a
//! CI test and NOT shipped — it loads a real quantized GGUF and runs the FULL
//! production pipeline (`analyze_text`: split → chunk → extract → locate →
//! heuristic floor → `integrity::validate`) over the hard fixtures below, then
//! reports the quality metrics the model pick is judged on:
//!   (a) JSON parse rate       — chunks whose model output parsed to ≥1 draft
//!   (b) recall                — expected real credential values that survive
//!                               into the validated proposal
//!   (c) hallucination-drop    — draft `verbatim_text`s NOT in the source, which
//!                               the locator correctly drops (proves the guard
//!                               holds on real model output)
//!   (d) segmentation/grouping — the proposal is printed for human judgement
//!
//! Run: `cargo run -p kokos-ai --bin text-import-bench -- <model.gguf> <tokenizer.json> [model_id]`
//! `model_id` (default `qwen2.5-1.5b-instruct`) selects the `GenModelDef` chat
//! template. Nothing here is compiled into the app or the test suite.

use std::sync::Mutex;
use std::time::Instant;

use kokos_ai::text_import::engine::extractor::{Extractor, FieldHint, RawEntryDraft};
use kokos_ai::text_import::engine::gen::GenExtractor;
use kokos_ai::text_import::engine::pipeline::analyze_text;
use kokos_ai::text_import::engine::registry::resolve_gen;
use kokos_ai::text_import::model::ImportProposal;
use kokos_ai::AiError;

/// A hard-case fixture: source text + the real credential values a good model
/// should recall. `expected` is only for scoring — the guard never trusts it.
struct Fixture {
    name: &'static str,
    source: &'static str,
    expected: &'static [&'static str],
}

/// The four hard cases (multi-site, mixed secrets+comments, api-key+TOTP+
/// security-Q&A, non-ASCII RU). Synthetic data — no real secrets.
const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "multi-site-in-one-file",
        source: "\
GitHub
url: https://github.com
login: octocat
password: Gh!7xQ2р-wolf

GitLab
https://gitlab.com
user: octo.dev
pass: Zebra$99_Lime

personal router admin
192.168.1.1
admin / R0uter-Adm1n!\n",
        expected: &["Gh!7xQ2р-wolf", "Zebra$99_Lime", "R0uter-Adm1n!", "octocat", "octo.dev"],
    },
    Fixture {
        name: "mixed-secrets-and-comments",
        source: "\
Notes from setting up the new laptop (delete this file later!!)

The wifi at the office is on the sticker under the router, but the guest
network password is: Guest-Wifi-2026

reminder: call the bank about the card before friday

Netflix — shared with family
email netflix.family@example.com
pw: N3tfl1x#share

random thought: should probably use a password manager for this stuff\n",
        expected: &["Guest-Wifi-2026", "N3tfl1x#share", "netflix.family@example.com"],
    },
    Fixture {
        name: "apikey-totp-securityqa",
        source: "\
AWS production access key
AKIAIOSFODNN7EXAMPLE
secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

Google Authenticator seed for the ops account:
otpauth://totp/Ops:root@corp?secret=JBSWY3DPEHPK3PXP&issuer=Ops

Bank security question
Q: What was the name of your first pet?
A: Mr-Whiskers-1998\n",
        expected: &[
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "JBSWY3DPEHPK3PXP",
            "Mr-Whiskers-1998",
        ],
    },
    Fixture {
        name: "non-ascii-russian",
        source: "\
Госуслуги
сайт: https://gosuslugi.ru
логин: ivan.petrov
пароль: Пар0ль-Медведь!

Почта Mail.ru
адрес: ivan.petrov@mail.ru
пароль: Кот1ки-forever\n",
        expected: &["Пар0ль-Медведь!", "Кот1ки-forever", "ivan.petrov", "ivan.petrov@mail.ru"],
    },
];

/// Wraps the real extractor to record every `(chunk, drafts)` a single pipeline
/// run produces, so raw-draft metrics (parse rate, hallucination) come from the
/// SAME inference that builds the validated proposal — no second model run.
struct Recording<'a> {
    inner: &'a GenExtractor,
    calls: Mutex<Vec<Vec<RawEntryDraft>>>,
}

impl Extractor for Recording<'_> {
    fn extract(&self, chunk: &str, hints: &[FieldHint]) -> Result<Vec<RawEntryDraft>, AiError> {
        let drafts = self.inner.extract(chunk, hints)?;
        self.calls.lock().unwrap().push(drafts.clone());
        Ok(drafts)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: text-import-bench <model.gguf> <tokenizer.json> [model_id]");
        std::process::exit(2);
    }
    let gguf = &args[1];
    let tokenizer = &args[2];
    let model_id = args.get(3).map(String::as_str).unwrap_or("qwen2.5-1.5b-instruct");

    let def = resolve_gen(model_id).unwrap_or_else(|| {
        eprintln!("unknown model_id '{model_id}' (not in GEN_MODELS)");
        std::process::exit(2);
    });

    eprintln!("loading {model_id}\n  gguf: {gguf}\n  tok : {tokenizer}");
    let t0 = Instant::now();
    let gen = GenExtractor::load(def, gguf.as_ref(), tokenizer.as_ref()).unwrap_or_else(|e| {
        eprintln!("load failed: {e}");
        std::process::exit(1);
    });
    eprintln!("loaded in {:.1}s\n", t0.elapsed().as_secs_f32());

    let chunk_budget = 4096usize;

    let mut tot_expected = 0usize;
    let mut tot_recalled = 0usize;
    let mut tot_raw_fields = 0usize;
    let mut tot_halluc = 0usize;
    let mut tot_proposal_fields = 0usize;
    let mut guard_violations = 0usize;

    for fx in FIXTURES {
        let rec = Recording { inner: &gen, calls: Mutex::new(Vec::new()) };
        let t = Instant::now();
        let proposal: ImportProposal = match analyze_text(fx.source, &rec, chunk_budget) {
            Ok(p) => p,
            Err(e) => {
                println!("\n===== {} =====\n  PIPELINE ERROR (guard rejected file): {e}", fx.name);
                continue;
            }
        };
        let elapsed = t.elapsed().as_secs_f32();
        let raw_calls = rec.calls.into_inner().unwrap();

        let chunks = raw_calls.len().max(1);
        let parsed_chunks = raw_calls.iter().filter(|d| !d.is_empty()).count();
        let mut raw_fields = 0usize;
        let mut halluc = 0usize;
        for drafts in &raw_calls {
            for d in drafts {
                for f in &d.fields {
                    raw_fields += 1;
                    if !fx.source.contains(&f.verbatim_text) {
                        halluc += 1;
                    }
                }
            }
        }

        let mut proposal_values: Vec<&str> = Vec::new();
        for e in &proposal.entries {
            for f in &e.fields {
                proposal_values.push(f.value.as_str());
                tot_proposal_fields += 1;
                if !fx.source.contains(&f.value) {
                    guard_violations += 1;
                    println!("  !! GUARD VIOLATION: {:?} not in source", f.value);
                }
            }
        }
        let recalled = fx.expected.iter().filter(|v| proposal_values.contains(v)).count();
        let missed: Vec<&str> =
            fx.expected.iter().copied().filter(|v| !proposal_values.contains(v)).collect();

        tot_expected += fx.expected.len();
        tot_recalled += recalled;
        tot_raw_fields += raw_fields;
        tot_halluc += halluc;

        println!("\n===== {} =====", fx.name);
        println!(
            "  parse: {parsed_chunks}/{chunks} chunks yielded drafts | raw fields {raw_fields} \
             | hallucinated (dropped) {halluc}"
        );
        println!(
            "  recall: {recalled}/{} expected values | {:.0}% | time {elapsed:.1}s",
            fx.expected.len(),
            100.0 * recalled as f32 / fx.expected.len().max(1) as f32
        );
        if !missed.is_empty() {
            println!("  MISSED: {missed:?}");
        }
        println!("  proposal ({} entries):", proposal.entries.len());
        for e in &proposal.entries {
            let title = e.title.as_deref().unwrap_or("(no title)");
            println!("    [{:?}] {title}", e.kind);
            for f in &e.fields {
                println!("      {:?} = {:?}", f.field_type, f.value);
            }
        }
    }

    println!("\n########## SUMMARY ({model_id}) ##########");
    println!(
        "  recall           : {tot_recalled}/{tot_expected}  ({:.0}%)",
        100.0 * tot_recalled as f32 / tot_expected.max(1) as f32
    );
    println!("  raw draft fields : {tot_raw_fields}");
    println!(
        "  hallucinated     : {tot_halluc}  (dropped by locator; {:.0}% of raw)",
        100.0 * tot_halluc as f32 / tot_raw_fields.max(1) as f32
    );
    println!("  proposal fields  : {tot_proposal_fields}");
    println!(
        "  GUARD violations : {guard_violations}   <-- MUST be 0 (verbatim-span invariant)"
    );
}

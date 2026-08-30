# distilbert-secret-masker

A DistilBERT token-classification model that finds secrets (credentials,
tokens, keys, passwords) in code and text and emits **character spans** for
masking. It is designed to **complement** rule-based scanners, not replace them:
rules are excellent on known formats, and this model covers the non-pattern,
context-dependent secrets that regex misses.

- **Recommended checkpoint:** `v3.3a-RS` (see `MODEL_CARD.md`)
- **Weights:** published on Hugging Face (a new revision — not the old v2 model)
- **Metric:** strict exact span + line (exact value **and** line)
- **Operating point:** τ = 0.99 (frozen)
- **Long inputs:** handled via manual sliding windows (see below)

## Why a model, next to your scanners

On our frozen real-code benchmarks it is the only tool strong in **both**
regimes — it dominates on non-pattern code and ties/leads the best rule tools on
regex-friendly code. Full numbers and the head-to-head against gitleaks,
detect-secrets, TruffleHog and Semgrep are in `RESULTS.md`.

## Inference (reference implementation — required to reproduce results)

Results were measured with the manual sliding-window path (tokenize once without
truncation → (max_len−2)-piece windows, stride 128 → per-WordPiece BIO decode →
char spans in the original text; first window wins on overlap). A plain
`transformers.pipeline("token-classification", ...)` does **not** reproduce this
on documents beyond 512 tokens and does not apply the frozen span aggregation.

```python
from span_infer import load_model, infer_spans
tok, model, id2label = load_model("path/to/distilbert-secret-masker-v3.3a-RS")
spans, _ = infer_spans(text, tok, model, id2label, mode="threshold", tau=0.99)
# spans: [{"start","end","line","value","score"}]
```

## Repository layout

- `span_infer.py`, `span_eval.py` — reference inference + strict span evaluator
- `scanner_bench.py` — head-to-head harness vs gitleaks / detect-secrets / TruffleHog / Semgrep
- `rc_*.py`, `test_rc_c_sanitation.py`, `select_realcode_repos.py` — the **RealCode-1**
  benchmark: builders, sanitation core + proof suite, blind labeler, evaluators
- `run_benchB/C/D.py`, `ext_secret_bench.py`, `prowl_error_*.py` — benchmark runners + external diagnostics
- `train_*.py`, `build_*.py`, `mine_v33a_negatives.py` — training methodology
- `realcode1/` — the RealCode-1 eval corpora (sanitized; see `data/README.md`)
- `MODEL_CARD.md`, `RESULTS.md`, `PREREG_SECMASK_REALCODE1.md`, `REPO_SELECTION_v1.md`

## Data & secrets policy

This repository **does not distribute raw secrets.** The CredData-derived
benchmarks (B/C/D) are rebuilt locally from their source (see `data/README.md`);
RealCode-1 corpora are safe by construction (RC-A negatives carry no values,
RC-B values are synthetic, RC-C values are sanitized). See `MODEL_CARD.md` for
measured limitations.

## License

Code: MIT. Model weights: Apache-2.0 (on Hugging Face).

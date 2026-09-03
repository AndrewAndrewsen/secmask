# Contributing to SecMask

Thanks for your interest in improving SecMask. This repository is a **standalone
DistilBERT secret detector** (`v3.3a-RS`) plus the frozen benchmarks and
evaluation tooling used to measure it. It is intentionally a single
token-classification model — there is no scanner fusion or routing layer in the
shipped code. Contributions that make the model better, the evaluation more
rigorous, or the docs clearer are all welcome.

## Getting started

```bash
# Fork on GitHub, then:
git clone git@github.com:<you>/secmask.git
cd secmask
git remote add upstream git@github.com:AndrewAndrewsen/secmask.git

python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

The weights are on the Hugging Face Hub and are pulled on first use — no separate
download step:

`AndrewAndrewsen/distilbert-secret-masker-v3.3a-rs`

## Quick check that inference works

The reference inference path is `span_infer.py` (manual sliding windows, so it
handles inputs longer than 512 tokens and applies the frozen span aggregation).
Every number in `RESULTS.md` / `MODEL_CARD.md` was measured through it.

CLI:

```bash
python span_infer.py \
  --model AndrewAndrewsen/distilbert-secret-masker-v3.3a-rs \
  --text 'db = "postgres://admin:s3cr3t-P@ss@db.internal:5432/app"' \
  --mode threshold --tau 0.99 --mask
```

Python API:

```python
from span_infer import load_model, infer_spans, mask_text

tok, model, id2label = load_model("AndrewAndrewsen/distilbert-secret-masker-v3.3a-rs")
text = 'db = "postgres://admin:s3cr3t-P@ss@db.internal:5432/app"'
spans, _ = infer_spans(text, tok, model, id2label, mode="threshold", tau=0.99)
# spans: [{"start", "end", "line", "value", "score"}]
print(mask_text(text, spans))
```

> A plain `transformers.pipeline("token-classification", ...)` call does **not**
> reproduce the published results on long inputs and does not apply the frozen
> threshold/aggregation. Use `span_infer.py` as the reference.

## Repository layout

- `span_infer.py` — reference sliding-window inference (load, decode, mask).
- `span_eval.py` — strict character-span + line evaluator.
- `scanner_bench.py` — head-to-head harness vs gitleaks / detect-secrets / TruffleHog / Semgrep.
- `run_benchB.py`, `run_benchC.py`, `run_benchD.py` — per-corpus runners (data rebuilt from CredData; see `data/README.md`).
- `ext_secret_bench.py`, `prowl_error_*.py` — external-dataset (Prowl / CodeSecret) evaluation; see `data/README.md`.
- `rc_build.py`, `rc_c_build.py`, `rc_c_sanitize.py`, `rc_c_subset.py`, `rc_c_label.py`, `rc_c_suggest.py`, `rc_eval.py`, `rc_c_eval.py` — the RealCode-1 benchmark toolchain.
- `test_rc_c_sanitation.py` — sanitation proof gating RealCode-1 (run before touching the sanitizer).
- `realcode1/` — frozen RealCode-1 manifests, labels, and results (metadata only; no raw corpora).
- `README.md`, `MODEL_CARD.md`, `RESULTS.md`, `PREREG_SECMASK_REALCODE1.md`, `REPO_SELECTION_v1.md`, `data/README.md` — docs and provenance.

## Benchmark data

The benchmark **corpora are not shipped** (they contain real secrets). Rebuild
them from the documented sources before running the corpus scorers:

- B / C / D are rebuilt from Samsung **CredData** (repo-disjoint from any training).
- Prowl / CodeSecret are fetched from the Hugging Face Hub.

Exact repo IDs, pinned revisions, file hashes, and download commands are in
`data/README.md`. RealCode-1 ships as sanitized metadata only.

## Tests

```bash
python test_rc_c_sanitation.py     # sanitation proof (must pass before sanitizer changes)
```

If you change the sanitizer (`rc_c_sanitize.py`) or the RealCode-1 build, the
sanitation proof **must** stay green — it guarantees no raw secret value can be
persisted.

## Code style

- Standard PEP 8; keep functions small and readable.
- Type hints where they aid clarity; no required type-checker gate.
- No new runtime dependencies without discussion — the point is a small,
  auditable model + evaluation, not a framework.
- Determinism matters: seed anything stochastic and keep the frozen operating
  point (`τ = 0.99`) intact unless a change is explicitly about re-freezing.

## Pull requests

1. Branch from `main`: `git checkout -b feat/<short-name>`.
2. Keep the change focused; update docs and `RESULTS.md` if numbers change.
3. If a change affects measured results, re-run the relevant benchmark and say
   how (corpus, revision, command) in the PR.
4. Commit style: `<type>(<scope>): <subject>` — types `feat|fix|docs|test|refactor|chore`,
   scopes like `infer`, `eval`, `rc`, `bench`, `data`, `docs`. Examples:
   - `fix(infer): correct BIO/subword span alignment`
   - `feat(bench): add a new external corpus runner`
   - `docs(model-card): clarify limitations`
5. Open the PR against `AndrewAndrewsen/secmask`; describe what you changed and
   how you verified it. Be available to discuss.

## Good places to contribute

- **UUID / hash / high-entropy false positives** — the known precision frontier
  (RC-A: uuid ~8%, sha256 ~9%). Better handling here is the highest-value work.
- **Recall on prefixless generic secrets** (passwords, non-vendor tokens) — the
  hardest recall case (RC-B password recall ~0.66).
- **Non-code / non-English** — chat, logs, and non-English prose are measurably
  weaker than source code; more/better eval and training signal would help.
- **More frozen real-code benchmark corpora** — additional held-out, repo-disjoint
  corpora strengthen the evaluation.
- **Inference throughput** — the sliding-window path is CPU-friendly; speedups
  that preserve the exact outputs are welcome.

## Reporting bugs

Open an issue with a minimal reproducer: input text, the command or API call,
what you expected, and what you got. For a false positive/negative, include the
exact span and, if possible, whether `span_infer.py` at `τ = 0.99` reproduces it.

## Code of conduct

Be respectful and constructive. Assume good faith, keep discussion technical, and
help make the project welcoming. Harassment or discrimination is not tolerated.

## License

By contributing you agree that your contributions are licensed under the
repository's terms: **Apache-2.0** for model weights and **MIT** for the SecMask
code (see `LICENSE`).

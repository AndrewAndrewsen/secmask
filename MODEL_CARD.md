# distilbert-secret-masker — v3.3a-RS

**Recommended standalone checkpoint.** A DistilBERT token-classification model
that finds secrets (credentials, tokens, keys, passwords) in code and text and
emits character spans for masking. This card documents the **v3.3a-RS** revision
and supersedes the older v2-era documentation (which reported NER F1 ~0.52 and a
512-token limit — both outdated; see *Changes* below).

- Architecture: DistilBERT + token-classification head, BIO (`O`, `B-SECRET`, `I-SECRET`)
- Task: character-span secret detection → optional span masking
- License: Apache-2.0 (weights) / MIT (SecMask code)
- Frozen operating point: **τ = 0.99** (span score = mean over entity WordPieces of P(B)+P(I))
- Long inputs: **handled** via manual sliding windows (see *Inference*)

## Version lineage

```
v3.2      real-code precision fix (public DistilBERT collapse 0.004 -> 0.53)
v3.3a-1   data+loss revision; stronger on some STRUCTURED lookalikes
v3.3a-RS  ← current recommended standalone
```

Two negative/selection results are part of this model's provenance and are
reported deliberately:

- **Synthetic-diversity scaling (scale1)** improved development metrics but did
  **not** improve real-code transfer; v3.3a-RS (medium) therefore remains the
  selected checkpoint rather than a larger-scale variant.
- **v3.3a-1** is more precise on selected *structured* lookalikes (UUID/hash),
  but a **blind natural-code adjudicator (RealCode-1 RC-C)** favored v3.3a-RS
  overall (see below). RS is the recommended standalone; a1 may suit deployments
  whose false positives are dominated by structured UUID/hash lookalikes.

## Intended use

- Detecting/masking secrets in **source code** and code-adjacent text, as a
  complement to — not a replacement for — rule-based scanners.
- Best used through the **frozen sliding-window inference path** (below), which
  is what every number here was measured with.

Out of scope: a guarantee of finding all secrets; standalone compliance
gating; chat/log/prose is weaker than source code (see *Limitations*).

## Evaluation

All evaluation is on **frozen real code held out from training** (repo-disjoint). Benchmarks **B/C/D are observed regression sets** — repo-disjoint from training, but watched repeatedly during development, so they are **not blind**. **RealCode-1** (below) is the purpose-built, never-observed adjudicator. Headline
metric is **strict exact span + line** (exact character span AND correct line);
file-level and line-level are also reported because rule scanners are line/file
detectors, not span labelers.

### Strict real-code regression benchmarks — B/C/D, observed (v3.3a-RS @ τ=0.99)

| set | files (pos/total) | strict span+line P/R/F1 | line P/R/F1 | file P/R/F1 |
|---|---|---|---|---|
| Benchmark B (non-pattern real OSS) | 153/300 | 0.739/0.545/0.627 | 0.850/0.597/0.701 | 0.982/0.719/0.830 |
| Benchmark C (non-pattern real OSS) | 128/275 | 0.735/0.626/0.676 | 0.851/0.697/0.766 | 0.954/0.805/0.873 |
| Benchmark D (regex-friendly real OSS) | 150/300 | 0.714/0.680/0.696 | 0.935/0.898/0.916 | 0.979/0.927/0.952 |

Note the strict F1 is **corpus-stable (0.63–0.70)** while rule scanners swing
0.4→0.9 with corpus regex-friendliness.

### RealCode-1 (purpose-built, frozen, never trained on)

- **RC-A — precision on natural lookalike negatives** (422 files, 2629 spans):
  false-positive rate on structurally-certain non-secrets. v3.3a-RS lookalike-FP
  **0.048** overall; per category — uuid 0.080, hex-sha256 0.090, hex-md5 0.055,
  hex-sha1 0.016, SRI 0.006, ipv4/mac/env-name 0.000. *(UUID/hash is the known
  residual precision frontier.)*
- **RC-B — recall on real-context injected prefixless positives** (710):
  strict P/R/F1 **0.962/0.810/0.879**; by family — api_key 0.955, high_entropy
  0.870, basic_auth 0.751, password 0.663. Rule scanners largely miss these
  prefixless families.
- **RC-C — blind natural adjudicator** (400 candidates, human-labeled to policy,
  intra-rater 1.0): v3.3a-RS strict recall **0.467**, natural-negative FP
  **0.096**, vs v3.3a-1 recall 0.378 / FP 0.133. Paired McNemar: RS
  **significantly more precise** on natural negatives (p = 0.011); recall
  higher, not significant (n=45). RS Pareto-dominates a1 on blind natural code.

### External diagnostics (row-level, off the strict-span family)

| dataset | P | R | F1 |
|---|---|---|---|
| CodeSecret (balanced code) | 1.000 | 0.892 | 0.943 |
| Prowl (code & English slice) | 0.874 | 0.826 | 0.849 |
| Prowl (all sources/langs) | 0.848 | 0.651 | 0.736 |

Prowl by source F1: code 0.850 > jira 0.722 > slack 0.675 > confluence 0.645 >
log 0.532; non-English recall 0.46 (precision 0.97). Source code is the strong
domain; chat, logs, and non-English prose are weaker. This is row-level
detection on a synthetic multilingual set, not the strict-span metric used for
the headline numbers.

### Scanner comparison (file-level / line-level F1, same corpora, our harness)

| tool | B | C | D |
|---|---|---|---|
| gitleaks | 0.500 / 0.393 | 0.431 / 0.381 | 0.948 / 0.885 |
| detect-secrets | 0.641 / 0.407 | 0.679 / 0.365 | 0.953 / 0.891 |
| trufflehog | 0.099 / n/a* | 0.231 / n/a* | 0.736 / n/a* |
| semgrep | 0.145 / 0.058 | 0.171 / 0.072 | 0.527 / 0.421 |
| **v3.3a-RS** | **0.830 / 0.701** | **0.873 / 0.766** | **0.952 / 0.916** |

v3.3a-RS is the only tool strong in both regimes: it dominates on non-pattern
code (B/C) and ties/leads the best rule tool on regex-friendly code (D).
*trufflehog line-level not reliably recoverable in this harness; semgrep hit
parse errors on some files.*

## Inference (reference implementation — required to reproduce these numbers)

These results were produced with SecMask's **manual sliding-window** inference
(tokenize once without truncation → (max_len−2)-piece windows with stride 128 →
per-WordPiece BIO decode → char spans in the original text; first window wins on
overlap). Use `span_infer.py` from the SecMask repo.

> A plain `transformers.pipeline("token-classification", ...)` call does **not**
> reproduce this behavior on documents beyond 512 tokens and does not apply the
> frozen span aggregation / threshold — it will not match these benchmarks. Use
> the SecMask inference path as the reference.

```python
from span_infer import load_model, infer_spans
tok, model, id2label = load_model("path/to/distilbert-secret-masker-v3.3a-RS/best")
spans, _ = infer_spans(text, tok, model, id2label, mode="threshold", tau=0.99)
# spans: [{"start","end","line","value","score"}]
```

## Limitations (concrete, measured)

- **UUID / hash / checksum lookalikes are the known precision frontier** — the
  model occasionally flags high-entropy non-secrets (RC-A: uuid 8%, sha256 9%).
  If your data is dense with UUIDs/hashes/lockfiles, expect over-masking there
  (and consider v3.3a-1, which is more precise on that specific class).
- **Prefixless generic secrets** (passwords, non-vendor tokens) are the harder
  recall case (RC-B password recall 0.66).
- **Chat, logs, and non-English prose are weaker than source code** — on
  row-level Prowl (synthetic/multilingual): Slack 0.68, Jira 0.72, logs 0.53 vs
  code 0.85; non-English recall 0.46 while precision holds at 0.97 (a miss
  problem, not a false-positive one).
- **Not a replacement for all rule-based scanners** — it complements them; a
  rules+SLM hybrid is the higher-ceiling configuration (not included here).
- Regex-friendly corpora favor rule tools; the model's edge is largest on
  non-pattern code.

## Reproducibility & provenance

- Frozen inference path, model/version SHA, and benchmark manifests are in the
  SecMask repo (the evaluation report and external-benchmark records,
  RealCode-1 `PREREG_*` + `REALCODE1_FREEZE.json`).
- RealCode-1 corpora are frozen with corpus + label SHAs; **no
  credential-containing training or eval artifacts are distributed** (RC-B
  values are synthetic; RC-A/RC-C secret values are sanitized/never persisted).
- RealCode-1 A/B/C are **consumed observed canaries**; a pre-registered reserve
  backs a future RC-C-v2.

## Changes vs the previous public version

- Real-code precision collapse fixed (public DistilBERT P 0.004 → 0.53 on unseen
  real code).
- Long documents now handled via sliding windows (previous card's "max 512
  tokens" no longer applies to the reference inference path).
- Superseded metrics: the old NER-eval F1 ~0.52 and "Fast+Filters F1 0.857"
  numbers do not describe this checkpoint; use the tables above.

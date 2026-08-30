# Evaluation results — distilbert-secret-masker v3.3a-RS

Headline metric: **strict exact span + line** (exact value AND line).
Operating point τ=0.99. All sets are frozen, held-out real code unless noted.
File-level and line-level are also reported because rule scanners are line/file
detectors, not span labelers.

## Strict real-code benchmarks (v3.3a-RS)

| set | files (pos/total) | strict span+line P/R/F1 | line P/R/F1 | file P/R/F1 |
|---|---|---|---|---|
| B (non-pattern OSS) | 153/300 | 0.739/0.545/0.627 | 0.850/0.597/0.701 | 0.982/0.719/0.830 |
| C (non-pattern OSS) | 128/275 | 0.735/0.626/0.676 | 0.851/0.697/0.766 | 0.954/0.805/0.873 |
| D (regex-friendly OSS) | 150/300 | 0.714/0.680/0.696 | 0.935/0.898/0.916 | 0.979/0.927/0.952 |

The strict F1 is corpus-stable (0.63–0.70) while rule scanners swing 0.4→0.9
with corpus regex-friendliness.

## Head-to-head vs open-source scanners (file / line F1, same corpora)

| tool | B | C | D |
|---|---|---|---|
| gitleaks | 0.500 / 0.393 | 0.431 / 0.381 | 0.948 / 0.885 |
| detect-secrets | 0.641 / 0.407 | 0.679 / 0.365 | 0.953 / 0.891 |
| TruffleHog | 0.099 / n/a* | 0.231 / n/a* | 0.736 / n/a* |
| Semgrep | 0.145 / 0.058 | 0.171 / 0.072 | 0.527 / 0.421 |
| **v3.3a-RS** | **0.830 / 0.701** | **0.873 / 0.766** | **0.952 / 0.916** |

Only the model is strong in both regimes: it dominates on non-pattern code
(B/C) and ties/leads the best rule tool on regex-friendly code (D).
Tool versions: gitleaks 8.30.1, detect-secrets 1.5.0, TruffleHog 3.97.1,
Semgrep 1.175.0. *TruffleHog line-level not reliably recoverable in-harness;
Semgrep hit parse errors on some files; detect-secrets behavior is
corpus-dependent.

## RealCode-1 (purpose-built, frozen, never trained on)

- **RC-A — precision on natural lookalike negatives** (422 files, 2629 spans):
  lookalike false-positive rate 0.048 overall; uuid 0.080, sha256 0.090,
  md5 0.055, sha1 0.016, SRI 0.006, ipv4/mac/env-name 0.000.
- **RC-B — recall on real-context injected prefixless positives** (710):
  strict P/R/F1 0.962/0.810/0.879; api_key 0.955, high_entropy 0.870,
  basic_auth 0.751, password 0.663.
- **RC-C — blind natural adjudicator** (400 candidates, human-labeled to policy,
  intra-rater 1.0): v3.3a-RS strict recall 0.467, natural-negative FP 0.096;
  Pareto-better than the alternative checkpoint on blind natural code
  (paired McNemar on false positives, p = 0.011).

## External diagnostics (row-level)

| dataset | P | R | F1 |
|---|---|---|---|
| CodeSecret (balanced code) | 1.000 | 0.892 | 0.943 |
| Prowl (code & English slice) | 0.874 | 0.826 | 0.849 |
| Prowl (all sources/langs) | 0.848 | 0.651 | 0.736 |

Source code is the strong domain; chat/ticket/doc prose is weaker.

## Known limitations (measured)

- UUID / hash / checksum lookalikes are the residual precision frontier.
- Prefixless generic secrets (passwords, non-vendor tokens) are the harder recall case.
- Chat / logs / non-English prose are weaker than source code.
- Not a replacement for rule scanners — it complements them.

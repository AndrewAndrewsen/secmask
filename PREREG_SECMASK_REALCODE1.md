# Pre-registration — SecMask RealCode-1 (pure EVALUATION benchmark)

Status: PRE-REGISTERED (design frozen before any data collection/labeling).
Principle: a real-code, strict span+line evaluation benchmark, built to probe
the TWO decisions our diagnostics localized — (1) precision on high-entropy
NON-secret lookalikes, (2) recall on prefixless generic credentials — plus a
blind natural part that we do NOT get to shape to our strengths.

NEVER TRAINED ON. Not now, not later, no exceptions. If SecretBench access
ever lands it becomes an additional independent test, not a dependency.

Naming & provenance: parts are RC-A / RC-B / RC-C (distinct from Benchmark
A/B/C/D). The family is a REAL-CONTEXT STRICT-SPAN benchmark — NOT presented as
identical-provenance to B/C/D. Metric is EXACT span+line (span_eval), so it is
metric-COMPATIBLE and may share a table with B/C/D, but every row MUST carry a
`provenance` tag:
  RC-A = natural real code, natural negatives;
  RC-B = real code context + SYNTHETIC injected positive value;
  RC-C = natural real-code candidate/context, positives SANITIZED to synthetic.
This prevents "RC-B F1 0.91 > Benchmark C 0.87" from being read as two
equivalent natural-real-code results. Compatible metric != equivalent
provenance.

## Standing guardrails (hard)
- NO live credentials are ever stored, tested, or distributed. RC-B values are
  synthetic by construction.
- HARD RULE (RC-C): a raw candidate credential VALUE must NEVER be persisted to
  disk, logs, reports, caches, or manifests. Pipeline:
      GitHub response -> candidate detected -> EPHEMERAL classify/sanitize
      -> ONLY the sanitized representation is written.
  Persist only: non-reversible candidate id, provenance (repo/commit/file/line),
  surrounding real code context, family, lookalike_category, and the
  format-preserving SYNTHETIC replacement (synth_like/synth_pem; offsets
  recomputed; assert value==text[s:e]; assert distinctive original absent). The
  original value lives only in memory during sanitation and is discarded.
- If blind human labeling would require a person to SEE the actual credential
  value, prefer marking it AMBIGUOUS/EXCLUDED over creating any local store of
  potentially-live secrets. The benchmark build must never become a
  secret-harvester.
- RC-A/RC-C negatives are real non-secret strings (UUIDs, hashes, public keys) —
  not credentials — and are kept as-is.
- Repo-disjoint from ALL of train/dev, Benchmark B/C/D, CredData-337, and the
  Benchmark-D repo pool. Frozen repo allow/deny list + commit pins.
- Read-only evaluation. Build -> freeze (corpus + label hashes) -> THEN run
  models. No label edits after models run.
- Blindness (RC-C): candidate generation and labeling use tools/humans, NEVER
  our model, so we do not select the test to our own strengths.

## RC-A — natural hard negatives (precision / lookalike discrimination)
- Source: NEW public OSS repos, repo-disjoint. Real code, real contexts.
- Harvest strings we KNOW are not secrets, by category:
  UUIDs, sha256/sha1/md5 hex + package-integrity/subresource-integrity hashes,
  git object hashes, SSH/PGP PUBLIC keys, base64 data blobs (images/resources),
  Kubernetes/pod/instance identifiers, cache keys, content hashes, ETags,
  build/lockfile checksums, env-var NAMES without values.
- Each item: {repo, commit, file, char-span, line, lookalike_category}, label
  POLICY_NEGATIVE. Verified non-secret by category rule + spot human check.
- Target: 3,000-10,000 spans, category-stratified, with the residual classes we
  KNOW are still weak up-weighted: UUID, sha/md5 checksums, ssh public keys.
- Metrics: false-positive rate per lookalike_category, file-level FP, exact
  false-positive rate. This is a PRECISION test; it has (almost) no positives.

## RC-B — real-context injected positives (recall / exact spans)
- Source: untouched files from NEW repos (repo-disjoint). REAL code; we inject a
  safely-generated synthetic credential at a realistic position (config value,
  constructor arg, env handling, auth header, connection string, etc.).
- Difference from RegexSynth: the VALUE is synthetic, the REST of the file is
  real code. Ground truth is exact and unambiguous: file, line, char-span,
  family. Offsets recomputed + asserted.
- Deliberately mass-load our weakest positives (no vendor prefix):
  generic_password, generic_api_key, generic_high_entropy, basic_auth_header
  (plus a minority of structured families for coverage).
- One injection policy, frozen: at most one injected secret per file; realistic
  key/var naming drawn from the host file's style; A10 span policy.
- Metrics: exact span+line P/R/F1 + overlap + file-level, sliced by family and
  by host language/context type. This is a RECALL test in real context.
- Caveat recorded: injected != naturally-occurring positives; RC-B is a strong
  unseen real-CONTEXT recall test, not a claim about natural secret prevalence.

## RC-C — blind natural candidates (the real SecretBench substitute)
- Source: 100-200 entirely NEW GitHub repos, repo-disjoint, commit-pinned.
- Candidate layer = UNION of external detectors (Gitleaks, detect-secrets,
  TruffleHog/Whispers) + our own entropy/lookalike rules. Our MODEL is NOT run
  in candidate generation.
- Blind labeling to OUR MASKING POLICY (not liveness):
  POLICY_POSITIVE (should be masked), POLICY_NEGATIVE (should not),
  AMBIGUOUS (excluded from headline; reported separately). A credential need
  NOT be live to be POLICY_POSITIVE.
- Then sanitize POLICY_POSITIVE values (guardrail above) and FREEZE corpus +
  labels + hashes. Only AFTER freeze do we run v3.2, v3.3a-1, v3.3a-RS,
  Gitleaks, detect-secrets.
- Metrics: exact span+line P/R/F1 (headline, == value+line (exact value AND line)), overlap,
  file-level; AMBIGUOUS reported but excluded from headline. This is the test
  the model never got to shape.

## Off-domain diagnostic (SEPARATE, not the main benchmark) — VERIFIED
IssueGuard (MSR 2026, arXiv 2602.08072; code github.com/disa-lab/IssueGuard):
54,148 labeled instances, 5,881 true secrets, 75/10/15 split; in-the-wild set =
178 real-world GitHub repos. RESULT NUANCE (important): the widely-quoted
"~0.82" is a MACRO-average F1 across secret/non-secret; the SECRET-class F1 on
the wild set is 0.642, and the in-distribution benchmark F1 is 0.927 (CodeBERT).
So the fair comparison to OUR secret-detection F1 is 0.642 (wild) / 0.927
(in-dist), NOT 0.82. (Distinct from the earlier, smaller arXiv 2410.23657:
25,000 labeled / 437 positives, best F1 0.635 — not this dataset.)
Issue text is NOT source code -> off-domain robustness probe ONLY (how far does
our code specialization transfer to developer prose). Kept OUT of the
RealCode-1 strict-span family. Confirm license before any redistribution;
row/candidate-level metric, aligned to their Secret-class F1 for comparison.

## Frozen evaluation protocol
- Models (frozen): v3.2, v3.3a-1, v3.3a-RS + baselines Gitleaks, detect-secrets.
- Operating point: our canonical tau=0.99 (report a tau-sweep as diagnostic).
- Metric: span_eval exact (span+line) headline; overlap + file-level secondary.
- Per-subset + per-category/family slices; RC-A by lookalike_category; RC-B by
  family; RC-C by policy label.
- Manifest per subset: repos+commits, file/label sha256, sizes, category/family
  counts, sanitization report (n positives replaced), disjointness proof.

## What each subset answers (interpretation, pre-registered)
- RC-A: did the UUID/hash/pubkey FP weakness (localized in EXTERNAL_BENCHMARKS)
  show up in NATURAL code, and per category?
- RC-B: recall on prefixless generics in REAL context (our persistent FN gap).
- RC-C: unbiased holistic real-code capability the model did not select.
Together they map precision (RC-A) and recall (RC-B) on the exact frontier, with
RC-C as the honest, un-gamed anchor.

## Non-goals / cautions
- No training on any part, ever. No tuning of tau against it (tau frozen).
- RC-B is injected -> not proof of natural-prevalence performance; RC-C is.
- A model that only added POSITIVES could inflate RC-B recall while worsening
  RC-A precision (the v3.3a-1 failure mode) -> always read RC-A and RC-B TOGETHER.

## Priority / sequence
1. Build RC-A + RC-B first (fast; cloud has GitHub access; no external gate).
2. Build RC-C as "SecMask RealCode-1" core (labor = blind manual labeling;
   this is the SecretBench substitute).
3. Run the GitHub-issue set as a separate off-domain diagnostic (verify first).
4. If SecretBench later arrives: an extra independent test, not a dependency.

## Repo-selection freeze (RC-A / RC-B / RC-C) — decided BEFORE harvesting
- Population/source defined in advance (e.g. a fixed language x popularity
  sampling frame over public GitHub), written down before any repo is pulled.
- Fixed random seed for selection; the drawn repo+commit list is frozen and
  hashed before harvesting.
- Repo-disjoint vs ALL of train/dev, Benchmark B/C/D, CredData-337, and the
  Benchmark-D repo pool (norm_repo check, asserted).
- NO model scores (ours or others') may influence which repos/files/spans are
  selected. Selection is blind to model behavior.
- Language / filetype strata fixed before harvesting; strata targets frozen.

## Permanent-canary rule (RC-A / RC-B)
Because RC-A/RC-B are built FROM a diagnosed weakness they are already somewhat
targeted. Therefore, after the first freeze they are PERMANENT canaries:
- NO iteration against v3.3a-RS (or any model) after the first result.
- If we later discover a missed variant (e.g. a new UUID/hash form), it goes to
  FUTURE train/dev — it is NOT added to RC-A/RC-B v1, which stay byte-frozen.
- Any expansion is a NEW version id (RC-A-v2, ...), evaluated separately; v1
  numbers remain comparable over time.
- RC-C is the guard against RC-A/RC-B only ever measuring what we anticipated:
  it is blind and natural, so it can surprise us where A/B cannot.

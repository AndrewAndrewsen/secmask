# RealCode-1 repo-selection v1 (FROZEN before harvesting)

Frozen deterministic frame for RC-A / RC-B / RC-C repositories. No repo, file,
or span is chosen by any model score. Selection is captured-and-hashed (a
GitHub snapshot is not time-reproducible, so the FROZEN artifact is the captured
list + SHAs + hash, not a re-runnable query).

## Frozen frame
| Dimension | Frozen rule |
|---|---|
| Languages | Python, JS/TS, Go, Java (4 language groups) |
| Popularity strata | 100-999, 1k-9,999, >=10k stars (3 buckets) |
| Config/YAML/TOML/shell | NOT a repo stratum — harvested as FILETYPES inside the 4 language repos |
| Eligibility | public, non-fork, non-archived, non-mirror, real source repo, has a default branch, size>0 |
| Snapshot | GitHub search on a recorded date; results captured verbatim |
| Ordering | stable sort by (stars desc, repo_node_id) then seeded shuffle (seed=20260829) |
| Identity | GitHub repo node_id + normalized owner/repo (norm_repo) |
| Version pin | default-branch HEAD commit SHA pinned per repo |
| Leakage | repo AND fork-family disjoint from train/dev, Benchmark B/C/D, CredData-337, Benchmark-D pool |
| Model influence | NONE at any stage |

Per stratum (language x bucket = 12 cells): draw a fixed N eligible repos
(default 12/cell -> ~144-repo pool), spread evenly across the 3 sub-bands and
both sort directions (~2 from each end of each sub-band). Pool size, per-cell N,
and sub-band edges are frozen in the manifest.

## Simultaneous A/B/C partition (frozen NOW; RC-C not harvested yet)
The whole pool is partitioned deterministically into disjoint repo sets BEFORE
any A/B result is seen:
- Round-robin by frozen order within each stratum -> RC-A / RC-B / RC-C, so each
  gets a balanced language x popularity mix.
- Repo sets are DISJOINT across A, B, C (not merely file-disjoint).
- RC-C repos are commit-pinned + hashed now; harvesting/labeling deferred. This
  prevents choosing a "good blind test" after seeing A/B.

## Pre-persistence sanitation gate (HARD — before any file is written)
Frozen scanner union for the gate: Gitleaks + detect-secrets + a frozen
entropy/lookalike rule set (+ TruffleHog if available; version-pinned). Rules:
- RC-B: a host file is ELIGIBLE only if the frozen scanner union finds NO
  potential credential anywhere in it. If any is found -> REJECT the file, draw
  another. Then inject our OWN synthetic prefixless positive into the clean
  real-code file. (So RC-B files carry exactly one secret: ours, synthetic.)
- RC-A: we WANT UUID/hash/public-key/base64/identifier lookalikes -> those
  categories are explicitly WHITELISTED-AS-NEGATIVE. Any OTHER credential-like
  span flagged by the union makes the file REJECT/sanitize before anything is
  persisted.
- No raw candidate credential value is ever written to disk/logs/reports/cache/
  manifest (see PREREG_SECMASK_REALCODE1 guardrails). Classification/sanitation
  is ephemeral; only sanitized representation + provenance persist.

## Build order (after this freeze is committed)
1. Snapshot + deterministic selection of the A/B/C repo pool.
2. Pin default-branch SHAs; write manifest + hashes.
3. Verify disjointness + fork ancestry vs all existing pools (assert 0 overlap).
4. RC-A: harvest natural lookalike-negatives (category-stratified) through the
   sanitation gate.
5. RC-B: inject prefixless synthetic positives into scanner-clean real files;
   recompute offsets + assert.
6. Freeze corpus + label hashes.
7. ONLY THEN run v3.2 / v3.3a-1 / v3.3a-RS / Gitleaks / detect-secrets.

## Permanent freeze
Once RC-A/RC-B have their first model results, v1 is byte-frozen. New variants
found later go to future train/dev or RealCode-2 — never into RC-A/RC-B v1.

## Operational requirements
- GITHUB_TOKEN required (core API is 60/hr unauth vs 5000/hr auth; pinning SHAs
  for a ~144-repo pool needs auth). Token used read-only for public metadata.
- Runs in the CLOUD container (GitHub reachable there; the Mac VM egress is
  restricted). Harvest/sanitize in cloud -> commit frozen SANITIZED corpus to
  the Mac -> evaluate on the Mac where the models live. Raw repos are NOT
  retained after sanitized harvest.

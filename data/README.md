# Benchmark data

## RealCode-1 (included, sanitized)
`realcode1/` ships the frozen RealCode-1 eval corpora. These are **safe to
distribute by construction**:
- RC-A: natural lookalike **negatives** — real code, no secret values stored.
- RC-B: real code context with **synthetic** injected secret values.
- RC-C (subset_v1): natural candidates with secret values **sanitized**
  (format/semantic-class-preserving synthetic replacement); raw values are never
  persisted. The RC-C reserve pool is intentionally **not** published (it backs a
  pre-registered RC-C-v2).

## B / C / D benchmarks (rebuild locally — NOT distributed)
Benchmarks B/C/D are derived from Samsung **CredData**, which deliberately does
not redistribute raw secrets. This repository follows the same policy: the raw
secret files and value-bearing ground truth are **not** committed. To reproduce
B/C/D, obtain CredData from its upstream source and run the builders
(`run_benchB.py` / `run_benchC.py` / `run_benchD.py` and the selection/ingest
scripts). No credential values are stored in this repo.

## External evaluation datasets (fetch separately — NOT distributed)
The Prowl and CodeSecret results in `MODEL_CARD.md` / `RESULTS.md` are produced
by `ext_secret_bench.py` (row-level detection) and diagnosed by
`prowl_error_dump.py` / `prowl_error_taxonomy.py`. These are third-party datasets
already published on the Hugging Face Hub, so they are **not** re-vendored here.
Fetch them to the exact local paths the scripts expect:

```
# Prowl
hf download Podric/prowl-secrets-corpus \
  --repo-type dataset --local-dir data/extbench/prowl

# CodeSecret
hf download asudarshan/Synthetic-CodeSecretClassifier-Instruct \
  --repo-type dataset --local-dir data/extbench/codesecret
```

To reproduce our exact numbers, pin the dataset revision and verify the file
hash — the Hub content can change under a moving `main`:

| Dataset | HF repo | Revision (commit) | Benchmarked file | SHA-256 | Size |
|---|---|---|---|---|---|
| Prowl | `Podric/prowl-secrets-corpus` | `06f6d2cdf6a64c6d77ffb95a8dfb7abf7913b885` | `data/extbench/prowl/prowlbench.jsonl` | `0a66fc09b180261eabb311af04f7be5112895e27dd08dbd18cdcbdd07021b70f` | 8,692,566 B / 24,603 rows |
| CodeSecret | `asudarshan/Synthetic-CodeSecretClassifier-Instruct` | `09ecc0cf7f333e1296cb6303bead16e89c40de18` | `data/extbench/codesecret/formatted_dataset_validation.jsonl` | `e4bff3f10caf3f760318bb06d464f2d400f48053a36afa00831d09849dae2eb5` | 7,315,968 B / 20,000 rows |

Pin + verify example:
```
hf download Podric/prowl-secrets-corpus --repo-type dataset \
  --revision 06f6d2cdf6a64c6d77ffb95a8dfb7abf7913b885 \
  --local-dir data/extbench/prowl
shasum -a 256 data/extbench/prowl/prowlbench.jsonl
# expect 0a66fc09b180261eabb311af04f7be5112895e27dd08dbd18cdcbdd07021b70f
```

**Licensing / provenance.** CodeSecret is **MIT**. Prowl is
**CC-BY-NC-4.0 (non-commercial)** — the Prowl evaluation figures are reported for
research comparison only; downstream commercial use of that dataset requires
permission from its authors. Consult each dataset card for the authoritative
terms before use. These are external **synthetic** row-level detection sets (not
real-code, not an SB holdout); for Prowl the `span` field is candidate/augmented
and is **not** used for our strict-span scoring.

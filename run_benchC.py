#!/usr/bin/env python3
"""
Benchmark C — FINAL ONE-SHOT generalization score for v3.2.

Frozen operating point (locked before this run, per user confirmation):
  * weights : outputs/distilbert-secret-masker-v3.2/best
  * inference: windowed span_infer.py (argmax decode)
  * threshold: tau = 0.85  (selected on Dev only)

Benchmark C (benchmark_c/, 40 repo-disjoint real-OSS repos, pristine,
never scored by any model) is evaluated EXACTLY ONCE. The script verifies
the corpus sha256 against the frozen manifest before scoring, so any
accidental change to the corpus aborts the run.

Run in a terminal (single process):
  ~/venv/bin/python run_benchC.py
"""
import hashlib, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

from span_infer import load_model, infer_spans
from span_eval import evaluate

MODEL = "outputs/distilbert-secret-masker-v3.2/best"
TAU = 0.85
CDIR = "benchmark_c"
REPORTS = "reports"

def sha256_bytes(b): return hashlib.sha256(b).hexdigest()

def main():
    # ---- integrity gate --------------------------------------------------
    man = json.load(open(os.path.join(CDIR, "manifest.json")))
    gt = [json.loads(l) for l in open(os.path.join(CDIR, "ground_truth.jsonl")) if l.strip()]
    file_hashes = {}
    for r in gt:
        p = os.path.join(CDIR, "files", r["file"])
        file_hashes[r["file"]] = sha256_bytes(open(p, "rb").read())
    corpus_hash = sha256_bytes("".join(file_hashes[k] for k in sorted(file_hashes)).encode())
    exp = man.get("corpus_sha256")
    if exp and corpus_hash != exp:
        print(f"ABORT: corpus sha256 mismatch\n  manifest {exp}\n  actual   {corpus_hash}")
        sys.exit(1)
    print(f"corpus integrity OK: {corpus_hash}")
    print(f"files {len(gt)} | positive {sum(1 for r in gt if r.get('file_has_secrets'))} | "
          f"spans {sum(len(r['spans']) for r in gt)}")

    # ---- inputs / gold ---------------------------------------------------
    rows = [{"id": r["id"], "text": open(os.path.join(CDIR, "files", r["file"]),
             encoding="utf-8", errors="replace").read()} for r in gt]
    gold = {r["id"]: [{"start": s["start"], "end": s["end"], "line": s.get("line"),
                        "value": s.get("value")} for s in r["spans"]] for r in gt}

    # ---- inference (argmax once, capture scores) -------------------------
    print(f"\nloading {MODEL}")
    tok, model, i2l = load_model(MODEL)
    print("id2label", i2l, "| tau", TAU)
    preds = {}
    t0 = time.time()
    for i, r in enumerate(rows):
        spans, _ = infer_spans(r["text"], tok, model, i2l, mode="argmax")
        preds[r["id"]] = spans
        if (i + 1) % 50 == 0:
            print(f"  {i+1}/{len(rows)}  ({time.time()-t0:.0f}s)")

    os.makedirs(REPORTS, exist_ok=True)
    with open(f"{REPORTS}/benchC_v32_argmax.jsonl", "w") as f:
        for k, v in preds.items():
            f.write(json.dumps({"id": k, "spans": v}, ensure_ascii=False) + "\n")

    def score(pd, name, out, tau_meta, decode):
        res = {"name": name, "operating_point": {"model": MODEL, "tau": tau_meta,
               "decode": decode, "inference": "windowed span_infer.py"},
               "corpus_sha256": corpus_hash, **evaluate(gold, pd)}
        json.dump(res, open(out, "w"), indent=2)
        e, ov, fl = res["exact"], res["overlap"], res["file_level"]
        print(f"\n{name}")
        print(f"  exact   P/R/F1 {e['precision']:.3f}/{e['recall']:.3f}/{e['f1']:.3f}")
        print(f"  overlap P/R/F1 {ov['precision']:.3f}/{ov['recall']:.3f}/{ov['f1']:.3f}")
        print(f"  file    P/R/F1 {fl['precision']:.3f}/{fl['recall']:.3f}/{fl['f1']:.3f}")
        print(f"  gold {res['gold_spans']} pred {res['pred_spans']} inflation {res['inflation_ratio']} "
              f"frag {res['fragmentation']['pct_fragmented']}%")
        return res

    print("\n================ BENCHMARK C — FINAL ================")
    score(preds, "v3.2-windowed-argmax-BENCH-C",
          f"{REPORTS}/benchC_metrics_v32_argmax.json", None, "argmax")
    thr = {k: [s for s in v if s.get("score", 1.0) >= TAU] for k, v in preds.items()}
    with open(f"{REPORTS}/benchC_v32_thr.jsonl", "w") as f:
        for k, v in thr.items():
            f.write(json.dumps({"id": k, "spans": v}, ensure_ascii=False) + "\n")
    score(thr, f"v3.2-threshold-tau{TAU}-BENCH-C",
          f"{REPORTS}/benchC_metrics_v32_thr.json", TAU, "argmax+threshold")
    print("\nDONE in %.0fs — Benchmark C scored ONCE. Do not re-run." % (time.time()-t0))

if __name__ == "__main__":
    main()

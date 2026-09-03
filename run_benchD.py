#!/usr/bin/env python3
"""Benchmark D (interim injection-based) — score gitleaks and the standalone
model ONCE with the FROZEN operating point:
  * standalone Gitleaks 8.30.1
  * standalone v3.2 (windowed span_infer, tau .85)
Integrity-gated (corpus sha256 vs manifest) + leakage check vs all
internal/B/C values. Run in your terminal:  ~/venv/bin/python run_benchD.py
"""
import json, os, sys, hashlib, subprocess, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("HF_HUB_OFFLINE","1"); os.environ.setdefault("TOKENIZERS_PARALLELISM","false")
from span_eval import evaluate
from score_scanners_C import conv_gitleaks, _safe_json

DDIR="benchmark_d"; MODEL="outputs/distilbert-secret-masker-v3.2/best"
TAU=0.85; GITLEAKS=os.path.expanduser("gitleaks")  # expects gitleaks on PATH
def sha(b): return hashlib.sha256(b).hexdigest()

def main():
    man=json.load(open(f"{DDIR}/manifest.json"))
    gt=[json.loads(l) for l in open(f"{DDIR}/ground_truth.jsonl") if l.strip()]
    fh={g["file"]:sha(open(f"{DDIR}/files/{g['file']}","rb").read()) for g in gt}
    ch=sha("".join(fh[k] for k in sorted(fh)).encode())
    if ch!=man.get("corpus_sha256"):
        print(f"ABORT: corpus sha mismatch {ch} != {man.get('corpus_sha256')}"); sys.exit(1)
    print(f"corpus integrity OK: {ch[:16]} | {len(gt)} files, "
          f"{sum(len(g['spans']) for g in gt)} spans")

    file2id={g["file"]:g["id"] for g in gt}
    texts={g["file"]:open(f"{DDIR}/files/{g['file']}",encoding="utf-8",errors="replace").read() for g in gt}
    gold={g["id"]:[{"start":s["start"],"end":s["end"],"line":s.get("line"),"value":s.get("value")} for s in g["spans"]] for g in gt}

    # leakage check vs internal + B/C
    internal=set()
    for fn in ("data/v3_train.jsonl","data/v3_val.jsonl","data/v3_test.jsonl","data/v31_test.jsonl"):
        if os.path.exists(fn):
            for l in open(fn):
                if l.strip():
                    for s in json.loads(l).get("spans",[]): internal.add(s.get("value"))
    for fn in ("benchmark_b/gold_spans.jsonl","benchmark_c/ground_truth.jsonl"):
        if os.path.exists(fn):
            for l in open(fn):
                if l.strip():
                    for s in json.loads(l).get("spans",[]): internal.add(s.get("value"))
    dvals={s["value"] for g in gt for s in g["spans"]}
    leak=dvals & internal
    print(f"value leakage vs internal/B/C: {len(leak)}")

    # standalone gitleaks
    print("\nrunning gitleaks on D ...")
    subprocess.run(f"gitleaks detect --source {DDIR}/files --no-git --report-format json --report-path reports/glD.json",
                   shell=True, capture_output=True)
    glp,miss=conv_gitleaks(_safe_json("reports/glD.json") or [], file2id, texts)
    gl={g["id"]:[] for g in gt}; gl.update(glp)

    # v3.2 inference
    from span_infer import load_model, infer_spans
    print(f"running v3.2 on D ({len(gt)} files) ...")
    tok,model,i2l=load_model(MODEL)
    v32={}; t0=time.time()
    for i,g in enumerate(gt):
        spans,_=infer_spans(texts[g["file"]],tok,model,i2l,mode="argmax")
        v32[g["id"]]=spans
        if (i+1)%75==0: print(f"  {i+1}/{len(gt)} ({time.time()-t0:.0f}s)")
    with open("reports/benchD_v32_argmax.jsonl","w") as f:
        for k,v in v32.items(): f.write(json.dumps({"id":k,"spans":v},ensure_ascii=False)+"\n")

    v32_thr={k:[s for s in v if s.get("score",1)>=TAU] for k,v in v32.items()}

    def rep(name,pd,out):
        r={"name":name,"corpus_sha256":ch,**evaluate(gold,pd)}
        json.dump(r,open(out,"w"),indent=2)
        e,o,fl=r["exact"],r["overlap"],r["file_level"]
        print(f"\n{name}\n  exact P/R/F1 {e['precision']:.3f}/{e['recall']:.3f}/{e['f1']:.3f} | "
              f"overlap F {o['f1']:.3f} | file P/R/F1 {fl['precision']:.3f}/{fl['recall']:.3f}/{fl['f1']:.3f} | "
              f"pred {r['pred_spans']} inflation {r['inflation_ratio']}")
        return r
    print("\n================ BENCHMARK D — gitleaks + standalone model ================")
    rep("gitleaks-8.30.1-BENCH-D",gl,"reports/benchD_metrics_gitleaks.json")
    rep("v3.2-tau.85-BENCH-D",v32_thr,"reports/benchD_metrics_v32.json")
    print("\nDONE. (Interim injection-based D; SecretBench positives supersede when access lands.)")

if __name__=="__main__": main()

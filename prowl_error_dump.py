#!/usr/bin/env python3
"""Dump per-row predictions for prowl error-taxonomy (READ-ONLY, no training).
Only the two subsets we analyze: T4 hard-negatives (FP source) and code&en
positives (FN source). Writes reports/prowl_errrows.jsonl. Run in a terminal
(long-ish, ~15k inferences).

  ~/venv/bin/python3 prowl_error_dump.py --model outputs/distilbert-secret-masker-v3.3a-RS/best --tag v33aRS
"""
import argparse, json, os, sys, time
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("HF_HUB_OFFLINE","1"); os.environ.setdefault("TOKENIZERS_PARALLELISM","false")
from span_infer import load_model, infer_spans

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--model",required=True); ap.add_argument("--tag",required=True)
    ap.add_argument("--path",default="data/extbench/prowl/prowlbench.jsonl")
    a=ap.parse_args()
    rows=[json.loads(l) for l in open(a.path)]
    sub=[r for r in rows if r.get("tier")=="T4_hard_negative"
         or (r.get("source")=="code" and r.get("lang")=="en" and r.get("label")==1)]
    tok,model,i2l=load_model(a.model)
    out=open(f"reports/prowl_errrows_{a.tag}.jsonl","w"); t0=time.time()
    for i,r in enumerate(sub):
        spans=infer_spans(r["text"],tok,model,i2l,mode="argmax")[0]
        spans=sorted(spans,key=lambda s:-s["score"])
        sp=r.get("span"); gv=None
        if sp and len(sp)==2 and 0<=sp[0]<sp[1]<=len(r["text"]): gv=r["text"][sp[0]:sp[1]]
        out.write(json.dumps({"id":r["id"],"tier":r.get("tier"),"source":r.get("source"),
            "lang":r.get("lang"),"type":r.get("type"),"label":r["label"],
            "maxscore":spans[0]["score"] if spans else 0.0,
            "pred_values":[s["value"] for s in spans[:3]],
            "gold_value":gv},ensure_ascii=False)+"\n")
        if (i+1)%1000==0: print(f"  {i+1}/{len(sub)} ({time.time()-t0:.0f}s)",flush=True)
    out.close(); print(f"wrote reports/prowl_errrows_{a.tag}.jsonl ({len(sub)} rows)")
if __name__=="__main__": main()

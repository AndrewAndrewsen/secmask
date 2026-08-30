#!/usr/bin/env python3
"""Row-level detection benchmark of a frozen standalone model against external
SYNTHETIC secret datasets (prowlbench, codesecret-instruct). Read-only eval.

Row-level ONLY (fair across differing secret-boundary conventions): pred
positive = the model emits >=1 span with score>=tau; gold positive = the
dataset's label. prowlbench `span` is NOT used (it is candidate/augmented and
often not a valid char offset). Slices: source (code vs chat/docs/log), lang
(en vs non-en), tier (hard-negative FP). One argmax pass per row; tau swept in
post from the max span score.

  ~/venv/bin/python3 ext_secret_bench.py --model outputs/distilbert-secret-masker-v3.3a-RS/best \
      --tag v33aRS --limit 6000
"""
import argparse, json, os, sys, time, random, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("HF_HUB_OFFLINE","1"); os.environ.setdefault("TOKENIZERS_PARALLELISM","false")
from span_infer import load_model, infer_spans

def maxscore(text, tok, model, i2l):
    sp=infer_spans(text, tok, model, i2l, mode="argmax")[0]
    return max((s["score"] for s in sp), default=0.0)

def prf(tp,fp,fn):
    p=tp/(tp+fp) if tp+fp else 0.0; r=tp/(tp+fn) if tp+fn else 0.0
    f=2*p*r/(p+r) if p+r else 0.0
    return {"tp":tp,"fp":fp,"fn":fn,"precision":round(p,4),"recall":round(r,4),"f1":round(f,4)}

def rowlevel(scored, tau):
    """scored: list of (maxscore, gold_pos_bool)."""
    tp=fp=fn=tn=0
    for sc,g in scored:
        pred = sc>=tau
        if g and pred: tp+=1
        elif (not g) and pred: fp+=1
        elif g and (not pred): fn+=1
        else: tn+=1
    m=prf(tp,fp,fn); m["tn"]=tn; m["n"]=len(scored)
    m["accuracy"]=round((tp+tn)/len(scored),4) if scored else 0.0
    return m

def stratified(rows, keyfn, limit, seed=13):
    if not limit or limit>=len(rows): return rows
    rng=random.Random(seed); groups=collections.defaultdict(list)
    for r in rows: groups[keyfn(r)].append(r)
    out=[]; ng=len(groups)
    for k,g in groups.items():
        rng.shuffle(g); out+=g[:max(1,round(limit*len(g)/len(rows)))]
    rng.shuffle(out); return out[:limit]

def bench_prowl(path, tok, model, i2l, tau, limit):
    rows=[json.loads(l) for l in open(path)]
    rows=stratified(rows, lambda r:(r["source"], r["label"]), limit)
    scored=[]; t0=time.time()
    for i,r in enumerate(rows):
        sc=maxscore(r["text"],tok,model,i2l)
        scored.append((sc, r["label"]==1, r["source"], r.get("lang","?"), r.get("tier","?")))
        if (i+1)%1000==0: print(f"  [prowl] {i+1}/{len(rows)} ({time.time()-t0:.0f}s)",flush=True)
    base=[(s,g) for s,g,_,_,_ in scored]
    out={"n":len(scored),"tau":tau,"overall":rowlevel(base,tau)}
    # slices
    def slc(pred): 
        sub=[(s,g) for s,g,src,lg,ti in scored if pred(src,lg,ti)]
        return rowlevel(sub,tau) if sub else None
    out["by_source"]={src:slc(lambda s,l,t,S=src: s==S) for src in sorted(set(x[2] for x in scored))}
    out["lang_en"]=slc(lambda s,l,t: l=="en"); out["lang_non_en"]=slc(lambda s,l,t: l!="en")
    out["code_en"]=slc(lambda s,l,t: s=="code" and l=="en")
    # hard-negative FP rate (tier T4 are the negatives)
    hn=[(s,g) for s,g,src,lg,ti in scored if ti=="T4_hard_negative"]
    out["hard_negative_FP_rate"]=round(sum(1 for s,g in hn if s>=tau)/len(hn),4) if hn else None
    out["tau_sweep_overall"]=[{"tau":t,**{k:rowlevel(base,t)[k] for k in ("precision","recall","f1","accuracy")}}
                              for t in [0.5,0.6,0.7,0.8,0.9,0.95,0.99]]
    return out

def bench_codesecret(path, tok, model, i2l, tau, limit):
    rows=[]
    for l in open(path):
        t=json.loads(l)["text"]
        if "<|code|>" not in t or "<|assistant|>" not in t: continue
        code=t.split("<|code|>",1)[1].split("<|assistant|>",1)[0].strip()
        ans=t.split("<|assistant|>",1)[1].strip().lower()
        rows.append((code, ans.startswith("yes")))
    rng=random.Random(13); rng.shuffle(rows)
    if limit and limit<len(rows): rows=rows[:limit]
    scored=[]; t0=time.time()
    for i,(code,g) in enumerate(rows):
        scored.append((maxscore(code,tok,model,i2l), g))
        if (i+1)%1000==0: print(f"  [codesecret] {i+1}/{len(rows)} ({time.time()-t0:.0f}s)",flush=True)
    return {"n":len(scored),"tau":tau,"overall":rowlevel(scored,tau),
            "tau_sweep_overall":[{"tau":t,**{k:rowlevel(scored,t)[k] for k in ("precision","recall","f1","accuracy")}}
                                 for t in [0.5,0.6,0.7,0.8,0.9,0.95,0.99]]}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--model",required=True); ap.add_argument("--tag",required=True)
    ap.add_argument("--tau",type=float,default=0.99); ap.add_argument("--limit",type=int,default=6000,
        help="stratified sample size per dataset; 0 = full")
    a=ap.parse_args()
    tok,model,i2l=load_model(a.model)
    res={"model":a.model,"tag":a.tag,"tau":a.tau,"limit":a.limit,
         "note":"row-level detection on external SYNTHETIC sets; not real-code, not SB-holdout; prowl spans unused (candidate/augmented)"}
    P="data/extbench/prowl/prowlbench.jsonl"; C="data/extbench/codesecret/formatted_dataset_validation.jsonl"
    if os.path.exists(P): res["prowlbench"]=bench_prowl(P,tok,model,i2l,a.tau,a.limit)
    if os.path.exists(C): res["codesecret"]=bench_codesecret(C,tok,model,i2l,a.tau,a.limit)
    os.makedirs("reports",exist_ok=True)
    json.dump(res,open(f"reports/extbench_{a.tag}.json","w"),indent=2)
    pb=res.get("prowlbench",{}); cs=res.get("codesecret",{})
    print("\n===== EXTERNAL BENCHMARK (row-level, tau=%.2f, %s) ====="%(a.tau,a.tag))
    if pb:
        o=pb["overall"]; print(f"prowlbench overall: P {o['precision']} R {o['recall']} F1 {o['f1']} acc {o['accuracy']} (n={o['n']})")
        ce=pb.get("code_en"); 
        if ce: print(f"  code&en slice:    P {ce['precision']} R {ce['recall']} F1 {ce['f1']} (n={ce['n']})")
        print(f"  hard-negative FP rate: {pb['hard_negative_FP_rate']}")
        print("  by source:", {k:(v['f1'] if v else None) for k,v in pb['by_source'].items()})
    if cs:
        o=cs["overall"]; print(f"codesecret overall: P {o['precision']} R {o['recall']} F1 {o['f1']} acc {o['accuracy']} (n={o['n']})")
    print(f"report -> reports/extbench_{a.tag}.json")

if __name__=="__main__": main()

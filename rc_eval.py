#!/usr/bin/env python3
"""SecMask RealCode-1 evaluator (frozen corpora; read RC-A and RC-B TOGETHER).

RC-A  precision / FALSE-POSITIVE behavior on natural lookalike NEGATIVES.
      Every RC-A file is all-negative, so any predicted span is a false
      positive. Headline: per-category FP rate (can the model leave
      uuid / hash / sri / pubkey / ip / mac / env-name alone?) + file-level
      FP rate. Off-lookalike FP spans (flagging plain code) counted too.

RC-B  exact span+line RECALL on real-context injected prefixless POSITIVES,
      broken down per family and per language. Strict (span+line) is the
      headline ("value+line" equivalent); exact/overlap/file reported.

Baselines: gitleaks + detect-secrets, scored at FILE and LINE level only
(they are not span labelers) — clearly separated from the model span metrics.

Usage (models are heavy on CPU; predict is resumable/sliceable):
  python3 rc_eval.py predict --model outputs/distilbert-secret-masker-v3.3a-RS/best \
        --corpus rc_a --tau 0.99 --tag v33aRS [--start 0 --limit 0]
  python3 rc_eval.py predict --model .../best --corpus rc_b --tau 0.99 --tag v33aRS
  python3 rc_eval.py score   --tag v33aRS
  python3 rc_eval.py scan    --corpus rc_a          # gitleaks + detect-secrets
  python3 rc_eval.py scan    --corpus rc_b
  python3 rc_eval.py score-scan
"""
import argparse, json, os, sys, time, collections, subprocess, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("HF_HUB_OFFLINE","1"); os.environ.setdefault("TOKENIZERS_PARALLELISM","false")
RC="realcode1"

def load_gt(corpus): return [json.loads(l) for l in open(f"{RC}/{corpus}/ground_truth.jsonl") if l.strip()]
def read_file(corpus,fid): return open(f"{RC}/{corpus}/files/{fid}",encoding="utf-8",errors="replace").read()
def preds_path(tag,corpus): return f"{RC}/preds/{tag}_{corpus}.jsonl"
def load_preds(tag,corpus):
    d={}
    with open(preds_path(tag,corpus)) as f:
        for l in f:
            if l.strip():
                r=json.loads(l); d[r["id"]]=r.get("spans",[])
    return d

# ------------------------------------------------------------------ predict
def cmd_predict(a):
    from span_infer import load_model, infer_spans
    import span_infer
    tok,model,i2l=load_model(a.model,a.device)
    gt=load_gt(a.corpus); os.makedirs(f"{RC}/preds",exist_ok=True)
    raw=getattr(a,"raw",False)
    mode="argmax" if raw else "threshold"
    out=f"{RC}/preds/{a.tag}_raw_{a.corpus}.jsonl" if raw else preds_path(a.tag,a.corpus)
    end=len(gt) if not a.limit else min(len(gt),a.start+a.limit)
    todo=gt[a.start:end]; t0=time.time()
    mode="w" if a.start==0 else "a"
    with open(out,mode,encoding="utf-8") as f:
        for i,g in enumerate(todo):
            text=read_file(a.corpus,g["file"])
            spans=infer_spans(text,tok,model,i2l,mode=mode,tau=(None if raw else a.tau),device=a.device)[0]
            f.write(json.dumps({"id":g["id"],"spans":spans},ensure_ascii=False)+"\n")
            if (i+1)%100==0: print(f"  [{a.corpus}] {i+1}/{len(todo)} ({time.time()-t0:.0f}s)",flush=True)
    print(f"wrote [{a.start}:{end}) -> {out}  (tau={a.tau}) max_fwd={span_infer.MAX_FORWARD_TOKENS} (<=512)")

# ------------------------------------------------------------------ scoring helpers
def _overlaps(p,s,e): return min(p["end"],e)>max(p["start"],s)

def score_rc_a(preds,gt):
    cat_tot=collections.Counter(); cat_flag=collections.Counter()
    files_with_pred=0; total_pred=0; off_lk_spans=0; nfiles=len(gt)
    for g in gt:
        ps=preds.get(g["id"],[]); 
        if ps: files_with_pred+=1
        total_pred+=len(ps)
        lks=g["lookalike_spans"]
        for lk in lks:
            cat_tot[lk["category"]]+=1
            if any(_overlaps(p,lk["start"],lk["end"]) for p in ps): cat_flag[lk["category"]]+=1
        for p in ps:
            if not any(_overlaps(p,lk["start"],lk["end"]) for lk in lks): off_lk_spans+=1
    per_cat={c:{"lookalikes":cat_tot[c],"flagged":cat_flag[c],
                "fp_rate":round(cat_flag[c]/cat_tot[c],4) if cat_tot[c] else None}
             for c in sorted(cat_tot)}
    return {"files":nfiles,"files_with_any_pred":files_with_pred,
            "file_fp_rate":round(files_with_pred/nfiles,4) if nfiles else None,
            "total_pred_spans":total_pred,"off_lookalike_fp_spans":off_lk_spans,
            "lookalike_spans":sum(cat_tot.values()),
            "flagged_lookalikes":sum(cat_flag.values()),
            "overall_lookalike_fp_rate":round(sum(cat_flag.values())/max(1,sum(cat_tot.values())),4),
            "per_category":per_cat}

def score_rc_b(preds,gt):
    from span_eval import evaluate
    gold={g["id"]:[{"start":s["start"],"end":s["end"],"line":s.get("line"),"value":s.get("value")} for s in g["spans"]] for g in gt}
    def sub(ids):
        ids=set(ids); return evaluate({k:gold[k] for k in ids},{k:preds.get(k,[]) for k in ids})
    allids=[g["id"] for g in gt]
    overall=sub(allids)
    by_fam={}; fam_ids=collections.defaultdict(list)
    for g in gt: fam_ids[g["spans"][0]["type"]].append(g["id"])
    for fam,ids in sorted(fam_ids.items()):
        r=sub(ids); by_fam[fam]={"n":len(ids),
            "strict_recall":r["strict_span_and_line"]["recall"],
            "exact_recall":r["exact"]["recall"],"overlap_recall":r["overlap"]["recall"],
            "file_recall":r["file_level"]["recall"]}
    by_lang={}; lang_ids=collections.defaultdict(list)
    for g in gt: lang_ids[g["lang"]].append(g["id"])
    for lang,ids in sorted(lang_ids.items()):
        r=sub(ids); by_lang[lang]={"n":len(ids),
            "strict_recall":r["strict_span_and_line"]["recall"],
            "exact_recall":r["exact"]["recall"],"file_recall":r["file_level"]["recall"]}
    return {"overall":{"strict":overall["strict_span_and_line"],"exact":overall["exact"],
            "overlap":overall["overlap"],"file_level":overall["file_level"],
            "inflation_ratio":overall["inflation_ratio"]},
            "by_family":by_fam,"by_language":by_lang}

def cmd_score(a):
    ga=load_gt("rc_a"); gb=load_gt("rc_b")
    pa=load_preds(a.tag,"rc_a"); pb=load_preds(a.tag,"rc_b")
    rc_a=score_rc_a(pa,ga); rc_b=score_rc_b(pb,gb)
    res={"tag":a.tag,"tau":a.tau,"rc_a":rc_a,"rc_b":rc_b}
    os.makedirs(f"{RC}/results",exist_ok=True)
    json.dump(res,open(f"{RC}/results/{a.tag}.json","w"),indent=2)
    # read-together summary
    print(f"\n================= {a.tag} @ tau={a.tau} =================")
    print(f"RC-B  RECALL (positives, n={rc_b['overall']['file_level']['tp']+rc_b['overall']['file_level']['fn']}):")
    o=rc_b["overall"]
    print(f"   strict span+line  P/R/F1 = {o['strict']['precision']:.3f}/{o['strict']['recall']:.3f}/{o['strict']['f1']:.3f}")
    print(f"   exact span        R      = {o['exact']['recall']:.3f}   file R = {o['file_level']['recall']:.3f}   infl = {o['inflation_ratio']}")
    print("   by family (strict recall):  "+"  ".join(f"{k}={v['strict_recall']:.3f}" for k,v in rc_b["by_family"].items()))
    print(f"RC-A  FALSE POSITIVES (negatives, {rc_a['files']} files):")
    print(f"   file FP rate = {rc_a['file_fp_rate']:.3f}   lookalike FP rate = {rc_a['overall_lookalike_fp_rate']:.3f}   off-lookalike FP spans = {rc_a['off_lookalike_fp_spans']}")
    print("   per-category FP rate:")
    for c,v in rc_a["per_category"].items():
        if v["lookalikes"]>=10:
            print(f"      {c:16s} {v['fp_rate']:.3f}  ({v['flagged']}/{v['lookalikes']})")
    print(f"\nwrote {RC}/results/{a.tag}.json")

# ------------------------------------------------------------------ scanners
def gitleaks_lines(path):
    with tempfile.NamedTemporaryFile(suffix=".json",delete=False) as tf: rep=tf.name
    try:
        subprocess.run(["gitleaks","detect","--no-git","--source",path,"-f","json","-r",rep],capture_output=True,timeout=600)
        if os.path.getsize(rep)==0: return {}
        d=json.load(open(rep)); out=collections.defaultdict(set)
        for f in (d if isinstance(d,list) else []):
            fp=os.path.abspath(os.path.join(path,f.get("File","")))
            out[fp].add(f.get("StartLine") or f.get("startLine"))
        return out
    except Exception: return {}
    finally:
        try: os.unlink(rep)
        except Exception: pass
def detect_secrets_lines(path):
    try:
        r=subprocess.run(["detect-secrets","scan",path],capture_output=True,text=True,timeout=600)
        d=json.loads(r.stdout or "{}"); out=collections.defaultdict(set)
        for f,items in d.get("results",{}).items():
            out[os.path.abspath(os.path.join(path,f))]={it.get("line_number") for it in items}
        return out
    except Exception: return {}

def cmd_scan(a):
    """Run scanners over a corpus's files/ dir; write per-file flagged line sets."""
    gt=load_gt(a.corpus); fdir=os.path.abspath(f"{RC}/{a.corpus}/files")
    os.makedirs(f"{RC}/preds",exist_ok=True)
    gl=gitleaks_lines(fdir); ds=detect_secrets_lines(fdir)
    for tool,mp in (("gl",gl),("ds",ds)):
        out=f"{RC}/preds/scanner_{tool}_{a.corpus}.jsonl"
        with open(out,"w") as f:
            for g in gt:
                ap=os.path.join(fdir,g["file"])
                lines=sorted(int(x) for x in mp.get(ap,set()) if x is not None)
                f.write(json.dumps({"id":g["id"],"lines":lines})+"\n")
        print(f"wrote {out}  (files flagged: {sum(1 for g in gt if mp.get(os.path.join(fdir,g['file'])))}/{len(gt)})")

def _load_lines(tool,corpus):
    d={}
    for l in open(f"{RC}/preds/scanner_{tool}_{corpus}.jsonl"):
        if l.strip(): r=json.loads(l); d[r["id"]]=set(r["lines"])
    return d

def cmd_score_scan(a):
    ga=load_gt("rc_a"); gb=load_gt("rc_b")
    print("\n============ SCANNER BASELINES (file/line level only) ============")
    for tool in ("gl","ds"):
        name={"gl":"gitleaks","ds":"detect-secrets"}[tool]
        # RC-A: all-negative -> any flag is FP
        la=_load_lines(tool,"rc_a")
        files_fp=sum(1 for g in ga if la.get(g["id"]))
        # RC-B: recall = flagged the injected line
        lb=_load_lines(tool,"rc_b")
        hit=0
        for g in gb:
            inj_line=g["spans"][0]["line"]
            if inj_line in lb.get(g["id"],set()): hit+=1
        file_hit=sum(1 for g in gb if lb.get(g["id"]))
        print(f"{name}:")
        print(f"   RC-A file FP rate = {files_fp/len(ga):.3f}  ({files_fp}/{len(ga)})")
        print(f"   RC-B line-level recall (injected line flagged) = {hit/len(gb):.3f}  ({hit}/{len(gb)})")
        print(f"   RC-B file-level recall (any flag in file)      = {file_hit/len(gb):.3f}  ({file_hit}/{len(gb)})")

def _strict_recall(preds,gt,tau):
    tp=0; tot=0
    for g in gt:
        gs=g["spans"][0]; tot+=1
        ps=[p for p in preds.get(g["id"],[]) if p.get("score",1.0)>=tau]
        if any(p["start"]==gs["start"] and p["end"]==gs["end"] and p.get("line")==gs["line"] for p in ps): tp+=1
    return tp/tot if tot else 0.0
def _lookalike_fp(preds,gt,tau):
    flag=0; tot=0
    for g in gt:
        ps=[p for p in preds.get(g["id"],[]) if p.get("score",1.0)>=tau]
        for lk in g["lookalike_spans"]:
            tot+=1
            if any(_overlaps(p,lk["start"],lk["end"]) for p in ps): flag+=1
    return flag/tot if tot else 0.0
def _file_fp(preds,gt,tau):
    n=sum(1 for g in gt if any(p.get("score",1.0)>=tau for p in preds.get(g["id"],[])))
    return n/len(gt) if gt else 0.0
def _load_raw(tag,corp):
    d={}
    for l in open(f"{RC}/preds/{tag}_raw_{corp}.jsonl"):
        if l.strip(): x=json.loads(l); d[x["id"]]=x["spans"]
    return d

def cmd_sweep(a):
    tags=a.tags.split(","); ga=load_gt("rc_a"); gb=load_gt("rc_b")
    grid=[i/1000 for i in range(0,1000,10)]+[0.99,0.995,0.999,0.9995,0.9999,0.99999,1.0]
    grid=sorted(set(round(x,5) for x in grid))
    curves={}
    for tag in tags:
        pa=_load_raw(tag,"rc_a"); pb=_load_raw(tag,"rc_b")
        pts=[]
        for t in grid:
            pts.append({"tau":t,"rc_b_strict_recall":round(_strict_recall(pb,gb,t),4),
                        "rc_a_lookalike_fp":round(_lookalike_fp(pa,ga,t),4),
                        "rc_a_file_fp":round(_file_fp(pa,ga,t),4)})
        curves[tag]=pts
    os.makedirs(f"{RC}/results",exist_ok=True)
    json.dump({"tags":tags,"curves":curves},open(f"{RC}/results/sweep.json","w"),indent=2)
    # matched-FP and matched-recall crossovers between the first two tags
    if len(tags)>=2:
        A,B=tags[0],tags[1]
        def recall_at_fp(tag,target):
            best=None
            for p in curves[tag]:
                if p["rc_a_lookalike_fp"]<=target:
                    if best is None or p["rc_b_strict_recall"]>best[1]: best=(p["tau"],p["rc_b_strict_recall"],p["rc_a_lookalike_fp"])
            return best
        def fp_at_recall(tag,target):
            best=None
            for p in curves[tag]:
                if p["rc_b_strict_recall"]>=target:
                    if best is None or p["rc_a_lookalike_fp"]<best[2]: best=(p["tau"],p["rc_b_strict_recall"],p["rc_a_lookalike_fp"])
            return best
        print(f"\n=== FULL-FRONTIER Pareto: {A} vs {B} ===")
        for fp in (0.01,0.02,0.023,0.03,0.05):
            print(f"  matched-FP<= {fp:.3f}:  {A} R={recall_at_fp(A,fp)}  |  {B} R={recall_at_fp(B,fp)}")
        for r in (0.70,0.75,0.79,0.80,0.85):
            print(f"  matched-recall>= {r:.2f}: {A} FP={fp_at_recall(A,r)}  |  {B} FP={fp_at_recall(B,r)}")
    print(f"\nwrote {RC}/results/sweep.json")

def main():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest="cmd")
    p=sub.add_parser("predict"); p.add_argument("--model",required=True); p.add_argument("--corpus",choices=["rc_a","rc_b"],required=True)
    p.add_argument("--tau",type=float,default=0.99); p.add_argument("--tag",required=True)
    p.add_argument("--device",default="cpu"); p.add_argument("--start",type=int,default=0); p.add_argument("--limit",type=int,default=0)
    p.add_argument("--raw",action="store_true",help="argmax decode; keep ALL candidate spans+scores for sweeping")
    s=sub.add_parser("score"); s.add_argument("--tag",required=True); s.add_argument("--tau",type=float,default=0.99)
    sc=sub.add_parser("scan"); sc.add_argument("--corpus",choices=["rc_a","rc_b"],required=True)
    sub.add_parser("score-scan")
    sw=sub.add_parser("sweep"); sw.add_argument("--tags",required=True,help="comma-separated tags with *_raw_* preds")
    a=ap.parse_args()
    if a.cmd=="predict": cmd_predict(a)
    elif a.cmd=="score": cmd_score(a)
    elif a.cmd=="scan": cmd_scan(a)
    elif a.cmd=="score-scan": cmd_score_scan(a)
    elif a.cmd=="sweep": cmd_sweep(a)
    else: ap.print_help()
if __name__=="__main__": main()

#!/usr/bin/env python3
"""SecMask RealCode-1 / RC-C evaluator (blind natural-code adjudicator).

Scores models against FROZEN blind policy labels (rc_c/labels_frozen.json):
  POLICY_POSITIVE     -> gold span the model SHOULD flag (recall + strict P)
  POLICY_NEGATIVE     -> candidate the model should NOT flag (overlap = FP)
  AMBIGUOUS_EXCLUDED  -> excluded from headline; predictions overlapping an
                         ambiguous span are neither TP nor FP (masked out).
Headline metric = exact span+line (== value+line: exact value AND line). Off-candidate model
predictions (plain code) count as FP. This is the test the model never shaped;
read against RC-A/RC-B it adjudicates H1 (a1 genuinely > RS on natural code)
vs H2 (a1 better only on the targeted A/B frontier).

  python3 rc_c_eval.py predict --model outputs/.../best --tag v33a1 [--tau .99]
  python3 rc_c_eval.py score   --tag v33a1 [--tau .99]
  python3 rc_c_eval.py --self-test
"""
import argparse, json, os, sys, time, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("HF_HUB_OFFLINE","1"); os.environ.setdefault("TOKENIZERS_PARALLELISM","false")
RC="realcode1/rc_c"; FILES="realcode1/rc_c/files"
def _cand_path():
    return f"{RC}/selected_candidates.jsonl" if os.path.exists(f"{RC}/selected_candidates.jsonl") else f"{RC}/candidates.jsonl"
def load_candidates(): return [json.loads(l) for l in open(_cand_path()) if l.strip()]
def load_labels():     return json.load(open(f"{RC}/labels_frozen.json"))["labels"]
def files_in_order():
    seen=[]; s=set()
    for c in load_candidates():
        if c["file"] not in s: s.add(c["file"]); seen.append(c["file"])
    return seen
def preds_path(tag): return f"{RC}/preds/{tag}.jsonl"

# ---------- predict ----------
def cmd_predict(a):
    from span_infer import load_model, infer_spans
    import span_infer
    tok,model,i2l=load_model(a.model,a.device)
    files=files_in_order(); os.makedirs(f"{RC}/preds",exist_ok=True)
    end=len(files) if not a.limit else min(len(files),a.start+a.limit)
    todo=files[a.start:end]; t0=time.time()
    mode="w" if a.start==0 else "a"
    with open(preds_path(a.tag),mode,encoding="utf-8") as f:
        for i,fid in enumerate(todo):
            text=open(f"{FILES}/{fid}",encoding="utf-8",errors="replace").read()
            spans=infer_spans(text,tok,model,i2l,mode="threshold",tau=a.tau,device=a.device)[0]
            f.write(json.dumps({"file":fid,"spans":spans},ensure_ascii=False)+"\n")
            if (i+1)%50==0: print(f"  {i+1}/{len(todo)} ({time.time()-t0:.0f}s)",flush=True)
    print(f"wrote [{a.start}:{end}) -> {preds_path(a.tag)} tau={a.tau} max_fwd={span_infer.MAX_FORWARD_TOKENS}")

# ---------- score ----------
def _ov(p,s,e): return min(p["end"],e)>max(p["start"],s)
def score(tag,tau,preds_by_file):
    cands=load_candidates(); labels=load_labels()
    pos=collections.defaultdict(list); neg=collections.defaultdict(list); amb=collections.defaultdict(list)
    for c in cands:
        lab=labels.get(c["id"])
        rec={"start":c["start"],"end":c["end"],"line":c["line"],"lang":c["lang"]}
        if   lab=="POLICY_POSITIVE":    pos[c["file"]].append(rec)
        elif lab=="POLICY_NEGATIVE":    neg[c["file"]].append(rec)
        elif lab=="AMBIGUOUS_EXCLUDED": amb[c["file"]].append(rec)
    files=files_in_order()
    tp=fp=fn=0; extp=exfp=exfn=0; ov_tp=0; langc=collections.Counter(); langtp=collections.Counter()
    file_tp=file_fp=file_fn=0
    for fid in files:
        P=[p for p in preds_by_file.get(fid,[]) if p.get("score",1.0)>=tau]
        G=pos[fid][:]; A=amb[fid]
        used_g=set(); used_p=set()
        # strict (exact span + line) one-to-one
        for pi,p in enumerate(P):
            for gi,g in enumerate(G):
                if gi in used_g: continue
                if p["start"]==g["start"] and p["end"]==g["end"] and p.get("line")==g["line"]:
                    used_g.add(gi); used_p.add(pi); tp+=1; langtp[g["lang"]]+=1; break
        for g in G: langc[g["lang"]]+=1
        fn+=len(G)-len(used_g)
        # remaining preds: ambiguous-overlap excluded, else FP
        for pi,p in enumerate(P):
            if pi in used_p: continue
            if any(_ov(p,s["start"],s["end"]) for s in A): continue   # excluded
            fp+=1
        # exact (span only, ignore line) for a secondary number
        ug=set(); up=set()
        for pi,p in enumerate(P):
            for gi,g in enumerate(G):
                if gi in ug: continue
                if p["start"]==g["start"] and p["end"]==g["end"]: ug.add(gi); up.add(pi); extp+=1; break
        exfn+=len(G)-len(ug)
        for pi,p in enumerate(P):
            if pi in up: continue
            if any(_ov(p,s["start"],s["end"]) for s in A): continue
            exfp+=1
        # overlap recall on positives
        for g in G:
            if any(_ov(p,g["start"],g["end"]) for p in P): ov_tp+=1
        # file-level (does file have >=1 positive / >=1 non-excluded pred)
        has_g=bool(G)
        nonexcl=[p for p in P if not any(_ov(p,s["start"],s["end"]) for s in A)]
        has_p=bool(nonexcl)
        file_tp+= has_g and has_p; file_fp+= (not has_g) and has_p; file_fn+= has_g and (not has_p)
    def prf(tp,fp,fn):
        p=tp/(tp+fp) if tp+fp else 0.0; r=tp/(tp+fn) if tp+fn else 0.0
        return {"tp":tp,"fp":fp,"fn":fn,"precision":round(p,4),"recall":round(r,4),
                "f1":round(2*p*r/(p+r),4) if p+r else 0.0}
    npos=sum(len(v) for v in pos.values())
    res={"tag":tag,"tau":tau,
         "n_positive":npos,"n_negative":sum(len(v) for v in neg.values()),
         "n_ambiguous_excluded":sum(len(v) for v in amb.values()),
         "strict_span_and_line":prf(tp,fp,fn),
         "exact_span":prf(extp,exfp,exfn),
         "overlap_recall":round(ov_tp/npos,4) if npos else None,
         "file_level":prf(file_tp,file_fp,file_fn),
         "strict_recall_by_lang":{k:round(langtp[k]/langc[k],4) for k in sorted(langc)}}
    return res

def cmd_score(a):
    preds={}
    for l in open(preds_path(a.tag)):
        if l.strip(): r=json.loads(l); preds[r["file"]]=r["spans"]
    res=score(a.tag,a.tau,preds)
    os.makedirs(f"{RC}/results",exist_ok=True)
    json.dump(res,open(f"{RC}/results/{a.tag}.json","w"),indent=2)
    s=res["strict_span_and_line"]
    print(f"\n===== RC-C {a.tag} @ tau={a.tau} (blind natural adjudicator) =====")
    print(f"  positives={res['n_positive']} negatives={res['n_negative']} ambiguous(excluded)={res['n_ambiguous_excluded']}")
    print(f"  strict span+line  P/R/F1 = {s['precision']:.3f}/{s['recall']:.3f}/{s['f1']:.3f}  (tp{s['tp']} fp{s['fp']} fn{s['fn']})")
    print(f"  exact span R = {res['exact_span']['recall']:.3f}   overlap R = {res['overlap_recall']}   file F1 = {res['file_level']['f1']:.3f}")
    print(f"  wrote {RC}/results/{a.tag}.json")

# ---------- self-test (fabricated labels + preds; no model) ----------
def self_test():
    import tempfile, shutil
    d=tempfile.mkdtemp(prefix="rcc_eval_st_")
    global RC; old=RC; RC=d
    try:
        os.makedirs(f"{RC}/files"); globals()["FILES"]=f"{RC}/files"
        f1="a.py"; open(f"{RC}/files/{f1}","w").write('K="AAAA"\nU="bbbb"\nX="cccc"\nY="dddd"\n')
        cands=[{"id":"c1","file":f1,"lang":"py","start":3,"end":7,"line":1},   # positive
               {"id":"c2","file":f1,"lang":"py","start":11,"end":15,"line":2}, # negative
               {"id":"c3","file":f1,"lang":"py","start":19,"end":23,"line":3}] # ambiguous
        open(f"{RC}/candidates.jsonl","w").write("\n".join(json.dumps(c) for c in cands))
        json.dump({"labels":{"c1":"POLICY_POSITIVE","c2":"POLICY_NEGATIVE","c3":"AMBIGUOUS_EXCLUDED"}},
                  open(f"{RC}/labels_frozen.json","w"))
        def sp(s,e,ln): return {"start":s,"end":e,"line":ln,"score":1.0}
        # PERFECT: flag only the positive
        r=score("PERF",0.99,{f1:[sp(3,7,1)]})
        assert r["strict_span_and_line"]=={"tp":1,"fp":0,"fn":0,"precision":1.0,"recall":1.0,"f1":1.0}, r["strict_span_and_line"]
        # flag positive + negative -> FP=1 ; + ambiguous -> excluded (no FP)
        r=score("X",0.99,{f1:[sp(3,7,1),sp(11,15,2),sp(19,23,3)]})
        assert r["strict_span_and_line"]["tp"]==1 and r["strict_span_and_line"]["fp"]==1, r["strict_span_and_line"]
        # miss positive -> FN
        r=score("M",0.99,{f1:[]})
        assert r["strict_span_and_line"]=={"tp":0,"fp":0,"fn":1,"precision":0.0,"recall":0.0,"f1":0.0}, r["strict_span_and_line"]
        # wrong line -> strict miss but exact hit
        r=score("L",0.99,{f1:[{"start":3,"end":7,"line":9,"score":1.0}]})
        assert r["strict_span_and_line"]["tp"]==0 and r["exact_span"]["tp"]==1, (r["strict_span_and_line"],r["exact_span"])
        # off-candidate plain-code flag -> FP
        r=score("O",0.99,{f1:[sp(0,1,1)]})
        assert r["strict_span_and_line"]["fp"]==1 and r["strict_span_and_line"]["fn"]==1, r["strict_span_and_line"]
        # tau gating
        r=score("T",0.999,{f1:[{"start":3,"end":7,"line":1,"score":0.99}]})
        assert r["strict_span_and_line"]["tp"]==0, "score below tau must be filtered"
        print("RC-C EVAL SELF-TEST PASS: positive/negative/ambiguous/off-candidate/line/tau all correct")
    finally:
        RC=old; shutil.rmtree(d,ignore_errors=True)

def main():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest="cmd")
    p=sub.add_parser("predict"); p.add_argument("--model",required=True); p.add_argument("--tag",required=True)
    p.add_argument("--tau",type=float,default=0.99); p.add_argument("--device",default="cpu")
    p.add_argument("--start",type=int,default=0); p.add_argument("--limit",type=int,default=0)
    p.add_argument("--dir",default="realcode1/rc_c"); p.add_argument("--files-dir",default="realcode1/rc_c/files")
    s=sub.add_parser("score"); s.add_argument("--tag",required=True); s.add_argument("--tau",type=float,default=0.99)
    s.add_argument("--dir",default="realcode1/rc_c"); s.add_argument("--files-dir",default="realcode1/rc_c/files")
    ap.add_argument("--self-test",action="store_true")
    a=ap.parse_args()
    if a.self_test: self_test(); return
    global RC, FILES
    if getattr(a,"dir",None): RC=a.dir
    if getattr(a,"files_dir",None): FILES=a.files_dir
    if a.cmd=="predict": cmd_predict(a)
    elif a.cmd=="score": cmd_score(a)
    else: ap.print_help()
if __name__=="__main__": main()

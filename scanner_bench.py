#!/usr/bin/env python3
"""Multi-scanner head-to-head vs the SecMask model on our real-OSS benchmarks.

Runs gitleaks / detect-secrets / trufflehog / semgrep and the SecMask model over
benchmark_{b,c,d}/files, maps every finding to (file, line), and scores each tool
FILE-level (did it flag a file that has a secret) and LINE-level (did it flag the
exact gold secret line). Scanners are line/file detectors, not span labelers, so
file+line is the fair cross-tool basis; the model additionally gets its native
STRICT span+line score as a ceiling.

Per-tool status (version / findings / errors) is recorded so a tool that isn't
installed or errors is reported as NOT-RUN, never as a silent 0.

  python3 scanner_bench.py scan  --corpus B --model outputs/distilbert-secret-masker-v3.3a-RS/best
  python3 scanner_bench.py score --corpus B
Corpora: B=benchmark_b  C=benchmark_c  D=benchmark_d
"""
import argparse, json, os, sys, subprocess, tempfile, time, collections, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("HF_HUB_OFFLINE","1"); os.environ.setdefault("TOKENIZERS_PARALLELISM","false")
CORP={"B":"benchmark_b","C":"benchmark_c","D":"benchmark_d"}
OUT="reports/scanbench"

def gold(corpus):
    d=CORP[corpus]; g={}
    for l in open(f"{d}/ground_truth.jsonl"):
        if not l.strip(): continue
        r=json.loads(l)
        g[r["file"]]={"has":bool(r.get("file_has_secrets") or r.get("spans")),
                      "lines":sorted({s["line"] for s in r.get("spans",[]) if s.get("line") is not None}),
                      "spans":[{"start":s["start"],"end":s["end"],"line":s.get("line")} for s in r.get("spans",[])]}
    return g
def filesdir(corpus): return os.path.abspath(f"{CORP[corpus]}/files")
def det_path(corpus,tool): return f"{OUT}/{corpus}_{tool}.jsonl"
def status_path(corpus): return f"{OUT}/{corpus}_status.json"

# ------------- tool runners: return {basename: set(lines)} + status -------------
def _run(cmd, timeout=1800):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

def run_gitleaks(fdir):
    if shutil.which("gitleaks") is None: return None,{"status":"not_installed"}
    fd,rep=tempfile.mkstemp(suffix=".json"); os.close(fd)
    try:
        v=_run(["gitleaks","version"]).stdout.strip()
        r=_run(["gitleaks","detect","--no-git","--source",fdir,"-f","json","-r",rep])
        data=[]
        if os.path.getsize(rep)>0:
            try: data=json.load(open(rep))
            except Exception: data=[]
        if not data:
            _run(["gitleaks","dir",fdir,"-f","json","-r",rep])
            if os.path.getsize(rep)>0:
                try: data=json.load(open(rep))
                except Exception: data=[]
        det=collections.defaultdict(set)
        for f in (data if isinstance(data,list) else []):
            bn=os.path.basename(f.get("File","")); ln=f.get("StartLine")
            if bn and ln is not None: det[bn].add(int(ln))
        return det,{"status":"ok","version":v,"findings":sum(len(v2) for v2 in det.values())}
    except Exception as e: return None,{"status":"error","error":str(e)[:200]}
    finally:
        try: os.unlink(rep)
        except Exception: pass

def run_detect_secrets(fdir):
    if shutil.which("detect-secrets") is None: return None,{"status":"not_installed"}
    try:
        v=_run(["detect-secrets","--version"]).stdout.strip()
        r=_run(["detect-secrets","scan",fdir])
        d=json.loads(r.stdout or "{}"); det=collections.defaultdict(set)
        for f,items in d.get("results",{}).items():
            bn=os.path.basename(f)
            for it in items:
                ln=it.get("line_number")
                if ln is not None: det[bn].add(int(ln))
        return det,{"status":"ok","version":v,"findings":sum(len(v2) for v2 in det.values())}
    except Exception as e: return None,{"status":"error","error":str(e)[:200]}

def run_trufflehog(fdir):
    if shutil.which("trufflehog") is None: return None,{"status":"not_installed"}
    try:
        v=_run(["trufflehog","--version"]).stderr.strip() or _run(["trufflehog","--version"]).stdout.strip()
        r=_run(["trufflehog","filesystem",fdir,"--json","--no-verification"])
        det=collections.defaultdict(set); n=0
        for line in (r.stdout or "").splitlines():
            line=line.strip()
            if not line or not line.startswith("{"): continue
            try: o=json.loads(line)
            except Exception: continue
            fs=(((o.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
            f=fs.get("file"); ln=fs.get("line")
            if f:
                bn=os.path.basename(f); n+=1
                det[bn].add(int(ln)+1 if isinstance(ln,int) else -1)  # trufflehog line is 0-based; -1 = unknown
        return det,{"status":"ok","version":v,"findings":n}
    except Exception as e: return None,{"status":"error","error":str(e)[:200]}

def run_semgrep(fdir):
    if shutil.which("semgrep") is None: return None,{"status":"not_installed"}
    try:
        v=_run(["semgrep","--version"]).stdout.strip()
        r=_run(["semgrep","scan","--config","p/secrets","--json","--quiet",fdir],timeout=2400)
        det=collections.defaultdict(set)
        try: d=json.loads(r.stdout or "{}")
        except Exception:
            return None,{"status":"error","error":"semgrep json parse failed (ruleset/registry?)","stderr":(r.stderr or "")[:200]}
        for res in d.get("results",[]):
            bn=os.path.basename(res.get("path","")); ln=(res.get("start") or {}).get("line")
            if bn and ln is not None: det[bn].add(int(ln))
        errs=d.get("errors",[])
        return det,{"status":"ok","version":v,"findings":sum(len(v2) for v2 in det.values()),"semgrep_errors":len(errs)}
    except Exception as e: return None,{"status":"error","error":str(e)[:200]}

def run_model(fdir, corpus, model_path):
    from span_infer import load_model, infer_spans
    tok,model,i2l=load_model(model_path)
    g=gold(corpus); det={}; spans_out={}
    files=list(g.keys()); t0=time.time()
    for i,fn in enumerate(files):
        text=open(f"{filesdir(corpus)}/../files/{fn}",encoding="utf-8",errors="replace").read() if False else \
             open(os.path.join(fdir,fn),encoding="utf-8",errors="replace").read()
        sp=infer_spans(text,tok,model,i2l,mode="threshold",tau=0.99)[0]
        det[fn]=sorted({s["line"] for s in sp})
        spans_out[fn]=[{"start":s["start"],"end":s["end"],"line":s["line"]} for s in sp]
        if (i+1)%100==0: print(f"  model {i+1}/{len(files)} ({time.time()-t0:.0f}s)",flush=True)
    return det,spans_out,{"status":"ok","version":os.path.basename(os.path.dirname(model_path)),
                          "findings":sum(len(v) for v in det.values())}

def cmd_scan(a):
    os.makedirs(OUT,exist_ok=True); fdir=filesdir(a.corpus); status={}
    for tool,fn in (("gitleaks",run_gitleaks),("detect-secrets",run_detect_secrets),
                    ("trufflehog",run_trufflehog),("semgrep",run_semgrep)):
        print(f"[{a.corpus}] {tool} ...",flush=True)
        det,st=fn(fdir); status[tool]=st
        if det is not None:
            with open(det_path(a.corpus,tool),"w") as f:
                for bn,lines in det.items(): f.write(json.dumps({"file":bn,"lines":sorted(x for x in lines if x>0)})+"\n")
        print(f"    {st}")
    if a.model:
        print(f"[{a.corpus}] model ...",flush=True)
        det,spans,st=run_model(fdir,a.corpus,a.model); status["model"]=st
        with open(det_path(a.corpus,"model"),"w") as f:
            for bn in det: f.write(json.dumps({"file":bn,"lines":det[bn],"spans":spans[bn]})+"\n")
        print(f"    {st}")
    json.dump(status,open(status_path(a.corpus),"w"),indent=2)
    print("status ->",status_path(a.corpus))

def prf(tp,fp,fn):
    p=tp/(tp+fp) if tp+fp else 0.0; r=tp/(tp+fn) if tp+fn else 0.0
    return {"tp":tp,"fp":fp,"fn":fn,"P":round(p,3),"R":round(r,3),"F1":round(2*p*r/(p+r),3) if p+r else 0.0}

def cmd_score(a):
    g=gold(a.corpus); allfiles=set(g); status=json.load(open(status_path(a.corpus))) if os.path.exists(status_path(a.corpus)) else {}
    tools=[t for t in ("gitleaks","detect-secrets","trufflehog","semgrep","model") if os.path.exists(det_path(a.corpus,t))]
    rows={}
    for t in tools:
        det={}; spans={}
        for l in open(det_path(a.corpus,t)):
            if l.strip():
                r=json.loads(l); det[r["file"]]=set(r.get("lines",[])); spans[r["file"]]=r.get("spans")
        # file-level
        ftp=ffp=ffn=0
        for fn in allfiles:
            flagged=bool(det.get(fn)); has=g[fn]["has"]
            ftp+=has and flagged; ffp+=(not has) and flagged; ffn+=has and (not flagged)
        # line-level
        ltp=lfp=lfn=0
        for fn in allfiles:
            gl=set(g[fn]["lines"]); pl=det.get(fn,set())
            ltp+=len(gl&pl); lfn+=len(gl-pl); lfp+=len(pl-gl)
        row={"file":prf(ftp,ffp,ffn),"line":prf(ltp,lfp,lfn)}
        # model: strict span+line
        if t=="model":
            stp=sfp=sfn=0
            for fn in allfiles:
                gs=g[fn]["spans"]; ps=spans.get(fn) or []
                used=set(); m=0
                for p in ps:
                    for i,gg in enumerate(gs):
                        if i in used: continue
                        if p["start"]==gg["start"] and p["end"]==gg["end"] and p["line"]==gg["line"]:
                            used.add(i); m+=1; break
                stp+=m; sfp+=len(ps)-m; sfn+=len(gs)-m
            row["strict_span_line"]=prf(stp,sfp,sfn)
        rows[t]=row
    res={"corpus":a.corpus,"n_files":len(allfiles),
         "n_pos_files":sum(1 for f in allfiles if g[f]["has"]),
         "n_gold_lines":sum(len(g[f]["lines"]) for f in allfiles),
         "status":status,"metrics":rows}
    os.makedirs(OUT,exist_ok=True); json.dump(res,open(f"{OUT}/{a.corpus}_summary.json","w"),indent=2)
    print(f"\n===== {CORP[a.corpus]} : {res['n_pos_files']} pos / {len(allfiles)} files, {res['n_gold_lines']} gold lines =====")
    print(f"{'tool':16} | {'FILE P/R/F1':22} | {'LINE P/R/F1':22} | strict span+line")
    for t in ("gitleaks","detect-secrets","trufflehog","semgrep","model"):
        if t not in rows:
            st=status.get(t,{}); print(f"{t:16} | NOT RUN ({st.get('status','absent')})"); continue
        fl=rows[t]["file"]; ln=rows[t]["line"]; ss=rows[t].get("strict_span_line")
        s=f"{t:16} | {fl['P']:.3f}/{fl['R']:.3f}/{fl['F1']:.3f}      | {ln['P']:.3f}/{ln['R']:.3f}/{ln['F1']:.3f}      |"
        if ss: s+=f" {ss['P']:.3f}/{ss['R']:.3f}/{ss['F1']:.3f}"
        print(s)
    print(f"\nwrote {OUT}/{a.corpus}_summary.json")

def self_test():
    global CORP
    import tempfile as tf
    d=tf.mkdtemp(); CORP={"T":d}; os.makedirs(f"{d}/files")
    open(f"{d}/files/pos-0.py","w").write("x=1\nAPI_KEY='abc'\n")
    open(f"{d}/files/neg-0.py","w").write("y=2\n")
    open(f"{d}/ground_truth.jsonl","w").write(
        json.dumps({"file":"pos-0.py","file_has_secrets":True,"spans":[{"start":6,"end":11,"line":2}]})+"\n"+
        json.dumps({"file":"neg-0.py","file_has_secrets":False,"spans":[]})+"\n")
    os.makedirs(OUT,exist_ok=True)
    # perfect scanner: flags pos-0 line2
    open(det_path("T","gitleaks"),"w").write(json.dumps({"file":"pos-0.py","lines":[2]})+"\n")
    # noisy scanner: flags neg-0 line1 (FP) + pos line2
    open(det_path("T","semgrep"),"w").write(json.dumps({"file":"pos-0.py","lines":[2]})+"\n"+json.dumps({"file":"neg-0.py","lines":[1]})+"\n")
    json.dump({},open(status_path("T"),"w"))
    class A: corpus="T"
    cmd_score(A())
    print("SELF-TEST done (gitleaks should be file 1/1/1 line 1/1/1; semgrep file P .5)")
    shutil.rmtree(d,ignore_errors=True)

def main():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest="cmd")
    s=sub.add_parser("scan"); s.add_argument("--corpus",required=True,choices=list(CORP)); s.add_argument("--model",default="")
    sc=sub.add_parser("score"); sc.add_argument("--corpus",required=True,choices=list(CORP))
    ap.add_argument("--self-test",action="store_true")
    a=ap.parse_args()
    if a.self_test: self_test(); return
    if a.cmd=="scan": cmd_scan(a)
    elif a.cmd=="score": cmd_score(a)
    else: ap.print_help()
if __name__=="__main__": main()

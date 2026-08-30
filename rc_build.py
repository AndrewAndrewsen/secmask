#!/usr/bin/env python3
"""SecMask RealCode-1 builder: RC-A harvester + RC-B injector.
Design frozen in REPO_SELECTION_v1.md + PREREG_SECMASK_REALCODE1.md.

RC-A: natural lookalike-NEGATIVES from real repos (UUID/hash/pubkey/base64/
      identifier/env-name), each POLICY_NEGATIVE with char-span+line, harvested
      only from files that pass the sanitation gate (any NON-whitelist
      credential-like finding by the frozen scanner union -> file REJECTED).
RC-B: synthetic prefixless POSITIVES injected into scanner-CLEAN real files
      (zero scanner findings), exact ground truth, offsets recomputed+asserted.

READ-ONLY on models. No raw candidate secret value is ever persisted (RC-B
values are synthetic; RC-A keeps only structurally-certain NON-secrets).
Runs where GitHub + gitleaks + detect-secrets are available (your machine).

  python3 rc_build.py harvest-a --target 4000
  python3 rc_build.py inject-b  --target 1500
  python3 rc_build.py --self-test
"""
import argparse, json, os, sys, re, subprocess, tempfile, shutil, hashlib, random, glob, collections, math
SEL="realcode1/repo_selection_v1.json"; SEED=20260829
EXT_LANG={"py":"py","js":"js","jsx":"js","ts":"ts","tsx":"ts","go":"go","java":"java",
          "yaml":"yaml","yml":"yaml","toml":"toml","ini":"ini","cfg":"cfg","conf":"conf",
          "env":"env","sh":"sh","bash":"sh","properties":"properties","json":"json","xml":"xml"}
MAXBYTES=64000

# ---------- whitelist lookalike detectors (structurally-certain NON-secrets) ----------
LK=[
 ("uuid", re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')),
 ("sri_integrity", re.compile(r'\bsha(?:256|384|512)-[A-Za-z0-9+/]{20,}={0,2}')),
 ("hex_sha256", re.compile(r'\b[0-9a-f]{64}\b')),
 ("hex_sha1_or_git", re.compile(r'\b[0-9a-f]{40}\b')),
 ("hex_md5", re.compile(r'\b[0-9a-f]{32}\b')),
 ("ssh_pubkey", re.compile(r'\bssh-(?:rsa|ed25519|dss)\s+AAAA[0-9A-Za-z+/]+={0,2}')),
 ("pem_public", re.compile(r'-----BEGIN (?:PGP )?PUBLIC KEY(?: BLOCK)?-----')),
 ("ipv4", re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')),
 ("mac", re.compile(r'\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b')),
 ("env_var_name", re.compile(r'\b[A-Z][A-Z0-9]{2,}(?:_[A-Z0-9]+)+\b')),
]
# RC-A per-category quotas: prioritize the FRONTIER (high-entropy value
# lookalikes the error taxonomy flagged as the model's residual FP weakness);
# hard-cap weak/easy distractors (ALLCAPS env names) so they cannot dominate.
QUOTA={"uuid":600,"hex_sha256":500,"hex_sha1_or_git":500,"hex_md5":400,
       "sri_integrity":400,"ssh_pubkey":250,"pem_public":150,"ipv4":120,
       "mac":80,"env_var_name":150}
def line_starts(t):
    idx=[0]
    for i,c in enumerate(t):
        if c=="\n": idx.append(i+1)
    return idx
def line_of(ls,pos):
    import bisect; return bisect.bisect_right(ls,pos)
HEXCATS=("hex_md5","hex_sha1_or_git","hex_sha256")
def _hex_ok(v):
    """reject degenerate/low-entropy hex placeholders (e.g. aaaa..., 0000...,
    git null SHA) so RC-A hex negatives are realistic HARD distractors."""
    if len(set(v))<6: return False
    c=collections.Counter(v); n=len(v)
    h=-sum((k/n)*math.log2(k/n) for k in c.values())
    return h>=3.0
def lookalikes(text):
    ls=line_starts(text); out=[]; taken=[]
    for cat,rx in LK:
        for m in rx.finditer(text):
            s,e=m.span()
            if any(not(e<=a or s>=b) for a,b in taken): continue   # no overlap; earlier cats win
            if cat in HEXCATS and not _hex_ok(m.group()): continue  # skip degenerate hex placeholders
            taken.append((s,e)); out.append({"start":s,"end":e,"line":line_of(ls,s),"category":cat,"value_len":e-s})
    return sorted(out,key=lambda d:d["start"])

# ---------- frozen scanner union ----------
def have(cmd): return shutil.which(cmd) is not None
def gitleaks_findings(path):
    """list of {file,startLine,endLine,secret,match,ruleID}. path=dir."""
    with tempfile.NamedTemporaryFile(suffix=".json",delete=False) as tf: rep=tf.name
    try:
        subprocess.run(["gitleaks","detect","--no-git","--source",path,"-f","json","-r",rep],
                       capture_output=True,timeout=300)
        if os.path.getsize(rep)==0: return []
        d=json.load(open(rep)); return d if isinstance(d,list) else []
    except Exception: return []
    finally:
        try: os.unlink(rep)
        except Exception: pass
def detect_secrets_findings(path):
    """{relfile:[line_no,...]}"""
    try:
        r=subprocess.run(["detect-secrets","scan",path],capture_output=True,text=True,timeout=300)
        d=json.loads(r.stdout or "{}"); out={}
        for f,items in d.get("results",{}).items():
            out[os.path.abspath(f)]=[it.get("line_number") for it in items]
        return out
    except Exception: return {}

# ---------- gate ----------
def gate_file(abspath, text, gl_by_file, ds_by_file):
    """OK if every scanner finding on this file is EXPLAINED by a whitelist
    lookalike on the same line; else reject (potential real secret)."""
    lk=lookalikes(text); ls=line_starts(text)
    lk_lines=set(d["line"] for d in lk)
    unexplained=[]
    for f in gl_by_file.get(abspath,[]):
        ln=f.get("StartLine") or f.get("startLine")
        val=(f.get("Secret") or f.get("Match") or "")
        # explained if that line has a lookalike, OR the flagged value itself is a lookalike
        if ln in lk_lines: continue
        if any(rx.search(val) for _,rx in LK): continue
        unexplained.append(("gitleaks",ln,val[:20]))
    for ln in ds_by_file.get(abspath,[]):
        if ln in lk_lines: continue
        unexplained.append(("detect-secrets",ln,""))
    return (len(unexplained)==0), unexplained

# ---------- repo clone ----------
def clone(repo, sha, dest):
    url=f"https://github.com/{repo}.git"
    try:
        subprocess.run(["git","clone","--quiet","--filter=blob:none",url,dest],
                       capture_output=True,timeout=600,check=True)
        subprocess.run(["git","-C",dest,"checkout","--quiet",sha],capture_output=True,timeout=120,check=True)
        return True
    except Exception: return False
def src_files(root):
    for dp,dn,fn in os.walk(root):
        if "/.git" in dp: continue
        dn[:]=[d for d in dn if d not in ("node_modules","vendor","dist","build",".git")]
        for f in fn:
            ext=f.rsplit(".",1)[-1].lower() if "." in f else ""
            if ext in EXT_LANG:
                p=os.path.join(dp,f)
                try:
                    if 0<os.path.getsize(p)<=MAXBYTES: yield p,EXT_LANG[ext]
                except OSError: pass

# ---------- synthetic prefixless positive generators (RC-B) ----------
def _rng(seedkey): return random.Random(hashlib.sha256(seedkey.encode()).hexdigest())
import string
def gen_value(family, seedkey):
    r=_rng(seedkey)
    if family=="generic_password":
        al=string.ascii_letters+string.digits+"!@#$%^&*-_"; return "".join(r.choice(al) for _ in range(r.randint(14,24)))
    if family=="generic_api_key":
        al=string.ascii_letters+string.digits; return "".join(r.choice(al) for _ in range(r.randint(32,40)))
    if family=="generic_high_entropy":
        al=string.ascii_letters+string.digits+"+/"; return "".join(r.choice(al) for _ in range(40))
    if family=="basic_auth_header":
        import base64; up=f"svc_{r.randint(1000,9999)}:"+"".join(r.choice(string.ascii_letters+string.digits) for _ in range(16))
        return "Basic "+base64.b64encode(up.encode()).decode()
    raise ValueError(family)
INJECT={  # per language: (varname, line template with {V})
 "py":('API_SECRET','{K} = "{V}"'),"js":('apiSecret','const {K} = "{V}";'),"ts":('apiSecret','const {K}: string = "{V}";'),
 "go":('apiSecret','\t{K} := "{V}"'),"java":('API_SECRET','String {K} = "{V}";'),
 "yaml":('api_secret','{K}: "{V}"'),"toml":('api_secret','{K} = "{V}"'),"ini":('api_secret','{K} = {V}'),
 "cfg":('api_secret','{K} = {V}'),"conf":('api_secret','{K} = {V}'),"env":('API_SECRET','{K}={V}'),
 "sh":('API_SECRET','export {K}="{V}"'),"properties":('api.secret','{K}={V}'),"json":('api_secret','  "{K}": "{V}",'),
 "xml":('apiSecret','<{K}>{V}</{K}>'),
}
FAM_KEY={"generic_password":"password","generic_api_key":"api_key","generic_high_entropy":"secret","basic_auth_header":"authorization"}
def inject(text, lang, family, seedkey):
    tmpl=INJECT.get(lang,INJECT["py"]); base=FAM_KEY[family]
    varname=base.upper() if tmpl[1][:1] in ("A","S","e") and lang in("py","java","env","sh") else base
    val=gen_value(family,seedkey); line=tmpl[1].format(K=varname,V=val)
    # label only the SECRET, not a fixed scheme keyword: for basic_auth the
    # secret is the base64 credential, not the literal "Basic " prefix.
    label_val=val[len("Basic "):] if family=="basic_auth_header" else val
    lines=text.split("\n")
    # anchor: after the last of the first 40 lines that looks like an assignment/kv; else after imports/top
    anchor=0
    for i,l in enumerate(lines[:60]):
        if re.search(r'[:=]\s*\S', l) and not l.strip().startswith(("#","//","*")): anchor=i
    ins=min(anchor+1,len(lines))
    newlines=lines[:ins]+[line]+lines[ins:]; newtext="\n".join(newlines)
    start=sum(len(x)+1 for x in newlines[:ins])+line.index(label_val)
    end=start+len(label_val)
    assert newtext[start:end]==label_val, "offset recompute failed"
    return newtext, {"start":start,"end":end,"line":ins+1,"value":label_val,"type":family}

# ---------- drivers ----------
def load_partition(part):
    m=json.load(open(SEL)); return [r for r in m["repos"] if r["partition"]==part], m["frozen_list_sha256"]
def preflight():
    miss=[c for c in ("git","gitleaks","detect-secrets") if not have(c)]
    if miss: sys.exit(f"MISSING required tools for the sanitation gate: {miss}. "
                      f"Install (brew install gitleaks; pip install detect-secrets) and re-run.")

def harvest_a(target):
    preflight(); repos,selsha=load_partition("RC-A"); rng=random.Random(SEED)
    out="realcode1/rc_a"; shutil.rmtree(out,ignore_errors=True); os.makedirs(os.path.join(out,"files"))
    gt=[]; cat_count=collections.Counter(); idx=0; kept_repos=0
    for r in repos:
        if sum(cat_count.values())>=target: break
        d=tempfile.mkdtemp(prefix="rca_")
        try:
            if not clone(r["repo"],r["sha"],d): continue
            gl=collections.defaultdict(list)
            for f in gitleaks_findings(d): gl[os.path.abspath(os.path.join(d,f.get("File",f.get("file",""))))].append(f)
            ds=detect_secrets_findings(d); used=False
            files=list(src_files(d)); rng.shuffle(files)
            for p,lang in files:
                if sum(cat_count.values())>=target: break
                try: text=open(p,encoding="utf-8",errors="replace").read()
                except Exception: continue
                lk=lookalikes(text)
                if not lk: continue
                ok,_=gate_file(os.path.abspath(p),text,gl,ds)
                if not ok: continue           # potential real secret -> reject file
                # window around the lookalike cluster (real context, bounded)
                lines=text.split("\n"); lmin=min(x["line"] for x in lk); lmax=max(x["line"] for x in lk)
                a=max(0,lmin-25); b=min(len(lines),lmax+25); snippet="\n".join(lines[a:b])
                off=sum(len(x)+1 for x in lines[:a])
                lkw=[{"start":x["start"]-off,"end":x["end"]-off,"line":x["line"]-a,"category":x["category"]}
                     for x in lk if a<=x["line"]-1<b and 0<=x["start"]-off]
                lkw=[x for x in lkw if 0<=x["start"]<x["end"]<=len(snippet) and snippet[x["start"]:x["end"]]]
                # enforce per-category quotas: keep only spans still under quota
                kept=[]
                for x in lkw:
                    c=x["category"]
                    if cat_count[c] < QUOTA.get(c,0):
                        kept.append(x); cat_count[c]+=1
                lkw=kept
                if not lkw: continue
                fid=f"rca-{idx:05d}.{lang}"; idx+=1
                open(os.path.join(out,"files",fid),"w").write(snippet)
                gt.append({"id":f"rca-{idx:05d}","file":fid,"repo":r["repo"],"commit":r["sha"],"lang":lang,
                           "file_has_secrets":False,"spans":[],"lookalike_spans":lkw})
                used=True
            kept_repos+=used
        finally: shutil.rmtree(d,ignore_errors=True)
    _write(out,gt,{"benchmark":"SecMask RealCode-1 / RC-A","provenance":"natural real code, natural negatives",
        "selection_sha":selsha,"files":len(gt),"lookalike_spans":sum(len(g["lookalike_spans"]) for g in gt),
        "by_category":dict(cat_count),"repos_used":kept_repos,"policy":"POLICY_NEGATIVE; sanitation-gated"})
    print(f"RC-A: {len(gt)} files, {sum(cat_count.values())} lookalike-negatives, categories {dict(cat_count)}")

def inject_b(target):
    preflight(); repos,selsha=load_partition("RC-B"); rng=random.Random(SEED); rng.shuffle(repos)
    fams=["generic_password","generic_api_key","generic_high_entropy","basic_auth_header"]
    out="realcode1/rc_b"; shutil.rmtree(out,ignore_errors=True); os.makedirs(os.path.join(out,"files"))
    gt=[]; fam_count=collections.Counter(); lang_count=collections.Counter(); idx=0
    langcap=max(30,int(target*0.35))
    for r in repos:
        if len(gt)>=target: break
        d=tempfile.mkdtemp(prefix="rcb_")
        try:
            if not clone(r["repo"],r["sha"],d): continue
            gl=collections.defaultdict(list)
            for f in gitleaks_findings(d): gl[os.path.abspath(os.path.join(d,f.get("File",f.get("file",""))))].append(f)
            ds=detect_secrets_findings(d)
            files=[(p,l) for p,l in src_files(d) if l in INJECT]; rng.shuffle(files)
            per_repo=0
            for p,lang in files:
                if len(gt)>=target or per_repo>=max(1,target//max(1,len(repos))+1): break
                ap=os.path.abspath(p)
                if gl.get(ap) or ds.get(ap): continue          # RC-B requires a CLEAN file
                if lang_count[lang]>=langcap: continue          # per-language cap for balance
                try: text=open(p,encoding="utf-8",errors="replace").read()
                except Exception: continue
                if lookalikes(text): continue   # keep RC-B a clean recall set: no incidental lookalikes
                fam=fams[idx%4]
                try: newtext,span=inject(text,lang,fam,f"{r['repo']}|{p}|{fam}")
                except Exception: continue
                fid=f"rcb-{idx:05d}.{lang}"; 
                open(os.path.join(out,"files",fid),"w").write(newtext)
                gt.append({"id":f"rcb-{idx:05d}","file":fid,"repo":r["repo"],"commit":r["sha"],"lang":lang,
                           "file_has_secrets":True,"spans":[span]})
                fam_count[fam]+=1; lang_count[lang]+=1; idx+=1; per_repo+=1
        finally: shutil.rmtree(d,ignore_errors=True)
    _write(out,gt,{"benchmark":"SecMask RealCode-1 / RC-B","provenance":"real code context + SYNTHETIC injected positive value",
        "selection_sha":selsha,"files":len(gt),"positives":len(gt),"by_family":dict(fam_count),
        "by_language":dict(lang_count),
        "policy":"injected synthetic prefixless positive; host file scanner-CLEAN"})
    print(f"RC-B: {len(gt)} injected positives, families {dict(fam_count)}")

def _write(out,gt,man):
    with open(os.path.join(out,"ground_truth.jsonl"),"w") as f:
        for g in gt: f.write(json.dumps(g,ensure_ascii=False)+"\n")
    fh={g["file"]:hashlib.sha256(open(os.path.join(out,"files",g["file"]),"rb").read()).hexdigest() for g in gt}
    man["corpus_sha256"]=hashlib.sha256("".join(fh[k] for k in sorted(fh)).encode()).hexdigest(); man["frozen"]=True
    json.dump(man,open(os.path.join(out,"manifest.json"),"w"),indent=2)

def self_test():
    # lookalikes + gate logic (no scanners/clone)
    t='id = "550e8400-e29b-41d4-a716-446655440000"\nsha = "5d41402abc4b2a76b9719d911017c592"\nkey = ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI\nAPI_BASE_URL = os.environ["API_BASE_URL"]\n'
    lk=lookalikes(t); cats={x["category"] for x in lk}
    assert "uuid" in cats and "hex_md5" in cats and "ssh_pubkey" in cats and "env_var_name" in cats, cats
    for x in lk: assert t[x["start"]:x["end"]], x
    # gate: a gitleaks finding on a lookalike line is explained; off a lookalike line is not
    ls=line_starts(t)
    gl={"/f":[{"StartLine":lk[0]["line"],"Secret":t[lk[0]["start"]:lk[0]["end"]]}]}
    ok,_=gate_file("/f",t,gl,{}); assert ok, "lookalike-line finding should be explained"
    gl2={"/f":[{"StartLine":99,"Secret":"AKIA" "IOSFODNN7EXAMPLE"}]}
    ok2,un=gate_file("/f",t,gl2,{}); assert not ok2 and un, "off-lookalike finding must reject"
    # injection offset asserts across languages
    for lang in ("py","js","go","java","yaml","env","sh","json"):
        nt,sp=inject("x = 1\ny = 2\n",lang,"generic_api_key","k"); assert nt[sp["start"]:sp["end"]]==sp["value"]
    # basic_auth value present
    nt,sp=inject("a=1\n","py","basic_auth_header","k")
    assert not sp["value"].startswith("Basic ") and nt[sp["start"]:sp["end"]]==sp["value"]  # label is credential only
    assert nt[sp["start"]-6:sp["start"]]=="Basic ", "scheme keyword should precede the labeled credential"
    print("SELF-TEST PASS: lookalike detect, gate explain/reject, injection offsets (8 langs), basic-auth")

def main():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest="cmd")
    a=sub.add_parser("harvest-a"); a.add_argument("--target",type=int,default=4000)
    b=sub.add_parser("inject-b"); b.add_argument("--target",type=int,default=800)
    ap.add_argument("--self-test",action="store_true")
    args=ap.parse_args()
    if args.self_test: self_test(); return
    if args.cmd=="harvest-a": harvest_a(args.target)
    elif args.cmd=="inject-b": inject_b(args.target)
    else: ap.print_help()
if __name__=="__main__": main()

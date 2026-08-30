#!/usr/bin/env python3
"""RealCode-1 repo-selection v1 (frozen frame; REPO_SELECTION_v1.md).
Deterministic stratified-popularity selection over public GitHub, partitions
A/B/C disjointly, pins default-branch SHAs, writes a captured+hashed manifest.
No model scores anywhere. Runs where GitHub is reachable (cloud). Read-only
metadata; clones/harvest are separate later steps.

  GITHUB_TOKEN=... python3 select_realcode_repos.py --per-cell 12 --out realcode1/repo_selection_v1.json
"""
import argparse, json, os, sys, time, hashlib, urllib.request, urllib.parse, random, re
LANGS=["Python","JavaScript","Go","Java"]   # JS covers JS/TS
# each bucket split into sub-bands; sample across bands AND both sort orders
# so a cell spans its whole star range instead of hugging the ceiling.
BUCKETS=[("100-999",["100..299","300..599","600..999"]),
         ("1k-9999",["1000..2999","3000..5999","6000..9999"]),
         (">=10k",["10000..29999","30000..99999",">=100000"])]
SEED=20260829; API="https://api.github.com"
def gh(url):
    req=urllib.request.Request(url,headers={"User-Agent":"realcode1","Accept":"application/vnd.github+json"})
    t=os.environ.get("GITHUB_TOKEN")
    if t: req.add_header("Authorization",f"Bearer {t}")
    for attempt in range(5):
        try:
            r=urllib.request.urlopen(req,timeout=30); return json.load(r), r.headers
        except urllib.error.HTTPError as e:
            if e.code in (403,429):
                reset=e.headers.get("X-RateLimit-Reset")
                wait=max(2,min(60,(int(reset)-int(time.time())) if reset else 15))
                print(f"  rate-limited, sleep {wait}s",flush=True); time.sleep(wait); continue
            raise
    raise SystemExit("gh: too many rate-limit retries (need GITHUB_TOKEN)")
def norm_repo(u):
    u=(u or "").strip().rstrip("/").replace(".git",""); m=re.search(r"([^/]+/[^/]+)$",u); return (m.group(1).lower() if m else u.lower())
def load_exclusions():
    excl=set()
    for f in ("benchmark_b/ground_truth.jsonl","benchmark_c/ground_truth.jsonl","benchmark_d/ground_truth.jsonl"):
        if os.path.exists(f):
            for l in open(f):
                if l.strip():
                    r=json.loads(l).get("repo")
                    if r: excl.add(norm_repo(r))
    snap="benchmark_c/creddata_snapshot_commits.json"
    if os.path.exists(snap):
        for v in json.load(open(snap)).values():
            if isinstance(v,dict) and v.get("url"): excl.add(norm_repo(v["url"]))
    return excl
def search(lang,star_range,order):
    q=f"language:{lang} stars:{star_range} is:public archived:false fork:false"
    url=f"{API}/search/repositories?q={urllib.parse.quote(q)}&sort=stars&order={order}&per_page=100"
    d,_=gh(url); return d.get("items",[])
def eligible(items,excl):
    return [it for it in items if not it.get("fork") and not it.get("archived")
            and not it.get("mirror_url") and (it.get("size") or 0)>0 and it.get("default_branch")
            and norm_repo(it["full_name"]) not in excl]
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--per-cell",type=int,default=12); ap.add_argument("--out",default="realcode1/repo_selection_v1.json")
    a=ap.parse_args(); rng=random.Random(SEED); excl=load_exclusions()
    snapshot=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
    pool=[]; per_cell={}
    seen_global=set()
    for lang in LANGS:
        for blabel,bands in BUCKETS:
            per_band=max(1,a.per_cell//len(bands)); per_end=max(1,per_band//2)
            cell=[]
            for band in bands:
                got=[]
                for order in ("desc","asc"):
                    el=eligible(search(lang,band,order),excl)
                    el=[it for it in el if it["node_id"] not in seen_global and it["node_id"] not in {g["node_id"] for g in got}]
                    el.sort(key=lambda it:(-int(it.get("stargazers_count") or 0), it["node_id"]))
                    rng.shuffle(el)
                    got+=el[:per_end]
                # backfill within-band if an end was short
                if len(got)<per_band:
                    extra=eligible(search(lang,band,"desc"),excl)
                    extra=[it for it in extra if it["node_id"] not in {g["node_id"] for g in got} and it["node_id"] not in seen_global]
                    extra.sort(key=lambda it:(-int(it.get("stargazers_count") or 0),it["node_id"])); rng.shuffle(extra)
                    got+=extra[:per_band-len(got)]
                cell+=got[:per_band]
            for it in cell[:a.per_cell]:
                seen_global.add(it["node_id"])
                pool.append({"node_id":it["node_id"],"repo":it["full_name"],"norm":norm_repo(it["full_name"]),
                             "stars":it.get("stargazers_count"),"default_branch":it["default_branch"],
                             "lang":lang,"bucket":blabel,"parent":(it.get("parent") or {}).get("full_name")})
            per_cell[f"{lang}|{blabel}"]=len(cell[:a.per_cell])
            print(f"{lang} {blabel}: picked {len(cell[:a.per_cell])} across {len(bands)} sub-bands",flush=True)
    # stable global order, then partition A/B/C round-robin within stratum
    pool.sort(key=lambda r:(r["lang"],r["bucket"],-(r["stars"] or 0),r["node_id"]))
    parts=["RC-A","RC-B","RC-C"]
    cnt={}
    for r in pool:
        k=(r["lang"],r["bucket"]); i=cnt.get(k,0); r["partition"]=parts[i%3]; cnt[k]=i+1
    # pin default-branch SHA
    for r in pool:
        d,_=gh(f"{API}/repos/{r['repo']}/commits/{r['default_branch']}")
        r["sha"]=d.get("sha"); time.sleep(0.05)
    # disjointness assertions
    norms=[r["norm"] for r in pool]
    assert len(norms)==len(set(norms)), "duplicate repo in pool"
    assert not (set(norms)&excl), "exclusion leak"
    byp={p:sorted(r["norm"] for r in pool if r["partition"]==p) for p in parts}
    assert not (set(byp["RC-A"])&set(byp["RC-B"])) and not (set(byp["RC-A"])&set(byp["RC-C"])) and not (set(byp["RC-B"])&set(byp["RC-C"])), "A/B/C not disjoint"
    core=[{k:r[k] for k in ("node_id","repo","norm","stars","default_branch","sha","lang","bucket","partition","parent")} for r in pool]
    frozen_sha=hashlib.sha256(json.dumps(core,sort_keys=True).encode()).hexdigest()
    man={"benchmark":"SecMask RealCode-1","selection_version":"v1","snapshot_utc":snapshot,"seed":SEED,
         "frame":{"languages":LANGS,"buckets":{bl:bands for bl,bands in BUCKETS},"per_cell":a.per_cell,
                  "eligibility":"public,non-fork,non-archived,non-mirror,size>0,has default_branch"},
         "exclusions_norm_count":len(excl),"pool_size":len(pool),"per_cell_counts":per_cell,
         "partition_counts":{p:len(byp[p]) for p in parts},
         "disjoint_ABC":True,"disjoint_vs_existing":True,
         "authenticated":bool(os.environ.get("GITHUB_TOKEN")),
         "frozen_list_sha256":frozen_sha,"repos":core}
    os.makedirs(os.path.dirname(a.out) or ".",exist_ok=True)
    json.dump(man,open(a.out,"w"),indent=2)
    print(f"\nPOOL {len(pool)} | A {len(byp['RC-A'])} B {len(byp['RC-B'])} C {len(byp['RC-C'])} | sha {frozen_sha[:12]} -> {a.out}")
if __name__=="__main__": main()

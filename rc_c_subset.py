#!/usr/bin/env python3
"""SecMask RealCode-1 / RC-C-v1: deterministic stratified evaluation subset.

Freezes the full 1209-candidate harvest (candidates_sha already frozen), then
deterministically selects ~N stratified candidates as RC-C-v1 BEFORE any label
is seen. The remaining candidates are UNLABELED/RESERVED — never used for
training or model selection — available only for a PRE-REGISTERED RC-C-v2
expansion from the frozen reserve (no post-result re-harvest).

Stratification axes (from candidates.jsonl + sealed vault; selection is a
separate step from labeling, packets stay blind): detector/source, language,
value shape class + length + entropy bucket, vendor-vs-generic. Selection is
seeded and reproducible; subset_sha frozen before labels exist.

Blind labeling packets for the subset carry ONLY sanitized context + span +
lang (no provenance), plus ~12% blind duplicates for intra-rater agreement.

  python3 rc_c_subset.py select --n 400 --dup-rate 0.12
  python3 rc_c_subset.py freeze-labels --labels realcode1/rc_c/subset_v1/labels_filled.csv
  python3 rc_c_subset.py --self-test
"""
import argparse, collections, csv, hashlib, json, math, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rc_c_sanitize as S

BASE="realcode1/rc_c"; SUB=f"{BASE}/subset_v1"; SEED=20260829

def _h(*parts):  # deterministic per-id ordering, independent of dict/file order
    return int(hashlib.sha256("|".join(map(str,parts)).encode()).hexdigest(), 16)

def shape_bucket(v):
    if not v: return "empty"
    import re
    n=len(v)
    if S.PREFIX_ANY.search(v): cls="vendor"
    elif re.fullmatch(r'[0-9a-f]+', v): cls="hexlo"
    elif re.fullmatch(r'[0-9A-F]+', v): cls="hexup"
    elif re.fullmatch(r'[0-9]+', v): cls="digits"
    elif re.fullmatch(r'[A-Za-z0-9+/=_\-.]+', v): cls="b64ish"
    else: cls="mixed"
    lb = "s" if n<20 else ("m" if n<40 else "l")
    h=S.shannon(v); eb="lo" if h<3.0 else ("md" if h<4.2 else "hi")
    return f"{cls}:{lb}:{eb}"

def load():
    cands=[json.loads(l) for l in open(f"{BASE}/candidates.jsonl") if l.strip()]
    vault={}
    for l in open(f"{BASE}/VAULT_sealed_until_labels_frozen.jsonl"):
        d=json.loads(l)
        if "packet_map" in d: continue
        vault[d["id"]]=d
    return cands, vault

def stratum_key(c, vault):
    v=open(f"{BASE}/files/{c['file']}",encoding="utf-8",errors="replace").read()[c["start"]:c["end"]]
    prov=vault.get(c["id"],{})
    return f'{prov.get("detector","?")}|{c["lang"]}|{shape_bucket(v)}'

def select(n, dup_rate):
    cands, vault = load()
    total=len(cands)
    strata=collections.defaultdict(list)
    for c in cands: strata[stratum_key(c,vault)].append(c)
    # proportional allocation with a floor of 1 for non-empty strata
    keys=sorted(strata)
    alloc={k: min(len(strata[k]), max(1, int(math.floor(n*len(strata[k])/total)))) for k in keys}
    # adjust to hit exactly n (respecting per-stratum capacity)
    def total_alloc(): return sum(alloc.values())
    # trim if over: remove from largest allocations (that stay >=1), by frac remainder
    order=sorted(keys, key=lambda k:(-(n*len(strata[k])/total - math.floor(n*len(strata[k])/total)), k))
    i=0
    while total_alloc()>n:
        k=order[i%len(order)]
        if alloc[k]>1: alloc[k]-=1
        i+=1
        if i>100000: break
    # grow if under: add where capacity remains, by frac remainder (largest first)
    order2=sorted(keys, key=lambda k:(-(n*len(strata[k])/total - math.floor(n*len(strata[k])/total)), k))
    i=0
    while total_alloc()<n:
        k=order2[i%len(order2)]
        if alloc[k]<len(strata[k]): alloc[k]+=1
        i+=1
        if i>100000: break
    # deterministic pick within each stratum
    selected=[]
    for k in keys:
        pool=sorted(strata[k], key=lambda c:_h(SEED,"pick",c["id"]))
        selected.extend(pool[:alloc[k]])
    selected=sorted(selected, key=lambda c:c["id"])
    sel_ids={c["id"] for c in selected}
    reserve=[c["id"] for c in cands if c["id"] not in sel_ids]
    assert len(sel_ids & set(reserve))==0
    assert len(sel_ids)+len(reserve)==total

    os.makedirs(SUB, exist_ok=True)
    with open(f"{SUB}/selected_candidates.jsonl","w") as f:
        for c in selected: f.write(json.dumps(c)+"\n")
    json.dump({"reserved_candidate_ids":sorted(reserve),
               "policy":"UNLABELED/RESERVED — never train or select on these; RC-C-v2 must be pre-registered from this frozen pool"},
              open(f"{SUB}/RESERVED_candidate_ids.json","w"), indent=2)

    # blind packets (+ duplicates) for the subset
    rng_order=sorted(range(len(selected)), key=lambda i:_h(SEED,"order",selected[i]["id"]))
    n_dup=int(round(dup_rate*len(selected)))
    dup_ids=[selected[i]["id"] for i in sorted(range(len(selected)),
             key=lambda i:_h(SEED,"dup",selected[i]["id"]))[:n_dup]]
    jobs=[(selected[i]["id"], False) for i in rng_order]+[(cid, True) for cid in dup_ids]
    jobs=sorted(jobs, key=lambda t:_h(SEED,"jobs",t[0],t[1]))
    byid={c["id"]:c for c in selected}
    pmap=[]
    with open(f"{SUB}/packets.jsonl","w") as pf, open(f"{SUB}/labels_template.csv","w",newline="") as cf:
        wr=csv.writer(cf); wr.writerow(["packet_id","label(POLICY_POSITIVE|POLICY_NEGATIVE|AMBIGUOUS_EXCLUDED)","note"])
        for k,(cid,is_dup) in enumerate(jobs):
            c=byid[cid]; pid=f"spkt-{k:04d}"
            text=open(f"{BASE}/files/{c['file']}",encoding="utf-8").read()
            lines=text.split("\n"); ln=c["line"]-1; ls=S.line_starts(text); col=c["start"]-ls[ln]
            view=[]
            for j in range(max(0,ln-8), min(len(lines),ln+9)):
                view.append(lines[j])
                if j==ln: view.append(" "*col+"^"*max(1,c["end"]-c["start"]))
            pf.write(json.dumps({"packet_id":pid,"lang":c["lang"],"context":"\n".join(view)})+"\n")
            wr.writerow([pid,"",""])
            pmap.append({"packet_id":pid,"candidate_id":cid,"is_dup":is_dup})
    with open(f"{SUB}/VAULT_sealed_until_labels_frozen.jsonl","w") as f:
        for c in selected:
            f.write(json.dumps({"id":c["id"], **{k:vault.get(c["id"],{}).get(k) for k in ("repo","commit","path","detector","family")}})+"\n")
        for m in pmap: f.write(json.dumps({"packet_map":m})+"\n")

    subsha=hashlib.sha256(open(f"{SUB}/selected_candidates.jsonl","rb").read()).hexdigest()
    strata_counts={k:{"pool":len(strata[k]),"selected":alloc[k]} for k in keys}
    man={"benchmark":"SecMask RealCode-1 / RC-C-v1 (stratified eval subset)",
         "stage":"SUBSET FROZEN — before any label seen",
         "seed":SEED,"n_target":n,"n_selected":len(selected),"n_reserved":len(reserve),
         "full_candidates_sha256":hashlib.sha256(open(f"{BASE}/candidates.jsonl","rb").read()).hexdigest(),
         "subset_sha256":subsha,"n_strata":len(keys),
         "blind_duplicates":n_dup,"packets":len(jobs),
         "strata":strata_counts,
         "reserve_policy":"frozen; RC-C-v2 expansion must be pre-registered from reserve, no post-result re-harvest"}
    json.dump(man, open(f"{SUB}/manifest_subset.json","w"), indent=2)
    print(f"RC-C-v1: selected {len(selected)}/{total} across {len(keys)} strata, "
          f"reserved {len(reserve)}, {n_dup} blind dups, {len(jobs)} packets, subset_sha={subsha[:12]}")

def freeze_labels(labels_csv):
    rows=list(csv.DictReader(open(labels_csv)))
    lab={r["packet_id"]:r[[k for k in r if k.startswith("label")][0]].strip() for r in rows}
    valid={"POLICY_POSITIVE","POLICY_NEGATIVE","AMBIGUOUS_EXCLUDED"}
    bad={p:v for p,v in lab.items() if v not in valid}
    assert not bad, f"invalid/missing labels: {list(bad.items())[:5]} (+{max(0,len(bad)-5)} more)"
    pmap={}
    for l in open(f"{SUB}/VAULT_sealed_until_labels_frozen.jsonl"):
        d=json.loads(l)
        if "packet_map" in d: pmap[d["packet_map"]["packet_id"]]=d["packet_map"]["candidate_id"]
    by=collections.defaultdict(list)
    for pid,v in lab.items(): by[pmap[pid]].append(v)
    dups=[v for v in by.values() if len(v)>1]
    agree=sum(1 for v in dups if len(set(v))==1)
    final={cid:(v[0] if len(set(v))==1 else "AMBIGUOUS_EXCLUDED") for cid,v in by.items()}
    out={"labeler_type":"human","labels":final,
         "intra_rater":{"duplicate_pairs":len(dups),"agreed":agree,
                        "rate":round(agree/len(dups),4) if dups else None},
         "counts":dict(collections.Counter(final.values())),
         "labels_sha256":hashlib.sha256(json.dumps(final,sort_keys=True).encode()).hexdigest()}
    json.dump(out, open(f"{SUB}/labels_frozen.json","w"), indent=2)
    print(f"RC-C-v1 labels frozen: {out['counts']}  intra-rater={out['intra_rater']}  sha={out['labels_sha256'][:12]}")

def self_test():
    cands,vault=load()
    # determinism: two selects identical
    select(120,0.12); a=open(f"{SUB}/selected_candidates.jsonl").read()
    m1=json.load(open(f"{SUB}/manifest_subset.json"))
    select(120,0.12); b=open(f"{SUB}/selected_candidates.jsonl").read()
    m2=json.load(open(f"{SUB}/manifest_subset.json"))
    assert a==b and m1["subset_sha256"]==m2["subset_sha256"], "selection not deterministic"
    sel=[json.loads(l) for l in open(f"{SUB}/selected_candidates.jsonl") if l.strip()]
    res=set(json.load(open(f"{SUB}/RESERVED_candidate_ids.json"))["reserved_candidate_ids"])
    ids={c["id"] for c in sel}
    assert not (ids & res), "subset/reserve overlap"
    assert len(ids)+len(res)==len(cands), "subset+reserve != full"
    # packet blindness
    pk=[json.loads(l) for l in open(f"{SUB}/packets.jsonl") if l.strip()]
    assert all(set(p)=={"packet_id","lang","context"} for p in pk), "packet leaks fields"
    import re
    assert not any(re.search(r'gitleaks|RuleID|detector|entropy_|vendor_prefix', p["context"]) for p in pk), "provenance word in context"
    # duplicates present + byte-identical
    pmap={}
    for l in open(f"{SUB}/VAULT_sealed_until_labels_frozen.jsonl"):
        d=json.loads(l)
        if "packet_map" in d: pmap.setdefault(d["packet_map"]["candidate_id"],[]).append(d["packet_map"]["packet_id"])
    ctx={p["packet_id"]:p["context"] for p in pk}
    dups={c:ps for c,ps in pmap.items() if len(ps)>1}
    assert dups and all(len({ctx[p] for p in ps})==1 for ps in dups.values()), "duplicates not blind-identical"
    # strata coverage: no selected stratum exceeds its pool
    for k,st in m1["strata"].items(): assert st["selected"]<=st["pool"]
    print(f"RC-C-SUBSET SELF-TEST PASS: deterministic, disjoint reserve, blind packets, "
          f"{len(dups)} blind-identical dup candidates, {m1['n_strata']} strata, n={len(ids)}")
    import shutil; shutil.rmtree(SUB, ignore_errors=True)

def main():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest="cmd")
    s=sub.add_parser("select"); s.add_argument("--n",type=int,default=400); s.add_argument("--dup-rate",type=float,default=0.12)
    fl=sub.add_parser("freeze-labels"); fl.add_argument("--labels",required=True)
    ap.add_argument("--self-test",action="store_true")
    a=ap.parse_args()
    if a.self_test: self_test(); return
    if a.cmd=="select": select(a.n,a.dup_rate)
    elif a.cmd=="freeze-labels": freeze_labels(a.labels)
    else: ap.print_help()
if __name__=="__main__": main()

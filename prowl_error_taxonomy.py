#!/usr/bin/env python3
"""Bucketize prowl external errors (READ-ONLY, no model). Consumes
reports/prowl_errrows.jsonl. FP = T4 hard-negative predicted positive at tau;
FN = code&en positive predicted negative at tau. FPs bucketed by the VALUE the
model flagged; FNs bucketed by prowl `type` (family) + value shape.

  python3 prowl_error_taxonomy.py --tau 0.99
"""
import argparse, json, re, collections
U=re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
HEX=re.compile(r'^[0-9a-fA-F]+$'); B64=re.compile(r'^[A-Za-z0-9+/=_-]+$')
IPV4=re.compile(r'^\d{1,3}(\.\d{1,3}){3}$'); MAC=re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')
JWT=re.compile(r'^ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
ENVN=re.compile(r'^[A-Z][A-Z0-9_]{3,}$'); NUM=re.compile(r'^\d{5,}$')
URL=re.compile(r'[a-z][a-z0-9+.-]*://', re.I)
PLACE=("example","changeme","your_","your-","yourkey","placeholder","dummy","test","sample",
       "redact","xxxx","<",">","replace","insert","todo","fixme","none","null","xxx","****","...")
def strip(v): return (v or "").strip().strip('\'"`').strip()
def classify_value(v):
    s=strip(v); low=s.lower()
    if not s: return "empty"
    if any(p in low for p in PLACE): return "placeholder/example/redacted"
    if s.startswith("-----BEGIN") or ("BEGIN" in s and ("KEY" in s or "CERTIFICATE" in s)): return "private_key/cert_material"
    if JWT.match(s): return "jwt"
    if URL.search(s): return "url/connection_string"
    if U.match(s): return "uuid"
    if IPV4.match(s): return "ip_address"
    if MAC.match(s): return "mac_address"
    if HEX.match(s) and len(s) in (32,40,64,128): return f"hex_hash/checksum(len{len(s)})"
    if ENVN.match(s): return "env_var_name(no_value)"
    if NUM.match(s): return "numeric_id"
    if B64.match(s) and len(s)>=24: return "base64/hex_blob"
    if len(s)>=16: return "high_entropy_other"
    return "short/other"
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--tau",type=float,default=0.99)
    ap.add_argument("--in",dest="inp",default=None); ap.add_argument("--tag",default="v33aRS"); a=ap.parse_args()
    inp=a.inp or f"reports/prowl_errrows_{a.tag}.jsonl"; outp=f"reports/prowl_error_taxonomy_{a.tag}.json"
    rows=[json.loads(l) for l in open(inp)]
    fps=[r for r in rows if r["tier"]=="T4_hard_negative" and r["maxscore"]>=a.tau]
    t4=[r for r in rows if r["tier"]=="T4_hard_negative"]
    fns=[r for r in rows if r["source"]=="code" and r["lang"]=="en" and r["label"]==1 and r["maxscore"]<a.tau]
    codeen_pos=[r for r in rows if r["source"]=="code" and r["lang"]=="en" and r["label"]==1]
    fp_b=collections.Counter(classify_value(r["pred_values"][0] if r["pred_values"] else "") for r in fps)
    fn_fam=collections.Counter(r.get("type") or "?" for r in fns)
    fn_shape=collections.Counter(classify_value(r.get("gold_value") or "") for r in fns)
    def top(c,n=15): return [{"bucket":k,"n":v,"pct":round(100*v/sum(c.values()),1)} for k,v in c.most_common(n)] if c else []
    rep={"tau":a.tau,
      "hard_negative_FP":{"n_T4":len(t4),"n_FP":len(fps),"FP_rate":round(len(fps)/max(1,len(t4)),4),
                          "buckets_by_flagged_value":top(fp_b),
                          "examples":{b:[strip(r["pred_values"][0]) for r in fps if (r["pred_values"] and classify_value(r["pred_values"][0])==b)][:4] for b,_ in fp_b.most_common(6)}},
      "code_en_FN":{"n_code_en_pos":len(codeen_pos),"n_FN":len(fns),"FN_rate":round(len(fns)/max(1,len(codeen_pos)),4),
                    "buckets_by_family":top(fn_fam),"buckets_by_value_shape":top(fn_shape),
                    "examples":{f:[strip(r.get("gold_value") or "")[:50] for r in fns if (r.get("type")==f)][:4] for f,_ in fn_fam.most_common(6)}}}
    json.dump(rep,open(outp,"w"),indent=2)
    print(json.dumps({"FP_rate":rep["hard_negative_FP"]["FP_rate"],
                      "FP_buckets":rep["hard_negative_FP"]["buckets_by_flagged_value"],
                      "FN_rate":rep["code_en_FN"]["FN_rate"],
                      "FN_by_family":rep["code_en_FN"]["buckets_by_family"][:8]},indent=2))
    print("full ->",outp)
if __name__=="__main__": main()

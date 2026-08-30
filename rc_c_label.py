#!/usr/bin/env python3
"""SecMask RealCode-1 / RC-C blind interactive labeler.

Shows one packet's sanitized context at a time and records your policy label
straight into labels_filled.csv. BLIND by construction: reads packets.jsonl
only (no scanner provenance, no model score, no candidate/file id). Resumable
and crash-safe — every keystroke rewrites the CSV atomically, and re-running
skips rows already labeled.

Keys:  p = POLICY_POSITIVE   n = POLICY_NEGATIVE   a = AMBIGUOUS_EXCLUDED
       s = skip (leave blank, decide later)   b = back (re-label previous)
       q = save & quit        ?  = help
A trailing note is optional:  "p needs review"  stores label + note.

  python3 rc_c_label.py                      # default subset_v1
  python3 rc_c_label.py --dir realcode1/rc_c/subset_v1
"""
import argparse, csv, json, os, sys, tempfile

def load_rows(csv_path):
    rows=[]
    with open(csv_path, newline="") as f:
        r=csv.reader(f); hdr=next(r)
        for row in r:
            row += [""]*(3-len(row)); rows.append(row[:3])
    return hdr, rows

def save_atomic(csv_path, hdr, rows):
    d=os.path.dirname(csv_path) or "."
    fd,tmp=tempfile.mkstemp(dir=d, suffix=".tmp"); os.close(fd)
    with open(tmp,"w",newline="") as f:
        w=csv.writer(f); w.writerow(hdr); w.writerows(rows)
    os.replace(tmp, csv_path)

KEYMAP={"p":"POLICY_POSITIVE","n":"POLICY_NEGATIVE","a":"AMBIGUOUS_EXCLUDED"}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--dir", default="realcode1/rc_c/subset_v1")
    ap.add_argument("--suggest", default="", help="CSV of suggested labels shown as default (Enter=accept)")
    a=ap.parse_args()
    D=a.dir
    packets_path=f"{D}/packets.jsonl"; tmpl=f"{D}/labels_template.csv"; filled=f"{D}/labels_filled.csv"
    if not os.path.exists(packets_path): sys.exit(f"no packets at {packets_path}")
    if not os.path.exists(filled):
        # seed from template (all-empty) if not started yet
        if not os.path.exists(tmpl): sys.exit(f"no template at {tmpl}")
        import shutil; shutil.copy(tmpl, filled); print(f"created {filled} from template")
    packets={p["packet_id"]:p for p in (json.loads(l) for l in open(packets_path) if l.strip())}
    hdr, rows = load_rows(filled)
    sugg={}
    if a.suggest and os.path.exists(a.suggest):
        import csv as _csv
        for r in _csv.DictReader(open(a.suggest)):
            sugg[r["packet_id"]]=(r.get("suggested_label","") or "", r.get("reason",""))
        print(f"loaded {len(sugg)} suggestions from {a.suggest} (Enter accepts; p/n/a overrides)")
    idx_by_pid={row[0]:i for i,row in enumerate(rows)}
    order=[row[0] for row in rows]

    done=sum(1 for r in rows if r[1].strip())
    total=len(rows)
    print(f"RC-C blind labeler — {D}")
    print(f"{done}/{total} already labeled. Keys: p/n/a  s=skip b=back q=quit ?=help\n")

    # iterate over unlabeled, but allow 'back'
    pos=0
    # start at first unlabeled
    while pos<len(order) and rows[idx_by_pid[order[pos]]][1].strip(): pos+=1
    while 0<=pos<len(order):
        pid=order[pos]; ri=idx_by_pid[pid]; pk=packets.get(pid,{})
        labeled=sum(1 for r in rows if r[1].strip())
        print("="*72)
        print(f"[{labeled}/{total} done]  packet {pid}  lang={pk.get('lang','?')}"
              + (f"   (current: {rows[ri][1]})" if rows[ri][1].strip() else ""))
        print("-"*72)
        print(pk.get("context",""))
        print("-"*72)
        sg=sugg.get(pid)
        if sg and sg[0]:
            print(f"  SUGGESTION: {sg[0]}  ({sg[1]})   [Enter=accept]")
        try: raw=input("label (Enter=accept sugg, p/n/a, s/b/q, ?): ").strip()
        except (EOFError,KeyboardInterrupt): print("\nsaved. bye."); save_atomic(filled,hdr,rows); return
        if not raw:
            if sg and sg[0] in ("POLICY_POSITIVE","POLICY_NEGATIVE","AMBIGUOUS_EXCLUDED"):
                rows[ri][1]=sg[0]; rows[ri][2]="(accepted suggestion)"
                save_atomic(filled,hdr,rows); pos+=1
                while pos<len(order) and rows[idx_by_pid[order[pos]]][1].strip(): pos+=1
            continue
        cmd=raw.split(None,1); key=cmd[0].lower(); note=cmd[1] if len(cmd)>1 else ""
        if key=="?":
            print("\n p=POSITIVE (should be masked)  n=NEGATIVE (should NOT)  a=AMBIGUOUS_EXCLUDED\n"
                  " s=skip  b=back  q=save&quit.  Add a note after the key, e.g. 'a base64 blob?'\n"); continue
        if key=="q": save_atomic(filled,hdr,rows); print(f"saved {filled}. {labeled}/{total} labeled."); return
        if key=="b":
            pos=max(0,pos-1); continue
        if key=="s": pos+=1; continue
        if key in KEYMAP:
            rows[ri][1]=KEYMAP[key]; rows[ri][2]=note
            save_atomic(filled,hdr,rows)   # crash-safe: persist every label
            pos+=1
            # skip forward over any already-labeled
            while pos<len(order) and rows[idx_by_pid[order[pos]]][1].strip(): pos+=1
            continue
        print("  ? unrecognized — p/n/a, s skip, b back, q quit")
    save_atomic(filled,hdr,rows)
    labeled=sum(1 for r in rows if r[1].strip())
    print(f"\nAll packets seen. {labeled}/{total} labeled. Saved {filled}.")
    if labeled==total: print("Ready: python3 rc_c_subset.py freeze-labels --labels "+filled)
if __name__=="__main__": main()

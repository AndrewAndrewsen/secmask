#!/usr/bin/env python3
"""SecMask RealCode-1 / RC-C harvester: blind natural candidates.

Pipeline (prereg + the four hardening gates):
  47 frozen reserved repos (partition RC-C, pinned SHAs)
    -> scanner union: gitleaks (--redact, LOCATIONS ONLY, report parsed
       ephemerally and deleted; if --redact unsupported the integration is
       UNSAFE_EXCLUDED) + internal entropy/lookalike rules (rc_c_sanitize).
       detect-secrets: EXCLUDED (HARNESS_INVALID, see realcode1/results/).
       Our MODEL is never consulted.
    -> deterministic candidate union + dedup (rc_c_sanitize.sanitize_text)
    -> EPHEMERAL sanitation + verification (raw value never persisted)
    -> blind labeling packets: sanitized context + marked span + language.
       NO detector names, NO scanner provenance, NO scores. Provenance is
       sealed in a separate vault, to be opened only after labels freeze.
    -> 12% blind duplicate packets (label-consistency check; mapping in vault)
    -> freeze labels + corpus hashes -> ONLY THEN model evaluation.
  Candidate sampling is deterministic and frozen BEFORE labeling begins.

  python3 rc_c_build.py harvest   [--per-repo-cap 40] [--max-candidates 1200]
  python3 rc_c_build.py packets   [--dup-rate 0.12]
  python3 rc_c_build.py freeze-labels --labels realcode1/rc_c/labels_filled.csv
  python3 rc_c_build.py --self-test     # REAL-gitleaks sentinel proof (Mac)
"""
import argparse, collections, csv, hashlib, json, os, random, re, shutil, subprocess, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rc_build            # clone, src_files, EXT_LANG, MAXBYTES, SEL
import rc_c_sanitize as S

SEED = 20260829
OUT = "realcode1/rc_c"
VAULT = f"{OUT}/VAULT_sealed_until_labels_frozen.jsonl"

# ---------------- gitleaks: locations only, never values ----------------
def gitleaks_supports_redact():
    try:
        r = subprocess.run(["gitleaks", "detect", "--help"], capture_output=True, text=True, timeout=30)
        return "--redact" in (r.stdout + r.stderr)
    except Exception:
        return False

def gitleaks_locations(path):
    """Run gitleaks with --redact; return {abs_file: [(SL,SC,EL,EC,rule)]}.
    The report tempfile is parsed and deleted; subprocess stdout/stderr are
    captured and DISCARDED (never printed/logged). Returns None if the
    integration is unsafe (no --redact) or gitleaks is missing."""
    if shutil.which("gitleaks") is None or not gitleaks_supports_redact():
        return None
    fd, rep = tempfile.mkstemp(suffix=".json"); os.close(fd)
    try:
        subprocess.run(["gitleaks", "detect", "--no-git", "--redact",
                        "--source", path, "-f", "json", "-r", rep],
                       capture_output=True, timeout=600)   # output captured, discarded
        data = []
        if os.path.getsize(rep) > 0:
            try: data = json.load(open(rep))
            except Exception: data = []
        if not data:   # newer gitleaks prefers `dir` for non-git scans
            subprocess.run(["gitleaks", "dir", path, "--redact", "-f", "json", "-r", rep],
                           capture_output=True, timeout=600)
            if os.path.getsize(rep) > 0:
                try: data = json.load(open(rep))
                except Exception: data = []
        out = collections.defaultdict(list)
        for f in (data if isinstance(data, list) else []):
            fp = os.path.abspath(os.path.join(path, f.get("File", "")))
            out[fp].append((f.get("StartLine"), f.get("StartColumn"),
                            f.get("EndLine"), f.get("EndColumn"),
                            f.get("RuleID", "?")))
        return out
    except Exception:
        return {}
    finally:
        try: os.unlink(rep)
        except Exception: pass

def loc_to_span(text, SL, SC, EL, EC):
    """1-based line/col (inclusive) -> char span. None if out of bounds."""
    ls = S.line_starts(text)
    try:
        s0 = ls[SL-1] + (SC-1); e0 = ls[EL-1] + EC
        if 0 <= s0 < e0 <= len(text): return s0, e0
    except Exception: pass
    return None

# ---------------- harvest ----------------
def load_rc_c_repos():
    m = json.load(open(rc_build.SEL))
    return [r for r in m["repos"] if r["partition"] == "RC-C"], m["frozen_list_sha256"]

def harvest(per_repo_cap, max_candidates):
    repos, selsha = load_rc_c_repos()
    gl_safe = gitleaks_supports_redact() and shutil.which("gitleaks") is not None
    if not gl_safe:
        print("WARNING: gitleaks --redact unavailable -> gitleaks integration UNSAFE_EXCLUDED "
              "(recorded in manifest); proceeding with internal detectors only.")
    shutil.rmtree(f"{OUT}/files", ignore_errors=True)   # clear stale files from a prior harvest
    for _f in ("candidates.jsonl", VAULT.split("/")[-1], "manifest_harvest.json"):
        try: os.remove(f"{OUT}/{_f}")
        except OSError: pass
    os.makedirs(f"{OUT}/files", exist_ok=True)
    rng = random.Random(SEED)
    cands_out, vault, n_total, idx, excluded = [], [], 0, 0, 0
    for r in repos:
        if n_total >= max_candidates: break
        d = tempfile.mkdtemp(prefix="rcc_")
        try:
            if not rc_build.clone(r["repo"], r["sha"], d): continue
            gl = gitleaks_locations(d) if gl_safe else {}
            files = list(rc_build.src_files(d)); rng.shuffle(files)
            per_repo = 0
            for p, lang in files:
                if per_repo >= per_repo_cap or n_total >= max_candidates: break
                try: text = open(p, encoding="utf-8", errors="replace").read()
                except Exception: continue
                extra = []
                ok_locs = True
                for (SL, SC, EL, EC, rule) in (gl or {}).get(os.path.abspath(p), []):
                    sp = loc_to_span(text, SL, SC, EL, EC)
                    if sp is None: ok_locs = False; break   # can't locate -> can't sanitize -> exclude file
                    extra.append({"start": sp[0], "end": sp[1], "detector": "gitleaks", "family": rule})
                if not ok_locs: excluded += 1; continue
                if not extra and not S.find_candidates(text): continue
                prov = f'{r["repo"]}|{r["sha"]}|{os.path.relpath(p, d)}'
                try:
                    clean, recs = S.sanitize_text(text, extra=extra, prov=prov)
                except S.ExcludedFile:
                    excluded += 1; continue
                if not recs: continue
                # window ±25 lines around the candidate cluster (length-preserving
                # sanitation => raw-text offsets are valid in `clean`)
                lines = clean.split("\n"); lmin = min(x["line"] for x in recs); lmax = max(x["line"] for x in recs)
                a, b = max(0, lmin-25), min(len(lines), lmax+25)
                snippet = "\n".join(lines[a:b]); off = sum(len(x)+1 for x in lines[:a])
                w = [dict(x, start=x["start"]-off, end=x["end"]-off, line=x["line"]-a) for x in recs]
                w = [x for x in w if 0 <= x["start"] < x["end"] <= len(snippet)
                     and snippet[x["start"]:x["end"]] == x["synth_value"]]
                if not w: continue
                fid = f"rcc-{idx:05d}.{lang}"; idx += 1
                tmp = f"{OUT}/files/.{fid}.tmp"; open(tmp, "w").write(snippet); os.replace(tmp, f"{OUT}/files/{fid}")
                for x in w:
                    cands_out.append({"id": x["id"], "file": fid, "lang": lang,
                                      "start": x["start"], "end": x["end"], "line": x["line"]})
                    vault.append({"id": x["id"], "repo": r["repo"], "commit": r["sha"],
                                  "path": prov.split("|", 2)[2], "detector": x["detector"],
                                  "family": x["family"]})
                    n_total += 1
                per_repo += 1
        finally:
            shutil.rmtree(d, ignore_errors=True)
    with open(f"{OUT}/candidates.jsonl", "w") as f:
        for c in cands_out: f.write(json.dumps(c) + "\n")
    with open(VAULT, "w") as f:
        for v in vault: f.write(json.dumps(v) + "\n")
    csha = hashlib.sha256(open(f"{OUT}/candidates.jsonl", "rb").read()).hexdigest()
    man = {"benchmark": "SecMask RealCode-1 / RC-C", "stage": "HARVESTED — candidates frozen pre-labeling",
           "selection_sha": selsha, "seed": SEED, "files": idx, "candidates": n_total,
           "files_excluded_by_sanitation": excluded,
           "gitleaks_integration": ("redact-locations-only" if gl_safe else "UNSAFE_EXCLUDED (no --redact)"),
           "detect_secrets": "EXCLUDED — HARNESS_INVALID (realcode1/results/detect_secrets_HARNESS_INVALID.json)",
           "model_consulted": False, "candidates_sha256": csha,
           "sampling_rule": "FROZEN at harvest; no category top-ups after labeling begins"}
    json.dump(man, open(f"{OUT}/manifest_harvest.json", "w"), indent=2)
    print(f"RC-C harvest: {idx} files, {n_total} candidates, {excluded} files excluded by sanitation, "
          f"gitleaks={'ON(redact)' if gl_safe else 'UNSAFE_EXCLUDED'}, candidates_sha={csha[:12]}")

# ---------------- blind labeling packets ----------------
def packets(dup_rate):
    cands = [json.loads(l) for l in open(f"{OUT}/candidates.jsonl") if l.strip()]
    rng = random.Random(SEED + 1)
    order = list(range(len(cands))); rng.shuffle(order)
    n_dup = int(round(dup_rate * len(cands)))
    dup_idx = rng.sample(order, n_dup) if n_dup else []
    jobs = [(i, False) for i in order] + [(i, True) for i in dup_idx]
    rng.shuffle(jobs)
    pk, dupmap = [], []
    with open(f"{OUT}/packets.jsonl", "w") as pf, open(f"{OUT}/labels_template.csv", "w", newline="") as cf:
        wr = csv.writer(cf); wr.writerow(["packet_id", "label(POLICY_POSITIVE|POLICY_NEGATIVE|AMBIGUOUS_EXCLUDED)", "note"])
        for k, (i, is_dup) in enumerate(jobs):
            c = cands[i]; pid = f"pkt-{k:05d}"
            text = open(f"{OUT}/files/{c['file']}", encoding="utf-8").read()
            lines = text.split("\n"); ln = c["line"] - 1
            ls = S.line_starts(text); col = c["start"] - ls[ln]
            view = []
            for j in range(max(0, ln-8), min(len(lines), ln+9)):
                view.append(lines[j])
                if j == ln: view.append(" " * col + "^" * max(1, c["end"]-c["start"]))
            pf.write(json.dumps({"packet_id": pid, "lang": c["lang"],
                                 "context": "\n".join(view)}) + "\n")   # NO detector, NO file id, NO score
            wr.writerow([pid, "", ""])
            (dupmap if is_dup else pk).append({"packet_id": pid, "candidate_id": c["id"]})
    with open(VAULT, "a") as f:
        for m in pk + dupmap:
            f.write(json.dumps({"packet_map": m}) + "\n")
    print(f"packets: {len(jobs)} total ({n_dup} blind duplicates). Label labels_template.csv; "
          f"packet->candidate mapping sealed in vault.")

# ---------------- freeze labels ----------------
def freeze_labels(labels_csv):
    rows = list(csv.DictReader(open(labels_csv)))
    lab = {r["packet_id"]: r[[k for k in r if k.startswith("label")][0]].strip() for r in rows}
    valid = {"POLICY_POSITIVE", "POLICY_NEGATIVE", "AMBIGUOUS_EXCLUDED"}
    bad = {p: v for p, v in lab.items() if v not in valid}
    assert not bad, f"invalid/missing labels: {list(bad.items())[:5]} (+{max(0,len(bad)-5)} more)"
    pmap = {}
    for l in open(VAULT):
        d = json.loads(l)
        if "packet_map" in d: pmap[d["packet_map"]["packet_id"]] = d["packet_map"]["candidate_id"]
    by_cand = collections.defaultdict(list)
    for pid, v in lab.items(): by_cand[pmap[pid]].append(v)
    agree = [v for v in by_cand.values() if len(v) > 1]
    n_agree = sum(1 for v in agree if len(set(v)) == 1)
    final = {}
    for cid, v in by_cand.items():
        final[cid] = v[0] if len(set(v)) == 1 else "AMBIGUOUS_EXCLUDED"   # disagreement -> excluded
    out = {"labels": final,
           "duplicate_agreement": {"pairs": len(agree), "agreed": n_agree,
                                    "rate": round(n_agree/len(agree), 4) if agree else None},
           "counts": dict(collections.Counter(final.values())),
           "labels_sha256": hashlib.sha256(json.dumps(final, sort_keys=True).encode()).hexdigest()}
    json.dump(out, open(f"{OUT}/labels_frozen.json", "w"), indent=2)
    print(f"labels frozen: {out['counts']}  dup-agreement={out['duplicate_agreement']}  "
          f"sha={out['labels_sha256'][:12]}. Vault may now be opened. Models may now run.")

# ---------------- REAL-gitleaks sentinel proof ----------------
def self_test():
    """Plants sentinels in a fixture repo, runs the REAL harvest persist path
    (with actual gitleaks), then sweeps outputs + tempdir + logs for sentinels.
    Requires gitleaks; exits 2 (SKIPPED) without it."""
    if shutil.which("gitleaks") is None:
        print("SKIPPED: gitleaks not installed on this machine — run on the harvest machine."); sys.exit(2)
    if not gitleaks_supports_redact():
        print("FAIL-SAFE OK: no --redact => integration would be UNSAFE_EXCLUDED. Nothing persisted."); return
    # NOTE: values must NOT contain gitleaks-allowlisted stopwords ("EXAMPLE"!)
    SENT = {"aws": "AKIA" "JQ7WLPX4KZM2N3T9",
            "ghp": "ghp_" "Zt5Kq8Wm2Xr7Vn4Ls1Jd9Hf6Bg3Pc0Ye5Ta2",
            "slack": "xoxb-" "2489517306-Xw3Lq9Zt7Rm1Vn5Kp8Ys",
            "gen": "q9zR3mX7vL2pK8wN4tY6bJ1hG5dF0aC9eU3iO7sQ"}
    scratch = tempfile.mkdtemp(prefix="rcc_prooftmp_")
    old_tmp, os.environ["TMPDIR"] = os.environ.get("TMPDIR"), scratch
    tempfile.tempdir = scratch
    outdir = tempfile.mkdtemp(prefix="rcc_proofout_", dir=scratch)
    try:
        repo = os.path.join(scratch, "fixture_repo"); os.makedirs(repo)
        open(f"{repo}/conf.py", "w").write(
            f'aws_access_key_id = "{SENT["aws"]}"\ntoken = "{SENT["ghp"]}"\n'
            f'slack_bot = "{SENT["slack"]}"\napi_secret = "{SENT["gen"]}"\n')
        gl = gitleaks_locations(repo)
        text = open(f"{repo}/conf.py").read()
        extra = []
        for (SL, SC, EL, EC, rule) in (gl or {}).get(os.path.abspath(f"{repo}/conf.py"), []):
            sp = loc_to_span(text, SL, SC, EL, EC); assert sp, "gitleaks loc unmappable"
            extra.append({"start": sp[0], "end": sp[1], "detector": "gitleaks", "family": rule})
        clean, recs = S.sanitize_text(text, extra=extra, prov="fixture|deadbeef|conf.py")
        open(f"{outdir}/rcc-proof.py", "w").write(clean)
        json.dump([{k: v for k, v in r.items()} for r in recs], open(f"{outdir}/candidates.json", "w"))
        # sweep EVERYTHING: outputs, whole scratch tempdir (leftover reports), env
        fails = 0
        blobs = {}
        for dp, _, fn in os.walk(scratch):
            for f in fn:
                p = os.path.join(dp, f)
                if os.path.samefile(os.path.dirname(p), repo) if os.path.isdir(repo) else False: continue
                if p.startswith(repo): continue   # the planted fixture itself
                try: blobs[p] = open(p, errors="replace").read()
                except Exception: pass
        for name, val in SENT.items():
            hits = [p for p, b in blobs.items() if val in b]
            print(("PASS  " if not hits else "FAIL  ") + f"sentinel absent outside fixture: {name}"
                  + ("" if not hits else f"  <- {hits}"))
            fails += bool(hits)
        got = {r["detector"] for r in recs}
        gl_ok = "gitleaks" in got or bool(extra)   # gitleaks located something (even if dedup kept another detector's span)
        print(("PASS  " if gl_ok else "FAIL  ") + f"gitleaks contributed locations "
              f"(gitleaks_spans={len(extra)}, record_detectors={sorted(got)})")
        if not gl_ok:
            # SAFE diagnostics only: version + rule ids + counts. NEVER Secret/Match.
            v = subprocess.run(["gitleaks", "version"], capture_output=True, text=True, timeout=30)
            print(f"   diag: gitleaks version = {(v.stdout or v.stderr).strip().splitlines()[:1]}")
            print(f"   diag: findings for fixture file = {len((gl or {}).get(os.path.abspath(f'{repo}/conf.py'), []))}")
            print(f"   diag: all report files = {[os.path.relpath(k, repo) for k in (gl or {})]}")
            print(f"   diag: rule ids = {[t[4] for v2 in (gl or {}).values() for t in v2]}")
        fails += (not gl_ok)
        print(("PASS  " if all(v not in clean for v in SENT.values()) else "FAIL  ") + "sanitized output value-free")
        fails += any(v in clean for v in SENT.values())
        if fails: print("GATE CLOSED — do not harvest."); sys.exit(1)
        print("REAL-GITLEAKS SENTINEL PROOF PASS — harvest path safe on this machine.")
    finally:
        tempfile.tempdir = None
        if old_tmp is None: os.environ.pop("TMPDIR", None)
        else: os.environ["TMPDIR"] = old_tmp
        shutil.rmtree(scratch, ignore_errors=True)

def main():
    ap = argparse.ArgumentParser(); sub = ap.add_subparsers(dest="cmd")
    h = sub.add_parser("harvest"); h.add_argument("--per-repo-cap", type=int, default=40)
    h.add_argument("--max-candidates", type=int, default=1200)
    p = sub.add_parser("packets"); p.add_argument("--dup-rate", type=float, default=0.12)
    fl = sub.add_parser("freeze-labels"); fl.add_argument("--labels", required=True)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test: self_test(); return
    if a.cmd == "harvest": harvest(a.per_repo_cap, a.max_candidates)
    elif a.cmd == "packets": packets(a.dup_rate)
    elif a.cmd == "freeze-labels": freeze_labels(a.labels)
    else: ap.print_help()

if __name__ == "__main__": main()

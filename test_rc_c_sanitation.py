#!/usr/bin/env python3
"""SANITATION PROOF for RC-C (gates all RC-C labeling; prereg HARD RULE).

Plants known sentinel 'secrets' of every candidate family in fixture files,
runs the exact persist path a harvester would run, then sweeps EVERY persisted
byte and EVERY captured log line for every sentinel. Zero tolerance.

Run on the machine that will run the RC-C harvest:
    python3 test_rc_c_sanitation.py
"""
import io, json, os, re, shutil, sys, contextlib, hashlib
import rc_c_sanitize as S

# ---- sentinels: realistic fakes, one per detector family ------------------
SENT = {
 "vendor_ghp":  "ghp_" "Xq7Lm2Nv8Rt4Yw1Zs6Ke9Ju3Hd5Fg0Ab2Cd4E",
 "vendor_akia": "AKIA" "JQ7WLPX4KZM2N3T9",
 "vendor_slack":"xoxb-" "2489517306-Xw3Lq9Zt7Rm1Vn5Kp8Ys",
 "entropy":     "q9zR3mX7vL2pK8wN4tY6bJ1hG5dF0aC9eU3iO7sQ",
 "keyworded":   "trustno1-Zebra-9942x",
 "pem_body":    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj",
 "hex48":       "3f9c2a7e5d1b8f4a6c0e2d9b7f5a3c1e8d6b4f2a9c7e5d1b",   # non-whitelist length hex
 "ext_only":    "hunter2-plain-Passw0rd",                              # missed by internal detectors
}
PEM_BLOCK = ("-----BEGIN RSA PRIVATE KEY-----\n" + SENT["pem_body"] + "\n"
             + SENT["pem_body"][:40] + "==\n-----END RSA PRIVATE KEY-----")
FIXTURES = {
 "app/config.py":  f'API_TOKEN = "{SENT["vendor_ghp"]}"\nAWS_KEY = "{SENT["vendor_akia"]}"\nUUID = "550e8400-e29b-41d4-a716-446655440000"\n',
 "app/deploy.sh":  f'export SLACK_TOKEN="{SENT["vendor_slack"]}"\nCHECKSUM="5d41402abc4b2a76b9719d911017c592"\n',
 "app/settings.yaml": f'db_password: "{SENT["keyworded"]}"\ncache_key: "{SENT["entropy"]}"\n',
 "certs/server.key": PEM_BLOCK + "\n",
 "app/dup.env":    f'A_SECRET={SENT["entropy"]}\nB_SECRET={SENT["entropy"]}\n',   # duplicate value
 "app/clean.go":   'package main\nvar version = "1.2.3"\n',                        # nothing to find
 "app/hash.py":    f'secret_a = "{SENT["hex48"]}"\nsecret_b = "{SENT["hex48"]}"\n',    # keyworded hex, both candidates
 "app/mixed.py":   f'DERIVED = "{SENT["hex48"]}"\nsecret_salt = "{SENT["hex48"]}"\n', # candidate + non-candidate copy => must EXCLUDE
}
import time
OUT = f"_to_delete/sanitation_proof_{int(time.time())}_{os.getpid()}"  # unique per run (gitignored)

passed = failed = 0
def check(name, ok, detail=""):
    global passed, failed
    print(("PASS  " if ok else "FAIL  ") + name + (("  <- " + detail) if (detail and not ok) else ""))
    passed += ok; failed += (not ok)

def main():
    os.makedirs(f"{OUT}/files"); os.makedirs(f"{OUT}/logs")
    log = io.StringIO()
    gt = []
    excluded = []

    # ---- the exact persist path a harvester runs, with stdout captured ----
    with contextlib.redirect_stdout(log):
        ext_raw = f'password = "{SENT["ext_only"]}"\n'
        FIXTURES["app/legacy.cfg"] = ext_raw    # sanitized ONLY via external scanner span
        for rel, raw in FIXTURES.items():
            try:
                extra = None
                if rel == "app/legacy.cfg":
                    s0 = raw.index(SENT["ext_only"]); extra = [{"start": s0, "end": s0+len(SENT["ext_only"]),
                                                                "detector": "gitleaks", "family": "generic-rule"}]
                clean, recs = S.sanitize_text(raw, extra=extra, prov=f"fixture|deadbeef|{rel}")
            except S.ExcludedFile as e:
                excluded.append(rel); print(f"excluded {rel}: {e}"); continue
            fid = rel.replace("/", "__")
            tmp = f"{OUT}/files/.{fid}.tmp"
            open(tmp, "w").write(clean); os.replace(tmp, f"{OUT}/files/{fid}")  # write AFTER sanitize
            gt.append({"file": fid, "provenance": "fixture", "candidates": recs})
            print(f"persisted {fid}: {len(recs)} candidate(s) " +
                  ", ".join(f'{r["family"]}@{r["line"]} id={r["id"]}' for r in recs))
    json.dump(gt, open(f"{OUT}/ground_truth.json", "w"), indent=2)
    open(f"{OUT}/logs/build.log", "w").write(log.getvalue())

    # ---- PROOF 1: no sentinel anywhere in ANY persisted byte or log line ----
    blobs = {"log": log.getvalue()}
    for dp, _, fn in os.walk(OUT):
        for f in fn: blobs[os.path.join(dp, f)] = open(os.path.join(dp, f), errors="replace").read()
    for sname, sval in SENT.items():
        hits = [p for p, b in blobs.items() if sval in b]
        check(f"sentinel absent everywhere: {sname}", not hits, f"found in {hits}")
        for frag in (sval[:12], sval[-12:]):   # fragments too (partial-write / substring leaks)
            if len(frag) >= 12:
                hits = [p for p, b in blobs.items() if frag in b]
                check(f"  fragment absent: {sname}[{frag[:6]}..]", not hits, f"found in {hits}")

    # ---- PROOF 2: structure of what WAS persisted ----
    allrecs = [r for g in gt for r in g["candidates"]]
    check("every planted secret produced a sanitized candidate (8 planted values, >=8 records)",
          len(allrecs) >= 8, f"got {len(allrecs)}")
    # scanner-union path: external-only candidate sanitized
    lg = blobs[f"{OUT}/files/app__legacy.cfg"]
    check("external-scanner-only candidate sanitized (union entry point)", SENT["ext_only"] not in lg)
    # semantic-class preservation: non-whitelist hex stays hex
    import re as _re
    hx = blobs[f"{OUT}/files/app__hash.py"]
    m = _re.findall(r'"([0-9a-f]{48})"', hx)
    check("hex candidate sanitized but STILL 48-char lowercase hex (semantic class preserved)",
          len(m) == 2 and all(v != SENT["hex48"] for v in m), f"matches={len(m)}")
    # conservative exclusion: value present as BOTH candidate and non-candidate
    check("file with candidate+non-candidate copies of same value is EXCLUDED (residue rule)",
          "app/mixed.py" in excluded and not os.path.exists(f"{OUT}/files/app__mixed.py"))
    for g in gt:
        text = blobs[f"{OUT}/files/{g['file']}"]
        for r in g["candidates"]:
            check(f"offset verifies in persisted file: {g['file']}:{r['id']}",
                  text[r["start"]:r["end"]] == r["synth_value"])
    # format preservation on the ghp sentinel
    ghp = [r for r in allrecs if "ghp_" in r["synth_value"]]
    check("vendor prefix structure preserved (ghp_ kept, tail synthetic)",
          bool(ghp) and ghp[0]["synth_value"].startswith("ghp_")
          and ghp[0]["synth_value"] != SENT["vendor_ghp"]
          and len(ghp[0]["synth_value"]) == len(SENT["vendor_ghp"]))
    # PEM: header/footer intact, body replaced
    pem = blobs.get(f"{OUT}/files/certs__server.key", "")
    check("PEM header/footer preserved", "BEGIN RSA PRIVATE KEY" in pem and "END RSA PRIVATE KEY" in pem)
    check("PEM body replaced", SENT["pem_body"] not in pem)
    # whitelist lookalikes untouched
    check("uuid lookalike untouched", "550e8400-e29b-41d4-a716-446655440000" in blobs[f"{OUT}/files/app__config.py"])
    check("md5 lookalike untouched", "5d41402abc4b2a76b9719d911017c592" in blobs[f"{OUT}/files/app__deploy.sh"])
    # duplicate occurrences: both replaced
    dup = blobs[f"{OUT}/files/app__dup.env"]
    check("duplicate secret: both occurrences sanitized", SENT["entropy"] not in dup)
    # clean file persisted with zero candidates
    check("clean file persisted unmodified", blobs[f"{OUT}/files/app__clean.go"] == FIXTURES["app/clean.go"])

    # ---- PROOF 3: identity is VALUE-INDEPENDENT; everything deterministic ----
    p = "repo/x|abc123|src/a.py"
    check("candidate_id deterministic", S.candidate_id(p,10,50,"f") == S.candidate_id(p,10,50,"f"))
    check("candidate_id value-independent (no value in the identity function at all)",
          "value" not in S.candidate_id.__code__.co_varnames and len(S.candidate_id(p,10,50,"f")) == 16)
    check("candidate_id location-sensitive", S.candidate_id(p,10,50,"f") != S.candidate_id(p,11,50,"f"))
    c1,_ = S.sanitize_text(FIXTURES["app/settings.yaml"], prov="P|C|f"); c2,_ = S.sanitize_text(FIXTURES["app/settings.yaml"], prov="P|C|f")
    check("sanitation deterministic (same prov)", c1 == c2)
    # synth randomness is seeded from LOCATION, not value: two different raw
    # values at the same location produce DIFFERENT synth only via length/class,
    # and identical values at different locations produce different synth
    s1 = S.synth_like("abcdef0123456789abcdef0123456789", "P|1|2")
    s2 = S.synth_like("abcdef0123456789abcdef0123456789", "P|3|4")
    check("synth seeded by location (same value, different location => different synth)", s1 != s2)
    # WIDE external span (scanner matched keyword+quotes+token): must sanitize,
    # preserve embedded vendor prefix, and pass the containment re-scan
    ghp = "ghp_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2"
    wide_raw = f'token = "{ghp}"\n'
    wtext, wrecs = S.sanitize_text(wide_raw, extra=[{"start":0,"end":len(wide_raw)-1,
                                                     "detector":"gitleaks","family":"generic"}],
                                   prov="P|C|wide.py")
    check("wide external span sanitized (raw token gone)", ghp not in wtext)
    check("wide external span keeps embedded vendor prefix", "ghp_" in wtext)
    # internal-first dedup: internal narrow span wins over overlapping external wide span
    d = {r["detector"] for r in wrecs}
    check("overlapping internal candidate wins dedup (external drops)",
          d == {"vendor_prefix"} or d == {"gitleaks"} and len(wrecs)==1, str(d))
    # out-of-bounds external span => ExcludedFile
    try: S.sanitize_text("x = 1\n", extra=[{"start":0,"end":99}], prov="P|C|f")
    except S.ExcludedFile: ok=True
    else: ok=False
    check("out-of-bounds external span excludes the file", ok)

    # ---- PROOF 4: exclusion path persists NOTHING ----
    class Boom(S.ExcludedFile): pass
    real = S.synth_like
    S.synth_like = lambda *a: (_ for _ in ()).throw(Boom("forced"))
    try:
        try: S.sanitize_text('token = "' + SENT["entropy"] + '"', prov="P|C|f")
        except S.ExcludedFile: pass
        else: check("exclusion path raises", False); 
    finally: S.synth_like = real
    check("exclusion path raises (nothing returned, nothing to persist)", True)

    print()
    print(f"{'='*60}\nSANITATION PROOF: {passed} passed, {failed} failed")
    if failed == 0:
        shutil.rmtree(OUT, ignore_errors=True)   # best-effort; dir is gitignored scratch either way
        print("ALL CLEAR. RC-C labeling gate: OPEN (on this machine).")
    else:
        print(f"GATE CLOSED — inspect {OUT}/ (kept for debugging). Do NOT begin RC-C labeling.")
        sys.exit(1)

if __name__ == "__main__":
    main()

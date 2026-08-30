#!/usr/bin/env python3
"""SecMask RealCode-1 / RC-C sanitation core (prereg HARD RULE implementation).

Contract (PREREG_SECMASK_REALCODE1.md):
  A raw candidate credential VALUE must NEVER be persisted to disk, logs,
  reports, caches, or manifests. GitHub response -> candidate detected ->
  EPHEMERAL classify/sanitize -> ONLY the sanitized representation is written.
  Persist only: non-reversible candidate id, provenance, surrounding real code
  context, family/lookalike_category, and the format-preserving SYNTHETIC
  replacement. Prefer AMBIGUOUS/EXCLUDED over persisting anything live.

This module is PURE (no I/O except reading): every function returns data;
callers decide what to write, and MUST only write SanitizedWindow.text.
The proof suite (test_rc_c_sanitation.py) is the gate: RC-C labeling may not
begin until it passes on the machine that will run the harvest.
"""
import hashlib, math, re, collections
import rc_build   # single source of truth for whitelist lookalikes
LK = rc_build.LK
line_starts = rc_build.line_starts
line_of = rc_build.line_of

SCHEME = "SECMASK-RCC-v1"

# ---------- credential-candidate detectors (NEVER our model) ----------
VENDOR = re.compile(r'\b(?:ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|'
                    r'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|'
                    r'sk-[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_\-]{20,}|AIza[0-9A-Za-z_\-]{35})')
GENERIC = re.compile(r'[A-Za-z0-9+/=_\-.]{12,}')
PEM_PRIV = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', re.S)
ASSIGN_CTX = re.compile(r'(secret|passw|token|apikey|api_key|credential|auth)', re.I)
_KW = '(?:secret|passw|pwd|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credential|bearer|auth)[a-z0-9_]*'
KV = re.compile('(?:secret|passw|pwd|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credential|bearer|auth)[a-z0-9_]*\\s*["\'`\\]]?\\s*(?::=|=(?!=)|[:>])\\s*["\'`{]?\\s*([A-Za-z0-9+/=_\\-]{6,})(?![\\w.]*\\()', re.I)

def shannon(s):
    if not s: return 0.0
    c = collections.Counter(s); n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def _covered(s, e, spans):
    return any(a <= s and e <= b for a, b in spans)

def find_candidates(text):
    """Credential-like spans in RAW text. Returns list of
    {start,end,detector,family} sorted, non-overlapping. Whitelist lookalikes
    (rc_build.LK) are NOT candidates — they are structurally-certain non-secrets."""
    lk_spans = [(d["start"], d["end"]) for d in rc_build.lookalikes(text)]
    out, taken = [], []
    def add(s, e, det, fam):
        if _covered(s, e, lk_spans): return
        if any(not (e <= a or s >= b) for a, b in taken): return
        taken.append((s, e)); out.append({"start": s, "end": e, "detector": det, "family": fam})
    for m in PEM_PRIV.finditer(text): add(*m.span(), "pem_private", "private_key")
    for m in VENDOR.finditer(text):   add(*m.span(), "vendor_prefix", "vendor_token")
    # (1) keyworded assignment / tag: capture the VALUE group only (the key is
    #     consumed by the regex, so KEY=VALUE never swallows the key). Skips
    #     comparisons (==), function-call RHS, and keyword substrings in names.
    for m in KV.finditer(text):
        s, e = m.span(1); v = m.group(1)
        if _covered(s, e, lk_spans): continue
        if "/" in v or v.count(".") >= 2: continue
        if shannon(v) >= 3.0 and len(v) >= 8:
            add(s, e, "entropy", "keyworded_generic")
    # (2) non-keyworded: ONLY a strong high-entropy STRING LITERAL (quoted),
    #     never a bare code identifier / import / call token.
    for m in GENERIC.finditer(text):
        s, e = m.span(); v = m.group()
        if _covered(s, e, lk_spans): continue
        if any(not (e <= a or s >= b) for a, b in taken): continue   # already taken
        if "/" in v or v.count(".") >= 2: continue
        prevch = text[s-1] if s > 0 else ""
        if prevch in ('"', "'", "`") and shannon(v) >= 4.5 and len(v) >= 24:
            add(s, e, "entropy", "generic_high_entropy")
    return sorted(out, key=lambda d: d["start"])

# ---------- identity & synthetic replacement ----------
def candidate_id(prov, start, end, family):
    """Value-INDEPENDENT deterministic id. Identity = location + class
    (prov string 'repo|commit|path' + char span + family). NEVER a function
    of the credential bytes — no pepper needed, nothing to leak, and the
    repo/commit/path -> id mapping is exactly reproducible."""
    return hashlib.sha256(f"{SCHEME}|{prov}|{start}|{end}|{family}".encode()).hexdigest()[:16]

def _rng_stream(seedkey):
    """Deterministic byte stream seeded from a LOCATION key (never the value)."""
    seed = hashlib.sha256((SCHEME + "|synth|" + seedkey).encode()).digest()
    while True:
        for b in seed: yield b
        seed = hashlib.sha256(seed).digest()

HEX_LO = re.compile(r'^[0-9a-f]+$'); HEX_UP = re.compile(r'^[0-9A-F]+$'); DIGITS = re.compile(r'^[0-9]+$')
def synth_like(value, seedkey):
    """Semantic-class-preserving synthetic value (same length):
    - all-hex stays hex (same case), all-digit stays digits — a hash-like
      original must still read as the same NEGATIVE class after sanitation;
    - otherwise per-character class-preserving (A-Z->A-Z, a-z->a-z, 0-9->0-9,
      separators/symbols verbatim), which keeps token/base64 shapes."""
    g = _rng_stream(seedkey); out=[]
    if   len(value) >= 8 and HEX_LO.match(value): alpha="0123456789abcdef"
    elif len(value) >= 8 and HEX_UP.match(value): alpha="0123456789ABCDEF"
    elif len(value) >= 4 and DIGITS.match(value): alpha="0123456789"
    else: alpha=None
    if alpha is not None:
        s = "".join(alpha[next(g) % len(alpha)] for _ in value)
        assert len(s) == len(value)
        return s
    UP="ABCDEFGHIJKLMNOPQRSTUVWXYZ"; LO=UP.lower(); DG="0123456789"
    for ch in value:
        if   ch in UP: out.append(UP[next(g) % 26])
        elif ch in LO: out.append(LO[next(g) % 26])
        elif ch in DG: out.append(DG[next(g) % 10])
        else: out.append(ch)
    s = "".join(out)
    assert len(s) == len(value)
    return s

def synth_pem(value, seedkey):
    """Replace PEM body lines with synthetic base64 of identical line lengths;
    header/footer kept."""
    B64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    g=_rng_stream(seedkey); lines=value.split("\n"); out=[]
    for ln in lines:
        if ln.startswith("-----") or not ln.strip(): out.append(ln)
        else:
            core = "".join(B64[next(g) % 64] for _ in range(max(0, len(ln.rstrip("=")))))
            out.append(core + "=" * (len(ln) - len(ln.rstrip("="))))
    s="\n".join(out)
    assert len(s)==len(value)
    return s

KNOWN_PREFIX = re.compile(r'^(ghp_|gho_|github_pat_|AKIA|ASIA|xox[baprs]-|sk-|glpat-|AIza)')
def synth_vendor(value, seedkey):
    """Keep the PUBLIC vendor prefix (format information, not secret);
    synthesize only the credential tail."""
    m = KNOWN_PREFIX.match(value)
    if not m: return synth_like(value, seedkey)
    p = m.group(1)
    return p + synth_like(value[len(p):], seedkey)

PREFIX_ANY = re.compile(r'(ghp_|gho_|github_pat_|AKIA|ASIA|xox[baprs]-|sk-|glpat-|AIza)')
def synth_external(value, seedkey):
    """External-scanner spans can be WIDER than the credential (keyword, quotes,
    assignment). Preserve embedded PUBLIC vendor prefixes (format info), synth
    the rest per character class."""
    keep = [(m.start(), m.end()) for m in PREFIX_ANY.finditer(value)]
    body = synth_like(value, seedkey)
    out = list(body)
    for a, b in keep: out[a:b] = value[a:b]
    s = "".join(out)
    assert len(s) == len(value)
    return s

class ExcludedFile(Exception):
    """Raised when a file cannot be sanitized with certainty; caller must
    persist NOTHING from it (prefer AMBIGUOUS/EXCLUDED over storing live)."""

def sanitize_text(text, extra=None, prov="fixture"):
    """EPHEMERAL sanitation of a raw text. Returns (sanitized_text, records).
    `extra`: candidate spans from EXTERNAL scanners (e.g. gitleaks --redact
    locations) as {start,end,detector,family} — the scanner-union entry point;
    external scanners contribute LOCATIONS ONLY, never values. `prov` is the
    'repo|commit|path' identity string used for ids and synth seeding (both
    value-independent). Offsets are valid in BOTH raw and sanitized text
    (replacement is length-preserving). Raises ExcludedFile on any doubt."""
    cands = list(find_candidates(text))
    for c in (extra or []):
        s0, e0 = c["start"], c["end"]
        if not (0 <= s0 < e0 <= len(text)):
            raise ExcludedFile("external span out of bounds")
        cands.append({"start": s0, "end": e0, "external": True,
                      "detector": c.get("detector", "external"),
                      "family": c.get("family", "external_candidate")})
    # deterministic union dedup, INTERNAL detectors first: they carry precise,
    # format-aware spans; external scanners contribute only locations internal
    # detection missed (an external span overlapping an internal one is dropped)
    internal = [c for c in cands if c["detector"] != "gitleaks" and not c.get("external")]
    external = [c for c in cands if c not in internal]
    internal.sort(key=lambda c: (c["start"], c["end"], c["detector"]))
    external.sort(key=lambda c: (c["start"], c["end"], c["detector"]))
    merged, taken = [], []
    for c in internal + external:
        if any(not (c["end"] <= a or c["start"] >= b) for a, b in taken): continue
        taken.append((c["start"], c["end"])); merged.append(c)
    cands = sorted(merged, key=lambda c: c["start"])
    out = text; records = []
    for c in cands:
        raw = text[c["start"]:c["end"]]
        seedkey = f"{prov}|{c['start']}|{c['end']}"
        if   c["detector"]=="pem_private" or PEM_PRIV.search(raw):
            synth = synth_pem(raw, seedkey)
        elif c["detector"]=="vendor_prefix":
            synth = synth_vendor(raw, seedkey)
        elif c.get("external"):
            synth = synth_external(raw, seedkey)
        else:
            synth = synth_like(raw, seedkey)
        if len(synth) != len(raw) or synth == raw:
            raise ExcludedFile("un-sanitizable candidate")
        out = out[:c["start"]] + synth + out[c["end"]:]
        records.append({"id": candidate_id(prov, c["start"], c["end"], c["family"]),
                        "start": c["start"], "end": c["end"],
                        "line": line_of(line_starts(text), c["start"]),
                        "detector": c["detector"], "family": c["family"],
                        "synth_value": synth})
    # verification gate on the FINAL text
    for r in records:
        if out[r["start"]:r["end"]] != r["synth_value"]:
            raise ExcludedFile("offset verify failed")
    for c, r in zip(cands, records):
        raw = text[c["start"]:c["end"]]
        core = max(re.findall(r'[A-Za-z0-9+/=_\-.]{8,}', raw), key=len, default=raw)
        if len(core) >= 8 and core in out:
            raise ExcludedFile("raw residue in sanitized text")
    # re-scan: sanitized text must contain no NEW un-accounted candidates.
    # A candidate fully CONTAINED in a sanitized span is our own synthetic
    # material (e.g. the token inside a wider external span) — accounted for.
    resc = find_candidates(out)
    for c in resc:
        if not any(r["start"] <= c["start"] and c["end"] <= r["end"] for r in records):
            raise ExcludedFile("unaccounted candidate after sanitation")
    return out, records

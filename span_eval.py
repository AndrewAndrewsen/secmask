#!/usr/bin/env python3
"""
Reusable character-span evaluator (plan sections 9/15, amendment A9).

Input format (gold and predictions): JSONL, one document per row:

    {"id": "test-000123",
     "spans": [{"start": 10, "end": 30, "line": 1, "value": "...",
                "score": 0.98}]}

"score" is predictions-only and optional. "line" is 1-based and
optional; when present on both sides it feeds line accuracy and the
strict (exact span + line) metric. Documents present only in gold are
scored as all-FN; documents present only in predictions as all-FP.

Matching is ONE-TO-ONE everywhere (a prediction can satisfy at most
one gold span and vice versa):

  exact   : pred.start == gold.start and pred.end == gold.end
  strict  : exact AND pred.line == gold.line   (strict value+line criterion)
  overlap : spans intersect; greedy matching by descending overlap
            length (diagnostic only, never a substitute for exact)

Reported metrics:
  exact / strict / overlap precision, recall, F1
  file-level (has-secret) precision, recall, F1
  line accuracy over exact-span matches
  gold/pred entity counts + inflation ratio
  fragmentation: distribution of predictions overlapping each gold span
                 (counted WITHOUT one-to-one, to expose splitting),
                 pct of gold spans covered by >1 prediction

CLI:
  python3 span_eval.py --gold gold.jsonl --pred pred.jsonl \
      --out reports/metrics.json [--name cfg-label]
"""
import argparse
import json
from collections import Counter, defaultdict


def load_docs(path):
    docs = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            docs[r["id"]] = r.get("spans", [])
    return docs


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(f1, 4)}


def match_exact(preds, golds, require_line=False):
    """One-to-one exact matching. Returns (n_matched, line_correct)."""
    unused = list(range(len(golds)))
    matched = 0
    line_correct = 0
    for p in preds:
        hit = None
        for k, gi in enumerate(unused):
            g = golds[gi]
            if p["start"] == g["start"] and p["end"] == g["end"]:
                if require_line and p.get("line") != g.get("line"):
                    continue
                hit = k
                break
        if hit is not None:
            gi = unused.pop(hit)
            matched += 1
            if (p.get("line") is not None
                    and p.get("line") == golds[gi].get("line")):
                line_correct += 1
    return matched, line_correct


def match_overlap(preds, golds):
    """Greedy one-to-one matching by descending overlap length."""
    pairs = []
    for pi, p in enumerate(preds):
        for gi, g in enumerate(golds):
            ov = min(p["end"], g["end"]) - max(p["start"], g["start"])
            if ov > 0:
                pairs.append((ov, pi, gi))
    pairs.sort(key=lambda x: (-x[0], x[1], x[2]))
    used_p, used_g = set(), set()
    matched = 0
    for ov, pi, gi in pairs:
        if pi in used_p or gi in used_g:
            continue
        used_p.add(pi)
        used_g.add(gi)
        matched += 1
    return matched


def evaluate(gold_docs, pred_docs):
    ids = sorted(set(gold_docs) | set(pred_docs))
    tot = {k: Counter() for k in ("exact", "strict", "overlap", "file")}
    n_gold = n_pred = 0
    line_correct_total = 0
    frag_hist = Counter()
    frag_gt_multi = 0
    gt_with_overlap = 0

    for did in ids:
        golds = gold_docs.get(did, [])
        preds = pred_docs.get(did, [])
        n_gold += len(golds)
        n_pred += len(preds)

        m_exact, line_ok = match_exact(preds, golds, require_line=False)
        m_strict, _ = match_exact(preds, golds, require_line=True)
        m_over = match_overlap(preds, golds)
        line_correct_total += line_ok

        for key, m in (("exact", m_exact), ("strict", m_strict),
                       ("overlap", m_over)):
            tot[key]["tp"] += m
            tot[key]["fp"] += len(preds) - m
            tot[key]["fn"] += len(golds) - m

        # file-level
        g_has, p_has = bool(golds), bool(preds)
        if g_has and p_has:
            tot["file"]["tp"] += 1
        elif not g_has and p_has:
            tot["file"]["fp"] += 1
        elif g_has and not p_has:
            tot["file"]["fn"] += 1
        else:
            tot["file"]["tn"] += 1

        # fragmentation: per gold span, count ALL overlapping predictions
        for g in golds:
            n_ov = sum(1 for p in preds
                       if min(p["end"], g["end"]) > max(p["start"], g["start"]))
            frag_hist[n_ov] += 1
            if n_ov >= 1:
                gt_with_overlap += 1
            if n_ov > 1:
                frag_gt_multi += 1

    exact_tp = tot["exact"]["tp"]
    result = {
        "documents": len(ids),
        "gold_spans": n_gold,
        "pred_spans": n_pred,
        "inflation_ratio": round(n_pred / n_gold, 4) if n_gold else None,
        "exact": prf(tot["exact"]["tp"], tot["exact"]["fp"], tot["exact"]["fn"]),
        "strict_span_and_line": prf(tot["strict"]["tp"], tot["strict"]["fp"],
                                    tot["strict"]["fn"]),
        "overlap": prf(tot["overlap"]["tp"], tot["overlap"]["fp"],
                       tot["overlap"]["fn"]),
        "file_level": dict(prf(tot["file"]["tp"], tot["file"]["fp"],
                               tot["file"]["fn"]),
                           tn=tot["file"]["tn"]),
        "line_accuracy_on_exact_matches":
            round(line_correct_total / exact_tp, 4) if exact_tp else None,
        "fragmentation": {
            "gold_spans_with_multiple_overlapping_preds": frag_gt_multi,
            "pct_fragmented":
                round(100 * frag_gt_multi / n_gold, 2) if n_gold else None,
            "gold_spans_with_any_overlap": gt_with_overlap,
            "overlapping_preds_per_gold_hist":
                {str(k): v for k, v in sorted(frag_hist.items())},
        },
    }
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gold", required=True)
    ap.add_argument("--pred", required=True)
    ap.add_argument("--out")
    ap.add_argument("--name", default=None, help="configuration label")
    args = ap.parse_args()

    res = evaluate(load_docs(args.gold), load_docs(args.pred))
    if args.name:
        res = {"name": args.name, **res}
    print(json.dumps(res, indent=2))
    if args.out:
        import os
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)


if __name__ == "__main__":
    main()

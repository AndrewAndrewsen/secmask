#!/usr/bin/env python3
"""
v3 recommended span-based inference path (revision-2 amendment A5).

Contract:
  raw text -> fast tokenizer with offset_mapping (never re-tokenized,
  never pre-split) -> per-WordPiece BIO decode -> character spans in the
  ORIGINAL text -> optional masking by span replacement on the original.

No " ".join reconstruction, no first-WordPiece heuristic, no
simple_tokenize. Long inputs are handled with overflowing windows; a
character position seen in more than one window keeps its first
window's prediction.

Modes (amendment A6):
  argmax     -- reference mode: plain argmax BIO decoding, no threshold.
                This is how the published model must behave.
  threshold  -- additional mode: entities are kept only when their span
                confidence (mean over entity WordPieces of P(B)+P(I))
                is >= --tau. tau must be chosen on validation data only.

Entity decoding uses lenient BIO (an I with no open entity opens one);
invalid transitions are counted and reported per document.

CLI (resumable; safe to drive in short slices):
  python3 span_infer.py --model outputs/distilbert-secret-masker-v3/best \
      --in-jsonl data/v3_test.jsonl --out reports/preds_v3_test.jsonl \
      --mode argmax [--start 0 --limit 100]
  python3 span_infer.py --model ... --text "AWS key AKIA..." [--mask]

Output rows: {"id", "spans": [{"start","end","line","value","score"}],
              "invalid_bio_transitions": int}
"""
import argparse
import json
import os
import sys

import torch
import torch.nn.functional as F
from transformers import AutoModelForTokenClassification, AutoTokenizer

ID2LABEL_FALLBACK = {0: "O", 1: "B-SECRET", 2: "I-SECRET"}


def load_model(model_dir, device="cpu"):
    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    assert tokenizer.is_fast, "fast tokenizer required for offset_mapping"
    model = AutoModelForTokenClassification.from_pretrained(model_dir)
    model.to(device).eval()
    id2label = {int(k): v for k, v in model.config.id2label.items()} \
        if model.config.id2label else ID2LABEL_FALLBACK
    return tokenizer, model, id2label


# Diagnostic: largest per-window sequence length actually sent to a model
# forward in this process. With correct manual windowing this MUST stay
# <= max_length (512). The assert in predict_pieces enforces it and makes
# the benign "Token indices sequence length is longer than 512" warning
# (emitted by the initial *untruncated* tokenize call, not the forward)
# unambiguous — the forward never sees >512.
MAX_FORWARD_TOKENS = 0


@torch.no_grad()
def predict_pieces(text, tokenizer, model, max_length=512, stride=128,
                   device="cpu", batch_size=8):
    """Run the model over raw text. Returns a list of
    (char_start, char_end, label_id, p_secret) per WordPiece, first
    window wins for duplicated positions.

    Windowing is done MANUALLY: tokenize once without truncation, then
    slice into (max_length - 2)-piece windows with `stride` overlap and
    add [CLS]/[SEP] per window. The tokenizer's own
    return_overflowing_tokens is NOT used -- in transformers 5.x it was
    observed to stop chaining after two windows, silently dropping
    everything beyond ~the first window (root cause of the apparent
    "continuation window" recall loss in early v3 evaluation)."""
    global MAX_FORWARD_TOKENS
    full = tokenizer(text, add_special_tokens=False,
                     return_offsets_mapping=True)
    ids = full["input_ids"]
    offs = full["offset_mapping"]
    n = len(ids)
    body = max_length - 2
    step = max(1, body - stride)
    starts = list(range(0, max(n, 1), step))
    # drop windows fully covered by the previous one
    windows = []
    for w0 in starts:
        w1 = min(w0 + body, n)
        windows.append((w0, w1))
        if w1 >= n:
            break

    cls_id, sep_id = tokenizer.cls_token_id, tokenizer.sep_token_id
    pieces = []
    seen = set()
    for b0 in range(0, len(windows), batch_size):
        batch = windows[b0:b0 + batch_size]
        maxlen = max(w1 - w0 for w0, w1 in batch) + 2
        input_ids = []
        attn = []
        for w0, w1 in batch:
            row = [cls_id] + ids[w0:w1] + [sep_id]
            pad = maxlen - len(row)
            input_ids.append(row + [tokenizer.pad_token_id] * pad)
            attn.append([1] * len(row) + [0] * pad)
        assert maxlen <= max_length, (
            f"window seq_len {maxlen} exceeds model max_length {max_length} "
            f"- manual windowing is broken")
        MAX_FORWARD_TOKENS = max(MAX_FORWARD_TOKENS, maxlen)
        logits = model(
            input_ids=torch.tensor(input_ids).to(device),
            attention_mask=torch.tensor(attn).to(device),
        ).logits
        probs = F.softmax(logits, dim=-1).cpu()
        for wi, (w0, w1) in enumerate(batch):
            for k in range(w1 - w0):
                s, e = offs[w0 + k]
                if s == e or (s, e) in seen:
                    continue
                seen.add((s, e))
                p = probs[wi, k + 1]      # +1 skips [CLS]
                label_id = int(p.argmax())
                pieces.append((s, e, label_id, float(p[1] + p[2])))
    pieces.sort(key=lambda x: (x[0], x[1]))
    return pieces


def decode_entities(pieces, id2label):
    """Lenient BIO decode over sorted pieces -> (entities, invalid_transitions).
    Each entity: dict(start, end, piece_scores=[...])."""
    entities = []
    invalid = 0
    cur = None
    prev_label = "O"
    for (s, e, lid, p_secret) in pieces:
        label = id2label.get(lid, "O")
        if label == "B-SECRET":
            if cur is not None:
                entities.append(cur)
            cur = {"start": s, "end": e, "piece_scores": [p_secret]}
        elif label == "I-SECRET":
            if cur is None:
                invalid += 1
                cur = {"start": s, "end": e, "piece_scores": [p_secret]}
            else:
                cur["end"] = e
                cur["piece_scores"].append(p_secret)
        else:
            if cur is not None:
                entities.append(cur)
                cur = None
        prev_label = label
    if cur is not None:
        entities.append(cur)
    return entities, invalid


def infer_spans(text, tokenizer, model, id2label, mode="argmax", tau=None,
                max_length=512, stride=128, device="cpu"):
    pieces = predict_pieces(text, tokenizer, model, max_length, stride, device)
    entities, invalid = decode_entities(pieces, id2label)
    spans = []
    for ent in entities:
        score = sum(ent["piece_scores"]) / len(ent["piece_scores"])
        if mode == "threshold":
            assert tau is not None, "--tau required in threshold mode"
            if score < tau:
                continue
        s, e = ent["start"], ent["end"]
        spans.append({
            "start": s,
            "end": e,
            "line": text[:s].count("\n") + 1,
            "value": text[s:e],
            "score": round(score, 6),
        })
    return spans, invalid


def mask_text(text, spans, mask_token="[SECRET]"):
    """Replace spans in the ORIGINAL text, right-to-left so offsets hold."""
    out = text
    for sp in sorted(spans, key=lambda x: x["start"], reverse=True):
        out = out[:sp["start"]] + mask_token + out[sp["end"]:]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--mode", choices=["argmax", "threshold"], default="argmax")
    ap.add_argument("--tau", type=float)
    ap.add_argument("--max-length", type=int, default=512)
    ap.add_argument("--stride", type=int, default=128)
    ap.add_argument("--device", default="cpu")
    ap.add_argument("--text")
    ap.add_argument("--mask", action="store_true")
    ap.add_argument("--in-jsonl", help="rows need 'id' and 'text'")
    ap.add_argument("--out")
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--limit", type=int, default=0, help="0 = all")
    args = ap.parse_args()

    tokenizer, model, id2label = load_model(args.model, args.device)

    if args.text is not None:
        spans, invalid = infer_spans(args.text, tokenizer, model, id2label,
                                     args.mode, args.tau,
                                     args.max_length, args.stride, args.device)
        if args.mask:
            print(mask_text(args.text, spans))
        else:
            print(json.dumps({"spans": spans,
                              "invalid_bio_transitions": invalid}, indent=2))
        return

    assert args.in_jsonl and args.out, "--in-jsonl and --out required"
    rows = []
    with open(args.in_jsonl, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    end = len(rows) if not args.limit else min(len(rows), args.start + args.limit)
    todo = rows[args.start:end]

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    open_mode = "a" if args.start > 0 else "w"
    with open(args.out, open_mode, encoding="utf-8") as f:
        for i, r in enumerate(todo):
            spans, invalid = infer_spans(r["text"], tokenizer, model, id2label,
                                         args.mode, args.tau,
                                         args.max_length, args.stride,
                                         args.device)
            f.write(json.dumps({"id": r["id"], "spans": spans,
                                "invalid_bio_transitions": invalid},
                               ensure_ascii=False) + "\n")
    print(f"wrote rows [{args.start}:{end}) -> {args.out}")


if __name__ == "__main__":
    main()

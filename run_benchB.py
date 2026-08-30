#!/usr/bin/env python3
"""Run all model configs over frozen Benchmark B, writing prediction files.
One process (background), so the 45s per-call limit doesn't apply."""
import json, os, sys, time
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

IN = "benchmark_b/inputs.jsonl"
rows = [json.loads(l) for l in open(IN) if l.strip()]
log = open("benchmark_b/run_benchB.log", "w")
def say(*a):
    print(*a, file=log, flush=True); print(*a, flush=True)

from span_infer import load_model, infer_spans
from secmask_v2_replica import predict as v2predict
from transformers import AutoTokenizer, AutoModelForTokenClassification

def run_span(model_dir, out, mode="argmax"):
    tok, m, i2l = load_model(model_dir)
    with open(out, "w") as f:
        for r in rows:
            spans, _ = infer_spans(r["text"], tok, m, i2l, mode)
            f.write(json.dumps({"id": r["id"], "spans": spans}, ensure_ascii=False) + "\n")
    say("done", out)

def run_v2secmask(model_dir, out, tau=0.80):
    tok = AutoTokenizer.from_pretrained(model_dir)
    m = AutoModelForTokenClassification.from_pretrained(model_dir); m.eval()
    with open(out, "w") as f:
        for r in rows:
            spans = v2predict(r["text"], tok, m, tau, apply_filters=False)
            f.write(json.dumps({"id": r["id"], "spans": spans}, ensure_ascii=False) + "\n")
    say("done", out)

t0 = time.time()
say("start", time.strftime("%H:%M:%S"))
run_span("outputs/distilbert-secret-masker-v3.1/best", "reports/benchB_v31_argmax.jsonl")
run_span("outputs/distilbert-secret-masker-v3/best", "reports/benchB_v3_argmax.jsonl")
run_span("models/distilbert-secret-masker-v2", "reports/benchB_v2_argmax.jsonl")
run_v2secmask("models/distilbert-secret-masker-v2", "reports/benchB_v2_secmask.jsonl")
say("ALL DONE in %.0fs" % (time.time() - t0))

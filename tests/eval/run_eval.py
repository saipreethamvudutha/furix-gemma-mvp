"""Compliance-mapping accuracy benchmark.

Runs every labeled event in gold_set.jsonl through the DETERMINISTIC resolver
(mapping.resolve) and scores predicted controls against the gold labels. Reports:

  - micro precision / recall / F1   (overall accuracy)
  - per-control table                (which controls are missed / over-fired)
  - benign false-positive rate       (do clean logs wrongly get controls?)
  - per-tier attribution             (are keyword rules or embeddings the noise?)
  - worst false-positive / false-negative events (what to fix first)

Usage:
  cd "MVP_TEST GEMMA"
  # deterministic rules + crosswalk only (embeddings off):
  MOCK_LLM=1 RAG_ENABLED=0 .venv/bin/python tests/eval/run_eval.py
  # include the embedding tier:
  MOCK_LLM=1 RAG_ENABLED=1 .venv/bin/python tests/eval/run_eval.py --rag

It writes tests/eval/last_report.json for trend tracking across tuning passes.
"""
from __future__ import annotations
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from furix_mvp import mapping, rag                       # noqa: E402
from furix_mvp.containers import c6_normaliser as c6     # noqa: E402

GOLD = Path(__file__).with_name("gold_set.jsonl")
USE_RAG = "--rag" in sys.argv or os.environ.get("RAG_ENABLED") == "1"


def _load_gold() -> list[dict]:
    return [json.loads(line) for line in GOLD.read_text().splitlines() if line.strip()]


def _ground_for(raw: str, finding: dict) -> dict:
    if not USE_RAG:
        return {"available": False}
    try:
        return rag.retrieve(raw, finding)
    except Exception as e:  # noqa: BLE001
        return {"available": False, "reason": f"rag_error:{e}"}


def main() -> None:
    gold = _load_gold()
    rows = []
    # aggregate counters
    tp = fp = fn = 0
    per_control = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    per_tier = defaultdict(lambda: {"tp": 0, "fp": 0})
    benign_total = benign_fp = 0

    for ev in gold:
        finding = c6.normalise(ev["raw"], ev.get("log_type", "auto"))
        ground = _ground_for(ev["raw"], finding)
        res = mapping.resolve(finding, ground)
        pred = set(res["control_ids"])
        truth = set(ev["controls"])
        prov = res.get("provenance", {})

        ev_tp = pred & truth
        ev_fp = pred - truth
        ev_fn = truth - pred
        tp += len(ev_tp); fp += len(ev_fp); fn += len(ev_fn)

        for c in ev_tp: per_control[c]["tp"] += 1
        for c in ev_fp: per_control[c]["fp"] += 1
        for c in ev_fn: per_control[c]["fn"] += 1

        # tier attribution: credit each predicted control to the tier(s) that found it
        for c in pred:
            tiers = prov.get(c, [res.get("primary_tier", "?")])
            for t in tiers:
                per_tier[t]["tp" if c in truth else "fp"] += 1

        if not truth:  # benign event
            benign_total += 1
            if pred:
                benign_fp += 1

        rows.append({"id": ev["id"], "gold": sorted(truth), "pred": sorted(pred),
                     "fp": sorted(ev_fp), "fn": sorted(ev_fn),
                     "primary_tier": res.get("primary_tier"),
                     "needs_llm": res.get("needs_llm")})

    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0

    # ── report ───────────────────────────────────────────────────────────────
    print("=" * 72)
    print(f"COMPLIANCE MAPPING ACCURACY  (embedding tier: {'ON' if USE_RAG else 'OFF'})")
    print("=" * 72)
    print(f"events={len(gold)}  TP={tp}  FP={fp}  FN={fn}")
    print(f"micro precision={prec:.2f}  recall={rec:.2f}  F1={f1:.2f}")
    print(f"benign false-positive rate: {benign_fp}/{benign_total} clean events got controls")
    print()
    print("PER-CONTROL  (sorted by problems: FP+FN desc)")
    print(f"  {'control':<12} {'TP':>3} {'FP':>3} {'FN':>3}  prec  rec")
    for c, s in sorted(per_control.items(),
                       key=lambda kv: kv[1]["fp"] + kv[1]["fn"], reverse=True):
        p = s["tp"] / (s["tp"] + s["fp"]) if (s["tp"] + s["fp"]) else 0.0
        r = s["tp"] / (s["tp"] + s["fn"]) if (s["tp"] + s["fn"]) else 0.0
        print(f"  {c:<12} {s['tp']:>3} {s['fp']:>3} {s['fn']:>3}  {p:.2f}  {r:.2f}")
    print()
    print("PER-TIER ATTRIBUTION  (where predictions came from)")
    for t, s in sorted(per_tier.items(), key=lambda kv: kv[1]["fp"], reverse=True):
        acc = s["tp"] / (s["tp"] + s["fp"]) if (s["tp"] + s["fp"]) else 0.0
        print(f"  {t:<22} correct={s['tp']:>3}  wrong={s['fp']:>3}  precision={acc:.2f}")
    print()
    print("WORST FALSE POSITIVES (predicted controls that are wrong):")
    for r in sorted(rows, key=lambda x: len(x["fp"]), reverse=True)[:6]:
        if r["fp"]:
            print(f"  {r['id']:<22} extra={r['fp']}  (tier={r['primary_tier']})")
    print()
    print("WORST FALSE NEGATIVES (gold controls that were missed):")
    for r in sorted(rows, key=lambda x: len(x["fn"]), reverse=True)[:6]:
        if r["fn"]:
            print(f"  {r['id']:<22} missed={r['fn']}")

    out = {"rag": USE_RAG, "tp": tp, "fp": fp, "fn": fn,
           "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3),
           "benign_fp_rate": f"{benign_fp}/{benign_total}",
           "per_control": {c: dict(s) for c, s in per_control.items()},
           "per_tier": {t: dict(s) for t, s in per_tier.items()},
           "rows": rows}
    Path(__file__).with_name("last_report.json").write_text(json.dumps(out, indent=2))
    print(f"\nwrote {Path(__file__).with_name('last_report.json')}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  TOOL · BATCH INGEST — push many logs through the appliance at once         ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# WHAT : Reads logs from a file/directory (or the built-in samples) and submits
#        them to POST /api/analyze/batch on a running dashboard (C11).
# WHY  : Real SOCs never analyse one event — they analyse streams. This is how
#        you feed a backlog and watch C6→C14→C8 chew through it.
# LOG SOURCES it understands:
#   --samples            all built-in sample logs
#   --file logs.txt      one file; logs separated by a line of "---" or blank lines
#   --dir ./logs/        every *.log / *.txt file in a directory = one log each
#
# Modes: --mode direct  (returns a verdict per log)   [default]
#        --mode pipeline (streams through the C2→C6→C14→C8 bus; returns summary)
#
#   python tools/batch_ingest.py --samples
#   python tools/batch_ingest.py --file mylogs.txt --mode pipeline --url http://localhost:8080
from __future__ import annotations
import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _split_blocks(text: str) -> list[str]:
    """A file may hold many logs. Separate on '---' lines or blank-line gaps."""
    if "\n---" in text or text.startswith("---"):
        blocks = [b.strip() for b in text.split("---")]
    else:
        blocks = [b.strip() for b in text.split("\n\n")]
    return [b for b in blocks if b]


def collect(args) -> list[str]:
    if args.samples:
        from furix_mvp.samples import SAMPLE_LOGS
        return list(SAMPLE_LOGS.values())
    if args.file:
        return _split_blocks(Path(args.file).read_text(encoding="utf-8"))
    if args.dir:
        d = Path(args.dir)
        files = sorted([*d.glob("*.log"), *d.glob("*.txt")])
        return [f.read_text(encoding="utf-8").strip() for f in files]
    raise SystemExit("Provide --samples, --file PATH, or --dir PATH")


def post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as resp:
        return json.loads(resp.read().decode())


def main() -> None:
    ap = argparse.ArgumentParser(description="Batch-ingest logs into Furix")
    ap.add_argument("--samples", action="store_true")
    ap.add_argument("--file")
    ap.add_argument("--dir")
    ap.add_argument("--url", default="http://localhost:8080")
    ap.add_argument("--mode", choices=["direct", "pipeline"], default="direct")
    args = ap.parse_args()

    logs = collect(args)
    print(f"→ submitting {len(logs)} logs ({args.mode}) to {args.url}")
    t0 = time.time()
    out = post(f"{args.url}/api/analyze/batch",
               {"logs": logs, "mode": args.mode, "source": "batch_cli"})
    dt = time.time() - t0

    if args.mode == "direct":
        print(f"\n{'log_type':<22}{'severity':<14}{'risk':<6}{'cache':<7}{'ms'}")
        print("-" * 56)
        for r in out["results"]:
            v = r["verdict"]
            print(f"{r['log_type']:<22}{v['severity']:<14}{v['risk_score']:<6}"
                  f"{'hit' if r.get('cache_hit') else '-':<7}{r['latency_ms']}")
        print(f"\n{out['count']} analysed in {dt:.1f}s "
              f"({out['count']/dt:.1f}/s wall-clock)")
    else:
        print(json.dumps(out, indent=2)[:1200])
        print(f"\npipeline ingest in {dt:.1f}s")


if __name__ == "__main__":
    main()

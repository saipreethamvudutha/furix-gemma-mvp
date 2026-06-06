#!/usr/bin/env python3
# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  TOOL · GEMMA LOAD / STRESS TEST — find C7's real limits                    ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# WHAT : Drives the in-house Gemma (C7) with REALISTIC agent prompts at rising
#        concurrency and reports latency percentiles, throughput, tokens/sec,
#        error rate, and the saturation point (where adding load stops helping).
# WHY  : "Does Gemma work?" is not enough for an enterprise deploy. You need to
#        know: how many concurrent analysts/agents can it serve? where does p95
#        latency blow past the agent's budget (Risk Scorer = 5s)? when do errors
#        start? This answers that with numbers.
# HOW  : Each "request" runs one real agent call (default Risk Scorer) on a
#        rotating set of sample findings, so prompts vary (no free model-side
#        cache wins). It calls the SAME client the AI Brain uses (furix_mvp.llm),
#        so what you measure is what production gets.
#
#   python tools/loadtest.py --concurrency 1,2,4,8,16 --requests 20
#   python tools/loadtest.py --agent compliance_mapper --duration 30 --concurrency 4,8,16
#   MOCK_LLM=0 GEMMA_BASE_URL=http://YOUR_GEMMA_HOST:11434/v1 python tools/loadtest.py
from __future__ import annotations
import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from furix_mvp import agents, config           # noqa: E402
from furix_mvp.containers import c6_normaliser as c6  # noqa: E402
from furix_mvp.dal import DAL                  # noqa: E402
from furix_mvp.samples import SAMPLE_LOGS      # noqa: E402

# Pre-build realistic, DAL-redacted findings (what the agents actually receive).
def _findings() -> list[dict]:
    out = []
    for raw in SAMPLE_LOGS.values():
        dal = DAL()
        f = c6.normalise(dal.strip(raw))
        out.append(f)
    return out


_FINDINGS = _findings()
_GROUND = {"available": False, "controls": [], "snippets": []}

# Map --agent name → a zero-arg callable that performs ONE Gemma call.
def _call_for(agent: str, finding: dict):
    if agent == "risk_scorer":
        return lambda: agents.run_risk_scorer(finding, _GROUND)
    if agent == "compliance_mapper":
        return lambda: agents.run_compliance_mapper(finding, _GROUND)
    if agent == "anomaly_detector":
        return lambda: agents.run_anomaly_detector(finding, _GROUND)
    if agent == "remediation_generator":
        return lambda: agents.run_remediation_generator(finding, {"control_ids": ["Control 6"]}, _GROUND)
    raise SystemExit(f"unknown agent {agent}")


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    v = sorted(values)
    return round(v[min(len(v) - 1, int(round(p / 100 * (len(v) - 1))))], 1)


def run_level(agent: str, concurrency: int, n_requests: int, duration: float) -> dict:
    """Fire load at one concurrency level. Returns the measured stats."""
    latencies: list[float] = []
    tokens: list[int] = []
    errors = 0
    submitted = 0
    deadline = time.time() + duration if duration else None

    def _one(i: int):
        finding = _FINDINGS[i % len(_FINDINGS)]
        t = time.perf_counter()
        res = _call_for(agent, finding)()
        dt = (time.perf_counter() - t) * 1000.0
        ok = res.ok and res.source != "fallback"
        return dt, ok, res.completion_tokens, res.source

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = []
        i = 0
        # Keep the pool saturated until we hit the request count or the deadline.
        while (duration and time.time() < deadline) or (not duration and i < n_requests):
            futures.append(ex.submit(_one, i))
            i += 1; submitted += 1
            if not duration and i >= n_requests:
                break
        for fut in as_completed(futures):
            try:
                dt, ok, tok, _src = fut.result()
                latencies.append(dt); tokens.append(tok or 0)
                errors += 0 if ok else 1
            except Exception:  # noqa: BLE001
                errors += 1
    wall = time.perf_counter() - t0
    done = len(latencies)
    return {
        "concurrency": concurrency, "requests": submitted, "completed": done,
        "errors": errors, "error_rate": round(errors / max(1, submitted), 3),
        "wall_s": round(wall, 2),
        "throughput_rps": round(done / wall, 2) if wall else 0,
        "tokens_per_s": round(sum(tokens) / wall, 1) if wall else 0,
        "p50_ms": _pct(latencies, 50), "p95_ms": _pct(latencies, 95),
        "p99_ms": _pct(latencies, 99), "max_ms": round(max(latencies), 1) if latencies else 0,
        "avg_tokens": round(sum(tokens) / max(1, done), 1),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Stress-test the in-house Gemma (C7)")
    ap.add_argument("--concurrency", default="1,2,4,8", help="comma list of levels")
    ap.add_argument("--requests", type=int, default=20, help="requests per level")
    ap.add_argument("--duration", type=float, default=0, help="secs per level (overrides --requests)")
    ap.add_argument("--agent", default="risk_scorer")
    ap.add_argument("--json", dest="json_out", help="write full results to this path")
    args = ap.parse_args()

    levels = [int(x) for x in args.concurrency.split(",") if x.strip()]
    print(f"# Gemma load test · agent={args.agent} · model={config.GEMMA_MODEL} · "
          f"endpoint={config.GEMMA_BASE_URL}")
    if config.MOCK_LLM:
        print("# ⚠️  MOCK_LLM=1 — latencies are fake. Set MOCK_LLM=0 on the Gemma network "
              "for real numbers. (Use this run only to validate the harness.)")
    mode = f"{args.duration}s/level" if args.duration else f"{args.requests} reqs/level"
    print(f"# load: {mode}\n")

    hdr = f"{'conc':>4} {'done':>5} {'err%':>5} {'rps':>7} {'tok/s':>8} {'p50':>8} {'p95':>8} {'p99':>8} {'max':>8}"
    print(hdr); print("-" * len(hdr))
    results = []
    prev_rps = 0.0
    saturation = None
    for c in levels:
        r = run_level(args.agent, c, args.requests, args.duration)
        results.append(r)
        print(f"{r['concurrency']:>4} {r['completed']:>5} {r['error_rate']*100:>4.0f}% "
              f"{r['throughput_rps']:>7} {r['tokens_per_s']:>8} {r['p50_ms']:>8} "
              f"{r['p95_ms']:>8} {r['p99_ms']:>8} {r['max_ms']:>8}")
        # Saturation heuristic: throughput gained <10% while concurrency doubled.
        if saturation is None and prev_rps and r["throughput_rps"] < prev_rps * 1.10:
            saturation = r["concurrency"]
        prev_rps = max(prev_rps, r["throughput_rps"])

    best = max(results, key=lambda x: x["throughput_rps"])
    print(f"\nPeak throughput : {best['throughput_rps']} req/s at concurrency "
          f"{best['concurrency']} (p95 {best['p95_ms']}ms)")
    if saturation:
        print(f"Saturation point: ~{saturation} concurrent — past here, more load "
              f"adds latency, not throughput.")
    else:
        print("Saturation point: not reached — Gemma still scaled at the top level tested.")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, indent=2))
        print(f"Full results → {args.json_out}")


if __name__ == "__main__":
    main()

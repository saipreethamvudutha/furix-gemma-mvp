#!/usr/bin/env python3
# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  TOOL · COMPLIANCE-ENGINE LOAD TEST — end-to-end, LLM-rate aware            ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# WHAT : Drives the FULL compliance engine (brain.analyze: C6 rules -> crosswalk
#        -> embeddings -> conditional Gemma fallback, + config-state checks) at
#        scale and reports end-to-end throughput, latency percentiles, AND the
#        number that actually matters after the re-architecture:
#        **what fraction of events ever reach the LLM.**
# WHY  : The original MVP question was "can locally-deployed Gemma take the load?"
#        Now that mapping is deterministic and Gemma is a rare fallback, the real
#        answer is "Gemma only sees the few events the deterministic tiers can't
#        handle." This quantifies that, and projects the Gemma req/s a given event
#        rate implies — which you compare against tools/loadtest.py's measured
#        Gemma capacity.
# HOW  : Runs a realistic mixed event stream through brain.analyze. With MOCK_LLM=1
#        the deterministic tiers run FOR REAL (regex/crosswalk/embeddings) — only
#        the rare fallback call is mocked — so deterministic throughput + LLM-rate
#        are real. Also load-tests config_checks.evaluate.
#
#   MOCK_LLM=1 RAG_ENABLED=0 python tools/loadtest_engine.py --events 3000 --concurrency 8
#   python tools/loadtest_engine.py --events 3000 --gemma-rps 4   # project capacity
from __future__ import annotations
import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from furix_mvp import brain, config, config_checks   # noqa: E402
from furix_mvp.samples import SAMPLE_LOGS            # noqa: E402


def _corpus() -> list[tuple[str, str]]:
    """Realistic mixed stream: every sample log + the eval/holdout events if present,
    so the mix spans attacks, benign traffic, and many log types."""
    items: list[tuple[str, str]] = [(v, "auto") for v in SAMPLE_LOGS.values()]
    for name in ("gold_set.jsonl", "holdout_set.jsonl"):
        p = ROOT / "tests" / "eval" / name
        if p.exists():
            for line in p.read_text().splitlines():
                if line.strip():
                    ev = json.loads(line)
                    items.append((ev["raw"], ev.get("log_type", "auto")))
    return items


def _config_snapshots() -> list[dict]:
    secure = {"aws_account": {"root_mfa_enabled": True, "password_policy": {"min_length": 16}},
              "iam_users": [{"name": "a", "mfa_enabled": True}],
              "s3_buckets": [{"name": "b", "public": False, "encrypted": True}],
              "cloudtrail": {"enabled": True}, "backups": {"configured": True},
              "tls_endpoints": [{"name": "api", "min_version": "1.3"}],
              "security_groups": [{"name": "sg", "open_ingress": []}]}
    insecure = {"aws_account": {"root_mfa_enabled": False, "password_policy": {"min_length": 8}},
                "iam_users": [{"name": "svc", "mfa_enabled": False}],
                "s3_buckets": [{"name": "b", "public": True, "encrypted": False}],
                "cloudtrail": {"enabled": False}, "backups": {"configured": False},
                "tls_endpoints": [{"name": "api", "min_version": "1.0"}],
                "security_groups": [{"name": "sg", "open_ingress": [{"cidr": "0.0.0.0/0", "port": 22}]}]}
    return [secure, insecure]


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    v = sorted(values)
    return round(v[min(len(v) - 1, int(round(p / 100 * (len(v) - 1))))], 2)


# A genuinely novel-but-suspicious event: it trips a deterministic RISK signal
# (lateral movement) but matches NO keyword control, so the resolver returns
# needs_llm=True and the event escalates to the LLM fallback. Used to simulate the
# small fraction of real traffic the deterministic tiers can't map.
_NOVEL = "alert: lateral movement detected via previously-unseen technique vektor-{i} on host h{i}"


# Agents that call Gemma in real (non-mock) mode. risk_scorer & anomaly_detector
# already have DETERMINISTIC logic in agents.py (used as the mock) and could be
# switched off the LLM; remediation & report are narrative (genuinely want Gemma).
_LLM_AGENTS = {"risk_scorer", "compliance_mapper", "anomaly_detector",
               "remediation_generator", "report_generator"}


def run_events(corpus, n_events: int, concurrency: int, unique: bool = True,
               novel_rate: float = 0.0) -> dict:
    lat: list[float] = []
    comp_llm = benign = cache = 0
    gemma_calls = 0
    per_agent: dict[str, int] = {}
    tiers: dict[str, int] = {}
    errors = 0
    novel_every = int(round(1 / novel_rate)) if novel_rate > 0 else 0

    def _one(i: int):
        if novel_every and i % novel_every == 0:
            raw, lt = _NOVEL.format(i=i), "generic"
        else:
            raw, lt = corpus[i % len(corpus)]
            if unique:
                raw = f"{raw}  evt-{i}"
        t = time.perf_counter()
        rec = brain.analyze(raw, lt)
        dt = (time.perf_counter() - t) * 1000.0
        c = rec.get("compliance", {})
        # In real mode each agent that ran == one Gemma call.
        agents_ran = [a["agent"] for a in rec.get("agents", []) if a["agent"] in _LLM_AGENTS]
        return dt, bool(c.get("llm_used")), bool(c.get("benign")), bool(rec.get("cache_hit")), c.get("primary_tier"), agents_ran

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(_one, i) for i in range(n_events)]
        for f in as_completed(futs):
            try:
                dt, is_llm, is_benign, is_cache, tier, agents_ran = f.result()
                lat.append(dt); comp_llm += is_llm; benign += is_benign; cache += is_cache
                tiers[tier or "none"] = tiers.get(tier or "none", 0) + 1
                gemma_calls += len(agents_ran)
                for a in agents_ran:
                    per_agent[a] = per_agent.get(a, 0) + 1
            except Exception:  # noqa: BLE001
                errors += 1
    wall = time.perf_counter() - t0
    done = len(lat)
    return {"events": done, "errors": errors, "wall_s": round(wall, 2),
            "throughput_eps": round(done / wall, 1) if wall else 0,
            "compliance_llm_calls": comp_llm, "compliance_llm_rate": round(comp_llm / max(1, done), 4),
            "gemma_calls_total": gemma_calls,
            "gemma_calls_per_event": round(gemma_calls / max(1, done), 2),
            "per_agent_calls": per_agent,
            "benign_suppressed": benign, "cache_hits": cache,
            "p50_ms": _pct(lat, 50), "p95_ms": _pct(lat, 95), "p99_ms": _pct(lat, 99),
            "tiers": tiers}


def run_config(snaps, n: int) -> dict:
    t0 = time.perf_counter()
    fails = 0
    for i in range(n):
        r = config_checks.evaluate(snaps[i % len(snaps)])
        fails += r["summary"]["fail"]
    wall = time.perf_counter() - t0
    return {"scans": n, "wall_s": round(wall, 2),
            "throughput_sps": round(n / wall, 1) if wall else 0,
            "total_fail_findings": fails}


def main() -> None:
    ap = argparse.ArgumentParser(description="End-to-end compliance-engine load test")
    ap.add_argument("--events", type=int, default=3000)
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--config-scans", type=int, default=2000)
    ap.add_argument("--gemma-rps", type=float, default=0,
                    help="measured Gemma capacity (req/s) to project max event rate")
    ap.add_argument("--no-unique", dest="unique", action="store_false",
                    help="allow verdict-cache hits (best case) instead of all-unique worst case")
    ap.add_argument("--novel-rate", type=float, default=0.0,
                    help="fraction of synthetic novel-suspicious events that hit the LLM fallback (e.g. 0.05)")
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args()

    corpus = _corpus()
    print(f"# Compliance-engine load test")
    print(f"# corpus={len(corpus)} distinct events · MOCK_LLM={int(config.MOCK_LLM)} · "
          f"RAG={int(config.RAG_ENABLED)} · SCF={'on' if __import__('furix_mvp.compliance', fromlist=['crosswalk_source']).crosswalk_source()!='builtin' else 'off'}")
    if config.MOCK_LLM:
        print("# note: deterministic tiers (regex/crosswalk/embeddings) run FOR REAL; only the rare")
        print("#       LLM fallback is mocked — so throughput + LLM-rate below are real.\n")

    print(f"# mode: {'ALL-UNIQUE events (worst case, cache disabled)' if args.unique else 'cache-allowed (best case)'}\n")
    if args.unique:
        # Disable the verdict cache so EVERY event runs the full deterministic
        # pipeline (the cache keys on finding shape, not raw text, so otherwise
        # identical-shaped events would hit cache and hide real compute cost).
        from furix_mvp.containers import c13_valkey as _cache
        _cache.get_verdict = lambda finding: None
    ev = run_events(corpus, args.events, args.concurrency, unique=args.unique,
                    novel_rate=args.novel_rate)
    print("── EVENT MAPPING (full brain.analyze pipeline) ──")
    print(f"  events               : {ev['events']}  (errors {ev['errors']})")
    print(f"  throughput           : {ev['throughput_eps']} events/sec  (concurrency {args.concurrency})")
    print(f"  latency              : p50 {ev['p50_ms']}ms · p95 {ev['p95_ms']}ms · p99 {ev['p99_ms']}ms")
    print(f"  compliance mapping   : {ev['compliance_llm_calls']}/{ev['events']} hit LLM "
          f"= {ev['compliance_llm_rate']*100:.2f}%  (deterministic otherwise)")
    print(f"  mapped by tier       : {ev['tiers']}")
    print(f"  TOTAL Gemma calls    : {ev['gemma_calls_total']}  =  {ev['gemma_calls_per_event']} per event")
    print(f"  per-agent Gemma calls: {ev['per_agent_calls']}")

    cfg = run_config(_config_snapshots(), args.config_scans)
    print("\n── CONFIG-STATE CHECKS (config_checks.evaluate) ──")
    print(f"  scans                : {cfg['scans']}   throughput: {cfg['throughput_sps']} scans/sec")

    print("\n── VERDICT ──")
    print(f"  Compliance MAPPING is ~{(1-ev['compliance_llm_rate'])*100:.0f}% deterministic (zero LLM).")
    gpe = ev["gemma_calls_per_event"]
    print(f"  BUT the 5-agent AI Brain still makes ~{gpe} Gemma calls/event "
          f"(risk, anomaly, remediation, report run on every event).")
    if args.gemma_rps and gpe > 0:
        max_eps = args.gemma_rps / gpe
        print(f"  → With local Gemma at {args.gemma_rps} req/s, the brain sustains ~{max_eps:,.1f} events/sec.")
        # what if risk+anomaly were also made deterministic (they already have it)?
        narrative = sum(ev['per_agent_calls'].get(a, 0) for a in ('remediation_generator', 'report_generator'))
        gpe2 = round(narrative / max(1, ev['events']), 2)
        if gpe2 and gpe2 < gpe:
            print(f"  → If risk_scorer + anomaly_detector were made deterministic too (their logic")
            print(f"    already exists), Gemma calls/event drop to ~{gpe2}, sustaining "
                  f"~{args.gemma_rps/gpe2:,.1f} events/sec.")
    else:
        print(f"  → Pass --gemma-rps <measured from tools/loadtest.py> to project sustainable event rate.")
    print(f"  Deterministic engine itself runs at {ev['throughput_eps']} events/sec — never the bottleneck.")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps({"events": ev, "config": cfg}, indent=2))
        print(f"\nFull results → {args.json_out}")


if __name__ == "__main__":
    main()

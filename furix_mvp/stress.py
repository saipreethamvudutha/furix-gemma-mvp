# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  STRESS / LOAD TEST API — run benchmarks from the dashboard (not just CLI)  ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# WHAT : Background-job runner that powers the /stress dashboard page. Two
#        scenarios, each surfaced live (progress polled by the browser):
#
#   1. routing   — run each sample log through the FULL brain pipeline and report,
#                  per log, WHICH tier decided it: deterministic rules (0ms, no
#                  model) vs a Gemma LLM call (real ms). This is the "why is this
#                  log instant and that one hits the model?" story for clients.
#
#   2. gemma_ramp— drive a real Gemma agent at rising concurrency and report
#                  p50/p95/p99 latency, throughput (req/s), tokens/s, and the
#                  saturation point (where more load stops adding throughput).
#
# WHY  : Clients want to SEE the model's response time and the cost-routing, not
#        read a CLI table. Same measurement logic as tools/loadtest*.py, exposed
#        over HTTP as start()+get_job() with a shared in-memory job store.
from __future__ import annotations
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import agents, brain
from .samples import SAMPLE_LOGS
from .dal import DAL
from .containers import c6_normaliser as c6

# ── Job store (in-memory; one appliance process) ──────────────────────────────
_JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()

# Agents that genuinely call Gemma. risk_scorer & anomaly_detector run as
# deterministic rules by default (DETERMINISTIC_SCORING=1) → 0ms, no model.
ALL_AGENTS = ("risk_scorer", "compliance_mapper", "anomaly_detector",
              "remediation_generator", "report_generator")
GEMMA_AGENTS = ("remediation_generator", "report_generator", "compliance_mapper")
_GROUND = {"available": False, "controls": [], "snippets": []}

# Safety caps so a demo can't accidentally fire thousands of Gemma calls.
MAX_REQUESTS = 40
MAX_CONCURRENCY = 16
MAX_LEVELS = 6


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    v = sorted(values)
    return round(v[min(len(v) - 1, int(round(p / 100 * (len(v) - 1))))], 1)


def _findings() -> list[dict]:
    """Pre-build DAL-redacted, C6-normalised findings (what agents receive)."""
    out = []
    for raw in SAMPLE_LOGS.values():
        dal = DAL()
        out.append(c6.normalise(dal.strip(raw)))
    return out


def _call(agent: str, finding: dict):
    if agent == "remediation_generator":
        return agents.run_remediation_generator(finding, {"control_ids": ["Control 6"]}, _GROUND)
    if agent == "report_generator":
        return agents.run_report_generator(finding, {"risk_scorer": {"severity": "high", "risk_score": 70}})
    if agent == "compliance_mapper":
        return agents.run_compliance_mapper(finding, _GROUND)
    if agent == "anomaly_detector":
        return agents.run_anomaly_detector(finding, _GROUND)
    return agents.run_risk_scorer(finding, _GROUND)


# ── Job lifecycle ─────────────────────────────────────────────────────────────
def get_job(jid: str) -> dict | None:
    with _LOCK:
        j = _JOBS.get(jid)
        return dict(j) if j else None


def _set(jid: str, **kw) -> None:
    with _LOCK:
        if jid in _JOBS:
            _JOBS[jid].update(kw)


def _bump(jid: str, n: int = 1) -> None:
    with _LOCK:
        if jid in _JOBS:
            _JOBS[jid]["progress"] += n


def start(scenario: str, params: dict) -> str:
    jid = uuid.uuid4().hex[:12]
    with _LOCK:
        _JOBS[jid] = {"id": jid, "scenario": scenario, "state": "running",
                      "progress": 0, "total": 0, "started": time.time(),
                      "params": params, "rows": [], "levels": [],
                      "summary": None, "error": None}
    threading.Thread(target=_run, args=(jid, scenario, params), daemon=True).start()
    return jid


def _run(jid: str, scenario: str, params: dict) -> None:
    try:
        if scenario == "routing":
            _routing(jid, params)
        elif scenario == "gemma_ramp":
            _gemma_ramp(jid, params)
        else:
            raise ValueError(f"unknown scenario '{scenario}'")
        _set(jid, state="done", ended=time.time())
    except Exception as e:  # noqa: BLE001
        _set(jid, state="error", error=str(e), ended=time.time())


# ── Scenario 1 · ROUTING (deterministic vs Gemma, per log) ────────────────────
def _routing(jid: str, params: dict) -> None:
    concurrency = max(1, min(int(params.get("concurrency", 3)), MAX_CONCURRENCY))
    items = list(SAMPLE_LOGS.items())          # (name, raw)
    _set(jid, total=len(items))

    def _one(name_raw):
        name, raw = name_raw
        t = time.perf_counter()
        rec = brain.analyze(raw)
        total_ms = round((time.perf_counter() - t) * 1000.0, 1)
        v = rec.get("verdict", {})
        comp = rec.get("compliance", {})
        ags = rec.get("agents", [])
        gemma = [a for a in ags if a.get("source") in ("llm", "mock")]
        det = [a for a in ags if a.get("source") == "deterministic"]
        gemma_ms = sum(int(a.get("latency_ms") or 0) for a in gemma)
        return {
            "sample": name,
            "log_type": rec.get("log_type"),
            "severity": v.get("severity"),
            "risk_score": v.get("risk_score"),
            "is_anomaly": v.get("is_anomaly"),
            "primary_tier": comp.get("primary_tier"),
            "compliance_llm": bool(comp.get("llm_used")),
            "gemma_agents": [a.get("agent") for a in gemma],
            "deterministic_agents": [a.get("agent") for a in det],
            "gemma_calls": len(gemma),
            "gemma_ms": gemma_ms,
            "deterministic_ms": max(0, round(total_ms - gemma_ms, 1)),
            "total_ms": total_ms,
            "cache_hit": bool(rec.get("cache_hit")),
            "route": "Gemma LLM" if gemma else "Deterministic (no model)",
        }

    rows = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(_one, it) for it in items]
        for f in as_completed(futs):
            try:
                rows.append(f.result())
            except Exception:  # noqa: BLE001
                pass
            _bump(jid)
            with _LOCK:
                _JOBS[jid]["rows"] = list(rows)

    rows.sort(key=lambda r: r["total_ms"], reverse=True)
    n = len(rows) or 1
    det_only = [r for r in rows if r["gemma_calls"] == 0]
    gemma_any = [r for r in rows if r["gemma_calls"] > 0]
    total_gemma_calls = sum(r["gemma_calls"] for r in rows)
    total_gemma_ms = sum(r["gemma_ms"] for r in rows)
    _set(jid, rows=rows, summary={
        "logs": n,
        "deterministic_only": len(det_only),
        "hit_gemma": len(gemma_any),
        "deterministic_pct": round(100 * len(det_only) / n, 1),
        "total_gemma_calls": total_gemma_calls,
        "total_gemma_ms": total_gemma_ms,
        "avg_gemma_ms": round(total_gemma_ms / max(1, total_gemma_calls), 0),
        "compliance_llm_rate": round(100 * sum(1 for r in rows if r["compliance_llm"]) / n, 1),
    })


# ── Scenario 2 · GEMMA CAPACITY RAMP ──────────────────────────────────────────
def _gemma_ramp(jid: str, params: dict) -> None:
    agent = params.get("agent", "remediation_generator")
    if agent not in ALL_AGENTS:
        agent = "remediation_generator"
    levels = [int(x) for x in params.get("concurrency", [1, 2, 4]) if int(x) > 0][:MAX_LEVELS]
    levels = [min(c, MAX_CONCURRENCY) for c in levels] or [1, 2, 4]
    reqs = max(1, min(int(params.get("requests", 4)), MAX_REQUESTS))
    findings = _findings()
    _set(jid, total=len(levels) * reqs, agent=agent)

    def _one(i):
        f = findings[i % len(findings)]
        t = time.perf_counter()
        res = _call(agent, f)
        dt = (time.perf_counter() - t) * 1000.0
        ok = bool(res.ok) and res.source != "fallback"
        return dt, ok, int(res.completion_tokens or 0)

    results = []
    prev_rps = 0.0
    saturation = None
    for c in levels:
        lat, toks, errors = [], [], 0
        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=c) as ex:
            futs = [ex.submit(_one, i) for i in range(reqs)]
            for fut in as_completed(futs):
                try:
                    dt, ok, tk = fut.result()
                    lat.append(dt)
                    toks.append(tk)
                    errors += 0 if ok else 1
                except Exception:  # noqa: BLE001
                    errors += 1
                _bump(jid)
        wall = time.perf_counter() - t0
        done = len(lat)
        rps = round(done / wall, 2) if wall else 0
        level = {
            "concurrency": c, "completed": done, "errors": errors,
            "error_rate": round(errors / max(1, reqs), 3),
            "throughput_rps": rps,
            "tokens_per_s": round(sum(toks) / wall, 1) if wall else 0,
            "p50_ms": _pct(lat, 50), "p95_ms": _pct(lat, 95), "p99_ms": _pct(lat, 99),
            "max_ms": round(max(lat), 1) if lat else 0,
            "avg_tokens": round(sum(toks) / max(1, done), 1),
        }
        results.append(level)
        with _LOCK:
            _JOBS[jid]["levels"] = list(results)
        if saturation is None and prev_rps and rps < prev_rps * 1.10:
            saturation = c
        prev_rps = max(prev_rps, rps)

    best = max(results, key=lambda x: x["throughput_rps"]) if results else {}
    _set(jid, levels=results, summary={
        "agent": agent, "requests_per_level": reqs,
        "peak_rps": best.get("throughput_rps", 0),
        "peak_concurrency": best.get("concurrency", 0),
        "peak_p95_ms": best.get("p95_ms", 0),
        "saturation": saturation,
    })

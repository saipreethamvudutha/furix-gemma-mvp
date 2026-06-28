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
import glob
import json
import os
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import agents, brain
from .samples import SAMPLE_LOGS
from .dal import DAL
from .containers import c6_normaliser as c6
from .containers import c13_valkey as _c13
from .containers.c6_normaliser import KW as _KW
from .containers.c8_storage_detect import RULES as _DETECTION_RULES

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


def _cancelled(jid: str) -> bool:
    with _LOCK:
        j = _JOBS.get(jid)
        return bool(j and j.get("cancel"))


def stop(jid: str) -> bool:
    """Signal a running job (e.g. the live forge feed) to stop after the current
    event. The job loop checks _cancelled() each iteration."""
    with _LOCK:
        if jid in _JOBS:
            _JOBS[jid]["cancel"] = True
            return True
    return False


def start(scenario: str, params: dict) -> str:
    jid = uuid.uuid4().hex[:12]
    with _LOCK:
        _JOBS[jid] = {"id": jid, "scenario": scenario, "state": "running",
                      "progress": 0, "total": 0, "started": time.time(),
                      "params": params, "rows": [], "levels": [],
                      "summary": None, "error": None, "cancel": False}
    threading.Thread(target=_run, args=(jid, scenario, params), daemon=True).start()
    return jid


def _run(jid: str, scenario: str, params: dict) -> None:
    try:
        if scenario == "routing":
            _routing(jid, params)
        elif scenario == "gemma_ramp":
            _gemma_ramp(jid, params)
        elif scenario == "ingest":
            _ingest(jid, params)
        elif scenario == "forge":
            _forge(jid, params)
        else:
            raise ValueError(f"unknown scenario '{scenario}'")
        _set(jid, state="done", ended=time.time())
    except Exception as e:  # noqa: BLE001
        _set(jid, state="error", error=str(e), ended=time.time())


# A few synthetic NOVEL events: each trips a real risk signal (lateral movement
# via psexec/netbios) that maps to NO control and NO detection rule and NO known
# CVE — so the deterministic tiers can't resolve them and they correctly escalate
# to the LLM. They make the "model is for the novel" path visible in the demo.
_NOVEL_PROBES = [
    ("novel · psexec lateral move",
     "alert: WORKSTATION-22 lateral movement detected via psexec to internal host 10.2.7.40 — previously-unseen pattern"),
    ("novel · netbios anomaly",
     "warning: anomalous netbios session from 10.2.3.9 to fileserver fin-db-07, behaviour not seen before"),
]


# ── Scenario 1 · ROUTING (which tier decided each event) ──────────────────────
def _routing(jid: str, params: dict) -> None:
    # Sequential by default so any escalated LLM calls are timed honestly (no
    # queue contention inflating per-log timings).
    concurrency = max(1, min(int(params.get("concurrency", 1)), MAX_CONCURRENCY))
    items = list(SAMPLE_LOGS.items()) + list(_NOVEL_PROBES)   # (name, raw)
    _set(jid, total=len(items))

    def _one(name_raw):
        name, raw = name_raw
        t = time.perf_counter()
        rec = brain.analyze(raw)
        total_ms = round((time.perf_counter() - t) * 1000.0, 1)
        v = rec.get("verdict", {})
        ags = rec.get("agents", [])
        gemma = [a for a in ags if a.get("source") in ("llm", "mock")]
        gemma_ms = sum(int(a.get("latency_ms") or 0) for a in gemma)
        deterministic = bool(v.get("deterministic", True))
        return {
            "sample": name,
            "log_type": rec.get("log_type"),
            "severity": v.get("severity"),
            "decided_by": v.get("decided_by", "deterministic"),
            "decision_engine": v.get("decision_engine", "—"),
            "decision_detail": v.get("decision_detail", ""),
            "deterministic": deterministic,
            "gemma_calls": len(gemma),
            "gemma_ms": gemma_ms,
            "total_ms": total_ms,
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

    # Order: deterministic first (fast), escalated LLM rows last.
    rows.sort(key=lambda r: (not r["deterministic"], r["total_ms"]))
    n = len(rows) or 1
    det = [r for r in rows if r["deterministic"]]
    llm = [r for r in rows if not r["deterministic"]]
    total_gemma_calls = sum(r["gemma_calls"] for r in rows)
    total_gemma_ms = sum(r["gemma_ms"] for r in rows)

    # Count how each engine decided things (the deterministic-coverage breakdown).
    by_engine: dict[str, int] = {}
    for r in rows:
        by_engine[r["decision_engine"]] = by_engine.get(r["decision_engine"], 0) + 1

    _set(jid, rows=rows, summary={
        "logs": n,
        "deterministic_only": len(det),
        "hit_gemma": len(llm),
        "deterministic_pct": round(100 * len(det) / n, 1),
        "total_gemma_calls": total_gemma_calls,
        "total_gemma_ms": total_gemma_ms,
        "avg_gemma_ms": round(total_gemma_ms / max(1, total_gemma_calls), 0) if total_gemma_calls else 0,
        "by_engine": by_engine,
        # The deterministic engines available, for the coverage panel.
        "engines": {
            "siem_rules": len(_DETECTION_RULES),
            "cve_catalog": len(brain._KNOWN_CVES),
            "compliance_keywords": len(_KW),
        },
    })


# ── Scenario 3 · INGESTION THROUGHPUT ─────────────────────────────────────────
# How many logs can ONE process ingest + fully resolve per second? Pushes N events
# through the complete brain.analyze pipeline at a chosen concurrency and reports
# events/sec, latency percentiles, the deterministic-vs-LLM split, and the engine
# breakdown. Worst-case by default (verdict cache disabled, every event unique) so
# the number reflects real compute, not cache wins.
INGEST_MAX_EVENTS = 5000


def _ingest(jid: str, params: dict) -> None:
    n = max(1, min(int(params.get("events", 1000)), INGEST_MAX_EVENTS))
    concurrency = max(1, min(int(params.get("concurrency", 8)), MAX_CONCURRENCY))
    worst_case = bool(params.get("worst_case", True))
    corpus = list(SAMPLE_LOGS.values()) or ["benign event"]
    _set(jid, total=n)

    lat: list[float] = []
    gemma_calls = 0
    errors = 0
    deterministic = 0
    by_engine: dict[str, int] = {}

    def _one(i):
        raw = corpus[i % len(corpus)] + f"  evt-{i}"
        t = time.perf_counter()
        rec = brain.analyze(raw)
        dt = (time.perf_counter() - t) * 1000.0
        v = rec.get("verdict", {})
        gemma = [a for a in rec.get("agents", []) if a.get("source") in ("llm", "mock")]
        return dt, len(gemma), bool(v.get("deterministic", True)), v.get("decision_engine", "—")

    # Worst case: disable the verdict cache so every event runs the full pipeline
    # (otherwise identical-shaped events would hit cache and hide real compute cost).
    orig_get = _c13.get_verdict
    if worst_case:
        _c13.get_verdict = lambda finding: None
    t0 = time.perf_counter()
    try:
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futs = [ex.submit(_one, i) for i in range(n)]
            for f in as_completed(futs):
                try:
                    dt, g, det, eng = f.result()
                    lat.append(dt)
                    gemma_calls += g
                    if det:
                        deterministic += 1
                    by_engine[eng] = by_engine.get(eng, 0) + 1
                except Exception:  # noqa: BLE001
                    errors += 1
                _bump(jid)
    finally:
        if worst_case:
            _c13.get_verdict = orig_get
    wall = time.perf_counter() - t0
    done = len(lat) or 1
    eps = round(len(lat) / wall, 1) if wall else 0
    _set(jid, summary={
        "events": len(lat), "errors": errors, "wall_s": round(wall, 2),
        "concurrency": concurrency, "worst_case": worst_case,
        "throughput_eps": eps,
        "per_hour": int(round(eps * 3600)),
        "per_min": int(round(eps * 60)),
        "p50_ms": _pct(lat, 50), "p95_ms": _pct(lat, 95), "p99_ms": _pct(lat, 99),
        "gemma_calls": gemma_calls,
        "gemma_per_event": round(gemma_calls / done, 3),
        "deterministic_pct": round(100 * deterministic / done, 1),
        "by_engine": by_engine,
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


# ── Scenario 4 · LIVE FORGE FEED ──────────────────────────────────────────────
# Stream a real logforge bundle (logs/*.jsonl + labels.jsonl) through the full
# pipeline, one event at a time, and score each verdict against ground truth —
# live, with a stop button. Answers "watch real attack data flow through and see
# what we catch vs miss." Ground-truth join ported from tools/forge_feed.py.
_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_HEX32 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_JSON_ID_KEYS = ("event_id", "eventID", "ReportId", "id", "auditID")


def _norm_id(s: str) -> str:
    return re.sub(r"[^0-9a-f]", "", s.lower())


def _extract_event_id(line: str) -> str | None:
    s = line.strip()
    if s.startswith("{"):
        try:
            o = json.loads(s)
            for k in _JSON_ID_KEYS:
                if isinstance(o.get(k), str):
                    return _norm_id(o[k])
            evt = (o.get("output_fields") or {}).get("evt.id")
            if isinstance(evt, str):
                return _norm_id(evt)
        except json.JSONDecodeError:
            pass
    m = _GUID.search(s) or _HEX32.search(s)
    return _norm_id(m.group(0)) if m else None


def _load_forge_logs(bundle: str) -> list[dict]:
    out = []
    for f in sorted(glob.glob(os.path.join(bundle, "logs", "*"))):
        src = os.path.splitext(os.path.basename(f))[0]
        with open(f, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if line.strip():
                    out.append({"source": src, "raw": line, "event_id": _extract_event_id(line)})
    return out


def _load_forge_labels(bundle: str) -> dict:
    labels = {}
    p = os.path.join(bundle, "labels.jsonl")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                try:
                    o = json.loads(line)
                    labels[_norm_id(o["event_id"])] = o
                except (json.JSONDecodeError, KeyError):
                    pass
    return labels


def _forge(jid: str, params: dict) -> None:
    bundle = str(params.get("bundle", "")).strip()
    limit = max(1, min(int(params.get("limit", 80)), 2000))
    delay_ms = max(0, min(int(params.get("delay_ms", 120)), 3000))
    if not bundle or not os.path.isdir(bundle):
        raise ValueError(f"bundle directory not found on server: {bundle!r}")

    logs = _load_forge_logs(bundle)
    labels = _load_forge_labels(bundle)
    if not logs:
        raise ValueError(f"no log files found under {bundle}/logs/")

    def _label(l):
        return labels.get(l["event_id"] or "", {}).get("label", "unlabeled")

    def _tech(l):
        return labels.get(l["event_id"] or "", {}).get("mitre_technique", "")

    # Keep ALL malicious + suspicious (rare, the point), plus a capped benign sample.
    mal = [l for l in logs if _label(l) == "malicious"]
    sus = [l for l in logs if _label(l) == "benign_suspicious"]
    ben = [l for l in logs if _label(l) == "benign"][:limit]
    feed = mal + sus + ben
    _set(jid, total=len(feed))

    tp = fn = fp = tn = sus_alert = 0
    rows = []
    for l in feed:
        if _cancelled(jid):
            break
        rec = brain.analyze(l["raw"])
        v = rec.get("verdict", {})
        sev = v.get("severity")
        alerted = sev in ("critical", "high") or bool(v.get("is_anomaly"))
        truth = _label(l)
        if truth == "malicious":
            if alerted:
                tp += 1; outcome = "TP"
            else:
                fn += 1; outcome = "FN"
        elif truth == "benign":
            if alerted:
                fp += 1; outcome = "FP"
            else:
                tn += 1; outcome = "TN"
        elif truth == "benign_suspicious":
            sus_alert += 1 if alerted else 0
            outcome = "SUS-alert" if alerted else "SUS-quiet"
        else:
            outcome = "—"
        rows.append({
            "source": l["source"], "truth": truth, "mitre": _tech(l),
            "severity": sev, "decided_by": v.get("decision_engine", "—"),
            "alerted": alerted, "outcome": outcome, "raw": l["raw"][:1500],
        })
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        with _LOCK:
            if jid in _JOBS:
                _JOBS[jid]["rows"] = rows[-150:]      # keep the most recent for display
                _JOBS[jid]["summary"] = {
                    "bundle": bundle, "fed": len(rows),
                    "malicious": len(mal), "suspicious": len(sus), "benign": min(len(ben), limit),
                    "tp": tp, "fn": fn, "fp": fp, "tn": tn, "sus_alert": sus_alert,
                    "precision": round(prec, 2), "recall": round(recall, 2),
                    "total_logs": len(logs),
                }
        _bump(jid)
        if delay_ms:
            time.sleep(delay_ms / 1000.0)

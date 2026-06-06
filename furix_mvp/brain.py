# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C14 · AI BRAIN (Praxis) — the orchestrator                       ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# ROLE        : The single decision layer between data and the model. For each
#               finding it: (1) checks the verdict cache (C13), (2) DAL-redacts
#               so the model never sees PII, (3) grounds with RAG (C9), (4) runs
#               the five agents against Gemma (C7), (5) merges one verdict.
# REAL-WORLD  : Python + asyncio. Owns the DAL, the three-tier router (cache →
#               GBDT instinct → LLM), and CTG replay. We model the cache tier +
#               the LLM tier (the instinct GBDT tier is out of scope for an MVP).
# DATA FLOW   : C6 normalised finding ─▶ [C13 cache?] ─▶ DAL ─▶ RAG(C9) ─▶
#               5 agents ─▶ Gemma(C7) ─▶ rehydrate ─▶ verdict ─▶ (C8 persists).
# INSIGHT     : Notice the model is the LAST resort, wrapped in cache + DAL +
#               grounding + validation. The orchestration around an LLM is what
#               makes it trustworthy and affordable — the call itself is 6 lines.
from __future__ import annotations
import copy
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor

from . import agents, config, rag
from .compliance import CIS_CONTROLS, validate_controls, nist_for_controls
from .dal import DAL
from .containers import c6_normaliser as c6      # deterministic triage (no LLM)
from .containers import c13_valkey as cache       # verdict cache
from .containers import c12_operations as ops


def _finding_id(raw: str) -> str:
    h = hashlib.sha256(f"{raw}{time.time()}".encode()).hexdigest()[:12]
    return f"F-{h}"


def _redact_finding(raw_finding: dict, dal: DAL) -> dict:
    """Copy the finding with every real identifier swapped for a DAL placeholder.

    C6 normalises RAW text (so it can join real IPs against threat intel). But
    the AGENTS talk to Gemma, so their view must be redacted. We reuse the same
    DAL token map, and collapse intel hits to counts (never raw values).
    """
    f = copy.deepcopy(raw_finding)
    ent = f.get("entities", {})
    # Field-aware redaction: usernames are sensitive but no regex catches a bare
    # "root", so we tokenize that field directly. CVE IDs are PUBLIC identifiers
    # the model NEEDS to reason — never redact them. Everything else: regex strip.
    FIELD_KINDS = {"usernames": "USER", "hostnames": "HOST"}
    for k, vals in list(ent.items()):
        if not isinstance(vals, list):
            continue
        if k == "cve_ids":
            continue                                  # public — keep visible
        if k in FIELD_KINDS:
            ent[k] = [dal.tokenize(v, FIELD_KINDS[k]) for v in vals]
        else:
            ent[k] = [dal.strip(str(v)) for v in vals]
    hits = f.get("intel", {}).get("ioc_hits", [])
    f["intel"] = {"ioc_hit_count": len(hits),
                  "kinds": sorted({h["type"] for h in hits})}
    return f


def _ground(redacted: str, finding: dict) -> dict:
    """RAG grounding if the C9 stack returns a STRONG match, else fall back to the
    deterministic candidate controls. Handles three cases: RAG off, RAG on but
    weak (below floor → empty controls), RAG on with good matches."""
    r = rag.retrieve(redacted, finding)
    if r.get("available") and r.get("controls"):
        return r                                    # strong vector + graph grounding
    # RAG unavailable, OR available but every match fell below the relevance floor.
    cands = validate_controls(finding.get("candidate_controls", []))
    reason = r.get("reason", "static") if not r.get("available") else f"rag_weak:{r.get('reason')}"
    return {"available": r.get("available", False), "reason": reason, "controls": cands,
            "snippets": [{"control_id": c, "framework": "cis_v8",
                          "content": CIS_CONTROLS[c], "score": None} for c in cands]}


def _run_agents(finding: dict, ground: dict, enabled: list[str]) -> tuple[list, dict]:
    """Run the 5 agents respecting dependencies + the parallel toggle."""
    outputs: dict[str, dict] = {}
    results: list = []

    def _run(name):
        if name == "risk_scorer":        return agents.run_risk_scorer(finding, ground)
        if name == "compliance_mapper":  return agents.run_compliance_mapper(finding, ground)
        if name == "anomaly_detector":   return agents.run_anomaly_detector(finding, ground)
        return None

    # Independent agents → run together (this is where concurrency buys latency).
    indep = [a for a in enabled if a in ("risk_scorer", "compliance_mapper", "anomaly_detector")]
    if config.PARALLEL_AGENTS and len(indep) > 1:
        with ThreadPoolExecutor(max_workers=len(indep)) as ex:
            for res in ex.map(_run, indep):
                results.append(res); outputs[res.agent] = res.output
    else:
        for a in indep:
            res = _run(a); results.append(res); outputs[res.agent] = res.output

    # Remediation depends on the compliance mapping.
    if "remediation_generator" in enabled:
        res = agents.run_remediation_generator(finding, outputs.get("compliance_mapper", {}), ground)
        results.append(res); outputs[res.agent] = res.output
    # The report depends on everything else.
    if "report_generator" in enabled:
        res = agents.run_report_generator(finding, outputs)
        results.append(res); outputs[res.agent] = res.output
    return results, outputs


def analyze(raw_log: str, log_type: str = "auto",
            want_agents: list[str] | None = None) -> dict:
    """Analyse ONE event end to end. Pure: returns the record, does not persist.
    Callers persist exactly once (API directly, or C8 from the bus)."""
    t0 = time.time()
    enabled = want_agents or config.enabled_agents()
    dal = DAL()

    # 1. Deterministic triage (C6) on RAW; then redact for the model.
    raw_finding = c6.normalise(raw_log, log_type)
    redacted = dal.strip(raw_log)
    finding = _redact_finding(raw_finding, dal)

    # 2. Verdict cache (C13): identical finding shape → skip the 5 Gemma calls.
    cached = cache.get_verdict(finding)
    if cached:
        return {"finding_id": _finding_id(raw_log), "log_type": finding["log_type"],
                "finding": dal.rehydrate_obj(finding), "verdict": cached, "agents": [],
                "rag": {"available": False, "reason": "verdict_cache_hit"},
                "dal": dal.report(), "cache_hit": True,
                "total_latency_ms": int((time.time() - t0) * 1000)}

    # 3. Grounding (C9 RAG or static map)
    ground = _ground(redacted, finding)

    # 4. The 5 agents (each a Gemma call) — timed for the Ops/stress view.
    with ops.timer("ai_brain_agents_latency"):
        results, outputs = _run_agents(finding, ground, enabled)
    ops.incr("ai_brain_analyses_total")

    # 5. Rehydrate (placeholders → real values) AFTER the model has answered.
    finding = dal.rehydrate_obj(finding)
    for res in results:
        res.output = dal.rehydrate_obj(res.output)

    # 6. Merge one verdict from the agents' specialised outputs.
    risk = outputs.get("risk_scorer", {})
    comp = outputs.get("compliance_mapper", {})
    anom = outputs.get("anomaly_detector", {})
    controls = comp.get("control_ids") or finding.get("candidate_controls", [])
    verdict = {
        "severity": risk.get("severity", "medium"),
        "risk_score": int(risk.get("risk_score", 0) or 0),
        "confidence": float(risk.get("confidence", 0.0) or 0.0),
        "control_ids": controls,
        "nist_subcategories": comp.get("nist_subcategories") or nist_for_controls(controls),
        "hipaa_sections": comp.get("hipaa_sections", []),
        "is_anomaly": bool(anom.get("is_anomaly", False)),
        "summary": finding.get("summary", ""),
    }
    cache.put_verdict(finding, verdict)   # warm the cache for the next identical event

    return {
        "finding_id": _finding_id(raw_log), "log_type": finding.get("log_type", "generic"),
        "finding": finding, "verdict": verdict,
        "agents": [r.model_dump() for r in results],
        "rag": {"available": ground.get("available"), "reason": ground.get("reason"),
                "controls": ground.get("controls", []), "snippets": ground.get("snippets", []),
                "graph_controls": ground.get("graph_controls", [])},
        "dal": dal.report(), "cache_hit": False,
        "total_latency_ms": int((time.time() - t0) * 1000),
    }

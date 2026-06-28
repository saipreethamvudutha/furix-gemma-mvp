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

from . import agents, config, rag, mapping
from .compliance import CIS_CONTROLS, validate_controls, nist_for_controls
from .dal import DAL
from .containers import c6_normaliser as c6      # deterministic triage (no LLM)
from .containers import c13_valkey as cache       # verdict cache
from .containers import c12_operations as ops
from .containers.c4_intel_sync import _FEED as _INTEL_FEED
from .containers.c3_scan_engine import _CATALOG as _SCAN_CATALOG

# Every CVE the appliance recognises deterministically: the KEV intel feed (C4)
# + the scan engine's vulnerability catalog (C3). A finding referencing one of
# these is decided by the scan/intel tier — no model needed.
_KNOWN_CVES = ({c.upper() for c in _INTEL_FEED.get("cve_kev", set())}
               | {row[1].upper() for row in _SCAN_CATALOG})


def _siem_rule(sig: dict, ioc_hits: list) -> str | None:
    """Mirror of the C8 detection rules — which deterministic SIEM rule fires?"""
    if sig.get("malware"):
        return "malware_execution"
    if sig.get("c2_or_exfil") or ioc_hits:
        return "c2_or_exfil_or_ioc"
    if sig.get("failed_logins") and sig.get("successful_logins"):
        return "brute_force_success"
    if sig.get("privilege_escalation"):
        return "privilege_escalation"
    if sig.get("account_creation"):
        return "unauthorized_account"
    return None


def _classify_decision(raw_finding: dict, comp_map: dict) -> dict:
    """Which TIER decided this event — and was the model needed at all?

    Order = most authoritative / cheapest first. The LLM is reached ONLY when no
    deterministic engine (scan CVE catalog, SIEM detection rule, compliance
    crosswalk) can resolve the event — i.e. it is genuinely novel.
    """
    ent = raw_finding.get("entities", {})
    sig = raw_finding.get("signals", {})
    ioc_hits = raw_finding.get("intel", {}).get("ioc_hits", [])
    cves = [c.upper() for c in ent.get("cve_ids", [])]

    known_cve = next((c for c in cves if c in _KNOWN_CVES), None)
    if known_cve:
        return {"by": "scan_engine", "engine": "Scan Engine · CVE catalog",
                "detail": f"known exploited CVE {known_cve}", "deterministic": True}

    rule = _siem_rule(sig, ioc_hits)
    if rule:
        return {"by": "siem_rule", "engine": "SIEM · detection rule",
                "detail": rule, "deterministic": True}

    if comp_map.get("control_ids") and not comp_map.get("needs_llm"):
        return {"by": "compliance_rule", "engine": "Compliance · rule + crosswalk",
                "detail": "mapped by control keyword / crosswalk", "deterministic": True}

    if comp_map.get("needs_llm"):
        return {"by": "llm", "engine": "AI Brain · Gemma (escalated)",
                "detail": "novel event — no rule, CVE, or control matched", "deterministic": False}

    return {"by": "deterministic", "engine": "Normaliser · no risk signal",
            "detail": "benign — no detection signal fired", "deterministic": True}


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


def _run_agents(finding: dict, ground: dict, enabled: list[str],
                comp_map: dict, explicit: bool = False) -> tuple[list, dict, list]:
    """Run the agents respecting dependencies + the parallel toggle.

    `comp_map` is the already-resolved DETERMINISTIC compliance mapping. The
    compliance_mapper (Gemma) is expected to have been filtered out of `enabled`
    by the caller unless this event is the unknown case — see analyze().
    Narrative agents (remediation/report) run ON-DEMAND: only if severity meets
    NARRATIVE_MIN_SEVERITY, or `explicit` (the caller asked for them by name)."""
    outputs: dict[str, dict] = {}
    results: list = []
    skipped: list[str] = []

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

    # ON-DEMAND gate: the narrative agents are the remaining Gemma load. Run them
    # only for serious events (or explicit request) — everything else gets the
    # deterministic verdict + mapping and can generate narrative later on click.
    severity = outputs.get("risk_scorer", {}).get("severity", "medium")
    # Narrative is ON-DEMAND by default: it runs only when the caller explicitly
    # asks (analyst clicks "generate report"), or when NARRATIVE_AUTO is enabled.
    # This keeps routine detection fully deterministic — zero Gemma calls.
    run_narrative = explicit or (config.NARRATIVE_AUTO and config.severity_meets(severity))

    if "remediation_generator" in enabled:
        if run_narrative:
            mapping_for_remediation = {"control_ids": comp_map.get("control_ids", []),
                                       "nist_subcategories": comp_map.get("nist_subcategories", []),
                                       "hipaa_sections": comp_map.get("hipaa_sections", [])}
            res = agents.run_remediation_generator(finding, mapping_for_remediation, ground)
            results.append(res); outputs[res.agent] = res.output
        else:
            skipped.append("remediation_generator")
    if "report_generator" in enabled:
        if run_narrative:
            res = agents.run_report_generator(finding, outputs)
            results.append(res); outputs[res.agent] = res.output
        else:
            skipped.append("report_generator")
    return results, outputs, skipped


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
    #    BUT skip the cache when the caller explicitly named agents (e.g. analyst
    #    clicked "Generate AI Report") — they want fresh narrative, not a cached
    #    deterministic verdict that never ran the requested Gemma agents.
    explicit = want_agents is not None
    cached = None if explicit else cache.get_verdict(finding)
    if cached:
        return {"finding_id": _finding_id(raw_log), "log_type": finding["log_type"],
                "finding": dal.rehydrate_obj(finding), "verdict": cached, "agents": [],
                "compliance": {"primary_tier": "verdict_cache", "tiers_used": ["verdict_cache"],
                               "provenance": {}, "confidence": None, "authoritative": True,
                               "needs_review": False, "llm_used": False,
                               "rationale": "Served from the deterministic verdict cache."},
                "rag": {"available": False, "reason": "verdict_cache_hit"},
                "dal": dal.report(), "cache_hit": True,
                "total_latency_ms": int((time.time() - t0) * 1000)}

    # 3. Grounding (C9 RAG or static map)
    ground = _ground(redacted, finding)

    # 3b. DETERMINISTIC compliance mapping FIRST (code, no LLM): rules + crosswalk
    #     + embeddings. This is the authoritative path. The Gemma compliance_mapper
    #     is only kept in `enabled` for the UNKNOWN case (nothing matched) and only
    #     when COMPLIANCE_LLM_FALLBACK is on. Known events skip that Gemma call.
    det_map = mapping.resolve(finding, ground)
    enabled = list(enabled)
    use_llm_mapper = det_map["needs_llm"] and config.COMPLIANCE_LLM_FALLBACK
    if "compliance_mapper" in enabled and not use_llm_mapper:
        enabled.remove("compliance_mapper")
    if use_llm_mapper:
        ops.incr("compliance_llm_fallback_total")
    else:
        ops.incr("compliance_deterministic_total")

    # 4. The agents — timed for the Ops/stress view. `explicit` = the caller named
    #    agents (e.g. analyst clicked "generate remediation"), so always run them.
    explicit = want_agents is not None
    with ops.timer("ai_brain_agents_latency"):
        results, outputs, narrative_skipped = _run_agents(finding, ground, enabled, det_map, explicit)
    ops.incr("ai_brain_analyses_total")

    # 4b. Settle the compliance mapping: deterministic stands as-is; for the
    #     unknown case fold the LLM suggestion in (validated, non-authoritative).
    comp_map = mapping.merge_llm_suggestion(det_map, outputs.get("compliance_mapper"))

    # 5. Rehydrate (placeholders → real values) AFTER the model has answered.
    finding = dal.rehydrate_obj(finding)
    for res in results:
        res.output = dal.rehydrate_obj(res.output)

    # 6. Merge one verdict. Compliance fields come from the AUTHORITATIVE
    #    deterministic mapping (comp_map), NOT from a raw LLM agent output.
    risk = outputs.get("risk_scorer", {})
    anom = outputs.get("anomaly_detector", {})
    controls = comp_map.get("control_ids", [])
    # Which tier actually decided this event (scan CVE / SIEM rule / compliance /
    # novel→LLM)? Classify on the RAW finding so we still see real CVEs/signals.
    decision = _classify_decision(raw_finding, comp_map)
    verdict = {
        "severity": risk.get("severity", "medium"),
        "risk_score": int(risk.get("risk_score", 0) or 0),
        "confidence": float(risk.get("confidence", 0.0) or 0.0),
        "control_ids": controls,
        "nist_subcategories": comp_map.get("nist_subcategories", []),
        "hipaa_sections": comp_map.get("hipaa_sections", []),
        "is_anomaly": bool(anom.get("is_anomaly", False)),
        "summary": finding.get("summary", ""),
        # Decision provenance: was the model needed, and which engine decided?
        "decided_by": decision["by"],
        "decision_engine": decision["engine"],
        "decision_detail": decision["detail"],
        "deterministic": decision["deterministic"],
    }
    cache.put_verdict(finding, verdict)   # warm the cache for the next identical event

    return {
        "finding_id": _finding_id(raw_log), "log_type": finding.get("log_type", "generic"),
        "finding": finding, "verdict": verdict,
        # Original vs DAL-redacted text, so the UI can show clients the privacy step.
        "original_log": raw_log[:600],
        "redacted_log": redacted[:600],
        "agents": [r.model_dump() for r in results],
        # Provenance for the mapping: which tier decided it, per-control sources,
        # whether the LLM was needed, and whether a human should review.
        "compliance": {
            "primary_tier": comp_map.get("primary_tier"),
            "tiers_used": comp_map.get("tiers_used", []),
            "provenance": comp_map.get("provenance", {}),
            "confidence": comp_map.get("confidence"),
            "authoritative": comp_map.get("authoritative"),
            "needs_review": comp_map.get("needs_review", False),
            "llm_used": use_llm_mapper,
            "rationale": comp_map.get("rationale"),
        },
        # Narrative agents deferred (on-demand): below NARRATIVE_MIN_SEVERITY they
        # are skipped to save Gemma; re-run later via analyze(..., want_agents=[...]).
        "narrative": {"skipped": narrative_skipped,
                      "reason": (f"severity '{verdict['severity']}' < "
                                 f"NARRATIVE_MIN_SEVERITY '{config.NARRATIVE_MIN_SEVERITY}'"
                                 if narrative_skipped else "")},
        "rag": {"available": ground.get("available"), "reason": ground.get("reason"),
                "controls": ground.get("controls", []), "snippets": ground.get("snippets", []),
                "graph_controls": ground.get("graph_controls", [])},
        "dal": dal.report(), "cache_hit": False,
        "total_latency_ms": int((time.time() - t0) * 1000),
    }

"""CONTAINER C14 · The five Praxis agents. Each = one strict Gemma call + validation.

Every agent returns an AgentResult (schemas.AgentResult-compatible dict). Output
is validated against the closed compliance catalogs so a hallucinated control ID
never escapes. Mock outputs keep the whole pipeline runnable offline.
"""
from __future__ import annotations
from typing import Any

from . import prompts
from .llm import complete_json, LLMResult
from .compliance import (validate_controls, validate_nist, validate_hipaa,
                         nist_for_controls, SEVERITIES)
from .schemas import AgentResult


def _result(name: str, r: LLMResult, output: dict) -> AgentResult:
    return AgentResult(
        agent=name, ok=bool(output) and r.source != "fallback", output=output,
        latency_ms=r.latency_ms, prompt_tokens=r.prompt_tokens,
        completion_tokens=r.completion_tokens, source=r.source, error=r.error,
    )


def _clamp_sev(sev: str) -> str:
    sev = (sev or "").strip().lower()
    return sev if sev in SEVERITIES else "medium"


# ── 1. Risk Scorer ───────────────────────────────────────────────────────────
def _mock_severity(sig: dict) -> tuple[str, int]:
    benign = sig.get("successful_logins") and not any(
        sig.get(k) for k in ("malware", "c2_or_exfil", "account_creation", "lateral_movement"))
    if sig.get("malware") or sig.get("c2_or_exfil"):
        return "critical", 90
    if sig.get("account_creation") or sig.get("lateral_movement"):
        return "high", 72
    if benign:
        return "informational", 8
    if sig.get("privilege_escalation"):
        return "high", 68
    if sig.get("failed_logins"):
        return "medium", 50
    return "medium", 45


def run_risk_scorer(finding: dict, rag: dict | None = None) -> AgentResult:
    sig = finding.get("signals", {})
    sev, score = _mock_severity(sig)
    mock = {"severity": sev, "risk_score": score, "confidence": 0.6,
            "rationale": "Mock score (offline).", "top_factors": [k for k, v in sig.items() if v][:3]}
    r = complete_json(prompts.RISK_SYS, prompts.risk_user(finding, rag),
                      max_tokens=400, mock=mock)
    out = dict(r)
    if out:
        out["severity"] = _clamp_sev(out.get("severity"))
        try:
            out["risk_score"] = max(0, min(100, int(out.get("risk_score", 0))))
        except (TypeError, ValueError):
            out["risk_score"] = 0
    return _result("risk_scorer", r, out)


# ── 2. Compliance Mapper (LLM FALLBACK ONLY — non-authoritative) ──────────────
# Compliance mapping is normally done deterministically in mapping.py (rules +
# crosswalk + embeddings). brain.py invokes THIS agent only for the unknown case
# (no deterministic tier matched) and treats its output as a reviewable
# suggestion, re-validated and crosswalk-expanded before it is shown. It is never
# the system of record.
def run_compliance_mapper(finding: dict, rag: dict | None = None) -> AgentResult:
    cand = finding.get("candidate_controls", [])
    mock = {"control_ids": validate_controls(cand) or ["Control 8"],
            "nist_subcategories": nist_for_controls(validate_controls(cand) or ["Control 8"])[:4],
            "hipaa_sections": ["164.312b"], "rationale": "Mock mapping.", "confidence": 0.6}
    r = complete_json(prompts.COMPLIANCE_SYS, prompts.compliance_user(finding, rag),
                      max_tokens=600, mock=mock)
    out = dict(r)
    if out:
        out["control_ids"] = validate_controls(out.get("control_ids", []))
        nist = validate_nist(out.get("nist_subcategories", []))
        # enrich with deterministic crosswalk so mapping is never empty
        for sc in nist_for_controls(out["control_ids"]):
            if sc not in nist:
                nist.append(sc)
        out["nist_subcategories"] = nist
        out["hipaa_sections"] = validate_hipaa(out.get("hipaa_sections", []))
    return _result("compliance_mapper", r, out)


# ── 3. Remediation Generator ─────────────────────────────────────────────────
def run_remediation_generator(finding: dict, mapping: dict,
                              rag: dict | None = None) -> AgentResult:
    mock = {"priority": "high", "effort": "medium",
            "steps": [{"order": 1, "action": "Isolate affected host and rotate credentials.",
                       "rationale": "Stops active harm.", "control_ref": "Control 6"}],
            "containment": ["Block source IP at the firewall."]}
    r = complete_json(prompts.REMEDIATION_SYS,
                      prompts.remediation_user(finding, mapping, rag),
                      max_tokens=700, mock=mock)
    return _result("remediation_generator", r, dict(r))


# ── 4. Anomaly Detector ──────────────────────────────────────────────────────
def run_anomaly_detector(finding: dict, rag: dict | None = None) -> AgentResult:
    sig = finding.get("signals", {})
    anom = any(sig.get(k) for k in ("malware", "c2_or_exfil",
                                    "lateral_movement", "account_creation"))
    mock = {"is_anomaly": bool(anom), "anomaly_type": "process" if anom else "none",
            "confidence": 0.6, "explanation": "Mock anomaly assessment.",
            "indicators": [k for k, v in sig.items() if v][:3]}
    r = complete_json(prompts.ANOMALY_SYS, prompts.anomaly_user(finding, rag),
                      max_tokens=400, mock=mock)
    out = dict(r)
    if out:
        out["is_anomaly"] = bool(out.get("is_anomaly"))
    return _result("anomaly_detector", r, out)


# ── 5. Report Generator ──────────────────────────────────────────────────────
def run_report_generator(finding: dict, agent_outputs: dict) -> AgentResult:
    mock = {"executive_summary": "Mock report — Gemma offline.",
            "attack_narrative": "", "business_impact": "",
            "remediation_roadmap": "", "compliance_posture": ""}
    r = complete_json(prompts.REPORT_SYS, prompts.report_user(finding, agent_outputs),
                      max_tokens=900, mock=mock)
    return _result("report_generator", r, dict(r))

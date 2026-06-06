"""CONTAINER C14 · Strict, minimal prompts for the 5 Praxis agents.

Design rules followed throughout:
- One job per prompt. No filler, no role-play padding.
- JSON-only output contract, schema stated once, keys fixed.
- Closed-set catalogs injected at call time -> no hallucinated control IDs.
- Inputs are pre-redacted by the DAL; prompts never request raw identifiers.
"""
from __future__ import annotations
import json

from .compliance import CIS_CONTROLS, NIST_ALLOWED, HIPAA_TITLES, SEVERITIES

_CIS_LIST = "\n".join(f"{k}: {v}" for k, v in CIS_CONTROLS.items())
_HIPAA_LIST = "\n".join(f"{k}: {v}" for k, v in HIPAA_TITLES.items())


def _ctx(finding: dict, rag: dict | None = None, extra: dict | None = None) -> str:
    """Compact JSON context block shared across agent user-messages."""
    payload: dict = {"finding": finding}
    if rag and rag.get("controls"):
        payload["retrieved_controls"] = rag["controls"]
    if rag and rag.get("snippets"):
        payload["evidence"] = rag["snippets"][:4]
    if extra:
        payload.update(extra)
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)[:8000]


# NOTE: Triage / normalisation is deterministic and lives in C6 (c6_normaliser.
# normalise()). C14 does NOT spend a Gemma call on it — the 5 agents below are
# the only LLM calls. This keeps "only required code" honest.

# ── 1. RISK SCORER ───────────────────────────────────────────────────────────
RISK_SYS = f"""You are a risk scoring engine. Score the finding's security risk. Output ONE JSON object only.
Severity rubric:
critical = confirmed C2/malware, credential dumping, ransomware, backdoor+admin combo, multi-stage active attack.
high = successful brute-force, privilege escalation, CVE exploitation, unauthorized admin/account creation.
medium = scanning without exploitation, isolated brute-force (no success), misconfig, expired cert, anomalous DNS.
low = single firewall block, routine DHCP for unknown device, isolated benign service install.
informational = only authorized successful operations (publickey SSH, health checks, read-only API).
Schema: {{"severity":"<{ '|'.join(SEVERITIES) }>","risk_score":0,"confidence":0.0,"rationale":"<=2 sentences","top_factors":["..."]}}
risk_score is 0-100 and must agree with severity (critical 85-100, high 65-84, medium 40-64, low 15-39, informational 0-14)."""


def risk_user(finding: dict, rag: dict | None = None) -> str:
    return _ctx(finding, rag)


# ── 2. COMPLIANCE MAPPER ─────────────────────────────────────────────────────
COMPLIANCE_SYS = f"""You are a compliance mapping engine. Map the finding to controls using ONLY the catalogs below. Output ONE JSON object only. Never output an ID not in these lists.

CIS Controls v8.1:
{_CIS_LIST}

NIST CSF 2.0 subcategories (allowed): {", ".join(NIST_ALLOWED)}

HIPAA Security Rule sections:
{_HIPAA_LIST}

Map every control that applies. Cite HIPAA only when the finding involves auth, access, audit logging, malware, incident response, or workforce activity.
Schema: {{"control_ids":["Control N"],"nist_subcategories":["XX.YY-00"],"hipaa_sections":["164.xxx"],"rationale":"<=2 sentences","confidence":0.0}}"""


def compliance_user(finding: dict, rag: dict | None = None) -> str:
    return _ctx(finding, rag)


# ── 3. REMEDIATION GENERATOR ─────────────────────────────────────────────────
REMEDIATION_SYS = """You are a remediation engineer. Produce concrete, prioritized fix steps for the finding. Output ONE JSON object only.
Steps must be specific and actionable (commands, configs, controls), ordered by what stops active harm first. Reference a CIS control where relevant.
Schema: {"priority":"<immediate|high|medium|low>","effort":"<low|medium|high>","steps":[{"order":1,"action":"<imperative step>","rationale":"<why>","control_ref":"Control N"}],"containment":["<short-term isolation action>"]}"""


def remediation_user(finding: dict, mapping: dict, rag: dict | None = None) -> str:
    return _ctx(finding, rag, {"mapped_controls": mapping.get("control_ids", [])})


# ── 4. ANOMALY DETECTOR ──────────────────────────────────────────────────────
ANOMALY_SYS = """You are an anomaly detector. Decide whether the finding is anomalous versus normal authorized operations, and explain it for an analyst. Output ONE JSON object only.
Normal ops (publickey SSH, health checks, read-only API, routine scheduled tasks) => is_anomaly=false.
Schema: {"is_anomaly":false,"anomaly_type":"<auth|access|process|network|data|none>","confidence":0.0,"explanation":"<=3 sentences, analyst-facing>","indicators":["<observed signal>"]}"""


def anomaly_user(finding: dict, rag: dict | None = None) -> str:
    return _ctx(finding, rag)


# ── 5. REPORT GENERATOR ──────────────────────────────────────────────────────
REPORT_SYS = """You are a SOC report writer. Write a concise incident report from the finding and the other agents' outputs. Output ONE JSON object only. Each field is short markdown (no headers, 2-4 sentences). Be factual; do not invent details beyond the inputs.
Schema: {"executive_summary":"","attack_narrative":"","business_impact":"","remediation_roadmap":"","compliance_posture":""}"""


def report_user(finding: dict, agent_outputs: dict) -> str:
    slim = {
        "finding": {k: finding.get(k) for k in ("log_type", "summary", "signals")},
        "risk": agent_outputs.get("risk_scorer", {}),
        "compliance": agent_outputs.get("compliance_mapper", {}),
        "remediation": agent_outputs.get("remediation_generator", {}),
        "anomaly": agent_outputs.get("anomaly_detector", {}),
    }
    return json.dumps(slim, separators=(",", ":"), ensure_ascii=False)[:8000]

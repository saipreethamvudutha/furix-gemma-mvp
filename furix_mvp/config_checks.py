"""Config-state compliance checking — the "is the control IMPLEMENTED?" half.

Event mapping (mapping.py) answers "did something happen?". This module answers
the other half of compliance: "is the system actually configured securely?" — the
job Tenable/Qualys do with SCAP/OVAL and Wiz/Prowler do with policy-as-code.

It is a deterministic policy engine: each check is a pure function over a config
snapshot that returns pass / fail / na, mapped to CIS controls (and, via the SCF
crosswalk, to every other framework). NO LLM, NO external binary — same input
always yields the same posture, which is what an auditor needs.

These checks mirror CIS-Benchmark / OVAL / OPA-Rego rules; in production you would
load OVAL/SCAP content or OPA bundles, but the evaluation harness and the
control-mapping are exactly this.

Input — a normalized config snapshot, e.g.:
    {
      "aws_account": {"root_mfa_enabled": false,
                      "password_policy": {"min_length": 8}},
      "iam_users":   [{"name": "alice", "mfa_enabled": true},
                      {"name": "svc",   "mfa_enabled": false}],
      "s3_buckets":  [{"name": "data", "public": true, "encrypted": false}],
      "cloudtrail":  {"enabled": false},
      "security_groups": [{"name": "sg-1", "open_ingress": [{"cidr": "0.0.0.0/0", "port": 22}]}],
      "tls_endpoints": [{"name": "api", "min_version": "1.0"}],
      "backups":     {"configured": false},
    }
Missing sections → those checks return "na" (not assessed), never a false fail.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .compliance import frameworks_for_controls

PASS, FAIL, NA = "pass", "fail", "na"


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    control_ids: tuple[str, ...]
    severity: str
    # fn(config) -> (status, evidence_str). Return NA if the data isn't present.
    fn: Callable[[dict], tuple[str, str]]


# ── individual checks (each mirrors a CIS-Benchmark / OVAL / Rego rule) ───────
def _root_mfa(cfg):
    acct = cfg.get("aws_account")
    if not acct or "root_mfa_enabled" not in acct:
        return NA, "no aws_account.root_mfa_enabled in snapshot"
    ok = bool(acct["root_mfa_enabled"])
    return (PASS if ok else FAIL), f"root_mfa_enabled={acct['root_mfa_enabled']}"


def _iam_user_mfa(cfg):
    users = cfg.get("iam_users")
    if users is None:
        return NA, "no iam_users in snapshot"
    bad = [u.get("name", "?") for u in users if not u.get("mfa_enabled")]
    return (FAIL, f"users without MFA: {bad}") if bad else (PASS, f"all {len(users)} users have MFA")


def _password_min_length(cfg):
    pol = (cfg.get("aws_account") or {}).get("password_policy")
    if not pol or "min_length" not in pol:
        return NA, "no password_policy.min_length"
    n = pol["min_length"]
    return (PASS if n >= 14 else FAIL), f"min_length={n} (require >=14)"


def _s3_public(cfg):
    buckets = cfg.get("s3_buckets")
    if buckets is None:
        return NA, "no s3_buckets in snapshot"
    pub = [b.get("name", "?") for b in buckets if b.get("public")]
    return (FAIL, f"public buckets: {pub}") if pub else (PASS, f"{len(buckets)} buckets non-public")


def _s3_encryption(cfg):
    buckets = cfg.get("s3_buckets")
    if buckets is None:
        return NA, "no s3_buckets in snapshot"
    un = [b.get("name", "?") for b in buckets if not b.get("encrypted")]
    return (FAIL, f"unencrypted buckets: {un}") if un else (PASS, f"{len(buckets)} buckets encrypted")


def _cloudtrail(cfg):
    ct = cfg.get("cloudtrail")
    if not ct or "enabled" not in ct:
        return NA, "no cloudtrail.enabled"
    return (PASS if ct["enabled"] else FAIL), f"cloudtrail.enabled={ct['enabled']}"


def _open_ssh(cfg):
    sgs = cfg.get("security_groups")
    if sgs is None:
        return NA, "no security_groups in snapshot"
    bad = []
    for sg in sgs:
        for rule in sg.get("open_ingress", []):
            if rule.get("cidr") == "0.0.0.0/0" and rule.get("port") in (22, 3389):
                bad.append(f"{sg.get('name','?')}:{rule.get('port')}")
    return (FAIL, f"world-open admin ports: {bad}") if bad else (PASS, "no world-open SSH/RDP")


def _tls_min(cfg):
    eps = cfg.get("tls_endpoints")
    if eps is None:
        return NA, "no tls_endpoints in snapshot"
    bad = [e.get("name", "?") for e in eps if str(e.get("min_version", "0")) < "1.2"]
    return (FAIL, f"weak TLS endpoints: {bad}") if bad else (PASS, "all endpoints TLS>=1.2")


def _backups(cfg):
    b = cfg.get("backups")
    if not b or "configured" not in b:
        return NA, "no backups.configured"
    return (PASS if b["configured"] else FAIL), f"backups.configured={b['configured']}"


# ── the policy registry (data-driven; add rows here) ─────────────────────────
CHECKS: list[Check] = [
    Check("CFG-ROOT-MFA",    "Root account uses MFA",                ("Control 6",),  "critical", _root_mfa),
    Check("CFG-IAM-MFA",     "All IAM users have MFA",               ("Control 6",),  "high",     _iam_user_mfa),
    Check("CFG-PW-LEN",      "Password policy >= 14 chars",          ("Control 5",),  "medium",   _password_min_length),
    Check("CFG-S3-PUBLIC",   "No public object storage",             ("Control 3",),  "high",     _s3_public),
    Check("CFG-S3-ENC",      "Object storage encrypted at rest",     ("Control 3",),  "high",     _s3_encryption),
    Check("CFG-AUDIT-LOG",   "Audit logging (CloudTrail) enabled",   ("Control 8",),  "high",     _cloudtrail),
    Check("CFG-NET-SSH",     "No world-open SSH/RDP",                ("Control 12",), "critical", _open_ssh),
    Check("CFG-TLS-MIN",     "TLS 1.2+ enforced",                    ("Control 4",),  "medium",   _tls_min),
    Check("CFG-BACKUP",      "Backups configured",                   ("Control 11",), "high",     _backups),
]


def evaluate(config: dict) -> dict:
    """Run all checks against a config snapshot. Deterministic; no LLM.

    Returns findings (each control-mapped + framework-expanded), a pass/fail/na
    summary, the failed controls, and a per-control posture.
    """
    findings = []
    posture: dict[str, str] = {}
    for chk in CHECKS:
        status, evidence = chk.fn(config)
        findings.append({
            "check_id": chk.id,
            "title": chk.title,
            "status": status,
            "severity": chk.severity if status == FAIL else "informational",
            "control_ids": list(chk.control_ids),
            "frameworks": frameworks_for_controls(list(chk.control_ids)),
            "evidence": evidence,
        })
        # roll up per-control posture: any fail -> fail; else any pass -> pass; else na
        for c in chk.control_ids:
            if status == FAIL:
                posture[c] = FAIL
            elif posture.get(c) != FAIL and status == PASS:
                posture[c] = PASS
            else:
                posture.setdefault(c, NA)

    counts = {PASS: 0, FAIL: 0, NA: 0}
    for f in findings:
        counts[f["status"]] += 1
    failed_controls = sorted({c for c, s in posture.items() if s == FAIL})
    assessed = counts[PASS] + counts[FAIL]
    return {
        "findings": findings,
        "summary": {**counts, "total": len(findings),
                    "score": round(counts[PASS] / assessed, 3) if assessed else None},
        "failed_controls": failed_controls,
        "posture": posture,
        "source": "config-state policy-as-code (deterministic, no LLM)",
    }

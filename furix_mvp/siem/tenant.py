"""Tenant profile — the org-specific assets the SIEM engine keys on.

The source engine baked one fake tenant ("Coventra Health Insurance") directly
into its parsers, rules, and PII scrubber. Centralising those values here — each
overridable via a ``SIEM_TENANT_*`` env var — lets the same detection code serve a
different organisation without edits. This module is grown one port-module at a
time; Module 2 seeds the constants the ECS ingestion parsers reference.
"""
from __future__ import annotations
import os
import re


def _csv_env(key: str, default: list[str]) -> list[str]:
    """Comma-separated env override → list, else the in-code default."""
    raw = os.environ.get(key, "")
    items = [x.strip() for x in raw.split(",") if x.strip()]
    return items or list(default)


def _int_env(key: str, default: int) -> int:
    """Integer env override, else the in-code default."""
    try:
        return int(os.environ.get(key, "").strip())
    except (TypeError, ValueError):
        return default


# Organisation name stamped on every ECS record (``organization.name``).
ORG_NAME = os.environ.get("SIEM_TENANT_ORG", "Coventra Health Insurance")

# Cloud object stores holding PHI — CloudTrail access to these escalates severity.
PHI_BUCKETS = set(_csv_env(
    "SIEM_TENANT_PHI_BUCKETS",
    ["coventra-phi-backup", "coventra-claims-archive"],
))

# Executive-role username / email fragments — the BEC email-targeting heuristic
# flags a message whose recipient contains any of these.
EXEC_ROLE_PREFIXES = _csv_env(
    "SIEM_TENANT_EXEC_PREFIXES",
    ["cfo", "ciso", "vp_", "cio", "ceo"],
)

# Privileged-access (PAM) vault identity — used as a fallback when a CyberArk
# record omits the device IP, and as the observer name on PAM events.
PAM_VAULT_IP = os.environ.get("SIEM_TENANT_PAM_VAULT_IP", "10.30.6.10")
PAM_VAULT_NAME = os.environ.get("SIEM_TENANT_PAM_VAULT_NAME", "pam-vault-01")


# ── Rule-engine org assets (Module 3) ─────────────────────────────────────────
# Signature rules key on these to recognise the org's crown-jewel systems. They
# stay in code (not rules.json) because they need Python types (sets / regex);
# each is env-overridable so a different customer is served without code edits.

# PHI database servers — direct access to these (esp. from a workstation or an
# external/vendor IP, bypassing PAM) is a high-severity signal.
PHI_DB_IPS = set(_csv_env("SIEM_TENANT_PHI_DB_IPS", ["10.30.1.10", "10.30.1.11"]))

# Workstation subnet prefix — a workstation reaching a PHI DB is anomalous.
WS_SUBNET_PREFIX = os.environ.get("SIEM_TENANT_WS_SUBNET_PREFIX", "10.10.")

# Immutable audit / SIEM repositories — delete/modify here = audit-tampering.
AUDIT_REPOS = set(_csv_env(
    "SIEM_TENANT_AUDIT_REPOS",
    ["audit-repo-01", "audit-repo-02", "splunk-idx-01", "splunk-idx-02"],
))

# The only service account approved to perform HSM key operations; any other
# actor on an HSM op is a credential-theft / insider signal.
HSM_APPROVED_ACTOR = os.environ.get("SIEM_TENANT_HSM_APPROVED_ACTOR", "svc_cyberark_pam")

# PHI database tables — a bulk SELECT touching these escalates to a data-theft
# signal once it crosses the row-count threshold below.
PHI_TABLES = set(_csv_env("SIEM_TENANT_PHI_TABLES", [
    "member_health_records", "claim_diagnoses", "rx_history",
    "mental_health_records", "lab_results", "prior_auth_records",
]))

# Row count above which a PHI SELECT counts as "bulk".
BULK_ROW_THRESHOLD = _int_env("SIEM_TENANT_BULK_ROW_THRESHOLD", 1000)

# Business-Email-Compromise look-alike domain patterns. These are HAND-CRAFTED
# character-level mutations of the org's own domain ("coventra") and cannot be
# mechanically derived — REGENERATE these for a different tenant's domain.
BEC_DOMAIN_PATTERNS = [
    re.compile(r'coventr[^a]',                              re.IGNORECASE),
    re.compile(r'c[^o]ventra',                              re.IGNORECASE),
    re.compile(r'coventra[-.](?:secure|portal|login|auth)', re.IGNORECASE),
    re.compile(r'coventra\.(ru|xyz|info|net|biz)',          re.IGNORECASE),
]


# ── DAL PII-scrubber classification assets (Module 5) ─────────────────────────
# The scrubber maps raw identifiers to role-typed placeholders before they reach
# the LLM. These org-identifying values drive that classification; externalised
# so a different tenant is served without editing scrub code.

# The org's own domain — references to it abstract to the INTERNAL_DOMAIN type.
ORG_DOMAIN = os.environ.get("SIEM_TENANT_ORG_DOMAIN", "coventra.com")

# Executive-account username prefixes (scrubber form, trailing underscore) →
# EXEC_USER placeholder. Distinct from EXEC_ROLE_PREFIXES (the email-fragment
# form the ingest BEC heuristic uses).
EXEC_USER_PREFIXES = _csv_env(
    "SIEM_TENANT_EXEC_USER_PREFIXES",
    ["cfo_", "ciso_", "ceo_", "vp_", "president_", "director_"],
)

# Service-account username prefix → SVC_ACCOUNT placeholder.
SVC_ACCOUNT_PREFIX = os.environ.get("SIEM_TENANT_SVC_ACCOUNT_PREFIX", "svc_")

# Look-alike fragments of the org domain seen in phishing/BEC infrastructure →
# ATTACKER_DOMAIN placeholder. Org-name-derived; regenerate per tenant.
ATTACKER_DOMAIN_LOOKALIKES = _csv_env(
    "SIEM_TENANT_ATTACKER_LOOKALIKES",
    ["coventr4", "c0ventra", "coventra-"],
)

# Org-specific PHI dataset / table name fragments → PHI_TABLE placeholder.
# (Generic medical-term fragments stay local in the scrubber.)
PHI_NAME_FRAGMENTS = _csv_env(
    "SIEM_TENANT_PHI_NAME_FRAGMENTS",
    ["coventra_phi", "coventra_members", "claims_dw"],
)


# ── UEBA peer-group rules (Module 6) ──────────────────────────────────────────
# Maps a username to a behavioural peer group so users with too few individual
# observations are scored against their group's baseline. Order matters — first
# substring match wins. These encode org username conventions AND specific named
# accounts, so they are inherently tenant-specific: REPLACE for a different org.
# (Structured data, so this stays a Python literal rather than an env CSV.)
PEER_GROUP_RULES: list[tuple[str, list[str]]] = [
    ("service_acct",  ["svc_"]),
    ("soc",           ["soc_analyst", "infosec_lead", "risk_analyst", "audit_mgr"]),
    ("it_ops",        ["cloud_ops_aws", "sysadmin_ops", "netadmin_", "devops_"]),
    ("dba",           ["dba_oracle", "dba_mssql"]),
    ("compliance",    ["compliance_analyst"]),
    ("leadership",    ["ciso_", "cfo_", "vp_", "ceo_"]),
    ("claims",        ["_clm", "_bil", "cs_rep_", "cjackson", "ybrown", "cjones"]),
]
DEFAULT_PEER_GROUP = "general"

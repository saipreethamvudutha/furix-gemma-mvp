"""
rule_engine.py
--------------
Rule-based threat detection on ECS-structured events.

Rule definitions live in furix_mvp/siem/rules/rules.json — edit that file to
add, remove, tune, or re-tag rules without touching this code.

This file contains only:
  - Field extractor helpers (_src_ip, _msg, etc.)
  - Generic (vendor-neutral) detection constants; tenant-specific org assets
    (PHI_DB_IPS, AUDIT_REPOS, etc.) come from furix_mvp/siem/tenant.py
  - Custom handler functions for complex multi-field rules
  - The CHECK_REGISTRY that maps check_type strings to builder functions
  - RuleEngine class — loader, validator, detect(), score()

34 rules across two layers:
  Layer A — ECS field rules      (structured checks on typed ECS fields)
  Layer B — Pattern file rules   (regex / string matching on message field)

Output per triggered event: a risk_event dict with MITRE context,
kill chain stage, score, and confidence. See detect() docstring.
"""
from __future__ import annotations

import json
import os
import re
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..config import (
    HIGH_RISK_PORTS, MEDIUM_RISK_PORTS,
    PRIVATE_IP_PREFIXES,
    RULE_WEIGHTS_PATH,
    MITRE_TECHNIQUES_PATH,
    RULES_JSON_PATH,           # furix_mvp/siem/rules/rules.json
    RULES_DIR,                 # furix_mvp/siem/rules/ — pattern_file / string_file
                               # references in rules.json are resolved here
)
from ..ingest import get_field


# =============================================================================
#  Organisation-specific asset constants
#  The tenant-specific assets (org systems / accounts) are externalised to the
#  shared tenant profile (furix_mvp/siem/tenant.py, env-overridable), so a
#  different customer is served without editing detection code. The remaining
#  constants here are GENERIC (not tenant-specific) and stay local.
# =============================================================================

from ..tenant import (
    PHI_DB_IPS,
    WS_SUBNET_PREFIX,
    AUDIT_REPOS,
    HSM_APPROVED_ACTOR,
    PHI_BUCKETS as PHI_S3_BUCKETS,
    PHI_TABLES,
    BULK_ROW_THRESHOLD,
    BEC_DOMAIN_PATTERNS,
)

# Generic detection constants (vendor-neutral) — not tenant assets.
PHI_DB_PORTS        = {1521, 1433, 5432, 3306}   # Oracle / MSSQL / Postgres / MySQL
C2_TLDS             = {".ru",".onion",".xyz",".tk",".su",".cc",".to"}


# =============================================================================
#  Pattern / string file loaders
# =============================================================================

def _load_patterns(path: str) -> List[re.Pattern]:
    out: List[re.Pattern] = []
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                out.append(re.compile(line, re.IGNORECASE))
            except re.error:
                pass
    return out


def _load_lines(path: str) -> List[str]:
    out: List[str] = []
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def _load_weights(path: str) -> Dict[str, float]:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError:
            return {}


def _load_mitre(path: str) -> Dict[str, Dict]:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError:
            return {}


# =============================================================================
#  ECS field extractors
# =============================================================================

def _is_private(ip) -> bool:
    return bool(ip) and isinstance(ip, str) and ip.startswith(PRIVATE_IP_PREFIXES)

def _is_workstation(ip) -> bool:
    return bool(ip) and str(ip).startswith(WS_SUBNET_PREFIX)

def _is_phi_db(ip, port) -> bool:
    return ip in PHI_DB_IPS and port in PHI_DB_PORTS

def _offhours(ts_str) -> bool:
    if not ts_str:
        return False
    try:
        from datetime import datetime
        h = datetime.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S").hour
        from ..config import OFFHOURS_START, OFFHOURS_END
        return h >= OFFHOURS_START or h < OFFHOURS_END
    except Exception:
        return False

def _msg(e) -> str:
    return get_field(e, "message") or ""

def _action(e) -> str:
    return (get_field(e, "event.action") or "").lower()

def _outcome(e) -> str:
    return (get_field(e, "event.outcome") or "").lower()

def _module(e) -> str:
    return (get_field(e, "event.module") or "").lower()

def _src_ip(e) -> str:
    return get_field(e, "source.ip") or ""

def _dst_ip(e) -> str:
    return get_field(e, "destination.ip") or ""

def _dst_port(e) -> int:
    return get_field(e, "destination.port") or 0

def _match_patterns(text: str, patterns: List[re.Pattern]) -> bool:
    return any(p.search(text) for p in patterns)

def _match_strings(text: str, strings: List[str]) -> bool:
    tl = text.lower()
    return any(s.lower() in tl for s in strings)

def _is_bec_domain(text: str) -> bool:
    return any(pat.search(text) for pat in BEC_DOMAIN_PATTERNS)

def _has_audit_target(msg: str) -> bool:
    return any(r in msg for r in AUDIT_REPOS)

def _has_c2_tld(msg: str) -> bool:
    return any(tld in msg.lower() for tld in C2_TLDS)

def _proto_app_mismatch(e) -> bool:
    proto = (get_field(e, "network.protocol") or "").lower()
    app   = (get_field(e, "labels.application") or "").lower()
    port  = _dst_port(e)
    if proto == "https":
        if app in ("ssh","rdp","smb","ftp","smtp","telnet"):
            return True
        if port in (22, 25, 23, 445, 3389):
            return True
    if proto in ("http","dns"):
        if port in (1521, 1433, 5432, 3306):
            return True
    return False

def _sensitive_endpoint(e) -> bool:
    SENSITIVE = (
        "/admin","/api/admin","/api/internal","/api/auth/reset",
        "/api/auth/token","/.env","/config","/backup",
        "/api/users/delete","/api/password",
    )
    path = (
        get_field(e, "url.path") or get_field(e, "labels.endpoint") or ""
    ).lower()
    return any(path.startswith(p) for p in SENSITIVE)


# =============================================================================
#  Custom handler functions
#  Complex multi-field rules that cannot be expressed in the JSON schema.
#  Referenced by name from rules.json check_config.handler field.
# =============================================================================

def check_protocol_app_mismatch(e) -> bool:
    return _proto_app_mismatch(e)

def check_outbound_smtp(e) -> bool:
    return (
        _dst_port(e) == 25
        and _is_private(_src_ip(e))
        and not _is_private(_dst_ip(e))
    )

def check_denied_medium_port_offhours(e) -> bool:
    return (
        _outcome(e) == "failure"
        and _dst_port(e) in MEDIUM_RISK_PORTS
        and _offhours(get_field(e, "@timestamp"))
    )

def check_auth_failure(e) -> bool:
    return (
        _module(e) in ("authentication", "application", "web_server")
        and _outcome(e) == "failure"
    )

def check_account_lockout(e) -> bool:
    return (
        "ACCOUNT_LOCKOUT" in _msg(e)
        or _action(e) == "user.account.lock"
        or "account.lock" in (get_field(e, "labels.okta_event_type") or "")
    )

def check_auth_failure_offhours(e) -> bool:
    return (
        _outcome(e) == "failure"
        and _offhours(get_field(e, "@timestamp"))
    )

def check_firewall_allow_high_risk(e) -> bool:
    return (
        _module(e) == "firewall"
        and _action(e) in ("allow", "allowed")
        and _dst_port(e) in HIGH_RISK_PORTS
        and not _is_private(_dst_ip(e))
    )

def check_cloud_offhours_external(e) -> bool:
    return (
        _module(e) == "cloud"
        and _offhours(get_field(e, "@timestamp"))
        and not _is_private(_src_ip(e))
    )

def check_db_external_access(e) -> bool:
    return (
        _module(e) == "database"
        and bool(_src_ip(e))
        and not _is_private(_src_ip(e))
    )

def check_sensitive_endpoint(e) -> bool:
    return _sensitive_endpoint(e)

def check_workstation_to_phi_db(e) -> bool:
    return (
        _is_workstation(_src_ip(e)) and _is_phi_db(_dst_ip(e), _dst_port(e))
    ) or "WORKSTATION_TO_PHI_DB" in _msg(e)

def check_vendor_direct_phi(e) -> bool:
    return (
        not _is_private(_src_ip(e))
        and bool(_src_ip(e))
        and _is_phi_db(_dst_ip(e), _dst_port(e))
    ) or "NO_PAM_SESSION" in _msg(e)

def check_bec_phishing(e) -> bool:
    return (
        _module(e) == "email"
        and (
            get_field(e, "labels.bec_indicator") == True
            or "BEC_INDICATOR" in _msg(e)
            or _is_bec_domain(_msg(e))
            or _is_bec_domain(str(get_field(e, "labels.sender_domain") or ""))
        )
    )

def check_hsm_wrong_actor(e) -> bool:
    return (
        ("HSM_" in _msg(e) or "hsm" in _action(e))
        and bool(get_field(e, "user.name"))
        and get_field(e, "user.name") != HSM_APPROVED_ACTOR
        and "WRONG_ACTOR" in _msg(e)
    ) or (
        get_field(e, "labels.key_identifier", "") != ""
        and get_field(e, "labels.expected_actor", "") != ""
        and get_field(e, "labels.expected_actor") != get_field(e, "user.name")
    )

def check_audit_integrity(e) -> bool:
    return (
        "AUDIT_INTEGRITY_VIOLATION" in _msg(e)
    ) or (
        _has_audit_target(_msg(e))
        and _action(e) in ("delete_attempt","write_to_immutable","delete","modify")
    )

def check_c2_dns_beacon(e) -> bool:
    return (
        "C2_BEACON_PATTERN" in _msg(e) or "DNS_TUNNELING" in _msg(e)
    ) or (
        "DNS_QUERY" in _msg(e) and _has_c2_tld(_msg(e))
    )

def check_credential_stuffing(e) -> bool:
    if "CREDENTIAL_STUFFING" in _msg(e):
        return True
    if _module(e) in ("web_server","application") and _outcome(e) == "failure":
        m = re.search(r'calls=(\d+)', _msg(e))
        if m and int(m.group(1)) > 500:
            return True
    return False

def check_bulk_phi_query(e) -> bool:
    if "BULK_QUERY_ANOMALY" in _msg(e):
        return True
    return (
        _module(e) == "database"
        and _action(e) == "select"
        and (get_field(e, "labels.row_count") or 0) > BULK_ROW_THRESHOLD
        and any(tbl in _msg(e) for tbl in PHI_TABLES)
    )

def check_privilege_escalation(e) -> bool:
    return (
        "UNAUTHORIZED_PRIVILEGE_ESCALATION" in _msg(e)
    ) or (
        "privilege.escalation" in (get_field(e, "labels.okta_event_type") or "")
    ) or (
        "Member_Added_To_Privileged_Group" in _msg(e)
        and "unknown_actor" in _msg(e)
    )

def check_mass_smb_enum(e) -> bool:
    return (
        "MASS_SHARE_ENUM" in _msg(e)
    ) or (
        (get_field(e, "network.protocol") or "").lower() == "smb"
        and (get_field(e, "labels.anomaly_context") or "") != ""
    )

def check_bulk_s3_phi_access(e) -> bool:
    return (
        _module(e) == "cloud"
        and "s3" in (get_field(e, "labels.aws_service") or "")
        and get_field(e, "labels.phi_bucket") == True
        and (get_field(e, "labels.s3_object_count") or 0) > 100
    ) or "BULK_S3_ACCESS" in _msg(e)


# Registry — name -> function. Add new handlers here when rules.json
# references a new handler name.
CUSTOM_HANDLERS: Dict[str, Callable] = {
    "check_protocol_app_mismatch":    check_protocol_app_mismatch,
    "check_outbound_smtp":            check_outbound_smtp,
    "check_denied_medium_port_offhours": check_denied_medium_port_offhours,
    "check_auth_failure":             check_auth_failure,
    "check_account_lockout":          check_account_lockout,
    "check_auth_failure_offhours":    check_auth_failure_offhours,
    "check_firewall_allow_high_risk": check_firewall_allow_high_risk,
    "check_cloud_offhours_external":  check_cloud_offhours_external,
    "check_db_external_access":       check_db_external_access,
    "check_sensitive_endpoint":       check_sensitive_endpoint,
    "check_workstation_to_phi_db":    check_workstation_to_phi_db,
    "check_vendor_direct_phi":        check_vendor_direct_phi,
    "check_bec_phishing":             check_bec_phishing,
    "check_hsm_wrong_actor":          check_hsm_wrong_actor,
    "check_audit_integrity":          check_audit_integrity,
    "check_c2_dns_beacon":            check_c2_dns_beacon,
    "check_credential_stuffing":      check_credential_stuffing,
    "check_bulk_phi_query":           check_bulk_phi_query,
    "check_privilege_escalation":     check_privilege_escalation,
    "check_mass_smb_enum":            check_mass_smb_enum,
    "check_bulk_s3_phi_access":       check_bulk_s3_phi_access,
}


# =============================================================================
#  CHECK_REGISTRY — maps check_type string -> lambda builder
#  Each builder receives (check_config, engine_ref) and returns a lambda
#  that takes one ECS event dict and returns bool.
# =============================================================================

def _build_threat_intel(cfg, eng) -> Callable:
    return lambda e: bool(_src_ip(e)) and _src_ip(e) in eng._threat_intel

def _build_high_risk_port(cfg, eng) -> Callable:
    return lambda e: _dst_port(e) in HIGH_RISK_PORTS

def _build_field_gte(cfg, eng) -> Callable:
    field = cfg["field"]
    value = cfg["value"]
    return lambda e: (get_field(e, field) or 0) >= value

def _build_any_of(cfg, eng) -> Callable:
    markers      = cfg.get("message_markers", [])
    label_checks = cfg.get("label_equals", [])
    def _check(e):
        msg = _msg(e)
        if any(m in msg for m in markers):
            return True
        for lc in label_checks:
            if get_field(e, lc["field"]) == lc["value"]:
                return True
        return False
    return _check

def _build_pattern_file(cfg, eng) -> Callable:
    fname    = cfg["pattern_file"]
    patterns = eng._pattern_cache.get(fname, [])
    return lambda e: _match_patterns(_msg(e), patterns)

def _build_string_file(cfg, eng) -> Callable:
    fname   = cfg["string_file"]
    strings = eng._string_cache.get(fname, [])
    return lambda e: _match_strings(_msg(e), strings)

def _build_regex(cfg, eng) -> Callable:
    pat = re.compile(cfg["pattern"])
    return lambda e: bool(pat.search(_msg(e)))

def _build_custom_handler(cfg, eng) -> Callable:
    name = cfg["handler"]
    fn   = CUSTOM_HANDLERS[name]
    return fn

CHECK_REGISTRY: Dict[str, Callable] = {
    "threat_intel":    _build_threat_intel,
    "high_risk_port":  _build_high_risk_port,
    "field_gte":       _build_field_gte,
    "any_of":          _build_any_of,
    "pattern_file":    _build_pattern_file,
    "string_file":     _build_string_file,
    "regex":           _build_regex,
    "custom_handler":  _build_custom_handler,
}


# =============================================================================
#  MITRE lookup
# =============================================================================

_MITRE: Dict[str, Dict] = _load_mitre(MITRE_TECHNIQUES_PATH)

def _mitre(technique_id: str) -> Dict:
    return _MITRE.get(technique_id, {
        "id": technique_id, "name": "Unknown",
        "tactic": "Unknown", "tactic_id": "",
        "kill_chain_stage": 0,
    })


# =============================================================================
#  RuleEngine
# =============================================================================

class RuleEngine:
    """
    Loads rule definitions from furix_mvp/siem/rules/rules.json and executes
    them against ECS events.

    To add a rule: edit rules.json.
    To tune a boost or MITRE tag: edit rules.json.
    To add a new complex check: add a function to CUSTOM_HANDLERS and
    reference it by name in rules.json with check_type: custom_handler.
    """

    def __init__(self, threat_intel: Optional[set] = None):
        self._threat_intel    = threat_intel or set()
        self._weights         = _load_weights(RULE_WEIGHTS_PATH)
        self._pattern_cache:  Dict[str, List[re.Pattern]] = {}
        self._string_cache:   Dict[str, List[str]]         = {}
        self._rules:          List[Dict[str, Any]]         = []
        self._load()

    # ------------------------------------------------------------------ #
    # Loading
    # ------------------------------------------------------------------ #

    def _load(self):
        """Load and validate rules.json, build check lambdas."""
        if not os.path.exists(RULES_JSON_PATH):
            raise FileNotFoundError(
                f"rules.json not found: {RULES_JSON_PATH}\n"
                "Expected at furix_mvp/siem/rules/rules.json"
            )

        with open(RULES_JSON_PATH, "r", encoding="utf-8") as fh:
            try:
                definitions = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ValueError(f"rules.json is not valid JSON: {exc}") from exc

        # Pre-load all pattern and string files referenced by any rule
        self._preload_files(definitions)

        # Validate and build each rule
        built   = []
        skipped = 0
        for defn in definitions:
            if not defn.get("enabled", True):
                skipped += 1
                continue
            try:
                rule = self._build_rule(defn)
                built.append(rule)
            except Exception as exc:
                print(f"[RuleEngine] WARNING: skipping rule "
                      f"'{defn.get('name','?')}': {exc}")
                skipped += 1

        self._rules = built
        layer_b = [r for r in built if r.get("layer") == "B"]

        # Rebuild pattern summary for logging
        pat_summary = ", ".join(
            f"{k.replace('_patterns.txt','').replace('_pattern','').replace('patterns','')}="
            f"{len(v)}"
            for k, v in self._pattern_cache.items()
        )
        print(
            f"[RuleEngine] {len(built)} rules loaded"
            + (f" ({skipped} disabled/skipped)" if skipped else "")
            + (f".  Patterns: {pat_summary}" if pat_summary else "")
        )

    def _preload_files(self, definitions: List[Dict]):
        """Pre-load all pattern/string files referenced in any rule definition."""
        for defn in definitions:
            cfg  = defn.get("check_config", {})
            ctype = defn.get("check_type", "")
            if ctype == "pattern_file":
                fname = cfg.get("pattern_file", "")
                if fname and fname not in self._pattern_cache:
                    path = os.path.join(RULES_DIR, fname)
                    self._pattern_cache[fname] = _load_patterns(path)
            elif ctype == "string_file":
                fname = cfg.get("string_file", "")
                if fname and fname not in self._string_cache:
                    path = os.path.join(RULES_DIR, fname)
                    self._string_cache[fname] = _load_lines(path)

    def _build_rule(self, defn: Dict) -> Dict:
        """Validate one rule definition and build its check lambda."""
        # Required fields
        for field in ("name", "boost", "mitre", "confidence", "check_type"):
            if field not in defn:
                raise ValueError(f"Missing required field '{field}'")

        check_type = defn["check_type"]
        if check_type not in CHECK_REGISTRY:
            raise ValueError(
                f"Unknown check_type '{check_type}'. "
                f"Valid types: {sorted(CHECK_REGISTRY)}"
            )

        cfg = defn.get("check_config", {})

        # Validate custom_handler name exists
        if check_type == "custom_handler":
            handler = cfg.get("handler", "")
            if handler not in CUSTOM_HANDLERS:
                raise ValueError(
                    f"Handler '{handler}' not found in CUSTOM_HANDLERS. "
                    f"Add the function and register it in CUSTOM_HANDLERS."
                )

        # Apply weight override from rule_weights.json if present
        boost = float(self._weights.get(defn["name"], defn["boost"]))

        # Build the check lambda via the registry
        builder = CHECK_REGISTRY[check_type]
        check   = builder(cfg, self)

        return {
            "name":       defn["name"],
            "layer":      defn.get("layer", "A"),
            "boost":      boost,
            "mitre":      defn["mitre"],
            "confidence": float(defn["confidence"]),
            "description":defn.get("description", ""),
            "check":      check,
        }

    # ------------------------------------------------------------------ #
    # Detection — primary interface
    # ------------------------------------------------------------------ #

    def detect(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate all rules against one ECS event.

        Returns a list with one risk_event dict if any rules fired,
        empty list otherwise.

        risk_event schema:
          detector, rule_name, triggered_rules, mitre_technique_id,
          mitre_technique, mitre_tactic, mitre_tactic_id,
          kill_chain_stage, score, confidence, event_id,
          user, source_ip, timestamp, event_module
        """
        triggered: List[str]  = []
        best_boost  = 0.0
        best_rule   = None
        best_mitre  = "T1071"
        best_conf   = 0.5

        for rule in self._rules:
            try:
                if not rule["check"](event):
                    continue
            except Exception:
                continue

            triggered.append(rule["name"])
            if rule["boost"] > best_boost:
                best_boost = rule["boost"]
                best_rule  = rule["name"]
                best_mitre = rule["mitre"]
                best_conf  = rule["confidence"]

        if not triggered:
            return []

        meta  = _mitre(best_mitre)
        total = min(100.0, sum(
            r["boost"] for r in self._rules if r["name"] in triggered
        ))

        return [{
            "detector":           "signature_rules",
            "rule_name":          best_rule,
            "triggered_rules":    triggered,
            "mitre_technique_id": best_mitre,
            "mitre_technique":    meta.get("name", "Unknown"),
            "mitre_tactic":       meta.get("tactic", "Unknown"),
            "mitre_tactic_id":    meta.get("tactic_id", ""),
            "kill_chain_stage":   meta.get("kill_chain_stage", 0),
            "score":              total,
            "confidence":         best_conf,
            "event_id":           (event.get("event") or {}).get("id") or str(uuid.uuid4()),
            "user":               (event.get("user") or {}).get("name", ""),
            "source_ip":          (event.get("source") or {}).get("ip", ""),
            "timestamp":          event.get("@timestamp", ""),
            "event_module":       (event.get("event") or {}).get("module", ""),
        }]

    def detect_all(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Batch detect. Returns flattened list of risk_events."""
        out: List[Dict[str, Any]] = []
        for e in events:
            out.extend(self.detect(e))
        return out

    # ------------------------------------------------------------------ #
    # Legacy compatibility wrapper
    # ------------------------------------------------------------------ #

    def score(self, event: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Legacy interface. Use detect() for new code."""
        risk_events = self.detect(event)
        if not risk_events:
            return 0.0, []
        re0 = risk_events[0]
        return re0["score"], re0["triggered_rules"]

    def score_all(self, events: List[Dict[str, Any]]) -> List[Tuple[float, List[str]]]:
        """Legacy batch interface. Use detect_all() for new code."""
        return [self.score(e) for e in events]

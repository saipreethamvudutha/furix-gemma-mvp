"""
anomaly_store.py
----------------
Persists the complete set of anomalous events detected by Block 1.

The detection pipeline's hot path produces 457 detection_bundles in memory,
but only a small slice ever reaches the LLM. This module captures the
complete record so the final report can include every detected anomaly
with its score, rule, timestamp, and MITRE context.

Two views are produced:
  rule_hit_events    — events where the signature_rules engine fired
                       (the high-confidence "we know this is bad" set)
  high_risk_events   — events where the bundle reached a HIGH+ severity
                       in Block 2 accumulation (rule + UEBA + ML)

For each event the full context is captured:
  timestamp, entity (user), source IP, dest IP, dest port,
  event module, rule name(s), score, confidence,
  MITRE technique + tactic + kill chain stage,
  short raw message preview.

Output: results/anomaly_events.json — read by Block 5 to populate
the detected_anomalies appendix in the final incident report.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# =============================================================================
#  Rule → plain-English description table
#  Used to enrich each anomaly with a one-line "what it means" string
#  so the final report is analyst-readable without LLM enrichment.
# =============================================================================

RULE_DESCRIPTION: Dict[str, str] = {
    "known_bad_ip":             "Connection from IP listed in threat intelligence feed",
    "protocol_app_mismatch":    "Network protocol does not match expected application layer",
    "high_risk_port":           "Destination port commonly abused for C2 or remote access",
    "outbound_smtp":            "Internal host sending mail directly to external SMTP server",
    "denied_medium_port_offhours": "Firewall denied medium-risk port traffic outside business hours",
    "auth_failure":             "Authentication attempt failed",
    "account_lockout":          "Account locked after repeated failed authentication",
    "auth_failure_offhours":    "Authentication failure outside business hours",
    "high_log_severity":        "Source system flagged this event as high severity",
    "firewall_allow_high_risk": "Firewall allowed traffic to a high-risk external port",
    "cloud_offhours_external":  "Cloud API call from external IP outside business hours",
    "db_external_access":       "Database accessed directly from an external (non-private) IP",
    "sensitive_endpoint":       "HTTP request to admin / credential / config endpoint",
    "workstation_to_phi_db":    "End-user workstation connected directly to PHI database, bypassing PAM",
    "vendor_direct_phi":        "External vendor IP connected directly to PHI database with no PAM session",
    "bec_phishing":             "Email matched Business Email Compromise pattern (lookalike domain, exec target)",
    "hsm_wrong_actor":          "Hardware Security Module operation performed by unauthorised actor",
    "audit_integrity":          "Attempt to modify or delete audit log records",
    "c2_dns_beacon":            "DNS query pattern matches Command and Control beaconing behaviour",
    "impossible_travel":        "Same account authenticated from geographically impossible locations within minutes",
    "credential_stuffing":      "High-volume failed login attempts using leaked credentials",
    "bulk_phi_query":           "Database SELECT returned bulk PHI rows above baseline threshold",
    "pam_outside_window":       "Privileged account checked out outside approved access window",
    "privilege_escalation":     "User account elevated to privileged group by unknown actor",
    "mass_smb_enum":            "Mass SMB share enumeration detected (potential ransomware staging)",
    "bulk_s3_phi_access":       "Bulk object retrieval from PHI-tagged S3 bucket",
    "sql_injection":            "SQL injection pattern detected in HTTP request",
    "xss_pattern":              "Cross-site scripting pattern detected in HTTP request",
    "shell_injection":          "Shell command injection pattern detected",
    "ransomware_pattern":       "File extension or content matched ransomware signature",
    "jndi_injection":           "JNDI/Log4Shell injection pattern detected",
    "sensitive_file_access":    "Access to credentials, configuration, or backup file",
    "scanner_agent":            "User-agent matched known vulnerability scanner",
    "base64_payload":           "Long base64-encoded payload in request body",
}


# =============================================================================
#  Rule → correct MITRE tactic override
#  Several rules share T1078 (Valid Accounts) but the tactic differs by context.
#  This map prevents the LLM (or generic MITRE lookup) from assigning the
#  wrong tactic to a rule in the final report.
# =============================================================================

RULE_TACTIC_OVERRIDE: Dict[str, tuple] = {
    "impossible_travel":      ("T1078",     "Credential Access",   8),
    "credential_stuffing":    ("T1110.004", "Credential Access",   8),
    "account_lockout":        ("T1110",     "Credential Access",   8),
    "auth_failure":           ("T1110",     "Credential Access",   8),
    "auth_failure_offhours":  ("T1110",     "Credential Access",   8),
    "workstation_to_phi_db":  ("T1021",     "Lateral Movement",   10),
    "vendor_direct_phi":      ("T1078",     "Initial Access",      3),
    "bec_phishing":           ("T1566",     "Initial Access",      3),
    "bulk_phi_query":         ("T1213",     "Collection",         11),
    "bulk_s3_phi_access":     ("T1530",     "Collection",         11),
    "pam_outside_window":     ("T1078",     "Privilege Escalation", 6),
    "audit_integrity":        ("T1562",     "Defense Evasion",     7),
    "c2_dns_beacon":          ("T1071.004", "Command and Control",12),
    "mass_smb_enum":          ("T1135",     "Discovery",           9),
    "privilege_escalation":   ("T1078.003", "Privilege Escalation", 6),
    "hsm_wrong_actor":        ("T1552",     "Credential Access",   8),
    "outbound_smtp":          ("T1048",     "Exfiltration",       13),
    "sql_injection":          ("T1190",     "Initial Access",      3),
    "jndi_injection":         ("T1190",     "Initial Access",      3),
    "xss_pattern":            ("T1059",     "Execution",           4),
    "shell_injection":        ("T1059",     "Execution",           4),
    "ransomware_pattern":     ("T1486",     "Impact",             14),
    "scanner_agent":          ("T1595",     "Reconnaissance",      1),
    "known_bad_ip":           ("T1071",     "Command and Control",12),
}


def _rule_description(rule_name: str) -> str:
    """Return human-readable description for a rule."""
    return RULE_DESCRIPTION.get(rule_name, "Anomalous behaviour detected")


def _correct_mitre(rule_name: str, fallback: tuple) -> tuple:
    """
    Return the (technique_id, tactic_name, kill_chain_stage) tuple for a rule.
    Uses RULE_TACTIC_OVERRIDE when present, otherwise the fallback tuple.
    """
    return RULE_TACTIC_OVERRIDE.get(rule_name, fallback)


# =============================================================================
#  Extraction
# =============================================================================

def _get(obj: dict, dotted: str, default=None):
    parts = dotted.split(".")
    node = obj
    for p in parts:
        if not isinstance(node, dict):
            return default
        node = node.get(p)
        if node is None:
            return default
    return node


def extract_anomalies(bundles: List[dict]) -> Dict[str, List[dict]]:
    """
    Extract two complete views of anomalous events from Block 1 bundles.

    Returns dict with keys:
      "rule_hit_events"   — every event where signature_rules fired
      "all_detections"    — every event where any lane fired (large set)
    """
    rule_events: List[dict] = []
    all_events:  List[dict] = []

    for bundle in bundles:
        if not bundle.get("detectors_fired"):
            continue

        raw       = bundle.get("raw_event", {})
        ts        = bundle.get("timestamp", "")
        user      = bundle.get("user", "")
        src_ip    = bundle.get("source_ip", "")
        dst_ip    = _get(raw, "destination.ip", "") or ""
        dst_port  = _get(raw, "destination.port", 0) or 0
        module    = bundle.get("event_module", "")
        message   = _get(raw, "message", "") or ""
        event_id  = bundle.get("event_id", "")

        # ── Collect risk_events by detector ──
        rule_re = next(
            (r for r in bundle["risk_events"]
             if r.get("detector") == "signature_rules"),
            None,
        )
        ueba_re = next(
            (r for r in bundle["risk_events"]
             if r.get("detector") == "ueba"),
            None,
        )
        ml_re = next(
            (r for r in bundle["risk_events"]
             if r.get("detector") == "ml_ensemble"),
            None,
        )

        # ── Build common record ──
        base_record = {
            "event_id":         event_id,
            "timestamp":        ts,
            "entity":           user,
            "source_ip":        src_ip,
            "destination_ip":   dst_ip,
            "destination_port": dst_port,
            "event_module":     module,
            "lanes_fired":      bundle.get("detectors_fired", []),
            "ml_score":         bundle.get("ml_score", 0.0),
            "raw_message_preview": message[:200] if message else "",
        }

        # ── Rule hit details (if signature_rules fired) ──
        if rule_re:
            primary_rule = rule_re.get("rule_name", "")
            triggered    = rule_re.get("triggered_rules", [])
            score        = float(rule_re.get("score", 0))
            confidence   = float(rule_re.get("confidence", 0))

            # Apply tactic correction so context matches the actual rule
            fallback = (
                rule_re.get("mitre_technique_id", ""),
                rule_re.get("mitre_tactic", ""),
                int(rule_re.get("kill_chain_stage", 0)),
            )
            tid, tactic, stage = _correct_mitre(primary_rule, fallback)
            technique_name = rule_re.get("mitre_technique", "")

            rule_record = {
                **base_record,
                "primary_rule":         primary_rule,
                "all_rules_fired":      triggered,
                "rule_count":           len(triggered),
                "rule_score":           round(score, 2),
                "rule_confidence":      round(confidence, 3),
                "mitre_technique_id":   tid,
                "mitre_technique":      technique_name,
                "mitre_tactic":         tactic,
                "kill_chain_stage":     stage,
                "what_it_means":        _rule_description(primary_rule),
            }
            rule_events.append(rule_record)

        # ── Full all-detections record (broader set) ──
        full_record = dict(base_record)
        if rule_re:
            full_record["rule"] = {
                "name":        rule_re.get("rule_name"),
                "all_rules":   rule_re.get("triggered_rules", []),
                "score":       float(rule_re.get("score", 0)),
                "confidence":  float(rule_re.get("confidence", 0)),
                "mitre_id":    rule_re.get("mitre_technique_id"),
            }
        if ueba_re:
            details = ueba_re.get("ueba_details", {})
            full_record["ueba"] = {
                "score":            float(ueba_re.get("score", 0)),
                "confidence":       float(ueba_re.get("confidence", 0)),
                "anomaly_driver":   details.get("anomaly_driver"),
                "peer_group":       details.get("peer_group"),
                "n_dims_scored":    details.get("n_dims_scored"),
            }
        if ml_re:
            full_record["ml"] = {
                "score":        float(ml_re.get("score", 0)),
                "confidence":   float(ml_re.get("confidence", 0)),
            }
        all_events.append(full_record)

    # Sort rule hits by kill chain stage then timestamp for narrative ordering
    rule_events.sort(key=lambda r: (r.get("kill_chain_stage", 0),
                                     r.get("timestamp", "")))

    return {
        "rule_hit_events": rule_events,
        "all_detections":  all_events,
    }


def save_anomaly_store(
    bundles:    List[dict],
    output_path: str,
) -> dict:
    """
    Extract anomalies from bundles and persist to JSON.

    Returns the summary stats dict written to the file.
    """
    views = extract_anomalies(bundles)
    rule_hits  = views["rule_hit_events"]
    all_detect = views["all_detections"]

    # Aggregate counts per rule for fast lookup
    rule_counts: Dict[str, int] = {}
    for ev in rule_hits:
        for r in ev.get("all_rules_fired", []):
            rule_counts[r] = rule_counts.get(r, 0) + 1

    # Aggregate counts per kill chain stage
    stage_counts: Dict[int, int] = {}
    for ev in rule_hits:
        s = ev.get("kill_chain_stage", 0)
        if s:
            stage_counts[s] = stage_counts.get(s, 0) + 1

    payload = {
        "metadata": {
            "generated_at":       datetime.now(timezone.utc).isoformat(),
            "total_bundles":      len(bundles),
            "rule_hit_event_count": len(rule_hits),
            "all_detection_count":  len(all_detect),
            "unique_rules_fired": sorted(rule_counts.keys()),
            "rule_counts":        rule_counts,
            "stage_counts":       {str(k): v for k, v in stage_counts.items()},
        },
        "rule_hit_events": rule_hits,
        "all_detections":  all_detect,
    }

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
                exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print(f"[AnomalyStore] Saved → {output_path}  "
          f"({len(rule_hits)} rule-hit events, "
          f"{len(all_detect)} total detections)")
    return payload["metadata"]


def load_anomaly_store(path: str) -> Optional[dict]:
    """Load previously saved anomaly_events.json. Returns None if missing."""
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

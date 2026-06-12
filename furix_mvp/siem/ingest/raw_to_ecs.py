#!/usr/bin/env python3
"""
raw_to_ecs.py
-------------
Converts raw vendor log formats to ECS 8.11 structured JSON.

Supported formats (auto-detected per line):
  1. Palo Alto NGFW     — PAN-OS CSV syslog (TRAFFIC + THREAT)
  2. CrowdStrike Falcon — JSON telemetry (EventType key)
  3. Imperva DAM        — CEF key=value audit text
  4. Okta               — System Log JSON (eventType key)
  5. CyberArk PAM       — CEF syslog text (CyberArk|Vault)
  6. AWS CloudTrail     — CloudTrail JSON (eventSource ends .amazonaws.com)
  7. Nginx              — Combined log format + WAF JSON
  8. Proofpoint         — Syslog key=value (proofpoint:)

Each parser returns an ECS dict identical in schema to jsonl_to_ecs.py output.

Usage (standalone):
    python raw_to_ecs.py input.log output.ecs.jsonl

Usage (called from layer1_ecs_reader.py):
    from furix_mvp.siem.ingest.raw_to_ecs import run as raw_convert
    stats, by_cat = raw_convert(input_path, output_path)
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

from ..tenant import (
    ORG_NAME,
    PHI_BUCKETS,
    EXEC_ROLE_PREFIXES,
    PAM_VAULT_IP,
    PAM_VAULT_NAME,
)

# ── ECS version stamped on every record ──────────────────────────────────────
ECS_VERSION = "8.11.0"

# =============================================================================
#  FINGERPRINTING — identify source from raw line
# =============================================================================

# Pre-compiled fingerprint patterns
_RE_PANW_CSV   = re.compile(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2},[^,]+,(TRAFFIC|THREAT|SYSTEM|CONFIG),")
_RE_NGINX_LOG  = re.compile(r'^\d+\.\d+\.\d+\.\d+ - .+ \[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}')
_RE_PROOFPOINT = re.compile(r'proofpoint:.*action=', re.IGNORECASE)
_RE_CYBERARK   = re.compile(r'CyberArk\|Vault', re.IGNORECASE)
_RE_IMPERVA    = re.compile(r'Imperva Inc\.\|SecureSphere', re.IGNORECASE)
_RE_SYSLOG_HDR = re.compile(r'^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}')
_RE_ISO_HDR    = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')


def detect_source(line: str) -> str:
    """
    Return source type string for a raw log line.
    Deterministic — no ML, no guessing.
    """
    stripped = line.strip()
    if not stripped:
        return "unknown"

    # Try JSON first — covers CrowdStrike, Okta, CloudTrail, Nginx WAF
    if stripped.startswith("{"):
        try:
            doc = json.loads(stripped)
            if isinstance(doc, dict):
                # CrowdStrike: has EventType key
                if "EventType" in doc and "aip" in doc:
                    return "crowdstrike"
                # Okta: has eventType starting with known Okta prefixes
                if "eventType" in doc and "actor" in doc and "client" in doc:
                    return "okta"
                # CloudTrail: has eventSource ending .amazonaws.com
                if "eventSource" in doc and str(doc.get("eventSource","")).endswith(".amazonaws.com"):
                    return "cloudtrail"
                # CloudTrail variant: eventName + awsRegion
                if "eventName" in doc and "awsRegion" in doc:
                    return "cloudtrail"
                # Nginx WAF JSON
                if doc.get("type") == "waf" and "waf_rule" in doc:
                    return "nginx_waf"
                # Generic JSON fallback
                return "json_unknown"
        except (json.JSONDecodeError, ValueError):
            pass

    # PAN-OS CSV: starts with timestamp in YYYY/MM/DD format
    if _RE_PANW_CSV.match(stripped):
        return "paloalto"

    # Nginx combined log
    if _RE_NGINX_LOG.match(stripped):
        return "nginx"

    # Proofpoint syslog
    if _RE_PROOFPOINT.search(stripped):
        return "proofpoint"

    # CyberArk CEF
    if _RE_CYBERARK.search(stripped):
        return "cyberark"

    # Imperva DAM CEF
    if _RE_IMPERVA.search(stripped):
        return "imperva"

    return "unknown"


# =============================================================================
#  SHARED HELPERS
# =============================================================================

def _ecs_base(timestamp: str, message: str, module: str,
              dataset: str, category: list, etype: list,
              kind: str = "event") -> Dict[str, Any]:
    """Build the ECS skeleton common to all events."""
    return {
        "ecs":       {"version": ECS_VERSION},
        "@timestamp": timestamp,
        "message":   message,
        "log":       {"level": "info"},
        "event": {
            "module":   module,
            "dataset":  dataset,
            "category": category,
            "type":     etype,
            "kind":     kind,
            "severity": 2,
            "original": message,
        },
        "organization": {"name": ORG_NAME},
        "labels": {},
    }


def _parse_kv(text: str) -> Dict[str, str]:
    """
    Parse key=value pairs from CEF extension strings and syslog lines.
    Handles:
      - key=value
      - key="value with spaces"
      - CEF label pairs: cs1Label=Safe (stored but not confused with cs1=value)
    """
    result: Dict[str, str] = {}
    # First pass: quoted values (may contain spaces)
    for m in re.finditer(r'(\w+)="([^"]*)"', text):
        result[m.group(1)] = m.group(2)
    # Second pass: unquoted values (stop at space or end)
    for m in re.finditer(r'(\w+)=([^\s"\']+)', text):
        key = m.group(1)
        val = m.group(2)
        # Skip CEF Label suffix keys (cs1Label, cs2Label etc) — they describe
        # the field name, not a value we extract
        if key.endswith("Label"):
            continue
        # Don't overwrite a quoted value already captured
        if key not in result:
            result[key] = val
    return result


def _safe_int(val, default=None):
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _safe_float(val, default=None):
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def _level_from_severity(sev: str) -> str:
    sev = str(sev).upper()
    if sev in ("CRITICAL","CRIT","5","6","7"):
        return "critical"
    if sev in ("HIGH","ERROR","ERR","4"):
        return "error"
    if sev in ("MEDIUM","WARN","WARNING","3"):
        return "warn"
    return "info"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# =============================================================================
#  1. PALO ALTO NGFW PARSER
#  PAN-OS Traffic/Threat log CSV — fixed field positions
#  Reference: PAN-OS 10.x Log Field Descriptions
# =============================================================================

# Field indices for PAN-OS TRAFFIC log
_PANW_F = {
    "receive_time":    0,
    "serial":          1,
    "type":            2,
    "subtype":         3,
    "config_ver":      4,
    "generate_time":   5,
    "src_ip":          6,
    "dst_ip":          7,
    "natsrc":          8,
    "natdst":          9,
    "rule":            10,
    "src_user":        11,
    "dst_user":        12,
    "app":             13,
    "vsys":            14,
    "src_zone":        15,
    "dst_zone":        16,
    "inbound_if":      17,
    "outbound_if":     18,
    "logprofile":      19,
    "sessionid":       20,
    "repeatcnt":       21,
    "src_port":        22,
    "dst_port":        23,
    "natsport":        24,
    "natdport":        25,
    "flags":           26,
    "protocol":        27,
    "action":          28,
    "bytes":           29,
    "bytes_sent":      30,
    "bytes_recv":      31,
    "packets":         32,
    "start_time":      33,
    "elapsed":         34,
    "category":        35,
    "seqno":           37,
    "src_country":     38,
    "dst_country":     39,
    "pkts_sent":       40,
    "pkts_recv":       41,
    "session_end":     42,
    "device_name":     47,
}

# THREAT log has threat name at index 29, severity at index 30
_PANW_THREAT_F = {
    "src_ip":       6,
    "dst_ip":       7,
    "rule":         10,
    "src_user":     11,
    "app":          13,
    "src_zone":     15,
    "dst_zone":     16,
    "protocol":     27,
    "action":       28,
    "threat_name":  29,
    "threat_id":    30,
    "category":     31,
    "severity":     32,
    "src_port":     22,
    "dst_port":     23,
    "device_name":  len(_PANW_F),  # last field
}

_PANW_ACTION_OUTCOME = {
    "allow": "success", "allowed": "success",
    "deny":  "failure", "denied":  "failure",
    "drop":  "failure", "dropped": "failure",
    "reset-both": "failure", "reset-client": "failure",
    "block-ip": "failure", "alert": "unknown",
}

_PANW_PROTO_MAP = {
    "tcp":"tcp","udp":"udp","icmp":"icmp",
    "ssl":"tcp","tls":"tcp",
}


def _get_panw(fields: list, key: str, default="") -> str:
    idx = _PANW_F.get(key)
    if idx is None:
        return default
    try:
        return fields[idx].strip()
    except IndexError:
        return default


def parse_paloalto(line: str) -> Optional[Dict[str, Any]]:
    # Strip any trailing anomaly annotations (space-separated after CSV)
    # Find the CSV portion — split only on the structured fields
    raw = line.strip()

    # Some lines have extra annotation after the last CSV field
    # Split carefully — PAN-OS fields may contain spaces in some positions
    # Use split with limit to preserve trailing annotations
    parts = raw.split(",")
    if len(parts) < 30:
        return None

    log_type = parts[2].strip().upper() if len(parts) > 2 else "TRAFFIC"
    ts_raw   = parts[5].strip() if len(parts) > 5 else parts[0].strip()

    # Parse timestamp: 2026/05/28 14:31:01
    try:
        dt = datetime.strptime(ts_raw, "%Y/%m/%d %H:%M:%S")
        ts = dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except ValueError:
        ts = _now_iso()

    # Extract trailing annotation (everything after the last structured field)
    # Join any fields beyond index 47 as extra context
    extra_ctx = " ".join(parts[48:]).strip() if len(parts) > 48 else ""
    # Also check if last normal field contains anomaly markers
    last_field = parts[-1].strip() if parts else ""
    if "[ANOMALY:" in last_field or "[NO_PAM" in last_field:
        extra_ctx = last_field + " " + extra_ctx

    def get(key):
        return _get_panw(parts, key)

    src_ip   = get("src_ip")
    dst_ip   = get("dst_ip")
    src_port = _safe_int(get("src_port"))
    dst_port = _safe_int(get("dst_port"))
    proto    = get("protocol").lower()
    app      = get("app")
    action   = get("action").lower()
    rule     = get("rule")
    src_zone = get("src_zone")
    dst_zone = get("dst_zone")
    src_user = get("src_user")
    bytes_s  = _safe_int(get("bytes_sent"), 0)
    bytes_r  = _safe_int(get("bytes_recv"), 0)
    device   = get("device_name") or "palo-alto-ngfw"
    outcome  = _PANW_ACTION_OUTCOME.get(action, "unknown")

    if log_type == "THREAT":
        severity_str = parts[_PANW_THREAT_F.get("severity", 32)].strip() \
                       if len(parts) > 32 else "informational"
        threat_name  = parts[_PANW_THREAT_F.get("threat_name", 29)].strip() \
                       if len(parts) > 29 else ""
        category     = parts[_PANW_THREAT_F.get("category", 31)].strip() \
                       if len(parts) > 31 else ""
        severity_num = {"critical":8,"high":6,"medium":4,"low":2,"informational":1}.get(
            severity_str.lower(), 2)
        level        = _level_from_severity(severity_str)
        msg          = (f"THREAT {category.upper()} {src_ip}:{src_port} -> "
                        f"{dst_ip}:{dst_port} threat={threat_name} "
                        f"severity={severity_str} action={action} rule={rule}")
        ecs = _ecs_base(ts, msg, "firewall", "security.firewall",
                        ["network","intrusion_detection"], ["info","denied"])
        ecs["event"].update({
            "action":   action,
            "outcome":  outcome,
            "severity": severity_num,
            "reason":   threat_name,
        })
        ecs["log"]["level"] = level
        ecs["labels"].update({
            "threat_name": threat_name,
            "threat_category": category,
            "src_zone": src_zone, "dst_zone": dst_zone,
            "rule_name": rule,
        })
    else:
        # TRAFFIC log
        level_map = {"allow":"info","deny":"warn","drop":"error"}
        level     = level_map.get(action, "info")
        sev_map   = {"allow":2,"deny":4,"drop":6}
        sev_num   = sev_map.get(action, 2)
        msg       = (f"TRAFFIC {action.upper()} {proto.upper()} "
                     f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                     f"app={app} rule={rule}"
                     + (f" {extra_ctx}" if extra_ctx else ""))
        ecs = _ecs_base(ts, msg, "firewall", "security.firewall",
                        ["network"], ["connection",
                         "allowed" if action == "allow" else "denied"])
        ecs["event"].update({
            "action":   action,
            "outcome":  outcome,
            "severity": sev_num,
        })
        ecs["log"]["level"] = level
        ecs["labels"].update({
            "application": app,
            "src_zone":    src_zone,
            "dst_zone":    dst_zone,
            "rule_name":   rule,
            "bytes_recv":  bytes_r,
            "session_end": get("session_end"),
        })
        if extra_ctx:
            ecs["labels"]["anomaly_context"] = extra_ctx

    ecs["observer"] = {
        "name":    device,
        "type":    "firewall",
        "vendor":  "Palo Alto Networks",
        "product": "PAN-OS NGFW",
    }
    ecs["source"]      = {"ip": src_ip, "port": src_port, "bytes": bytes_s}
    ecs["destination"] = {"ip": dst_ip, "port": dst_port, "bytes": bytes_r}
    ecs["network"]     = {
        "protocol":  _PANW_PROTO_MAP.get(proto, proto),
        "transport": _PANW_PROTO_MAP.get(proto, "tcp"),
        "bytes":     bytes_s + bytes_r,
        "direction": "outbound" if src_zone in ("User_LAN","Server_VLAN") else "inbound",
    }
    if src_user:
        ecs["user"] = {"name": src_user}

    return ecs


# =============================================================================
#  2. CROWDSTRIKE FALCON PARSER
#  JSON telemetry — FDR event format
# =============================================================================

_CS_SEVERITY_MAP = {
    "Critical": 8, "High": 6, "Medium": 4,
    "Low": 2, "Informational": 1,
}

_CS_PROCESS_EVENTS = {
    "ProcessRollup2", "SyntheticProcessRollup2",
}
_CS_NETWORK_EVENTS = {
    "NetworkConnectIP4", "NetworkConnectIP6",
    "NetworkListenIP4",
}
_CS_AUTH_EVENTS = {
    "UserLogon", "UserLogoff", "UserIdentityUpdateV2",
}
_CS_DNS_EVENTS = {"DnsRequest"}
_CS_DETECTION  = {"DetectionSummaryEvent", "IncidentSummaryEvent"}


def parse_crowdstrike(line: str) -> Optional[Dict[str, Any]]:
    try:
        doc = json.loads(line.strip())
    except (json.JSONDecodeError, ValueError):
        return None

    evt_type = doc.get("EventType","unknown")
    ts_epoch = doc.get("timestamp", 0)

    # Convert epoch ms to ISO
    try:
        dt = datetime.fromtimestamp(int(ts_epoch) / 1000, tz=timezone.utc)
        ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (TypeError, ValueError, OSError):
        ts = _now_iso()

    host  = doc.get("ComputerName", doc.get("Hostname",""))
    ip    = doc.get("aip","")
    user  = doc.get("UserName","")
    aid   = doc.get("aid","")

    if evt_type in _CS_DETECTION:
        detect_name = doc.get("DetectName","")
        severity_n  = doc.get("Severity", 2)
        severity_s  = doc.get("SeverityName","Medium")
        cmd_line    = doc.get("CommandLine","")
        target      = doc.get("TargetFileName", doc.get("DetectDescription",""))
        mitre_t     = doc.get("MitreAttackTactic","")
        mitre_tech  = doc.get("MitreAttackTechnique","")
        anomaly_f   = doc.get("AnomalyFlags",[])
        hsm_op      = doc.get("HsmOperation","")
        exp_actor   = doc.get("ExpectedActor","")
        key_id      = doc.get("KeyIdentifier","")

        msg = f"{detect_name} host={host} user={user} target={target}"
        if hsm_op:
            msg = (f"HSM_{hsm_op.upper()} key={key_id} actor={user} "
                   f"expected_actor={exp_actor} "
                   + " ".join(f"[{f}]" for f in anomaly_f))
        elif "AUDIT_INTEGRITY" in str(anomaly_f):
            msg = (f"SECURITY_ALERT {detect_name.replace('SECURITY_ALERT_','')} "
                   f"actor={user} target={target} src={ip} "
                   + " ".join(f"[{f}]" for f in anomaly_f))

        ecs = _ecs_base(ts, msg, "endpoint", "security.endpoint",
                        ["process"], ["info"])
        ecs["event"].update({
            "action":   detect_name.lower().replace(" ","_"),
            "outcome":  "unknown",
            "severity": _safe_int(severity_n, 4),
            "reason":   detect_name,
        })
        ecs["log"]["level"] = _level_from_severity(severity_s)
        ecs["labels"].update({
            "detect_name":         detect_name,
            "mitre_tactic":        mitre_t,
            "mitre_technique":     mitre_tech,
            "anomaly_flags":       ",".join(anomaly_f) if anomaly_f else "",
            "expected_actor":      exp_actor,
            "key_identifier":      key_id,
        })

    elif evt_type in _CS_PROCESS_EVENTS:
        process  = doc.get("FileName", doc.get("ImageFileName",""))
        cmd_line = doc.get("CommandLine","")
        sha256   = doc.get("SHA256HashData","")
        integ    = doc.get("IntegrityLevel","Medium")
        msg      = (f"WIN_EVENT 4688 Process_Creation host={host} "
                    f"user={user} process={process}")
        ecs = _ecs_base(ts, msg, "endpoint", "security.endpoint",
                        ["process"], ["start"])
        ecs["event"].update({
            "action":  "process_creation",
            "outcome": "unknown",
            "severity": 2,
        })
        ecs["process"] = {
            "name":        process,
            "command_line":cmd_line,
            "hash":        {"sha256": sha256},
            "pid":         _safe_int(doc.get("ProcessId")),
        }
        ecs["labels"]["integrity_level"] = integ

    elif evt_type in _CS_NETWORK_EVENTS:
        dst_ip   = doc.get("RemoteAddressIP4","")
        dst_port = _safe_int(doc.get("RemotePort"))
        src_port = _safe_int(doc.get("LocalPort"))
        proto    = doc.get("Protocol","TCP").lower()
        process  = doc.get("ImageFileName","")
        msg      = (f"NETWORK_CONNECT host={host} user={user} "
                    f"src={ip} dst={dst_ip}:{dst_port} proto={proto}")
        ecs = _ecs_base(ts, msg, "endpoint", "security.endpoint",
                        ["network"], ["connection"])
        ecs["event"].update({"action":"network_connect","severity":2})
        ecs["source"]      = {"ip": ip, "port": src_port}
        ecs["destination"] = {"ip": dst_ip, "port": dst_port}
        ecs["network"]     = {"transport": proto}

    elif evt_type in _CS_AUTH_EVENTS:
        logon_type = doc.get("LogonTypeName", doc.get("LogonType",""))
        auth_pkg   = doc.get("AuthenticationPackage","")
        is_logoff  = evt_type == "UserLogoff"
        msg        = (f"WIN_EVENT {'4634 Logoff' if is_logoff else '4624 Logon_Success'} "
                      f"host={host} user={user} "
                      f"logon_type={logon_type}")
        ecs = _ecs_base(ts, msg, "authentication", "security.authentication",
                        ["authentication"], ["end" if is_logoff else "start"])
        ecs["event"].update({
            "action":  "logoff" if is_logoff else "logon_success",
            "outcome": "success",
            "severity":2,
        })
        ecs["labels"]["logon_type"] = str(logon_type)
        ecs["labels"]["auth_package"] = auth_pkg

    elif evt_type in _CS_DNS_EVENTS:
        domain    = doc.get("DomainName","")
        req_type  = doc.get("RequestType","1")
        msg       = f"DNS_QUERY host={host} user={user} query={domain} type={req_type}"
        ecs = _ecs_base(ts, msg, "endpoint", "security.endpoint",
                        ["network"], ["info"])
        ecs["event"].update({"action":"dns_query","severity":2})
        ecs["dns"] = {"question": {"name": domain, "type": req_type}}

    else:
        msg = f"CS_EVENT type={evt_type} host={host} user={user}"
        ecs = _ecs_base(ts, msg, "endpoint", "security.endpoint",
                        ["process"], ["info"])
        ecs["event"].update({"action": evt_type.lower(), "severity":2})

    ecs["host"] = {"name": host, "ip": [ip]}
    if user:
        ecs["user"] = {"name": user}
    ecs["agent"] = {"type": "crowdstrike", "id": aid, "name": "CrowdStrike Falcon"}
    ecs["labels"]["event_type"] = evt_type

    return ecs


# =============================================================================
#  3. IMPERVA DAM PARSER
#  CEF key=value format
#  Format: <ts> <host> CEF:0|Imperva Inc.|SecureSphere|ver|sig|name|sev|ext
# =============================================================================

_IMPERVA_OP_CATEGORY = {
    "SELECT": ["database","access"],
    "INSERT": ["database","creation"],
    "UPDATE": ["database","change"],
    "DELETE": ["database","deletion"],
    "EXEC":   ["database","access"],
}

_IMPERVA_OUTCOME = {
    "SELECT":"success","INSERT":"success","UPDATE":"success",
    "DELETE":"success","EXEC":"success",
}

def parse_imperva(line: str) -> Optional[Dict[str, Any]]:
    raw = line.strip()

    # Extract timestamp — ISO or syslog at start of line
    ts = _now_iso()
    m_ts = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)', raw)
    if m_ts:
        ts = m_ts.group(1)

    # Extract host (second token before CEF:)
    m_host = re.search(r'(\S+)\s+CEF:', raw)
    host   = m_host.group(1) if m_host else ""

    # Extract CEF severity (field between last two pipes before extensions)
    cef_sev = "LOW"
    m_cef = re.search(r'CEF:0\|[^|]+\|[^|]+\|[^|]+\|([^|]+)\|([^|]+)\|([^|]+)\|', raw)
    if m_cef:
        cef_sev = m_cef.group(3)

    # Extract extension key=value pairs
    ext_start = raw.rfind("|")
    ext_str   = raw[ext_start+1:].strip() if ext_start >= 0 else raw

    kv = _parse_kv(ext_str)

    op        = kv.get("act","SELECT").upper()
    user      = kv.get("suser","")
    src_ip    = kv.get("src","")
    db_host   = kv.get("dhost", host)
    db_ip     = kv.get("dst","")
    dst_port  = _safe_int(kv.get("dpt"), 1521)
    # CEF cs1/cs2/cs3 fields — ignore their Label counterparts
    db_type   = kv.get("cs1","Oracle")
    db_name   = kv.get("cs2","")
    table     = kv.get("cs3","")
    rows      = _safe_int(kv.get("cnt"), 0)
    sess_id   = kv.get("externalId","")
    app_name  = kv.get("app","")
    # Fallback: try to extract from raw line if kv parsing missed fields
    if not table:
        m = re.search(r'cs3=([^\s]+)', ext_str)
        if m: table = m.group(1)
    if not user:
        m = re.search(r'suser=([^\s]+)', ext_str)
        if m: user = m.group(1)
    if rows == 0:
        m = re.search(r'\bcnt=(\d+)', ext_str)
        if m: rows = int(m.group(1))

    # Duration: "443ms" → 443
    dur_str = kv.get("duration","0ms")
    dur_ms  = _safe_int(re.sub(r'[^\d]','',dur_str), 0)

    # Extra tags in the line (anomaly markers)
    extra_tags = ""
    for tag in re.findall(r'\[([A-Z_:]+)\]', raw):
        extra_tags += f"[{tag}] "

    phi_access = "PHI_DATA_ACCESS" in raw or "PHI_ACCESS" in raw
    bulk       = rows > 1000

    sev_map = {"HIGH":6,"MEDIUM":4,"LOW":2}
    sev_num = sev_map.get(cef_sev.upper(), 2)
    if bulk:
        sev_num = max(sev_num, 6)

    level = {6:"error",4:"warn",2:"info"}.get(sev_num,"info")

    msg = (f"DB_AUDIT {op} ON {table} user={user} rows={rows} "
           f"duration={dur_ms}ms client={src_ip}"
           + (" [HIPAA_PHI_ACCESS]" if phi_access else "")
           + (f" {extra_tags.strip()}" if extra_tags else ""))

    cats = _IMPERVA_OP_CATEGORY.get(op, ["database","access"])
    ecs  = _ecs_base(ts, msg, "database", "security.database", cats, ["access"])
    ecs["event"].update({
        "action":   op.lower(),
        "outcome":  _IMPERVA_OUTCOME.get(op,"success"),
        "severity": sev_num,
        "duration": dur_ms * 1_000_000,  # ECS duration in nanoseconds
    })
    ecs["log"]["level"] = level
    ecs["source"]       = {"ip": src_ip}
    ecs["destination"]  = {"ip": db_ip, "port": dst_port}
    ecs["user"]         = {"name": user}
    ecs["server"]       = {"address": db_host}
    ecs["labels"].update({
        "db_type":      db_type,
        "db_name":      db_name,
        "table_name":   table,
        "row_count":    rows,
        "session_id":   sess_id,
        "phi_access":   phi_access,
        "bulk_query":   bulk,
        "anomaly_context": extra_tags.strip(),
    })

    return ecs


# =============================================================================
#  4. OKTA SYSTEM LOG PARSER
#  Okta System Log API JSON format
# =============================================================================

_OKTA_OUTCOME_MAP = {
    "SUCCESS":"success","ALLOW":"success",
    "FAILURE":"failure","DENY":"failure",
    "SKIPPED":"unknown","UNKNOWN":"unknown",
}

_OKTA_EVT_CATEGORY = {
    "user.authentication":  (["authentication"],["info"]),
    "user.session":         (["authentication"],["start"]),
    "user.account":         (["iam"],           ["change"]),
    "user.mfa":             (["authentication"],["info"]),
    "policy.evaluate":      (["authentication"],["info"]),
    "app.oauth2":           (["authentication"],["info"]),
}


def _okta_category(evt_type: str):
    for prefix, cats in _OKTA_EVT_CATEGORY.items():
        if evt_type.startswith(prefix):
            return cats
    return (["authentication"],["info"])


def parse_okta(line: str) -> Optional[Dict[str, Any]]:
    try:
        doc = json.loads(line.strip())
    except (json.JSONDecodeError, ValueError):
        return None

    evt_type = doc.get("eventType","")
    ts       = doc.get("published", _now_iso())
    severity = doc.get("severity","INFO")

    actor    = doc.get("actor",{})
    client   = doc.get("client",{})
    outcome  = doc.get("outcome",{})
    debug    = doc.get("debugContext",{}).get("debugData",{})
    targets  = doc.get("target",[])

    user      = actor.get("alternateId","").split("@")[0] or actor.get("displayName","")
    client_ip = client.get("ipAddress","")
    geo       = client.get("geographicalContext",{})
    country   = geo.get("country","US")
    city      = geo.get("city","")
    out_result= outcome.get("result","SUCCESS")
    out_reason= outcome.get("reason","")
    ecs_outcome = _OKTA_OUTCOME_MAP.get(out_result.upper(),"unknown")

    # Target app/group name
    target_name = ""
    if targets:
        target_name = targets[0].get("displayName","")

    # Privilege escalation context
    group_name   = debug.get("groupName","")
    anomaly_type = debug.get("anomalyType","")
    prev_ip      = debug.get("previousLoginIp","")
    curr_ip      = client_ip
    travel_time  = debug.get("timeSinceLastLoginMin","")

    # Build message
    if "impossible_travel" in str(anomaly_type).lower() or \
       "IMPOSSIBLE_TRAVEL" in str(debug.get("anomalyFlags","")):
        msg = (f"AUTH_SUCCESS method=Okta user={user} "
               f"src={client_ip} country={country} "
               f"prev_ip={prev_ip} prev_location={debug.get('previousLoginLocation','')} "
               f"[ANOMALY:IMPOSSIBLE_TRAVEL] time_gap={travel_time}min")
        sev_num = 8
        level   = "error"
    elif "privilege.escalation" in evt_type:
        tgt_user = targets[0].get("alternateId","").split("@")[0] if targets else ""
        msg = (f"AD_EVENT 4728 Member_Added_To_Privileged_Group "
               f"actor={user} target_user={tgt_user} group={group_name} "
               f"[ANOMALY:UNAUTHORIZED_PRIVILEGE_ESCALATION]")
        sev_num = 8
        level   = "error"
    elif "lock" in evt_type:
        msg     = f"ACCOUNT_LOCKOUT user={user} src={client_ip} reason={out_reason}"
        sev_num = 6
        level   = "error"
    elif ecs_outcome == "failure":
        msg     = (f"AUTH_FAILURE method=Okta_{evt_type.split('.')[-1].upper()} "
                   f"user={user} src={client_ip} reason={out_reason}")
        sev_num = 4
        level   = "warn"
    else:
        msg = (f"AUTH_SUCCESS method=Okta user={user} "
               f"src={client_ip} app={target_name}")
        sev_num = 2
        level   = "info"

    cats, etypes = _okta_category(evt_type)
    ecs = _ecs_base(ts, msg, "authentication", "security.authentication",
                    cats, etypes)
    ecs["event"].update({
        "action":   evt_type,
        "outcome":  ecs_outcome,
        "severity": sev_num,
        "reason":   out_reason or anomaly_type,
    })
    ecs["log"]["level"] = level
    ecs["source"]       = {"ip": client_ip}
    ecs["user"]         = {"name": user, "email": actor.get("alternateId","")}
    ecs["labels"].update({
        "okta_event_type":    evt_type,
        "target_app":         target_name,
        "geo_country":        country,
        "geo_city":           city,
        "group_name":         group_name,
        "anomaly_type":       anomaly_type,
        "previous_login_ip":  prev_ip,
        "travel_time_min":    str(travel_time),
    })

    return ecs


# =============================================================================
#  5. CYBERARK PAM PARSER
#  CEF syslog format: CyberArk|Vault
# =============================================================================

_PAM_RISK_ACTIONS = {
    "CheckOutExclusiveAccount", "RetrievePassword",
    "InitiatePSMSession", "ConnectToPSM",
}

def parse_cyberark(line: str) -> Optional[Dict[str, Any]]:
    raw = line.strip()

    # Syslog timestamp
    ts = _now_iso()
    m_ts = re.match(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', raw)
    if m_ts:
        # Convert "May 28 14:42:36" → ISO (assume current year)
        try:
            year = datetime.now().year
            dt   = datetime.strptime(f"{year} {m_ts.group(1)}", "%Y %b %d %H:%M:%S")
            ts   = dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        except ValueError:
            pass

    # CEF severity (numeric field)
    cef_sev = 3
    m_sev = re.search(r'CEF:0\|[^|]+\|[^|]+\|[^|]+\|([^|]+)\|([^|]+)\|(\d+)\|', raw)
    if m_sev:
        cef_sev = _safe_int(m_sev.group(3), 3)
        action_name = m_sev.group(1)
    else:
        action_name = ""

    # Extract extension KV
    ext_start = raw.rfind("|")
    ext_str   = raw[ext_start+1:].strip() if ext_start >= 0 else raw
    kv        = _parse_kv(ext_str)

    action    = kv.get("act", action_name)
    user      = kv.get("suser","")
    src_ip    = kv.get("src","")
    target    = kv.get("dhost","")
    safe      = kv.get("cs1","")
    result    = kv.get("cs2","Succeeded")
    sess_id   = kv.get("cs3","")
    reason    = kv.get("cs4","")
    duration  = kv.get("cs5","")
    vault_ip  = kv.get("dvc", PAM_VAULT_IP)
    # Fallback direct regex for fields that CEF Label suffixes may have disrupted
    if not user:
        m = re.search(r'suser=(\S+)', ext_str)
        if m: user = m.group(1)
    if not target:
        m = re.search(r'dhost=(\S+)', ext_str)
        if m: target = m.group(1)
    if not safe:
        m = re.search(r'cs1=([^\s]+?)(?:\s+cs1Label|\s+cs2=|$)', ext_str)
        if m: safe = m.group(1)
    if result == "Succeeded":
        m = re.search(r'cs2=([^\s]+?)(?:\s+cs2Label|\s+cs3=|$)', ext_str)
        if m: result = m.group(1)
    if not sess_id:
        m = re.search(r'cs3=([^\s]+?)(?:\s+cs3Label|\s+cs4=|$)', ext_str)
        if m: sess_id = m.group(1)
    if not reason:
        m = re.search(r'cs4=([^\s]+?)(?:\s+cs4Label|\s+cs5=|$)', ext_str)
        if m: reason = m.group(1)
    if not duration:
        m = re.search(r'cs5=([^\s]+?)(?:\s+cs5Label|\s+dvc=|$)', ext_str)
        if m: duration = m.group(1)

    # Extra anomaly tags
    extra_tags = " ".join(re.findall(r'\[[A-Z_:]+\]', raw))
    outside_window = "OUTSIDE_APPROVED_WINDOW" in raw
    no_ticket      = "NO_CHANGE_TICKET" in raw

    sev_map   = {5:6, 4:4, 3:2}
    sev_num   = sev_map.get(cef_sev, 2)
    if outside_window:
        sev_num = max(sev_num, 6)

    outcome   = "failure" if result == "Failed" else "success"
    level_map = {6:"error",4:"warn",2:"info"}
    level     = level_map.get(sev_num,"info")

    msg = (f"PAM_{action.upper()} user={user} target={target} "
           f"safe={safe} result={result} session={sess_id}"
           + (f" duration={duration}" if duration else "")
           + (f" reason={reason}" if reason else "")
           + (f" {extra_tags}" if extra_tags else ""))

    ecs = _ecs_base(ts, msg, "authentication", "security.authentication",
                    ["iam","authentication"], ["info"])
    ecs["event"].update({
        "action":   action.lower(),
        "outcome":  outcome,
        "severity": sev_num,
        "reason":   reason,
    })
    ecs["log"]["level"] = level
    ecs["source"]       = {"ip": src_ip}
    ecs["destination"]  = {"address": target}
    ecs["user"]         = {"name": user}
    ecs["observer"]     = {
        "name":    PAM_VAULT_NAME,
        "ip":      [vault_ip],
        "product": "CyberArk PAM",
        "vendor":  "CyberArk",
        "type":    "pam",
    }
    ecs["labels"].update({
        "pam_action":       action,
        "safe":             safe,
        "session_id":       sess_id,
        "target_system":    target,
        "outside_window":   outside_window,
        "no_change_ticket": no_ticket,
        "anomaly_context":  extra_tags,
    })

    return ecs


# =============================================================================
#  6. AWS CLOUDTRAIL PARSER
#  CloudTrail JSON record format
# =============================================================================

_CT_SENSITIVE_APIS = {
    "GetSecretValue","GetObject","AssumeRole","CreateUser","AttachRolePolicy",
    "DeleteUser","Decrypt","GenerateDataKey","CreateSnapshot",
    "DisableCloudTrailLogging","StopLogging","DeleteTrail",
}

def parse_cloudtrail(line: str) -> Optional[Dict[str, Any]]:
    try:
        doc = json.loads(line.strip())
    except (json.JSONDecodeError, ValueError):
        return None

    ts         = doc.get("eventTime", _now_iso())
    svc        = doc.get("eventSource","")
    api        = doc.get("eventName","")
    region     = doc.get("awsRegion","")
    src_ip     = doc.get("sourceIPAddress","")
    user_id    = doc.get("userIdentity",{})
    user       = user_id.get("userName", user_id.get("sessionContext",{})
                             .get("sessionIssuer",{}).get("userName",""))
    error      = doc.get("errorCode","")
    req_params = doc.get("requestParameters",{}) or {}
    read_only  = doc.get("readOnly", api.startswith(("Describe","List","Get","Head")))

    # S3 specific
    bucket     = req_params.get("bucketName","")
    obj_key    = req_params.get("key","")
    obj_count  = req_params.get("objectCount",0)
    size_gb    = req_params.get("sizeGb",0)
    anomaly_f  = req_params.get("anomalyFlags",[])

    is_sensitive = api in _CT_SENSITIVE_APIS
    is_error     = bool(error)
    is_phi_bucket= bucket in PHI_BUCKETS
    bulk_s3      = bool(obj_count) and _safe_int(obj_count,0) > 100

    sev_num = 2
    if is_error:
        sev_num = 4
    if is_sensitive:
        sev_num = max(sev_num, 4)
    if is_phi_bucket and "GetObject" in api:
        sev_num = max(sev_num, 6)
    if bulk_s3:
        sev_num = max(sev_num, 6)

    level = {6:"error",4:"warn",2:"info"}.get(sev_num,"info")
    outcome = "failure" if is_error else "success"

    if "s3" in svc and bucket:
        msg = (f"S3_ACCESS {api} bucket={bucket} "
               f"iam_user={user} size_gb={size_gb} "
               f"object_count={obj_count} region={region}"
               + (" " + " ".join(f"[{f}]" for f in anomaly_f) if anomaly_f else ""))
    else:
        msg = (f"CLOUDTRAIL event={api} user={user} "
               f"region={region} result={'Error:'+error if error else 'Success'} "
               f"service={svc}")

    ecs = _ecs_base(ts, msg, "cloud", "security.cloud",
                    ["network","access"], ["info" if read_only else "change"])
    ecs["event"].update({
        "action":   api.lower(),
        "outcome":  outcome,
        "severity": sev_num,
        "reason":   error,
    })
    ecs["log"]["level"] = level
    ecs["source"]       = {"ip": src_ip}
    ecs["user"]         = {"name": user}
    ecs["cloud"]        = {
        "provider":    "aws",
        "region":      region,
        "service":     {"name": svc},
        "account":     {"id": user_id.get("accountId","")},
    }
    ecs["labels"].update({
        "api_action":     api,
        "aws_service":    svc,
        "read_only":      read_only,
        "error_code":     error,
        "s3_bucket":      bucket,
        "s3_object_count":obj_count,
        "size_gb":        size_gb,
        "phi_bucket":     is_phi_bucket,
        "anomaly_flags":  ",".join(anomaly_f) if anomaly_f else "",
    })

    return ecs


# =============================================================================
#  7. NGINX PARSER
#  Combined log format + WAF JSON
# =============================================================================

# Regex for Nginx combined log:
# $remote_addr - - [$time_local] "$request" $status $bytes "$referer" "$ua" $resp_time $req_id server=x vhost=y
_NGINX_RE = re.compile(
    r'^(\S+) - \S+ \[([^\]]+)\] "(\S+) (\S+) HTTP/[\d.]+" '
    r'(\d+) (\d+) "([^"]*)" "([^"]*)" ([\d.]+) (\S+)'
    r'(?:\s+server=(\S+))?(?:\s+vhost=(\S+))?'
    r'(?:\s+(.*))?$'
)

_NGINX_STATUS_CATEGORY = {
    2: (["web"],"access","success",2),
    3: (["web"],"access","success",2),
    4: (["web"],"access","failure",4),
    5: (["web"],"error", "failure",6),
}


def parse_nginx(line: str) -> Optional[Dict[str, Any]]:
    raw = line.strip()

    m = _NGINX_RE.match(raw)
    if not m:
        return None

    client_ip  = m.group(1)
    ts_raw     = m.group(2)   # "28/May/2026:14:32:40 +0000"
    method     = m.group(3)
    path       = m.group(4)
    status     = _safe_int(m.group(5), 200)
    resp_bytes = _safe_int(m.group(6), 0)
    referer    = m.group(7)
    ua         = m.group(8)
    resp_time  = _safe_float(m.group(9), 0.0)
    req_id     = m.group(10)
    server     = m.group(11) or "nginx"
    vhost      = m.group(12) or ""
    extra      = m.group(13) or ""

    # Parse timestamp
    try:
        dt = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
        ts = dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except ValueError:
        ts = _now_iso()

    status_class = status // 100
    cats, evt_type_s, outcome, sev_num = _NGINX_STATUS_CATEGORY.get(
        status_class, (["web"],"access","unknown",2)
    )

    # Extract user from extra fields
    user = ""
    m_user = re.search(r'user=(\S+)', extra)
    if m_user:
        user = m_user.group(1)

    # Anomaly context
    anomaly_ctx = ""
    for tag in re.findall(r'\[([A-Z_:]+)\]', extra):
        anomaly_ctx += f"[{tag}] "
    if anomaly_ctx:
        sev_num = max(sev_num, 6)

    msg = (f"HTTP {method} {path} {status} "
           f"{int(resp_time*1000)}ms "
           f"client={client_ip} host={vhost}"
           + (f" {extra}" if extra else ""))

    ecs = _ecs_base(ts, msg, "web_server", "security.web_server",
                    cats, [evt_type_s])
    ecs["event"].update({
        "action":   method.lower(),
        "outcome":  outcome,
        "severity": sev_num,
        "duration": int(resp_time * 1_000_000_000),
    })
    ecs["log"]["level"] = {6:"error",4:"warn",2:"info"}.get(sev_num,"info")
    ecs["source"]        = {"ip": client_ip}
    ecs["url"]           = {"path": path, "domain": vhost}
    ecs["http"]          = {
        "request":  {"method": method, "referrer": referer},
        "response": {"status_code": status, "body": {"bytes": resp_bytes}},
    }
    ecs["user_agent"]    = {"original": ua}
    if user:
        ecs["user"]      = {"name": user}
    ecs["labels"].update({
        "server":        server,
        "vhost":         vhost,
        "request_id":    req_id,
        "response_time_ms": int(resp_time * 1000),
        "anomaly_context": anomaly_ctx.strip(),
    })

    return ecs


def parse_nginx_waf(line: str) -> Optional[Dict[str, Any]]:
    """Parse Nginx WAF JSON events."""
    try:
        doc = json.loads(line.strip())
    except (json.JSONDecodeError, ValueError):
        return None

    ts         = doc.get("timestamp", _now_iso())
    waf_action = doc.get("waf_action","ALERT")
    waf_rule   = doc.get("waf_rule","")
    client_ip  = doc.get("client_ip","")
    method     = doc.get("method","")
    path       = doc.get("path","")
    status     = doc.get("status",200)
    server     = doc.get("server","")
    vhost      = doc.get("vhost","")
    ua         = doc.get("user_agent","")

    sev_map    = {"BLOCK":6,"ALERT":4,"ALLOW":2}
    sev_num    = sev_map.get(waf_action.upper(), 4)
    outcome    = "failure" if waf_action == "BLOCK" else "unknown"

    msg = (f"WAF_{waf_action} rule={waf_rule} "
           f"src={client_ip} host={vhost} method={method} path={path}")

    ecs = _ecs_base(ts, msg, "web_server", "security.web_server",
                    ["web","intrusion_detection"], ["info","denied"])
    ecs["event"].update({
        "action":   f"waf_{waf_action.lower()}",
        "outcome":  outcome,
        "severity": sev_num,
        "reason":   waf_rule,
    })
    ecs["log"]["level"] = {6:"error",4:"warn",2:"info"}.get(sev_num,"info")
    ecs["source"]        = {"ip": client_ip}
    ecs["url"]           = {"path": path, "domain": vhost}
    ecs["http"]          = {"request": {"method": method}}
    ecs["user_agent"]    = {"original": ua}
    ecs["labels"].update({
        "waf_action": waf_action,
        "waf_rule":   waf_rule,
        "server":     server,
    })

    return ecs


# =============================================================================
#  8. PROOFPOINT PARSER
#  Syslog key=value format
# =============================================================================

_PP_DISPOSITION_SEV = {
    "clean":      2,
    "bulk":       2,
    "spam":       3,
    "dmarc_fail": 3,
    "phishing":   7,
    "malware":    8,
    "bec":        8,
}

_PP_ACTION_OUTCOME = {
    "DELIVERED": "success",
    "QUARANTINED":"failure",
    "BLOCKED":   "failure",
    "REJECTED":  "failure",
    "DEFERRED":  "unknown",
}

def parse_proofpoint(line: str) -> Optional[Dict[str, Any]]:
    raw = line.strip()

    # ISO timestamp at start
    ts = _now_iso()
    m_ts = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)', raw)
    if m_ts:
        ts = m_ts.group(1)

    kv = _parse_kv(raw)

    # Also grab quoted values with spaces
    for m in re.finditer(r'(\w+)="([^"]*)"', raw):
        kv[m.group(1)] = m.group(2)

    action      = kv.get("action","DELIVERED").upper()
    direction   = kv.get("direction","inbound").lower()
    sender      = kv.get("from","")
    recipient   = kv.get("to","")
    subject_len = _safe_int(kv.get("subject_length"),0)
    disposition = kv.get("disposition","clean").lower()
    spam_score  = _safe_float(kv.get("spam_score"),0.0)
    attachment  = kv.get("attachment","")
    relay_ip    = kv.get("relay_ip","")
    dkim        = kv.get("dkim","pass")
    spf         = kv.get("spf","pass")
    dmarc       = kv.get("dmarc","pass")
    rule        = kv.get("rule","")
    guid        = kv.get("id","")

    # Extract sender domain
    sender_domain = sender.split("@")[-1] if "@" in sender else ""

    # BEC detection signals
    auth_fail  = dkim == "fail" or spf == "fail" or dmarc == "fail"
    has_attach = bool(attachment and attachment not in ("","false","False"))
    is_exec_targeted = any(e in recipient for e in EXEC_ROLE_PREFIXES)
    is_bec     = (disposition == "bec" or
                  (auth_fail and is_exec_targeted and has_attach))

    sev_num = _PP_DISPOSITION_SEV.get(disposition, 2)
    if is_bec:
        sev_num = max(sev_num, 8)
    if auth_fail and action == "DELIVERED":
        sev_num = max(sev_num, 6)

    level   = {8:"error",7:"error",6:"error",4:"warn",3:"warn",2:"info"}.get(sev_num,"info")
    outcome = _PP_ACTION_OUTCOME.get(action,"unknown")

    msg = (f"EMAIL_{action} direction={direction} "
           f"from={sender} to={recipient} "
           f"disposition={disposition} spam_score={spam_score} "
           f"attachment={attachment}"
           + (" [BEC_INDICATOR]" if is_bec else "")
           + (" [AUTH_FAIL]" if auth_fail else ""))

    ecs = _ecs_base(ts, msg, "email", "security.email",
                    ["email"], ["info"])
    ecs["event"].update({
        "action":   action.lower(),
        "outcome":  outcome,
        "severity": sev_num,
        "reason":   disposition,
    })
    ecs["log"]["level"] = level
    ecs["email"] = {
        "from":       {"address": [sender]},
        "to":         {"address": [recipient]},
        "direction":  direction,
        "subject":    {"registered_domain": sender_domain},
        "attachments":[{"file":{"name": attachment}}] if has_attach else [],
    }
    ecs["source"]       = {"ip": relay_ip}
    ecs["labels"].update({
        "action":         action,
        "disposition":    disposition,
        "sender_domain":  sender_domain,
        "spam_score":     spam_score,
        "dkim":           dkim,
        "spf":            spf,
        "dmarc":          dmarc,
        "rule":           rule,
        "bec_indicator":  is_bec,
        "auth_fail":      auth_fail,
        "exec_targeted":  is_exec_targeted,
        "has_attachment": has_attach,
        "guid":           guid,
    })

    return ecs


# =============================================================================
#  DISPATCH TABLE
# =============================================================================

PARSERS = {
    "paloalto":    parse_paloalto,
    "crowdstrike": parse_crowdstrike,
    "imperva":     parse_imperva,
    "okta":        parse_okta,
    "cyberark":    parse_cyberark,
    "cloudtrail":  parse_cloudtrail,
    "nginx":       parse_nginx,
    "nginx_waf":   parse_nginx_waf,
    "proofpoint":  parse_proofpoint,
}


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """Auto-detect and parse a single raw log line to ECS dict."""
    source = detect_source(line)
    parser = PARSERS.get(source)
    if parser is None:
        return None
    try:
        return parser(line)
    except Exception:
        return None


# =============================================================================
#  run() — public interface (mirrors jsonl_to_ecs.py)
# =============================================================================

def run(input_path: str, output_path: str):
    """
    Convert a raw vendor log file to ECS JSONL.

    Returns:
        stats    : {"total":N, "ok":N, "failed":N, "skipped":N}
        by_source: {"paloalto": N, "okta": N, ...}
    """
    stats     = {"total":0, "ok":0, "failed":0, "skipped":0}
    by_source: Dict[str, int] = {}

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    with open(input_path,  "r", encoding="utf-8", errors="replace") as fin, \
         open(output_path, "w", encoding="utf-8") as fout:

        for raw in fin:
            line = raw.strip()
            if not line:
                stats["skipped"] += 1
                continue

            stats["total"] += 1
            source = detect_source(line)
            by_source[source] = by_source.get(source, 0) + 1

            parser = PARSERS.get(source)
            if parser is None:
                stats["failed"] += 1
                continue

            try:
                ecs = parser(line)
                if ecs:
                    fout.write(json.dumps(ecs, ensure_ascii=False) + "\n")
                    stats["ok"] += 1
                else:
                    stats["failed"] += 1
            except Exception:
                stats["failed"] += 1

    return stats, by_source


# =============================================================================
#  CLI
# =============================================================================

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python raw_to_ecs.py <input.log> <output.ecs.jsonl>")
        sys.exit(1)

    inp, out = sys.argv[1], sys.argv[2]
    if not os.path.exists(inp):
        print(f"ERROR: input file not found: {inp}")
        sys.exit(1)

    print(f"Converting: {inp} → {out}")
    stats, by_source = run(inp, out)

    print(f"\nResults:")
    print(f"  Total lines : {stats['total']:,}")
    print(f"  Converted   : {stats['ok']:,}")
    print(f"  Failed      : {stats['failed']:,}")
    print(f"  Skipped     : {stats['skipped']:,}")
    print(f"\n  By source:")
    for src, cnt in sorted(by_source.items(), key=lambda x: -x[1]):
        print(f"    {src:20s} {cnt:>8,}")

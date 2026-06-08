# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C6 · NORMALISER — Parse → Standardise → Enrich → Lane-tag        ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# ROLE        : Turn messy raw logs (20 vendor formats) into ONE canonical event
#               shape every downstream box understands. Four deterministic
#               stages — NO LLM here. This is the workhorse that makes the data
#               clean enough for the AI Brain to reason about cheaply.
# REAL-WORLD  : Python + aiokafka. Stage 1 parse (CEF/JSON/syslog), Stage 2
#               enrich (GeoIP, signatures, IOC join against C4/C13), Stage 3 lane
#               classify, Stage 4 tenant routing. Emits to normalized.events.
# IN THIS MVP : The same 4 stages, lightweight. The canonical "finding skeleton"
#               it produces (log_type + entities + signals + candidate controls)
#               is ALSO what the AI Brain uses as its deterministic fallback when
#               Gemma is offline — single source of truth for triage rules.
# INSIGHT     : Doing cheap deterministic work HERE (keyword signals, intel hits)
#               means the expensive box (C14→C7 Gemma) gets a tidy, pre-enriched
#               object. ~90% of the "thinking" is actually pattern-matching that
#               never needs a model. C6 is where that saving begins.
from __future__ import annotations

import re

from .c5_bus import BUS, T
from . import c12_operations as ops
from . import c4_intel_sync as intel

# ── Stage-3 grounding: keyword → candidate CIS control (closed catalog) ──────
# This is the canonical home of the triage rules. C14 imports these too.
#
# ACCURACY NOTE: every short/ambiguous token is WORD-BOUNDARY anchored (\b...\b).
# Bare substrings caused catastrophic false positives — e.g. "rce" matched
# "souRCE"/"eventSouRCE", "c2" matched "eC2.amazonaws", "s3"/"bucket" fired
# Control 3 on every S3 call including benign reads. Measure changes with
# tests/eval/run_eval.py before/after editing this map.
KW = {
    "Control 1":  r"\bdhcp\b|\brogue\b|unknown[- ]?mac|unauthorized device|unknown client",
    "Control 2":  r"\b7045\b|new service was installed|service installed|unauthorized software|unknown executable|installutil|new service",
    "Control 3":  r"getsecretvalue|getsecret|\bexfil|exfiltrat|sensitive (data|file|employee)|secretsmanager|credential dump|sekurlsa",
    "Control 4":  r"conditional access|legacy authentication|default password|certificate has expired|cert(ificate)? expired|misconfig|insecure configuration|policy.{0,20}disabled|disabled.{0,20}policy",
    "Control 5":  r"\buseradd\b|net user .*\/add|createuser|create user|\b4720\b|\b4732\b|provision\.?user|add member to role|account created|\badduser\b|createserviceaccount|service account",
    "Control 6":  r"\bsudo\b|privilege escalat|\bescalat|sebackup|\b4672\b|failed password|invalid user|\b4625\b|\b4732\b|\bmfa\b|mfaused|without mfa|mfa\.factor|conditional access|roles/owner|global admin|super admin(istrator)?|administratoraccess|administrator access|attachuserpolicy|localgroup administ",
    "Control 7":  r"\bcve-\d|\bnmap\b|vulnerab|\bexploit|\bvuln\b",
    "Control 8":  r"\bauditd\b|\bexecve\b|\b4688\b|\b4698\b|integrity (checksum|changed)|checksum changed|type=syscall|/etc/shadow|audit log",
    "Control 9":  r"\bwget\b|\bcurl\b|malicious-domain|malware-c2|phishing|\.ru\b|data-exfil\.|payload\.(sh|ps1)",
    "Control 10": r"mimikatz|\bbeacon\b|cobalt(strike)?|ransom|encrypt\.exe|powershell\s+-?enc|powershell.{0,20}-enc|\bmalware\b|/payload\b|payload\.(sh|ps1|exe)",
    "Control 11": r"deletebucket|delete bucket|backup.{0,15}delet|delet.{0,15}backup|snapshot delet|recovery (fail|point)",
    "Control 12": r"\bfirewall\b|\bufw\b|%asa|access-group|\bvpn\b|network infrastructure",
    "Control 13": r"suricata|\bzeek\b|intrusion detection|intrusion prevention|\bids/ips\b|\bnids\b|\bbeacon\b|eternalblue|signature_id|et (exploit|malware|scan)|c2 checkin|command and control",
    "Control 15": r"\biam\b|service account|gserviceaccount|createserviceaccount|consolelogin|\bcontractor\b",
    "Control 16": r"sql injection|\bsqli\b|modsecurity|\bwaf\b|remote code execution|\brce\b|\bxss\b|directory traversal",
}
# ── Behavioural signals: the boolean fingerprint of an event ─────────────────
# Same word-boundary discipline as KW: bare "c2" used to match "eC2.amazonaws",
# making benign EC2 reads look like C2/exfil and wrongly escalate to the LLM.
SIG = {
    "malware":              r"mimikatz|\bbeacon\b|cobalt|ransom|encrypt\.exe|payload\.(sh|ps1|exe)|\bmalware\b|powershell\s+-?enc",
    "c2_or_exfil":          r"\bc2\b|command and control|\bexfil|exfiltrat|getsecretvalue|/stage2|malicious-domain|malware-c2|filedownloaded|data-exfil",
    "privilege_escalation": r"\bsudo\b|privilege escalat|\bescalat|sebackup|\b4672\b|roles/owner|global admin|super admin",
    "account_creation":     r"\buseradd\b|net user .*\/add|createuser|\b4720\b|provision\.?user|add member to role|\bbackdoor\b",
    "lateral_movement":     r"lateral movement|psexec|netbios|\b3389\b|\bsmb\b|eternalblue",
    "failed_logins":        r"failed password|invalid user|\b4625\b|res=failed|authentication_failed",
    "successful_logins":    r"accepted publickey|consolelogin.{0,30}success|loggedin|aaa user authentication successful",
}

# ── Stage-1 entity extraction (kept RAW; DAL redaction happens later in C14) ──
_IP   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOM  = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|corp|local|internal)\b", re.I)
_CVE  = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_USER = re.compile(r"(?:user(?:name)?|account name|acct|userName|principalEmail)[\"'=: ]+([A-Za-z0-9._@\\-]+)", re.I)


def _detect_log_type(raw: str) -> str:
    low = raw.lower()
    for key, pat in (("aws_cloudtrail", "amazonaws.com"), ("gcp_audit", "googleapis.com"),
                     ("azure_ad", "onmicrosoft"), ("okta", "eventtype"),
                     ("windows_evtx", "eventid"), ("suricata", "event_type"),
                     ("zeek", "id.orig_h"), ("nmap", "nmap scan report"),
                     ("dns", "queries: info"), ("auditd", "type=syscall")):
        if pat in low:
            return key
    if "sshd[" in low or "sudo[" in low:
        return "linux_auth_syslog"
    return "generic"


def normalise(raw: str, log_type_hint: str = "auto") -> dict:
    """The 4 stages, condensed. Returns the canonical finding skeleton."""
    low = raw.lower()
    # Stage 1 — parse / extract entities
    entities = {
        "source_ip":   sorted(set(_IP.findall(raw)))[:10],
        "domains":     sorted(set(m.lower() for m in _DOM.findall(raw)))[:10],
        "cve_ids":     sorted(set(c.upper() for c in _CVE.findall(raw))) or [],
        "usernames":   sorted(set(_USER.findall(raw)))[:10],
    }
    # Stage 2 — enrich: join entities against threat intel (C4/C13)
    ioc_hits = []
    for ip in entities["source_ip"]:
        if intel.is_known_bad("ip", ip):
            ioc_hits.append({"type": "ip", "value": ip})
    for dom in entities["domains"]:
        if intel.is_known_bad("domain", dom):
            ioc_hits.append({"type": "domain", "value": dom})
    for cve in entities["cve_ids"]:
        if intel.is_known_bad("cve_kev", cve):
            ioc_hits.append({"type": "cve_kev", "value": cve})
    # Stage 3 — signals + candidate controls (the grounding for C14)
    signals = {k: bool(re.search(p, low)) for k, p in SIG.items()}
    controls = [c for c, p in KW.items() if re.search(p, low)]
    if ioc_hits:                       # a known-bad indicator is itself a signal
        signals["c2_or_exfil"] = True
    return {
        "log_type": log_type_hint if log_type_hint != "auto" else _detect_log_type(raw),
        "entities": entities,
        "intel": {"ioc_hits": ioc_hits},
        "signals": signals,
        # rule_controls = GENUINE keyword/signature matches ([] when nothing fired).
        # candidate_controls keeps the legacy default sentinel for backward compat.
        # The mapping resolver reads rule_controls so it can tell a real Control 8
        # hit from "nothing matched, defaulted to audit-log".
        "rule_controls": controls,
        "candidate_controls": controls or ["Control 8"],
        "summary": "Normalised by C6 (deterministic).",
    }


def on_raw(envelope: dict) -> None:
    """Bus handler: consume a raw.* envelope, normalise, fan out downstream."""
    with ops.timer("c6_normalise_latency"):
        event = normalise(envelope["raw"], envelope.get("log_type_hint", "auto"))
    event["_envelope"] = {k: envelope.get(k) for k in ("source", "ingest_ts", "lane")}
    ops.incr("normalized_total", log_type=event["log_type"])
    # Canonical event → storage + detection; enrichment request → AI Brain.
    BUS.publish(T.NORMALIZED, event)
    BUS.publish(T.DETECTION_INPUT, event)
    BUS.publish(T.AI_ENRICHMENT, {"raw": envelope["raw"], "finding": event})


def start() -> None:
    """Wire C6 onto the bus: it listens on all three raw lanes."""
    for lane in (T.RAW_HOT, T.RAW_WARM, T.RAW_COLD):
        BUS.subscribe(lane, on_raw)
    ops.register_health("C6_normaliser", lambda: {"ok": True, "stages": 4})

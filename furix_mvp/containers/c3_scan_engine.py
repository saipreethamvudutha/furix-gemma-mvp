# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C3 · SCAN ENGINE — Active Vulnerability + Posture Scanning       ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# ROLE        : The "go look" half of the platform (logs are the "watch" half).
#               On demand, it probes an asset, fingerprints services, checks them
#               against known CVEs, and emits findings onto the bus.
# REAL-WORLD  : Drives OpenVAS/Tenable/Qualys-style engines, 8-phase pipeline
#               (scope→discover→fingerprint→interrogate→enrich→dedup→output).
# IN THIS MVP : A simulated scanner with a tiny CVE catalog. scan(target)
#               returns findings AND publishes them to scan.findings so the rest
#               of the pipeline (C6 enrich → C14 reason → C8 store) treats a scan
#               finding exactly like a log event. Same plumbing, two sources.
# INSIGHT     : Unifying scans and logs onto ONE bus + ONE knowledge graph is the
#               whole Furix thesis: a scanner that also knows your alerts, and an
#               AI that reasons over both, beats three disconnected tools.
from __future__ import annotations

import time

from .c5_bus import BUS, T
from . import c12_operations as ops

# Minimal CVE catalog: (service signature, cve, severity, summary).
_CATALOG = [
    ("OpenSSH 7.9",        "CVE-2018-15473", "medium",   "OpenSSH username enumeration"),
    ("Apache httpd 2.4.41","CVE-2021-41773", "high",     "Apache path traversal / RCE"),
    ("Exchange",           "CVE-2024-21410", "critical", "Exchange EoP (KEV-listed)"),
    ("Windows Server 2019","CVE-2020-1472",  "critical", "Zerologon domain takeover"),
    ("ms-wbt-server",      "CVE-2019-0708",  "critical", "BlueKeep RDP RCE"),
]


def scan(target: str, services: list[str] | None = None) -> dict:
    """Simulate an authenticated scan of one asset.

    `services` are the fingerprinted product strings (as nmap would report). We
    match them against the CVE catalog and emit one finding per hit.
    """
    services = services or ["OpenSSH 7.9", "ms-wbt-server", "Windows Server 2019"]
    findings = []
    for svc in services:
        for sig, cve, sev, desc in _CATALOG:
            if sig.lower() in svc.lower():
                finding = {"target": target, "service": svc, "cve": cve,
                           "severity": sev, "summary": desc, "scan_ts": time.time()}
                findings.append(finding)
                # Render as a raw "scan log" so the normal pipeline can ingest it.
                BUS.publish(T.SCAN_FINDINGS, finding)
                ops.incr("scan_findings_total", severity=sev)
    return {"target": target, "services": services, "findings": findings}


def as_raw_log(finding: dict) -> str:
    """Format a scan finding as a log line for C2/C6 to ingest uniformly."""
    return (f"Scan finding on {finding['target']}: {finding['service']} vulnerable to "
            f"{finding['cve']} ({finding['severity']}) — {finding['summary']}")


def register_health() -> None:
    ops.register_health("C3_scan_engine", lambda: {"ok": True, "cve_catalog": len(_CATALOG)})

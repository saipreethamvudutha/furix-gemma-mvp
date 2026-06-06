# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C4 · INTEL SYNC — Threat Intelligence Feed                       ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# ROLE        : Keeps a fresh set of "known bad" indicators (IOCs): malicious
#               IPs, domains, file hashes, plus CVE/KEV data. Other containers
#               ask "is this IP/domain known-bad?" during enrichment.
# REAL-WORLD  : A 5MB Go binary. THE ONLY OUTBOUND FLOW in the whole appliance —
#               it pulls signed feed deltas from Furix Cloud every ~4 hours over
#               mTLS, then writes IOCs into Valkey (C13) and Postgres (C9).
# IN THIS MVP : A small built-in feed (the IOCs that appear in our sample logs)
#               seeded into the C13 cache. refresh() simulates a feed pull and
#               publishes intel.updates so downstream caches warm up.
# INSIGHT     : Intel is what turns "an IP connected out" into "an IP connected
#               to a known C2 server." Same event, hugely different severity.
#               Enrichment (C6) is where that join happens, using THIS data.
from __future__ import annotations

import time

from .c5_bus import BUS, T
from . import c12_operations as ops
from . import c13_valkey as cache

# A tiny built-in feed. In production these arrive signed from Furix Cloud.
_FEED = {
    "ip": {"203.0.113.55", "45.33.32.156", "172.16.40.50"},
    "domain": {"malware-c2.ru", "c2.malicious-domain.com",
               "data-exfil.base64encoded.attacker.com"},
    "cve_kev": {"CVE-2024-21410", "CVE-2024-3400", "CVE-2026-31431", "CVE-2024-21412"},
}

_LAST_SYNC = 0.0


def refresh() -> dict:
    """Simulate a feed pull: load IOCs into the C13 cache + announce on the bus."""
    global _LAST_SYNC
    count = 0
    for kind, values in _FEED.items():
        for v in values:
            cache.CACHE.set(f"ioc:{kind}:{v.lower()}", "1", ttl=0)
            count += 1
    _LAST_SYNC = time.time()
    BUS.publish(T.INTEL_UPDATES, {"updated": count, "ts": _LAST_SYNC})
    ops.incr("intel_iocs_loaded_total", value=count)
    return {"iocs_loaded": count, "kinds": list(_FEED)}


def is_known_bad(kind: str, value: str) -> bool:
    """O(1) lookup used by C6 enrichment. kind ∈ {ip, domain, cve_kev}."""
    if not value:
        return False
    hit = cache.CACHE.get(f"ioc:{kind}:{value.lower()}") is not None
    if hit:
        ops.incr("intel_hits_total", kind=kind)
    return hit


def register_health() -> None:
    ops.register_health("C4_intel_sync", lambda: {
        "ok": True, "last_sync_s_ago": round(time.time() - _LAST_SYNC, 1) if _LAST_SYNC else None})

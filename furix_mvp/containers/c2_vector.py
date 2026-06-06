# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C2 · VECTOR — Log Ingestion (the SIEM front door)                ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# ROLE        : First thing every log hits. Accepts raw events, triages them into
#               priority LANES, and feeds them onto the bus. C2 is about
#               throughput + routing, NOT deep understanding (that's C6).
# REAL-WORLD  : vector.dev (Rust). 500K+ events/sec, forwards to Kafka topics
#               raw.HOT / raw.WARM / raw.COLD.
# IN THIS MVP : A small Python intake PLUS a LaneScheduler (below) that makes the
#               lanes actually matter even in lite mode: under a backlog, HOT logs
#               are drained (fully processed through C6→C14) before WARM before
#               COLD. So a credential-dumping alert never waits behind debug noise.
# INSIGHT     : Lanes are a PRIORITY guarantee. They only matter when there is
#               contention (a backlog). With one log at a time there's nothing to
#               prioritise — which is why the scheduler drains highest-priority-
#               first whenever more than one event is waiting.
from __future__ import annotations

import re
import threading
import time
from collections import deque

from .c5_bus import BUS, T
from . import c12_operations as ops

# Signatures that promote a log to the HOT lane (worked first). Checked FIRST, so
# a single scary keyword wins — when in doubt, escalate.
_HOT = re.compile(
    r"failed password|invalid user|4625|4720|4672|sudo|privilege|mimikatz|beacon|"
    r"cobalt|ransom|malware|exploit|cve-|c2|backdoor|getsecretvalue|eternalblue",
    re.IGNORECASE)
# Signatures for the WARM lane (security-relevant but not urgent).
_WARM = re.compile(r"accepted|login|connect|policy|config|firewall|deny|allow|dns|"
                   r"scan|createuser|add member", re.IGNORECASE)


def classify_lane(raw: str) -> str:
    if _HOT.search(raw):
        return T.RAW_HOT
    if _WARM.search(raw):
        return T.RAW_WARM
    return T.RAW_COLD


# ── Lane scheduler — what makes the lanes actually reprioritise work ──────────
# Three queues, drained strictly HOT → WARM → COLD. This is the lite-mode stand-in
# for "more Kafka consumers on the HOT topic": same outcome (HOT first), one box.
class LaneScheduler:
    PRIORITY = [T.RAW_HOT, T.RAW_WARM, T.RAW_COLD]   # drain order

    def __init__(self) -> None:
        self._q: dict[str, deque] = {lane: deque() for lane in self.PRIORITY}
        self._lock = threading.Lock()

    def enqueue(self, lane: str, envelope: dict) -> None:
        with self._lock:
            self._q[lane].append(envelope)

    def _next(self):
        """Pop the highest-priority waiting envelope, or None if all empty."""
        with self._lock:
            for lane in self.PRIORITY:           # HOT first, always
                if self._q[lane]:
                    return lane, self._q[lane].popleft()
        return None, None

    def drain(self) -> list[str]:
        """Process the whole backlog in priority order. Returns the lane sequence
        actually processed (the proof that HOT went first)."""
        order: list[str] = []
        while True:
            lane, envelope = self._next()
            if lane is None:
                break
            short = lane.split(".")[-1]
            order.append(short)
            ops.incr("lane_processed_total", lane=short)
            BUS.publish(lane, envelope)          # → C6.on_raw handles it now
        return order

    def pending(self) -> dict:
        with self._lock:
            return {lane.split(".")[-1]: len(q) for lane, q in self._q.items()}


_SCHED = LaneScheduler()


def _enqueue(raw_log: str, source: str, log_type: str) -> str:
    """Classify + wrap in an envelope (adds lineage) + queue it. No processing yet."""
    lane = classify_lane(raw_log)
    envelope = {"raw": raw_log, "source": source, "log_type_hint": log_type,
                "ingest_ts": time.time(), "lane": lane}
    _SCHED.enqueue(lane, envelope)
    ops.incr("ingest_total", lane=lane.split(".")[-1])
    return lane


def ingest(raw_log: str, source: str = "api", log_type: str = "auto") -> dict:
    """One log in. Enqueue then drain immediately (a single event has no backlog
    to prioritise, so it's processed right away)."""
    lane = _enqueue(raw_log, source, log_type)
    _SCHED.drain()
    return {"lane": lane, "source": source, "bytes": len(raw_log)}


def ingest_many(logs: list[str], source: str = "batch") -> dict:
    """Bulk intake. Enqueue ALL first, THEN drain once — so the scheduler sees the
    whole backlog and processes every HOT log before any WARM/COLD. THIS is where
    the lanes earn their keep."""
    lanes = {"HOT": 0, "WARM": 0, "COLD": 0}
    for raw in logs:
        lane = _enqueue(raw, source, "auto")
        lanes[lane.split(".")[-1]] += 1
    order = _SCHED.drain()                        # priority drain of the backlog
    return {"accepted": len(logs), "by_lane": lanes,
            "processed_order": order}             # e.g. ['HOT','HOT','WARM','COLD']


def register_health() -> None:
    ops.register_health("C2_vector", lambda: {
        "ok": True, "role": "log ingestion", "pending": _SCHED.pending()})

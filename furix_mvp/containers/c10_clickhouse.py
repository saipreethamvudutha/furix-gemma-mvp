# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C10 · CLICKHOUSE — Columnar Event Timeline                       ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# ROLE        : The "what happened, when" store. Append-mostly, immutable, built
#               for sub-second queries over billions of rows. The dashboard's
#               live timeline + historical search read from here.
# REAL-WORLD  : ClickHouse. 500K+ rows/sec ingest, 10-15x compression, HOT/WARM/
#               COLD tiered tables. C8 batch-writes (1000 rows / 5s).
# IN THIS MVP : clickhouse-connect if CLICKHOUSE_URL is set; else an in-memory
#               ring buffer with the same append()/recent() surface.
# INSIGHT     : Postgres (C9) answers "how are these things related?" (graph);
#               ClickHouse (C10) answers "show me every event in order, fast."
#               Two stores, two questions — using one DB for both is the classic
#               SIEM mistake this architecture avoids.
from __future__ import annotations

import os
import threading
import time
from collections import deque

from . import c12_operations as ops

_mem = deque(maxlen=10000)
_lock = threading.Lock()
_ch = None   # real client, if configured


def _client():
    global _ch
    if _ch is not None:
        return _ch
    url = os.environ.get("CLICKHOUSE_URL")
    if not url:
        return None
    try:  # pragma: no cover — only in compose deployment
        import clickhouse_connect  # type: ignore
        _ch = clickhouse_connect.get_client(dsn=url)
        _ch.command(
            "CREATE TABLE IF NOT EXISTS timeline_events (ts DateTime, finding_id String, "
            "log_type String, severity String, summary String) ENGINE=MergeTree ORDER BY ts")
        return _ch
    except Exception as e:  # noqa: BLE001
        print(f"[C10 clickhouse] unavailable ({e}) → in-memory timeline")
        return None


def append(row: dict) -> None:
    """Write one timeline row. Called by C8 Storage Writer."""
    row = {"ts": row.get("ts", time.time()), **row}
    c = _client()
    if c:  # pragma: no cover
        c.insert("timeline_events", [[row["ts"], row.get("finding_id", ""),
                  row.get("log_type", ""), row.get("severity", ""), row.get("summary", "")]],
                 column_names=["ts", "finding_id", "log_type", "severity", "summary"])
    else:
        with _lock:
            _mem.append(row)
    ops.incr("timeline_rows_total")


def recent(limit: int = 50) -> list[dict]:
    with _lock:
        return list(_mem)[-limit:][::-1]


def count() -> int:
    with _lock:
        return len(_mem)


def register_health() -> None:
    ops.register_health("C10_clickhouse", lambda: {
        "ok": True, "backend": "clickhouse" if _ch else "memory", "rows": count()})

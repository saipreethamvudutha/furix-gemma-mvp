# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  PIPELINE WIRING — bring the 15 containers up as ONE lite process           ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# This is the "docker-compose of the lite mode": it starts each Furix container
# and subscribes it to the bus, so a single log flows through the WHOLE system
# in-process. In the real deployment docker-compose.yml does this across 15
# actual containers; here one bootstrap() call does it in one Python process.
#
#   C2 ingest ─▶ raw.* ─▶ C6 normalise ─▶ ┬─ normalized.events ─▶ C8 store→C10
#                                          ├─ detection.input  ─▶ C8 rules
#                                          └─ ai.enrichment    ─▶ C14 → C7 Gemma
#                                                                   └─ ai.verdicts ─▶ C8 persist
from __future__ import annotations

from .containers import (c2_vector, c3_scan_engine, c4_intel_sync, c5_bus,
                         c6_normaliser, c8_storage_detect, c9_stores,
                         c10_clickhouse, c12_operations as ops, c13_valkey,
                         c14_ai_brain, c15_backup)

_started = False


def bootstrap() -> None:
    """Idempotently start every container and wire it to the bus."""
    global _started
    if _started:
        return
    c4_intel_sync.refresh()      # warm the IOC cache (C4 → C13)
    c6_normaliser.start()        # C6 listens on raw.* lanes
    c8_storage_detect.start()    # C8 listens on normalized / detection / verdicts
    c14_ai_brain.start()         # C14 listens on ai.enrichment, emits ai.verdicts

    # Register health probes for the boxes that don't self-start a listener.
    for mod in (c2_vector, c3_scan_engine, c4_intel_sync, c10_clickhouse,
                c9_stores, c13_valkey, c15_backup):
        mod.register_health()
    c5_bus.register_health()
    _started = True
    ops.incr("pipeline_bootstrap_total")


def ingest_one(raw_log: str, source: str = "api") -> dict:
    """Push one log through the streaming pipeline (async-style, fire-and-flow)."""
    bootstrap()
    return c2_vector.ingest(raw_log, source=source)


def ingest_many(logs: list[str], source: str = "batch") -> dict:
    """Push many logs through the pipeline — the batch ingestion entry point."""
    bootstrap()
    return c2_vector.ingest_many(logs, source=source)

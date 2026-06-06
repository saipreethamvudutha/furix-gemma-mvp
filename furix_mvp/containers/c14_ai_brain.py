# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C14 · AI BRAIN — bus process wrapper                             ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# ROLE        : The "process" face of the AI Brain. The pure orchestration logic
#               lives in furix_mvp/brain.py (analyze()). THIS module connects it
#               to the bus: it consumes ai.enrichment requests and publishes
#               ai.verdicts — exactly how C14 behaves as a streaming service.
# DATA FLOW   : C6/C8 ─ai.enrichment▶ [consume] ─▶ brain.analyze() ─▶
#               ai.verdicts▶ C8(persist) + C11(dashboard feed).
# INSIGHT     : Separating "what to do" (brain.py) from "how it's triggered"
#               (this file) means the SAME analyze() serves both the synchronous
#               dashboard API and the asynchronous streaming pipeline. Write the
#               logic once, drive it two ways.
from __future__ import annotations

from .. import brain
from .c5_bus import BUS, T
from . import c7_vllm
from . import c12_operations as ops

analyze = brain.analyze   # convenience re-export


def consume(msg: dict) -> None:
    """Handle one ai.enrichment message → produce one ai.verdict."""
    raw = msg.get("raw") or ""
    finding = msg.get("finding", {})
    if not raw:                      # detection-triggered with no raw text
        raw = finding.get("summary", "") or str(finding.get("candidate_controls", ""))
    log_type = finding.get("log_type", "auto")
    with ops.timer("ai_brain_e2e_latency"):
        record = brain.analyze(raw, log_type)
    BUS.publish(T.AI_VERDICTS, record)


def start() -> None:
    BUS.subscribe(T.AI_ENRICHMENT, consume)
    c7_vllm.register_health()
    ops.register_health("C14_ai_brain", lambda: {"ok": True, "role": "orchestrator"})

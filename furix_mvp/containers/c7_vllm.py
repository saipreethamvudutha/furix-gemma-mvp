# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C7 · vLLM / GEMMA — Local Model Inference (the box under test)   ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# ROLE        : Runs the LLM locally and answers prompts. 100% on-prem — no
#               outbound calls. The AI Brain (C14) is its ONLY client, over mTLS.
# REAL-WORLD  : vLLM serving a Gemma variant (E2B/E4B/26B-MoE/31B). Batch
#               scheduler, 16K context, kill-switch + 50KB prompt cap + post-
#               response PII scan as safety rails.
# IN THIS MVP : Your in-house endpoint at GEMMA_BASE_URL (gemma4:e4b). The real
#               client lives in furix_mvp/llm.py; this module is C7's "face" so
#               the container map is complete and the load tester has a clean
#               handle to hammer. Flip MOCK_LLM=1 to test the plumbing offline.
# INSIGHT     : This is the component you are validating. Everything else exists
#               to feed it clean, safe, well-grounded prompts and to cache its
#               answers so you call it as little as possible.
from __future__ import annotations

from .. import config
from ..llm import complete_json, parse_json, health   # re-export the real client
from . import c12_operations as ops

__all__ = ["complete_json", "parse_json", "health", "register_health", "info"]


def info() -> dict:
    return {"endpoint": config.GEMMA_BASE_URL, "model": config.GEMMA_MODEL,
            "mock": config.MOCK_LLM}


def register_health() -> None:
    # health() actually probes the endpoint, so cache nothing here.
    ops.register_health("C7_vllm", lambda: {"ok": health().get("reachable", False), **info()})

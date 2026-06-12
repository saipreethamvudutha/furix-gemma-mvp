"""Correlation — turns per-event detections into correlated attack campaigns.

- ``RiskAccumulator`` (Block 2): consumes detection_bundles and maintains a
  per-entity risk ledger across dual sliding windows (60 min / 24 h) with
  exponential decay. The **strong-rule anchor** (``STRONG_RULE_SCORE_FLOOR``)
  caps an entity at MEDIUM unless it has at least one real signature_rules hit —
  preventing ML/UEBA volume alone from escalating. Emits ``incident_candidate``
  dicts on HIGH/CRITICAL crossings.
- ``MultistageCorrelator`` (Block 3): clusters incident_candidates into
  ``attack_narrative`` objects (graph + union-find), each a coordinated campaign
  with a kill-chain timeline, IOCs, and a pre-assembled ``llm_context`` for the
  report stage. ``correlate()`` returns ``(narratives, noise)`` and early-returns
  ``([], [])`` on empty input.

Both are pure standard library (``dateutil`` is a lazy fallback in the
accumulator), so this runs inside furix's light core. The correlator's
``assign_peer_group`` dependency on the UEBA module (Module 6) is a defensive
import that degrades until UEBA lands. ``MIN_LLM_CONFIDENCE`` gates which
narratives a caller routes to the LLM report stage (Module 5).
"""
from .risk_accumulator import RiskAccumulator
from .multistage_correlator import MultistageCorrelator, MIN_LLM_CONFIDENCE
from . import risk_accumulator, multistage_correlator

__all__ = [
    "RiskAccumulator",
    "MultistageCorrelator",
    "MIN_LLM_CONFIDENCE",
    "risk_accumulator",
    "multistage_correlator",
]

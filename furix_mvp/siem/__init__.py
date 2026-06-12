"""Furix SIEM subsystem — a self-contained campaign-correlation anomaly engine.

Ported from the Anomaly-detection engine and namespaced under ``furix_mvp.siem``
so its richer ECS → detection-bundle → incident-candidate → attack-narrative data
model can live alongside furix's flat per-event ``finding`` without colliding with
the appliance's own modules (notably ``furix_mvp.config``).

Pipeline (runtime): raw log → ECS normalise → 3 detector lanes (rules · UEBA · ML)
→ detection bundles → risk accumulator → multistage correlator → DAL scrub →
LLM report (re-pointed at the in-house Gemma via ``furix_mvp.llm``).

This is built up one module at a time; see docs/SIEM_PORT.md for the sequence.
"""
__all__ = ["config"]

"""Detection lanes + aggregation.

- ``rule_engine`` — the signature lane: 34 rules (loaded from
  ``furix_mvp/siem/rules/rules.json``) evaluated against ECS events. Pure
  standard library, so it runs inside furix's light core. This is the strongest
  deterministic signal and the "strong-rule anchor" the risk accumulator later
  gates escalation on.
- ``anomaly_store`` — pure-stdlib persistence + the ``RULE_DESCRIPTION`` /
  ``RULE_TACTIC_OVERRIDE`` tables and ``load_anomaly_store`` that the report stage
  consumes. Exposed eagerly (no ML deps).
- ``severity_engine`` (numpy) and ``detection_aggregator`` (the full ML stack —
  it fans an event through all three lanes) are NOT imported here; import them
  explicitly so ``RuleEngine`` / ``anomaly_store`` stay usable without the SIEM
  ML dependencies:

      from furix_mvp.siem.detect.severity_engine import SeverityEngine
      from furix_mvp.siem.detect.detection_aggregator import DetectionAggregator
"""
from .rule_engine import RuleEngine
from . import rule_engine, anomaly_store
from .anomaly_store import (
    RULE_DESCRIPTION,
    RULE_TACTIC_OVERRIDE,
    extract_anomalies,
    save_anomaly_store,
    load_anomaly_store,
)

__all__ = [
    "RuleEngine",
    "rule_engine",
    "anomaly_store",
    "RULE_DESCRIPTION",
    "RULE_TACTIC_OVERRIDE",
    "extract_anomalies",
    "save_anomaly_store",
    "load_anomaly_store",
]

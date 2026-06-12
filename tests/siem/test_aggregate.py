"""Module 8 smoke test — detection aggregator + anomaly store.

The integration capstone. Checks:
  - the aggregator degrades to the rule lane when ML/UEBA are untrained (the
    verifier-flagged guard) instead of crashing on load(),
  - it fans real ECS events through the lanes into detection_bundles,
  - anomaly_store round-trips with RULE_DESCRIPTION + corrected MITRE tactic,
  - the report stage's anomaly_store seam (Module 5) is now closed,
  - a full pipeline runs: aggregator → risk accumulator → correlator → narrative.

    python3 tests/siem/test_aggregate.py        # direct
    pytest tests/siem/test_aggregate.py         # under pytest
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

os.environ.setdefault("MOCK_LLM", "1")
# Point model paths at an empty throwaway dir so the ML/UEBA lanes are "untrained".
os.environ.setdefault("SIEM_MODELS_DIR", tempfile.mkdtemp(prefix="siem-agg-test-"))

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from furix_mvp.siem.ingest import raw_to_ecs
from furix_mvp.siem.detect import anomaly_store, save_anomaly_store, load_anomaly_store, RULE_DESCRIPTION
from furix_mvp.siem.detect.detection_aggregator import DetectionAggregator
from furix_mvp.siem.correlate import RiskAccumulator, MultistageCorrelator


def _cloudtrail_phi(ts: str) -> str:
    return json.dumps({
        "eventTime": ts, "eventSource": "s3.amazonaws.com", "eventName": "GetObject",
        "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.9",
        "userIdentity": {"userName": "svc_backup", "accountId": "111122223333"},
        "requestParameters": {"bucketName": "coventra-phi-backup",
                              "key": "claims/2026.csv", "objectCount": 500},
    })


# Three PHI-bulk-S3 events for one entity, minutes apart → escalation later.
_TIMES = ["2026-05-28T14:00:00Z", "2026-05-28T14:02:00Z", "2026-05-28T14:04:00Z"]
_EVENTS = [raw_to_ecs.parse_line(_cloudtrail_phi(t)) for t in _TIMES]
_BENIGN = raw_to_ecs.parse_line(
    '10.10.5.30 - - [28/May/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" '
    '200 1024 "-" "Mozilla/5.0" 0.012 req-x server=web01 vhost=portal.coventra.com'
)

_AGG = DetectionAggregator()
_AGG.load()   # no trained pickles present → must NOT raise


def test_aggregator_degrades_to_rule_lane():
    assert _AGG.is_loaded
    assert _AGG._ueba is None and _AGG._ml_detector is None      # guarded off
    assert _AGG.active_lanes() == ["signature_rules"]
    print("  ok  aggregator loaded rule-only when untrained (no crash)")


def test_bundles_capture_rule_hits():
    bundles = _AGG.process_all(_EVENTS)
    assert len(bundles) == 3
    for b in bundles:
        assert "signature_rules" in b["detectors_fired"]
        assert b["ml_score"] == 0.0                              # ML lane off
        assert b["user"] == "svc_backup"
        names = b["risk_events"][0]["triggered_rules"]
        assert "bulk_s3_phi_access" in names
    print(f"  ok  {len(bundles)} bundles, each with a signature_rules hit")


def test_benign_event_filtered():
    assert _AGG.process_all([_BENIGN]) == []
    print("  ok  benign event produces no bundle")


def test_anomaly_store_roundtrip_with_mitre_correction():
    bundles = _AGG.process_all(_EVENTS)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "anomaly_events.json")
        meta = save_anomaly_store(bundles, path)
        loaded = load_anomaly_store(path)
    assert meta["rule_hit_event_count"] == 3
    hits = loaded["rule_hit_events"]
    assert hits, "expected rule-hit events"
    h0 = hits[0]
    assert h0["primary_rule"] == "bulk_s3_phi_access"
    assert h0["what_it_means"] == RULE_DESCRIPTION["bulk_s3_phi_access"]
    # RULE_TACTIC_OVERRIDE corrects the tactic/stage for the rule.
    assert h0["mitre_tactic"] == "Collection"
    assert h0["kill_chain_stage"] == 11
    print("  ok  anomaly_store round-trip with corrected MITRE + descriptions")


def test_report_seam_closed():
    # The report stage imported anomaly_store defensively; it now resolves real.
    from furix_mvp.siem.report import llm_router
    assert llm_router.load_anomaly_store is not None
    assert llm_router.RULE_DESCRIPTION == anomaly_store.RULE_DESCRIPTION
    assert "bulk_s3_phi_access" in llm_router.RULE_DESCRIPTION
    print("  ok  report↔anomaly_store seam closed (real tables, not fallback)")


def test_end_to_end_aggregator_to_narrative():
    bundles = _AGG.process_all(_EVENTS)
    acc = RiskAccumulator()
    candidates = [r["incident_candidate"]
                  for r in acc.process_all(bundles) if r["new_emission"]]
    assert candidates, "svc_backup should escalate from repeated PHI bulk access"
    narratives, _noise = MultistageCorrelator().correlate(candidates)
    assert len(narratives) >= 1
    n = narratives[0]
    assert n["severity"] in ("HIGH", "CRITICAL")
    assert "svc_backup" in json.dumps(n)         # raw (scrubbing is a later stage)
    assert "T1530" in n["iocs"]["mitre_techniques"]
    print(f"  ok  e2e: {len(_EVENTS)} ECS events → {len(narratives)} "
          f"{n['severity']} campaign(s)")


def main() -> int:
    tests = [
        test_aggregator_degrades_to_rule_lane,
        test_bundles_capture_rule_hits,
        test_benign_event_filtered,
        test_anomaly_store_roundtrip_with_mitre_correction,
        test_report_seam_closed,
        test_end_to_end_aggregator_to_narrative,
    ]
    print(f"SIEM aggregate smoke test — {len(tests)} cases")
    for t in tests:
        t()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Module 9 (training) smoke test — light up the ML + UEBA lanes.

Trains the IsolationForest+ECOD ensemble and the UEBA profiles on the synthetic
benign baseline, then confirms the detection aggregator activates all three lanes
and that ML + UEBA actually fire on the attack sample (not just rules).

Writes artifacts to a throwaway SIEM_MODELS_DIR so the repo stays clean.

    python3 tests/siem/test_train.py        # direct
    pytest tests/siem/test_train.py         # under pytest
"""
from __future__ import annotations

import os
import sys
import tempfile

os.environ.setdefault("MOCK_LLM", "1")
os.environ["SIEM_MODELS_DIR"] = tempfile.mkdtemp(prefix="siem-train-test-")

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from furix_mvp.siem.train import train_models, models_status
from furix_mvp.siem.detect.detection_aggregator import DetectionAggregator
from furix_mvp.siem.ingest import ensure_ecs, load_events
from furix_mvp.siem.samples import SIEM_SAMPLE


def test_status_before_training_is_rules_only():
    st = models_status()
    assert st["active_lanes"] == ["signature_rules"]
    assert not st["ml_ready"] and not st["ueba_ready"]
    print("  ok  before training: rules-only")


def test_training_lights_up_all_lanes():
    res = train_models(synthetic=840)
    assert res["events"] == 840
    assert res["ml_features"] == [840, 16]
    assert res["ueba_users"] == 12
    st = models_status()
    assert st["ml_ready"] and st["ueba_ready"]
    assert st["active_lanes"] == ["signature_rules", "ueba", "ml_ensemble"]
    print(f"  ok  training built {res['ueba_users']} UEBA profiles + IForest+ECOD")


def _attack_events():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "a.log")
        with open(p, "w", encoding="utf-8") as f:
            f.write(SIEM_SAMPLE)
        return load_events(ensure_ecs(p))


def test_aggregator_runs_all_three_lanes():
    agg = DetectionAggregator()
    agg.load()                                   # models now exist → no guard
    assert agg.active_lanes() == ["signature_rules", "ueba", "ml_ensemble"]
    bundles = agg.process_all(_attack_events())
    fired = {re["detector"] for b in bundles for re in b["risk_events"]}
    # The ECOD+IForest lane and UEBA now contribute, not just rules.
    assert "ml_ensemble" in fired, fired
    assert "ueba" in fired, fired
    assert "signature_rules" in fired, fired
    # ML flagged the attack events as outliers (high raw score, pre-cap).
    assert max(b["ml_score"] for b in bundles) >= 80.0
    print(f"  ok  all three lanes fire on the attack sample: {sorted(fired)}")


def main() -> int:
    tests = [
        test_status_before_training_is_rules_only,
        test_training_lights_up_all_lanes,
        test_aggregator_runs_all_three_lanes,
    ]
    print(f"SIEM train smoke test — {len(tests)} cases")
    for t in tests:
        t()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

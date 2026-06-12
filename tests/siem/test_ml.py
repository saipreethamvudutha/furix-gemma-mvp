"""Module 7 smoke test — ML detection lane (features + ensemble).

Extracts feature vectors, trains the IsolationForest+ECOD ensemble on a synthetic
baseline, and checks a stark anomaly scores well above the baseline. Also asserts
the verifier-flagged behaviour that EnsembleDetector.load() RAISES on missing
pickles (the detection aggregator, Module 8, must guard this), and that the ML
lane closes the severity engine's FEATURE_NAMES seam (Module 3).

Needs numpy + scikit-learn + pyod. IForest uses a fixed random_state, so the
result is deterministic.

    python3 tests/siem/test_ml.py        # direct
    pytest tests/siem/test_ml.py         # under pytest
"""
from __future__ import annotations

import os
import sys
import tempfile

# Redirect trained-model output to a throwaway dir so fit() never writes pickles
# into the repo's furix_mvp/siem/models/. Must be set before furix config import.
os.environ.setdefault("SIEM_MODELS_DIR", tempfile.mkdtemp(prefix="siem-ml-test-"))

import numpy as np

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from furix_mvp.siem.ml import FeatureEngine, FEATURE_NAMES
from furix_mvp.siem.ml.layer3_detector import EnsembleDetector


def _ev(user, hour, action, outcome, src_ip, dst_port, proto, message, dst_ip=""):
    return {
        "@timestamp": f"2026-05-21T{hour:02d}:15:00.000Z",
        "user": {"name": user},
        "source": {"ip": src_ip},
        "destination": {"port": dst_port, "ip": dst_ip},
        "network": {"protocol": proto},
        "event": {"action": action, "outcome": outcome},
        "message": message,
    }


def _baseline(n: int = 100) -> list[dict]:
    # Normal business-hours, private-IP, HTTPS, successful reads — mild variance.
    users = ["alice", "bob", "carol"]
    out = []
    for i in range(n):
        out.append(_ev(
            user=users[i % 3],
            hour=9 + (i % 8),                       # 09:00–16:00
            action="select" if i % 2 else "read",
            outcome="success",
            src_ip=f"10.10.5.{20 + (i % 30)}",
            dst_port=443,
            proto="https",
            message=f"GET /api/records/{i} 200 ok",
            dst_ip=f"10.30.1.{10 + (i % 5)}",
        ))
    return out


def _anomaly() -> dict:
    # Off-hours, never-seen action, failure, high-risk port, external IP, DNS,
    # long high-entropy message — anomalous on many features at once.
    return _ev(
        user="mallory", hour=3, action="exfiltrate", outcome="failure",
        src_ip="203.0.113.9", dst_port=4444, proto="dns",
        message="x9Z!q2@v8#k1%w7^t4&b6*r3(n5)" * 8 + " aGVsbG8gd29ybGQgZXhmaWw=",
        dst_ip="198.51.100.7",
    )


def test_feature_extraction_shape():
    eng = FeatureEngine()
    base = _baseline()
    eng.fit(base)
    X = eng.extract_all(base)
    assert len(FEATURE_NAMES) == 16
    assert X.shape == (len(base), 16), X.shape
    assert X.dtype == np.float32
    print(f"  ok  FeatureEngine → {X.shape} matrix over {len(FEATURE_NAMES)} features")


def test_ensemble_flags_anomaly():
    eng = FeatureEngine()
    base = _baseline()
    eng.fit(base)
    X = eng.extract_all(base)

    det = EnsembleDetector()
    det.fit(X)                      # trains IForest + ECOD, computes calibration
    assert det.is_trained

    base_scores = det.score(X)
    assert base_scores.min() >= 0.0 and base_scores.max() <= 100.0

    X_anom = eng.extract_all([_anomaly()])
    anom = float(det.score(X_anom)[0])

    assert anom > float(np.mean(base_scores)), (anom, float(np.mean(base_scores)))
    assert anom >= 50.0, anom
    print(f"  ok  ensemble: anomaly={anom:.1f} vs baseline mean={np.mean(base_scores):.1f}")


def test_load_raises_without_pickles():
    # The exact "defer ML / untrained" scenario: load() must raise so Module 8
    # can guard it (the verifier flagged that this is NOT graceful by default).
    # Clear any pickles a prior fit() persisted so this is order-independent.
    from furix_mvp.siem import config as C
    for p in (C.SCALER_PATH, C.ISO_FOREST_PATH, C.ECOD_PATH, C.CALIBRATION_PATH):
        if os.path.exists(p):
            os.remove(p)
    det = EnsembleDetector()
    try:
        det.load()
        raised = False
    except FileNotFoundError:
        raised = True
    assert raised, "EnsembleDetector.load() should raise FileNotFoundError when untrained"
    assert not det.is_trained
    print("  ok  load() raises FileNotFoundError when untrained (aggregator must guard)")


def test_severity_engine_seam_closed():
    # ML lane present → severity engine's defensive FEATURE_NAMES import resolves
    # to the real 16-name list (was [] in Module 3 before this lane existed).
    from furix_mvp.siem.detect import severity_engine
    assert len(severity_engine.FEATURE_NAMES) == 16
    assert "hour_of_day" in severity_engine.FEATURE_NAMES
    assert severity_engine.FEATURE_NAMES == FEATURE_NAMES
    print("  ok  severity_engine FEATURE_NAMES seam closed (real 16-name list)")


def main() -> int:
    tests = [
        test_feature_extraction_shape,
        test_ensemble_flags_anomaly,
        test_load_raises_without_pickles,
        test_severity_engine_seam_closed,
    ]
    print(f"SIEM ml smoke test — {len(tests)} cases")
    for t in tests:
        t()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

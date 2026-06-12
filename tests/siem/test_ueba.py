"""Module 6 smoke test — UEBA profiler (offline build) + scorer (runtime).

Builds a tiny synthetic baseline in-memory, fits profiles via the real profiler
functions, loads them into the scorer, and checks that an in-envelope event is
quiet while an out-of-envelope one fires a UEBA risk_event. Also verifies the
de-duplicated field extractor, the tenant-sourced peer-group rules, and that the
correlator's assign_peer_group seam is now closed.

Uses a service-account profile (zero-tolerance min/max envelope) for an
unambiguous normal-vs-anomalous signal. Needs numpy + scipy.

    python3 tests/siem/test_ueba.py        # direct
    pytest tests/siem/test_ueba.py         # under pytest
"""
from __future__ import annotations

import json
import os
import pickle
import sys
import tempfile

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from furix_mvp.siem import tenant
from furix_mvp.siem.ueba import ueba_profiler as P, ueba_scorer as S, UEBAScorer

_USER = "svc_batch"   # svc_ → service account → zero-tolerance envelope


def _db_event(user: str, row_count: int, hour: int) -> dict:
    return {
        "@timestamp": f"2026-05-21T{hour:02d}:00:00.000Z",
        "event": {"module": "database", "action": "select", "outcome": "success"},
        "user": {"name": user},
        "source": {"ip": "10.10.5.20"},
        "labels": {"row_count": row_count},
    }


def _build_scorer() -> UEBAScorer:
    """Fit a baseline profile for svc_batch (row_count in [50,150]) and load it."""
    with tempfile.TemporaryDirectory() as d:
        ecs = os.path.join(d, "baseline.ecs.jsonl")
        with open(ecs, "w", encoding="utf-8") as fh:
            for i in range(60):
                fh.write(json.dumps(_db_event(_USER, 50 + (i % 100), 8 + (i % 4))) + "\n")

        user_obs, user_counts = P.collect_observations([ecs])
        peer_groups  = {u: P.assign_peer_group(u) for u in user_obs}
        pg_obs       = P.build_peer_group_obs(user_obs, peer_groups)
        global_stats = P.build_global_stats(user_obs)
        profiles     = P.build_profiles(user_obs, user_counts, pg_obs, global_stats, peer_groups)
        pg_profiles  = P.build_peer_group_profiles(pg_obs)
        artifact = {
            "profiles": profiles, "peer_group_profiles": pg_profiles,
            "global_stats": global_stats,
            "metadata": {"total_users": len(profiles),
                         "total_events": sum(user_counts.values()),
                         "dimensions_tracked": sorted(global_stats.keys())},
        }
        pkl = os.path.join(d, "ueba_profiles.pkl")
        with open(pkl, "wb") as fh:
            pickle.dump(artifact, fh)
        scorer = UEBAScorer()
        scorer.load(pkl)
        return scorer


_SCORER = _build_scorer()


def test_normal_event_is_quiet():
    # row_count + hour inside the observed envelope → below threshold → no event.
    risk = _SCORER.detect(_db_event(_USER, 100, 9))
    assert risk == [], risk
    print("  ok  in-envelope event → no UEBA risk_event")


def test_anomalous_event_fires():
    # row_count far outside the envelope → zero-tolerance → high anomaly.
    risk = _SCORER.detect(_db_event(_USER, 10_000_000, 9))
    assert len(risk) == 1, risk
    re0 = risk[0]
    assert re0["detector"] == "ueba"
    assert re0["score"] >= 15.0
    assert re0["ueba_details"]["anomaly_driver"] == "query_row_count"
    # risk_event shape matches the rule-engine contract the correlator consumes.
    assert re0["mitre_technique_id"] == "T1213"      # query_row_count → Collection
    assert re0["kill_chain_stage"] == 11
    assert re0["user"] == _USER
    print(f"  ok  out-of-envelope event → UEBA risk_event "
          f"(score {re0['score']}, driver {re0['ueba_details']['anomaly_driver']})")


def test_extract_dimensions_is_deduplicated():
    # Scorer reuses the profiler's single canonical implementation (no drift).
    assert S._extract_dimensions is P._extract_dimensions
    assert S._get is P._get
    print("  ok  _extract_dimensions / _get de-duplicated (shared object)")


def test_peer_group_rules_from_tenant():
    assert P.PEER_GROUP_RULES is tenant.PEER_GROUP_RULES
    assert P.assign_peer_group("svc_x") == "service_acct"
    assert P.assign_peer_group("cfo_jane") == "leadership"
    assert P.assign_peer_group("nobody_special") == tenant.DEFAULT_PEER_GROUP
    assert P.is_service_account("svc_x") and not P.is_service_account("alice")
    print("  ok  peer-group rules sourced from tenant profile")


def test_correlator_seam_closed():
    # The correlator's defensive UEBA import now resolves to the real function.
    from furix_mvp.siem.correlate import multistage_correlator as mc
    assert mc.assign_peer_group is P.assign_peer_group
    assert mc.assign_peer_group("svc_batch") == "service_acct"
    print("  ok  correlator assign_peer_group seam closed (real UEBA)")


def main() -> int:
    tests = [
        test_normal_event_is_quiet,
        test_anomalous_event_fires,
        test_extract_dimensions_is_deduplicated,
        test_peer_group_rules_from_tenant,
        test_correlator_seam_closed,
    ]
    print(f"SIEM ueba smoke test — {len(tests)} cases")
    for t in tests:
        t()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

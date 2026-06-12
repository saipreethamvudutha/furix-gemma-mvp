"""Module 4 smoke test — risk accumulator + multistage correlator.

Builds detection_bundles (the contract Module 8's DetectionAggregator will
produce), drives them through the RiskAccumulator, and feeds the emitted
incident_candidates into the MultistageCorrelator. Verifies:
  - per-entity escalation + incident_candidate emission,
  - the STRONG-RULE ANCHOR: ML/UEBA volume alone is capped at MEDIUM,
  - campaign assembly: two asset-linked entities → one attack_narrative,
  - the correlator's empty-input early return,
  - the defensive assign_peer_group fallback (UEBA not ported yet).

    python3 tests/siem/test_correlate.py        # direct
    pytest tests/siem/test_correlate.py         # under pytest
"""
from __future__ import annotations

import os
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from furix_mvp.siem.correlate import (
    RiskAccumulator, MultistageCorrelator, multistage_correlator,
)

_T0 = "2026-05-28T09:0"   # prefix; append "M:SS" → 09:0M:SS


def _re(detector, score, confidence, stage, mitre, ts,
        rules=None, source_ip="10.10.5.20", driver=""):
    """One risk_event (the shape rule_engine.detect / the ML+UEBA lanes emit)."""
    ev = {
        "detector": detector, "score": float(score), "confidence": float(confidence),
        "kill_chain_stage": int(stage), "mitre_technique_id": mitre,
        "triggered_rules": rules or [], "source_ip": source_ip, "timestamp": ts,
    }
    if detector == "ueba":
        ev["ueba_details"] = {"anomaly_driver": driver}
    return ev


def _bundle(ts, user, source_ip, risk_events):
    detectors = sorted({r["detector"] for r in risk_events})
    return {
        "timestamp": ts, "user": user, "source_ip": source_ip,
        "event_id": f"evt-{ts}-{user or source_ip}",
        "detectors_fired": detectors, "risk_events": risk_events, "raw_event": {},
    }


def test_strong_rule_entity_escalates_and_emits():
    acc = RiskAccumulator()
    emitted = []
    # Entity A (user svc_backup): three real signature_rules bundles across
    # PHI Collection/Exfil stages within minutes → crosses HIGH then CRITICAL.
    plan = [("0:00", 11, "T1213"), ("2:00", 11, "T1213"), ("4:00", 13, "T1530")]
    for mmss, stage, mitre in plan:
        ts = _T0 + mmss
        r = _re("signature_rules", 50, 0.9, stage, mitre, ts, rules=["bulk_phi_query"])
        res = acc.process(_bundle(ts, "svc_backup", "10.10.5.20", [r]))
        if res["new_emission"]:
            emitted.append(res["incident_candidate"])
    st = acc.get_entity_state("svc_backup")
    assert st.has_strong_rule_evidence is True
    assert emitted, "entity with strong rule evidence should emit"
    assert emitted[-1]["severity"] == "CRITICAL", emitted[-1]["severity"]
    print(f"  ok  strong-rule entity escalated → emitted {[e['severity'] for e in emitted]}")


def test_strong_rule_anchor_caps_ueba_volume_at_medium():
    acc = RiskAccumulator()
    last = None
    # Entity C (busy_user): 12 UEBA login_hour bundles. By raw score this lands
    # in HIGH range, but with NO signature_rules hit the anchor caps it at MEDIUM.
    for i in range(12):
        ts = f"2026-05-28T09:{i:02d}:00"   # 09:00:00 .. 09:11:00, one minute apart
        r = _re("ueba", 50, 0.5, 7, "T1078", ts, driver="login_hour", source_ip="10.10.9.9")
        last = acc.process(_bundle(ts, "busy_user", "10.10.9.9", [r]))
    st = acc.get_entity_state("busy_user")
    assert st.has_strong_rule_evidence is False
    # Raw accumulated score reached HIGH territory ...
    assert last["short_window"]["score"] >= 80, last["short_window"]["score"]
    # ... but the anchor capped the verdict at MEDIUM and suppressed emission.
    assert last["final_severity"] == "MEDIUM", last["final_severity"]
    assert last["new_emission"] is False
    print(f"  ok  UEBA volume (raw score {last['short_window']['score']:.0f}) "
          f"capped at {last['final_severity']} — no emission")


def _escalate(acc, user, source_ip, specs):
    """Feed bundles, return all emitted incident_candidates for this entity."""
    out = []
    for ts, score, stage, mitre, rule in specs:
        r = _re("signature_rules", score, 0.9, stage, mitre, ts, rules=[rule],
                source_ip=source_ip or "10.10.5.20")
        res = acc.process(_bundle(ts, user, source_ip, [r]))
        if res["new_emission"]:
            out.append(res["incident_candidate"])
    return out


def test_correlator_builds_campaign_from_linked_entities():
    acc = RiskAccumulator()
    candidates = []
    # Entity A — user, PHI Collection/Exfil (asset: phi_database via T1213, s3 via T1530)
    candidates += _escalate(acc, "svc_backup", "", [
        ("2026-05-28T09:00:00", 50, 11, "T1213", "bulk_phi_query"),
        ("2026-05-28T09:02:00", 50, 11, "T1213", "bulk_phi_query"),
        ("2026-05-28T09:04:00", 50, 13, "T1530", "bulk_s3_phi_access"),
    ])
    # Entity B — ip (no user), Lateral Movement to PHI DB (asset: phi_database via T1021)
    candidates += _escalate(acc, "", "10.30.9.5", [
        ("2026-05-28T09:01:00", 45, 10, "T1021", "workstation_to_phi_db"),
        ("2026-05-28T09:03:00", 45, 10, "T1021", "workstation_to_phi_db"),
        ("2026-05-28T09:05:00", 45,  3, "T1021", "workstation_to_phi_db"),
    ])
    assert candidates, "both entities should emit incident_candidates"

    narratives, noise = MultistageCorrelator().correlate(candidates)
    assert len(narratives) == 1, f"expected one campaign, got {len(narratives)}"
    n = narratives[0]
    # Two asset-linked entities clustered into one CRITICAL campaign.
    assert n["entity_count"] == 2, n["entity_count"]
    assert n["severity"] == "CRITICAL", n["severity"]
    assert {3, 10, 11, 13}.issubset(set(n["kill_chain_coverage"])), n["kill_chain_coverage"]
    assert n["campaign_id"].startswith("ATK-"), n["campaign_id"]
    # Pre-assembled report payload for the Module-5 LLM stage.
    ctx = n["llm_context"]
    assert ctx["system_prompt"] and ctx["narrative_summary"]
    assert "investigator" in ctx["agent_targets"]      # CRITICAL → investigator
    assert "anomaly_explainer" in ctx["agent_targets"]  # >=4 stages
    assert n["iocs"]["mitre_techniques"]
    print(f"  ok  campaign {n['campaign_id']} — {n['entity_count']} entities, "
          f"{len(n['kill_chain_coverage'])} stages, sev={n['severity']}")


def test_correlator_empty_input():
    assert MultistageCorrelator().correlate([]) == ([], [])
    print("  ok  empty input → ([], [])")


def test_peer_group_real_grouping_wired():
    # UEBA (Module 6) is ported → the correlator now resolves the REAL peer
    # grouping, not the defensive __solo__ fallback.
    assert multistage_correlator.assign_peer_group("svc_backup") == "service_acct"
    assert multistage_correlator.assign_peer_group("cfo_jdoe") == "leadership"
    assert "__solo__" not in multistage_correlator.assign_peer_group("random_xyz")
    print("  ok  correlator wired to real UEBA peer grouping")


def main() -> int:
    tests = [
        test_strong_rule_entity_escalates_and_emits,
        test_strong_rule_anchor_caps_ueba_volume_at_medium,
        test_correlator_builds_campaign_from_linked_entities,
        test_correlator_empty_input,
        test_peer_group_real_grouping_wired,
    ]
    print(f"SIEM correlate smoke test — {len(tests)} cases")
    for t in tests:
        t()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

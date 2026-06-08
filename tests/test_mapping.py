"""Tests for code-first compliance mapping.

Proves: (1) the deterministic resolver maps known events with NO LLM,
(2) the same input always yields the same mapping (repeatable / auditable),
(3) the LLM is only flagged for genuinely novel events,
(4) NIST + HIPAA expansion comes from the crosswalk tables.

Run:  cd "MVP_TEST GEMMA" && MOCK_LLM=1 RAG_ENABLED=0 python -m pytest tests/test_mapping.py -v
"""
import os
os.environ.setdefault("MOCK_LLM", "1")
os.environ.setdefault("RAG_ENABLED", "0")

from furix_mvp import mapping
from furix_mvp.containers import c6_normaliser as c6
from furix_mvp.mapping import (TIER_RULES, TIER_CROSSWALK, TIER_EMBEDDING, TIER_LLM)


# ── Known event: keyword rules fire → deterministic, no LLM ──────────────────
def test_known_event_maps_deterministically_without_llm():
    raw = ('{"eventName":"CreateUser","requestParameters":{"userName":"backdoor_admin"},'
           '"sourceIPAddress":"45.33.32.156"}')
    finding = c6.normalise(raw, "aws_cloudtrail")
    m = mapping.resolve(finding, ground={"available": False})

    assert m["needs_llm"] is False          # code handled it
    assert m["authoritative"] is True
    assert "Control 5" in m["control_ids"]   # Account Management
    assert m["primary_tier"] == TIER_RULES
    assert TIER_CROSSWALK in m["tiers_used"]
    # NIST + HIPAA came from the crosswalk tables, not a model.
    assert m["nist_subcategories"], "crosswalk should expand controls to NIST"
    assert m["hipaa_sections"], "crosswalk should expand controls to HIPAA"


def test_admin_escalation_maps_account_and_access_control():
    raw = ('{"eventName":"AttachUserPolicy","requestParameters":'
           '{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess","userName":"x"}}')
    finding = c6.normalise(raw, "aws_cloudtrail")
    m = mapping.resolve(finding, ground={"available": False})
    # 'roles/owner|global admin' not present, but IAM/console + privilege patterns;
    # at minimum Control 15 (service provider / IAM) should be present.
    assert m["needs_llm"] is False
    assert any(c in m["control_ids"] for c in ("Control 5", "Control 6", "Control 15"))


# ── Determinism: same input → identical mapping, every time ──────────────────
def test_mapping_is_repeatable():
    raw = "May 6 sshd[1]: Failed password for invalid user admin from 1.2.3.4"
    finding = c6.normalise(raw, "linux_auth_syslog")
    first = mapping.resolve(finding, ground={"available": False})
    for _ in range(5):
        again = mapping.resolve(finding, ground={"available": False})
        assert again["control_ids"] == first["control_ids"]
        assert again["nist_subcategories"] == first["nist_subcategories"]
        assert again["hipaa_sections"] == first["hipaa_sections"]


# ── Unknown-but-suspicious: no rule match BUT a risk signal → needs_llm ──────
def test_novel_suspicious_event_flags_llm_fallback():
    finding = {"rule_controls": [], "candidate_controls": ["Control 8"],
               "signals": {"malware": True}}          # risky but unmapped
    m = mapping.resolve(finding, ground={"available": False})
    assert m["needs_llm"] is True
    assert m["control_ids"] == []            # code refuses to guess
    assert m["authoritative"] is False
    assert m["primary_tier"] is None


# ── Benign event: no rule match AND no risk signals → suppressed, NO LLM ─────
def test_benign_event_suppressed_without_llm():
    finding = {"rule_controls": [], "candidate_controls": ["Control 8"],
               "signals": {"successful_logins": True}, "intel": {"ioc_hits": []}}
    m = mapping.resolve(finding, ground={"available": False})
    assert m["needs_llm"] is False           # do NOT burn an LLM call on benign
    assert m["control_ids"] == []            # no applicable control
    assert m["authoritative"] is True
    assert m["benign"] is True
    assert m["primary_tier"] == mapping.TIER_BENIGN


# ── LLM suggestion merge: validated + crosswalk-expanded + flagged for review ─
def test_llm_suggestion_is_non_authoritative():
    det = mapping.resolve({"rule_controls": [], "signals": {"malware": True}},
                          ground={"available": False})
    merged = mapping.merge_llm_suggestion(det, {"control_ids": ["Control 6", "BOGUS-99"]})
    assert merged["control_ids"] == ["Control 6"]   # BOGUS dropped by catalog validation
    assert merged["primary_tier"] == TIER_LLM
    assert merged["authoritative"] is False
    assert merged["needs_review"] is True
    assert merged["nist_subcategories"]             # crosswalk still authoritative


# ── Embedding tier: controls from RAG corroborate when rules miss ────────────
def test_embedding_tier_contributes_when_rules_miss():
    finding = {"rule_controls": []}            # rules found nothing
    ground = {"available": True, "controls": ["Control 13", "not-a-control"]}
    m = mapping.resolve(finding, ground)
    assert m["needs_llm"] is False
    assert m["control_ids"] == ["Control 13"]
    assert m["primary_tier"] == TIER_EMBEDDING
    assert m["provenance"]["Control 13"] == [TIER_EMBEDDING]


# ── End-to-end through brain.analyze in mock mode: no real LLM, mapping stands ─
def test_brain_analyze_known_event_skips_llm_mapper():
    from furix_mvp import brain
    rec = brain.analyze('{"eventName":"CreateUser","requestParameters":{"userName":"x"}}',
                        "aws_cloudtrail")
    assert rec["compliance"]["llm_used"] is False
    assert rec["compliance"]["authoritative"] is True
    assert "Control 5" in rec["verdict"]["control_ids"]
    # compliance_mapper agent should NOT have run for a known event
    assert "compliance_mapper" not in [a["agent"] for a in rec["agents"]]

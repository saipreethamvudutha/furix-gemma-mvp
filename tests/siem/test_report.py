"""Module 5 smoke test — DAL scrubber + LLM router (→ in-house Gemma).

Runs the scrub → report path end-to-end under MOCK_LLM=1 (no network), and
checks the three things the port had to get right:
  - the OpenRouter call was re-pointed at furix's Gemma (model/endpoint come
    from furix config; no API-key gate),
  - the scrubber→router IPC is the in-memory mappings dict (no disk needed),
  - PII round-trips: raw identifiers are scrubbed out and re-identified back.

    python3 tests/siem/test_report.py        # direct
    pytest tests/siem/test_report.py         # under pytest
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

os.environ.setdefault("MOCK_LLM", "1")   # offline — must be set before furix config import

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from furix_mvp import config
from furix_mvp.siem import tenant
from furix_mvp.siem.scrub import DALScrubber
from furix_mvp.siem.scrub.dal_scrubber import _classify
from furix_mvp.siem.report import LLMRouter

_IP   = "203.0.113.50"     # external → ATTACKER_IP
_USER = "cfo_jdoe"         # cfo_ prefix → EXEC_USER


def _narrative() -> dict:
    """A minimal correlator-style attack_narrative with one exec user + one
    external attacker IP, so scrubbing yields deterministic EXEC_USER_1 /
    ATTACKER_IP_1 placeholders."""
    iocs = {"external_ips": [_IP], "mitre_techniques": ["T1213"],
            "affected_assets": ["phi_database"], "affected_users": [_USER],
            "affected_hosts": []}
    stages = [{"stage": 11, "name": "Collection", "technique": "T1213",
               "entities": [{"entity": _USER, "type": "user", "severity": "CRITICAL"}],
               "entity_count": 1, "first_seen": "2026-05-28T09:00:00", "evidence": ["bulk_phi_query"]}]
    return {
        "campaign_id": "ATK-TEST-0001", "severity": "CRITICAL", "confidence": 0.95,
        "first_seen": "2026-05-28T09:00:00", "last_seen": "2026-05-28T09:30:00",
        "duration_minutes": 30, "entry_point": _USER, "entity_count": 1,
        "kill_chain_coverage": [3, 11, 13], "kill_chain_completeness": 0.21,
        "affected_entities": [{"entity_key": _USER, "entity_type": "user",
                               "severity": "CRITICAL", "stages": [11]}],
        "attack_stages": stages, "iocs": iocs,
        "llm_context": {
            "system_prompt": "analyst prompt",
            "narrative_summary": f"Campaign began with {_USER} accessing PHI from {_IP}.",
            "structured_data": {
                "campaign_id": "ATK-TEST-0001", "severity": "CRITICAL",
                "entry_point": _USER, "iocs": iocs, "attack_timeline": stages,
                "affected_entities": [{"entity_key": _USER, "entity_type": "user",
                                       "severity": "CRITICAL", "stages": [11]}],
                "top_evidence": [{"source_ip": _IP, "user": _USER, "score": 60,
                                  "mitre_technique_id": "T1213"}],
            },
        },
    }


def test_scrub_reidentify_roundtrip():
    scrubber = DALScrubber()
    scrubbed_list, mappings = scrubber.scrub([_narrative()])
    scrubbed = scrubbed_list[0]
    entry = mappings["ATK-TEST-0001"]

    blob = json.dumps(scrubbed)
    assert _USER not in blob and _IP not in blob, "raw identifiers leaked into scrubbed output"
    assert {_USER, _IP}.issubset(set(entry["reverse"].values()))

    restored = json.dumps(scrubber.reidentify_report(scrubbed, entry))
    assert _USER in restored and _IP in restored, "re-identification failed to restore values"
    print(f"  ok  scrub→reidentify round-trip ({entry['tokens_scrubbed']} tokens)")


def test_report_wiring_repoint_and_inmemory_mappings():
    assert config.MOCK_LLM is True, "test must run with MOCK_LLM=1"
    assert os.environ.get("OPENROUTER_API_KEY") is None  # no OpenRouter key, yet it runs

    scrubber = DALScrubber()
    scrubbed_list, mappings = scrubber.scrub([_narrative()])

    with tempfile.TemporaryDirectory() as out:
        reports = LLMRouter().process_campaigns(
            scrubbed_list,
            anomaly_store_path=os.path.join(out, "nonexistent.json"),
            output_dir=out,
            mappings=mappings,            # in-memory IPC — no disk pii_mapping files
        )
    assert len(reports) == 1
    rep = reports[0]

    for key in ("executive_summary", "attack_timeline", "risk_assessment",
                "remediation", "key_evidence", "anomaly_explanation",
                "detected_anomalies", "iocs", "campaign_context", "processing"):
        assert key in rep, f"report missing section: {key}"

    # Gemma re-point: model + endpoint come from furix config, NOT OpenRouter.
    proc = rep["processing"]
    assert proc["llm_status"] == "success"
    assert proc["llm_model"] == config.GEMMA_MODEL
    assert proc["api_endpoint"] == config.GEMMA_BASE_URL
    assert "openrouter" not in proc["api_endpoint"].lower()

    # Re-identification reached into the LLM's response.
    para = rep["executive_summary"]["one_paragraph"]
    assert _IP in para and _USER in para, para
    assert "ATTACKER_IP_1" not in para and "EXEC_USER_1" not in para, para
    print(f"  ok  scrub→Gemma report via {proc['llm_model']} @ {proc['api_endpoint']}")


def test_scrub_classification_uses_tenant():
    assert _classify("cfo_jdoe", set()) == "EXEC_USER"        # tenant.EXEC_USER_PREFIXES
    assert _classify("svc_backup", set()) == "SVC_ACCOUNT"    # tenant.SVC_ACCOUNT_PREFIX
    assert _classify("portal.coventra.com", set()) == "INTERNAL_DOMAIN"  # tenant.ORG_DOMAIN
    assert _classify("coventra-secure.io", set()) == "ATTACKER_DOMAIN"   # tenant lookalike
    assert tenant.ORG_DOMAIN == "coventra.com"
    assert "cfo_" in tenant.EXEC_USER_PREFIXES
    print("  ok  scrubber classification keyed on externalised tenant assets")


def main() -> int:
    tests = [
        test_scrub_reidentify_roundtrip,
        test_report_wiring_repoint_and_inmemory_mappings,
        test_scrub_classification_uses_tenant,
    ]
    print(f"SIEM report smoke test — {len(tests)} cases")
    for t in tests:
        t()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

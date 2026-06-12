"""Module 3 smoke test — SIEM signature lane (rule engine) + severity engine.

Drives the real RuleEngine over ECS events produced by the Module-2 ingest
parsers, asserting the expected named rules fire (and benign traffic fires
none), then checks SeverityEngine classification. Also confirms the rule
engine's org assets were externalised into the shared tenant profile.

    python3 tests/siem/test_detect.py        # direct
    pytest tests/siem/test_detect.py         # under pytest
"""
from __future__ import annotations

import json
import os
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from furix_mvp.siem import tenant
from furix_mvp.siem.ingest import raw_to_ecs, jsonl_to_ecs
from furix_mvp.siem.detect import RuleEngine, rule_engine

# ── Sample events (reuse Module-2 parsers to build real ECS) ─────────────────

_RAW_CLOUDTRAIL = json.dumps({
    "eventTime": "2026-05-28T14:05:00Z", "eventSource": "s3.amazonaws.com",
    "eventName": "GetObject", "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.9",
    "userIdentity": {"userName": "svc_backup", "accountId": "111122223333"},
    "requestParameters": {"bucketName": "coventra-phi-backup",
                          "key": "claims/2026.csv", "objectCount": 500},
})
_RAW_PROOFPOINT = (
    "2026-05-28T14:00:00.000Z mx01 proofpoint: action=DELIVERED direction=inbound "
    'from=attacker@evil.example to=cfo@coventra.com disposition=bec spam_score=9.1 '
    "attachment=invoice.html dkim=fail spf=fail dmarc=fail"
)
_RAW_NGINX_BENIGN = (
    '10.10.5.30 - - [28/May/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" '
    '200 1024 "-" "Mozilla/5.0" 0.012 req-abc server=web01 vhost=portal.coventra.com'
)
_STRUCTURED_BULK_PHI = {
    "timestamp": "2026-05-28T03:14:00.000Z", "level": "WARNING",
    "message": "DB_AUDIT SELECT ON lab_results rows=50000",
    "log_type": "anomaly",
    "source": {"type": "database", "org": "Coventra", "host": "db-01",
               "ip": "10.30.1.10", "name": "imperva"},
    "metadata": {"src_ip": "10.10.5.20", "user": "dba_jones",
                 "action": "SELECT", "table": "lab_results", "row_count": 50000},
}

_ENGINE = RuleEngine()   # loads furix_mvp/siem/rules/rules.json + MITRE table


def _structured_ecs(record: dict) -> dict:
    doc, _ = jsonl_to_ecs.convert(record, json.dumps(record))
    return doc


def test_engine_loads_all_rules():
    # rules.json has 34 enabled rules. If any custom_handler were missing, that
    # rule would be skipped and the count would drop — so an exact match against
    # the file's enabled count validates the full handler wiring (no skips).
    with open(rule_engine.RULES_JSON_PATH, encoding="utf-8") as fh:
        enabled = [r for r in json.load(fh) if r.get("enabled", True)]
    assert len(_ENGINE._rules) == len(enabled) == 34, (len(_ENGINE._rules), len(enabled))
    print(f"  ok  rule engine loaded {len(_ENGINE._rules)} rules (no skips)")


def _detect(ev: dict) -> list[str]:
    risk = _ENGINE.detect(ev)
    if not risk:
        return []
    re0 = risk[0]
    assert re0["detector"] == "signature_rules"
    assert re0["mitre_technique_id"]
    assert re0["score"] > 0
    return re0["triggered_rules"]


def test_bulk_s3_phi_access_fires():
    fired = _detect(raw_to_ecs.parse_line(_RAW_CLOUDTRAIL))
    assert "bulk_s3_phi_access" in fired, fired
    print(f"  ok  CloudTrail PHI bulk S3 → {fired}")


def test_bec_phishing_fires():
    fired = _detect(raw_to_ecs.parse_line(_RAW_PROOFPOINT))
    assert "bec_phishing" in fired, fired
    print(f"  ok  Proofpoint BEC → {fired}")


def test_bulk_phi_query_fires():
    fired = _detect(_structured_ecs(_STRUCTURED_BULK_PHI))
    assert "bulk_phi_query" in fired, fired
    print(f"  ok  bulk SELECT on PHI table → {fired}")


def test_benign_fires_nothing():
    fired = _detect(raw_to_ecs.parse_line(_RAW_NGINX_BENIGN))
    assert fired == [], fired
    print("  ok  benign nginx 200 → no rules")


def test_severity_engine_classify():
    import numpy as np
    from furix_mvp.siem.detect.severity_engine import SeverityEngine
    se = SeverityEngine()
    assert se.classify(95) == "CRITICAL"
    assert se.classify(75) == "HIGH"
    assert se.classify(50) == "MEDIUM"
    assert se.classify(35) == "LOW"
    assert se.classify(10) == "NORMAL"
    # build_results filters NORMAL/below-threshold and sorts by score desc.
    events = [{"@timestamp": "t", "event": {"module": "cloud"}},
              {"@timestamp": "t", "event": {"module": "web"}}]
    results = se.build_results(
        events=events,
        fused_scores=np.array([95.0, 10.0]),
        rule_results=[(95.0, ["bulk_s3_phi_access"]), (10.0, [])],
        feature_matrix=np.zeros((2, 4)),
        threshold="LOW",
    )
    assert len(results) == 1
    assert results[0].severity == "CRITICAL"
    assert "bulk_s3_phi_access" in results[0].triggered_rules
    print("  ok  severity engine classify + build_results")


def test_tenant_assets_externalised():
    assert rule_engine.PHI_DB_IPS is tenant.PHI_DB_IPS
    assert rule_engine.PHI_TABLES is tenant.PHI_TABLES
    assert rule_engine.BEC_DOMAIN_PATTERNS is tenant.BEC_DOMAIN_PATTERNS
    assert rule_engine.HSM_APPROVED_ACTOR == tenant.HSM_APPROVED_ACTOR
    assert rule_engine.BULK_ROW_THRESHOLD == tenant.BULK_ROW_THRESHOLD
    # PHI_S3_BUCKETS reuses the Module-2 tenant.PHI_BUCKETS (deduped, not a copy).
    assert rule_engine.PHI_S3_BUCKETS is tenant.PHI_BUCKETS
    # Defaults preserved verbatim from the source engine.
    assert tenant.PHI_DB_IPS == {"10.30.1.10", "10.30.1.11"}
    assert tenant.HSM_APPROVED_ACTOR == "svc_cyberark_pam"
    assert tenant.BULK_ROW_THRESHOLD == 1000
    print("  ok  rule-engine org assets externalised + defaults preserved")


def main() -> int:
    tests = [
        test_engine_loads_all_rules,
        test_bulk_s3_phi_access_fires,
        test_bec_phishing_fires,
        test_bulk_phi_query_fires,
        test_benign_fires_nothing,
        test_severity_engine_classify,
        test_tenant_assets_externalised,
    ]
    print(f"SIEM detect smoke test — {len(tests)} cases")
    for t in tests:
        t()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

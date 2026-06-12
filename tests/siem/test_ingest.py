"""Module 2 smoke test — SIEM Layer-1 ECS ingestion.

Exercises the real entry point (``ensure_ecs`` → ``load_events``) end-to-end on
both dispatch paths (structured Coventra JSONL and raw vendor formats), and
verifies the tenant constants were externalised out of raw_to_ecs into the
shared tenant profile. Pure stdlib — runs under bare ``python3`` or pytest:

    python3 tests/siem/test_ingest.py        # direct
    pytest tests/siem/test_ingest.py         # under pytest
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

# Allow direct execution from the repo root (no install / no pytest needed).
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from furix_mvp.siem import tenant
from furix_mvp.siem.ingest import ensure_ecs, load_events, detect_format
from furix_mvp.siem.ingest import raw_to_ecs

# ── Sample inputs ─────────────────────────────────────────────────────────────

# 1. Structured Coventra JSONL (jsonl_to_ecs path): a bulk DB read flagged anomaly.
_STRUCTURED = {
    "timestamp": "2026-05-28T14:31:01.000Z",
    "level": "WARNING",
    "message": "bulk select on patients",
    "log_type": "anomaly",
    "source": {"type": "database", "org": "Coventra", "host": "db-01",
               "ip": "10.30.1.5", "name": "imperva"},
    "metadata": {"src_ip": "10.10.5.20", "user": "dba_jones",
                 "action": "SELECT", "table": "patients", "row_count": 50000},
    "mitre": {"technique": "T1005", "tactic": "TA0009 Collection",
              "name": "Data from Local System"},
}

# 2. Raw vendor lines (raw_to_ecs path): Proofpoint BEC to an exec + a PHI-bucket
#    CloudTrail bulk GetObject. Both lean on externalised tenant constants.
_RAW_PROOFPOINT = (
    "2026-05-28T14:00:00.000Z mx01 proofpoint: action=DELIVERED direction=inbound "
    'from=attacker@evil.example to=cfo@coventra.com disposition=bec spam_score=9.1 '
    "attachment=invoice.html dkim=fail spf=fail dmarc=fail"
)
_RAW_CLOUDTRAIL = json.dumps({
    "eventTime": "2026-05-28T14:05:00Z",
    "eventSource": "s3.amazonaws.com",
    "eventName": "GetObject",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.9",
    "userIdentity": {"userName": "svc_backup", "accountId": "111122223333"},
    "requestParameters": {"bucketName": "coventra-phi-backup",
                          "key": "claims/2026.csv", "objectCount": 500},
})


def _ingest(text: str, suffix: str) -> list[dict]:
    """Write `text` to a temp file, run the real Layer-1 entry, return events."""
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "sample" + suffix)
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        ecs_path = ensure_ecs(src)
        return load_events(ecs_path)


def test_structured_jsonl_path():
    fmt = detect_format(_write_tmp(json.dumps(_STRUCTURED), ".jsonl"))
    assert fmt == "structured_jsonl", fmt
    events = _ingest(json.dumps(_STRUCTURED), ".jsonl")
    assert len(events) == 1
    ev = events[0]
    assert ev["ecs"]["version"] == "8.11.0"
    assert ev["@timestamp"] == "2026-05-28T14:31:01.000Z"
    assert ev["event"]["kind"] == "alert"          # log_type=anomaly → alert
    assert ev["organization"]["name"] == "Coventra"  # from record.source.org
    assert ev["user"]["name"] == "dba_jones"
    assert "T1005" in ev["threat"]["technique"]["id"]
    assert ev["labels"]["log_type"] == "anomaly"   # record-level log_type → label
    print("  ok  structured JSONL → ECS (alert, user, MITRE)")


def test_raw_proofpoint_bec():
    events = _ingest(_RAW_PROOFPOINT, ".log")
    assert len(events) == 1
    ev = events[0]
    assert ev["event"]["module"] == "email"
    assert ev["event"]["severity"] >= 8            # BEC escalates
    assert ev["labels"]["exec_targeted"] is True   # cfo@ matches EXEC_ROLE_PREFIXES
    assert ev["labels"]["bec_indicator"] is True
    assert ev["organization"]["name"] == tenant.ORG_NAME   # raw path uses tenant org
    print("  ok  raw Proofpoint → ECS (BEC, exec-targeted, tenant org)")


def test_raw_cloudtrail_phi_bucket():
    events = _ingest(_RAW_CLOUDTRAIL, ".log")
    assert len(events) == 1
    ev = events[0]
    assert ev["event"]["module"] == "cloud"
    assert ev["labels"]["phi_bucket"] is True      # coventra-phi-backup in PHI_BUCKETS
    assert ev["event"]["severity"] >= 6            # PHI + bulk escalates
    print("  ok  raw CloudTrail → ECS (PHI bucket, bulk escalation)")


def test_tenant_constants_externalised():
    # The parser must reference the shared tenant profile, not its own literals.
    assert raw_to_ecs.PHI_BUCKETS is tenant.PHI_BUCKETS
    assert raw_to_ecs.EXEC_ROLE_PREFIXES is tenant.EXEC_ROLE_PREFIXES
    assert raw_to_ecs.ORG_NAME == tenant.ORG_NAME
    assert raw_to_ecs.PAM_VAULT_IP == tenant.PAM_VAULT_IP
    # And the defaults match the source engine's Coventra values verbatim.
    assert "coventra-phi-backup" in tenant.PHI_BUCKETS
    assert "cfo" in tenant.EXEC_ROLE_PREFIXES
    assert tenant.PAM_VAULT_IP == "10.30.6.10"
    print("  ok  tenant constants externalised + defaults preserved")


def _write_tmp(text: str, suffix: str) -> str:
    """Persist a one-off temp file (caller-owned) for format detection checks."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text + "\n")
    return path


def main() -> int:
    tests = [
        test_structured_jsonl_path,
        test_raw_proofpoint_bec,
        test_raw_cloudtrail_phi_bucket,
        test_tenant_constants_externalised,
    ]
    print(f"SIEM ingest smoke test — {len(tests)} cases")
    for t in tests:
        t()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

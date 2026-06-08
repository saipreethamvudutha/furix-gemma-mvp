"""Tests for config-state compliance checking (the 'is it implemented?' half).

Proves: deterministic pass/fail, control mapping, framework expansion via SCF
crosswalk, NA handling for missing data, and repeatability.

Run:  cd "MVP_TEST GEMMA" && MOCK_LLM=1 RAG_ENABLED=0 .venv/bin/python -m pytest tests/test_config_checks.py
"""
import os
os.environ.setdefault("MOCK_LLM", "1")
os.environ.setdefault("RAG_ENABLED", "0")

from furix_mvp import config_checks as cc

INSECURE = {
    "aws_account": {"root_mfa_enabled": False, "password_policy": {"min_length": 8}},
    "iam_users": [{"name": "alice", "mfa_enabled": True}, {"name": "svc", "mfa_enabled": False}],
    "s3_buckets": [{"name": "data", "public": True, "encrypted": False}],
    "cloudtrail": {"enabled": False},
    "security_groups": [{"name": "sg-1", "open_ingress": [{"cidr": "0.0.0.0/0", "port": 22}]}],
    "tls_endpoints": [{"name": "api", "min_version": "1.0"}],
    "backups": {"configured": False},
}

SECURE = {
    "aws_account": {"root_mfa_enabled": True, "password_policy": {"min_length": 16}},
    "iam_users": [{"name": "alice", "mfa_enabled": True}, {"name": "bob", "mfa_enabled": True}],
    "s3_buckets": [{"name": "data", "public": False, "encrypted": True}],
    "cloudtrail": {"enabled": True},
    "security_groups": [{"name": "sg-1", "open_ingress": [{"cidr": "10.0.0.0/8", "port": 22}]}],
    "tls_endpoints": [{"name": "api", "min_version": "1.3"}],
    "backups": {"configured": True},
}


def test_insecure_config_fails_expected_controls():
    r = cc.evaluate(INSECURE)
    assert r["summary"]["fail"] >= 7
    for ctrl in ("Control 6", "Control 3", "Control 8", "Control 12", "Control 11"):
        assert ctrl in r["failed_controls"], f"{ctrl} should be failing"


def test_secure_config_passes():
    r = cc.evaluate(SECURE)
    assert r["summary"]["fail"] == 0
    assert r["failed_controls"] == []
    assert r["summary"]["score"] == 1.0


def test_findings_are_control_and_framework_mapped():
    r = cc.evaluate(INSECURE)
    f = next(x for x in r["findings"] if x["check_id"] == "CFG-ROOT-MFA")
    assert f["status"] == "fail"
    assert "Control 6" in f["control_ids"]
    # framework expansion present (built-in tables -> at least nist_csf)
    assert f["frameworks"], "expected framework expansion via crosswalk"


def test_missing_data_is_na_not_fail():
    r = cc.evaluate({"s3_buckets": [{"name": "x", "public": False, "encrypted": True}]})
    # only the two S3 checks are assessed; everything else is NA
    statuses = {f["check_id"]: f["status"] for f in r["findings"]}
    assert statuses["CFG-ROOT-MFA"] == "na"
    assert statuses["CFG-S3-PUBLIC"] == "pass"
    assert r["summary"]["na"] >= 6


def test_deterministic():
    a = cc.evaluate(INSECURE)
    b = cc.evaluate(INSECURE)
    assert a == b


def test_partial_posture_rolls_up_to_fail():
    # one passing + one failing check on the same control -> control posture = fail
    cfg = {"s3_buckets": [{"name": "ok", "public": False, "encrypted": False}]}  # public=pass, enc=fail
    r = cc.evaluate(cfg)
    assert r["posture"]["Control 3"] == "fail"

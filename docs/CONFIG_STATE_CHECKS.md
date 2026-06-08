# Config-State Compliance Checking

Compliance has two halves. Furix already did the first; this adds the second:

```
   "Did something happen?"          "Is the control IMPLEMENTED?"
   event → controls (mapping.py)    config → pass/fail (config_checks.py)
   the SIEM/GRC half                the Tenable/Qualys/Wiz half
```

`furix_mvp/config_checks.py` is a **deterministic policy engine**: each check is a
pure function over a config snapshot that returns **pass / fail / na**, mapped to
CIS controls and — via the SCF crosswalk — to every other framework. No LLM, no
external binary. Same input → same posture (what an auditor needs).

These checks mirror CIS-Benchmark / OVAL / OPA-Rego rules. In production you would
load OVAL/SCAP content or OPA bundles; the **evaluation harness and the
control-mapping are exactly this module**.

## Use it

```python
from furix_mvp import config_checks
result = config_checks.evaluate(snapshot)   # snapshot = normalized config dict
```
or over HTTP:
```
POST /api/config-scan   { "config": { ...snapshot... } }
```

## Input — a normalized config snapshot

```json
{
  "aws_account": {"root_mfa_enabled": false, "password_policy": {"min_length": 8}},
  "iam_users":   [{"name": "svc", "mfa_enabled": false}],
  "s3_buckets":  [{"name": "data", "public": true, "encrypted": false}],
  "cloudtrail":  {"enabled": false},
  "security_groups": [{"name": "sg-1", "open_ingress": [{"cidr": "0.0.0.0/0", "port": 22}]}],
  "tls_endpoints": [{"name": "api", "min_version": "1.0"}],
  "backups":     {"configured": false}
}
```
Missing sections → those checks return **na** (not assessed), never a false fail.

## Output

```json
{
  "findings": [{"check_id": "CFG-ROOT-MFA", "status": "fail", "severity": "critical",
                "control_ids": ["Control 6"], "frameworks": {...}, "evidence": "root_mfa_enabled=False"}, ...],
  "summary": {"pass": 0, "fail": 9, "na": 0, "total": 9, "score": 0.0},
  "failed_controls": ["Control 3","Control 4","Control 5","Control 6","Control 8","Control 11","Control 12"],
  "posture": {"Control 6": "fail", ...}
}
```

## Checks shipped (each = one CIS-Benchmark-style rule)

| Check | Control | What it verifies |
|---|---|---|
| CFG-ROOT-MFA | 6 | root account uses MFA |
| CFG-IAM-MFA | 6 | all IAM users have MFA |
| CFG-PW-LEN | 5 | password policy ≥ 14 chars |
| CFG-S3-PUBLIC | 3 | no public object storage |
| CFG-S3-ENC | 3 | object storage encrypted at rest |
| CFG-AUDIT-LOG | 8 | audit logging (CloudTrail) enabled |
| CFG-NET-SSH | 12 | no world-open SSH/RDP |
| CFG-TLS-MIN | 4 | TLS 1.2+ enforced |
| CFG-BACKUP | 11 | backups configured |

Add a row to `CHECKS` in `config_checks.py` to extend. With `SCF_PATH` set, every
finding's `frameworks` spans NIST CSF, NIST 800-53, HIPAA, PCI-DSS, SOC 2, …

## Tested

`tests/test_config_checks.py` (6 tests): insecure config fails the expected
controls, secure config scores 1.0, findings are control + framework mapped,
missing data is `na` (not a false fail), determinism, and partial posture rolls
up to fail.

## Roadmap

This is the deterministic harness. Next: ingest real **OVAL/SCAP** content (host)
and **OPA/Rego or Prowler/Checkov** policies (cloud), and key their rule IDs to SCF
control IDs — see `ENTERPRISE_ROADMAP.md` Phase 2.3.

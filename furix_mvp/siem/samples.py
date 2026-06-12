"""Built-in SIEM sample data for the dashboard "Load sample" action.

A compact but correlated attack campaign: one external attacker IP
(203.0.113.66) pivoting across three identities and stages —
  • cfo_jdoe   : impossible-travel logins (Okta)        → Credential Access
  • dba_oracle1: bulk PHI database reads (Imperva DAM)  → Collection
  • svc_backup : bulk PHI S3 retrieval (AWS CloudTrail) → Collection / Exfil
All raw-vendor formats so the ingest layer auto-detects each line. Fed through
the pipeline this clusters into a single multi-entity campaign.
"""
from __future__ import annotations

_ATTACKER_IP = "203.0.113.66"

# One raw log line per entry, mixed vendor formats (Okta JSON · Imperva CEF ·
# CloudTrail JSON). detect_source() routes each line individually.
_LINES = [
    # cfo_jdoe — two impossible-travel logins from the attacker IP (Okta)
    '{"eventType":"user.session.start","published":"2026-05-28T02:14:00.000Z","severity":"INFO",'
    '"actor":{"alternateId":"cfo_jdoe@coventra.com","displayName":"J Doe"},'
    '"client":{"ipAddress":"203.0.113.66","geographicalContext":{"country":"RU","city":"Moscow"}},'
    '"outcome":{"result":"SUCCESS"},"debugContext":{"debugData":{"anomalyType":"impossible_travel",'
    '"previousLoginIp":"10.10.5.20","previousLoginLocation":"US","timeSinceLastLoginMin":"11"}},'
    '"target":[{"displayName":"VPN Gateway"}]}',

    '{"eventType":"user.session.start","published":"2026-05-28T02:16:30.000Z","severity":"INFO",'
    '"actor":{"alternateId":"cfo_jdoe@coventra.com","displayName":"J Doe"},'
    '"client":{"ipAddress":"203.0.113.66","geographicalContext":{"country":"RU","city":"Moscow"}},'
    '"outcome":{"result":"SUCCESS"},"debugContext":{"debugData":{"anomalyType":"impossible_travel",'
    '"previousLoginIp":"10.10.5.20","previousLoginLocation":"US","timeSinceLastLoginMin":"3"}},'
    '"target":[{"displayName":"Finance Portal"}]}',

    # dba_oracle1 — two bulk PHI SELECTs from the attacker IP (Imperva DAM)
    '2026-05-28T02:20:00.000Z db-imperva CEF:0|Imperva Inc.|SecureSphere|14|3001|DB Audit|High|'
    'act=SELECT suser=dba_oracle1 src=203.0.113.66 dhost=phi-db-01 dst=10.30.1.10 dpt=1521 '
    'cs1=Oracle cs2=coventra_phi cs3=lab_results cnt=48000 duration=910ms [PHI_DATA_ACCESS]',

    '2026-05-28T02:22:10.000Z db-imperva CEF:0|Imperva Inc.|SecureSphere|14|3001|DB Audit|High|'
    'act=SELECT suser=dba_oracle1 src=203.0.113.66 dhost=phi-db-01 dst=10.30.1.10 dpt=1521 '
    'cs1=Oracle cs2=coventra_phi cs3=member_health_records cnt=52000 duration=1180ms [PHI_DATA_ACCESS]',

    # svc_backup — three bulk PHI S3 retrievals from the attacker IP (CloudTrail)
    '{"eventTime":"2026-05-28T02:26:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject",'
    '"awsRegion":"us-east-1","sourceIPAddress":"203.0.113.66",'
    '"userIdentity":{"userName":"svc_backup","accountId":"111122223333"},'
    '"requestParameters":{"bucketName":"coventra-phi-backup","key":"claims/2026-q2.csv","objectCount":900}}',

    '{"eventTime":"2026-05-28T02:28:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject",'
    '"awsRegion":"us-east-1","sourceIPAddress":"203.0.113.66",'
    '"userIdentity":{"userName":"svc_backup","accountId":"111122223333"},'
    '"requestParameters":{"bucketName":"coventra-phi-backup","key":"claims/2026-q1.csv","objectCount":1200}}',

    '{"eventTime":"2026-05-28T02:30:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject",'
    '"awsRegion":"us-east-1","sourceIPAddress":"203.0.113.66",'
    '"userIdentity":{"userName":"svc_backup","accountId":"111122223333"},'
    '"requestParameters":{"bucketName":"coventra-claims-archive","key":"archive/all-2025.csv","objectCount":2400}}',
]

SIEM_SAMPLE = "\n".join(_LINES) + "\n"

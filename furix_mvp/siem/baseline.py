"""Lightweight synthetic BENIGN baseline for training the ML + UEBA lanes.

This is NOT the source engine's full 810K-line Coventra corpus — it is just
enough well-behaved activity (business hours, private IPs, small data volumes,
US geo) across the peer groups so the IsolationForest + ECOD ensemble and the
UEBA KDE profiles fit to something meaningful. It deliberately includes the demo
attack identities (cfo_jdoe, dba_oracle1, svc_backup) so UEBA can baseline them
individually and later flag their anomalous behaviour.

For production accuracy, train on REAL baseline logs via the CLI's --logs option
(or a LogForge bundle); the synthetic set is for quickstart / demos.
"""
from __future__ import annotations

import random
from typing import Any, Dict, List

# (username, peer-group role) — covers each tenant peer group.
_USERS = [
    ("cfo_jdoe", "leadership"), ("ciso_smith", "leadership"),
    ("dba_oracle1", "dba"), ("dba_mssql1", "dba"),
    ("svc_backup", "service"), ("svc_etl", "service"),
    ("soc_analyst1", "soc"), ("cloud_ops_aws1", "it_ops"),
    ("jdoe", "general"), ("asmith", "general"), ("bwong", "general"), ("kpatel", "general"),
]


def _ts(rng: random.Random) -> str:
    """Business-hours timestamp on a weekday in 2026-05."""
    h, m, s = rng.randint(8, 18), rng.randint(0, 59), rng.randint(0, 59)
    day = rng.choice([25, 26, 27, 28])
    return f"2026-05-{day:02d}T{h:02d}:{m:02d}:{s:02d}.000Z"


def _ecs(module: str, action: str, user: str, src_ip: str, ts: str, *,
         message: str, dst_port: int | None = None, proto: str | None = None,
         row_count: int | None = None, s3_object_count: int | None = None,
         status: int | None = None) -> Dict[str, Any]:
    ev: Dict[str, Any] = {
        "ecs": {"version": "8.11.0"}, "@timestamp": ts,
        "event": {"module": module, "action": action, "outcome": "success", "severity": 2},
        "user": {"name": user}, "source": {"ip": src_ip},
        "labels": {"geo_country": "US"}, "message": message,
        "organization": {"name": "Coventra Health Insurance"},
    }
    if dst_port is not None:
        ev["destination"] = {"port": dst_port}
    if proto is not None:
        ev.setdefault("network", {})["protocol"] = proto
    if row_count is not None:
        ev["labels"]["row_count"] = row_count
    if s3_object_count is not None:
        ev["labels"]["s3_object_count"] = s3_object_count
    if status is not None:
        ev.setdefault("http", {}).setdefault("response", {})["status_code"] = status
    return ev


def generate(n: int = 840, *, seed: int = 7) -> List[Dict[str, Any]]:
    """Return ~n benign ECS events spread across the peer groups."""
    rng = random.Random(seed)
    events: List[Dict[str, Any]] = []
    per = max(6, n // len(_USERS))

    for user, role in _USERS:
        for _ in range(per):
            ts = _ts(rng)
            src = f"10.10.{rng.randint(1, 8)}.{rng.randint(10, 200)}"
            if role in ("leadership", "general", "soc"):
                if rng.random() < 0.6:
                    events.append(_ecs("authentication", "user.authentication", user, src, ts,
                                        message=f"AUTH_SUCCESS method=Okta user={user} src={src} app=Portal"))
                else:
                    events.append(_ecs("web_server", "get", user, src, ts, dst_port=443, proto="https",
                                        status=200, message=f"HTTP GET /app/home 200 client={src} user={user}"))
            elif role == "dba":
                rows = rng.randint(20, 400)
                events.append(_ecs("database", "select", user, src, ts, dst_port=1521, proto="tcp",
                                    row_count=rows,
                                    message=f"DB_AUDIT SELECT ON reports rows={rows} user={user}"))
            elif role == "service":
                objs = rng.randint(1, 25)
                events.append(_ecs("cloud", "getobject", user, src, ts, s3_object_count=objs,
                                    message=f"S3_ACCESS GetObject bucket=coventra-reports "
                                            f"object_count={objs} iam_user={user}"))
            else:  # it_ops
                events.append(_ecs("cloud", "describeinstances", user, src, ts,
                                   message=f"CLOUDTRAIL event=DescribeInstances user={user} region=us-east-1"))

    rng.shuffle(events)
    return events

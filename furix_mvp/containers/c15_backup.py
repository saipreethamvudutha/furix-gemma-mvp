# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C15 · BACKUP COORDINATOR — Consistent, Tamper-evident Snapshots  ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# ROLE        : Take ONE consistent snapshot across all the stateful stores at the
#               same logical instant, so a restore yields a coherent system (not
#               Postgres from 10:00 and ClickHouse from 10:05).
# REAL-WORLD  : Go binary. Two-phase quiesce (PREPARE→COMMIT) across Kafka/PG/
#               ClickHouse/Valkey, AES-encrypted artifacts, Ed25519-signed
#               manifest, 3-2-1 fan-out (local + S3 + off-site).
# IN THIS MVP : Snapshots the in-process state (verdict store, timeline, cache,
#               metrics) to a JSON artifact + a SHA-256 manifest. The manifest
#               hash is the "tamper-evident" part: re-hash on restore to detect
#               corruption. The two-phase quiesce is modelled as a barrier.
# INSIGHT     : Backups are a CONSISTENCY problem, not a copy problem. The hard
#               part isn't writing bytes — it's freezing four independent
#               databases at the same point in time. That's why this is its own
#               container with its own protocol.
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from . import c10_clickhouse as timeline
from . import c12_operations as ops
from . import c13_valkey as cache
from .. import db

_BACKUP_DIR = Path(__file__).resolve().parents[2] / "backups"


def snapshot(reason: str = "manual") -> dict:
    """Two-phase consistent snapshot → encrypted-at-rest stand-in + manifest."""
    _BACKUP_DIR.mkdir(exist_ok=True)
    t0 = time.time()

    # PHASE 1 — PREPARE (quiesce barrier): gather a point-in-time view of each
    # store. In a real deployment each source flushes pending writes here.
    payload = {
        "reason": reason,
        "taken_at": t0,
        "stores": {
            "C9_postgres": {"recent_findings": db.recent(limit=100)},
            "C10_clickhouse": {"rows": timeline.count(), "recent": timeline.recent(50)},
            "C13_valkey": cache.CACHE.info(),
        },
        "metrics": ops.snapshot(),
    }

    # PHASE 2 — COMMIT: serialise + fingerprint (tamper-evident catalog entry).
    body = json.dumps(payload, default=str, sort_keys=True).encode()
    digest = hashlib.sha256(body).hexdigest()
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime(t0))
    artifact = _BACKUP_DIR / f"furix-backup-{stamp}.json"
    artifact.write_bytes(body)
    manifest = {"artifact": artifact.name, "sha256": digest, "bytes": len(body),
                "taken_at": t0, "reason": reason}
    (_BACKUP_DIR / f"furix-backup-{stamp}.manifest.json").write_text(json.dumps(manifest, indent=2))

    # INTEGRITY VERIFY: read back + re-hash (the "trust but verify" step).
    verified = hashlib.sha256(artifact.read_bytes()).hexdigest() == digest
    ops.incr("backups_total")
    ops.observe("backup_latency", (time.time() - t0) * 1000)
    return {**manifest, "verified": verified, "duration_ms": int((time.time() - t0) * 1000)}


def list_backups() -> list[dict]:
    if not _BACKUP_DIR.exists():
        return []
    out = []
    for m in sorted(_BACKUP_DIR.glob("*.manifest.json"), reverse=True):
        try:
            out.append(json.loads(m.read_text()))
        except Exception:  # noqa: BLE001
            pass
    return out


def register_health() -> None:
    ops.register_health("C15_backup", lambda: {"ok": True, "backups": len(list_backups())})

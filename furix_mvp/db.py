"""CONTAINER C9 · Persistence for findings, verdicts, per-agent provenance, and audit.

Uses the same PostgreSQL instance as RAG when available; otherwise keeps an
in-memory ring so the MVP stays fully functional offline. Enterprise-grade
surface (immutable audit row per analysis), light footprint.
"""
from __future__ import annotations
import json
import threading
from collections import deque

from . import config

_lock = threading.Lock()
_mem: deque = deque(maxlen=200)   # offline fallback store
_pg_ok: bool | None = None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mvp_findings (
  finding_id text PRIMARY KEY,
  created_at timestamptz DEFAULT now(),
  log_type text,
  finding jsonb,
  verdict jsonb,
  agents jsonb,
  dal jsonb
);
CREATE TABLE IF NOT EXISTS mvp_audit (
  id bigserial PRIMARY KEY,
  ts timestamptz DEFAULT now(),
  finding_id text,
  event text,
  detail jsonb
);
"""


def _conn():
    import psycopg2
    return psycopg2.connect(host=config.PG_HOST, port=config.PG_PORT,
                            dbname=config.PG_DBNAME, user=config.PG_USER,
                            password=config.PG_PASSWORD, connect_timeout=5)


def init() -> bool:
    global _pg_ok
    if not config.RAG_ENABLED:
        _pg_ok = False
        return False
    try:
        conn = _conn(); conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(_SCHEMA)
        conn.close(); _pg_ok = True
    except Exception:  # noqa: BLE001
        _pg_ok = False
    return _pg_ok


def save(record: dict) -> None:
    if _pg_ok is None:
        init()
    if _pg_ok:
        try:
            conn = _conn(); conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO mvp_findings (finding_id, log_type, finding, verdict, agents, dal) "
                    "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (finding_id) DO NOTHING",
                    (record["finding_id"], record["log_type"],
                     json.dumps(record["finding"]), json.dumps(record["verdict"]),
                     json.dumps(record["agents"]), json.dumps(record.get("dal", {}))))
                cur.execute("INSERT INTO mvp_audit (finding_id, event, detail) VALUES (%s,%s,%s)",
                            (record["finding_id"], "analysis_completed",
                             json.dumps({"severity": record["verdict"].get("severity"),
                                         "agents": [a["agent"] for a in record["agents"]]})))
            conn.close(); return
        except Exception:  # noqa: BLE001 — fall through to memory
            pass
    with _lock:
        _mem.appendleft(record)


def recent(limit: int = 25) -> list[dict]:
    if _pg_ok:
        try:
            conn = _conn()
            with conn.cursor() as cur:
                cur.execute("SELECT finding_id, created_at, log_type, verdict "
                            "FROM mvp_findings ORDER BY created_at DESC LIMIT %s", (limit,))
                rows = cur.fetchall()
            conn.close()
            return [{"finding_id": r[0], "created_at": str(r[1]), "log_type": r[2],
                     "verdict": r[3]} for r in rows]
        except Exception:  # noqa: BLE001
            pass
    with _lock:
        return [{"finding_id": r["finding_id"], "log_type": r["log_type"],
                 "verdict": r["verdict"]} for r in list(_mem)[:limit]]


def backend() -> str:
    if _pg_ok is None:
        init()
    return "postgresql" if _pg_ok else "in-memory"

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C8 · STORAGE WRITER + DETECTION ENGINE                           ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# ROLE        : Two peer jobs in one box.
#               (1) Storage Writer: take canonical events + AI verdicts and
#                   persist them — graph/relational rows to Postgres (C9), a
#                   timeline row to ClickHouse (C10).
#               (2) Detection Engine: run fast, deterministic rules over every
#                   event. When a rule fires on something nasty, it asks the AI
#                   Brain (C14) for a deeper look by publishing ai.enrichment.
# REAL-WORLD  : Go + aiokafka. Idempotent batch writes (dedup by id), 500K
#               rows/sec to ClickHouse.
# IN THIS MVP : Subscribes normalized.events / detection.input / ai.verdicts and
#               does the lite equivalent. Rules are plain Python predicates.
# INSIGHT     : Detection rules (deterministic) and the AI Brain (probabilistic)
#               are PARTNERS. Rules are cheap and catch the known; the model is
#               expensive and reasons about the novel. C8 routes the scary,
#               novel stuff "up" to C14 and lets rules handle the obvious.
from __future__ import annotations

import time

from .c5_bus import BUS, T
from . import c10_clickhouse as timeline
from . import c12_operations as ops
from .. import db   # C9 relational persistence (existing module)

_alerts: list[dict] = []   # recent detection alerts (dashboard reads this)


# ── Detection rules: (name, predicate(event) -> bool, severity) ──────────────
def _rule_malware(e):  return e["signals"].get("malware")
def _rule_c2(e):       return e["signals"].get("c2_or_exfil") or e["intel"]["ioc_hits"]
def _rule_brute(e):    return e["signals"].get("failed_logins") and e["signals"].get("successful_logins")
def _rule_priv(e):     return e["signals"].get("privilege_escalation")
def _rule_newadmin(e): return e["signals"].get("account_creation")

RULES = [
    ("malware_execution",      _rule_malware, "critical"),
    ("c2_or_exfil_or_ioc",     _rule_c2,      "critical"),
    ("brute_force_success",    _rule_brute,   "high"),
    ("privilege_escalation",   _rule_priv,    "high"),
    ("unauthorized_account",   _rule_newadmin,"high"),
]


def on_normalized(event: dict) -> None:
    """Storage Writer: every canonical event lands on the timeline (C10)."""
    timeline.append({"finding_id": "", "log_type": event.get("log_type", ""),
                     "severity": "", "summary": event.get("summary", "")})
    BUS.publish(T.KG_FINDINGS, {"log_type": event.get("log_type"),
                                "controls": event.get("candidate_controls", [])})
    ops.incr("storage_events_total")


def on_detection(event: dict) -> None:
    """Detection Engine: fire rules; escalate critical hits to the AI Brain."""
    for name, pred, severity in RULES:
        try:
            if pred(event):
                alert = {"rule": name, "severity": severity, "ts": time.time(),
                         "log_type": event.get("log_type"),
                         "ioc_hits": event["intel"]["ioc_hits"]}
                _alerts.append(alert)
                if len(_alerts) > 200:
                    del _alerts[: len(_alerts) - 200]
                ops.incr("detections_total", rule=name)
                # NOTE: in the full furix arch the Detection Engine can escalate
                # to the AI Brain here. In this pipeline C6 already routes EVERY
                # normalised event to ai.enrichment, so re-publishing would double
                # the work. We keep the alert; the AI reasoning already happens.
        except Exception as e:  # noqa: BLE001 — a bad rule must not stop the engine
            ops.incr("detection_errors_total", rule=name)
            print(f"[C8 detection] rule {name} error: {e}")


def on_verdict(record: dict) -> None:
    """Storage Writer: persist the AI Brain's verdict (relational + timeline)."""
    db.save({k: record[k] for k in ("finding_id", "log_type", "finding", "verdict", "agents", "dal")})
    v = record["verdict"]
    timeline.append({"finding_id": record["finding_id"], "log_type": record["log_type"],
                     "severity": v.get("severity", ""), "summary": v.get("summary", "")})
    ops.incr("verdicts_persisted_total", severity=v.get("severity", "unknown"))


def recent_alerts(limit: int = 50) -> list[dict]:
    return _alerts[-limit:][::-1]


def start() -> None:
    BUS.subscribe(T.NORMALIZED, on_normalized)
    BUS.subscribe(T.DETECTION_INPUT, on_detection)
    BUS.subscribe(T.AI_VERDICTS, on_verdict)
    ops.register_health("C8_storage_detect", lambda: {
        "ok": True, "rules": len(RULES), "alerts": len(_alerts)})

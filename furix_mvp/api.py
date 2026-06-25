# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C11 · DASHBOARD — FastAPI surface (routes + static UI)           ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# This file IS container C11's backend. It exposes two analysis paths:
#   • POST /api/analyze        — synchronous, returns the full verdict (UI path)
#   • POST /api/analyze/batch  — many logs; "pipeline" mode streams them through
#     the real C2→C6→C14→C8 bus flow, "direct" mode scores each inline.
# Plus operational views (metrics/alerts/timeline/backup) so you can watch the
# whole appliance — essential when stress-testing Gemma.
from __future__ import annotations
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import brain, config, db, llm, rag, pipeline, config_checks, stress
from .schemas import AnalyzeRequest
from .samples import SAMPLE_LOGS
from .containers import (c12_operations as ops, c8_storage_detect as c8,
                         c10_clickhouse as c10, c15_backup as c15,
                         c3_scan_engine as c3, c4_intel_sync as c4)

app = FastAPI(title="Furix Appliance (15-container MVP)", version="0.2.0")
_STATIC = Path(__file__).resolve().parent.parent / "static"

_PERSIST_KEYS = ("finding_id", "log_type", "finding", "verdict", "agents", "dal")


def _persist(record: dict) -> None:
    db.save({k: record[k] for k in _PERSIST_KEYS})


@app.on_event("startup")
def _startup() -> None:
    # LITE mode (default): one process IS all 15 containers → bootstrap wires the
    # whole bus here. SPLIT mode (docker-compose): each container runs its own
    # role, so the dashboard sets FURIX_BOOTSTRAP=0 and does NOT start consumers.
    import os
    if os.environ.get("FURIX_BOOTSTRAP", "1") == "1":
        pipeline.bootstrap()


# ── UI ────────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (_STATIC / "index.html").read_text(encoding="utf-8")


@app.get("/demo", response_class=HTMLResponse)
def demo() -> str:
    """Client-facing pipeline demo: shows each container/step lighting up live
    as one log flows C2→C6→DAL→RAG→C14/C7→C8, then the final verdict."""
    return (_STATIC / "demo.html").read_text(encoding="utf-8")


@app.get("/stress", response_class=HTMLResponse)
def stress_page() -> str:
    """Client-facing stress/benchmark page: routing (deterministic vs Gemma per
    log) + Gemma capacity ramp (p50/p95/p99, throughput, saturation)."""
    return (_STATIC / "stress.html").read_text(encoding="utf-8")


class StressRequest(BaseModel):
    scenario: str                       # "routing" | "gemma_ramp"
    params: dict = {}


@app.post("/api/stress/start")
def stress_start(req: StressRequest) -> dict:
    """Kick off a benchmark in the background; returns a job id to poll."""
    job_id = stress.start(req.scenario, req.params or {})
    return {"job_id": job_id}


@app.get("/api/stress/status")
def stress_status(id: str) -> dict:
    """Poll a running/finished benchmark: progress + partial/final results."""
    job = stress.get_job(id)
    if not job:
        return {"error": "unknown job id", "state": "error"}
    return job


# ── Analysis ──────────────────────────────────────────────────────────────────
@app.post("/api/analyze")
def analyze(req: AnalyzeRequest) -> dict:
    record = brain.analyze(req.raw_log, req.log_type, req.agents)
    _persist(record)
    return record


class ConfigScanRequest(BaseModel):
    config: dict                # a normalized config snapshot (see config_checks.py)


@app.post("/api/config-scan")
def config_scan(req: ConfigScanRequest) -> dict:
    """Config-state compliance: 'is the control IMPLEMENTED?' Deterministic
    policy-as-code (no LLM) → pass/fail findings mapped to controls + frameworks."""
    return config_checks.evaluate(req.config)


class BatchRequest(BaseModel):
    logs: list[str]
    mode: str = "direct"        # "direct" = inline verdicts; "pipeline" = bus flow
    source: str = "batch"


@app.post("/api/analyze/batch")
def analyze_batch(req: BatchRequest) -> dict:
    """Ingest MANY logs at once. Returns per-log verdicts (direct) or a pipeline
    summary (pipeline). This is the multi-log ingestion entry point."""
    if req.mode == "pipeline":
        summary = pipeline.ingest_many(req.logs, source=req.source)
        return {"mode": "pipeline", **summary, "recent_verdicts": db.recent(limit=len(req.logs))}
    results = []
    for raw in req.logs:
        rec = brain.analyze(raw)
        _persist(rec)
        results.append({"finding_id": rec["finding_id"], "log_type": rec["log_type"],
                        "verdict": rec["verdict"], "cache_hit": rec.get("cache_hit"),
                        "latency_ms": rec["total_latency_ms"]})
    return {"mode": "direct", "count": len(results), "results": results}


# ── Operational views (the C12 / C8 / C10 / C15 / C3 / C4 faces) ──────────────
@app.get("/api/health")
def health() -> dict:
    return {"llm": llm.health(), "rag": rag.status(), "persistence": db.backend(),
            "agents": config.enabled_agents(), "parallel_agents": config.PARALLEL_AGENTS,
            "operations": ops.health()}


@app.get("/api/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    return ops.render_prometheus()      # real Prometheus exposition format


@app.get("/api/ops")
def ops_snapshot() -> dict:
    return ops.snapshot()


@app.get("/api/alerts")
def alerts() -> dict:
    return {"alerts": c8.recent_alerts()}


@app.get("/api/timeline")
def timeline() -> dict:
    return {"timeline": c10.recent()}


@app.get("/api/recent")
def recent() -> dict:
    return {"recent": db.recent()}


@app.post("/api/scan")
def scan(body: dict) -> dict:
    return c3.scan(body.get("target", "10.0.0.5"), body.get("services"))


@app.post("/api/intel/refresh")
def intel_refresh() -> dict:
    return c4.refresh()


@app.post("/api/backup")
def backup() -> dict:
    return c15.snapshot(reason="dashboard")


@app.get("/api/backups")
def backups() -> dict:
    return {"backups": c15.list_backups()}


@app.get("/api/samples")
def samples() -> dict:
    return {"samples": dict(SAMPLE_LOGS)}


if _STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

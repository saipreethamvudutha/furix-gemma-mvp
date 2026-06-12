"""SIEM pipeline orchestrator.

Chains the ported engine end to end and emits structured progress so a job
runner / dashboard can show exactly what the backend is doing:

    raw logs → ECS ingest → detector lanes (aggregate) → anomaly store
            → risk accumulator → multistage correlator → DAL scrub
            → Gemma incident reports

``analyze_logs`` is synchronous and takes a ``progress`` callback; the job
manager (``furix_mvp.siem.jobs``) runs it on a background thread and records the
progress events. Returns a JSON-serialisable result (campaigns + reports + stats).

The rule lane runs with zero training; the UEBA + ML lanes light up once their
pickles are built (the aggregator guards their absence).
"""
from __future__ import annotations

import os
import tempfile
from typing import Any, Callable, Dict, List, Optional

# The ordered steps the dashboard renders as a tracker. Keep keys stable.
STEPS: List[Dict[str, str]] = [
    {"key": "ingest",     "label": "Ingest → ECS",        "detail": "Detect format, normalise to ECS 8.11"},
    {"key": "detect",     "label": "Detector lanes",      "detail": "Rules · UEBA · ML → detection bundles"},
    {"key": "accumulate", "label": "Risk accumulation",   "detail": "Per-entity decay + strong-rule anchor"},
    {"key": "correlate",  "label": "Campaign correlation","detail": "Cluster incidents into attack campaigns"},
    {"key": "scrub",      "label": "PII scrub (DAL)",     "detail": "Role-typed placeholders before the LLM"},
    {"key": "report",     "label": "Gemma incident report","detail": "Per-campaign analysis via in-house Gemma"},
]

ProgressFn = Callable[[str, str, str], None]


def _noop(step: str, status: str, detail: str) -> None:  # default progress sink
    pass


def _ingest(text: str, limit: Optional[int]) -> List[dict]:
    if not text or not text.strip():
        return []
    from .ingest import ensure_ecs, load_events
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "upload.log")
        with open(src, "w", encoding="utf-8") as f:
            f.write(text)
        try:
            ecs_path = ensure_ecs(src)
            events = load_events(ecs_path)
        except ValueError:           # ensure_ecs rejects an empty / unreadable file
            return []
    events.sort(key=lambda e: e.get("@timestamp", ""))   # chronological replay
    if limit:
        events = events[:limit]
    return events


def _severity_summary(narratives: List[dict]) -> Dict[str, int]:
    out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for n in narratives:
        sev = n.get("severity", "LOW")
        out[sev] = out.get(sev, 0) + 1
    return out


def analyze_logs(
    text: str,
    *,
    progress: Optional[ProgressFn] = None,
    limit: Optional[int] = None,
    min_confidence: float = 0.0,
    report_top: int = 3,
) -> Dict[str, Any]:
    """Run the full SIEM pipeline over raw log text.

    progress(step_key, status, detail): status is running | done | skipped | error.
    Returns {events, bundles, candidates, active_lanes, anomaly_meta,
             severity_summary, campaigns:[narrative...], reports:[report...]}.
    """
    emit = progress or _noop

    # ── Step 1 · Ingest → ECS ────────────────────────────────────────────────
    emit("ingest", "running", STEPS[0]["detail"])
    try:
        events = _ingest(text, limit)
    except Exception as exc:
        emit("ingest", "error", str(exc)); raise
    if not events:
        emit("ingest", "done", "0 events — nothing to analyse")
        for s in STEPS[1:]:
            emit(s["key"], "skipped", "no events")
        return {"events": 0, "bundles": 0, "candidates": 0, "active_lanes": [],
                "anomaly_meta": {}, "severity_summary": _severity_summary([]),
                "campaigns": [], "reports": []}
    emit("ingest", "done", f"{len(events)} ECS events")

    # ── Step 2 · Detector lanes → bundles + anomaly store ────────────────────
    emit("detect", "running", STEPS[1]["detail"])
    try:
        from .detect.detection_aggregator import DetectionAggregator
        from .detect import save_anomaly_store
        agg = DetectionAggregator()
        agg.load()                                  # ML/UEBA guarded if untrained
        bundles = agg.process_all(events)
        lanes = agg.active_lanes()
    except Exception as exc:
        emit("detect", "error", str(exc)); raise
    anomaly_dir = tempfile.mkdtemp(prefix="siem-job-")
    anomaly_path = os.path.join(anomaly_dir, "anomaly_events.json")
    anomaly_meta = save_anomaly_store(bundles, anomaly_path) if bundles else {}
    emit("detect", "done",
         f"{len(bundles)} bundles · lanes: {', '.join(lanes)}")

    # ── Step 3 · Risk accumulation → incident candidates ─────────────────────
    emit("accumulate", "running", STEPS[2]["detail"])
    try:
        from .correlate import RiskAccumulator
        acc = RiskAccumulator()
        candidates = [r["incident_candidate"]
                      for r in acc.process_all(bundles) if r["new_emission"]]
    except Exception as exc:
        emit("accumulate", "error", str(exc)); raise
    emit("accumulate", "done", f"{len(candidates)} incident candidate(s)")

    # ── Step 4 · Correlation → attack campaigns ──────────────────────────────
    emit("correlate", "running", STEPS[3]["detail"])
    try:
        from .correlate import MultistageCorrelator
        narratives, _noise = MultistageCorrelator().correlate(candidates)
    except Exception as exc:
        emit("correlate", "error", str(exc)); raise
    emit("correlate", "done", f"{len(narratives)} campaign(s)")

    if not narratives:
        emit("scrub", "skipped", "no campaigns")
        emit("report", "skipped", "no campaigns")
        return {"events": len(events), "bundles": len(bundles),
                "candidates": len(candidates), "active_lanes": lanes,
                "anomaly_meta": anomaly_meta, "severity_summary": _severity_summary([]),
                "campaigns": [], "reports": []}

    # ── Step 5 · DAL scrub ───────────────────────────────────────────────────
    emit("scrub", "running", STEPS[4]["detail"])
    try:
        from .scrub import DALScrubber
        scrubbed, mappings = DALScrubber().scrub(narratives)
        tokens = sum(m.get("tokens_scrubbed", 0) for m in mappings.values())
    except Exception as exc:
        emit("scrub", "error", str(exc)); raise
    emit("scrub", "done", f"{tokens} identifier(s) scrubbed across {len(scrubbed)} campaign(s)")

    # ── Step 6 · Gemma incident reports (top campaigns) ──────────────────────
    emit("report", "running", STEPS[5]["detail"])
    try:
        from .report import LLMRouter
        # Report the most severe / confident campaigns first; cap the count so a
        # noisy upload can't fan out into dozens of Gemma calls.
        order = sorted(
            scrubbed,
            key=lambda n: (n.get("severity", ""), n.get("confidence", 0.0)),
            reverse=True,
        )[:report_top]
        with tempfile.TemporaryDirectory() as out:
            reports = LLMRouter().process_campaigns(
                order, anomaly_store_path=anomaly_path, output_dir=out,
                mappings=mappings, min_confidence=min_confidence,
            )
    except Exception as exc:
        emit("report", "error", str(exc)); raise
    emit("report", "done", f"{len(reports)} report(s) generated via Gemma")

    return {
        "events": len(events),
        "bundles": len(bundles),
        "candidates": len(candidates),
        "active_lanes": lanes,
        "anomaly_meta": anomaly_meta,
        "severity_summary": _severity_summary(narratives),
        "campaigns": scrubbed,     # scrubbed narratives (placeholders) for display
        "reports": reports,        # re-identified Gemma reports
    }

"""In-memory background-job manager for the SIEM pipeline.

Each submitted analysis runs ``pipeline.analyze_logs`` on a daemon thread and
records per-step progress, so the dashboard can poll job status and show exactly
what the backend is doing. Jobs are kept in memory (most-recent-N); nothing is
persisted — this is the lighter-than-production appliance.
"""
from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from . import pipeline


class Job:
    def __init__(self, job_id: str, source: str):
        self.id = job_id
        self.source = source
        self.status = "queued"          # queued | running | done | error
        self.created = time.time()
        self.started: Optional[float] = None
        self.finished: Optional[float] = None
        self.error: Optional[str] = None
        self.result: Optional[dict] = None
        self.steps: List[dict] = [
            {"key": s["key"], "label": s["label"], "status": "pending",
             "detail": s["detail"], "ts": None}
            for s in pipeline.STEPS
        ]
        self._lock = threading.Lock()

    def on_progress(self, key: str, status: str, detail: str) -> None:
        with self._lock:
            for st in self.steps:
                if st["key"] == key:
                    st["status"] = status
                    st["detail"] = detail
                    st["ts"] = time.time()
                    break

    def _steps_copy(self) -> List[dict]:
        with self._lock:
            return [dict(s) for s in self.steps]

    def summary(self) -> dict:
        """Lightweight view for the jobs list (no full result payload)."""
        steps = self._steps_copy()
        done = sum(1 for s in steps if s["status"] in ("done", "skipped"))
        sev = (self.result or {}).get("severity_summary", {}) if self.result else {}
        return {
            "id": self.id, "source": self.source, "status": self.status,
            "created": self.created, "started": self.started, "finished": self.finished,
            "error": self.error,
            "steps_done": done, "steps_total": len(steps),
            "severity_summary": sev,
            "campaign_count": len((self.result or {}).get("campaigns", [])) if self.result else 0,
            "report_count": len((self.result or {}).get("reports", [])) if self.result else 0,
        }

    def detail(self) -> dict:
        """Full view for the job-detail endpoint (steps + result)."""
        d = self.summary()
        d["steps"] = self._steps_copy()
        d["result"] = self.result
        return d


class JobManager:
    def __init__(self, max_jobs: int = 50):
        self.max_jobs = max_jobs
        self._jobs: Dict[str, Job] = {}
        self._order: List[str] = []         # newest first
        self._lock = threading.Lock()

    def submit(self, text: str, source: str = "upload", **kwargs: Any) -> str:
        job_id = "job_" + uuid.uuid4().hex[:8]
        job = Job(job_id, source)
        with self._lock:
            self._jobs[job_id] = job
            self._order.insert(0, job_id)
            while len(self._order) > self.max_jobs:
                self._jobs.pop(self._order.pop(), None)
        threading.Thread(target=self._run, args=(job, text, kwargs), daemon=True).start()
        return job_id

    def _run(self, job: Job, text: str, kwargs: dict) -> None:
        job.status = "running"
        job.started = time.time()
        try:
            job.result = pipeline.analyze_logs(text, progress=job.on_progress, **kwargs)
            job.status = "done"
        except Exception as exc:   # noqa: BLE001 — surface any pipeline failure to the UI
            job.error = f"{type(exc).__name__}: {exc}"
            job.status = "error"
        finally:
            job.finished = time.time()

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> List[Job]:
        with self._lock:
            return [self._jobs[j] for j in self._order if j in self._jobs]


# Module-level singleton used by the API routes.
manager = JobManager()

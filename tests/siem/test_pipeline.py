"""Module 9 smoke test — orchestrator + background job manager.

Runs the SIEM pipeline over the built-in sample (MOCK_LLM), then exercises the
job manager (submit → poll → done) the dashboard relies on.

    python3 tests/siem/test_pipeline.py        # direct
    pytest tests/siem/test_pipeline.py         # under pytest
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

os.environ.setdefault("MOCK_LLM", "1")
os.environ.setdefault("SIEM_MODELS_DIR", tempfile.mkdtemp(prefix="siem-pipe-test-"))

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from furix_mvp.siem import pipeline, jobs
from furix_mvp.siem.samples import SIEM_SAMPLE


def test_orchestrator_runs_sample_end_to_end():
    seen = []
    res = pipeline.analyze_logs(
        SIEM_SAMPLE, progress=lambda k, s, d: seen.append((k, s)), min_confidence=0.0)
    # Every step reached a terminal state.
    keys_done = {k for k, s in seen if s in ("done", "skipped", "error")}
    assert {st["key"] for st in pipeline.STEPS}.issubset(keys_done)
    assert res["events"] == 7
    assert res["bundles"] == 7
    assert res["active_lanes"] == ["signature_rules"]      # ML/UEBA guarded off
    assert len(res["campaigns"]) == 1
    assert res["severity_summary"]["CRITICAL"] == 1
    assert len(res["reports"]) == 1
    rep = res["reports"][0]
    assert rep["processing"]["llm_model"]                  # report went through Gemma path
    assert rep["executive_summary"]                        # has content
    print(f"  ok  orchestrator: 7 events → 1 CRITICAL campaign → 1 report")


def test_orchestrator_empty_input():
    res = pipeline.analyze_logs("", min_confidence=0.0)
    assert res["events"] == 0 and res["campaigns"] == [] and res["reports"] == []
    print("  ok  empty input → no events, no campaigns")


def test_job_manager_submit_poll_done():
    job_id = jobs.manager.submit(SIEM_SAMPLE, source="test", min_confidence=0.0)
    assert job_id.startswith("job_")
    # Poll until terminal (MOCK_LLM → fast; generous timeout for CI).
    deadline = time.time() + 60
    job = jobs.manager.get(job_id)
    while job.status not in ("done", "error") and time.time() < deadline:
        time.sleep(0.1)
    assert job.status == "done", job.error
    detail = job.detail()
    assert detail["steps_total"] == len(pipeline.STEPS)
    assert detail["steps_done"] == len(pipeline.STEPS)       # all steps terminal
    assert detail["result"]["severity_summary"]["CRITICAL"] == 1
    assert detail["campaign_count"] == 1 and detail["report_count"] == 1
    # Summary view (jobs list) carries the headline without the full payload.
    summ = job.summary()
    assert "result" not in summ and summ["status"] == "done"
    print(f"  ok  job {job_id}: submitted → polled → done with result")


def test_job_appears_in_list():
    jobs.manager.submit(SIEM_SAMPLE, source="list-test", min_confidence=0.0)
    listed = jobs.manager.list()
    assert any(j.source == "list-test" for j in listed)
    print("  ok  submitted job appears in manager.list()")


def main() -> int:
    tests = [
        test_orchestrator_runs_sample_end_to_end,
        test_orchestrator_empty_input,
        test_job_manager_submit_poll_done,
        test_job_appears_in_list,
    ]
    print(f"SIEM pipeline smoke test — {len(tests)} cases")
    for t in tests:
        t()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Offline training for the SIEM ML + UEBA lanes.

Builds the model artifacts the detection aggregator needs to light up the two
guarded-off lanes:

  ML ensemble : FeatureEngine.fit → extract → EnsembleDetector.fit
                → scaler.pkl · iso_forest.pkl · ecod.pkl · calibration.pkl
                  (+ baseline_stats.pkl, feature_stats.pkl)
  UEBA        : ueba_profiler.run(ecs_dir) → ueba_profiles.pkl

Run it:

    python -m furix_mvp.siem.train                 # synthetic benign baseline
    python -m furix_mvp.siem.train --logs auth.log # train on real baseline logs
    python -m furix_mvp.siem.train --synthetic 2000

Artifacts land under furix_mvp/siem/models/ (override with SIEM_MODELS_DIR). Once
present, ``DetectionAggregator.load()`` activates the rules + UEBA + ML lanes.
"""
from __future__ import annotations

import argparse
import json
import os
import pickle
import tempfile
from typing import Any, Callable, Dict, List, Optional

from . import baseline
from .config import (
    MODELS_DIR, BASELINE_STATS_PATH,
    SCALER_PATH, ISO_FOREST_PATH, ECOD_PATH, CALIBRATION_PATH,
    UEBA_PROFILES_PATH,
)

ProgressFn = Callable[[str, str, str], None]


def _noop(step: str, status: str, detail: str) -> None:
    pass


def _baseline_events(logs_text: Optional[str], logs_path: Optional[str],
                     synthetic: int) -> List[dict]:
    if logs_path:
        with open(logs_path, "r", encoding="utf-8", errors="replace") as f:
            logs_text = f.read()
    if logs_text is not None:
        from .pipeline import _ingest      # reuse the real ingest path
        return _ingest(logs_text, None)
    return baseline.generate(synthetic)


def train_models(
    *,
    logs_text: Optional[str] = None,
    logs_path: Optional[str] = None,
    synthetic: int = 840,
    progress: Optional[ProgressFn] = None,
) -> Dict[str, Any]:
    """Train the ML ensemble + UEBA profiles. Writes artifacts to MODELS_DIR."""
    emit = progress or _noop

    # ── Baseline events ──────────────────────────────────────────────────────
    emit("baseline", "running", "Loading benign baseline events")
    events = _baseline_events(logs_text, logs_path, synthetic)
    if len(events) < 50:
        emit("baseline", "error", f"only {len(events)} events (need ≥50)")
        raise ValueError(f"Need at least 50 baseline events to train; got {len(events)}.")
    emit("baseline", "done", f"{len(events)} benign baseline events")

    os.makedirs(MODELS_DIR, exist_ok=True)

    # ── ML ensemble (IsolationForest + ECOD) ─────────────────────────────────
    emit("ml", "running", "Extracting features, fitting IsolationForest + ECOD")
    from .ml.layer2_features import FeatureEngine
    from .ml.layer3_detector import EnsembleDetector
    fe = FeatureEngine()
    fe.fit(events)                              # action-frequency table
    X = fe.extract_all(events)                  # (N, 16)
    fe.save_baseline_stats(BASELINE_STATS_PATH)
    means, stds = X.mean(axis=0), X.std(axis=0)
    with open(os.path.join(MODELS_DIR, "feature_stats.pkl"), "wb") as f:
        pickle.dump({"means": means, "stds": stds}, f)
    EnsembleDetector().fit(X)                   # writes scaler/iso/ecod/calibration
    emit("ml", "done", f"IForest+ECOD trained on {X.shape[0]}×{X.shape[1]} features")

    # ── UEBA KDE profiles ────────────────────────────────────────────────────
    emit("ueba", "running", "Building per-user KDE behavioural profiles")
    from .ueba import ueba_profiler
    with tempfile.TemporaryDirectory() as d:
        ecs_file = os.path.join(d, "baseline.ecs.jsonl")
        with open(ecs_file, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        artifact = ueba_profiler.run(d)
    n_users = artifact.get("metadata", {}).get("total_users", 0)
    emit("ueba", "done", f"{n_users} user profiles built")

    return {
        "events": len(events),
        "ml_features": list(X.shape),
        "ueba_users": n_users,
        "models_dir": MODELS_DIR,
        "status": models_status(),
    }


def models_status() -> Dict[str, Any]:
    """Which lanes are trained → which the aggregator will activate."""
    files = {
        "scaler": SCALER_PATH, "iso_forest": ISO_FOREST_PATH, "ecod": ECOD_PATH,
        "calibration": CALIBRATION_PATH, "ueba_profiles": UEBA_PROFILES_PATH,
    }
    present = {k: os.path.exists(p) for k, p in files.items()}
    ml_ready = all(present[k] for k in ("scaler", "iso_forest", "ecod", "calibration"))
    ueba_ready = present["ueba_profiles"]
    lanes = (["signature_rules"]
             + (["ueba"] if ueba_ready else [])
             + (["ml_ensemble"] if ml_ready else []))
    return {"ml_ready": ml_ready, "ueba_ready": ueba_ready,
            "active_lanes": lanes, "files": present}


def _cli(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m furix_mvp.siem.train",
                                 description="Train the SIEM ML + UEBA lanes.")
    ap.add_argument("--logs", metavar="PATH", help="Baseline log file (raw vendor or ECS JSONL).")
    ap.add_argument("--synthetic", type=int, default=840,
                    help="Synthetic benign events when --logs is omitted (default 840).")
    args = ap.parse_args(argv)

    def pr(k: str, s: str, d: str) -> None:
        print(f"[train] {k:9s} {'✓' if s == 'done' else '…' if s == 'running' else '✗'} {d}")

    res = train_models(logs_path=args.logs, synthetic=args.synthetic, progress=pr)
    print(f"\n[train] Done — models in {res['models_dir']}")
    print(f"[train] Active lanes now: {', '.join(res['status']['active_lanes'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())

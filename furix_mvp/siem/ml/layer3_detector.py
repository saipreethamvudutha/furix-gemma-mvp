"""
layer3_detector.py
------------------
Layer 3: ML ensemble detection — Isolation Forest (60%) + ECOD (40%).
         No LLM anywhere.

Rule Engine scores are no longer blended here. Rules now run as an
independent detector lane and emit risk_events directly to the Risk
Accumulator (Detection Aggregator, Step 6). Blending them here caused
double-counting once the independent lane was added.

Training:
    fit(feature_matrix)  →  trains ISO Forest + ECOD, computes calibration
                             percentile tables, saves all artefacts.

Scoring:
    score(feature_matrix)
        →  fused_score (0-100) per event
"""
from __future__ import annotations

import os
import pickle
from typing import Tuple

import numpy as np
from sklearn.preprocessing import StandardScaler

from ..config import (
    IF_CONTAMINATION, IF_N_ESTIMATORS, IF_RANDOM_STATE,
    WEIGHT_ISO_FOREST, WEIGHT_ECOD,
    SCALER_PATH, ISO_FOREST_PATH, ECOD_PATH, CALIBRATION_PATH,
    MODELS_DIR,
)


# --------------------------------------------------------------------------- #
# Lazy import of pyod — gives a clear error if not installed
# --------------------------------------------------------------------------- #

def _load_pyod():
    try:
        from pyod.models.iforest import IForest
        from pyod.models.ecod   import ECOD
        return IForest, ECOD
    except ImportError as exc:
        raise ImportError(
            "pyod is required for the ML detector. "
            "Run: pip install pyod"
        ) from exc


# --------------------------------------------------------------------------- #
# Score calibration helpers
# --------------------------------------------------------------------------- #

def _to_percentile(scores: np.ndarray, reference: np.ndarray) -> np.ndarray:
    """
    Map raw detector scores to 0-100 percentile relative to a reference
    distribution (baseline scores).
    """
    result = np.zeros(len(scores))
    for i, s in enumerate(scores):
        result[i] = float(np.mean(reference <= s)) * 100.0
    return result


# --------------------------------------------------------------------------- #
# EnsembleDetector
# --------------------------------------------------------------------------- #

class EnsembleDetector:

    def __init__(self):
        self._scaler:      StandardScaler | None = None
        self._iso:         object | None = None   # pyod IForest
        self._ecod:        object | None = None   # pyod ECOD
        self._calib_iso:   np.ndarray | None = None   # baseline raw scores
        self._calib_ecod:  np.ndarray | None = None

    # ------------------------------------------------------------------ #
    # Training
    # ------------------------------------------------------------------ #

    def fit(self, X: np.ndarray):
        """
        Train on the baseline feature matrix X (shape N×16).
        Saves all artefacts to the models/ directory.
        """
        if X.shape[0] < 50:
            raise ValueError(
                f"Only {X.shape[0]} usable baseline events. Need at least 50."
            )

        IForest, ECOD = _load_pyod()

        os.makedirs(MODELS_DIR, exist_ok=True)

        print(f"[Layer3] Training on {X.shape[0]} baseline events ...")

        # Scale
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Isolation Forest
        self._iso = IForest(
            contamination=IF_CONTAMINATION,
            n_estimators=IF_N_ESTIMATORS,
            random_state=IF_RANDOM_STATE,
            n_jobs=-1,
        )
        self._iso.fit(X_scaled)
        self._calib_iso = self._iso.decision_scores_   # raw scores on training set

        # ECOD
        self._ecod = ECOD(contamination=IF_CONTAMINATION)
        self._ecod.fit(X_scaled)
        self._calib_ecod = self._ecod.decision_scores_

        # Persist
        self._save()
        print("[Layer3] Training complete. Models saved.")

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #

    def score(
        self,
        X: np.ndarray,
    ) -> np.ndarray:
        """
        Score incoming events using ML ensemble only.

        Parameters
        ----------
        X : (N, F) feature matrix — same feature set as training

        Returns
        -------
        fused_scores : np.ndarray shape (N,), values 0-100

        Note
        ----
        Rule engine scores are no longer accepted here. Rules emit
        independent risk_events via RuleEngine.detect() and are fused
        in the Detection Aggregator (Step 6), not in this layer.
        If you have existing call sites passing rule_scores as a second
        argument, remove that argument — it is no longer used.
        """
        if self._scaler is None:
            raise RuntimeError("Detector not trained. Run train first.")

        X_scaled = self._scaler.transform(X)

        # Raw scores from each model
        iso_raw  = self._iso.decision_function(X_scaled)
        ecod_raw = self._ecod.decision_function(X_scaled)

        # Calibrate to 0-100 percentiles using baseline distributions
        iso_pct  = _to_percentile(iso_raw,  self._calib_iso)
        ecod_pct = _to_percentile(ecod_raw, self._calib_ecod)

        # Weighted fusion — ISO 60%, ECOD 40%
        # Weights are normalised so they always sum to 1.0
        w_iso  = WEIGHT_ISO_FOREST / (WEIGHT_ISO_FOREST + WEIGHT_ECOD)
        w_ecod = WEIGHT_ECOD       / (WEIGHT_ISO_FOREST + WEIGHT_ECOD)
        fused  = w_iso * iso_pct + w_ecod * ecod_pct

        # Return true percentile scores (0-100) with no cap.
        # The MEDIUM ceiling (44) is enforced in DetectionAggregator._make_ml_risk_event()
        # so the raw score is available for Risk Accumulator weighting while the
        # capped score prevents pure ML from escalating to HIGH/CRITICAL alone.
        return np.clip(fused, 0.0, 100.0)

    # ------------------------------------------------------------------ #
    # Persist / load
    # ------------------------------------------------------------------ #

    def _save(self):
        with open(SCALER_PATH,      "wb") as f: pickle.dump(self._scaler,     f)
        with open(ISO_FOREST_PATH,  "wb") as f: pickle.dump(self._iso,        f)
        with open(ECOD_PATH,        "wb") as f: pickle.dump(self._ecod,       f)
        with open(CALIBRATION_PATH, "wb") as f: pickle.dump({
            "calib_iso":  self._calib_iso,
            "calib_ecod": self._calib_ecod,
        }, f)

    def load(self):
        """Load previously trained artefacts from disk."""
        for path, label in [
            (SCALER_PATH,      "scaler"),
            (ISO_FOREST_PATH,  "iso_forest"),
            (ECOD_PATH,        "ecod"),
            (CALIBRATION_PATH, "calibration"),
        ]:
            if not os.path.exists(path):
                raise FileNotFoundError(
                    f"Model artefact not found: {path}\n"
                    "Train the SIEM ML models first (offline training step)."
                )

        with open(SCALER_PATH,      "rb") as f: self._scaler    = pickle.load(f)
        with open(ISO_FOREST_PATH,  "rb") as f: self._iso       = pickle.load(f)
        with open(ECOD_PATH,        "rb") as f: self._ecod      = pickle.load(f)
        with open(CALIBRATION_PATH, "rb") as f:
            calib = pickle.load(f)
            self._calib_iso  = calib["calib_iso"]
            self._calib_ecod = calib["calib_ecod"]

        print("[Layer3] Models loaded from disk.")

    @property
    def is_trained(self) -> bool:
        return all(x is not None for x in (
            self._scaler, self._iso, self._ecod,
            self._calib_iso, self._calib_ecod,
        ))
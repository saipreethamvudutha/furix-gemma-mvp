"""
detection_aggregator.py
-----------------------
Step 6 — Detection Aggregator.

Fans out each ECS event to all three detector lanes in parallel:
    1. Signature Rules / IOC  →  RuleEngine.detect(event)
    2. UEBA Baselines         →  UEBAScorer.detect(event)
    3. ML Ensemble            →  EnsembleDetector.score(features)  (wrapped as risk_event)

Collects their outputs and packages a detection_bundle per event:

    {
        "event_id":        str,
        "timestamp":       str,
        "user":            str,
        "source_ip":       str,
        "event_module":    str,
        "detectors_fired": List[str],   # which lanes produced results
        "risk_events":     List[dict],  # all risk_events from all lanes
        "ml_score":        float,       # raw ensemble score (0-100)
        "raw_event":       dict,        # original ECS event
    }

The bundle is the input to the Risk Accumulator (Step 7+).

Usage:
    aggregator = DetectionAggregator()
    aggregator.load()

    bundle = aggregator.process(event)        # single event
    bundles = aggregator.process_all(events)  # batch
"""
from __future__ import annotations

import os
import uuid
from typing import Any, Dict, List, Optional

import numpy as np

from ..config import UEBA_PROFILES_PATH
from .rule_engine import RuleEngine
from ..ml.layer2_features import FeatureEngine
from ..ml.layer3_detector import EnsembleDetector
from ..ueba.ueba_scorer import UEBAScorer


# Context-aware MITRE mapping for ML lane.
# ML detects statistical deviation — we use event.module to pick the most
# specific technique rather than always assigning Defense Evasion T1078.
# Format: module → (technique_id, technique_name, tactic, tactic_id, kill_chain_stage)
_ML_MITRE_MAP: Dict[str, tuple] = {
    "authentication": ("T1110",     "Brute Force",                      "Credential Access",    "TA0006", 8),
    "database":       ("T1213",     "Data from Information Repositories","Collection",           "TA0009", 11),
    "cloud":          ("T1530",     "Data from Cloud Storage",           "Collection",           "TA0009", 11),
    "endpoint":       ("T1059",     "Command and Scripting Interpreter", "Execution",            "TA0002", 4),
    "firewall":       ("T1071",     "Application Layer Protocol",        "Command and Control",  "TA0011", 12),
    "email":          ("T1566",     "Phishing",                          "Initial Access",       "TA0001", 3),
    "network":        ("T1071",     "Application Layer Protocol",        "Command and Control",  "TA0011", 12),
    # Default fallback — used when module is unknown or doesn't match above
    "default":        ("T1078",     "Valid Accounts",                    "Defense Evasion",      "TA0005", 7),
}

def _ml_mitre(event_module: str) -> tuple:
    """Return (technique_id, technique, tactic, tactic_id, stage) for an event module."""
    return _ML_MITRE_MAP.get((event_module or "").lower(), _ML_MITRE_MAP["default"])

# ML scores below this threshold are not emitted as risk_events to avoid noise.
ML_MIN_SCORE = 10.0


def _get(event: Dict, dotted: str, default=None):
    parts = dotted.split(".")
    node  = event
    for p in parts:
        if not isinstance(node, dict):
            return default
        node = node.get(p)
        if node is None:
            return default
    return node


class DetectionAggregator:
    """
    Thin orchestration layer: loads all three detector lanes and
    fans out each event to them, returning a detection_bundle.
    """

    def __init__(self, threat_intel: Optional[set] = None):
        self._rule_engine:  Optional[RuleEngine]       = None
        self._ueba:         Optional[UEBAScorer]        = None
        self._ml_detector:  Optional[EnsembleDetector]  = None
        self._feature_eng:  Optional[FeatureEngine]     = None
        self._threat_intel: set = threat_intel or set()
        self._loaded = False

    # ------------------------------------------------------------------ #
    # Load
    # ------------------------------------------------------------------ #

    def load(
        self,
        ueba_profiles_path: str = UEBA_PROFILES_PATH,
        threat_intel: Optional[set] = None,
    ):
        """
        Load all three detector lanes.
        Call this once before processing events.
        """
        if threat_intel:
            self._threat_intel = threat_intel

        # Rule lane always loads — rules.json ships with the appliance.
        print("[Aggregator] Loading Rule Engine ...")
        self._rule_engine = RuleEngine(threat_intel=self._threat_intel)

        # UEBA + ML need trained artifacts built by the offline training step.
        # Guard their load so the aggregator degrades to the rule lane when the
        # pickles don't exist yet, rather than crashing (both load()s RAISE when
        # untrained). The per-lane runners already tolerate a None detector via
        # their own try/except, so nulling these is all that's needed.
        print("[Aggregator] Loading UEBA Scorer ...")
        self._ueba = UEBAScorer()
        try:
            self._ueba.load(ueba_profiles_path)
        except Exception as exc:
            print(f"[Aggregator] UEBA lane unavailable (not trained?): {exc}")
            self._ueba = None

        print("[Aggregator] Loading ML Ensemble ...")
        self._ml_detector = EnsembleDetector()
        try:
            self._ml_detector.load()
        except Exception as exc:
            print(f"[Aggregator] ML lane unavailable (not trained?): {exc}")
            self._ml_detector = None

        print("[Aggregator] Loading Feature Engine ...")
        self._feature_eng = FeatureEngine()

        self._loaded = True
        active = (["signature_rules"]
                  + (["ueba"] if self._ueba is not None else [])
                  + (["ml_ensemble"] if self._ml_detector is not None else []))
        print(f"[Aggregator] Ready. Active lanes: {active}")

    def active_lanes(self) -> List[str]:
        """Names of the detector lanes that loaded successfully."""
        if not self._loaded:
            return []
        return (["signature_rules"]
                + (["ueba"] if self._ueba is not None else [])
                + (["ml_ensemble"] if self._ml_detector is not None else []))

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    # ------------------------------------------------------------------ #
    # Internal lane runners — each returns (lane_name, List[risk_event])
    # ------------------------------------------------------------------ #

    def _run_rules(self, event: Dict[str, Any]):
        try:
            return "signature_rules", self._rule_engine.detect(event)
        except Exception as exc:
            print(f"[Aggregator] Rule lane error: {exc}")
            return "signature_rules", []

    def _run_ueba(self, event: Dict[str, Any]):
        try:
            return "ueba", self._ueba.detect(event)
        except Exception as exc:
            print(f"[Aggregator] UEBA lane error: {exc}")
            return "ueba", []

    # ------------------------------------------------------------------ #
    # Public interface
    # ------------------------------------------------------------------ #

    def _make_ml_risk_event(
        self, event: Dict[str, Any], ml_score_raw: float
    ) -> Optional[Dict[str, Any]]:
        """Wrap a pre-computed ML score into a risk_event dict."""
        ml_score_capped = float(np.clip(ml_score_raw, 0.0, 44.0))  # MEDIUM ceiling
        if ml_score_capped < ML_MIN_SCORE:
            return None
        event_module = (_get(event, "event.module") or "").lower()
        tid, tech, tactic, tactic_id, stage = _ml_mitre(event_module)
        return {
            "detector":           "ml_ensemble",
            "rule_name":          "ml_anomaly",
            "triggered_rules":    ["ml_ensemble"],
            "mitre_technique_id": tid,
            "mitre_technique":    tech,
            "mitre_tactic":       tactic,
            "mitre_tactic_id":    tactic_id,
            "kill_chain_stage":   stage,
            "score":              round(ml_score_capped, 2),
            "ml_raw_score":       round(ml_score_raw, 2),
            "confidence":         round(min(0.75, ml_score_raw / 100.0), 3),
            "event_id":           _get(event, "event.id") or str(uuid.uuid4()),
            "user":               _get(event, "user.name") or "",
            "source_ip":          _get(event, "source.ip") or "",
            "timestamp":          _get(event, "@timestamp") or "",
            "event_module":       event_module,
        }

    def process(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fan out one ECS event to rules + UEBA lanes.
        ML score must be pre-computed — use process_all() for batch work.
        For single-event use, falls back to per-event ML scoring.
        """
        if not self._loaded:
            raise RuntimeError("Call load() before process().")

        try:
            feat_matrix = self._feature_eng.extract_all([event])
            scores      = self._ml_detector.score(feat_matrix)
            ml_score    = float(np.clip(scores[0], 0.0, 100.0))
        except Exception as exc:
            print(f"[Aggregator] ML lane error: {exc}")
            ml_score = 0.0

        return self._build_bundle(event, ml_score)

    def _build_bundle(
        self, event: Dict[str, Any], ml_score: float
    ) -> Dict[str, Any]:
        """Assemble a detection_bundle for one event given pre-computed ml_score."""
        all_risk_events: List[Dict[str, Any]] = []
        detectors_fired: List[str]            = []

        # Rules lane
        _, rule_events = self._run_rules(event)
        if rule_events:
            detectors_fired.append("signature_rules")
            all_risk_events.extend(rule_events)

        # UEBA lane
        _, ueba_events = self._run_ueba(event)
        if ueba_events:
            detectors_fired.append("ueba")
            all_risk_events.extend(ueba_events)

        # ML lane — score already computed
        ml_re = self._make_ml_risk_event(event, ml_score)
        if ml_re:
            detectors_fired.append("ml_ensemble")
            all_risk_events.append(ml_re)

        return {
            "event_id":        _get(event, "event.id") or str(uuid.uuid4()),
            "timestamp":       _get(event, "@timestamp") or "",
            "user":            _get(event, "user.name") or "",
            "source_ip":       _get(event, "source.ip") or "",
            "event_module":    _get(event, "event.module") or "",
            "detectors_fired": detectors_fired,
            "risk_events":     all_risk_events,
            "ml_score":        round(ml_score, 2),
            "raw_event":       event,
        }

    def process_all(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process a list of ECS events.

        ML scoring is batched in one vectorized numpy call for the entire
        event list — this is the main performance fix vs calling
        extract_all([event]) per event in a loop.

        Returns only bundles where at least one lane fired.
        """
        if not self._loaded:
            raise RuntimeError("Call load() before process_all().")

        if not events:
            return []

        # ── Batch ML scoring — one vectorized pass over all events ────
        print(f"[Aggregator] Extracting features for {len(events):,} events ...")
        try:
            feat_matrix = self._feature_eng.extract_all(events)   # (N, F)
            ml_scores   = self._ml_detector.score(feat_matrix)     # (N,) — capped at 44 inside score()
            ml_scores   = np.array(ml_scores, dtype=np.float64)
        except Exception as exc:
            print(f"[Aggregator] Batch ML scoring failed: {exc}. "
                  "Defaulting all ML scores to 0.")
            ml_scores = np.zeros(len(events))

        print(f"[Aggregator] Running rules + UEBA lanes ...")

        # ── Per-event: rules + UEBA + bundle assembly ─────────────────
        bundles: List[Dict[str, Any]] = []
        for i, event in enumerate(events):
            bundle = self._build_bundle(event, float(ml_scores[i]))
            if bundle["detectors_fired"]:
                bundles.append(bundle)

            # Progress indicator for large files
            if (i + 1) % 1000 == 0:
                print(f"[Aggregator]   {i+1:,}/{len(events):,} events processed, "
                      f"{len(bundles)} detections so far ...")

        return bundles
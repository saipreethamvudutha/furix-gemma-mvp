"""ML detection lane (third detector lane).

- ``layer2_features`` — ``FeatureEngine`` extracts a 16-feature vector per ECS
  event (the canonical ``FEATURE_NAMES``); stateful, so feature values depend on
  call order within a session. Needs only ``numpy``, so it (and ``FEATURE_NAMES``,
  which the severity engine imports) stays light.
- ``layer3_detector`` — ``EnsembleDetector``: IsolationForest (0.60) + ECOD (0.40)
  fused to a 0-100 percentile score. Pulls ``scikit-learn`` (eager) and ``pyod``
  (lazy, at fit/load), so it is NOT imported here; import it explicitly:

      from furix_mvp.siem.ml.layer3_detector import EnsembleDetector

  ``EnsembleDetector.load()`` RAISES on missing model pickles — the detection
  aggregator (Module 8) guards this so the lane degrades when untrained.
"""
from .layer2_features import FeatureEngine, FEATURE_NAMES
from . import layer2_features

__all__ = ["FeatureEngine", "FEATURE_NAMES", "layer2_features"]

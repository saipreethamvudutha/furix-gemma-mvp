"""
ueba_scorer.py
--------------
Step 5 — UEBA Scorer (runtime).

Loads ueba_profiles.pkl built by ueba_profiler.py and scores live
ECS events against per-user behavioral baselines.

Scoring logic:
  For each dimension present in the incoming event:
    - Rate dimensions  (query_row_count, bytes_out, s3_object_count):
        tail_prob = 1 - CDF(value)   high values are anomalous
    - Presence dimensions (phi_table_access, sensitive_api_call, non_us_login):
        score = 1.0 if user has never shown this behavior, else low score
    - Temporal dimensions (login_hour, login_day_of_week):
        tail_prob = min(CDF(v), 1-CDF(v))  — both tails anomalous

  Final UEBA score = weighted average of per-dimension tail probs × 100
  capped at 100.

  Service accounts: any value outside observed [min, max] envelope
  returns score 100. Any value inside returns 0.

Output risk_event schema matches rule_engine.py detect() output:
  {
    "detector":         "ueba",
    "rule_name":        "ueba_anomaly",
    "mitre_technique_id": "T1078",
    "mitre_technique":  "Valid Accounts",
    "mitre_tactic":     "Defense Evasion",
    "mitre_tactic_id":  "TA0005",
    "kill_chain_stage": 7,
    "score":            float (0-100),
    "confidence":       float (0-1),
    "event_id":         str,
    "user":             str,
    "source_ip":        str,
    "timestamp":        str,
    "event_module":     str,
    "ueba_details": {
      "peer_group":      str,
      "profile_tier":    str,
      "anomaly_driver":  str,    # dimension with highest anomaly
      "dim_scores":      dict,   # per-dimension anomaly scores
    }
  }
"""
from __future__ import annotations

import os
import pickle
import uuid
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from ..config import UEBA_PROFILES_PATH
# _get / _extract_dimensions are imported from the profiler rather than copied:
# the source carried byte-identical duplicates that "must stay in sync" — sharing
# the single canonical implementation makes drift impossible. assign_peer_group
# comes from the same module (also used lazily in detect() for unknown users).
from .ueba_profiler import _get, _extract_dimensions, assign_peer_group

# =============================================================================
#  Dimension metadata
#  Defines scoring type and weight for each tracked dimension.
#
#  Types:
#    "high_tail"   — high values anomalous (query_row_count, bytes_out)
#    "both_tails"  — both extremes anomalous (login_hour, destination_port)
#    "presence"    — value=1.0 means behavior occurred; score by rarity
# =============================================================================

DIMENSION_META: Dict[str, Dict[str, Any]] = {
    # Temporal
    "login_hour":          {"type": "both_tails",  "weight": 1.5},
    "login_day_of_week":   {"type": "both_tails",  "weight": 0.3},
    # Auth
    "auth_failure":        {"type": "high_tail",   "weight": 2.0},
    "non_us_login":        {"type": "presence",    "weight": 2.5},
    "has_source_ip":       {"type": "presence",    "weight": 0.5},
    "auth_event":          {"type": "high_tail",   "weight": 0.5},
    "auth_success":        {"type": "high_tail",   "weight": 0.5},
    # Endpoint
    "process_creation":    {"type": "high_tail",   "weight": 1.0},
    "network_connect":     {"type": "high_tail",   "weight": 1.0},
    "bytes_out":           {"type": "high_tail",   "weight": 1.8},
    "destination_port":    {"type": "both_tails",  "weight": 1.2},
    "dns_query":           {"type": "high_tail",   "weight": 1.5},
    # Database
    "db_access":           {"type": "high_tail",   "weight": 1.0},
    "query_row_count":     {"type": "high_tail",   "weight": 2.5},
    "phi_table_access":    {"type": "presence",    "weight": 3.0},
    # Cloud
    "cloud_api_call":      {"type": "high_tail",   "weight": 1.0},
    "sensitive_api_call":  {"type": "presence",    "weight": 2.5},
    "s3_object_count":     {"type": "high_tail",   "weight": 2.0},
    # PAM / CyberArk (Bug 3 fix — these were profiled but never scored)
    "pam_checkout":        {"type": "high_tail",   "weight": 2.0},
    "pam_unique_target":   {"type": "presence",    "weight": 1.5},
    # Severity
    "high_severity_event": {"type": "presence",    "weight": 1.5},
}

# Minimum UEBA score to emit a risk_event (avoid noise from low-signal dims)
MIN_SCORE_THRESHOLD = 15.0

# Context-aware MITRE mapping per anomaly driver.
# Maps the dimension that drove the anomaly to the most specific technique.
# Format: driver → (technique_id, technique_name, tactic, tactic_id, kill_chain_stage)
UEBA_MITRE_MAP: Dict[str, Tuple] = {
    "non_us_login":       ("T1078",     "Valid Accounts",                  "Credential Access",   "TA0006", 8),
    "auth_failure":       ("T1110",     "Brute Force",                     "Credential Access",   "TA0006", 8),
    "auth_success":       ("T1078",     "Valid Accounts",                  "Credential Access",   "TA0006", 8),
    "auth_event":         ("T1078",     "Valid Accounts",                  "Credential Access",   "TA0006", 8),
    "query_row_count":    ("T1213",     "Data from Information Repositories","Collection",        "TA0009", 11),
    "phi_table_access":   ("T1213",     "Data from Information Repositories","Collection",        "TA0009", 11),
    "db_access":          ("T1213",     "Data from Information Repositories","Collection",        "TA0009", 11),
    "s3_object_count":    ("T1530",     "Data from Cloud Storage",         "Collection",          "TA0009", 11),
    "sensitive_api_call": ("T1078",     "Valid Accounts",                  "Privilege Escalation","TA0004", 6),
    "cloud_api_call":     ("T1078",     "Valid Accounts",                  "Defense Evasion",     "TA0005", 7),
    "bytes_out":          ("T1048",     "Exfiltration Over Alt Protocol",  "Exfiltration",        "TA0010", 13),
    "dns_query":          ("T1071.004", "Application Layer Protocol: DNS", "Command and Control", "TA0011", 12),
    "destination_port":   ("T1571",     "Non-Standard Port",               "Command and Control", "TA0011", 12),
    "network_connect":    ("T1071",     "Application Layer Protocol",      "Command and Control", "TA0011", 12),
    "process_creation":   ("T1059",     "Command and Scripting Interpreter","Execution",          "TA0002", 4),
    "pam_checkout":       ("T1078",     "Valid Accounts",                  "Privilege Escalation","TA0004", 6),
    "pam_unique_target":  ("T1078",     "Valid Accounts",                  "Lateral Movement",    "TA0008", 10),
    "high_severity_event":("T1078",     "Valid Accounts",                  "Defense Evasion",     "TA0005", 7),
    # Temporal signals — weakest mapping, keep at Defense Evasion
    "login_hour":         ("T1078",     "Valid Accounts",                  "Defense Evasion",     "TA0005", 7),
    "login_day_of_week":  ("T1078",     "Valid Accounts",                  "Defense Evasion",     "TA0005", 7),
    "has_source_ip":      ("T1078",     "Valid Accounts",                  "Defense Evasion",     "TA0005", 7),
}

# Fallback when driver not in map
_UEBA_MITRE_DEFAULT = ("T1078", "Valid Accounts", "Defense Evasion", "TA0005", 7)


def _ueba_mitre(driver: str) -> Tuple:
    """Return (technique_id, technique, tactic, tactic_id, stage) for a driver."""
    return UEBA_MITRE_MAP.get(driver, _UEBA_MITRE_DEFAULT)


# Field extractors (_get, _extract_dimensions) are imported from ueba_profiler
# above — the single canonical copy, so profiler and scorer can never drift.


# =============================================================================
#  Per-dimension anomaly scoring
# =============================================================================

_CDF_POINTS = 400   # resolution of the pre-baked CDF grid


def _bake_cdf(dim_profile: Dict[str, Any]) -> None:
    """
    Pre-compute a fixed CDF lookup table into the dim_profile dict at load time.
    Replaces the per-call numerical integration so detect() is just a lookup.
    Mutates dim_profile in-place by adding 'cdf_xs' and 'cdf_vals' arrays.
    """
    kde = dim_profile.get("kde")
    if kde is None or dim_profile.get("cdf_xs") is not None:
        return  # already baked or no KDE
    mean = dim_profile.get("mean", 0.0)
    std  = dim_profile.get("std",  1.0)
    lo   = mean - 6 * max(std, 1.0)
    hi   = mean + 6 * max(std, 1.0)
    try:
        xs   = np.linspace(lo, hi, _CDF_POINTS)
        pdfs = kde(xs)
        cdfs = np.cumsum(pdfs) * (xs[1] - xs[0])
        if cdfs[-1] > 0:
            cdfs /= cdfs[-1]
        dim_profile["cdf_xs"]   = xs
        dim_profile["cdf_vals"] = cdfs
    except Exception:
        pass


def _lookup_cdf(value: float, dim_profile: Dict[str, Any]) -> float:
    """
    Fast CDF lookup using pre-baked grid.
    Falls back to z-score if no grid available.
    """
    xs   = dim_profile.get("cdf_xs")
    cdfs = dim_profile.get("cdf_vals")

    if xs is None or cdfs is None:
        # z-score fallback (no KDE or bake failed)
        mean = dim_profile.get("mean", 0.0)
        std  = dim_profile.get("std",  1.0)
        if std < 1e-10:
            return 0.5
        from scipy.stats import norm
        return float(norm.cdf(value, loc=mean, scale=std))

    # Extend lookup beyond pre-baked range by clamping to grid edges
    if value <= xs[0]:
        return 0.0
    if value >= xs[-1]:
        return 1.0
    idx = int(np.searchsorted(xs, value))
    idx = min(idx, len(cdfs) - 1)
    return float(cdfs[idx])


def _score_kde_dimension(
    value:      float,
    dim_profile: Dict[str, Any],
    dim_type:   str,
) -> float:
    """
    Score one dimension value against a pre-baked KDE profile.
    Returns anomaly probability 0.0-1.0.
    """
    if dim_type == "presence":
        base_rate = dim_profile.get("mean", 0.5)
        if value == 0.0:
            return 0.0
        return float(max(0.0, 1.0 - base_rate))

    cdf_val = _lookup_cdf(value, dim_profile)

    if dim_type == "high_tail":
        return 1.0 - cdf_val
    else:  # both_tails — 1 at extremes, 0 at center
        return 1.0 - 2.0 * float(min(cdf_val, 1.0 - cdf_val))


def _score_svc_dimension(
    value:      float,
    dim_profile: Dict[str, Any],
) -> float:
    """
    Zero-tolerance scoring for service accounts.
    Any value outside observed [min, max] = 1.0 anomaly.
    """
    vmin = dim_profile.get("min", value)
    vmax = dim_profile.get("max", value)
    if value < vmin or value > vmax:
        return 1.0
    return 0.0


# =============================================================================
#  UEBA Scorer
# =============================================================================

class UEBAScorer:

    def __init__(self):
        self._profiles:    Optional[Dict] = None
        self._pg_profiles: Optional[Dict] = None
        self._global_stats: Optional[Dict] = None
        self._loaded = False

    def load(self, path: str = UEBA_PROFILES_PATH):
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"UEBA profiles not found: {path}\n"
                "Run ueba_profiler.py first."
            )
        with open(path, "rb") as f:
            artifact = pickle.load(f)

        self._profiles     = artifact["profiles"]
        self._pg_profiles  = artifact["peer_group_profiles"]
        self._global_stats = artifact["global_stats"]

        # Pre-bake CDF lookup tables for every KDE profile so detect() is fast
        baked = 0
        for profile in self._profiles.values():
            for dp in profile.get("dimensions", {}).values():
                if dp.get("kde") is not None:
                    _bake_cdf(dp)
                    baked += 1
        for pg_dims in self._pg_profiles.values():
            for dp in pg_dims.values():
                if dp.get("kde") is not None:
                    _bake_cdf(dp)
                    baked += 1

        self._loaded = True

        meta = artifact.get("metadata", {})
        print(f"[UEBAScorer] Loaded profiles for {meta.get('total_users')} users | "
              f"{meta.get('total_events'):,} baseline events | "
              f"{len(meta.get('dimensions_tracked', []))} dimensions | "
              f"{baked} CDFs baked")

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    # ------------------------------------------------------------------ #
    # Core scoring
    # ------------------------------------------------------------------ #

    def detect(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Score one ECS event against UEBA profiles.
        Returns list with one risk_event if score >= threshold, else [].
        """
        if not self._loaded:
            raise RuntimeError("Call load() before detect().")

        user = (_get(event, "user.name") or "").strip()
        if not user:
            return []

        # Get user profile — fall back to peer group for unknown users (new joiners etc.)
        profile = self._profiles.get(user)
        if profile is None:
            # Unknown user: assign peer group by username convention, score against group baseline
            peer_group  = assign_peer_group(user)
            pg_profile  = self._pg_profiles.get(peer_group)
            if pg_profile is None:
                return []
            is_svc    = user.lower().startswith("svc_")
            user_dims = pg_profile
            profile   = {"is_service_account": is_svc, "peer_group": peer_group, "dimensions": pg_profile}
        else:
            is_svc     = profile.get("is_service_account", False)
            peer_group = profile.get("peer_group", "general")
            user_dims  = profile.get("dimensions", {})

        event_dims   = _extract_dimensions(event)
        if not event_dims:
            return []

        dim_scores:  Dict[str, float] = {}
        dim_weights: Dict[str, float] = {}

        for dim, value in event_dims.items():
            meta  = DIMENSION_META.get(dim)
            if meta is None:
                continue

            dim_profile = user_dims.get(dim)
            if dim_profile is None:
                # Try peer group profile
                pg  = self._pg_profiles.get(peer_group, {})
                dim_profile = pg.get(dim)
            if dim_profile is None:
                continue

            if is_svc:
                raw = _score_svc_dimension(value, dim_profile)
            else:
                raw = _score_kde_dimension(value, dim_profile, meta["type"])

            dim_scores[dim]  = float(np.clip(raw, 0.0, 1.0))
            dim_weights[dim] = meta["weight"]

        if not dim_scores:
            return []

        # Weighted average → 0-100 score
        total_w = sum(dim_weights[d] for d in dim_scores)
        if total_w == 0:
            return []

        weighted_sum = sum(
            dim_scores[d] * dim_weights[d]
            for d in dim_scores
        )
        ueba_score = float(np.clip((weighted_sum / total_w) * 100.0, 0.0, 100.0))

        if ueba_score < MIN_SCORE_THRESHOLD:
            return []

        # Anomaly driver — dimension with highest weighted contribution
        driver = max(
            dim_scores,
            key=lambda d: dim_scores[d] * dim_weights.get(d, 1.0)
        )

        # Confidence: higher when multiple dimensions agree,
        # and when using individual tier profiles
        n_dims    = len(dim_scores)
        tier      = profile.get("dimensions", user_dims).get(driver, {}).get("profile_tier", "global")
        tier_conf = {"individual": 0.90, "peer_group": 0.70,
                     "zero_tolerance": 0.98, "global": 0.50}.get(tier, 0.60)
        multi_dim_bonus = min(0.10, (n_dims - 1) * 0.02)
        confidence = float(min(0.98, tier_conf + multi_dim_bonus))

        risk_event: Dict[str, Any] = {
            "detector":           "ueba",
            "rule_name":          "ueba_anomaly",
            "triggered_rules":    [f"ueba:{driver}"],
            "mitre_technique_id": _ueba_mitre(driver)[0],
            "mitre_technique":    _ueba_mitre(driver)[1],
            "mitre_tactic":       _ueba_mitre(driver)[2],
            "mitre_tactic_id":    _ueba_mitre(driver)[3],
            "kill_chain_stage":   _ueba_mitre(driver)[4],
            "score":              round(ueba_score, 2),
            "confidence":         round(confidence, 3),
            "event_id":           _get(event, "event.id") or str(uuid.uuid4()),
            "user":               user,
            "source_ip":          _get(event, "source.ip") or "",
            "timestamp":          _get(event, "@timestamp") or "",
            "event_module":       _get(event, "event.module") or "",
            "ueba_details": {
                "peer_group":     peer_group,
                "profile_tier":   tier,
                "anomaly_driver": driver,
                "dim_scores":     {d: round(s, 4) for d, s in dim_scores.items()},
                "n_dims_scored":  n_dims,
            },
        }

        return [risk_event]

    def detect_all(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Batch detect. Returns flattened list of risk_events."""
        results: List[Dict[str, Any]] = []
        for event in events:
            results.extend(self.detect(event))
        return results
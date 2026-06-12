"""
risk_accumulator.py
-------------------
Block 2 — Risk Accumulator.

Receives detection_bundles from the DetectionAggregator and answers:
"Given everything we've seen about this entity over a time window,
what is the cumulative risk score and should this escalate?"

Four components:
  1. Entity risk ledger   — dual sliding-window score per entity_key with
                            exponential decay (no cliff effects at window edges)
  2. Multi-detector fusion — per-lane accumulator weights + corroboration multiplier
  3. Kill chain bonus     — stage coverage within recency window, multiplicative
  4. Threshold gate       — accumulated score → CRITICAL/HIGH/MEDIUM/LOW →
                            escalation decision with Splunk RBA-style emission control

Two windows per entity:
  Short  60 min,  half-life 20 min — catches fast attacks with high confidence
  Long   24 hr,   half-life  6 hr  — catches slow-and-low campaigns

Emission policy:
  Emit incident_candidate on first HIGH/CRITICAL crossing and on severity upgrades.
  Suppress re-emissions at the same severity level.
  Reset emission state when entity score falls back to LOW on both windows.

Entity key resolution (fallback chain):
  user.name  →  source.ip  →  host.name
"""
from __future__ import annotations

import math
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# =============================================================================
#  Configuration constants
# =============================================================================

# Sliding windows
SHORT_WINDOW_MINUTES  = 60
LONG_WINDOW_MINUTES   = 1440    # 24 hours

# Exponential decay half-lives (minutes)
SHORT_HALF_LIFE_MIN   = 20
LONG_HALF_LIFE_MIN    = 360     # 6 hours

# Pre-computed decay lambdas: λ = ln(2) / half_life
_LAMBDA_SHORT = math.log(2) / SHORT_HALF_LIFE_MIN
_LAMBDA_LONG  = math.log(2) / LONG_HALF_LIFE_MIN

# Multi-lane corroboration multiplier
# Rewards events that are flagged by multiple independent detectors
MULTI_LANE_MULTIPLIER: Dict[int, float] = {1: 1.0, 2: 1.4, 3: 1.8}

# Maximum effective score a UEBA-only bundle can contribute per event.
# Prevents weak temporal signals (login_hour) from escalating entities
# through volume alone — they need rule or ML corroboration to escalate.
UEBA_ONLY_BUNDLE_CAP = 12.0

# Noise floor — minimum raw rule score for the signature_rules lane to contribute.
# Rules with score < this threshold are treated as background noise and dropped.
# This filters out auth_failure_offhours, denied_medium_port_offhours, and
# high_log_severity hits that fire at high volume on normal padding events
# without indicating a real attack. Real attack rules (workstation_to_phi_db=45,
# bec_phishing=50, bulk_phi_query=40, etc.) all score >= 25.
RULE_NOISE_FLOOR = 25.0

# Strong rule anchor — a signature_rules hit must reach this score for the
# entity to qualify for HIGH/CRITICAL escalation. Without this anchor, the
# entity's accumulated score is capped at MEDIUM regardless of how much
# ML/UEBA noise has accumulated. This is the Splunk RBA pattern:
# "risk-based alerting requires at least one signature trigger."
STRONG_RULE_SCORE_FLOOR = 25.0

# Names of rules that frequently fire on benign off-hours padding events.
# These rules require corroboration from another lane (ML or UEBA) to count;
# otherwise the bundle contributes nothing to the entity ledger.
NOISY_RULE_NAMES = {
    "auth_failure_offhours",
    "denied_medium_port_offhours",
    "high_log_severity",
    "auth_failure",
}

# Per-lane accumulator weight
# ML fires on nearly every event — dampened so it cannot escalate alone.
# Rules are specific and high-confidence — full weight.
LANE_ACCUMULATOR_WEIGHT: Dict[str, float] = {
    "signature_rules": 1.0,
    "ueba":            0.8,
    "ml_ensemble":     0.4,
}

# UEBA driver quality dampening
# Prevents weak temporal signals (login_hour) from dominating the accumulator.
# High-signal drivers (phi_table_access, sensitive_api_call) get full weight.
UEBA_DRIVER_WEIGHT: Dict[str, float] = {
    "phi_table_access":   1.0,
    "sensitive_api_call": 1.0,
    "non_us_login":       0.9,
    "auth_failure":       0.8,
    "query_row_count":    0.8,
    "s3_object_count":    0.7,
    "bytes_out":          0.7,
    "destination_port":   0.6,
    "process_creation":   0.5,
    "network_connect":    0.5,
    "dns_query":          0.5,
    "login_hour":         0.3,
    "login_day_of_week":  0.2,
}

# Kill chain bonus — multiplier applied to accumulated score
# when N distinct kill chain stages are covered within the recency window.
# Coverage-based (not strict ordering) to handle out-of-order log delivery.
KILL_CHAIN_BONUS: Dict[int, float] = {
    2: 1.2,
    3: 1.5,
    4: 2.0,
    5: 2.5,
    6: 3.0,
}
# Only stages seen within this many minutes count toward the bonus
KILL_CHAIN_RECENCY_SHORT_MIN  = 30   # short window recency cap
KILL_CHAIN_RECENCY_LONG_MIN   = 180  # long window recency cap (3 hours)

# Escalation thresholds (accumulated score after kill chain bonus applied)
THRESHOLD_CRITICAL_SHORT  = 150
THRESHOLD_HIGH_SHORT      = 80
THRESHOLD_MEDIUM_SHORT    = 40

THRESHOLD_CRITICAL_LONG   = 300
THRESHOLD_HIGH_LONG       = 150
THRESHOLD_MEDIUM_LONG     = 80

# Severity ordering — used for emission comparison
SEVERITY_ORDER: Dict[str, int] = {
    "NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4
}

# Entity key fallback chain — first non-empty value wins
ENTITY_KEY_FIELDS: List[Tuple[str, str]] = [
    ("user",      "user"),    # bundle["user"]      = event.user.name
    ("source_ip", "ip"),      # bundle["source_ip"] = event.source.ip
]
# host.name needs raw_event dig since bundles don't surface it directly
HOST_FALLBACK_PATHS = ["host.name", "destination.address", "labels.target_host"]

# Max risk_events to keep per entity for incident context
TOP_EVENTS_LIMIT = 10


# =============================================================================
#  Data structures
# =============================================================================

@dataclass
class ScoreEntry:
    """One bundle's contribution stored in the entity ledger."""
    timestamp:       datetime
    raw_score:       float       # effective score before decay (post lane-weight + multiplier)
    stages:          List[int]   # all kill chain stages from this bundle's risk_events
    risk_events:     List[dict]  # original risk_events (for incident candidate context)
    bundle_id:       str
    detectors_fired: List[str]


@dataclass
class EntityState:
    """Full ledger state for one entity across both windows."""
    entity_key:            str
    entity_type:           str
    entries:               List[ScoreEntry] = field(default_factory=list)
    last_emitted_severity: str              = "NONE"
    first_seen:            Optional[datetime] = None
    last_seen:             Optional[datetime] = None
    top_risk_events:       List[dict]       = field(default_factory=list)
    total_bundles:         int              = 0
    # Strong rule anchor: True if this entity has EVER had a signature_rules
    # hit with score >= STRONG_RULE_SCORE_FLOOR. Without this, the entity is
    # capped at MEDIUM severity to prevent ML+UEBA volume-only escalation.
    has_strong_rule_evidence: bool          = False


# =============================================================================
#  Pure helpers
# =============================================================================

def _get(obj: dict, dotted: str, default=None):
    parts = dotted.split(".")
    node  = obj
    for p in parts:
        if not isinstance(node, dict):
            return default
        node = node.get(p)
        if node is None:
            return default
    return node


def _parse_ts(ts_str: str) -> Optional[datetime]:
    """Parse ISO 8601 timestamp to UTC-aware datetime. Returns None on failure."""
    if not ts_str:
        return None
    try:
        dt = datetime.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        try:
            from dateutil import parser as dp
            return dp.parse(ts_str).replace(tzinfo=timezone.utc)
        except Exception:
            return None


def _decay(score: float, age_minutes: float, lam: float) -> float:
    """Exponential decay: score × e^(−λ × age_minutes).
    age_minutes is clamped to ≥0 to prevent explosion from out-of-order timestamps.
    """
    return score * math.exp(-lam * max(age_minutes, 0.0))


def _severity_label(score: float, short_window: bool) -> str:
    if short_window:
        if score >= THRESHOLD_CRITICAL_SHORT: return "CRITICAL"
        if score >= THRESHOLD_HIGH_SHORT:     return "HIGH"
        if score >= THRESHOLD_MEDIUM_SHORT:   return "MEDIUM"
        return "LOW"
    else:
        if score >= THRESHOLD_CRITICAL_LONG: return "CRITICAL"
        if score >= THRESHOLD_HIGH_LONG:     return "HIGH"
        if score >= THRESHOLD_MEDIUM_LONG:   return "MEDIUM"
        return "LOW"


def _max_severity(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def _kill_chain_multiplier(n_stages: int) -> float:
    """Return bonus multiplier for n distinct kill chain stages covered."""
    bonus = 1.0
    for threshold in sorted(KILL_CHAIN_BONUS.keys()):
        if n_stages >= threshold:
            bonus = KILL_CHAIN_BONUS[threshold]
    return bonus


# =============================================================================
#  RiskAccumulator
# =============================================================================

class RiskAccumulator:
    """
    Processes detection_bundles from DetectionAggregator and maintains
    per-entity risk ledgers across dual time windows.

    Usage:
        acc = RiskAccumulator()

        for bundle in bundles:
            result = acc.process(bundle)
            if result["new_emission"]:
                send_to_correlator(result["incident_candidate"])
    """

    def __init__(self):
        self._ledger: Dict[str, EntityState] = {}

    # ------------------------------------------------------------------ #
    # Entity key resolution
    # ------------------------------------------------------------------ #

    def _resolve_entity(self, bundle: dict) -> Tuple[str, str]:
        """
        Resolve entity key and type using fallback chain:
            user.name  →  source.ip  →  host.name (from raw_event)

        Returns ("unknown", "unknown") if nothing found.
        """
        # Primary: bundle-level fields (already extracted from ECS)
        for field_name, entity_type in ENTITY_KEY_FIELDS:
            val = bundle.get(field_name, "").strip()
            if val:
                return val, entity_type

        # Fallback: dig into raw_event for host-level identifiers
        raw = bundle.get("raw_event", {})
        for path in HOST_FALLBACK_PATHS:
            val = _get(raw, path)
            if val and str(val).strip():
                return str(val).strip(), "host"

        return "unknown", "unknown"

    # ------------------------------------------------------------------ #
    # Bundle score computation
    # ------------------------------------------------------------------ #

    def _compute_bundle_score(
        self,
        bundle: dict,
    ) -> Tuple[float, List[int]]:
        """
        Compute one detection_bundle's effective score contribution.

        Per risk_event:
          - signature_rules: score × confidence × LANE_WEIGHT
          - ml_ensemble:     score × confidence × LANE_WEIGHT
          - ueba:            score × UEBA_DRIVER_WEIGHT × LANE_WEIGHT

        Bundle effective score = sum(per-lane best scores) × MULTI_LANE_MULTIPLIER

        Returns:
            (effective_score, kill_chain_stages_in_bundle)
        """
        risk_events = bundle.get("risk_events", [])
        if not risk_events:
            return 0.0, []

        lane_scores: Dict[str, float] = {}
        all_stages:  List[int]        = []

        # ── Noise filter pass ─────────────────────────────────────────────
        # Drop the signature_rules risk_event if it:
        #   (a) scores below RULE_NOISE_FLOOR, AND
        #   (b) all triggered rules are in NOISY_RULE_NAMES.
        # This prevents off-hours padding events from polluting entity
        # ledgers while preserving real attack rules that score higher.
        filtered_events = []
        for re in risk_events:
            if re.get("detector") == "signature_rules":
                rscore = float(re.get("score", 0.0))
                rules  = set(re.get("triggered_rules", []))
                if rscore < RULE_NOISE_FLOOR and rules and rules.issubset(NOISY_RULE_NAMES):
                    continue   # drop noisy rule hit
            filtered_events.append(re)

        for re in filtered_events:
            detector   = re.get("detector", "")
            score      = float(re.get("score", 0.0))
            confidence = float(re.get("confidence", 0.5))
            stage      = int(re.get("kill_chain_stage", 0))

            if stage > 0:
                all_stages.append(stage)

            lane_weight = LANE_ACCUMULATOR_WEIGHT.get(detector, 0.5)

            if detector == "ueba":
                driver     = re.get("ueba_details", {}).get("anomaly_driver", "")
                drv_weight = UEBA_DRIVER_WEIGHT.get(driver, 0.5)
                eff        = score * drv_weight * lane_weight
            else:
                eff = score * confidence * lane_weight

            # Keep the single best effective score per lane
            # (rule_engine already aggregates multiple triggered rules into one risk_event)
            if eff > lane_scores.get(detector, 0.0):
                lane_scores[detector] = eff

        if not lane_scores:
            return 0.0, []

        lanes_fired    = len(bundle.get("detectors_fired", list(lane_scores.keys())))
        multi_mult     = MULTI_LANE_MULTIPLIER.get(min(lanes_fired, 3), 1.0)
        base_score     = sum(lane_scores.values())
        effective      = base_score * multi_mult

        # If UEBA is the only lane that fired, cap the contribution so that
        # weak temporal signals (login_hour) cannot escalate through volume.
        # UEBA gains full weight when corroborated by rules or ML.
        only_ueba = (lanes_fired == 1 and "ueba" in lane_scores)
        if only_ueba:
            effective = min(effective, UEBA_ONLY_BUNDLE_CAP)

        return round(float(effective), 4), list(set(all_stages))

    # ------------------------------------------------------------------ #
    # Window score computation
    # ------------------------------------------------------------------ #

    def _window_score(
        self,
        entries:         List[ScoreEntry],
        now:             datetime,
        window_minutes:  float,
        lam:             float,
        recency_minutes: float,
    ) -> Tuple[float, List[int], int]:
        """
        Compute accumulated decayed score for a given window.

        Only entries within window_minutes are included.
        Kill chain stages are counted only if seen within recency_minutes
        (prevents stale stage signals from inflating the bonus).

        Returns:
            (accumulated_score, recent_kill_chain_stages, contributing_entry_count)
        """
        now_ts           = now.timestamp()
        window_cutoff_ts = now_ts - window_minutes * 60
        recency_cutoff_ts = now_ts - recency_minutes * 60

        accumulated    = 0.0
        recent_stages: set = set()
        count = 0

        for entry in entries:
            entry_ts = entry.timestamp.timestamp()
            if entry_ts < window_cutoff_ts:
                continue
            age_min      = (now_ts - entry_ts) / 60.0
            accumulated += _decay(entry.raw_score, age_min, lam)
            if entry_ts >= recency_cutoff_ts:
                recent_stages.update(s for s in entry.stages if s > 0)
            count += 1

        return accumulated, sorted(recent_stages), count

    # ------------------------------------------------------------------ #
    # Incident candidate builder
    # ------------------------------------------------------------------ #

    def _build_incident_candidate(
        self,
        state:        EntityState,
        severity:     str,
        short_score:  float,
        long_score:   float,
        short_stages: List[int],
        long_stages:  List[int],
        short_bonus:  float,
        long_bonus:   float,
        now:          datetime,
    ) -> dict:
        """Build a self-contained incident_candidate dict for the multistage correlator."""
        return {
            "incident_id":    str(uuid.uuid4()),
            "entity_key":     state.entity_key,
            "entity_type":    state.entity_type,
            "severity":       severity,
            "short_window": {
                "score":            round(short_score, 2),
                "stages_covered":   short_stages,
                "kill_chain_bonus": short_bonus,
            },
            "long_window": {
                "score":            round(long_score, 2),
                "stages_covered":   long_stages,
                "kill_chain_bonus": long_bonus,
            },
            "first_seen":      state.first_seen.isoformat() if state.first_seen else "",
            "last_seen":       state.last_seen.isoformat()  if state.last_seen  else "",
            "emitted_at":      now.isoformat(),
            "total_bundles":   state.total_bundles,
            "top_risk_events": state.top_risk_events[:TOP_EVENTS_LIMIT],
        }

    # ------------------------------------------------------------------ #
    # Main process method
    # ------------------------------------------------------------------ #

    def process(self, bundle: dict) -> dict:
        """
        Process one detection_bundle.

        Updates the entity ledger, computes both window scores with kill chain
        bonuses, and determines whether to emit an incident_candidate.

        Returns an accumulator_result dict. Key fields:
            "final_severity"     — CRITICAL / HIGH / MEDIUM / LOW
            "escalate"           — True if final_severity >= HIGH
            "new_emission"       — True if a fresh incident_candidate was produced
            "incident_candidate" — populated only when new_emission is True
        """
        # ── Resolve entity ──────────────────────────────────────────────
        entity_key, entity_type = self._resolve_entity(bundle)

        # ── Parse timestamp — use event time for correct replay behaviour ─
        now = _parse_ts(bundle.get("timestamp", ""))
        if now is None:
            now = datetime.now(timezone.utc)

        # ── Get or create entity state ──────────────────────────────────
        if entity_key not in self._ledger:
            self._ledger[entity_key] = EntityState(
                entity_key  = entity_key,
                entity_type = entity_type,
                first_seen  = now,
            )
        state           = self._ledger[entity_key]
        state.last_seen = now
        state.total_bundles += 1

        # ── Compute this bundle's effective score contribution ──────────
        bundle_score, bundle_stages = self._compute_bundle_score(bundle)

        # ── Update strong-rule-evidence anchor ──────────────────────────
        # If this bundle contains a signature_rules hit with score >= the
        # strong floor, mark the entity as having qualified rule evidence.
        # Without this anchor, the entity will be capped at MEDIUM later
        # regardless of accumulated ML/UEBA score.
        for re in bundle.get("risk_events", []):
            if re.get("detector") == "signature_rules":
                if float(re.get("score", 0)) >= STRONG_RULE_SCORE_FLOOR:
                    # Also require it not to be a noisy-rule-only hit
                    rules = set(re.get("triggered_rules", []))
                    if rules and not rules.issubset(NOISY_RULE_NAMES):
                        state.has_strong_rule_evidence = True

        # ── Add entry to ledger ─────────────────────────────────────────
        if bundle_score > 0:
            entry = ScoreEntry(
                timestamp       = now,
                raw_score       = bundle_score,
                stages          = bundle_stages,
                risk_events     = bundle.get("risk_events", []),
                bundle_id       = bundle.get("event_id", str(uuid.uuid4())),
                detectors_fired = bundle.get("detectors_fired", []),
            )
            state.entries.append(entry)

            # Keep top risk_events by score for incident candidate context
            for re in bundle.get("risk_events", []):
                state.top_risk_events.append(re)
            state.top_risk_events.sort(key=lambda r: float(r.get("score", 0)), reverse=True)
            state.top_risk_events = state.top_risk_events[:TOP_EVENTS_LIMIT]

        # ── Prune entries that have fully aged out of the long window ───
        long_cutoff_ts = now.timestamp() - LONG_WINDOW_MINUTES * 60
        state.entries  = [e for e in state.entries
                          if e.timestamp.timestamp() >= long_cutoff_ts]

        # ── Compute window scores ───────────────────────────────────────
        short_raw, short_stages, short_n = self._window_score(
            state.entries, now,
            SHORT_WINDOW_MINUTES, _LAMBDA_SHORT, KILL_CHAIN_RECENCY_SHORT_MIN,
        )
        long_raw, long_stages, long_n = self._window_score(
            state.entries, now,
            LONG_WINDOW_MINUTES, _LAMBDA_LONG, KILL_CHAIN_RECENCY_LONG_MIN,
        )

        # ── Apply kill chain bonus ──────────────────────────────────────
        short_bonus = _kill_chain_multiplier(len(set(short_stages)))
        long_bonus  = _kill_chain_multiplier(len(set(long_stages)))

        short_score = short_raw * short_bonus
        long_score  = long_raw  * long_bonus

        # ── Severity mapping ────────────────────────────────────────────
        short_sev = _severity_label(short_score, short_window=True)
        long_sev  = _severity_label(long_score,  short_window=False)
        final_sev = _max_severity(short_sev, long_sev)

        # ── Rule-anchor cap: no strong rule evidence → MEDIUM ceiling ──
        # Splunk RBA pattern: ML+UEBA accumulation alone, no matter how high,
        # cannot escalate an entity to HIGH or CRITICAL without at least one
        # specific signature_rules hit (score >= 25, non-noisy).
        # This prevents the "busy user accumulates noise over 24h" false
        # positive that pulls hundreds of entities into the campaign.
        if not state.has_strong_rule_evidence:
            if final_sev in ("CRITICAL", "HIGH"):
                final_sev = "MEDIUM"
            if short_sev in ("CRITICAL", "HIGH"):
                short_sev = "MEDIUM"
            if long_sev  in ("CRITICAL", "HIGH"):
                long_sev  = "MEDIUM"

        # ── Escalation + emission decision ─────────────────────────────
        escalate = SEVERITY_ORDER[final_sev] >= SEVERITY_ORDER["HIGH"]

        new_emission = (
            escalate
            and SEVERITY_ORDER[final_sev] > SEVERITY_ORDER[state.last_emitted_severity]
        )

        # Reset emission state when the entity has cooled down to LOW —
        # next resurgence will trigger a fresh emission
        if final_sev == "LOW" and state.last_emitted_severity != "NONE":
            state.last_emitted_severity = "NONE"

        incident_candidate = None
        if new_emission:
            state.last_emitted_severity = final_sev
            incident_candidate = self._build_incident_candidate(
                state, final_sev,
                short_score, long_score,
                short_stages, long_stages,
                short_bonus, long_bonus,
                now,
            )

        # ── Build and return result ─────────────────────────────────────
        return {
            "entity_key":   entity_key,
            "entity_type":  entity_type,
            "timestamp":    now.isoformat(),
            "short_window": {
                "raw_score":            round(short_raw,   2),
                "score":                round(short_score, 2),
                "severity":             short_sev,
                "stages_covered":       short_stages,
                "kill_chain_bonus":     short_bonus,
                "contributing_events":  short_n,
            },
            "long_window": {
                "raw_score":            round(long_raw,   2),
                "score":                round(long_score, 2),
                "severity":             long_sev,
                "stages_covered":       long_stages,
                "kill_chain_bonus":     long_bonus,
                "contributing_events":  long_n,
            },
            "final_severity":       final_sev,
            "escalate":             escalate,
            "new_emission":         new_emission,
            "incident_candidate":   incident_candidate,
            "bundle_contribution":  round(bundle_score, 2),
            "total_entity_bundles": state.total_bundles,
        }

    def process_all(self, bundles: List[dict]) -> List[dict]:
        """
        Process a list of detection_bundles in chronological order.
        Returns all accumulator_results (including non-escalating ones).
        """
        return [self.process(b) for b in bundles]

    # ------------------------------------------------------------------ #
    # Utility / introspection
    # ------------------------------------------------------------------ #

    def escalated_entities(self) -> List[Tuple[str, str]]:
        """
        Returns (entity_key, last_emitted_severity) for all entities
        that have been escalated to HIGH or CRITICAL.
        """
        return [
            (k, v.last_emitted_severity)
            for k, v in self._ledger.items()
            if SEVERITY_ORDER.get(v.last_emitted_severity, 0) >= SEVERITY_ORDER["HIGH"]
        ]

    def get_entity_state(self, entity_key: str) -> Optional[EntityState]:
        """Return raw EntityState for debugging or testing."""
        return self._ledger.get(entity_key)

    def all_entities_summary(self) -> List[dict]:
        """
        Lightweight summary of all tracked entities.
        Useful for monitoring dashboards.
        """
        summary = []
        for key, state in self._ledger.items():
            summary.append({
                "entity_key":            key,
                "entity_type":           state.entity_type,
                "last_emitted_severity": state.last_emitted_severity,
                "total_bundles":         state.total_bundles,
                "first_seen":            state.first_seen.isoformat() if state.first_seen else "",
                "last_seen":             state.last_seen.isoformat()  if state.last_seen  else "",
                "ledger_entries":        len(state.entries),
            })
        return sorted(summary, key=lambda x: SEVERITY_ORDER.get(
            x["last_emitted_severity"], 0), reverse=True)

    def reset(self):
        """Clear all ledger state. Use between test runs."""
        self._ledger.clear()

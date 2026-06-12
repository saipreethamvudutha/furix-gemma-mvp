"""
layer2_features.py
------------------
Layer 2: Feature extraction from ECS events.

All 16 features are identical in semantics to the original pipeline.
Field paths are remapped to ECS:

    source.ip           (was: src_ip / client_ip)
    destination.port    (was: dst_port)
    network.protocol    (was: protocol)
    event.outcome       (was: result/action)
    event.action        (was: action)
    @timestamp          (was: timestamp)
    message             (unchanged)
    user.name           (was: user)
"""
from __future__ import annotations

import math
import os
import pickle
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import numpy as np

from ..config import (
    HIGH_RISK_PORTS, MEDIUM_RISK_PORTS, LOW_RISK_PORTS,
    PRIVATE_IP_PREFIXES, DEFAULT_PORT_RISK, DEFAULT_ENTROPY,
    OFFHOURS_START, OFFHOURS_END,
    SESSION_WINDOW_MINUTES, SESSION_FAILURE_WINDOW, SESSION_MAX_HISTORY,
    BASELINE_STATS_PATH,
)
from ..ingest import get_field

FEATURE_NAMES = [
    # Temporal (4)
    "hour_of_day",
    "day_of_week",
    "is_offhours",
    "seconds_since_last_event",
    # Network (4)
    "is_private_ip",
    "is_known_bad_ip",
    "port_risk_score",
    "protocol_ordinal",
    # Event (4)
    "action_rarity",
    "outcome_binary",
    "message_entropy",
    "message_length_norm",
    # Session (4)
    "failure_count_5min",
    "unique_dest_count_10min",
    "action_transition_surprise",
    "session_event_rate",
]

PROTOCOL_MAP = {
    "tcp": 1, "udp": 2, "icmp": 3,
    "http": 4, "https": 5, "ssh": 6, "dns": 7,
}


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _port_risk(port: Optional[int]) -> float:
    if port is None:
        return DEFAULT_PORT_RISK
    if port in HIGH_RISK_PORTS:
        return 0.8
    if port in MEDIUM_RISK_PORTS:
        return 0.5
    if port in LOW_RISK_PORTS:
        return 0.1
    return DEFAULT_PORT_RISK


def _is_private(ip: Optional[str]) -> float:
    if not ip or not isinstance(ip, str):
        return 0.0
    return 1.0 if ip.startswith(PRIVATE_IP_PREFIXES) else 0.0


def _parse_ts(ts_str: Optional[str]) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        from dateutil import parser as dp
        return dp.parse(ts_str)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Feature Engine
# --------------------------------------------------------------------------- #

class FeatureEngine:
    """
    Stateful feature extractor.
    Maintains session history (per user/source-IP) for window-based features.
    """

    def __init__(self, threat_intel: set | None = None):
        self.threat_intel: set = threat_intel or set()

        # Action frequency counts (filled during fit / running tally)
        self._action_counts: Dict[str, int] = defaultdict(int)
        self._total_events: int = 0

        # Baseline stats for calibration (loaded after training)
        self._baseline_stats: Dict[str, Any] = {}

        # Session state keyed by identity (user or source IP)
        # Each value: deque of (datetime, outcome, action, dest_ip) tuples
        self._sessions: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=SESSION_MAX_HISTORY)
        )
        self._last_event_time: Optional[datetime] = None

    # ------------------------------------------------------------------ #
    # Load / save baseline stats
    # ------------------------------------------------------------------ #

    def save_baseline_stats(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            pickle.dump({
                "action_counts": dict(self._action_counts),
                "total_events":  self._total_events,
            }, fh)

    def load_baseline_stats(self, path: str):
        if not os.path.exists(path):
            return
        with open(path, "rb") as fh:
            data = pickle.load(fh)
        self._action_counts = defaultdict(int, data.get("action_counts", {}))
        self._total_events  = data.get("total_events", 0)

    # ------------------------------------------------------------------ #
    # Fit on baseline events (builds action frequency table)
    # ------------------------------------------------------------------ #

    def fit(self, events: List[Dict[str, Any]]):
        """Pass all baseline events to build action frequency counts."""
        for ev in events:
            action = (get_field(ev, "event.action") or "unknown").lower()
            self._action_counts[action] += 1
            self._total_events += 1

    # ------------------------------------------------------------------ #
    # Extract one event → feature vector
    # ------------------------------------------------------------------ #

    def extract(self, event: Dict[str, Any]) -> np.ndarray:
        vec = np.zeros(len(FEATURE_NAMES), dtype=np.float32)

        # --- identity for session tracking ---
        identity = (
            get_field(event, "user.name")
            or get_field(event, "source.ip")
            or "unknown"
        )

        # --- timestamp ---
        ts = _parse_ts(get_field(event, "@timestamp"))
        now = ts or datetime.now(timezone.utc)

        # ── Temporal ──────────────────────────────────────────────────
        vec[0] = now.hour                              # hour_of_day
        vec[1] = now.weekday()                         # day_of_week
        h = now.hour
        vec[2] = 1.0 if (h >= OFFHOURS_START or h < OFFHOURS_END) else 0.0  # is_offhours

        if self._last_event_time and ts:
            delta = (ts - self._last_event_time).total_seconds()
            # Cap at 300s — gaps longer than 5 min are all equally "idle"
            # Prevents off-hours batch gaps from dominating the feature score
            vec[3] = min(max(0.0, delta), 300.0)       # seconds_since_last_event
        else:
            vec[3] = 0.0
        self._last_event_time = ts or self._last_event_time

        # ── Network ───────────────────────────────────────────────────
        src_ip   = get_field(event, "source.ip")
        dst_port = get_field(event, "destination.port")
        protocol = (
            get_field(event, "network.protocol")
            or get_field(event, "network.transport")
            or ""
        ).lower()

        vec[4] = _is_private(src_ip)                   # is_private_ip
        vec[5] = 1.0 if src_ip in self.threat_intel else 0.0  # is_known_bad_ip
        vec[6] = _port_risk(dst_port)                  # port_risk_score
        vec[7] = float(PROTOCOL_MAP.get(protocol, 0))  # protocol_ordinal

        # ── Event ─────────────────────────────────────────────────────
        action  = (get_field(event, "event.action") or "unknown").lower()
        outcome = (get_field(event, "event.outcome") or "").lower()
        message = get_field(event, "message") or ""

        total = max(self._total_events, 1)
        count = self._action_counts.get(action, 0)
        vec[8] = 1.0 - (count / total)                 # action_rarity

        vec[9] = 1.0 if outcome == "failure" else 0.0  # outcome_binary

        raw_entropy = _shannon_entropy(message)
        vec[10] = min(raw_entropy / 8.0, 1.0)          # message_entropy (norm to 0-1)

        vec[11] = min(len(message) / 500.0, 1.0)       # message_length_norm

        # ── Session ───────────────────────────────────────────────────
        dst_ip = get_field(event, "destination.ip") or ""
        session = self._sessions[identity]
        session.append((now, outcome, action, dst_ip))

        # failure_count_5min
        cutoff_fail = now.timestamp() - SESSION_FAILURE_WINDOW * 60
        vec[12] = float(sum(
            1 for (t, o, *_) in session
            if t.timestamp() >= cutoff_fail and o == "failure"
        ))

        # unique_dest_count_10min
        cutoff_dest = now.timestamp() - SESSION_WINDOW_MINUTES * 60
        vec[13] = float(len(set(
            d for (t, _, __, d) in session
            if t.timestamp() >= cutoff_dest and d
        )))

        # action_transition_surprise
        actions_recent = [a for (_, __, a, ___) in session]
        if len(actions_recent) >= 2:
            prev = actions_recent[-2]
            curr = actions_recent[-1]
            surprise = 0.0 if prev == curr else 1.0
        else:
            surprise = 0.0
        vec[14] = surprise                             # action_transition_surprise

        # session_event_rate — capped at 20 events/min to prevent
        # compressed test windows from inflating scores vs 24h baseline
        window_events = sum(
            1 for (t, *_) in session
            if t.timestamp() >= cutoff_dest
        )
        raw_rate = float(window_events) / SESSION_WINDOW_MINUTES
        vec[15] = min(raw_rate, 20.0)   # cap at 20/min — above this is anomalous

        # Update action frequency for running scoring
        self._action_counts[action] += 1
        self._total_events += 1

        return vec

    # ------------------------------------------------------------------ #
    # Batch extract
    # ------------------------------------------------------------------ #

    def extract_all(self, events: List[Dict[str, Any]]) -> np.ndarray:
        """Return (N, 16) feature matrix for a list of events."""
        return np.vstack([self.extract(e) for e in events]) if events else np.empty((0, len(FEATURE_NAMES)))

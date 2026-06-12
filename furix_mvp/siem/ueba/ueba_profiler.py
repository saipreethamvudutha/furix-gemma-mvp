"""
ueba_profiler.py
----------------
UEBA Profiler — offline, build-time script.

Reads all baseline ECS JSONL files, extracts per-user behavioral
dimensions, fits KDE profiles, and persists ueba_profiles.pkl.

Three-tier fallback pyramid:
    Individual KDE  (≥ MIN_OBS_INDIVIDUAL observations per dimension)
        ↓ fallback
    Peer Group KDE  (≥ MIN_OBS_PEER_GROUP observations per dimension)
        ↓ fallback
    Global stats    (always available — mean/std from full population)

Service accounts (svc_*) get zero-tolerance envelope profiling
instead of KDE — any value outside their observed min/max is
immediately maximum anomaly score.

Output:
    models/ueba/ueba_profiles.pkl
    models/ueba/ueba_build_report.json

Usage:
    python ueba_profiler.py                          # uses config paths
    python ueba_profiler.py --ecs-dir path/to/ecs   # override ECS dir
"""
from __future__ import annotations

import argparse
import json
import os
import pickle
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from scipy.stats import gaussian_kde

from ..config import (
    UEBA_DIR, UEBA_PROFILES_PATH, UEBA_REPORT_PATH,
)
from .. import tenant

# =============================================================================
#  Constants
# =============================================================================

# Minimum observations to fit individual KDE per dimension
MIN_OBS_INDIVIDUAL  = 30

# Minimum observations to fit peer group KDE per dimension
MIN_OBS_PEER_GROUP  = 50

# KDE bandwidth method
KDE_BANDWIDTH = "scott"

# Peer-group rules are tenant-specific (org username conventions + named
# accounts) — sourced from the shared tenant profile, env/literal-overridable.
PEER_GROUP_RULES: List[Tuple[str, List[str]]] = tenant.PEER_GROUP_RULES
DEFAULT_PEER_GROUP = tenant.DEFAULT_PEER_GROUP


# =============================================================================
#  Peer group assignment
# =============================================================================

def assign_peer_group(username: str) -> str:
    u = username.lower()
    for group, patterns in PEER_GROUP_RULES:
        if any(p.lower() in u for p in patterns):
            return group
    return DEFAULT_PEER_GROUP


def is_service_account(username: str) -> bool:
    return username.lower().startswith(tenant.SVC_ACCOUNT_PREFIX)


# =============================================================================
#  Event field extractors
#  Each returns a float value or None if the field isn't applicable
#  for this event. None values are simply skipped during aggregation.
# =============================================================================

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


def _extract_dimensions(event: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract all UEBA-relevant behavioral dimensions from one ECS event.
    Returns a dict of {dimension_name: float_value}.
    Only dimensions applicable to this event type are returned.
    """
    dims: Dict[str, float] = {}
    module  = (_get(event, "event.module") or "").lower()
    outcome = (_get(event, "event.outcome") or "").lower()
    ts      = _get(event, "@timestamp") or ""

    # ── Temporal dimensions (all sources) ────────────────────────────
    if ts:
        try:
            from datetime import datetime
            dt = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
            dims["login_hour"]         = float(dt.hour)
            dims["login_day_of_week"]  = float(dt.weekday())  # 0=Mon, 6=Sun
        except Exception:
            pass

    # ── Authentication (Okta) ────────────────────────────────────────
    if module == "authentication":
        dims["auth_event"] = 1.0
        if outcome == "failure":
            dims["auth_failure"] = 1.0
        elif outcome == "success":
            dims["auth_success"] = 1.0

        # Source IP diversity — tracked as unique IP flag per event
        src_ip = _get(event, "source.ip") or ""
        if src_ip:
            dims["has_source_ip"] = 1.0

        # Geo — non-US login flag
        country = _get(event, "labels.geo_country") or "US"
        dims["non_us_login"] = 0.0 if country.upper() in ("US", "UNITED STATES") else 1.0

    # ── Endpoint / CrowdStrike ───────────────────────────────────────
    if module == "endpoint":
        action = (_get(event, "event.action") or "").lower()

        if action == "process_creation":
            dims["process_creation"] = 1.0

        if action == "network_connect":
            dst_port = _get(event, "destination.port") or 0
            dims["network_connect"]  = 1.0
            dims["destination_port"] = float(dst_port)

            # Bytes out
            bytes_out = _get(event, "source.bytes") or 0
            if bytes_out:
                dims["bytes_out"] = float(bytes_out)

        if action == "dns_query":
            dims["dns_query"] = 1.0

    # ── Database / Imperva DAM ───────────────────────────────────────
    if module == "database":
        dims["db_access"] = 1.0
        row_count = _get(event, "labels.row_count") or 0
        if row_count:
            dims["query_row_count"] = float(row_count)
        phi = _get(event, "labels.phi_access") or False
        if phi:
            dims["phi_table_access"] = 1.0

    # ── PAM / CyberArk ───────────────────────────────────────────────
    if module in ("authentication",) and "pam" in (_get(event, "event.dataset") or "").lower():
        dims["pam_checkout"] = 1.0
        target = _get(event, "destination.address") or ""
        if target:
            dims["pam_unique_target"] = 1.0

    # ── Cloud / CloudTrail ───────────────────────────────────────────
    if module == "cloud":
        dims["cloud_api_call"] = 1.0
        api = (_get(event, "event.action") or "").lower()
        sensitive_apis = {
            "getsecretvalue", "assumerolewithsaml", "assumerolewithwebidentity",
            "getobject", "createuser", "attachrolepolicy",
            "decrypt", "generatedatakey", "deletebucketpolicy",
        }
        if api in sensitive_apis:
            dims["sensitive_api_call"] = 1.0

        s3_count = _get(event, "labels.s3_object_count") or 0
        if s3_count:
            dims["s3_object_count"] = float(s3_count)

    # ── Severity ─────────────────────────────────────────────────────
    sev = _get(event, "event.severity") or 0
    if sev >= 6:
        dims["high_severity_event"] = 1.0

    return dims


# =============================================================================
#  Raw observation collector
# =============================================================================

def collect_observations(
    ecs_files: List[str],
) -> Tuple[
    Dict[str, Dict[str, List[float]]],   # user → dim → [values]
    Dict[str, int],                       # user → total event count
]:
    """
    Pass 1: read all ECS events, collect raw dimension observations per user.
    """
    # user → dimension → list of float values
    user_obs:    Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
    user_counts: Dict[str, int]                    = defaultdict(int)

    total_events   = 0
    skipped_no_user = 0

    for fpath in ecs_files:
        fname = os.path.basename(fpath)
        print(f"  [Profiler] Reading {fname} ...")

        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                total_events += 1
                user = (_get(event, "user.name") or "").strip()
                if not user:
                    skipped_no_user += 1
                    continue

                user_counts[user] += 1
                dims = _extract_dimensions(event)
                for dim, val in dims.items():
                    user_obs[user][dim].append(val)

    print(f"  [Profiler] Total events: {total_events:,} | "
          f"With user: {total_events - skipped_no_user:,} | "
          f"Distinct users: {len(user_obs)}")

    return dict(user_obs), dict(user_counts)


# =============================================================================
#  KDE fitting helpers
# =============================================================================

def _fit_kde(values: List[float]) -> Optional[gaussian_kde]:
    """Fit a KDE on values. Returns None if too few unique values."""
    arr = np.array(values, dtype=np.float64)
    if len(arr) < 2:
        return None
    # KDE requires variance — if all values identical, return None
    if np.std(arr) < 1e-10:
        return None
    try:
        return gaussian_kde(arr, bw_method=KDE_BANDWIDTH)
    except Exception:
        return None


def _dim_profile(values: List[float], tier: str) -> Dict[str, Any]:
    """Build a single dimension profile dict."""
    arr = np.array(values, dtype=np.float64)
    kde = _fit_kde(values)
    return {
        "kde":           kde,
        "observations":  len(values),
        "mean":          float(np.mean(arr)),
        "std":           float(np.std(arr)),
        "min":           float(np.min(arr)),
        "max":           float(np.max(arr)),
        "p5":            float(np.percentile(arr, 5)),
        "p95":           float(np.percentile(arr, 95)),
        "profile_tier":  tier,
    }


# =============================================================================
#  Service account envelope profiling
# =============================================================================

def _build_svc_envelope(
    obs: Dict[str, List[float]]
) -> Dict[str, Dict[str, Any]]:
    """
    For service accounts: build min/max behavioral envelope per dimension.
    Any value outside [min, max] at score time = maximum anomaly.
    """
    envelope: Dict[str, Dict[str, Any]] = {}
    for dim, values in obs.items():
        if not values:
            continue
        arr = np.array(values, dtype=np.float64)
        envelope[dim] = {
            "kde":          None,          # not used for svc accounts
            "observations": len(values),
            "mean":         float(np.mean(arr)),
            "std":          float(np.std(arr)),
            "min":          float(np.min(arr)),
            "max":          float(np.max(arr)),
            "p5":           float(np.percentile(arr, 5)),
            "p95":          float(np.percentile(arr, 95)),
            "profile_tier": "zero_tolerance",
        }
    return envelope


# =============================================================================
#  Peer group aggregation
# =============================================================================

def build_peer_group_obs(
    user_obs:   Dict[str, Dict[str, List[float]]],
    peer_groups: Dict[str, str],   # username → group_name
) -> Dict[str, Dict[str, List[float]]]:
    """
    Aggregate all user observations by peer group.
    """
    pg_obs: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
    for user, dims in user_obs.items():
        group = peer_groups.get(user, DEFAULT_PEER_GROUP)
        for dim, values in dims.items():
            pg_obs[group][dim].extend(values)
    return {g: dict(dims) for g, dims in pg_obs.items()}


# =============================================================================
#  Global stats
# =============================================================================

def build_global_stats(
    user_obs: Dict[str, Dict[str, List[float]]]
) -> Dict[str, Dict[str, float]]:
    """Mean and std per dimension across all users."""
    all_obs: Dict[str, List[float]] = defaultdict(list)
    for dims in user_obs.values():
        for dim, values in dims.items():
            all_obs[dim].extend(values)

    global_stats: Dict[str, Dict[str, float]] = {}
    for dim, values in all_obs.items():
        arr = np.array(values, dtype=np.float64)
        global_stats[dim] = {
            "mean": float(np.mean(arr)),
            "std":  float(np.std(arr)),
            "min":  float(np.min(arr)),
            "max":  float(np.max(arr)),
            "observations": len(values),
        }
    return global_stats


# =============================================================================
#  Main profile builder
# =============================================================================

def build_profiles(
    user_obs:        Dict[str, Dict[str, List[float]]],
    user_counts:     Dict[str, int],
    pg_obs:          Dict[str, Dict[str, List[float]]],
    global_stats:    Dict[str, Dict[str, float]],
    peer_groups:     Dict[str, str],
) -> Dict[str, Any]:
    """
    Pass 2: for each user, for each dimension, fit the best available KDE.
    Returns the full profiles dict.
    """
    profiles: Dict[str, Any] = {}

    for user, dims in user_obs.items():
        group        = peer_groups.get(user, DEFAULT_PEER_GROUP)
        is_svc       = is_service_account(user)

        if is_svc:
            # Zero-tolerance envelope — no KDE
            dim_profiles = _build_svc_envelope(dims)
        else:
            dim_profiles: Dict[str, Any] = {}
            for dim, values in dims.items():
                if len(values) >= MIN_OBS_INDIVIDUAL:
                    # Tier 1: individual KDE
                    dim_profiles[dim] = _dim_profile(values, "individual")
                else:
                    # Try peer group fallback
                    pg_values = pg_obs.get(group, {}).get(dim, [])
                    if len(pg_values) >= MIN_OBS_PEER_GROUP:
                        dim_profiles[dim] = _dim_profile(pg_values, "peer_group")
                    else:
                        # Global stats fallback — no KDE, just mean/std
                        g = global_stats.get(dim, {})
                        dim_profiles[dim] = {
                            "kde":          None,
                            "observations": g.get("observations", 0),
                            "mean":         g.get("mean", 0.0),
                            "std":          g.get("std", 1.0),
                            "min":          g.get("min", 0.0),
                            "max":          g.get("max", 0.0),
                            "p5":           0.0,
                            "p95":          0.0,
                            "profile_tier": "global",
                        }

        profiles[user] = {
            "peer_group":         group,
            "is_service_account": is_svc,
            "total_events":       user_counts.get(user, 0),
            "dimensions":         dim_profiles,
        }

    return profiles


# =============================================================================
#  Peer group KDE profiles
# =============================================================================

def build_peer_group_profiles(
    pg_obs: Dict[str, Dict[str, List[float]]]
) -> Dict[str, Dict[str, Any]]:
    pg_profiles: Dict[str, Dict[str, Any]] = {}
    for group, dims in pg_obs.items():
        pg_profiles[group] = {}
        for dim, values in dims.items():
            if len(values) >= MIN_OBS_PEER_GROUP:
                pg_profiles[group][dim] = _dim_profile(values, "peer_group")
    return pg_profiles


# =============================================================================
#  Build report
# =============================================================================

def build_report(
    profiles:     Dict[str, Any],
    pg_profiles:  Dict[str, Dict[str, Any]],
    global_stats: Dict[str, Dict[str, float]],
    user_counts:  Dict[str, int],
    peer_groups:  Dict[str, str],
) -> Dict[str, Any]:

    tier_counts = defaultdict(int)
    for user, profile in profiles.items():
        if profile["is_service_account"]:
            tier_counts["zero_tolerance"] += 1
            continue
        for dim_p in profile["dimensions"].values():
            tier_counts[dim_p.get("profile_tier", "global")] += 1

    pg_user_counts = defaultdict(int)
    for group in peer_groups.values():
        pg_user_counts[group] += 1

    return {
        "built_at":          datetime.now(timezone.utc).isoformat(),
        "total_users":       len(profiles),
        "total_events":      sum(user_counts.values()),
        "dimensions_tracked": sorted(global_stats.keys()),
        "peer_groups": {
            g: {
                "user_count": pg_user_counts[g],
                "dimensions": list(dims.keys()),
            }
            for g, dims in pg_profiles.items()
        },
        "profile_tier_distribution": dict(tier_counts),
        "top_users_by_events": sorted(
            user_counts.items(), key=lambda x: -x[1]
        )[:20],
    }


# =============================================================================
#  Entry point
# =============================================================================

def run(ecs_dir: str):
    """Build UEBA profiles from all ECS JSONL files in ecs_dir."""

    print(f"\n[UEBA Profiler] ── BUILD ─────────────────────────────────")
    print(f"[UEBA Profiler] ECS directory: {ecs_dir}")

    # Collect ECS files
    ecs_files = sorted([
        os.path.join(ecs_dir, f)
        for f in os.listdir(ecs_dir)
        if f.endswith(".ecs.jsonl")
    ])
    if not ecs_files:
        raise FileNotFoundError(f"No .ecs.jsonl files found in: {ecs_dir}")
    print(f"[UEBA Profiler] Found {len(ecs_files)} ECS files.")

    # ── Pass 1: collect raw observations ──────────────────────────────
    print(f"\n[UEBA Profiler] Pass 1: collecting observations ...")
    user_obs, user_counts = collect_observations(ecs_files)

    # ── Assign peer groups ────────────────────────────────────────────
    peer_groups = {u: assign_peer_group(u) for u in user_obs}
    pg_dist = defaultdict(int)
    for g in peer_groups.values():
        pg_dist[g] += 1
    print(f"[UEBA Profiler] Peer group distribution: {dict(pg_dist)}")

    # ── Build aggregated peer group and global observations ───────────
    pg_obs       = build_peer_group_obs(user_obs, peer_groups)
    global_stats = build_global_stats(user_obs)

    # ── Pass 2: fit profiles ──────────────────────────────────────────
    print(f"\n[UEBA Profiler] Pass 2: fitting KDE profiles ...")
    profiles    = build_profiles(
        user_obs, user_counts, pg_obs, global_stats, peer_groups
    )
    pg_profiles = build_peer_group_profiles(pg_obs)

    print(f"[UEBA Profiler] Profiles built for {len(profiles)} users.")
    print(f"[UEBA Profiler] Peer group profiles: {list(pg_profiles.keys())}")
    print(f"[UEBA Profiler] Global dimensions tracked: {len(global_stats)}")

    # ── Persist ───────────────────────────────────────────────────────
    os.makedirs(UEBA_DIR, exist_ok=True)

    artifact = {
        "profiles":            profiles,
        "peer_group_profiles": pg_profiles,
        "global_stats":        global_stats,
        "metadata": {
            "built_at":          datetime.now(timezone.utc).isoformat(),
            "total_users":       len(profiles),
            "total_events":      sum(user_counts.values()),
            "dimensions_tracked": sorted(global_stats.keys()),
            "ecs_dir":           ecs_dir,
        },
    }

    with open(UEBA_PROFILES_PATH, "wb") as f:
        pickle.dump(artifact, f, protocol=pickle.HIGHEST_PROTOCOL)

    print(f"[UEBA Profiler] Saved: {UEBA_PROFILES_PATH}")

    # ── Build report ──────────────────────────────────────────────────
    report = build_report(
        profiles, pg_profiles, global_stats, user_counts, peer_groups
    )
    with open(UEBA_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[UEBA Profiler] Report: {UEBA_REPORT_PATH}")

    # ── Summary ───────────────────────────────────────────────────────
    print(f"\n[UEBA Profiler] ── SUMMARY ───────────────────────────────")
    print(f"  Users profiled       : {len(profiles)}")
    print(f"  Dimensions tracked   : {sorted(global_stats.keys())}")
    print(f"  Peer groups          : {list(pg_profiles.keys())}")
    t = report["profile_tier_distribution"]
    print(f"  Tier distribution    : {t}")
    print(f"[UEBA Profiler] Done.\n")

    return artifact


# =============================================================================
#  CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build UEBA profiles from ECS baseline logs.")
    parser.add_argument(
        "--ecs-dir",
        default=None,
        help="Directory containing .ecs.jsonl baseline files. "
             "Defaults to data/baseline_ecs/ from config.",
    )
    args = parser.parse_args()

    if args.ecs_dir:
        ecs_directory = args.ecs_dir
    else:
        # Default: same directory where baseline ECS files land after training.
        # Run as a module: python -m furix_mvp.siem.ueba.ueba_profiler --ecs-dir ...
        from ..config import DATA_DIR
        ecs_directory = os.path.join(DATA_DIR, "baseline_ecs")
        # Fallback: if baseline_ecs doesn't exist, try the raw baseline dir
        if not os.path.isdir(ecs_directory):
            from ..config import BASELINE_LOG
            ecs_directory = os.path.dirname(BASELINE_LOG)

    if not os.path.isdir(ecs_directory):
        print(f"ERROR: ECS directory not found: {ecs_directory}")
        print("Run 'python main.py train' first to generate ECS files, "
              "then run this profiler.")
        sys.exit(1)

    run(ecs_directory)
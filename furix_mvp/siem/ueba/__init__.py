"""UEBA — user/entity behavioural analytics (first ML-stack module).

- ``ueba_profiler`` (OFFLINE build): reads baseline ECS, fits per-user KDE
  profiles via a three-tier fallback (individual → peer-group → global; service
  accounts get a zero-tolerance min/max envelope), and persists
  ``ueba_profiles.pkl``. Owns ``assign_peer_group`` (also used by the correlator)
  and the canonical ``_extract_dimensions``.
- ``UEBAScorer`` (RUNTIME): loads those profiles and scores live ECS events into
  the same ``risk_event`` shape the rule engine emits (``detector="ueba"``).

Requires ``numpy`` + ``scipy`` (requirements-siem.txt) AND a trained
``ueba_profiles.pkl`` (built offline before scoring). Peer-group rules are
tenant-specific (``furix_mvp.siem.tenant``). Importing this package pulls the ML
stack, so the deterministic lanes never import it eagerly.
"""
from .ueba_profiler import assign_peer_group, is_service_account
from .ueba_profiler import run as build_profiles_from_dir
from .ueba_scorer import UEBAScorer
from . import ueba_profiler, ueba_scorer

__all__ = [
    "UEBAScorer",
    "assign_peer_group",
    "is_service_account",
    "build_profiles_from_dir",
    "ueba_profiler",
    "ueba_scorer",
]

"""Layer 1 — ECS ingestion.

Auto-detects a log file's format (already-ECS JSONL · structured Coventra JSONL ·
raw vendor) and normalises it to ECS 8.11 event dicts that every downstream
detector lane consumes. Pure standard library — no ML deps — so it runs inside
furix's light core.

    from furix_mvp.siem.ingest import ensure_ecs, load_events
    ecs_path = ensure_ecs("auth.log")          # → writes <name>.ecs.jsonl
    events   = load_events(ecs_path)           # → list[dict] of ECS events

Raw vendor formats supported (auto-detected per line): Palo Alto NGFW,
CrowdStrike Falcon, Imperva DAM, Okta, CyberArk PAM, AWS CloudTrail, Nginx
(+ WAF JSON), Proofpoint.
"""
from .layer1_ecs_reader import (
    detect_format,
    ensure_ecs,
    ensure_ecs_dir,
    load_events,
    load_events_from_dir,
    get_field,
)
from . import raw_to_ecs, jsonl_to_ecs

__all__ = [
    "detect_format",
    "ensure_ecs",
    "ensure_ecs_dir",
    "load_events",
    "load_events_from_dir",
    "get_field",
    "raw_to_ecs",
    "jsonl_to_ecs",
]

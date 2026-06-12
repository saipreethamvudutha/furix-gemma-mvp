"""
layer1_ecs_reader.py
--------------------
Layer 1: Format detection + ECS conversion gate + structured event reader.

Three-path detection on every input file:

    Input file
        ↓
    Peek first line
        ├── has "ecs" key        → already ECS JSONL  → read directly
        ├── has "source" + "metadata" keys
        │                        → structured Coventra JSONL → jsonl_to_ecs
        └── neither              → raw vendor format   → raw_to_ecs
        ↓
    List of normalised ECS event dicts

Directory mode:
    ensure_ecs_dir(directory) processes every file in the directory,
    converts each via the appropriate path, and returns merged event list.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Dict, Any, Tuple

from .jsonl_to_ecs import run as _jsonl_convert   # structured Coventra JSONL
from .raw_to_ecs   import run as _raw_convert     # real vendor raw formats

# File extensions we'll process in directory mode
_PROCESSABLE_EXTS = {".log", ".jsonl", ".json", ".txt"}

# Extensions to skip (already converted outputs)
_SKIP_SUFFIXES = {".ecs.jsonl"}


# =============================================================================
#  FORMAT DETECTION
# =============================================================================

def _is_ecs(line: str) -> bool:
    """Line is already ECS — has top-level 'ecs' key."""
    try:
        doc = json.loads(line)
        return isinstance(doc, dict) and "ecs" in doc
    except (json.JSONDecodeError, ValueError):
        return False


def _is_structured_jsonl(line: str) -> bool:
    """
    Line is structured Coventra JSONL — has 'source' object with 'type'
    and 'metadata' object. This is the format jsonl_to_ecs.py handles.
    """
    try:
        doc = json.loads(line)
        return (
            isinstance(doc, dict)
            and isinstance(doc.get("source"), dict)
            and "type" in doc.get("source", {})
            and "metadata" in doc
        )
    except (json.JSONDecodeError, ValueError):
        return False


def _peek_first(path: str) -> str:
    """Return first non-blank line of file."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped:
                return stripped
    return ""


def detect_format(path: str) -> str:
    """
    Return one of: 'ecs' | 'structured_jsonl' | 'raw_vendor' | 'empty'
    """
    first = _peek_first(path)
    if not first:
        return "empty"
    if _is_ecs(first):
        return "ecs"
    if _is_structured_jsonl(first):
        return "structured_jsonl"
    return "raw_vendor"


# =============================================================================
#  SINGLE FILE — ensure ECS
# =============================================================================

def ensure_ecs(input_path: str, ecs_output_path: str | None = None) -> str:
    """
    Convert input_path to ECS JSONL if needed.
    Returns path to the ECS file (may be input_path itself if already ECS).
    """
    name   = Path(input_path).name
    fmt    = detect_format(input_path)

    if fmt == "empty":
        raise ValueError(f"Input file is empty: {input_path}")

    if fmt == "ecs":
        print(f"[Layer1] '{name}' — already ECS, skipping conversion.")
        return input_path

    # Determine output path
    if ecs_output_path is None:
        base = os.path.splitext(input_path)[0]
        # Handle .ecs.jsonl already in name
        if base.endswith(".ecs"):
            base = base[:-4]
        ecs_output_path = base + ".ecs.jsonl"

    if fmt == "structured_jsonl":
        print(f"[Layer1] '{name}' — structured JSONL → converting via jsonl_to_ecs ...")
        stats, by_cat = _jsonl_convert(input_path, ecs_output_path)
    else:
        print(f"[Layer1] '{name}' — raw vendor format → converting via raw_to_ecs ...")
        stats, by_src = _raw_convert(input_path, ecs_output_path)
        by_cat = by_src

    total  = stats.get("total", 0)
    ok     = stats.get("ok", 0)
    failed = stats.get("failed", 0)
    print(f"[Layer1] '{name}' — {ok}/{total} converted"
          + (f", {failed} failed" if failed else ""))

    return ecs_output_path


# =============================================================================
#  DIRECTORY MODE — process all files in a directory
# =============================================================================

def ensure_ecs_dir(directory: str, ecs_output_dir: str | None = None) -> List[str]:
    """
    Process every log file in directory.
    Returns list of ECS JSONL file paths (one per source file).

    Skips:
      - Files already named *.ecs.jsonl
      - Non-log file extensions
      - Empty files
    """
    if not os.path.isdir(directory):
        raise NotADirectoryError(f"Not a directory: {directory}")

    out_dir = ecs_output_dir or directory
    os.makedirs(out_dir, exist_ok=True)

    ecs_files = []
    all_files = sorted(Path(directory).iterdir())

    for fpath in all_files:
        # Skip directories
        if fpath.is_dir():
            continue

        # Skip already-converted outputs
        if any(str(fpath).endswith(s) for s in _SKIP_SUFFIXES):
            continue

        # Skip non-log extensions
        if fpath.suffix.lower() not in _PROCESSABLE_EXTS:
            continue

        # Output path in out_dir
        stem       = fpath.stem
        if stem.endswith(".ecs"):
            stem = stem[:-4]
        out_path   = os.path.join(out_dir, stem + ".ecs.jsonl")

        try:
            ecs_path = ensure_ecs(str(fpath), ecs_output_path=out_path)
            ecs_files.append(ecs_path)
        except ValueError as exc:
            print(f"[Layer1] Skipping '{fpath.name}': {exc}")

    print(f"[Layer1] Directory '{Path(directory).name}': "
          f"{len(ecs_files)} files converted/ready.")
    return ecs_files


# =============================================================================
#  LOAD EVENTS
# =============================================================================

def load_events(ecs_path: str) -> List[Dict[str, Any]]:
    """Read an ECS JSONL file → list of event dicts."""
    events:  List[Dict[str, Any]] = []
    skipped: int = 0

    with open(ecs_path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
                if isinstance(doc, dict):
                    events.append(doc)
                else:
                    skipped += 1
            except json.JSONDecodeError:
                skipped += 1
                if skipped <= 3:
                    print(f"[Layer1] WARNING: malformed JSON at line {lineno} "
                          f"in '{Path(ecs_path).name}'")

    if skipped:
        print(f"[Layer1] {skipped} lines skipped (malformed) in '{Path(ecs_path).name}'.")
    print(f"[Layer1] Loaded {len(events):,} events from '{Path(ecs_path).name}'.")
    return events


def load_events_from_dir(ecs_files: List[str]) -> List[Dict[str, Any]]:
    """
    Load and merge events from multiple ECS JSONL files.
    Returns combined list sorted by @timestamp.
    """
    all_events: List[Dict[str, Any]] = []
    for path in ecs_files:
        all_events.extend(load_events(path))

    # Sort chronologically
    def _ts_key(ev):
        return ev.get("@timestamp", "")

    all_events.sort(key=_ts_key)
    print(f"[Layer1] Total merged events: {len(all_events):,}")
    return all_events


# =============================================================================
#  FIELD ACCESSOR
# =============================================================================

def get_field(event: Dict[str, Any], dotted_path: str, default=None):
    """
    Safe nested ECS field getter.
    get_field(event, "source.ip") → event["source"]["ip"] or default.
    """
    parts = dotted_path.split(".")
    node  = event
    for p in parts:
        if not isinstance(node, dict):
            return default
        node = node.get(p)
        if node is None:
            return default
    return node

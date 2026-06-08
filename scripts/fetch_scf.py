#!/usr/bin/env python3
"""Fetch the real Secure Controls Framework (SCF) crosswalk data.

Downloads the official SCF "JSON_Data" export (1,090 controls, 200+ frameworks)
from the public SCF OSCAL GitHub repo into data/scf/scf_catalog.json (gitignored —
the SCF is CC-BY-ND, so we do NOT commit it; we fetch it).

Then point the engine at it:
    export SCF_PATH=$(pwd)/data/scf/scf_catalog.json

Stdlib only (no requests/pandas needed). Run:
    python scripts/fetch_scf.py
"""
from __future__ import annotations

import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

REPO = "runyx1325/scf-oscal-catalog-model"
TREE_API = f"https://api.github.com/repos/{REPO}/git/trees/main?recursive=1"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/main/"
OUT = Path(__file__).resolve().parents[1] / "data" / "scf" / "scf_catalog.json"


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "furix-fetch-scf"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def _release_key(path: str) -> tuple:
    # crude version sort on the release folder, e.g. ".../2024.3/..." -> (2024,3)
    import re
    m = re.search(r"/(\d{4})\.(\d+)/", path)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def main() -> int:
    print(f"Listing {REPO} …")
    tree = json.loads(_get(TREE_API))
    candidates = [
        t["path"] for t in tree.get("tree", [])
        if t.get("type") == "blob"
        and t["path"].endswith(".json")
        and "JSON_Data_SCF" in t["path"]
    ]
    if not candidates:
        print("ERROR: no JSON_Data_SCF*.json found in the repo.", file=sys.stderr)
        return 1
    best = sorted(candidates, key=_release_key)[-1]
    print(f"Latest SCF data file: {best}")

    url = RAW_BASE + urllib.parse.quote(best)
    print(f"Downloading … ({url})")
    data = _get(url)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(data)

    # sanity check
    records = json.loads(data)
    print(f"Saved {len(records)} SCF control records → {OUT}")
    print()
    print("Now enable it:")
    print(f"    export SCF_PATH={OUT}")
    print("Verify:")
    print("    python -c \"from furix_mvp import compliance; print(compliance.crosswalk_source())\"")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

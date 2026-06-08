"""Phase 1.1 — load the authoritative Secure Controls Framework (SCF) crosswalk.

Replaces the small hand-typed CIS->NIST / HIPAA tables in compliance.py with the
official SCF crosswalk when an SCF export is provided. The SCF maps 1,400+ controls
across 200+ frameworks; this loader reads the SCF catalog CSV (one row per SCF
control, one column per framework) and builds a deterministic crosswalk keyed on
framework IDs — exactly the Drata/SCF pattern (B6 in FURIX_COMPLIANCE_GUIDE.md).

NO LLM is involved. Loading is a pure CSV parse + dictionary build.

How to get the data (free):
  https://securecontrolsframework.com/free-content/scf-download
  Export the catalog tab to CSV, then set SCF_CSV_PATH (see config.py).

If SCF_CSV_PATH is unset or the file is missing, compliance.py transparently falls
back to its built-in tables — so the engine always works.
"""
from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# Our internal framework keys -> candidate SCF column names (SCF wording varies by
# release, so we accept several). The loader uses the first column that exists.
DEFAULT_COLUMN_MAP: dict[str, list[str]] = {
    "scf_id":     ["SCF #", "SCF#", "SCF Identifier", "scf_id"],
    "scf_name":   ["SCF Control", "Control", "scf_name"],
    "nist_csf":   ["NIST CSF v2.0", "NIST CSF 2.0", "NIST CSF", "nist_csf"],
    "nist_80053": ["NIST 800-53 R5", "NIST 800-53 rev5", "NIST SP 800-53 R5"],
    "cis":        ["CIS CSC v8.1", "CIS CSC v8", "CIS Controls v8.1", "CIS v8.1", "cis"],
    "hipaa":      ["HIPAA", "HIPAA Security Rule", "hipaa"],
    "iso_27001":  ["ISO 27001 v2022", "ISO 27001:2022", "ISO 27002 v2022", "iso_27001"],
    "pci_dss":    ["PCI DSS v4.0", "PCI DSS v4", "PCI DSS", "pci_dss"],
    "soc2":       ["AICPA TSC 2017", "SOC 2", "soc2"],
}
# Optional metadata columns (STRM). Absent in the plain catalog CSV; present if you
# export an SCF STRM bundle. Defaults applied when missing.
STRM_REL_COLS = ["STRM Relationship", "Relationship", "strm_relationship"]
STRM_STR_COLS = ["Strength of Relationship", "Strength Score", "Strength", "strength"]

# Framework keys that hold real external IDs (everything except the SCF id/name).
FRAMEWORK_KEYS = ["nist_csf", "nist_80053", "cis", "hipaa", "iso_27001", "pci_dss", "soc2"]

# Column names in the official SCF "JSON_Data" export (from the SCF OSCAL GitHub
# repo). These headers contain newlines and vary by release, so we list several
# candidates and use the first present. This is the REAL SCF data format.
DEFAULT_JSON_COLUMN_MAP: dict[str, list[str]] = {
    "scf_id":     ["SCF #"],
    "scf_name":   ["SCF Control"],
    "nist_csf":   ["NIST\nCSF\nv2.0", "NIST\nCSF\nv1.1", "NIST CSF v2.0", "NIST CSF v1.1"],
    "nist_80053": ["NIST\n800-53\nrev5", "NIST\n800-53\nrev4"],
    "cis":        ["CIS\nCSC\nv8.1", "CIS\nCSC\nv8.0", "CIS\nCSC\nv8", "CIS CSC v8.1"],
    "hipaa":      ["US\nHIPAA", "HIPAA"],
    "iso_27001":  ["ISO\n27001\nv2022", "ISO\n27001\nv2013"],
    "pci_dss":    ["PCIDSS\nv4.0", "PCIDSS\nv3.2", "PCI DSS v4.0"],
    "soc2":       ["AICPA\nTSC 2017\n(SOC 2)", "AICPA TSC 2017"],
}


def _cis_control_number(value: str) -> str | None:
    """Normalise any CIS id to its control number: 'Control 6' / '6' / '6.8' -> '6'."""
    m = re.search(r"(\d{1,2})", value or "")
    return m.group(1) if m else None


def _split_ids(cell: str) -> list[str]:
    if not cell:
        return []
    parts = re.split(r"[\n;,]+", cell)
    return [p.strip() for p in parts if p.strip()]


@dataclass
class Crosswalk:
    """Deterministic, in-memory SCF crosswalk. Pure lookups, no inference."""
    # scf_id -> {framework_key: [external ids]}
    scf_to_fw: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    # (framework_key, normalized_external_id) -> [scf_ids]
    fw_to_scf: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    # (scf_id) -> {"relationship": str, "strength": int}
    strm: dict[str, dict] = field(default_factory=dict)
    source: str = ""

    # ── public API (mirrors compliance.py helpers) ───────────────────────────
    def frameworks(self) -> list[str]:
        seen: set[str] = set()
        for fwmap in self.scf_to_fw.values():
            seen.update(k for k, v in fwmap.items() if v)
        return sorted(seen)

    def _scf_ids_for_cis(self, control_ids: list[str]) -> list[str]:
        out: list[str] = []
        for c in control_ids:
            num = _cis_control_number(c)
            if num is None:
                continue
            for sid in self.fw_to_scf.get(("cis", num), []):
                if sid not in out:
                    out.append(sid)
        return out

    def expand(self, cis_controls: list[str]) -> dict[str, list[str]]:
        """CIS controls -> every other framework's IDs, via the SCF pivot."""
        result: dict[str, list[str]] = {}
        for sid in self._scf_ids_for_cis(cis_controls):
            for fw, ids in self.scf_to_fw.get(sid, {}).items():
                if fw == "cis":
                    continue
                bucket = result.setdefault(fw, [])
                for i in ids:
                    if i not in bucket:
                        bucket.append(i)
        return {k: sorted(v) for k, v in result.items() if v}

    def for_framework(self, cis_controls: list[str], framework: str) -> list[str]:
        return self.expand(cis_controls).get(framework, [])

    def nist_for_cis(self, cis_controls: list[str]) -> list[str]:
        # prefer CSF; fall back to 800-53 if CSF column absent
        exp = self.expand(cis_controls)
        return exp.get("nist_csf") or exp.get("nist_80053") or []

    def hipaa_for_cis(self, cis_controls: list[str]) -> list[str]:
        return self.expand(cis_controls).get("hipaa", [])


def _as_id_list(val) -> list[str]:
    """Normalise a framework cell (list | str | None) to a clean list of IDs."""
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x).strip() for x in val if str(x).strip()]
    return _split_ids(str(val))


def load(path: str | Path, column_map: dict[str, list[str]] | None = None) -> Crosswalk:
    """Load an SCF crosswalk. Dispatches by extension: .json -> SCF JSON_Data
    export (the real GitHub data), otherwise a catalog CSV. Deterministic."""
    if str(path).lower().endswith(".json"):
        return load_json(path, column_map)
    return load_csv(path, column_map)


def load_json(path: str | Path, column_map: dict[str, list[str]] | None = None) -> Crosswalk:
    """Parse the official SCF 'JSON_Data' export (list of control records) into a
    Crosswalk. This is the real SCF data from the SCF OSCAL GitHub repo."""
    column_map = column_map or DEFAULT_JSON_COLUMN_MAP
    cw = Crosswalk(source=str(path))
    with open(path, encoding="utf-8") as fh:
        records = json.load(fh)
    if not isinstance(records, list):
        raise ValueError(f"Expected a list of SCF records in {path}")

    sample_keys: set[str] = set()
    for r in records[:100]:
        if isinstance(r, dict):
            sample_keys.update(r.keys())

    def pick(cands: list[str]) -> str | None:
        for c in cands:
            if c in sample_keys:
                return c
        return None

    col = {key: pick(cands) for key, cands in column_map.items()}
    scf_col = col.get("scf_id")
    if not scf_col:
        raise ValueError(f"No SCF id column found in {path}")

    for r in records:
        if not isinstance(r, dict):
            continue
        raw_id = r.get(scf_col)
        scf_id = (raw_id[0] if isinstance(raw_id, list) and raw_id else raw_id)
        scf_id = str(scf_id).strip() if scf_id else ""
        if not scf_id:
            continue
        fwmap: dict[str, list[str]] = {}
        for fw in FRAMEWORK_KEYS:
            c = col.get(fw)
            if not c:
                continue
            ids = _as_id_list(r.get(c))
            if not ids:
                continue
            fwmap[fw] = ids
            for ext in ids:
                key = (fw, _cis_control_number(ext) if fw == "cis" else ext)
                cw.fw_to_scf.setdefault(key, [])
                if scf_id not in cw.fw_to_scf[key]:
                    cw.fw_to_scf[key].append(scf_id)
        cw.scf_to_fw[scf_id] = fwmap
    return cw


def load_csv(path: str | Path, column_map: dict[str, list[str]] | None = None) -> Crosswalk:
    """Parse an SCF catalog CSV into a Crosswalk. Deterministic."""
    column_map = column_map or DEFAULT_COLUMN_MAP
    cw = Crosswalk(source=str(path))
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        headers = reader.fieldnames or []

        def pick(cands: list[str]) -> str | None:
            for c in cands:
                if c in headers:
                    return c
            return None

        col = {key: pick(cands) for key, cands in column_map.items()}
        rel_col = pick(STRM_REL_COLS)
        str_col = pick(STRM_STR_COLS)
        scf_col = col.get("scf_id")
        if not scf_col:
            raise ValueError(f"No SCF id column found in {path}; headers={headers}")

        for row in reader:
            scf_id = (row.get(scf_col) or "").strip()
            if not scf_id:
                continue
            fwmap: dict[str, list[str]] = {}
            for fw in FRAMEWORK_KEYS:
                c = col.get(fw)
                if not c:
                    continue
                ids = _split_ids(row.get(c, ""))
                if not ids:
                    continue
                fwmap[fw] = ids
                for ext in ids:
                    key = (fw, _cis_control_number(ext) if fw == "cis" else ext)
                    cw.fw_to_scf.setdefault(key, [])
                    if scf_id not in cw.fw_to_scf[key]:
                        cw.fw_to_scf[key].append(scf_id)
            cw.scf_to_fw[scf_id] = fwmap
            if rel_col or str_col:
                rel = (row.get(rel_col, "") or "intersects_with").strip().lower().replace(" ", "_")
                try:
                    strength = int(float(row.get(str_col, "") or 5))
                except (TypeError, ValueError):
                    strength = 5
                cw.strm[scf_id] = {"relationship": rel, "strength": strength}
    return cw

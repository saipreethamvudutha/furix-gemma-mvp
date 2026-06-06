"""Static compliance knowledge: control catalogs + cross-framework maps.

This is the deterministic grounding layer. It (a) constrains agent prompts to a
closed allowed-value catalog (no hallucinated control IDs) and (b) provides
CIS->NIST and HIPAA->NIST crosswalks used to enrich + validate agent output.
Ported from the furix CIS_NIST_HIPAA reference pipeline.
"""
from __future__ import annotations

# ── CIS Controls v8.1 catalog (id -> canonical title) ────────────────────────
CIS_CONTROLS = {
    "Control 1":  "Inventory and Control of Enterprise Assets",
    "Control 2":  "Inventory and Control of Software Assets",
    "Control 3":  "Data Protection",
    "Control 4":  "Secure Configuration of Enterprise Assets and Software",
    "Control 5":  "Account Management",
    "Control 6":  "Access Control Management",
    "Control 7":  "Continuous Vulnerability Management",
    "Control 8":  "Audit Log Management",
    "Control 9":  "Email and Web Browser Protections",
    "Control 10": "Malware Defenses",
    "Control 11": "Data Recovery",
    "Control 12": "Network Infrastructure Management",
    "Control 13": "Network Monitoring and Defense",
    "Control 14": "Security Awareness and Skills Training",
    "Control 15": "Service Provider Management",
    "Control 16": "Application Software Security",
    "Control 17": "Incident Response Management",
    "Control 18": "Penetration Testing",
}

# ── CIS Controls v8.1 -> NIST CSF 2.0 subcategory crosswalk ──────────────────
CIS_TO_NIST = {
    "Control 1":  ["ID.AM-01", "ID.AM-02", "ID.AM-05", "DE.CM-01"],
    "Control 2":  ["ID.AM-02", "ID.AM-05", "ID.AM-08", "PR.PS-01"],
    "Control 3":  ["PR.DS-01", "PR.DS-02", "PR.DS-11", "PR.DS-10", "GV.PO-01"],
    "Control 4":  ["PR.PS-01", "PR.PS-02", "PR.PS-05", "PR.PS-03"],
    "Control 5":  ["PR.AA-01", "PR.AA-05", "GV.RR-02", "PR.AA-02", "PR.AA-06"],
    "Control 6":  ["PR.AA-01", "PR.AA-03", "PR.AA-05", "PR.AA-04", "PR.IR-01"],
    "Control 7":  ["ID.RA-01", "ID.RA-04", "ID.RA-05", "ID.RA-07", "PR.PS-02"],
    "Control 8":  ["PR.PS-04", "DE.CM-03", "DE.AE-02", "DE.CM-09"],
    "Control 9":  ["PR.PS-05", "DE.CM-09", "PR.AT-01", "DE.CM-01", "PR.PS-06"],
    "Control 10": ["DE.CM-09", "DE.AE-02", "PR.PS-05", "DE.CM-01", "RS.MA-01"],
    "Control 11": ["PR.DS-11", "RC.RP-03", "RC.RP-05", "RC.RP-01", "PR.DS-01"],
    "Control 12": ["PR.IR-01", "PR.AA-05", "DE.CM-01", "PR.IR-02", "GV.SC-07"],
    "Control 13": ["DE.CM-01", "DE.CM-03", "DE.AE-03", "DE.CM-06", "DE.AE-06", "RS.AN-03"],
    "Control 14": ["PR.AT-01", "PR.AT-02", "GV.RR-04", "GV.OC-03"],
    "Control 15": ["GV.SC-04", "GV.SC-07", "GV.SC-09", "GV.SC-06", "GV.SC-01", "ID.RA-08"],
    "Control 16": ["PR.PS-06", "ID.RA-08", "PR.PS-02", "PR.PS-04", "ID.IM-02"],
    "Control 17": ["RS.MA-01", "RS.AN-03", "RC.RP-01", "RS.CO-02", "RS.MI-01", "GV.OV-01"],
    "Control 18": ["ID.RA-01", "ID.IM-02", "DE.AE-02", "ID.RA-05", "ID.IM-01"],
}

# ── HIPAA Security Rule (45 CFR 164) -> NIST CSF 2.0 crosswalk ────────────────
HIPAA_TO_NIST = {
    "164.308a1": ["ID.RA-01", "ID.RA-04", "GV.RM-03"],
    "164.308a3": ["PR.AA-01", "PR.AA-02", "PR.AA-05"],
    "164.308a4": ["PR.AA-03", "PR.AA-06", "PR.IR-01"],
    "164.308a5": ["PR.AT-01", "PR.AT-02", "GV.RR-04"],
    "164.308a6": ["RS.MA-01", "RS.CO-02", "RS.AN-03"],
    "164.308a7": ["RC.RP-01", "RC.RP-03", "PR.DS-11"],
    "164.310a1": ["PR.IR-01", "PR.DS-01"],
    "164.312a1": ["PR.AA-01", "PR.AA-03", "PR.AA-05"],
    "164.312a2": ["PR.AA-02", "PR.AA-04"],
    "164.312b":  ["DE.CM-03", "PR.PS-04", "DE.AE-02"],
    "164.312c1": ["PR.DS-01", "PR.DS-02", "DE.CM-09"],
    "164.312d":  ["PR.AA-01", "PR.AA-03"],
    "164.312e1": ["PR.DS-02", "PR.DS-10"],
    "164.312e2": ["PR.DS-02", "PR.IR-02"],
}

HIPAA_TITLES = {
    "164.308a1": "Security Management Process",
    "164.308a3": "Workforce Security",
    "164.308a4": "Information Access Management",
    "164.308a5": "Security Awareness and Training",
    "164.308a6": "Security Incident Procedures",
    "164.308a7": "Contingency Plan",
    "164.310a1": "Facility Access Controls",
    "164.312a1": "Access Control",
    "164.312a2": "Access Control — Emergency / Encryption",
    "164.312b":  "Audit Controls",
    "164.312c1": "Integrity",
    "164.312d":  "Person or Entity Authentication",
    "164.312e1": "Transmission Security",
    "164.312e2": "Transmission Security — Encryption",
}

# Closed set of NIST CSF 2.0 subcategories agents are allowed to cite.
NIST_ALLOWED = sorted({sc for v in CIS_TO_NIST.values() for sc in v} |
                      {sc for v in HIPAA_TO_NIST.values() for sc in v})

SEVERITIES = ["critical", "high", "medium", "low", "informational"]


def nist_for_controls(control_ids: list[str]) -> list[str]:
    out: list[str] = []
    for c in control_ids:
        for sc in CIS_TO_NIST.get(c, []):
            if sc not in out:
                out.append(sc)
    return out


def validate_controls(control_ids: list[str]) -> list[str]:
    """Drop anything not in the CIS v8.1 catalog (anti-hallucination guard)."""
    return [c for c in control_ids if c in CIS_CONTROLS]


def validate_nist(subcats: list[str]) -> list[str]:
    allowed = set(NIST_ALLOWED)
    return [s for s in subcats if s in allowed]


def validate_hipaa(sections: list[str]) -> list[str]:
    return [s for s in sections if s in HIPAA_TO_NIST]

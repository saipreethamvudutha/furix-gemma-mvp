"""Tests for the SCF crosswalk loader (Phase 1.1).

Proves: (1) the loader parses an SCF-style catalog CSV deterministically,
(2) CIS controls expand to many frameworks via the SCF pivot,
(3) compliance.py uses the SCF when SCF_CSV_PATH is set and falls back cleanly,
(4) the engine never breaks when SCF is absent.

Run:  cd "MVP_TEST GEMMA" && MOCK_LLM=1 RAG_ENABLED=0 .venv/bin/python -m pytest tests/test_scf_loader.py
"""
import os
from pathlib import Path

os.environ.setdefault("MOCK_LLM", "1")
os.environ.setdefault("RAG_ENABLED", "0")

from furix_mvp import scf_loader

FIXTURE = str(Path(__file__).with_name("fixtures") / "scf_sample.csv")


# ── Loader basics ────────────────────────────────────────────────────────────
def test_loader_parses_and_indexes():
    cw = scf_loader.load(FIXTURE)
    # frameworks discovered
    fws = cw.frameworks()
    for expected in ("nist_csf", "cis", "hipaa", "iso_27001", "pci_dss"):
        assert expected in fws, f"{expected} missing from {fws}"


def test_cis_control_normalisation():
    # 'Control 6', '6', '6.8' all collapse to control number '6'
    assert scf_loader._cis_control_number("Control 6") == "6"
    assert scf_loader._cis_control_number("6") == "6"
    assert scf_loader._cis_control_number("6.8") == "6"


# ── Crosswalk expansion ──────────────────────────────────────────────────────
def test_cis_expands_to_many_frameworks():
    cw = scf_loader.load(FIXTURE)
    exp = cw.expand(["Control 6"])          # 6.8 + 6.1 in the fixture
    assert "PR.AA-05" in exp.get("nist_csf", [])
    assert "164.312(a)(2)(i)" in exp.get("hipaa", []) or "164.312(a)(1)" in exp.get("hipaa", [])
    assert exp.get("iso_27001"), "ISO mapping should be present"
    assert exp.get("pci_dss"), "PCI mapping should be present"


def test_nist_and_hipaa_helpers():
    cw = scf_loader.load(FIXTURE)
    assert "PR.DS-01" in cw.nist_for_cis(["Control 3"])
    assert "164.312(c)(1)" in cw.hipaa_for_cis(["Control 3"])


def test_strm_metadata_captured():
    cw = scf_loader.load(FIXTURE)
    assert cw.strm["IAC-20"]["relationship"] == "equal"
    assert cw.strm["IAC-20"]["strength"] == 9


def test_loader_is_deterministic():
    a = scf_loader.load(FIXTURE).expand(["Control 5"])
    b = scf_loader.load(FIXTURE).expand(["Control 5"])
    assert a == b


# ── Integration with compliance.py (provider on/off) ─────────────────────────
def _reset_compliance_cache():
    from furix_mvp import compliance
    compliance._scf_cache["loaded"] = False
    compliance._scf_cache["crosswalk"] = None


def test_compliance_uses_scf_when_configured(monkeypatch=None):
    from furix_mvp import compliance, config
    _reset_compliance_cache()
    old = config.SCF_CSV_PATH
    config.SCF_CSV_PATH = FIXTURE
    try:
        assert compliance.crosswalk_source().startswith("scf:")
        # CIS Control 6 -> NIST via the SCF (not the built-in table)
        assert "PR.AA-05" in compliance.nist_for_controls(["Control 6"])
        # multi-framework expansion now available
        fw = compliance.frameworks_for_controls(["Control 6"])
        assert "iso_27001" in fw and "pci_dss" in fw
    finally:
        config.SCF_CSV_PATH = old
        _reset_compliance_cache()


def test_compliance_falls_back_when_scf_absent():
    from furix_mvp import compliance, config
    _reset_compliance_cache()
    old = config.SCF_CSV_PATH
    config.SCF_CSV_PATH = ""            # no SCF configured
    try:
        assert compliance.crosswalk_source() == "builtin"
        # built-in CIS->NIST table still works
        assert "PR.AA-01" in compliance.nist_for_controls(["Control 5"])
    finally:
        config.SCF_CSV_PATH = old
        _reset_compliance_cache()

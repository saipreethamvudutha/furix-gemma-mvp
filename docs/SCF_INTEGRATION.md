# SCF Crosswalk Integration (Phase 1.1)

This is the highest-value enterprise step: replace the small hand-typed
CIS→NIST/HIPAA tables with the **authoritative Secure Controls Framework (SCF)**
crosswalk — 1,400+ controls across **200+ frameworks**, STRM-typed. It is the same
human-curated, AI-free crosswalk the industry treats as the gold standard.

**No LLM is involved.** Loading is a pure CSV parse + dictionary build, and the
result is deterministic (same input → same mapping).

## How it works

```
   SCF_CSV_PATH set + file present ──► compliance.py uses the SCF crosswalk
   SCF_CSV_PATH unset / missing    ──► compliance.py uses the built-in tables
                                       (engine always works either way)
```

- `furix_mvp/scf_loader.py` — parses an SCF catalog CSV (one row per SCF control,
  one column per framework) into a deterministic `Crosswalk`.
- `furix_mvp/compliance.py` — `nist_for_controls`, `hipaa_for_controls`, and the new
  `frameworks_for_controls` transparently use the SCF when configured.
- `furix_mvp/mapping.py` — the resolver now returns a `frameworks` block spanning
  every SCF framework (NIST CSF/800-53, HIPAA, ISO 27001, PCI-DSS, SOC 2, …).

## Drop-in steps

1. Download the SCF (free): https://securecontrolsframework.com/free-content/scf-download
2. Open the workbook, export the **catalog tab** to CSV (keep the header row).
   The loader auto-detects common SCF column names (NIST CSF, CIS, HIPAA, ISO,
   PCI, SOC 2). Adjust `DEFAULT_COLUMN_MAP` in `scf_loader.py` if your release
   uses different headers.
3. Point the engine at it:
   ```bash
   export SCF_CSV_PATH=/path/to/scf_catalog.csv
   ```
4. Verify:
   ```bash
   python -c "from furix_mvp import compliance; print(compliance.crosswalk_source())"
   # -> scf:/path/to/scf_catalog.csv   (vs 'builtin' when unset)
   ```

## What you get

One matched CIS control now expands to **every mapped framework** in one
deterministic lookup. Example (from the bundled test fixture):

```
   Control 6  ─►  nist_csf:  PR.AA-05
                  hipaa:     164.312(a)(1), 164.312(a)(2)(i)
                  iso_27001: A.8.2, A.8.3
                  pci_dss:   7.1, 7.2
```

## Tested

`tests/test_scf_loader.py` (8 tests): parsing, CIS-id normalisation
(`Control 6`/`6`/`6.8` → `6`), multi-framework expansion, STRM metadata capture,
determinism, and that compliance.py uses the SCF when configured and falls back
cleanly when not. The bundled fixture is `tests/fixtures/scf_sample.csv`.

## Notes & next steps

- **STRM fidelity:** the plain catalog CSV gives the mappings; full per-mapping STRM
  relationship + strength lives in the SCF's separate STRM bundles. The loader
  captures relationship/strength if those columns are present (the fixture
  includes them), defaulting to `intersects_with` / 5 otherwise.
- **Granularity:** the loader keys CIS at the control number (5, 6, …). To go
  safeguard-level (5.1, 5.2), extend the normaliser and the engine's rule outputs
  (roadmap Phase 2.2).
- **Versioning:** pin the SCF release you exported; re-export on SCF updates
  (roadmap Phase 3.4).

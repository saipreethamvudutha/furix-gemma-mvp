# SIEM port — Anomaly-detection engine → `furix_mvp/siem/`

Porting the campaign-correlation SIEM anomaly engine from the **Anomaly-detection**
repo into this appliance as a self-contained subsystem, one module at a time. End
goal: a lighter-than-production dashboard serving both **SIEM** and **SCAN**, with
data-upload buttons, live backend-processing visibility, and analysis display.

## Source engine (what we're porting)

Two non-shared spines:

- **Offline training:** `generators/baseline_generator.py` (~810K benign logs) →
  `main.py train` → fits `FeatureEngine` + `EnsembleDetector` (IsolationForest 0.60
  + ECOD 0.40), writes model pickles → `ueba_profiler.py` builds UEBA profiles.
- **Runtime (7 steps):** raw log → **(1)** ECS normalise (`layer1_ecs_reader` →
  `raw_to_ecs`/`jsonl_to_ecs`) → **(2)** three detector lanes (signature `rule_engine`,
  `ueba_scorer`, ML `layer2_features`→`layer3_detector`) aggregated into detection
  bundles → **(3)** `anomaly_store` flattens to analyst JSON → **(4)** `risk_accumulator`
  (per-entity dual-window decay + strong-rule anchor) → incident candidates → **(5)**
  `multistage_correlator` → attack narratives → **(6)** `dal_scrubber` role-typed PII
  placeholders → **(7)** `llm_router` → final incident report. `validate_report.py`
  scores the report against `generators/ground_truth_<DATE>.json`.

## Decisions (locked)

| Decision | Choice |
|---|---|
| ML/UEBA in v1 | **Full port** — bring `scikit-learn`/`pyod`/`scipy`; offline training required before those lanes score. |
| Data model | Keep the engine's `ECS → bundle → candidate → narrative` shapes **intact** inside `furix_mvp/siem/`; do **not** force them into furix's flat `finding` (lossy). |
| LLM provider | Re-point the engine's OpenRouter router at the in-house **Gemma** via `furix_mvp/llm.py` (`config.GEMMA_BASE_URL`; default `http://localhost:11434/v1`, `gemma4:e4b`). |
| DAL | **Two DALs** for now: furix `dal.py` for per-event findings; ported `dal_scrubber` for narratives. Scoped + documented; consolidate in a later pass. |
| Compliance | **Re-enrich** the final campaign report with furix's deterministic CIS/NIST/HIPAA mapping (`mapping.resolve`) — furix's differentiator, cheap. |
| Generators | Keep the engine's Faker generators as **dev-only** tooling (coupled to `validate_report.py` for an end-to-end correctness check); evaluate LogForge later. |
| Run model | **Background job** + step-progress events (not synchronous) so the dashboard can show live backend processing. |

## Rewire gotchas (caught in analysis — don't trip on these)

1. **Gemma re-point** uses `config.GEMMA_BASE_URL` — never hardcode an IP. The
   OpenRouter API-key gate exists in **two** places in `llm_router.py`
   (`_build_headers` *and* `process_campaigns`); both must go. Pass `max_tokens≈3000`
   to `complete_json` or campaign reports truncate (furix default is 1600).
2. **DAL disk-write is the IPC channel.** `dal_scrubber` writes
   `pii_mapping_<id>.json` and `llm_router.process_campaigns` **re-reads it from
   disk** (`load_mappings(dir)`). Moving to an in-memory token map is **not** a
   scrubber-local change — it forces a coupled rewrite of the router to receive the
   `mappings` dict directly. Land scrubber + router together (Module 5).
3. **Aggregator load() is eager + unguarded.** `DetectionAggregator.load()` calls
   `ueba.load()` and `ml_detector.load()`, which **raise** `FileNotFoundError` on
   missing pickles. Until models are trained, the aggregator must guard these or it
   crashes at load (net-new code, not free).
4. **Tenant de-hardcoding.** "Coventra" specifics (PHI bucket IPs, exec usernames,
   vault IP `10.30.6.10`, peer-group username rules, `BULK_ROW_THRESHOLD`, etc.) are
   baked through `raw_to_ecs`, `rule_engine`, `dal_scrubber`, UEBA. Externalize to
   config during each module's port or it only works for that one fake tenant.
5. **Import hygiene.** Source uses `sys.path` hacks + bare `from config import …` /
   `from ueba_profiler import …` (repo root). Every ported module gets package-
   relative imports; root `config.py` became `furix_mvp/siem/config.py` (namespaced).
6. **Build ordering.** Detector *code* lands before training, but the ML/UEBA lanes
   can't be exercised end-to-end until the offline train run produces the pickles.

## Module sequence & status

| # | Module | Target | Status |
|---|---|---|---|
| 1 | `siem/` scaffold + config + rules data + MITRE table | `furix_mvp/siem/{config.py,rules/,data/}` | ✅ done |
| 2 | ECS ingestion (layer1 + raw/jsonl_to_ecs) | `furix_mvp/siem/ingest/` | ✅ done |
| 3 | Rule engine + severity engine | `furix_mvp/siem/detect/` | ✅ done |
| 4 | Risk accumulator + multistage correlator | `furix_mvp/siem/correlate/` | ✅ done |
| 5 | DAL scrubber + LLM router (→ Gemma) | `furix_mvp/siem/{scrub,report}/` | ✅ done |
| 6 | UEBA (profiler + scorer) | `furix_mvp/siem/ueba/` | ✅ done |
| 7 | ML detection (features + ensemble) | `furix_mvp/siem/ml/` | ✅ done |
| 8 | Detection aggregator + anomaly store | `furix_mvp/siem/detect/` | ✅ done |
| 9 | Orchestrator + jobs + API/dashboard + **training CLI** | `furix_mvp/siem/{pipeline,jobs,samples,baseline,train}.py` + API + dashboard | ✅ done |

> Sequence note: detector lanes (rules/UEBA/ML) and the aggregator that fans them
> together are interleaved — the aggregator (Module 8) needs all three lanes present
> (ML guarded). Generators + `validate_report` come in alongside Module 9 for the
> end-to-end correctness check and to train the ML/UEBA artifacts.

## Module 1 — what landed

- `furix_mvp/siem/` package scaffold (`__init__.py`).
- `furix_mvp/siem/config.py`: ported constants **verbatim** (fusion weights,
  severity thresholds, session windows, port-risk tiers, RFC-1918 prefixes); paths
  repointed into the subpackage; `SIEM_*` env overrides with working defaults.
- `furix_mvp/siem/rules/`: 11 rule-data files copied verbatim.
- `furix_mvp/siem/data/mitre_techniques.json`: MITRE technique table (473 KB).
- `furix_mvp/siem/{models,models/ueba,logs}/`: dirs scaffolded (artifacts written
  at train time).
- `requirements-siem.txt`: isolated ML deps (kept out of the light core
  `requirements.txt`).

Verified: `from furix_mvp.siem import config` imports with no external deps; all 12
data paths and 4 dirs resolve.

## Module 2 — what landed

- `furix_mvp/siem/ingest/`: Layer-1 ECS ingestion, copied **verbatim** from the
  source (`layer1_ecs_reader.py`, `raw_to_ecs.py`, `jsonl_to_ecs.py`) with only:
  - `layer1_ecs_reader.py`: `sys.path` hack + bare imports → package-relative
    (`from .jsonl_to_ecs import …`, `from .raw_to_ecs import …`).
  - `raw_to_ecs.py`: the five Coventra tenant literals (`ORG_NAME`, PHI buckets,
    exec-role prefixes, PAM vault IP + name) replaced with imports from the new
    tenant profile; stale docstring usage path corrected.
  - `jsonl_to_ecs.py`: unchanged (clean, pure-stdlib).
- `furix_mvp/siem/tenant.py`: **new** central tenant profile — the org-specific
  assets the engine keys on, each overridable via `SIEM_TENANT_*` env vars,
  defaults preserved verbatim. Grown further in Modules 3 & 5 (rule-engine assets,
  DAL classification constants).
- `tests/siem/test_ingest.py`: end-to-end smoke test (runs under bare `python3` or
  pytest).

Ingestion is **pure stdlib** — no ML deps — so it runs inside furix's light core.
Auto-detects already-ECS / structured-Coventra-JSONL / raw-vendor and emits ECS
8.11 dicts. Raw vendor formats: Palo Alto NGFW, CrowdStrike, Imperva DAM, Okta,
CyberArk PAM, AWS CloudTrail, Nginx (+WAF), Proofpoint.

Verified: `ensure_ecs → load_events` round-trips all three dispatch paths;
Proofpoint BEC escalates + flags exec-targeting via the externalised prefixes;
CloudTrail PHI-bucket access escalates via the externalised bucket set; tenant
constants confirmed externalised with Coventra defaults intact. All 4 cases pass.

> Carried-forward note (latent, faithful to source): `parse_cyberark` assumes the
> **current year** for syslog timestamps that omit it (`datetime.now().year`) — a
> real CEF-syslog limitation, not tenant-specific. Left as-is; revisit if ingesting
> historical CyberArk logs across a year boundary.

## Module 3 — what landed

- `furix_mvp/siem/detect/`: the **signature lane** + severity classifier.
  - `rule_engine.py` (verbatim except imports + org assets): 34 rules loaded from
    `siem/rules/rules.json`, evaluated against ECS events → a `risk_event` with
    MITRE context, score, confidence. **Pure stdlib** — runs in furix's light core.
    This is the strong-rule anchor the risk accumulator (Module 4) gates on.
  - `severity_engine.py` (verbatim except imports): Layer-4 severity classification
    + structured/Rich report. Needs `numpy`; its `FEATURE_NAMES` import from the ML
    module (Module 7) is **defensive** — degrades to `[]` until that lands. Kept out
    of the `detect/` eager path so the rule lane stays numpy-free.
- `furix_mvp/siem/tenant.py`: extended with the rule-engine org assets — `PHI_DB_IPS`,
  `WS_SUBNET_PREFIX`, `AUDIT_REPOS`, `HSM_APPROVED_ACTOR`, `PHI_TABLES`,
  `BULK_ROW_THRESHOLD`, `BEC_DOMAIN_PATTERNS` (all env-overridable; defaults verbatim).
  `PHI_S3_BUCKETS` now reuses Module-2's `PHI_BUCKETS` (deduped). Generic constants
  (`PHI_DB_PORTS`, `C2_TLDS`) stayed local in `rule_engine` — they're vendor-neutral,
  not tenant assets.
- `tests/siem/test_detect.py`: drives the engine over Module-2-ingested ECS.

Verified (7 cases): engine loads all 34 rules with **no skips** (validates the full
`CUSTOM_HANDLERS` wiring); CloudTrail PHI-bulk-S3 → `bulk_s3_phi_access`, Proofpoint
BEC → `bec_phishing`, bulk SELECT on a PHI table → `bulk_phi_query`, benign nginx 200
→ no rules; severity `classify`/`build_results` bucket + sort correctly; org assets
confirmed externalised with Coventra defaults intact. `diff` vs source = imports +
org-asset block only.

> Source-doc fix: the engine's own header said "33 rules" but `rules.json` has **34**
> enabled — corrected in the ported docstring.

## Module 4 — what landed

- `furix_mvp/siem/correlate/`: the campaign-correlation core — the new engine's
  biggest differentiator over furix's per-event model. Both files copied
  **verbatim** except the noted import changes.
  - `risk_accumulator.py` (Block 2): per-entity risk ledger over dual sliding
    windows (60 min / 24 h) with exponential decay; turns detection_bundles into
    `incident_candidate`s. **Pure stdlib** (`dateutil` is a lazy fallback). Only
    change: removed the `sys.path` hack (+ unused `os`/`sys`). The **strong-rule
    anchor** (`STRONG_RULE_SCORE_FLOOR=25`, MEDIUM-cap when no real rule hit)
    ported byte-for-byte — it's the correctness keystone.
  - `multistage_correlator.py` (Block 3): graph + union-find clustering of
    incident_candidates into `attack_narrative`s with kill-chain timeline, IOCs,
    and a pre-built `llm_context`. Changes: removed `sys.path` hack; made the
    `assign_peer_group` import (from UEBA, Module 6) **defensive** — fallback
    returns a unique-per-entity group so the reinforcement-only temporal_proximity
    edge simply doesn't fire until UEBA lands (never mis-fires).
- `tests/siem/test_correlate.py`: 5-case end-to-end test.

Both run in furix's light core (stdlib only). `MIN_LLM_CONFIDENCE=0.70` gates
which narratives a caller routes to the LLM report stage (Module 5) — the verifier
flagged this constant is duplicated in the LLM router; reconcile there.

Verified (5 cases): a strong-rule entity escalates HIGH→CRITICAL and emits;
**12 UEBA-only bundles reaching raw score 120 are capped at MEDIUM with no
emission** (the strong-rule anchor — the single most important property); two
asset-linked entities cluster into one CRITICAL 4-stage campaign with a populated
`llm_context` (`investigator`/`anomaly_explainer` agent targets); empty input →
`([], [])`; the peer-group fallback is active. `diff` vs source = the two import
changes only.

## Module 5 — what landed (Gemma enters here)

- `furix_mvp/siem/scrub/dal_scrubber.py` (Block 4): PII scrub → role-typed
  placeholders, and re-identify after the LLM. Verbatim except: removed `sys.path`
  hack; externalised the org-identifying classification constants to the tenant
  profile (`ORG_DOMAIN`, `EXEC_USER_PREFIXES`, `SVC_ACCOUNT_PREFIX`,
  `ATTACKER_DOMAIN_LOOKALIKES`, `PHI_NAME_FRAGMENTS`); generic medical/security
  fragments stay local. Pure stdlib; Presidio NER optional. **`scrub()` already
  returns mappings in-memory** — disk `pii_mapping_*.json` is now audit-only.
- `furix_mvp/siem/report/llm_router.py` (Block 5): **re-pointed from OpenRouter to
  the in-house Gemma.** The OpenRouter call surface (`_build_headers`/`_call_api`/
  `_call_with_retry`) is replaced by `_call_gemma()` → `furix_mvp.llm.complete_json`
  (model/endpoint/temperature from furix config; `MAX_TOKENS=3000` so reports don't
  truncate; `MOCK_LLM` honoured). **Both** OpenRouter API-key gates removed; the
  `_load_dotenv`, `requests`, and OpenRouter constants deleted; the now-redundant
  `_parse_response` dropped (furix's `complete_json` parses). All prompt-building,
  re-identification, and report-assembly logic is **unchanged**.
- **DAL decoupling:** `process_campaigns(..., *, mappings=None)` now takes the
  scrubber's in-memory mappings dict directly (the decoupled IPC the verifier
  flagged); disk `load_mappings` remains a fallback only. `MIN_LLM_CONFIDENCE` is
  imported from the correlator (single source of truth — reconciles the duplicate).
- Defensive forward import: `RULE_DESCRIPTION`/`RULE_TACTIC_OVERRIDE`/
  `load_anomaly_store` from the anomaly store (Module 8) degrade gracefully until
  it lands (empty tables, empty rule-hit set).
- `tests/siem/test_report.py`: 3-case test (run with `MOCK_LLM=1`).

Verified (3 cases, `MOCK_LLM=1`): scrub→reidentify round-trips with no raw-PII
leak; the full scrub→report path produces a complete report whose
`processing.llm_model == gemma4:e4b` and `api_endpoint == GEMMA_BASE_URL` (proving
the re-point — **no OpenRouter**), runs with **no `OPENROUTER_API_KEY`**, consumes
**in-memory mappings** (no disk), and re-identifies placeholders inside the LLM's
own response; classification keys on the externalised tenant assets.

> Live-Gemma note: fully verified offline via `MOCK_LLM`. With `MOCK_LLM=0` the same
> path hits the real `gemma4:e4b` (`GEMMA_BASE_URL`) — run on a box that can reach
> it to confirm live. Local dev needs furix's core deps (`openai`, `python-dotenv`)
> installed for the report module to import.

## Module 6 — what landed (first ML-stack module)

- `furix_mvp/siem/ueba/`: behavioural analytics. **Needs `numpy` + `scipy`** and a
  trained `ueba_profiles.pkl` (built offline before scoring).
  - `ueba_profiler.py` (offline build): per-user KDE profiles (three-tier
    individual→peer→global; svc accounts get a zero-tolerance min/max envelope).
    Changes: removed `sys.path` hack; config imports → package-relative (module +
    `__main__`, now run via `python -m …`); **`PEER_GROUP_RULES` + service-account
    prefix externalised to the tenant profile** (they encode org usernames incl.
    named accounts). Owns `assign_peer_group` and the canonical `_extract_dimensions`.
  - `ueba_scorer.py` (runtime): loads profiles, scores live ECS events into the
    `risk_event` shape the rule engine emits (`detector="ueba"`). Changes: removed
    `sys.path` hack; config import → relative; **de-duplicated** — `_get` /
    `_extract_dimensions` are now **imported from the profiler** instead of carrying
    byte-identical copies (the source's own comment said they "must stay in sync";
    sharing one object makes drift impossible — directly resolves the flagged risk).
- **Seam closed:** the correlator's defensive `assign_peer_group` import (Module 4)
  now resolves to the real UEBA function; Module 4's test was updated from
  "fallback active" to "real grouping wired". The fallback still protects light-core
  use if `scipy` is absent.
- `user_distribution.py` deliberately **not ported** (dev-only, hardcoded Windows path).
- `tests/siem/test_ueba.py`: 5-case test.

Verified (5 cases): an in-envelope service-account event is quiet; an
out-of-envelope one fires a UEBA `risk_event` (score 47, driver `query_row_count`,
MITRE T1213/stage 11 — correct rule-engine-compatible shape); `_extract_dimensions`
/`_get` are the **same object** in profiler and scorer; peer-group rules come from
the tenant profile; the correlator seam resolves to the real function. All 5 SIEM
test modules stay green.

## Module 7 — what landed (third detector lane; last seam closed)

- `furix_mvp/siem/ml/`: the ML lane. **Needs `numpy` + `scikit-learn` + `pyod`**
  and trained model pickles. Both files verbatim except `sys.path` removal +
  config/`src` imports → package-relative; **no tenant assets here**.
  - `layer2_features.py`: `FeatureEngine` → 16-feature vector per ECS event
    (`FEATURE_NAMES`). numpy-only, so kept eager in `ml/__init__` — the severity
    engine imports `FEATURE_NAMES` from here. Stateful (session deques + running
    action counts), so feature values are call-order-dependent.
  - `layer3_detector.py`: `EnsembleDetector` — IsolationForest (0.60) + ECOD (0.40)
    → 0-100 percentile score. Pulls sklearn (eager) + pyod (lazy at fit/load), so
    **not** imported by `ml/__init__`; import it explicitly. `load()` **raises** on
    missing pickles — kept verbatim; Module 8's aggregator must guard it.
- **Seam closed:** the severity engine's defensive `FEATURE_NAMES` import (Module 3)
  now resolves to the real 16-name list. All three forward seams are now closed
  (correlator↔UEBA, severity↔ML, report↔anomaly-store remains until Module 8).
- `tests/siem/test_ml.py`: 4-case test. Redirects `SIEM_MODELS_DIR` to a temp dir
  so `fit()` never writes pickles into the repo.

Verified (4 cases): `FeatureEngine` → `(100, 16)` matrix; the ensemble trains and
scores a stark anomaly at **99.4 vs baseline mean 50.5**; `EnsembleDetector.load()`
**raises `FileNotFoundError`** when untrained (the behaviour the aggregator guards);
the severity-engine `FEATURE_NAMES` seam is the real list. IForest uses a fixed
`random_state`, so the result is deterministic. All 6 SIEM test modules green.

> Reminder: the ML and UEBA lanes only produce signal once the offline training
> step (Module 9) builds the pickles from baseline logs.

## Module 8 — what landed (lanes unified; final seam closed)

- `furix_mvp/siem/detect/anomaly_store.py`: copied **byte-identical** (pure stdlib,
  no imports to fix). Carries the `RULE_DESCRIPTION` / `RULE_TACTIC_OVERRIDE` tables,
  `extract_anomalies`, `save_anomaly_store`, `load_anomaly_store`.
- `furix_mvp/siem/detect/detection_aggregator.py`: the choke point that fans each
  ECS event through all three lanes (rules · UEBA · ML) into a `detection_bundle`
  (the risk accumulator's input). Changes: `sys.path`/`config`/`src` imports →
  package-relative, **plus the one piece of genuinely new code** — `load()` now
  **guards** the UEBA + ML loads in try/except (nulling the detector on failure) so
  the aggregator degrades to the rule lane when those pickles aren't trained yet,
  instead of crashing. Added `active_lanes()` for visibility. The existing per-lane
  runners already tolerate a `None` detector, so the guard is all that was needed.
- `detect/__init__` now exposes `anomaly_store` + its tables eagerly (stdlib);
  `DetectionAggregator` (full ML stack) stays an explicit import.
- **Final forward seam closed:** the report stage's defensive `anomaly_store` import
  (Module 5) now resolves to the real tables/loader. **All forward seams are now
  closed.**
- `tests/siem/test_aggregate.py`: 6-case integration test.

Verified (6 cases): the aggregator loads **rule-only without crashing** when
untrained (`active_lanes()==["signature_rules"]`, ML/UEBA nulled); real ECS events
fan into bundles carrying `bulk_s3_phi_access`; benign traffic yields no bundle;
`anomaly_store` round-trips with `RULE_DESCRIPTION` text + `RULE_TACTIC_OVERRIDE`
correction (`bulk_s3_phi_access`→Collection/stage 11); the report seam resolves real;
and a **full pipeline runs end-to-end — 3 ECS events → aggregator → accumulator →
correlator → 1 CRITICAL campaign**. All 7 SIEM test modules green.

### Deterministic pipeline complete

Modules 1–8 give a working SIEM engine on the rules-only path with **zero training
required**: raw log → ECS → 3 detector lanes (rules live; UEBA/ML guarded-off until
trained) → detection bundles → risk accumulator → correlator → scrub → **Gemma
incident report**, with compliance re-enrichment still to wire. Module 9 adds the
orchestrator that chains these as one call, the offline training CLI (to light up
the UEBA + ML lanes), and the upload/processing/results dashboard.

## Module 9 — what landed (orchestrator + live dashboard)

- `furix_mvp/siem/pipeline.py` — `analyze_logs(text, *, progress, …)` chains the
  whole engine (ingest → aggregate → accumulate → correlate → scrub → Gemma
  report) and emits structured per-step progress (the `STEPS` list the dashboard
  renders). Returns campaigns + re-identified reports + stats. Handles empty input.
- `furix_mvp/siem/jobs.py` — in-memory, threaded `JobManager`: each submission runs
  the pipeline on a daemon thread and records live per-step status. `summary()` (jobs
  list) vs `detail()` (full result). Most-recent-N retained; nothing persisted.
- `furix_mvp/siem/samples.py` — a curated correlated sample (one attacker IP →
  impossible-travel / bulk-PHI-DB / bulk-PHI-S3 across three identities) → one
  CRITICAL multi-entity campaign for the "Load sample" action.
- `furix_mvp/api.py` — new routes (no new deps; the file is read client-side and
  POSTed as JSON): `POST /api/siem/analyze` (→ job_id), `GET /api/siem/jobs`,
  `GET /api/siem/jobs/{id}`, `GET /api/siem/sample`. `/` now serves the dashboard;
  `/legacy` keeps the original analyzer.
- `static/dashboard.html` — sidebar console (Overview · SIEM · Scan/Compliance
  "soon"), drag-drop / sample upload, a **live step tracker** (polling), and a neat
  incident-report renderer (exec summary · risk · timeline · IOCs · remediation ·
  key evidence · detected anomalies). Single static page, vanilla JS — light.
- `report/llm_router.py` — `process_campaigns(..., min_confidence=…)` so the
  dashboard reports top campaigns regardless of the default 0.70 gate.
- `tests/siem/test_pipeline.py` — orchestrator + job-manager test (4 cases).

Verified: all 8 SIEM test modules pass; every HTTP route works via TestClient
(submit → poll → done, 6/6 steps, 1 campaign, 1 report); and a **live browser run**
of the real app confirmed the dashboard renders the sidebar, the live step tracker,
and a full re-identified CRITICAL incident report (real rule hits: `impossible_travel`,
`vendor_direct_phi`, `bulk_s3_phi_access`). Reports were MOCK_LLM; detection /
correlation / scrub were all real.

### Training — all three lanes now light up

- `furix_mvp/siem/baseline.py` — lightweight synthetic **benign** generator (~840
  ECS events across the peer groups; includes the demo identities so UEBA baselines
  them). Not the source's 810K Coventra corpus — enough to fit meaningful models.
  Real baseline logs go in via the CLI's `--logs`.
- `furix_mvp/siem/train.py` — `train_models()` does the source's `AnomalyPipeline.train`
  sequence (FeatureEngine.fit → extract → `EnsembleDetector.fit` writing scaler/iso/
  ecod/calibration) **and** `ueba_profiler.run` (→ `ueba_profiles.pkl`). CLI:
  `python -m furix_mvp.siem.train [--logs PATH] [--synthetic N]`. `models_status()`
  reports which lanes are trained.
- `api.py` — `POST /api/siem/train` (background) + `GET /api/siem/status`. Dashboard
  gains a **"Detector lanes"** card with a one-click "Train baseline models" button;
  lanes flip green when trained.
- `.gitignore` — trained `*.pkl` excluded (built locally, not committed).
- `tests/siem/test_train.py` — 3 cases.

Verified (test + live browser): before training `active_lanes == [signature_rules]`;
after training the aggregator activates **all three** (`signature_rules, ueba,
ml_ensemble`) and on the attack sample **all three fire** — the IsolationForest+ECOD
ensemble scores the attack events as outliers at **96.7–100** (capped to MEDIUM in
the bundle), UEBA fires (non-US login + off-hours), rules fire. The dashboard's
"Train baseline models" button flipped UEBA + ML to "trained" and a subsequent run
showed `lanes: signature_rules, ueba, ml_ensemble`.

### SIEM port COMPLETE

The SIEM half is fully end-to-end: train the lanes (or run rules-only) → upload logs
→ watch the pipeline live → read the Gemma incident report, all on furix's in-house
engine with all three detector lanes. **Remaining (optional / future):**
- **Compliance re-enrichment** — attach furix's CIS/NIST/HIPAA mapping to reports.
- **SCAN / Compliance** sidebar flows — a second engine port (different repo).
- Real baseline corpus (LogForge / Tenable) instead of the synthetic one for
  production-grade ML/UEBA accuracy.

> Known carry-over (verbatim from source, not introduced here): the UEBA `high_tail`
> dimensions score `1 - CDF(value)`, which under-weights extreme-high values — the
> ML ensemble and UEBA presence/both-tails dims still flag those, so detection holds,
> but worth revisiting if tuning UEBA later.

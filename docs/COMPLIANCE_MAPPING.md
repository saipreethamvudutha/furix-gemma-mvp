# How Furix does compliance mapping with code, not an LLM

This document explains, in plain terms, how the MVP maps security events to
compliance controls (CIS, NIST CSF, HIPAA) using **deterministic code**, and why
the local Gemma LLM is now only a last-resort fallback for genuinely novel events.

It answers the client's question directly: *"can you do compliance mapping with
code instead of an LLM?"* — yes, and here is exactly how.

---

## The one-sentence version

For every event we resolve the mapping through a **waterfall of deterministic
tiers** (keyword rules → crosswalk tables → embedding similarity); the LLM is
called **only** when all of them fail, and even then its answer is a reviewable
suggestion, never the system of record.

---

## What "deterministic" means here

**Deterministic = same input always gives the same output, every time.** That is
the property auditors and clients need: a mapping you can re-run and reproduce,
and explain line-by-line. An LLM is *not* deterministic (it can vary, and it can
hallucinate a control that does not apply), which is why it cannot be the
authority for compliance.

Everything in Tiers 1–3 below is deterministic. We proved it with a repeatability
test (`tests/test_mapping.py::test_mapping_is_repeatable`): the same event run
five times returns byte-identical control, NIST, and HIPAA lists.

---

## The four tiers

```
event ─▶ Tier 2 RULES ─┐
                       ├─▶ Tier 1 CROSSWALK ─▶ controls + NIST + HIPAA  (authoritative)
        Tier 3 EMBED ──┘
                       │
                       └─(nothing matched)─▶ Tier 4 LLM  (suggestion, needs review)
```

### Tier 1 — Crosswalk tables (the backbone). No ML at all.
A crosswalk is a table humans/standards bodies filled in once: "this control maps
to that requirement." We expand any matched CIS control to its NIST CSF
subcategories and HIPAA sections by pure dictionary lookup.

- Code: `furix_mvp/compliance.py` — `CIS_TO_NIST`, `HIPAA_TO_NIST`,
  `nist_for_controls()`, `hipaa_for_controls()`.
- HIPAA is derived deterministically through the NIST pivot: a HIPAA section
  relates to a control when their NIST subcategory sets overlap (the NIST IR 8477
  "intersects with" relationship). Pure set math.
- This is the same kind of artifact the Secure Controls Framework ships — and the
  SCF explicitly forbids AI/NLP in building it, for accuracy and legal
  defensibility. (See `~/Downloads/FURIX-COMPLIANCE-MAPPING-REPORT.md`.)

### Tier 2 — Deterministic rules (the primary matcher). No ML.
Keyword/signature regexes: "log contains `CreateUser` / `4720` / `add member` →
Control 5 (Account Management)." Plain if/then logic.

- Code: `furix_mvp/containers/c6_normaliser.py` — the `KW` map. C6 now exposes
  `rule_controls` (genuine matches; empty when nothing fired) alongside the legacy
  `candidate_controls`.
- This is the workhorse. In practice the large majority of real events are mapped
  here.

### Tier 3 — Embedding similarity (the smart fallback). ML, but NOT an LLM.
SecureBERT turns text into vectors (lists of numbers capturing meaning). To map an
event the keyword rules missed, we find the closest known controls by cosine
similarity, gated by a relevance floor so weak matches are ignored.

- Code: `furix_mvp/rag.py` (`retrieve()`), consumed by `furix_mvp/mapping.py`.
- This is **not generative** and **does not hallucinate** — it is a search/ranking
  step. For a fixed index it is deterministic.
- Requires `RAG_ENABLED=1` and the pgvector index populated. When off, Tiers 1–2
  still cover events fully.

### Tier 4 — LLM fallback (Gemma). Only for the unknown. Never authoritative.
Reached only when Tiers 2–3 produce nothing — a truly novel event. Gemma drafts a
*candidate* mapping; we re-validate it against the closed control catalog, expand
it through the Tier-1 crosswalk, and flag it `needs_review` + non-authoritative. A
human confirms before it counts.

- Code: `furix_mvp/agents.py::run_compliance_mapper` (the only compliance LLM
  call), invoked conditionally by `furix_mvp/brain.py`.
- Toggle: `COMPLIANCE_LLM_FALLBACK=0` turns even this off, so unmapped events are
  simply flagged for review with zero LLM usage.

---

## The resolver

`furix_mvp/mapping.py::resolve(finding, ground)` runs Tiers 1–3 and returns:

| field | meaning |
|---|---|
| `control_ids` | authoritative CIS controls (validated against the catalog) |
| `nist_subcategories` / `hipaa_sections` | Tier-1 crosswalk expansion |
| `primary_tier` | which tier decided it (`deterministic_rules`, `embedding_similarity`, `llm_fallback`, or `None`) |
| `tiers_used` | every tier that contributed |
| `provenance` | `{control_id: [tiers that found it]}` |
| `confidence` | 0.0–1.0 (rules 0.90, rules+embed 0.95, embed-only 0.70, none 0.0) |
| `needs_llm` | `True` only when nothing matched |
| `authoritative` | `True` when the mapping stands without the LLM |

`merge_llm_suggestion(det, llm_output)` folds a Gemma suggestion into the unknown
case — validated and crosswalk-expanded, then marked `needs_review`.

---

## Where the LLM sits in `brain.analyze()`

1. C6 normalises the raw log deterministically (`rule_controls`, signals).
2. RAG grounding (Tier 3) if enabled.
3. **`mapping.resolve()` runs first** — the deterministic mapping.
4. If it mapped the event (`needs_llm=False`), the `compliance_mapper` Gemma agent
   is **removed from the agent list and never called**. That is the load saving.
5. Only for the unknown case (and only if `COMPLIANCE_LLM_FALLBACK=1`) does Gemma
   run, as a reviewable suggestion.
6. The verdict's `control_ids` / `nist_subcategories` / `hipaa_sections` come from
   the resolved mapping — never from a raw LLM output.

Every response now carries a `compliance` block showing `primary_tier`,
`tiers_used`, per-control `provenance`, `confidence`, `authoritative`,
`needs_review`, and `llm_used` — so the mapping is fully explainable.

---

## Proof (what we ran)

```
$ MOCK_LLM=1 RAG_ENABLED=0 python -m pytest tests/test_mapping.py   # 7/7 pass
```

Live behavior:

| Event | primary_tier | llm_used | authoritative |
|---|---|---|---|
| IAM `AttachUserPolicy` AdministratorAccess | `deterministic_rules` | False | True |
| SSH `Failed password ... invalid user` | `deterministic_rules` | False | True |
| Keyword-free novel text, fallback ON | `llm_fallback` | True | False (needs_review) |
| Keyword-free novel text, fallback OFF | none | False | False (needs_review, no controls) |

For known events the `compliance_mapper` Gemma call does not run at all.

---

## Config knobs

| env var | default | effect |
|---|---|---|
| `COMPLIANCE_LLM_FALLBACK` | `1` | `0` = never call the LLM for mapping; unmapped → review |
| `RAG_ENABLED` | `0` | `1` = enable Tier-3 embedding similarity |
| `MAPPING_EMBED_FLOOR` | `0.30` | cosine floor for accepting an embedding-tier control |
| `MOCK_LLM` | `0` | `1` = no real Gemma calls (offline dev/test) |

---

## Measuring & improving accuracy (the eval loop)

Mapping accuracy is the quality of three assets: the rules, the crosswalk tables,
and the embedding index. Don't tune them blind — measure.

`tests/eval/` is a labeled benchmark + scorer:

```
cd "MVP_TEST GEMMA"
MOCK_LLM=1 RAG_ENABLED=0 .venv/bin/python tests/eval/run_eval.py        # rules + crosswalk
MOCK_LLM=1 RAG_ENABLED=1 .venv/bin/python tests/eval/run_eval.py --rag  # + embeddings
```

- `gold_set.jsonl` — atomic events with hand-labeled correct controls (extend it).
- `run_eval.py` — reports micro precision/recall/F1, a per-control table, the
  benign false-positive rate, **per-tier attribution** (which tier is the noise
  source), and the worst FP/FN events to fix next. Writes `last_report.json` so
  you can track trends across tuning passes.

This loop found and fixed the real accuracy bug: bare-substring keyword matching.
`rce` matched "souRCE"/"eventSouRCE"; `c2` matched "eC2.amazonaws"; `s3`/`bucket`
fired Control 3 on every S3 call. Word-boundary anchoring (`\b...\b`) + adding the
6 missing controls + tightening over-broad tokens took the benchmark from:

| pass | precision | recall | F1 | benign FP |
|---|---|---|---|---|
| baseline (substring keywords) | 0.60 | 0.75 | 0.67 | 2/4 |
| pass 1 (word boundaries + missing controls) | 0.81 | 0.85 | 0.83 | 2/4 |
| pass 2 (tighten Control 15, add mfa/conditional-access) | 0.95 | 1.00 | 0.97 | 0/4 |
| pass 3 (fix IDS/IPS token) | 0.97 | 1.00 | 0.99 | 0/4 |

The one remaining false positive (a DNS query to `malware-c2.ru` also tagged
Control 10 Malware Defenses) is defensible, not a bug.

**Rule of thumb:** when accuracy is poor, run the eval, read the per-tier
attribution and worst-FP/FN lists, fix the specific rule or table entry, re-run.
Never revert to the LLM to "fix accuracy" — improve the deterministic asset.

## How to make it even stronger (next steps)

1. Replace the hand-typed `CIS_TO_NIST` / `HIPAA_TO_NIST` tables with the official
   **SCF crosswalk** (OSCAL JSON / CSV) — see
   `~/Downloads/furix-deterministic/scf_crosswalk.py`. This swaps our small tables
   for the authoritative, versioned, human-curated standard.
2. Add **policy-as-code (OPA/Rego)** for cloud-config findings — see
   `~/Downloads/furix-deterministic/cloud_compliance.rego`.
3. Carry the **STRM relationship type + strength** on each crosswalk edge so the UI
   can show "fully covers" vs "partially intersects."

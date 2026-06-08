# Furix Compliance Mapping — The Complete Guide

### The single source of truth: why we built it this way, what it is, and how it works — in plain words and in technical depth.

> This document supersedes and combines the earlier notes. Companion deep-dives:
> `ACCURACY_TUNING.md`, `ENTERPRISE_ROADMAP.md`. Industry research with full
> citations is summarised here in Part B.

---

# PART A — WHY (the rationale)

## A1. The problem, in plain words

Security teams must obey **rulebooks** called *compliance frameworks* — CIS, NIST
CSF, NIST 800-53, HIPAA, ISO 27001, PCI-DSS. They all describe similar safety
goals, but each uses **different IDs and wording** for the same idea:

```
   "look after who holds the keys"  is called…
        CIS    → Control 5 / 6        NIST CSF → PR.AA-01
        HIPAA  → 164.312(a)           ISO 27001 → A.9
```

When something happens on a system (e.g. *a new admin account was created*), the
job is to answer: **which rules, in which rulebooks, does this touch?** That is
**compliance mapping**. Furix automates it.

## A2. Why not just ask an LLM? (with the evidence)

**In plain words:** an LLM (ChatGPT, our local Gemma) is a brilliant storyteller.
But it (a) can give a *different answer each time* and (b) sometimes *makes things
up*. For homework, fine. For audited security and law, not fine.

**Technically — and this is the crux — the published accuracy backs this up:**

- The leading academic study on **LLMs for regulatory/legal compliance mapping**
  reports **GPT-4 reaching ~81%** accuracy (paragraph-level) and only **~41%** at
  sentence-level; smaller/older models land at **30–41%**. The authors stress that
  human oversight remains *indispensable* and warn about hallucination and bias.
  [arxiv 2404.14356]
- A fine-tuned **BERT baseline** on the same task scored **~67% F-score**.
  [arxiv 2404.14356]
- By contrast, a **crosswalk table lookup is exact by construction** — if the table
  says CIS 5 ↔ NIST PR.AA-01, that is *always* the answer, provably.

So even **state-of-the-art LLMs cap out around 80%** on this kind of mapping and
*need a human to check them*. A small, locally-deployed model (our Gemma) would do
worse. A lookup table is 100% repeatable. **That gap is the entire reason we built
a deterministic, code-first engine and demoted the LLM to a checked fallback.**

```
   ACCURACY REALITY (how well each method maps controls)

   Crosswalk table (SCF/OSCAL)      ████████████████████ exact, by construction
   SCAP/OVAL config checks          ████████████████████ exact pass/fail
   Keyword / Sigma rules            ███████████████████░ very high (Furix 0.97-0.99 F1*)
   Embedding similarity (Siamese)   ██████████████████░░ ~90%+
   GRC hybrid (Drata, reviewed)     ██████████████████░░ ~93% first-pass, human-checked
   LLM GPT-4 (regulatory mapping)   ████████████████░░░░ ~81%, NOT deterministic, needs human
   LLM small/sentence-level         ████████░░░░░░░░░░░░ 30-41%
   * on our 30-event benchmark — see Part D for the honest caveat
```

## A3. The principle: deterministic

**Deterministic = same input, same output, every time** — and you can *prove* it.
A vending machine, not a storyteller. This is what auditors and regulators require,
and (as Part B shows) it is what the entire security industry actually uses.

> **ML and NLP are not banned.** The thing we avoid is the *generative,
> story-telling* LLM in the authoritative path. Deterministic ML (embeddings,
> classifiers) and NLP (keyword/regex rules) are welcome.

---

# PART B — HOW THE INDUSTRY GIANTS ACTUALLY DO IT

This is the detailed answer to "what techniques are they following, and how
accurate / state-of-the-art is it?" There are **two separate jobs**, and neither
uses a generative LLM as the authority.

```
   JOB 1: CONFIG-STATE CHECKING            JOB 2: CONTROL CROSSWALK MAPPING
   "Is the control actually implemented?"  "Which framework rules does this touch?"
   → SCAP / OVAL / XCCDF / OPA              → OSCAL catalogs + SCF/STRM crosswalk
   produces PASS/FAIL findings              produces control coverage
```

## B1. Technique — SCAP / OVAL / XCCDF  (Tenable, Qualys, Rapid7)

The **Security Content Automation Protocol** is the deterministic backbone of
configuration/compliance scanning.

- **XCCDF** — an XML checklist/benchmark language for automated compliance testing
  and scoring. [NIST CSRC]
- **OVAL** — a declarative language for logical assertions about system state;
  "a test links an object and a state, and passes when the resource satisfies the
  state." It is the default checking engine XCCDF rules bind to. [open-scap.org]
- **How Qualys does it:** an *Inference-Based Scanning Engine* runs OVAL via the
  *OVAL Definition Interpreter*, then evaluates results against *XCCDF rules* to
  produce a TestResult. [Qualys SCAP guide]
- **How Tenable does it:** Nessus consumes SCAP DataStreams (OVAL + XCCDF + CVE +
  CPE + CVSS) and exports XCCDF results. [Tenable docs]

**Accuracy: exact.** A check either passes or fails against a precisely defined
state. No model, no guessing.

## B2. Technique — NIST OSCAL  (the machine-readable backbone; FedRAMP)

**OSCAL** represents control catalogs and assessments in machine-readable
XML/JSON/YAML, with a **deterministic profile-resolution algorithm**
(Import → Merge → Modify) that gives "repeatable results regardless of the tool."
[pages.nist.gov/OSCAL]

- Layers: Catalog → Profile → Implementation → Assessment → **Assessment Results**
  → POA&M. End-to-end machine-readable.
- **State of the art / direction of travel:** FedRAMP **RFC-0024 (Jan 2026)**
  mandates machine-readable OSCAL authorization packages for *all* providers, with
  deadlines in 2026–2027. (Adoption is still early — FedRAMP reported ~0 OSCAL
  submissions across 100+ Rev5 authorizations in 2025 — but it is the mandated
  future.) [ignyteplatform, continuumgrc]
- Reference tools (`oscal-cli`, IBM `compliance-trestle`) are **pure code**.

**Accuracy: exact** (deterministic resolution).

## B3. Technique — Secure Controls Framework + STRM  (the crosswalk)

The **SCF** is the human-curated crosswalk: **1,400+ controls across 200+
frameworks**, shipped as Excel/CSV/OSCAL JSON.

- It uses **NIST IR 8477 STRM** (Set Theory Relationship Mapping): five
  relationship types (subset / intersects / equal / superset / no-relationship)
  plus a strength score.
- Crucially, the SCF **explicitly forbids AI/NLP** in producing its mappings,
  contrasting "Expert-Derived Content" with competitors' NLP, and noting
  "AI-generated content is not copyright-protectable." [securecontrolsframework.com]

**Accuracy: human-expert authored, exact on lookup.** This is the gold standard for
control-to-control crosswalks.

## B4. Technique — Sigma + MITRE ATT&CK  (detection-as-code)

For mapping *events* (not config), the industry uses **Sigma** — a vendor-agnostic
YAML detection-rule format. Each rule carries detection logic **plus a MITRE
ATT&CK technique tag**, and compiles to Splunk/Sentinel/Elastic/CrowdStrike
queries. [picussecurity, graylog]

- This is **detection-as-code**: rules are versioned data, not buried regex.
- Recent research even does **deterministic synthesis** — mapping each finding to a
  starter Sigma rule via a template library with an ATT&CK back-reference.
  [arxiv 2606.05252]
- ATT&CK techniques then crosswalk to controls (e.g. via the MITRE
  ATT&CK→NIST 800-53 mappings).

**Why it matters for Furix:** this is the maintainable, standardised upgrade path
from our hand-written keyword regex (see roadmap Part E).

## B5. Technique — Embeddings / semantic similarity  (non-generative ML)

When exact keywords miss, the industry uses **embeddings**: text → vectors, then
cosine similarity to the closest known control. This is **machine learning but not
generative** — it ranks, it does not invent, and it is deterministic for a fixed
index.

- Reported accuracy: **Siamese-network embeddings exceed ~90%**, about **+15% over
  traditional methods**; practical similarity thresholds run 75–90%.
  [Springer; medRxiv ICD-10 mapping]

## B6. What the GRC platforms (Drata, Vanta, Secureframe) actually do

This is the most directly comparable case to Furix — and it validates our design.

- **Drata's own engineering writeup** describes a **hybrid**: semantic **embeddings**
  (Snowflake `AI_EMBED`) **+ keyword TF-IDF** matching, with an LLM used **only to
  generate human-readable explanations** of the recommendation. Reported **"average
  first-pass accuracy 93%+"**, single control in <5 s, 500+ controls in <5 min — and
  the explanations exist precisely so **compliance teams validate the
  recommendations**. [drata.com/blog]
- Across **Drata, Vanta, and Secureframe, none use AI at the evidence-classification
  / control-determination layer** — AI is applied to *document and questionnaire
  generation*, not to deciding whether a configuration satisfies a control.
  [sprinto comparison]

**Translation:** the leading compliance-automation vendors map controls with
**embeddings + keyword matching + human review**, and keep the generative LLM for
*explanations and paperwork only.* That is exactly the Furix architecture.

## B7. Why we follow this approach (the synthesis)

```
   Deterministic methods (rules, crosswalk, OVAL, embeddings):
     ✔ exact or ~90%+ accurate    ✔ same answer every time
     ✔ auditable & provable        ✔ legally defensible (SCF/STRM)
     ✔ what NIST, Tenable, Qualys, Drata, Vanta actually use

   Generative LLM as the authority:
     ✘ ~81% best case (GPT-4), 30-41% small models
     ✘ different answer each time  ✘ hallucinates, inherits bias
     ✘ not provable to an auditor  ✘ used by NO major vendor for the system of record
```

We follow the deterministic, code-first approach because it is **more accurate,
repeatable, auditable, defensible, and industry-standard** — and we keep a small
local LLM only where the industry keeps it: as a *reviewed assistant* for novel
cases and explanations, never as the system of record.

---

# PART C — WHAT FURIX BUILT (the engine)

## C1. Big picture

Furix is a 15-container streaming appliance. Compliance mapping lives in the
**C6 normaliser** (sorting room) and the **C14 AI Brain** (decision desk).

```
   raw log ─► [C2 receive] ─► [C6 normalise] ─┬─► store
                                              ├─► detections
                                              └─► [C14 AI Brain] ─► verdict
```

## C2. The 4-tier waterfall — and which industry technique each tier implements

We try cheap, exact tiers first; the LLM is the last resort.

```
   ┌──────────────────────────────────────────────────────────────────────┐
   │ TIER 2  KEYWORD / SIGNATURE RULES   ← like Sigma rules (B4)            │
   │   "sees CreateUser / 4720 / add member → Control 5"                    │
   ├──────────────────────────────────────────────────────────────────────┤
   │ TIER 1  CROSSWALK TABLE             ← like SCF/STRM + OSCAL (B2,B3)    │
   │   "Control 5 → NIST PR.AA-01 + HIPAA 164.312(a)"                       │
   ├──────────────────────────────────────────────────────────────────────┤
   │ TIER 3  EMBEDDING SIMILARITY        ← like Drata's semantic match (B5,B6)│
   │   SecureBERT vectors, cosine similarity, floor-gated                  │
   ├──────────────────────────────────────────────────────────────────────┤
   │ TIER 4  LLM FALLBACK (Gemma)        ← like Drata's LLM-explanations    │
   │   ONLY for novel-and-risky events; suggestion, human-reviewed         │
   └──────────────────────────────────────────────────────────────────────┘
```

Every tier maps 1:1 to a real industry technique. Furix is a small, faithful
implementation of the same pattern Tenable/SCF/Drata use.

## C3. Code map

```
   furix_mvp/containers/c6_normaliser.py   Tier 2 rules + behavioural signals
   furix_mvp/compliance.py                 Tier 1 crosswalk tables + validators
   furix_mvp/rag.py                         Tier 3 embeddings (SecureBERT + rerank)
   furix_mvp/mapping.py                     the waterfall resolver (decides tiers)
   furix_mvp/brain.py                       orchestration; calls Tier 4 only if stuck
   furix_mvp/agents.py                      Gemma agents (fallback only)
```

---

# PART D — HOW WE MADE IT ACCURATE (testing & tuning)

## D1. The report card

We hand-labeled **30 atomic events** (the "answer key", `tests/eval/gold_set.jsonl`)
including 4 benign events whose correct answer is "no controls." `run_eval.py`
grades the engine and reports:

- **Precision** = of controls predicted, how many were right (low = false positives)
- **Recall** = of controls that should be found, how many were (low = misses)
- **F1** = combined score; plus the **benign false-alarm rate** and **per-tier blame**.

## D2. The accuracy journey: 0.67 → 0.99

The benchmark pinpointed a real bug: **substring keyword matching**. `rce` matched
inside "sou**rce**", `c2` inside "e**c2**.amazonaws", `s3`/`bucket` on every storage
call. Plus 6 controls had **no rules at all**.

```
   F1   0.67 ███████████████░░░░░  start (substring bugs, 6 empty controls)
        0.83 ███████████████████░  whole-word matching + fill empty controls
        0.97 ███████████████████████ tighten greedy rules + add mfa/conditional-access
        0.99 ████████████████████████ fix the "IDs:" token
```

| Try | Change | Precision | Recall | F1 | Benign FP |
|---|---|---|---|---|---|
| start | substring keywords | 0.60 | 0.75 | 0.67 | 2/4 |
| #1 | word boundaries + missing controls | 0.81 | 0.85 | 0.83 | 2/4 |
| #2 | tighten Control 15 + add signals | 0.95 | 1.00 | 0.97 | 0/4 |
| #3 | fix IDS/IPS token | 0.97 | 1.00 | 0.99 | 0/4 |

## D3. The end-to-end check (the most important test)

Testing the resolver alone wasn't enough. Running the **whole real pipeline**
(`brain.analyze`) revealed two more bugs the resolver-only test missed:

1. **Benign events were waking the LLM** ("just in case") — wasteful and noisy.
   Fix: only escalate when there's a *real risk signal*; benign → "no control", no LLM.
2. **The same substring bug in the signals list** (`c2` in "ec2"). Fix: word
   boundaries there too.

```
   Real-pipeline result   before fix:  25/30 correct,  5 needless LLM calls
                          after fix:   29/30 correct,  0 LLM calls
```

The 1 remaining "miss" is a defensible judgment call, not a bug.

## D4. What is tested

- **8 unit tests** (`tests/test_mapping.py`) incl. a determinism test (same event ×5
  → identical mapping) and benign-suppression.
- **The benchmark** (`tests/eval/run_eval.py`), runnable against the resolver *or*
  the real pipeline (`--pipeline`), with an LLM-call counter so regressions can't
  hide.

## D5. The honest caveat

F1 0.99 is on **30 events we wrote, labeled, and tuned against.** That measures the
engine against its own answer key — it is *not* a generalization guarantee. Real
accuracy on unseen production logs is unknown and will be lower. Fixing this (a
large held-out benchmark) is Phase 1 of the roadmap.

---

# PART E — MATURITY & THE PATH TO STATE-OF-THE-ART

## E1. Where we are

```
   L1 Prototype   L2 MVP ◄WE ARE HERE   L3 Production   L4 Enterprise   L5 SOTA
```

A well-architected MVP with a working accuracy loop. The architecture is sound; the
remaining work is **additive, not a rewrite.**

## E2. The honest gaps

```
   🔴 coverage      18 controls / 3 frameworks → SCF 200+ frameworks, safeguard-level
   🔴 detections    hand regex → standardised Sigma / MITRE ATT&CK / OVAL
   🔴 config-state  none → SCAP/OVAL + OPA ("is the control implemented?")
   🔴 benchmark     30 self-labeled → 500+ held-out, independently labeled
   🔴 evidence      none → attestation, POA&M, continuous monitoring, OSCAL results
   🔴 scale         single node → load-tested (incl. the Gemma stress test)
```

## E3. Roadmap (each item has a "done when" bar — see ENTERPRISE_ROADMAP.md)

```
   Phase 1  CREDIBILITY   real SCF/OSCAL crosswalk + held-out benchmark
   Phase 2  COVERAGE      Sigma/ATT&CK detections, safeguard-level, config-state checks
   Phase 3  OPERATIONS    Gemma load test, scale/SLOs, evidence + attestation
   Phase 4  SOTA          OSCAL-native end-to-end, continuous compliance, self-improving
```

## E4. Definition of done — enterprise grade

```
   [ ] SCF crosswalk ingested (200+ frameworks, safeguard-level, STRM-typed)
   [ ] OSCAL catalogs + profile resolution; OSCAL assessment-results output
   [ ] Detections standardised (Sigma / ATT&CK / OVAL), rules-as-data
   [ ] Config-state checking (OPA + OVAL)
   [ ] Held-out benchmark (500+), independent labels, CI accuracy gate
   [ ] Evidence + point-in-time attestation + POA&M + continuous monitoring
   [ ] Gemma load test passed; scale/SLOs; multi-tenancy + RBAC
   [ ] SOC 2 / ISO 27001 for the product itself
```

## E5. Whose playbook are we following — and the exact steps to match each

Furix's job is **mapping events/findings to controls across frameworks**. That is
the GRC/crosswalk problem (Drata, SCF) — *not* the scanner problem (Tenable,
Qualys). So we follow different giants for different parts:

```
   OUR CORE JOB (event → controls)         →  follow  SCF + OSCAL  (data)
                                              and     Drata        (pipeline)
   DETECTION CONTENT (what fires a rule)    →  follow  Sigma + ATT&CK
   CONFIG-STATE ("is the control ON?")      →  follow  Tenable / Qualys (SCAP/OVAL)
```

Concrete steps to reach each giant's level:

### To reach DRATA level (closest to what we do — our priority)
```
   1. Replace hand-typed crosswalk with SCF OSCAL JSON (200+ frameworks).
   2. Keep SecureBERT embeddings (Tier 3); calibrate the floor on a held-out set.
   3. Add LLM-generated, READ-ONLY explanations per mapping (Drata's exact pattern).
   4. Add a human-review queue for low-confidence / novel mappings.
   5. Measure first-pass accuracy on a held-out benchmark → target their 93%+.
   We already have tiers 2/3/4 in this shape; steps 1, 3, 5 close the gap.
```

### To reach TENABLE / QUALYS level (the config-state half we lack)
```
   1. Adopt OpenSCAP/OVAL for host config checks; OPA/Rego for cloud
      (cloud_compliance.rego is the seed).
   2. Ingest SCAP DataStreams (XCCDF + OVAL) for CIS Benchmarks / DISA STIGs.
   3. Emit pass/fail/NA per rule + an XCCDF-style compliance scorecard.
   4. Key each finding (CCE / rule-id) to SCF/OSCAL control IDs → feeds Tier 1.
   This adds the "is the control actually implemented?" capability we don't have.
```

### To reach OSCAL / FedRAMP level (state-of-the-art, mandated 2026–27)
```
   1. Represent catalogs in OSCAL; implement deterministic profile resolution.
   2. Emit OSCAL Assessment Results + POA&M from the engine.
   3. This is exactly what FedRAMP RFC-0024 will require.
```

### To reach SIGMA / MITRE ATT&CK level (maintainable detections)
```
   1. Replace bespoke keyword regex with Sigma rules (YAML, versioned, testable).
   2. Tag each rule with a MITRE ATT&CK technique.
   3. Crosswalk ATT&CK techniques → NIST 800-53 (published mapping) → feeds Tier 1.
```

**Bottom line on "who we follow":** for our core mapping job we are already on the
**SCF + Drata** playbook and match its architecture; the work is to load their
*content* (SCF/OSCAL) and prove their *accuracy* (held-out benchmark). We adopt
**Tenable/Qualys (SCAP/OVAL)** only to add config-state checking, and **OSCAL** to
become the machine-readable, FedRAMP-ready standard.

---

# PART F — REFERENCE

## F1. Glossary (plain words)

- **Compliance framework** — a security rulebook (CIS, NIST, HIPAA…).
- **Control** — one rule in a rulebook.
- **Crosswalk** — a dictionary translating one rulebook's rule to another's.
- **Deterministic** — same input → same output, every time; provable.
- **LLM** — a generative AI; clever but non-repeatable and can hallucinate.
- **Embedding** — text turned into numbers so similarity can be measured (non-generative ML).
- **SCAP/OVAL/XCCDF** — the standard, deterministic config-checking stack.
- **OSCAL** — NIST's machine-readable format for catalogs and assessments.
- **STRM** — NIST IR 8477's five-relationship crosswalk method (used by the SCF).
- **Sigma** — vendor-neutral YAML detection rules, tagged with MITRE ATT&CK.
- **Precision / Recall / F1** — accuracy scores for the mapping.

## F2. Sources (verified)

Standards & primary:
- NIST OSCAL — catalog, profile resolution: https://pages.nist.gov/OSCAL/learn/concepts/processing/profile-resolution/
- NIST CSRC — XCCDF: https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/xccdf
- OpenSCAP — SCAP components (OVAL/XCCDF): https://www.open-scap.org/features/scap-components/
- NIST IR 8477 — STRM: https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8477.pdf
- SCF — STRM & download (Excel/CSV/OSCAL): https://securecontrolsframework.com/set-theory-relationship-mapping-strm/
- Tenable Nessus — SCAP settings: https://docs.tenable.com/nessus/Content/SCAPSettings.htm
- Qualys — SCAP getting-started (Inference-Based Engine, OVAL Interpreter, XCCDF): https://cdn2.qualys.com/docs/qualys-scap-getting-started-guide.pdf

How the giants / GRC vendors / SOTA:
- Drata engineering — automated control mapping (hybrid embeddings+TF-IDF, LLM for explanations, 93%+): https://drata.com/blog/building-automated-compliance-control-mapping
- Sprinto — Drata/Vanta/Secureframe comparison (AI not used at evidence-classification layer): https://sprinto.com/blog/secureframe-vs-vanta-vs-drata/
- Sigma + MITRE ATT&CK detection engineering: https://graylog.org/post/tdir-mitre-attck-and-sigma-rules-2/
- Deterministic detection-as-code synthesis: https://arxiv.org/html/2606.05252
- OSCAL & FedRAMP automation (RFC-0024 mandate): https://www.ignyteplatform.com/blog/fedramp/oscal-and-fedramp-automation/

Accuracy of LLM / ML compliance mapping:
- LLMs for legal/regulatory compliance (GPT-4 ~81%, BERT ~67%, human oversight needed): https://arxiv.org/html/2404.14356
- Semantic mapping of regulatory guidelines to processes (Siamese embeddings >90%): https://link.springer.com/article/10.1007/s11761-016-0197-2

---

## One-paragraph summary

Furix maps security events to compliance controls with a deterministic, code-first
waterfall — keyword/signature rules, crosswalk-table lookups, and non-generative
embedding similarity — keeping a local LLM only as a non-authoritative,
human-reviewed fallback for novel cases. This mirrors exactly how the industry
works: Tenable/Qualys use SCAP/OVAL/XCCDF, NIST/FedRAMP use OSCAL, the SCF uses the
human-curated STRM crosswalk (AI explicitly forbidden), and even leading GRC
vendors like Drata map controls with embeddings+keyword matching and human review,
reserving the LLM for explanations. We chose this because the published accuracy is
decisive: deterministic crosswalk lookups are exact and provable, embedding methods
exceed ~90%, while state-of-the-art LLM regulatory mapping caps near 81% (and far
lower for small models) and still requires human oversight. A 30-event benchmark
took our engine from F1 0.67 to 0.99 by fixing brittle substring matching; the
honest next step is a large held-out benchmark and the roadmap to enterprise grade.

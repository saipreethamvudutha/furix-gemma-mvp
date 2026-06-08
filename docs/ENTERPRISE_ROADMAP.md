# Furix Compliance Engine — Maturity Assessment & Path to Enterprise Grade

### An honest, detailed roadmap from "working MVP" to "state-of-the-art, top-notch, enterprise-grade."

---

## 1. Executive verdict

The Furix compliance mapping engine today is a **well-architected MVP**: it proves a
deterministic, code-first mapping approach works, it has a measurable accuracy
loop, and it keeps the LLM off the authoritative path. That is the right
foundation and a genuinely good story.

It is **not yet enterprise-grade or state-of-the-art.** The architecture is sound,
so the work ahead is mostly **additive, not a rewrite** — but it is substantial.

```
   Maturity ladder (where we are, where we're going)

   L1  Prototype        ░░░░░  idea in a notebook
   L2  MVP              █████  ◄── WE ARE HERE: works, measured, small scope
   L3  Production-ready ░░░░░  real coverage, held-out eval, scale-tested
   L4  Enterprise-grade ░░░░░  config-state, evidence, attestation, multi-tenant
   L5  State-of-the-art ░░░░░  OSCAL-native, continuous compliance, self-improving
```

This document explains exactly what separates each rung and what to build to climb
it.

---

## 2. Maturity scorecard (detailed)

🟢 = strong  ·  🟠 = partial  ·  🔴 = gap

| # | Dimension | Now | Target (enterprise / SOTA) |
|---|---|---|---|
| 1 | Architecture & approach | 🟢 | deterministic waterfall, LLM as fallback — keep |
| 2 | Provenance & explainability | 🟢 | per-tier provenance exists; add auditor-grade reports |
| 3 | Accuracy eval loop | 🟠 | 30 self-labeled events → 1000s, **held-out**, independently labeled |
| 4 | Framework coverage | 🔴 | 3 frameworks, control-level → **200+ frameworks, safeguard-level** (SCF) |
| 5 | Crosswalk fidelity | 🔴 | NIST set-intersection heuristic → **STRM** types + strength |
| 6 | Detection content | 🔴 | ~18 hand regexes → standardized **Sigma / MITRE ATT&CK / OVAL** |
| 7 | Config-state compliance | 🔴 | none → **SCAP/OVAL + OPA/Rego** ("is the control implemented?") |
| 8 | Versioning & drift | 🔴 | none → pin + diff framework revisions; multi-version support |
| 9 | Embedding tier | 🟠 | present but unmeasured → calibrated, index lifecycle, eval'd |
| 10 | Multi-event correlation | 🔴 | per-event only → attack-chain / incident reasoning (Control 17) |
| 11 | Scale & throughput | 🔴 | single in-process node → load-tested, horizontal, the **Gemma stress test** |
| 12 | Evidence & attestation | 🔴 | none → continuous control monitoring, point-in-time reports, POA&M |
| 13 | Multi-tenancy & RBAC | 🔴 | none → tenant isolation, roles, SSO |
| 14 | Product security & certs | 🟠 | DAL redaction exists → SOC 2 / ISO 27001 for the product itself |

Six 🔴 gaps stand between MVP and enterprise grade. None require throwing away what
exists.

---

## 3. The four honest risks (name them before a client does)

```
   RISK 1  OVERFITTING
   F1 0.99 is on 30 events we wrote AND labeled AND tuned against.
   That measures the engine against its own answer key — not the real world.
   → Real accuracy on unseen production logs is unknown and will be lower.

   RISK 2  REGEX IS BRITTLE & UNSCALABLE
   The "rce inside source" bug proves it. Keyword rules can't cover the real
   signal space, attackers can evade them, and hand-maintaining thousands
   doesn't scale. The industry uses standardized content (Sigma, OVAL).

   RISK 3  TINY HAND-TYPED CROSSWALK
   18 controls, 3 frameworks, control-level. Enterprises map 1,400+ controls
   across 200+ frameworks at safeguard granularity, with relationship semantics.

   RISK 4  ONLY HALF OF COMPLIANCE
   We map log EVENTS to controls. We do NOT yet check config STATE
   ("is MFA actually enforced?"). Real compliance needs both.
```

---

## 4. What "state-of-the-art" looks like (target architecture)

```
            ┌──────────────────────────────────────────────────────────────┐
            │                  TARGET: OSCAL-NATIVE ENGINE                    │
            └──────────────────────────────────────────────────────────────┘

  INPUTS                         DETERMINISTIC CORE                    OUTPUTS
  ──────                         ──────────────────                    ───────
  log events ─┐                 ┌───────────────────────┐            control
  cloud cfg ──┤  ┌──────────┐   │ Tier 2  detections     │            coverage +
  host cfg  ──┼─►│ normalise│──►│  (Sigma/ATT&CK, OVAL)  │──┐         STRM-typed
  IaC/API   ──┘  │  + DAL    │   │ Tier 3  embeddings     │  │         crosswalk
                 └──────────┘   └───────────────────────┘  │              │
                                          │                 ▼              ▼
                 ┌───────────────────────────────────┐  ┌─────────────────────┐
                 │ Tier 1  CROSSWALK GRAPH            │  │ Evidence + Attest.  │
                 │  SCF (200+ frameworks, OSCAL)      │─►│  pass/fail/partial   │
                 │  STRM relationships + strength     │  │  point-in-time report│
                 │  versioned, multi-revision         │  │  POA&M, audit log    │
                 └───────────────────────────────────┘  └─────────────────────┘
                                          ▲                       ▲
                 ┌───────────────────────────────────┐           │
                 │ Tier 4  LLM (fallback, reviewed)   │  Human-in-the-loop
                 │  proposes → human approves → feeds │  curation feeds approved
                 │  back into deterministic content   │  mappings BACK into Tier 1/2
                 └───────────────────────────────────┘

   Continuous (not point-in-time) · machine-readable end to end · self-improving
```

The three ideas that make it state-of-the-art:
1. **OSCAL-native end to end** — catalog → profile → assessment results → POA&M, all
   machine-readable (the NIST standard the whole industry is moving to).
2. **Continuous compliance** — always-on monitoring of both events and config state,
   not a once-a-year audit snapshot.
3. **Self-improving content** — the LLM proposes new rules/mappings offline, humans
   approve, and the *deterministic* content gets better over time (the runtime stays
   deterministic).

---

## 5. The roadmap — 4 phases with concrete deliverables

Each item lists **what to build** and the **"done when"** acceptance bar.

### Phase 1 — Credibility (L2 → L3)
*Goal: make the accuracy number and the mappings trustworthy.*

```
   1.1  Replace hand-typed tables with the real SCF crosswalk
        Build: ingest SCF OSCAL JSON / CSV (scf_crosswalk.py) into Postgres;
               carry STRM relationship type + strength on every edge.
        Done when: mappings cover 200+ frameworks at safeguard level and every
               edge has a relationship type sourced from the SCF.

   1.2  Build a HELD-OUT benchmark
        Build: 200-500 labeled events, labeled by 2+ people (measure agreement
               with Cohen's kappa), split into tune / held-out / never-touched.
        Done when: accuracy is reported ONLY on the held-out split, with
               confidence intervals; tuning never sees it.

   1.3  Per-tier + per-framework accuracy dashboards
        Done when: run_eval reports precision/recall/F1 per framework and per tier,
               on every commit (CI gate blocks regressions).
```

### Phase 2 — Coverage & robustness (L3)
*Goal: cover the real signal space with maintainable, standard content.*

```
   2.1  Adopt standardized detection content
        Build: map events via Sigma rules + MITRE ATT&CK techniques instead of
               bespoke regex; keep rules as versioned data, not code.
        Done when: detections are Sigma/ATT&CK-backed, independently testable,
               and hot-reloadable without a code change.

   2.2  Safeguard-level granularity
        Done when: mapping resolves to CIS 5.1 / 5.2 (not just "Control 5") and
               NIST 800-53 control enhancements.

   2.3  Config-state compliance (the missing half)
        Build: OPA/Rego for cloud config (cloud_compliance.rego is the seed),
               OVAL/OpenSCAP for host config.
        Done when: the engine answers "is this control IMPLEMENTED?" with
               pass/fail/partial + evidence, not just "did an event occur?"

   2.4  Adversarial & fuzz testing
        Done when: evasion attempts (obfuscation, encoding, padding) and random
               fuzz inputs are part of CI; brittleness like the substring bug is
               caught automatically.
```

### Phase 3 — Operations (L3 → L4)
*Goal: run it for real, at scale, with proof.*

```
   3.1  The Gemma load test (the MVP's original reason to exist)
        Done when: measured throughput/latency with the LLM as a rare fallback;
               documented max events/sec the local Gemma can sustain.

   3.2  Scale & resilience
        Done when: horizontal scale, backpressure, and failure modes are tested;
               SLOs defined (latency, availability).

   3.3  Evidence, attestation & continuous monitoring
        Build: immutable audit log, point-in-time control-satisfaction reports,
               POA&M (plan of action & milestones) generation, OSCAL assessment
               results output.
        Done when: an auditor can pull a signed, point-in-time report showing
               every control's status with linked evidence.

   3.4  Versioning & framework drift
        Done when: framework versions are pinned, diffs across revisions are
               tooled, and multiple versions can be evaluated concurrently.
```

### Phase 4 — State-of-the-art (L4 → L5)
*Goal: the differentiators.*

```
   4.1  OSCAL-native pipeline end to end (catalog → profile → results → POA&M)
   4.2  Continuous compliance (always-on, not point-in-time)
   4.3  Self-improving content loop (LLM proposes → human approves → deterministic
        content improves; runtime stays deterministic)
   4.4  Crosswalk graph reasoning (multi-hop framework translation, gap analysis,
        "satisfy SOC 2 → what else do I get for free?")
   4.5  Multi-tenancy, RBAC/SSO, and SOC 2 / ISO 27001 for the product itself
```

---

## 6. Definition of done — the enterprise-grade checklist

Tick all of these and you can credibly say "enterprise-grade":

```
   CONTENT
   [ ] SCF crosswalk ingested (200+ frameworks, safeguard-level, STRM-typed)
   [ ] Official OSCAL catalogs (NIST 800-53) with profile resolution
   [ ] Detection content standardized (Sigma / MITRE ATT&CK / OVAL)
   [ ] Framework versions pinned + drift tooling

   QUALITY
   [ ] Held-out benchmark (500+ events), independent labels, kappa reported
   [ ] Accuracy reported per framework + per tier, on held-out only
   [ ] CI gate blocks accuracy regressions
   [ ] Adversarial / fuzz suite in CI

   CAPABILITY
   [ ] Config-state checking (OPA + OVAL), not just event mapping
   [ ] Multi-event correlation (incident-level reasoning)
   [ ] Evidence collection + point-in-time attestation + POA&M
   [ ] OSCAL assessment-results output

   OPERATIONS
   [ ] Gemma load test passed; throughput/latency documented
   [ ] Horizontal scale + SLOs + observability (metrics/tracing)
   [ ] Multi-tenancy + RBAC + SSO
   [ ] PII governance, retention, residency
   [ ] SOC 2 / ISO 27001 for the product
```

---

## 7. How the giants do it (so we're aiming at the right target)

From the verified research (see `~/Downloads/FURIX-COMPLIANCE-MAPPING-REPORT.md`):

- **Tenable / Qualys / Rapid7** run the **SCAP** stack — XCCDF checklists + OVAL
  checks + CVE/CPE/CVSS. Deterministic, no LLM in the mapping path.
- **NIST OSCAL** is the machine-readable backbone (catalogs, deterministic profile
  resolution); reference tools (`oscal-cli`, `compliance-trestle`) are pure code.
- **The Secure Controls Framework** is the human-curated crosswalk (1,400+ controls,
  200+ frameworks) and explicitly **forbids AI/NLP** in building it — for accuracy
  and legal defensibility.
- **GRC platforms (Drata, Vanta)** may use ML/NLP for *suggestions*, but the system
  of record is deterministic + human-reviewed.

Our target architecture (Section 4) is deliberately aligned with this: SCAP/OVAL
for state, OSCAL for catalogs/results, SCF for the crosswalk, LLM as a reviewed
assistant only.

---

## 8. Suggested sequencing & the one-line pitch

```
   QUARTER 1   Phase 1  (credibility)   → defensible accuracy + real SCF coverage
   QUARTER 2   Phase 2  (coverage)      → standard detections + config-state
   QUARTER 3   Phase 3  (operations)    → load test, evidence, attestation
   QUARTER 4   Phase 4  (SOTA)          → OSCAL-native, continuous, self-improving
```

**Pitch:** *"Furix already does compliance mapping the way NIST and Tenable do —
deterministic code, auditable, LLM only as a reviewed fallback. The MVP proves the
architecture and measures its own accuracy. The path to enterprise grade is
additive: load the authoritative SCF/OSCAL content, prove accuracy on a held-out
benchmark, add config-state checking and evidence/attestation, and pass a load
test. No rewrite — just the climb from L2 to L5."*

---

*Companion docs: `COMPLIANCE_ENGINE_EXPLAINED.md` (simple story),
`ACCURACY_TUNING.md` (the score bump), `COMPLIANCE_MAPPING.md` (architecture),
`~/Downloads/FURIX-COMPLIANCE-MAPPING-REPORT.md` (industry research).*

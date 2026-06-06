# Furix MVP — My Learning Notes

A running record of the guided walkthrough. One section per lesson. Skim the
**Key learnings** boxes to refresh the whole picture fast.

---

## 📖 Glossary (grows every lesson)

| Term | Plain-English meaning |
|---|---|
| **IOC** (Indicator of Compromise) | A concrete "wanted poster" clue of an attack: a bad IP, malicious domain, malware file hash, or known-exploited CVE. A match upgrades an event's severity. |
| **Container** | One box doing one job (here, one of the 15). |
| **Bus** | The "sushi belt" that carries messages between boxes (container C5 / Kafka). |
| **Topic** | A labeled channel on the bus (e.g. `raw.HOT`, `ai.verdicts`). |
| **Publish / Subscribe** | Publish = drop a message on a topic. Subscribe = register to receive that topic's messages. |
| **Lane** (HOT/WARM/COLD) | Priority class for incoming logs; HOT (auth fails, IOC hits) is worked first. |
| **CVE** | A globally unique ID for a known software vulnerability (e.g. CVE-2024-21410). |
| **Finding** | One normalized security observation the pipeline reasons about. |
| **Verdict** | The AI Brain's final answer for a finding (severity, risk, controls, etc.). |
| **Agent** | One specialized AI job that calls Gemma (we have 5). |
| **DAL** (Data Abstraction Layer) | The step that swaps real identifiers for placeholders before the prompt reaches Gemma. |
| **PII** | Personally/environment-identifying info (IPs, hostnames, usernames) — what the DAL hides. |
| **RAG** (Retrieval-Augmented Generation) | Fetching relevant facts (your real controls) and putting them in the prompt so the model doesn't guess. |
| **pgvector / AGE** | Postgres extensions: pgvector = vector DB (similarity search); AGE = graph DB (relationships). |

---

## Lesson 1 — The Big Picture

**What this lesson was about:** the 10,000-ft view — what Furix is, the core
mental model, and the journey one log takes through all 15 containers.

### 🔑 Key learnings (remember these)
1. **Furix = an on-prem security appliance.** Watches logs, scans for vulns,
   pulls threat intel, and reasons with a local AI (Gemma) — *no data leaves the
   network.* Rebuilt here as 15 cooperating containers.
2. **Boxes talk ONLY through the bus** (the "sushi belt"). A container publishes a
   labeled message to a *topic*; whoever subscribed to that topic picks it up. No
   box ever calls another box directly. → this is why each can scale/crash/restart
   alone.
3. **Gemma (C7) is the LAST and most expensive station.** Everything to its left
   exists to call it: **less** (cache), **safer** (DAL strips PII), **smarter**
   (RAG grounds the prompt in your real controls).
4. **Cheap deterministic work first, expensive AI only when needed.** C6 (signals)
   and C8 (rules) are fast pattern-matching; only genuine reasoning escalates to C7.
5. **One codebase, two run modes** — *lite* (`./run.sh`, one process = all 15,
   in-memory bus) and *real* (`docker compose up`, 15 containers + real Kafka).
   Only config differs; logic is identical.

### The 15 containers (one line each)
| # | Name | Job |
|---|---|---|
| C1 | Nginx | the only door in (reverse proxy) |
| C2 | Vector | log ingestion + HOT/WARM/COLD lanes |
| C3 | Scan Engine | active vulnerability scans |
| C4 | Intel Sync | pulls known-bad indicators (IOCs) |
| C5 | Kafka | the bus / sushi belt |
| C6 | Normaliser | parse→enrich→signals→controls (NO LLM) |
| C7 | Gemma (vLLM) | the model under test |
| C8 | Storage+Detection | persist events + run detection rules |
| C9 | PostgreSQL | knowledge store: relational + graph + **vector** |
| C10 | ClickHouse | the event timeline (what happened when) |
| C11 | Dashboard | what the analyst sees |
| C12 | Operations | metrics + health for every box |
| C13 | Valkey | fast cache (verdicts, IOCs, sessions) |
| C14 | AI Brain | the conductor: cache+DAL+RAG+5 agents |
| C15 | Backup | consistent encrypted snapshots |

### ⚠️ Three data stores — don't mix them up
- **C9 PostgreSQL** = the *knowledge* (relational rows + AGE graph + **pgvector**
  vector DB). Answers "how are things related / what's similar?"
- **C10 ClickHouse** = the *timeline*. Answers "show me every event in order, fast."
- **C13 Valkey** = the *cache*. Fast scratch memory (verdict cache, IOC lookups).

### Questions I asked
- **"Where's the vector DB?"** → It lives *inside C9* (PostgreSQL + the `pgvector`
  extension). It stores embedded compliance text so the AI can find semantically
  similar controls to ground a prompt. Deep dive = **Lesson 6**. Code: `rag.py`.
  (Off in lite mode `RAG_ENABLED=0`; seed it with `scripts/ingest.py`.)
- **"How is C4 connected?"** → C4 Intel Sync loads known-bad IOCs into the C13
  cache and announces `intel.updates` on the bus. C6 Normaliser *reads* C4/C13
  during enrichment to flag events touching known-bad IPs/domains/CVEs. Deep dive
  = **Lesson 3**.

```
  external feed ─▶ C4 Intel ──writes IOCs──▶ C13 Valkey cache
                                                  ▲
                          C6 Normaliser ──────────┘
                          "is 203.0.113.55 known-bad?"  (during enrichment)
```

---

## Lesson 2 — Foundations: C12 Operations + C5 Bus

**What this lesson was about:** the two boxes everything else depends on — how
every container *reports* what it's doing (C12) and how they *talk* (C5).
Files: `containers/c12_operations.py`, `containers/c5_bus.py`.

### 🔑 Key learnings (remember these)
1. **C12 = the metrics registry.** Counters (only go up: events, calls, errors)
   + histograms (latency samples → p50/p95/p99). Built FIRST because it's how we
   watch Gemma later.
2. **Use percentiles, not averages.** Averages hide pain. **p99 = the worst
   experience 1 in 100 users get** — it reveals a struggling Gemma before the
   average does.
3. **`ops.timer(...)`** times any block in one line; `register_health()` lets
   `/api/health` roll up all 15 boxes.
4. **C5 bus = two methods: `publish(topic, msg)` and `subscribe(topic, handler)`.**
   publish counts the message (via C12), finds subscribers, hands each the
   message, and **catches handler errors so one bad consumer can't kill the bus.**
5. **Topics are named constants (class `T`)** — a box knows a topic *name*, never
   another box's address.
6. **★ The big one: the bus has two backends (memory ↔ Kafka) behind ONE
   interface.** Because boxes only call `BUS.publish/subscribe`, you can swap the
   whole infrastructure (lite ↔ real) **without changing any business logic.**
   This is the most valuable architectural idea in the project.

### New keywords
- **Counter** — a metric that only increases (a tally).
- **Histogram** — a collection of samples (e.g. latencies) we summarize.
- **Percentile (p50/p95/p99)** — "X% of calls were faster than this." p99 = tail/worst-case.
- **Prometheus exposition** — the standard text format `/api/metrics` emits so monitoring tools can scrape it.
- **Health probe** — a function each box registers so its status appears in `/api/health`.
- **Backend (of the bus)** — the swappable implementation (in-memory vs Kafka) behind the same publish/subscribe interface.
- **Fan-out** — one published message delivered to many subscribers.

### Deep-dive: what `ai.enrichment` contains (asked mid-lesson)
A bus message is just a labeled JSON envelope. `ai.enrichment` means *"C14, please
reason about this finding."* C6 publishes it, C14 consumes it. Payload:
```
{
  "raw": "<original raw log text>",
  "finding": {                       # what C6 computed deterministically:
    "log_type": "...",
    "entities": {source_ip, domains, cve_ids, usernames},
    "intel": {"ioc_hits": [{type, value}, ...]},   # ← the IOC join result
    "signals": {malware, c2_or_exfil, privilege_escalation, ...},  # bool fingerprint
    "candidate_controls": ["Control 6", ...],
    "summary": "..."
  }
}
```
Nuance: in lite mode C14 takes `raw` and re-runs normalise+DAL itself (to redact
before the model), so `finding` is used mainly for the `log_type` hint. Every
topic is the same idea: a name + a JSON shape.

---

## Lesson 3 — Ingestion: building a finding (C2 → C4 → C6)

**What this lesson was about:** how a raw log becomes a clean, enriched `finding`
with ZERO Gemma calls. Files: `c2_vector.py`, `c4_intel_sync.py`, `c6_normaliser.py`.

### 🔑 Key learnings (remember these)
1. **C2 Vector = front door + lanes.** `classify_lane()` sorts each log into
   HOT/WARM/COLD by regex; HOT (auth fails, malware, IOC-ish) is worked first so
   urgent events never queue behind boring ones. It wraps the log in an *envelope*
   (source + ingest_ts + lane) = **lineage**.
2. **C4 Intel = the "wanted posters."** `refresh()` writes known-bad IOCs into the
   C13 cache as `ioc:<kind>:<value>` keys; `is_known_bad()` is the O(1) lookup.
   C4 *writes*, C6 *reads*. (In real Furix, C4 is the ONLY outbound container.)
3. **C6 Normaliser = 4 deterministic stages:**
   - Stage 1 **Parse**: regex out entities (IPs, domains, CVEs, usernames).
   - Stage 2 **Enrich**: join each entity against C4/C13 → `ioc_hits`.
   - Stage 3 **Signals + Controls**: boolean fingerprint (`malware`, `c2_or_exfil`,
     …) + candidate CIS controls; an IOC hit forces `c2_or_exfil=True`.
   - Stage 4 **Assemble** the canonical finding.
4. **Why a cache for IOC lookups?** C6 checks every entity in every log → must be
   instant (key lookup in C13), not a SQL query.
5. **C6 fans out the finding to 3 topics:** `normalized.events` (store),
   `detection.input` (rules), `ai.enrichment` (AI). One cheap pass, three jobs.
6. **The philosophy:** do ~90% of the work deterministically (regex + cache) so
   Gemma only handles the ~10% that needs real intelligence.

### New keywords
- **Envelope** — the wrapper C2 adds around a raw log (source, timestamp, lane) = lineage.
- **Lineage** — knowing where each event came from and when (auditability).
- **Entity extraction** — pulling structured items (IPs, CVEs, users) out of free text.
- **Enrichment** — adding context to an event (here: the IOC join against C4/C13).
- **Signal** — a boolean flag describing the event (e.g. `privilege_escalation=true`).
- **Candidate control** — a CIS control the deterministic stage *suspects* applies (the AI confirms later).
- **Normalisation** — converting many vendor log formats into one canonical shape.

### Deep-dive: making the lanes REAL (asked mid-lesson)
Originally the lanes were *inert* in lite mode (C6 handled all 3 lanes instantly,
same handler, synchronous bus). We added a **LaneScheduler** in `c2_vector.py`:
three queues drained strictly HOT→WARM→COLD. `ingest_many()` now enqueues the
whole backlog, then `drain()` processes every HOT log (fully, through C6→C14)
before any WARM, before any COLD. Proof: input order `[COLD,WARM,HOT,COLD,HOT]`
→ processed order `[HOT,HOT,WARM,COLD,COLD]`.
- **Lesson:** "architecturally present" ≠ "functionally active." Lanes only matter
  under **contention** (a backlog); one log at a time has nothing to prioritise.
- Real Kafka mode achieves the same with more consumers on the HOT topic.

---

## Lesson 4 — The Privacy Wall: the DAL

**What this lesson was about:** how the AI Brain lets Gemma reason about an event
without ever seeing real IPs/hostnames/usernames. File: `dal.py` (+ `brain.py`).

### 🔑 Key learnings (remember these)
1. **DAL rule (absolute): the model never sees a real identifier — only
   placeholders** (`10.0.0.5 → {IPV4_001}`). Reason in placeholders, restore reality
   after.
2. **Two moves:** `strip()` (real → placeholder, building a decoder map) and
   `rehydrate()` (placeholder → real). The map (`_rev`) is the "decoder ring."
3. **Stable mapping:** the same real value always gets the SAME placeholder, so the
   model still sees *relationships* ("same host keeps failing") while identities are
   hidden.
4. **Order of regex rules is a security property.** EMAIL before HOST (or emails get
   shredded); MAC before IPV6; IPv6 must contain a hex letter (or it eats `HH:MM:SS`
   timestamps). We literally fixed these bugs while building it.
5. **The DAL brackets the whole AI step in `brain.py`:** `strip` + `_redact_finding`
   *before* the agents, `rehydrate_obj` *after*. Even the structured finding is
   redacted; IOC hits become counts (no raw bad-IP rides along).
6. **Defense in depth:** even if Gemma were fully compromised, it only ever saw
   `{HOST_001}`. The `dal` report in every response (`redacted_count`, `by_kind`)
   proves what was hidden.

### New keywords
- **Tokenization/placeholder** — replacing a real value with a stand-in like `{IPV4_001}`.
- **Rehydrate** — swapping placeholders back to real values after inference.
- **Decoder map** — the in-memory placeholder→real lookup, kept only for the request's lifetime.
- **Defense in depth** — layered security that still protects you when one layer fails.
- **Stable mapping** — same input → same placeholder every time (preserves relationships).

### Deep-dive: "why only ~8 PII patterns vs HIPAA's 18?" (asked mid-lesson)
Two DIFFERENT meanings of "sensitive data":
- **Our DAL** (6 rules: EMAIL, MAC, IPV6, IPV4, HOST, SECRET) hides *infrastructure*
  identifiers found in **security logs** — that's our domain.
- **HIPAA Safe Harbor 18** defines PHI in **patient health records** (names, SSN,
  MRN, birth dates, …) — relevant only if you analyze health data.
- Honest gaps: bare **usernames aren't regex-redacted yet** (fix = field-aware
  redaction of the `entities.usernames` field, not regex). `_RULES` is a list →
  extending to HIPAA-18 is just adding patterns. (Optional Lesson 4.5 upgrade.)

### Deep-dive: "where is compliance mapped?" (asked mid-lesson)
Catalogs/rulebook live in **`compliance.py`**: `CIS_CONTROLS`, `CIS_TO_NIST`,
**`HIPAA_TO_NIST`** (your HIPAA), + `validate_*` anti-hallucination guards.
Mapping happens in two stages:
1. **C6** makes a cheap *candidate* guess (`KW` regex → `candidate_controls`).
2. **C14 "Compliance Mapper" agent** does the real mapping — its prompt
   (`prompts.COMPLIANCE_SYS`) is pinned to the closed catalog, Gemma proposes
   `control_ids`/`nist_subcategories`/`hipaa_sections`, then `agents.py` validates
   against `compliance.py` and drops anything invented. Deep dive = Lessons 6 & 7.

### Lesson 4.5 — Hardening the DAL (we built this)
Added two redaction *strategies* + opt-in HIPAA mode:
1. **Regex (`strip`)** — find PII by what it looks like (IPs, emails, MACs).
2. **Field-aware (`tokenize`)** — redact PII by WHERE it came from. `brain.
   _redact_finding` now tokenizes the `usernames` field directly (`root →
   {USER_001}`) because no regex catches a bare username. **CVE IDs are kept
   visible** (public; the model needs them).
3. **HIPAA-18 opt-in** (`config.DAL_HIPAA_MODE`, off by default) adds SSN/PHONE/
   DATE/VIN/URL rules — OFF for SIEM logs (DATE would shred timestamps), ON for
   healthcare data. Lossless roundtrip verified.
- **Lesson:** you can't regex your way to safety — some PII (usernames, names,
  MRNs) has no pattern; the only signal is the field. Match rules to the DOMAIN.

---

## Lesson 5 — The Cost Lever: C13 Verdict Cache

**What this lesson was about:** how the AI Brain avoids re-paying for Gemma on
repeated findings. File: `containers/c13_valkey.py` (+ `brain.py`).

### 🔑 Key learnings (remember these)
1. **Every finding = 5 Gemma calls.** The same KIND of event repeats constantly,
   so we cache the verdict and replay it.
2. **★ Key by SHAPE, not identity.** `verdict_key()` hashes
   `{log_type, signals, candidate_controls}` — **no IPs/usernames/hosts**. So two
   different hosts hit by the same kind of attack share one verdict (cache HIT).
3. **Two free wins from shape-keying:** (a) the key has **no PII** (privacy-safe),
   (b) it's the **"System 1"** pattern — fast deterministic replay for common
   cases; the slow "System 2" (5 agents → Gemma) runs only for NOVEL findings.
4. **Placement:** `brain.analyze` checks `get_verdict()` BEFORE grounding/agents;
   on HIT it returns immediately with `agents: []`, `cache_hit: true`. On MISS it
   runs the agents then `put_verdict()` (24h TTL).
5. **Measured savings:** `verdict_cache_hits_total` / `_misses_total` counters in
   C12 — the hit count literally = Gemma calls you didn't pay for.
6. **Backend swap** (like the bus): in-memory dict in lite, real Valkey when
   `VALKEY_URL` is set — same `get/set` interface.

### New keywords
- **Verdict cache** — stores a finding's final answer to skip re-computation.
- **Cache key by shape** — hashing the *kind* of event (fingerprint), not its identifiers.
- **TTL (time-to-live)** — how long a cached entry stays valid (24h here).
- **System 1 / System 2** — fast cheap pattern-replay vs slow expensive reasoning.
- **Cache hit / miss** — found in cache (free) vs not found (must compute).

---

## Lesson 6 — Grounding: C9 vector DB + graph

**What this lesson was about:** how the Brain fetches your REAL compliance controls
so Gemma selects from facts instead of inventing. Files: `compliance.py`,
`scripts/ingest.py`, `rag.py`.

### 🔑 Key learnings (remember these)
1. **Grounding = "open-book exam."** Put the relevant real controls in the prompt
   so the model picks, not guesses.
2. **Two kinds of mapping:** (a) cross-framework crosswalk (CIS↔NIST↔HIPAA) =
   static tables in `compliance.py` + AGE `MAPS_TO` edges; (b) finding→control =
   vector search (`rag.py`) + the Compliance Mapper agent (Lesson 7).
3. **★ NIST CSF 2.0 is the hub ("Rosetta Stone").** BOTH CIS and HIPAA map *to*
   NIST, so a finding mapped to CIS Control 6 also satisfies HIPAA 164.312a1
   through their shared NIST subcategories. One finding → 3 frameworks.
4. **What's in the vector DB** (`compliance_chunks` table): one row per control/
   section/subcat with `framework`, `control_id`, `content` (a sentence), and a
   **768-dim `embedding`** (vector). `ingest.py build_corpus()` writes the text;
   SecureBERT computes the vector.
5. **Embedding = a meaning-vector.** Similar meaning → near in 768-D space.
   SecureBERT is security-tuned, so "mimikatz"/"credential dumping"/"access
   control" cluster together, far from "DHCP".
6. **`retrieve()` = two-stage retrieve-then-rerank:** bi-encoder cosine search
   (fast, top 35) → cross-encoder rerank (accurate, top 6) → `_graph_expand`
   (walk `MAPS_TO` to NIST). Result handed to the agents.
7. **Honest caveat:** lite mode `RAG_ENABLED=0` → `retrieve()` returns
   `available:false` → falls back to static-map grounding. Full path needs
   Postgres+pgvector+AGE+SecureBERT + `python scripts/ingest.py`.

### New keywords
- **Grounding** — putting real facts in the prompt so the model selects, not invents.
- **Embedding** — a numeric vector capturing the meaning of text.
- **Vector DB (pgvector)** — stores embeddings + does nearest-neighbour (similarity) search.
- **Cosine distance** (`<=>`) — how pgvector measures "how close in meaning."
- **Bi-encoder vs cross-encoder** — fast approximate search vs slow accurate rerank.
- **Rerank** — re-scoring a shortlist more accurately.
- **AGE / `MAPS_TO`** — the graph + the edge connecting a CIS control to its NIST subcats.
- **Crosswalk** — a table mapping one framework's items to another's.
- **NIST hub** — NIST CSF as the pivot language linking CIS ↔ HIPAA.

### Deep-dive: RAG edge cases & training (asked mid-lesson)
- **Empty/off vector DB** → `status()` sees 0 rows → `available:False` → STATIC
  grounding (C6 candidates + `compliance.py` titles). Nothing goes ungrounded.
- **Populated but weak match** → ⚠️ our `retrieve()` has NO relevance floor; it
  always returns the nearest 6 even if weak. (Original had `COVERAGE_SCORE_FLOOR
  =0.50`; we trimmed it — can re-add.)
- **Repeat log = cached, NOT ignored.** It's still recorded (timeline + persisted
  as a separate occurrence); only the reasoning (RAG + 5 Gemma calls) is skipped
  via the verdict cache.
- **Fallback decided by 3 gates** in `rag.py`: RAG_ENABLED? connect ok? rows>0? —
  plus a `try/except` so any runtime error also falls back. Grounding degrades,
  never crashes.
- **RAG accuracy:** not benchmarked in this MVP; corpus is thin (titles only — real
  system ingests full PDFs). BUT accuracy affects *relevance*, not *correctness*:
  two safety nets (static crosswalk + agent validates against the closed catalog)
  mean a weak RAG result can only surface a less-relevant-but-VALID control, never
  a hallucinated one. (Eval harness can be re-added for a real number.)
- **Training:** NONE required. SecureBERT (embed/rerank) and Gemma are PRE-TRAINED
  & frozen. Furix prefers **RAG over fine-tuning** (retrieve facts at inference =
  cheap, updatable, auditable). The only trained piece in real Furix is the
  per-customer **GBDT Instinct** (nightly) — which we did NOT build in this MVP.

### What's special about `rag.py` (asked)
1. **Hybrid vector + graph** (GraphRAG-ish): pgvector cosine search THEN AGE
   `_graph_expand` — semantic *and* symbolic.
2. **Two-stage retrieve-then-rerank** (bi-encoder → cross-encoder).
3. **Aggressively defensive**: probe before trying, lazy model load, whole thing
   wrapped in try/except → degrades to static, never crashes.
4. **Lazy + cached + thread-safe** (models load on first real use; status cached).
5. **SecureBERT** = security-domain embeddings, not generic.
Theme: RAG is an *enhancement*, never a *dependency*.

### What are evals (asked)
Evals = repeatable automated measurement of OUTPUT QUALITY vs a labeled ground
truth (the quality twin of the load test, which measures speed).
- **Precision** = correct ÷ predicted (how much of what we said was right).
- **Recall** = correct ÷ expected (how much of the truth we found).
- **F1** = harmonic mean. **Coverage** = % of logs with ≥1 expected control found.

### Upgrades A + B (we built these)
- **A · RAG relevance floor** (`config.RAG_SCORE_FLOOR=0.30`): `rag.retrieve()` now
  drops matches whose cosine similarity < floor; `brain._ground()` backfills from
  C6 candidates when RAG returns weak/empty. ⚠️ Only active when RAG_ENABLED=1.
- **B · `tools/eval_rag.py`**: scores grounding controls vs hand-labeled truth.
  Lite/static result: **P=0.45, R=1.00, F1=0.62, coverage 8/8** → candidates are
  high-recall/low-precision (broad net); the agent+validation narrows it. Rerun
  after `RAG_ENABLED=1` + `scripts/ingest.py` to measure if the vector path lifts
  precision (it should — the cross-encoder rerank trims noise).

---

## Lesson 7 — The Reasoning: 5 agents + prompts + C7 Gemma

**What this lesson was about:** the heart — how the finding becomes a verdict via 5
specialized Gemma calls, each validated. Files: `prompts.py`, `agents.py`, `llm.py`.

### 🔑 Key learnings (remember these)
1. **Every agent = same skeleton:** strict prompt + grounding → ONE Gemma call →
   parse → VALIDATE → AgentResult. 5 agents, 5 jobs, one shape.
2. **5 prompt-design rules:** one job per prompt; JSON-only contract (schema stated
   once); a rubric not vibes; inputs pre-redacted by the DAL; zero filler (token
   budget per agent). **These 5 prompts ARE the Gemma test suite.**
3. **★ Net #2 — catalog validation** (`agents.run_compliance_mapper`): the prompt
   injects the closed CIS/NIST/HIPAA catalog ("use ONLY these"), AND the code
   validates the output (`validate_controls/nist/hipaa`) dropping any invented ID,
   then enriches NIST from the deterministic crosswalk. Belt + suspenders → a
   hallucinated control CANNOT escape. (This is why RAG accuracy mattered less.)
4. **Risk Scorer guards:** clamp severity to the 5 allowed values; clamp risk_score
   0–100.
5. **The Gemma call** (`llm.complete_json`): system+user messages, temperature 0.1
   (consistent not creative), `response_format=json_object`, per-agent max_tokens,
   3× retry + truncation-repair. Returns latency/tokens/source (what loadtest reads).
6. **Dependency order:** risk + compliance + anomaly run in PARALLEL; remediation
   needs the mapping; report needs all → 5 calls per finding (0 on cache hit).

### New keywords
- **Agent** — one specialized job = one strict prompt + one Gemma call + validation.
- **Output schema / contract** — the fixed JSON keys an agent must return.
- **Catalog validation** — dropping any model output not in the allowed list (anti-hallucination).
- **Rubric** — explicit definitions (e.g. severity tiers) that remove guesswork.
- **Temperature** — randomness knob; 0.1 = consistent, rule-following.
- **Token budget** — per-agent max_tokens cap (risk 400 … report 900).
- **Belt-and-suspenders** — the prompt asks for safety AND the code enforces it.

### Safety nets — the full list (asked)
A safety net = a guard/fallback that keeps the system correct/safe/up when a part
misbehaves. The 12 we've built:
1. DAL redaction (privacy) · 2. Verdict cache (cost) · 3. RAG relevance floor
(relevance) · 4. Static-map fallback (availability) · 5. Catalog validation —
"net #2" (no hallucinated IDs) · 6. Crosswalk enrichment (completeness) · 7.
Severity/score clamp (sane values) · 8. JSON parse + truncation repair
(robustness) · 9. 3× retry → fallback flag (reliability) · 10. Bus handler
try/except (isolation) · 11. Detection rules (catch obvious w/o AI) · 12. Mock
mode (offline).
Pattern: every place that *could* fail has a defined "what happens instead" →
that's what makes it enterprise-grade.

### Can local Gemma take 3 concurrent calls? (asked)
- **Client always sends 3** (ThreadPoolExecutor max_workers=3 for risk+compliance
  +anomaly). Whether the SERVER runs them in parallel depends on stack+hardware:
  - **Ollama** (their :11434): gated by `OLLAMA_NUM_PARALLEL` (old default 1 →
    serialize; new auto ~4) + `OLLAMA_MAX_LOADED_MODELS`. =1 → 3 calls queue
    (correct, not faster).
  - **vLLM (GPU)**: continuous batching → loves concurrency.
  - **CPU-only (E2B/E4B)**: concurrency usually doesn't help / can hurt (CPU-bound).
- **Always safe to send; "faster" is hardware-dependent.** MEASURE with
  `tools/loadtest.py --concurrency 1,2,3,4,8`. If rps rises → keep
  `PARALLEL_AGENTS=1` (+ raise OLLAMA_NUM_PARALLEL). If flat + p95 climbs → set
  `PARALLEL_AGENTS=0` (sequential) and lean on the cache.

---

## Lesson 8 — The Conductor: brain.py (C14)

**What this lesson was about:** how `analyze()` sequences all 7 prior lessons into
one clean function. File: `brain.py`.

### 🔑 Key learnings (remember these)
1. **The Brain sequences, it doesn't compute.** `analyze()` is ~40 lines; almost
   every line delegates to a specialist already met.
2. **The 6-step sequence** (each = a lesson): ① C6 normalise + DAL strip → ②
   C13 cache check (HIT = return, 0 Gemma) → ③ C9 ground (RAG/static) → ④ 5 agents
   (Gemma, timed) → ⑤ DAL rehydrate (placeholders→real) → ⑥ merge ONE verdict +
   cache it.
3. **Verdict merge = take the right field from the right agent:** severity/risk/
   confidence ← Risk Scorer; control_ids/nist/hipaa ← Compliance Mapper; is_anomaly
   ← Anomaly Detector; remediation+report ride along in `agents[]`. Fallbacks keep
   the verdict never-empty (controls→candidates, nist→crosswalk).
4. **`analyze()` is PURE** — no DB write, no bus publish; it returns the record.
   Callers persist once: API path (`/api/analyze`→`_persist`) OR bus path
   (`C14.consume`→`ai.verdicts`→C8). Same logic, two triggers = "separate WHAT
   from HOW" (same principle as the swappable bus/cache backends).
5. **`_run_agents`** runs the 3 independent agents in a ThreadPoolExecutor (the
   `PARALLEL_AGENTS` toggle), then remediation (needs mapping), then report (needs
   all).

### New keywords
- **Orchestration/conductor** — sequencing specialists rather than doing the work inline.
- **Pure function** — returns a result with no side-effects (no DB/bus); callers handle effects.
- **Verdict merge** — fusing multiple agent outputs into one coherent answer.
- **Separate WHAT from HOW** — write logic once, drive it from multiple triggers.

---

## Lesson 9 — After the Verdict: C8 Storage+Detection + C10 ClickHouse

**What this lesson was about:** where the verdict goes + how deterministic detection
runs alongside the AI. Files: `c8_storage_detect.py`, `c10_clickhouse.py`.

### 🔑 Key learnings (remember these)
1. **C8 = two boxes in one.** Storage Writer (persist) + Detection Engine (rules).
   It consumes the THREE topics C6 fanned out in Lesson 3: `normalized.events`,
   `detection.input`, and (via C14) `ai.verdicts`.
2. **A verdict is written to TWO stores:** C9 Postgres (`db.save` — full record/
   audit) AND C10 ClickHouse (timeline row). Two stores = two questions.
3. **★ Deterministic detection runs ALONGSIDE the AI on the SAME event.** Rules
   (instant, explainable, known threats) + Gemma (slow, novel reasoning) cover each
   other's blind spots. If Gemma is down, rules still fire → detection never goes
   dark.
4. **C10 ClickHouse = the timeline:** columnar, append-mostly, scans billions of
   time-ordered rows fast. Answers "what happened WHEN."
5. **★ Don't use one DB for everything** (classic SIEM mistake): C10 = "when",
   C9 graph = "how related", C9 pgvector = "what's similar".
6. Closes the loop: every consumer of C6's fan-out is now accounted for.

### New keywords
- **Detection rule** — a deterministic predicate that fires an alert on a known pattern.
- **Deterministic vs probabilistic** — rules (always-same, known) vs AI (reasoned, novel).
- **Columnar store** — DB optimized for scanning columns over many rows (timelines/analytics).
- **Append-mostly** — data is added, rarely updated (fits event timelines).
- **Storage Writer / Detection Engine** — C8's two jobs.

---

## Lesson 10 — The Edges: C3 Scan · C15 Backup · C1 Nginx · C11 Dashboard

**What this lesson was about:** the supporting cast that makes it an appliance.
Files: `c3_scan_engine.py`, `c15_backup.py`, `deploy/nginx/nginx.conf`, `api.py`.

### 🔑 Key learnings (remember these)
1. **C3 Scan = the "go look" half** (logs are the "watch" half). It actively probes
   assets, matches services→CVEs, and publishes findings to the SAME bus/graph.
   → the Furix thesis: scans + logs + intel on one asset = reasoning no separate
   tool could do. `as_raw_log()` lets a scan finding re-enter via C2.
2. **C15 Backup = a CONSISTENCY problem, not a copy problem.** Two-phase quiesce:
   PREPARE (freeze a point-in-time view across C9/C10/C13 at once) → COMMIT
   (serialize + SHA-256 fingerprint) → VERIFY (read back + re-hash). The hash =
   tamper-evidence. (Real adds encryption + Ed25519 + 3-2-1 rule.)
3. **C1 Nginx = the single door.** TLS/rate-limit/authz at ONE choke point; all
   other containers internal-only.
4. **C11 Dashboard = the only user-facing box.** All input through one box →
   C1+C11 are the entire attack surface (2 exposed, 13 sealed = small surface).

### New keywords
- **Active scanning vs log monitoring** — "go look" (C3) vs "watch" (C2/logs).
- **Two-phase quiesce** — freeze all stores at one logical instant, then snapshot.
- **Tamper-evident (SHA-256 manifest)** — re-hash on restore to detect any change.
- **3-2-1 rule** — 3 copies, 2 media types, 1 off-site.
- **Attack surface** — the parts exposed to users/attackers (here: just C1+C11).
- **Choke point** — one place where all traffic passes, so policy lives in one spot.

---

## Lesson 11 — Under Load: stress-testing Gemma

**What this lesson was about:** using the tools to size the deployment. Files:
`tools/loadtest.py`, `tools/batch_ingest.py`, `/api/metrics`.

### 🔑 Key learnings (remember these)
1. **Two questions, two tools:** loadtest.py = SPEED, eval_rag.py = QUALITY.
2. **Read the table:** `rps` (throughput), `p95/p99` (the tail users feel),
   `tok/s` (raw model speed), `err%` (stability). Tail latency matters more than
   the average.
3. **★ Saturation point ("the knee"):** where more concurrency stops adding rps and
   only adds latency. loadtest prints it. **Size just BELOW the knee.**
4. **Hardware shape:** CPU-only Gemma → barely scales (set `PARALLEL_AGENTS=0`);
   GPU+vLLM → scales well (keep parallel, raise concurrency).
5. **Check p95 vs the agent budget** (Risk Scorer = 5s). p95 > budget at target
   load → smaller model / more hardware / more caching.
6. **★ Cache is a throughput MULTIPLIER:** effective capacity = `rps ÷ (1 −
   cache_hit_rate)`. e.g. 2/sec raw × 60% hits = 5/sec effective. Proven live:
   call 1 cache_hit=False (5 agents), call 2 cache_hit=True (0 agents).
7. **Real run** (on Gemma network): `MOCK_LLM=0 python tools/loadtest.py
   --concurrency 1,2,3,4,8,16 --requests 30`. Four numbers size everything:
   peak rps, saturation point, p95 vs 5s, err%.

### New keywords
- **Throughput (rps)** — requests/sec the system sustains.
- **Tail latency (p95/p99)** — the slow few %; what users actually feel.
- **Saturation point / knee** — where added load stops helping throughput.
- **Tokens/sec** — raw model generation speed.
- **Effective capacity** — raw throughput amplified by the cache hit rate.

### Deep-dive: real-time scale — can Gemma/the MVP handle huge log volumes? (asked)
**Reframe: logs/sec ≠ Gemma calls/sec.** Raw logs flow C2→C6→C8→C10 (sort, enrich,
detect, store) at HIGH throughput with NO LLM. Only post-funnel findings reach C7.
```
 1,000,000 logs/s ─▶ lanes+deterministic+detection+store (NO LLM, scales sideways)
   → ~1,000 findings/s → cache(60%)+instinct(90%) → ~40 LLM-bound/s ×5 agents
   → ~200 Gemma calls/s  ← size the GPU fleet to THIS, not the million
```
(numbers illustrative; point = ~5 orders of magnitude reduction.)

- **4B Gemma throughput:** CPU ~0.3–0.5 calls/s; single GPU+vLLM ~15–30/s; bigger
  ~30–50/s. At 5 agents/finding that's ~3–6 findings/s per instance (×cache).
- **Ideal enterprise:** (1) DECOUPLE firehose from LLM (Vector/Kafka/ClickHouse scale
  horizontally to 500K+ eps, never wait on Gemma); (2) SHRINK what reaches the LLM
  (lanes→detection→cache→GBDT instinct, ~85–95% handled without the model); (3)
  SCALE the LLM tier (GPU fleet + vLLM batching + multiple AI-Brain workers on Kafka
  partitions) to the post-funnel trickle.
- **Can OUR MVP handle it?** Architecture = ✅ right shape (funnel keeps Gemma off
  the firehose — the worry is designed out). Lite impl = ⚠️ single-process/sync/
  in-memory → a learning model + Gemma capacity tester, NOT production throughput.
  Compose = 🔸 closer but minimal (single broker/instance).
- **Missing for true scale (not built):** System-1 GBDT instinct (biggest LLM
  reducer), Kafka partitioning + parallel AI-Brain workers, async + LLM backpressure,
  GPU serving.
- **MVP's real jobs:** prove Gemma is good enough on the prompts + MEASURE per-
  instance capacity (loadtest) → that number × GPU fleet = production sizing.

---

## Lesson 12 — The Whole Picture + Going Real (FINALE 🎓)

**What this lesson was about:** synthesis — one event through all 15 in order, and
the lite→real (docker compose) switch.

### 🔑 Key learnings (remember these)
1. **One event names all 15 in order:** C1 door → C2 lane → C5 bus → C6 normalise
   (+C4 intel) → C8 detect+store → C10 timeline / C9 graph → C14 (DAL→C13 cache→C9
   RAG→5 agents→C7 Gemma→rehydrate→verdict) → C8 persist → C9/C10 → C12 metrics →
   C13 cache → C11 dashboard; C15 backs up alongside.
2. **Lite and compose run IDENTICAL code** — the switch is config: `BUS_BACKEND=
   memory|kafka`, `FURIX_BOOTSTRAP=1|0`, `run_container.py <role>`. 7 Furix services
   share one image; 8 infra boxes are real OSS images. `docker compose up --build`.
3. **The 7 transferable principles:** (1) decouple via a bus; (2) separate WHAT from
   HOW; (3) deterministic-first, AI-last; (4) safety nets everywhere; (5) ground
   don't train; (6) privacy by construction (DAL); (7) measure don't guess.

### Next steps
1. Gemma network: `MOCK_LLM=0`, GET /api/health → confirm reachable.
2. `./run.sh` → analyze real logs in the dashboard.
3. `tools/loadtest.py --concurrency 1,2,4,8,16` → size it.
4. `RAG_ENABLED=1` + `scripts/ingest.py` + `tools/eval_rag.py` → precision lift.
5. `docker compose up --build` → the real 15-container appliance.
6. (future) build the System-1 GBDT instinct layer.

### 🎓 Course complete — 12 lessons, all 15 containers, every safety net, both
### measurement tools. From "what is this code" to "I can size and deploy it."

---

## Bonus — LogForge / VulnForge integration (`tools/forge_feed.py`)

**What:** a file-based "log shipper" that reads a LogForge bundle and feeds the
logs into the MVP via `/api/analyze/batch`, then JOINS our verdicts back to the
bundle's `labels.jsonl` (ground truth) and scores detection. Decoupled by design
(the generators have their own py3.12 venvs; the bundle on disk is the contract).

- **Generators (purpose-built for Furix):** LogForge = native-format correlated
  logs + `labels.jsonl` (benign/malicious/benign_suspicious + MITRE). VulnForge =
  Nessus/nmap findings + `labels.jsonl` (exploitability_tier, was_exploited). Same
  seed → shared estate → logs & scans correlate.
- **event_id join:** every log line carries event_id in a native slot (JSON key,
  Windows ActivityID GUID, PAN-OS/DHCP hex tail). `forge_feed.py` extracts +
  normalises it to match `labels.jsonl`.
- **First run result (MOCK mode, healthcare bundle):** precision 0.03 / recall 0.11
  — bad ON PURPOSE, and the lesson: (1) ingestion works; (2) the deterministic
  funnel alone is a weak detector — over-fires on benign (`sudo`/`privilege`) and
  MISSES subtle campaign steps (each looks benign alone). Fixes: real Gemma
  (`MOCK_LLM=0`) for reasoning + cross-log CORRELATION via the C9 graph.
- **Usage:** `python tools/forge_feed.py --bundle <dir> --limit 100` (start MVP
  first). With `MOCK_LLM=0` it's a real detection-quality benchmark for YOUR Gemma.
- **Three measuring tools now:** loadtest.py (speed), eval_rag.py (mapping),
  forge_feed.py (detection vs ground truth).
- **TODO/next:** a `--vuln` mode to feed VulnForge `scans/vuln/*.json` via the C3
  scan path + score exploitability; and cross-log correlation so campaign steps
  join (the missing piece the score exposed).

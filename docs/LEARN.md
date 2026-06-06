# LEARN — a guided walkthrough of the codebase

This is the "teach me the code" doc. Every source file carries a banner comment
saying **which container** it is, **what it does**, and **the insight** behind it.
Read in this order and you'll understand the whole system in ~an hour.

## 0. Mental model first

- The system is a **pipeline of 15 boxes** connected by a **bus** (C5).
- A box never calls another box directly — it **publishes to a topic**; whoever
  cares **subscribes**. That one rule is why each box can scale/crash/restart
  alone. Internalise this before reading code.
- The expensive box is **Gemma (C7)**. Everything else exists to call it *less*
  (cache), *safely* (DAL), and *well* (RAG grounding).

## 1. Read order (follow an event through the code)

| Step | File | What to learn |
|---|---|---|
| 1 | `containers/__init__.py` | the 15-container map in one screen |
| 2 | `containers/c12_operations.py` | how we measure everything (counters + p50/95/99) |
| 3 | `containers/c5_bus.py` | the bus: `publish`/`subscribe`, topics, memory↔kafka |
| 4 | `containers/c2_vector.py` | ingestion + HOT/WARM/COLD lanes |
| 5 | `containers/c6_normaliser.py` | the 4 deterministic stages (parse→enrich→signals→controls) |
| 6 | `dal.py` | **DAL**: how PII becomes `{HOST_001}` and back |
| 7 | `containers/c13_valkey.py` | the **verdict cache** — the single biggest cost lever |
| 8 | `prompts.py` | the 5 strict agent contracts (the crown jewels) |
| 9 | `agents.py` | one Gemma call per agent + output validation |
| 10 | `compliance.py` | the closed CIS/NIST/HIPAA catalogs the prompts are pinned to |
| 11 | `rag.py` | grounding: pgvector search → SecureBERT rerank → AGE graph-expand |
| 12 | `brain.py` (**C14**) | the orchestrator that ties cache+DAL+RAG+agents into a verdict |
| 13 | `containers/c8_storage_detect.py` | deterministic rules vs. the AI; persistence |
| 14 | `pipeline.py` | how `bootstrap()` wires all the boxes onto the bus |
| 15 | `api.py` (**C11**) | the HTTP surface + the dashboard |
| 16 | `tools/loadtest.py` | how to find Gemma's real limits |

## 2. The five concepts that matter most

### (a) The bus decouples everything — `c5_bus.py`
`publish(topic, msg)` fans out to every subscriber. In lite mode it's a synchronous
in-process call; in compose it's Kafka. Same two methods. If you understand
`_MemoryBus`, you understand the whole control flow.

### (b) The DAL is the privacy boundary — `dal.py`
`brain.analyze()` calls `dal.strip(raw)` **before** any agent runs, and
`dal.rehydrate_obj(out)` **after**. So Gemma only ever sees `{IPV4_001}` /
`{HOST_001}`. Trace `_redact_finding()` in `brain.py` to see the finding itself
get redacted too (entities → placeholders, intel hits → counts).

### (c) The verdict cache is the cost lever — `c13_valkey.py`
`verdict_key(finding)` hashes the *shape* of a finding (log_type + signals +
controls), not its PII. Two structurally-identical events share a key → the second
one is a **cache hit** and skips all 5 Gemma calls. Watch
`verdict_cache_hits_total` during a stress test — it explains your throughput.

### (d) Deterministic vs. probabilistic — `c6_normaliser.py` + `c8_storage_detect.py`
C6 (signals/controls) and C8 (detection rules) are **cheap and deterministic**.
The AI Brain is **expensive and probabilistic**. The architecture does as much as
possible deterministically and only escalates genuine reasoning to Gemma. This is
why "AI security" can be affordable on-prem.

### (e) Grounding stops hallucination — `rag.py` + `compliance.py`
The Compliance Mapper prompt is injected with a **closed catalog** (only real CIS
controls / NIST subcats / HIPAA sections), and `agents.py` validates the output
against it. RAG adds *your* environment's context. A control ID the model invents
cannot survive validation.

## 3. Hands-on exercises

1. **Trace one event.** `POST /api/analyze` with a sample log, then read
   `/api/ops` and `/api/metrics`. Match every counter to a line of code.
2. **Add a 6th detection rule.** Add a predicate to `RULES` in
   `c8_storage_detect.py`, ingest a matching log via `--mode pipeline`, see it in
   `/api/alerts`.
3. **Add an agent.** Write a prompt in `prompts.py`, a `run_*` in `agents.py`,
   register it in `config.ALL_AGENTS` and `brain._run_agents`. It now calls Gemma.
4. **Find Gemma's ceiling.** On the Gemma network:
   `MOCK_LLM=0 python tools/loadtest.py --concurrency 1,2,4,8,16,32 --requests 30`.
   Where does `rps` stop rising and `p95` start climbing? That's your saturation
   point — size your deployment below it.
5. **Prove the cache works.** Analyse the same log twice; the second response has
   `"cache_hit": true` and `agents: []`. That's one Gemma call you didn't pay for.

## 4. Where each requirement lives

| You asked for… | It's here |
|---|---|
| all 15 containers, lite | `furix_mvp/containers/*` + `docker-compose.yml` |
| ingest multiple logs at once | `POST /api/analyze/batch`, `tools/batch_ingest.py` |
| stress-test Gemma | `tools/loadtest.py` |
| heavy teaching comments per container | banner block at the top of every file |
| close-to-real-world deployment | `docker-compose.yml` + `deploy/*` |
| documentation | this file + `docs/ARCHITECTURE.md` |

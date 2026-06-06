# Furix Appliance — Architecture (15 containers)

Furix is one on-prem VM running **15 cooperating containers**. This MVP reproduces
all 15 in a form that is *close to real-world yet lite*, so you can both **learn**
the shape and **stress-test your in-house Gemma** end to end.

## Two ways to run the exact same code

| Mode | Command | What runs | Use it to |
|---|---|---|---|
| **Lite** (default) | `./run.sh` | ONE process *is* all 15 containers; bus/cache/timeline use in-memory fallbacks | learn, iterate, demo, stress-test offline |
| **Compose** (real) | `docker compose up --build` | 15 real containers on a Docker network, talking over real Kafka | see the true distributed shape |

The switch is just env: `BUS_BACKEND=memory|kafka`, `RAG_ENABLED`, `VALKEY_URL`,
etc. No business logic changes between modes — that is the design goal.

## The 15 containers

| # | Container | Kind | Real image (compose) | Code |
|---|---|---|---|---|
| C1 | Nginx | infra | `nginx` | `deploy/nginx/nginx.conf` |
| C2 | Vector | furix/infra | `timberio/vector` | `containers/c2_vector.py` |
| C3 | Scan Engine | furix | shared image | `containers/c3_scan_engine.py` |
| C4 | Intel Sync | furix | shared image | `containers/c4_intel_sync.py` |
| C5 | Kafka (KRaft) | infra | `apache/kafka` | `containers/c5_bus.py` |
| C6 | Normaliser | furix | shared image | `containers/c6_normaliser.py` |
| C7 | vLLM / **Gemma** | model | `ollama/ollama` or your server | `llm.py` + `containers/c7_vllm.py` |
| C8 | Storage + Detection | furix | shared image | `containers/c8_storage_detect.py` |
| C9 | PostgreSQL+AGE+pgvector | infra | `pgvector/pgvector` | `rag.py`, `db.py`, `containers/c9_stores.py` |
| C10 | ClickHouse | infra | `clickhouse/clickhouse-server` | `containers/c10_clickhouse.py` |
| C11 | Dashboard | furix | shared image | `api.py` + `static/index.html` |
| C12 | Operations | furix | `prom/prometheus` scrapes it | `containers/c12_operations.py` |
| C13 | Valkey | infra | `valkey/valkey` | `containers/c13_valkey.py` |
| C14 | AI Brain (Praxis) | furix | shared image | `brain.py` + `containers/c14_ai_brain.py` |
| C15 | Backup Coordinator | furix | shared image | `containers/c15_backup.py` |

The 7 Furix-built services (C3,C4,C6,C8,C11,C14,C15) share **one Docker image**;
`run_container.py` picks the role per container.

## The life of one security event

```
                  ┌────────── C12 Operations: counts + latency for EVERY hop ──────────┐
                  │                                                                     │
  log ─▶ C2 Vector ─raw.HOT/WARM/COLD▶ C6 Normaliser ─┬─ normalized.events ─▶ C8 ─▶ C10 ClickHouse (timeline)
        (lane tag)        (parse, enrich w/ C4 intel,  ├─ detection.input  ─▶ C8 Detection (rules → alerts)
                           tag controls — NO LLM)      └─ ai.enrichment    ─▶ C14 AI Brain
                                                                                  │
                              C13 Valkey ◀─ verdict cache ──┐                     │ 1. cache? (C13)
                                                            │                     │ 2. DAL strip (PII → {HOST_001})
                              C9 Postgres ◀─ RAG grounding ─┼─────────────────────┤ 3. ground (C9 RAG)
                              (pgvector + AGE graph)        │                     │ 4. 5 agents ─▶ C7 GEMMA
                                                            └─ put verdict ───────┤ 5. rehydrate + merge verdict
                                                                                  ▼
                                                            ai.verdicts ─▶ C8 persists (C9 + C10)
                                                                        └▶ C11 Dashboard shows it
```

**Key property:** Gemma (C7) is the *last* thing touched, wrapped in cache + DAL +
grounding + validation. ~most repeat work never reaches it (verdict cache), and
when it does, it sees only redacted placeholders grounded in your own controls.

## Kafka topics (the contracts between containers)

| Topic | Producer | Consumer | Carries |
|---|---|---|---|
| `raw.HOT/WARM/COLD` | C2 | C6 | raw log envelopes by priority |
| `scan.findings` | C3 | C6, C8 | vulnerability findings |
| `normalized.events` | C6 | C8 | canonical events → storage |
| `detection.input` | C6 | C8 | canonical events → rule engine |
| `ai.enrichment` | C6 / C8 | C14 | "please reason about this finding" |
| `ai.verdicts` | C14 | C8, C11 | verdict + per-agent provenance |
| `intel.updates` | C4 | C8, C13 | new IOCs/CVEs |
| `kg.findings` | C8 | C9 | graph writes |
| `timeline.events` | C8 | C10 | columnar timeline writes |

## The 5 agents (all call Gemma)

Risk Scorer · Compliance Mapper · Remediation Generator · Anomaly Detector ·
Report Generator. See `prompts.py` (the contracts) and `agents.py` (the calls +
validation). Triage/normalisation is deterministic (C6) — it does **not** spend a
Gemma call, keeping the model for genuine reasoning.

## Stress-testing Gemma

`tools/loadtest.py` drives C7 with real agent prompts at rising concurrency and
reports p50/p95/p99, throughput, tokens/s, error rate, and the saturation point.
Read those numbers off C12's `/api/metrics` while it runs. See `docs/LEARN.md`.

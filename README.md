# Furix · Gemma MVP — an on-prem security-AI test appliance

A lightweight, enterprise-shaped reproduction of the **15-container Furix security
appliance**, built to **validate our in-house Gemma model** (`gemma4:e4b`,
served at `http://YOUR_GEMMA_HOST:11434`) end-to-end with all **5 AI agents** —
before committing to the full production build.

> **Goal in one line:** prove the deployed Gemma is good enough (accuracy *and*
> capacity) to power Furix's AI reasoning, using realistic synthetic data with
> known ground truth.

---

## The three-repo ecosystem

This MVP is the **appliance**. Two sibling generators (also purpose-built for
Furix) produce the **realistic, labelled test data** we feed into it:

```
  logforge  ──(synthetic correlated LOGS + ground-truth labels)──┐
  (the "watch" half: 22 log sources, attack campaigns)           │
                                                                  ├─▶  furix-gemma-mvp  ─▶  in-house GEMMA
  vulnforge ──(synthetic SCANS + ground-truth labels)────────────┘     (15-container          (gemma4:e4b)
  (the "go look" half: Nessus/nmap, real CVE/KEV/EPSS)                   appliance, 5 agents)
```

| Repo | What it is | Link |
|---|---|---|
| **furix-gemma-mvp** (this) | The appliance under test — 15 containers, 5 AI agents, the AI Brain | *this repo* |
| **logforge** | Synthetic security-log generator. Emits 22 native log formats as *correlated* telemetry + a `labels.jsonl` ground-truth file (benign / malicious / benign_suspicious + MITRE). | https://github.com/saipreethamvudutha/logforge |
| **vulnforge** | Synthetic vulnerability-scan generator grounded in real CVE/KEV/EPSS data. Emits Nessus/nmap findings + a `labels.jsonl` (true priority, was-exploited). Shares logforge's estate so logs and scans correlate. | https://github.com/saipreethamvudutha/vulnforge |

**Why the ground truth matters:** because logforge/vulnforge *generate* the world,
they *know* the right answer for every event. So we can feed their data into the
MVP and **measure** whether Gemma detects the malicious activity and prioritises
the real vulnerabilities — a true accuracy benchmark a real scanner can't give.

---

## What the appliance does

For every security event: **DAL strip → cache → RAG grounding → 5 agents (Gemma) → verdict.**

```
 C2 Vector ─▶ C6 Normaliser ─▶ C14 AI Brain (─▶ C7 GEMMA) ─▶ C8 Storage+Detection ─▶ C9/C10
  (ingest)      (parse/enrich)   (DAL · cache · RAG · 5 agents)   (persist + rules)     (stores)
```

The **5 agents** (each one strict Gemma call): Risk Scorer · Compliance Mapper
(CIS/NIST/HIPAA) · Remediation Generator · Anomaly Detector · Report Generator.

**Two run modes, one codebase:** *lite* (one process = all 15 containers, no infra)
and *real* (`docker compose up` = 15 real containers over Kafka).

---

## Quickstart

### A. Offline self-test (no Gemma needed — verify the plumbing)
```bash
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
cp .env.example .env          # MOCK_LLM defaults to 0; for offline set MOCK_LLM=1
./run.sh                      # → http://localhost:8080
```

### B. Against the real Gemma (the actual purpose) → see **`DEPLOY.md`**
On a machine that can reach `YOUR_GEMMA_HOST` (VPN or in-network):
```bash
cp .env.example .env          # then set GEMMA_BASE_URL to your Gemma endpoint
./run.sh                      # Linux/macOS   (Windows: run.bat)
curl http://localhost:8080/api/health     # expect llm.reachable=true, mode=live
```
Open `http://localhost:8080`, analyze a log, and all 5 agents hit Gemma.

---

## The measurement tools (the point of the MVP)

| Tool | Answers | Command |
|---|---|---|
| `tools/loadtest.py` | **Capacity** — how many calls/sec can Gemma take? (p50/p95/p99, saturation) | `python tools/loadtest.py --concurrency 1,2,4,8 --requests 20` |
| `tools/eval_rag.py` | **Mapping quality** — precision/recall of control mapping | `python tools/eval_rag.py` |
| `tools/forge_feed.py` | **Detection quality** — feed a logforge bundle, score verdicts vs ground truth | `python tools/forge_feed.py --bundle <dir> --limit 100` |
| `tools/batch_ingest.py` | Bulk-ingest many logs | `python tools/batch_ingest.py --samples` |

---

## Status

- ✅ Built + verified in lite mode (all 15 containers, 5 agents, pipeline, tools).
- ✅ Connected to the real Gemma: `gemma4:e4b` reachable over VPN; `/v1/models` confirmed.
- ✅ logforge integration working (`forge_feed.py` ingests a real bundle + scores vs labels).
- ⏳ Next: run the real-Gemma benchmark, add vulnforge ingestion, add cross-log correlation.

## Documentation
| File | For |
|---|---|
| `DEPLOY.md` | Step-by-step deploy against the real Gemma (Windows + Linux + SSH tunnel) |
| `docs/ARCHITECTURE.md` | The 15-container map + data flow + topics |
| `docs/LEARN.md` | Guided code walkthrough + exercises |
| `docs/COURSE-NOTES.md` | Full teaching notes (every component explained) |
| `HANDOVER.md` | One-page handover summary |

## Next steps
1. **Real-Gemma benchmark** — `MOCK_LLM=0`, run `loadtest.py` (capacity) + `forge_feed.py` (detection accuracy).
2. **VulnForge ingestion** — feed `scans/vuln/*.json` via the C3 scan path; score prioritisation.
3. **Cross-log correlation** — group events by `correlation_id`/`session_id` so multi-step attacks are reasoned as a story (biggest detection-quality lever).
4. **Scale** — GPU serving (vLLM), the GBDT "instinct" layer, Kafka partitioning.

*Built to test, not yet to deploy at production scale — see `HANDOVER.md` §Scope.*

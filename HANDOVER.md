# Handover — Furix Gemma MVP

**Prepared for:** Engineering management / whoever picks this up next.
**Repo:** https://github.com/saipreethamvudutha/furix-gemma-mvp (private)

---

## 1. What this is & why it exists

We are evaluating whether our **in-house Gemma model** (`gemma4:e4b`, served on
`http://YOUR_GEMMA_HOST:11434`) is good enough to power **Furix**'s AI reasoning.
Rather than build the full production appliance first, this MVP is a **lightweight
but faithful reproduction of the 15-container Furix architecture** that exercises
the model exactly as production would — through **5 specialised AI agents** — and
**measures** the result.

**The question it answers:** *"Is our Gemma deployment accurate enough and fast
enough to run Furix's detection/compliance reasoning?"*

## 2. The three-repo ecosystem

| Repo | Role |
|---|---|
| **furix-gemma-mvp** (this) | The appliance under test: 15 containers, 5 agents, AI Brain. |
| **logforge** — https://github.com/saipreethamvudutha/logforge | Generates realistic, *correlated* synthetic logs (22 formats, attack campaigns) **with ground-truth labels**. The log input. |
| **vulnforge** — https://github.com/saipreethamvudutha/vulnforge | Generates synthetic vuln scans grounded in real CVE/KEV/EPSS **with ground-truth labels**. The scan input. Shares logforge's estate so logs+scans correlate. |

The generators produce data *with known correct answers*, so we can score the
appliance's verdicts objectively.

## 3. What's delivered (status)

- ✅ **Full appliance**, both run modes: *lite* (one process, no infra) and *real*
  (`docker compose up`, 15 containers over Kafka).
- ✅ **5 AI agents** against Gemma: Risk Scorer, Compliance Mapper (CIS/NIST/HIPAA),
  Remediation Generator, Anomaly Detector, Report Generator — each with strict
  prompts + a privacy layer (DAL) that redacts PII before it reaches the model.
- ✅ **Connected to the real Gemma** — `gemma4:e4b` reachable over the VPN, model
  confirmed via `/v1/models`.
- ✅ **Three measurement tools**: capacity (loadtest), mapping quality (eval_rag),
  detection quality vs ground truth (forge_feed — verified against a real logforge
  bundle).
- ✅ **Full documentation** (architecture, code walkthrough, deploy guide).

## 4. How to run it against Gemma (≈10 min)

Full detail in **`DEPLOY.md`**. Short version, on a machine that can reach
`YOUR_GEMMA_HOST` (VPN or in-network):

```bash
git clone https://github.com/saipreethamvudutha/furix-gemma-mvp.git
cd furix-gemma-mvp
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
cp .env.example .env            # then set GEMMA_BASE_URL to your Gemma endpoint
./run.sh                        # Windows: run.bat
# verify Gemma is wired:
curl http://localhost:8080/api/health     # → "llm": {"reachable": true, "mode": "live"}
```
Then open `http://localhost:8080` (or SSH-tunnel it — see DEPLOY.md §6).

## 5. How to verify it actually works

```bash
# 1. one analysis end-to-end (dashboard) — all 5 agents respond
# 2. capacity:
python tools/loadtest.py --concurrency 1,2,3,4,8 --requests 30
#    → peak req/s, p95 latency, saturation point  (= how to size the GPU/fleet)
# 3. detection accuracy vs ground truth:
#    (generate a bundle in logforge first, then:)
python tools/forge_feed.py --bundle <logforge-bundle> --limit 100
#    → precision/recall of malicious-event detection
```

## 6. Scope & honest limitations (important)

- This MVP's job is to **test the model and measure capacity** — it is **not** a
  production-scale deployment. Lite mode is single-process/in-memory.
- **Not yet built** (needed for production scale): GPU serving (vLLM), the per-
  customer GBDT "instinct" layer (the biggest LLM-call reducer), Kafka
  partitioning + parallel workers, and **cross-log correlation** (today each log is
  analysed independently, so multi-step attack campaigns are under-detected).
- Synthetic data is for bootstrapping/benchmarking; validate against **real**
  Tenable/Nessus + real logs before any production decision.

## 7. Recommended next steps

1. Run the **real-Gemma benchmark** (loadtest + forge_feed) → first hard numbers
   on accuracy + capacity for `gemma4:e4b`.
2. Add **VulnForge ingestion** (C3 scan path) → score vuln prioritisation.
3. Add **cross-log correlation** → the highest-impact detection-quality upgrade.
4. Decide model/hardware sizing from the loadtest's saturation point + the funnel
   math (see `docs/COURSE-NOTES.md` "real-time scale" section).

## 8. File map
```
furix_mvp/            the appliance (containers/ = one module per container, heavily commented)
tools/                loadtest · eval_rag · forge_feed · batch_ingest
docs/                 ARCHITECTURE.md · LEARN.md · COURSE-NOTES.md
deploy/               docker-compose configs (nginx, vector, prometheus, postgres)
DEPLOY.md             deploy-against-Gemma runbook
run.sh / run.bat      one-command launch (Linux-mac / Windows)
```

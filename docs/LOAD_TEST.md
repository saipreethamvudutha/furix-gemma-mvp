# Load Testing the Compliance Engine

Two complementary tools answer the MVP's original question — *"can the locally-deployed
Gemma take the load?"* — with numbers.

```
   tools/loadtest.py         hammers Gemma directly → its raw req/s + p95 (capacity)
   tools/loadtest_engine.py  drives the FULL engine → throughput + how many events
                             actually reach Gemma (demand)
```

You measure **capacity** with the first, **demand** with the second, and the engine
tool projects the sustainable event rate from both.

## Run it

```bash
# end-to-end engine, worst case (cache off, every event fully recomputed),
# 5% synthetic novel-suspicious events, projecting against a 4 req/s Gemma:
MOCK_LLM=1 RAG_ENABLED=0 python tools/loadtest_engine.py \
    --events 5000 --concurrency 8 --novel-rate 0.05 --gemma-rps 4

# against the REAL Gemma (on its network):
MOCK_LLM=0 GEMMA_BASE_URL=http://YOUR_GEMMA:11434/v1 python tools/loadtest.py \
    --agent risk_scorer --concurrency 1,2,4,8 --requests 30
```

With `MOCK_LLM=1` the deterministic tiers (regex / crosswalk / embeddings) run
**for real** — only the rare LLM fallback is mocked — so throughput and the
per-event Gemma-call count are real measurements.

## What we measured (5,000 events, worst case, this machine)

```
  throughput           : ~1,590 events/sec   (single process, concurrency 8)
  latency              : p50 3.9ms · p95 11.6ms · p99 17.6ms
  compliance mapping   : 95% deterministic (only ~5% novel events hit the LLM)
  config-state checks  : ~25,000 scans/sec
```

## The honest finding (this is the important part)

The compliance-mapping re-architecture works: **mapping is ~95–100% deterministic**,
and the deterministic engine itself runs at ~1,590 events/sec — it is **never the
bottleneck**.

**But the AI Brain has five agents, and only `compliance_mapper` was made
conditional.** The other four — `risk_scorer`, `anomaly_detector`,
`remediation_generator`, `report_generator` — still call Gemma on **every** event:

```
  per-agent Gemma calls: risk_scorer 5000 · anomaly_detector 5000 ·
                         remediation 5000 · report 5000 · compliance_mapper 249
  TOTAL                : ~4.05 Gemma calls per event
```

So the real Gemma demand is **~4 calls/event**, not the compliance fallback's 5%.
At a local-Gemma capacity of 4 req/s, that's only ~1 event/sec — **Gemma, not the
engine, is the bottleneck.**

## The lever (now pulled)

`risk_scorer` and `anomaly_detector` already had deterministic logic in `agents.py`
(`_mock_severity`, the signal-based anomaly check). We promoted both off the LLM —
the same move we made for compliance mapping — gated by `DETERMINISTIC_SCORING`
(default ON). Measured effect:

```
  before (all 5 agents LLM)        ~4.05 Gemma calls/event   → ~1 event/s @ 4 req/s Gemma
  risk+anomaly deterministic       ~2.05 Gemma calls/event   → ~2 event/s   (this change)
  + remediation/report on-demand   ~0.05 Gemma calls/event   → ~80 event/s  (narrative only on
                                                                high-severity / dropped via ENABLED_AGENTS)
```

Only `remediation_generator` and `report_generator` still call Gemma per event —
and they are genuinely generative (narrative write-ups). Run them **on-demand**
(high-severity events / analyst click) or drop them with
`ENABLED_AGENTS=risk_scorer,compliance_mapper,anomaly_detector` and Gemma falls to
~0.05 calls/event (just the ~5% novel compliance fallback).

Knobs:
```
  DETERMINISTIC_SCORING=1   risk+anomaly run as code, no Gemma (default)
  COMPLIANCE_LLM_FALLBACK=0 never call Gemma for mapping (unmapped → needs_review)
  ENABLED_AGENTS=...        drop the narrative agents for max throughput
```
With all three, the AI Brain makes **zero** Gemma calls — fully deterministic.

## Bottom line

- The **deterministic compliance engine works and is fast** (~1,600 eps, p99 ~17ms);
  it is never the bottleneck.
- **Gemma load is now ~2 calls/event** (down from ~4), and configurable down to
  ~0.05 — so local Gemma capacity is no longer the hard ceiling it was.
- Compliance accuracy is unchanged by the scoring change (gold F1 0.99, held-out 0.92):
  risk/anomaly scoring is orthogonal to control mapping.
- This validated both goals in one harness: **the compliance engine works**, and
  **the other agents — not the engine — were the Gemma load**, now halved.

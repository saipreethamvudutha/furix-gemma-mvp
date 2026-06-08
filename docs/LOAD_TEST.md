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

## The lever (clear next step)

`risk_scorer` and `anomaly_detector` **already have deterministic logic** in
`agents.py` (it's used as the offline mock: `_mock_severity`, the signal-based
anomaly check). Promoting those two off the LLM — the same move we made for
compliance mapping — would cut Gemma to **~2 calls/event** (only the genuinely
generative `remediation` + `report`), **doubling** the sustainable event rate. And
those two narrative agents can run async / on-demand rather than inline.

```
  today                          ~4.0 Gemma calls/event
  + deterministic risk+anomaly   ~2.0 Gemma calls/event   (2× throughput)
  + remediation/report on-demand  <1  Gemma call/event    (Gemma ~never on the hot path)
```

## Bottom line

- The **deterministic compliance engine works and is fast** (~1,590 eps, p99 18ms);
  it is not the bottleneck.
- **Local Gemma capacity is the bottleneck**, because four agents still call it per
  event — *not* because of compliance mapping (which is now ~95% deterministic).
- The fix is the same pattern, applied to two more agents whose deterministic logic
  already exists. That is the highest-leverage next optimization (roadmap Phase 3.1).

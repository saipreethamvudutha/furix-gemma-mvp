# How we bumped compliance-mapping accuracy from F1 0.67 to 0.99

A plain-English account of what was wrong with control mapping, how we measured
it, what we changed, and why the score jumped — using deterministic code only,
no LLM.

---

## 1. The starting problem

The deterministic mapper was producing bad results across the board: wrong
controls (false positives), missing controls (false negatives), wrong NIST/HIPAA,
and an overall "everything feels random" quality. Benign logs were getting tagged
with controls they had nothing to do with.

The instinct in that situation is to reach back for the LLM. That is the wrong
move. Poor accuracy from deterministic code almost never means "the code can't do
it" — it means one of three assets is weak:

1. the **rules** (keyword/signature matching),
2. the **crosswalk tables** (control → NIST/HIPAA), or
3. the **embedding index** (semantic similarity).

You cannot fix what you cannot see, so the first thing we built was measurement.

---

## 2. The principle: measure before you tune

We built a benchmark so every change could be judged by a number instead of a
gut feel. It lives in `tests/eval/`:

- **`gold_set.jsonl`** — 30 atomic security events (single, unambiguous events),
  each hand-labeled with the *correct* CIS controls. It deliberately includes 4
  **benign** events whose correct answer is "no controls," so we can catch false
  positives.
- **`run_eval.py`** — runs every event through the deterministic resolver and
  reports:
  - **precision / recall / F1** (overall accuracy),
  - a **per-control table** (which controls are over- or under-firing),
  - the **benign false-positive rate** (do clean logs wrongly get controls?),
  - **per-tier attribution** (is the noise coming from the keyword rules or the
    embeddings?), and
  - the **worst false-positive and false-negative events** (what to fix first).

Quick definitions, since these drive everything:

- **Precision** = of the controls we predicted, how many were correct. Low
  precision = too many wrong controls (false positives).
- **Recall** = of the controls that should have been found, how many we found.
  Low recall = missing controls (false negatives).
- **F1** = the single combined score (harmonic mean of the two).

Run it:

```bash
cd "MVP_TEST GEMMA"
MOCK_LLM=1 RAG_ENABLED=0 .venv/bin/python tests/eval/run_eval.py
```

---

## 3. What the benchmark revealed

The baseline came back at **precision 0.60, recall 0.75, F1 0.67, benign FP 2/4.**
The per-control table and worst-offenders list made the causes obvious and
specific — this is the whole point of measuring.

### Cause A — substring matching (the big one)
The keyword rules matched bare substrings anywhere in the text. That is
catastrophic, because real fragments hide inside unrelated words:

| keyword | intended | also matched (wrongly) |
|---|---|---|
| `rce` (remote code execution) | Control 16 App Security | "sou**rce**IPAddress", "event**S**ou**rce**" → fired on almost every log |
| `c2` (command & control) | Control 9 / 13 | "e**c2**.amazonaws.com" → fired on every AWS event |
| `s3`, `bucket` | Control 3 Data Protection | every S3 call, including benign reads |
| `ids` (intrusion detection) | Control 13 | the literal "**IDs:**" label in nmap output |

Control 16's precision was **0.09** — 10 wrong predictions for 1 correct one,
almost entirely from the `rce` substring.

### Cause B — missing rules
Six controls had **no keyword rules at all**: Controls 2, 4, 11, 14, 17, 18. Any
event that belonged to them could never be mapped. That was the source of most
false negatives (e.g. a new-service install, a disabled security policy, a deleted
backup bucket all mapped to nothing).

### Cause C — over-broad rules
Some rules were technically not substrings but still too greedy. Control 15 matched
`amazonaws.com` / `googleapis.com`, so **every cloud event** became "Service
Provider Management" — including the benign read-only API calls. That was the
source of the benign false positives.

---

## 4. What we changed (three measured passes)

We fixed one class of problem at a time and re-ran the benchmark after each, so we
always knew whether a change helped.

### Pass 1 — word boundaries + fill the gaps
- Anchored every short/ambiguous keyword with word boundaries `\b...\b`, so `rce`
  only matches the standalone word "rce", not "sou**rce**". This killed the
  substring false positives.
- Added rules for the 6 missing controls (2, 4, 11, 14, 17, 18).

Example, Control 16:

```
before:  r"sql injection|modsecurity|waf|rce|xss"
after:   r"sql injection|\bsqli\b|modsecurity|\bwaf\b|remote code execution|\brce\b|\bxss\b|directory traversal"
```

Result: **F1 0.67 → 0.83.**

### Pass 2 — tighten the greedy rules, add real signals
- Control 15 no longer matches every cloud domain; it now keys on the actual
  service-provider signals: `iam`, `service account`, `gserviceaccount`,
  `createserviceaccount`, `consolelogin`, `contractor`. This fixed both the
  Control 15 over-firing **and** the benign false positives (benign cloud reads
  stopped matching).
- Added signals the rules were missing: `mfaused` / `without mfa` (a login without
  MFA wasn't matching the bare `\bmfa\b`), `conditional access`, group-add (`4732`),
  and service-account creation (now correctly both Account Management *and* Service
  Provider Management).

Result: **F1 0.83 → 0.97, benign FP 2/4 → 0/4.**

### Pass 3 — one stubborn token
- The IDS/IPS rule still matched the literal "**IDs:**" header inside nmap output.
  We replaced bare `\bids\b` / `\bips\b` with precise markers: `intrusion
  detection`, `intrusion prevention`, `ids/ips`, `nids`, plus specific engine names
  (`suricata`, `zeek`, `eternalblue`, `et exploit/malware/scan`, `signature_id`).

Result: **F1 0.97 → 0.99.**

---

## 5. The results

| pass | what changed | precision | recall | F1 | benign FP |
|---|---|---|---|---|---|
| baseline | substring keywords, 6 controls missing | 0.60 | 0.75 | 0.67 | 2/4 |
| 1 | word boundaries + missing controls | 0.81 | 0.85 | 0.83 | 2/4 |
| 2 | tighten Control 15; add mfa / conditional-access / service-account | 0.95 | 1.00 | 0.97 | 0/4 |
| 3 | fix IDS/IPS token | **0.97** | **1.00** | **0.99** | **0/4** |

The single remaining false positive — a DNS query to `malware-c2.ru` also tagged
Control 10 (Malware Defenses) — is defensible, not a bug. We left it rather than
overfit the rules to the benchmark.

All 7 mapping unit tests still pass, so accuracy went up with no regressions.

---

## 6. How control mapping actually works now

For every event, the resolver (`furix_mvp/mapping.py`) runs deterministic tiers
in order; the LLM is only a last-resort fallback for genuinely novel events.

1. **C6 normaliser** (`containers/c6_normaliser.py`) parses the raw log and runs
   the **keyword/signature rules** (the `KW` map we tuned) to produce
   `rule_controls` — the genuine control matches.
2. **Crosswalk expansion** (`compliance.py`) turns each matched CIS control into
   its NIST CSF subcategories and HIPAA sections by pure table lookup.
3. **Embedding similarity** (`rag.py`, optional) corroborates and fills gaps using
   SecureBERT vectors — ML, but not generative, and deterministic for a fixed
   index.
4. If, and only if, none of the above match, Gemma drafts a reviewable suggestion
   (non-authoritative, flagged `needs_review`).

So the score we improved is the accuracy of step 1 — the rules — which is the
primary matcher and was the weak link. The crosswalk and embedding tiers build on
top of it.

---

## 7. How to keep improving it

The benchmark is now a permanent tool, not a one-time exercise:

1. **Every real failure becomes a test.** When you see the mapper get something
   wrong in practice, add that event to `gold_set.jsonl` with the correct labels.
   It can never silently regress after that.
2. **Always measure before and after.** Edit the `KW` rules or the crosswalk
   tables, then re-run `run_eval.py`. Read the per-tier attribution and the
   worst-FP/FN lists — they tell you exactly which rule to touch.
3. **Turn on the embedding tier and measure it** (`--rag`). It tells you whether
   embeddings add correct controls or add noise, and lets you tune
   `MAPPING_EMBED_FLOOR` with data instead of guesswork.
4. **Never revert to the LLM to "fix accuracy."** Improve the deterministic asset.
   The whole point — and the client's requirement — is that the mapping stays code,
   auditable and repeatable.

---

## 8. Generalization: the held-out benchmark (the honest test)

F1 0.99 above was measured on the SAME 30 events we tuned the rules against. That
risks **overfitting** — scoring the engine on its own answer key. So we built a
second set, `tests/eval/holdout_set.jsonl`: 30 **new** events with different log
types (Okta, Zeek, Palo Alto, O365, GCP, DLP, WAF, ransomware, pen-test, …) and
different phrasing, labeled by control intent and **never used for tuning**.

```bash
MOCK_LLM=1 RAG_ENABLED=0 python tests/eval/run_eval.py --holdout
```

The first held-out run was the reality check:

```
   tuning set (gold)   F1 0.99   ← what we'd been reporting
   held-out (fresh)    F1 0.59   ← the TRUE generalization number
```

Recall collapsed to 0.47: the rules had no coverage for Controls 14 (awareness) and
18 (pen testing) at all, and thin coverage for software-install, account-key,
mail-forwarding, and backup-failure phrasings they'd never seen.

That is exactly what a held-out set is for. We then made a **general coverage pass**
(added Controls 14 & 18, broadened phrasings for 2/3/5/6/11, tightened a couple of
false positives) — improving the rules, NOT relabeling the held-out events to flatter
the score:

```
   held-out F1   0.59 ███████████████░░░░░  before coverage pass
                 0.92 ███████████████████████ after (recall 0.47 -> 0.91, benign FP 1/7 -> 0/7)
   gold F1       still 0.99 (no regression)
```

### Honest caveat (important)
Because we used the held-out failures to improve the rules, that set is now a **dev
set**, not a pristine held-out. The 0.92 is a strong signal that the coverage gaps
were real and general — but the *final* generalization claim needs a **fresh,
larger, independently-labeled** held-out set (roadmap Phase 1.2). The remaining
held-out misses (e.g. gcp-bucket-public → Control 4, cron → Control 10) and the two
borderline FPs (4688→Control 8, DNS-exfil→Control 3) are documented, defensible
edge cases — not silent failures.

**Lesson:** a single high score on your tuning set means little. Always keep a set
the engine has never been tuned on, and report that number.

---

*Files: `tests/eval/gold_set.jsonl`, `tests/eval/holdout_set.jsonl`,
`tests/eval/run_eval.py` (`--holdout`), `furix_mvp/containers/c6_normaliser.py`
(the tuned `KW` rules), `furix_mvp/mapping.py` (the resolver). See
`docs/COMPLIANCE_MAPPING.md` for the full architecture.*

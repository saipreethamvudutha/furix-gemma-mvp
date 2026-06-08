# The Furix Compliance Mapping Engine — Explained Simply

### From the very beginning, end to end. Simple enough for a 10-year-old.

---

## Part 1 — What problem are we even solving?

Imagine your school has **rules**. "Wash your hands." "Don't run in the hall."

Now imagine there are **five different schools**, and each one wrote its own
rulebook. They all care about the same things (safety, cleanliness), but they use
**different words and numbers** for the same rule:

```
   School CIS   says rule  "Control 5"      = "look after who has keys"
   School NIST  says rule  "PR.AA-01"        = "look after who has keys"
   School HIPAA says rule  "164.312(a)"      = "look after who has keys"
```

These rulebooks are real. In computer security they are called **compliance
frameworks**: CIS, NIST, HIPAA, ISO 27001, PCI-DSS.

Now something happens on a computer — say, *somebody created a new user account*.
We need to answer: **which rules, in which rulebooks, does this relate to?**

That job is called **compliance mapping**. Furix does it automatically.

```
   "A new user account was created"   ───►   Which rules does this touch?
                                              CIS Control 5  (Account Management)
                                              NIST PR.AA-01
                                              HIPAA 164.312(a)
```

**That matching is the whole game.** Do it right and a security team instantly
knows which rules an event affects. Do it wrong and they get nonsense.

---

## Part 2 — Why not just ask an AI (an LLM)?

An **LLM** (like ChatGPT, or our local "Gemma") is like a **very clever friend who
loves telling stories**. Ask it anything and it gives a smart-sounding answer.

But it has two problems for rule-matching:

1. **It changes its mind.** Ask the same question twice, you can get two different
   answers.
2. **It sometimes makes things up** (we call this "hallucinating"). It might invent
   a rule that doesn't exist.

For homework that's annoying. For **security and law**, it's a deal-breaker — an
auditor needs an answer that is the **same every time** and that you can **prove**.

Compare:

```
   LLM (clever storyteller)        Code (a vending machine)
   ─────────────────────────       ─────────────────────────
   different answer each time       press B4 → always the SAME snack
   can invent things                can only give what's really inside
   hard to prove                    easy to check, every time
```

The fancy word for "same answer every time" is **deterministic**. Our client
asked: *"do the mapping with code, not the AI."* They were right — and it turns out
the whole security industry already works this way.

> **Key idea:** ML and NLP are not the enemy. The enemy is the *guessing,
> story-telling* part of a generative LLM. We can use smart code (even smart
> machine-learning code) as long as it is deterministic.

---

## Part 3 — The big picture of Furix

Furix is built like a **factory with 15 stations** (we call them containers). A log
(a line describing something that happened) rides a conveyor belt through them.

```
   raw log ─► [C2 receive] ─► [C6 clean & sort] ─┬─► store it
                                                  ├─► run detections
                                                  └─► [C14 AI Brain] ─► verdict
```

The part this document is about lives in **C14, the "AI Brain,"** and the cleaning
station **C6**. That's where compliance mapping happens.

> Think of C6 as the **sorting room** and C14 as the **decision desk**.

---

## Part 4 — The heart: a 4-step waterfall

When an event needs mapping, we don't immediately ask the clever-but-risky AI. We
try **cheap, reliable steps first**, and only fall back to the AI if everything
else fails. Like checking your pockets and your bag before buying a new pencil.

```
                    ┌─────────────────────────────────────────────┐
   an event  ─────► │  STEP 2  KEYWORD RULES                       │
                    │  "If you see the word 'CreateUser' → Box 5"  │
                    └───────────────┬─────────────────────────────┘
                                    │ found a match?
                    ┌───────────────▼─────────────────────────────┐
                    │  STEP 1  CROSSWALK TABLE                      │
                    │  "Box 5 also means NIST PR.AA-01 + HIPAA…"   │
                    └───────────────┬─────────────────────────────┘
                                    │
                    ┌───────────────▼─────────────────────────────┐
                    │  STEP 3  SIMILAR-MEANING SEARCH (embeddings) │
                    │  "This looks a lot like Box 13, by meaning"  │
                    └───────────────┬─────────────────────────────┘
                                    │ STILL nothing, and it looks risky?
                    ┌───────────────▼─────────────────────────────┐
                    │  STEP 4  ASK THE AI (Gemma) — last resort    │
                    │  only a SUGGESTION, a human must check it     │
                    └─────────────────────────────────────────────┘
```

Let's explain each step like you're 10.

### Step 2 — Keyword rules (the checklist)
This is a **checklist**: *"if the event contains the word `CreateUser`, or `4720`,
or `add member`, then it belongs in Box 5 (Account Management)."* Plain "if you see
X, do Y." No thinking, no guessing. Super fast, super reliable.

### Step 1 — The crosswalk table (the translation dictionary)
Once we know it's "Box 5" in the CIS rulebook, a **dictionary** tells us what Box 5
is called in the *other* rulebooks (NIST, HIPAA). It's just a lookup — like using a
French-English dictionary. Humans (and official standards bodies) wrote this
dictionary; we just read it.

### Step 3 — Similar-meaning search (embeddings)
Sometimes the exact keyword isn't there, but the **meaning** is close. Embeddings
turn words into numbers so the computer can measure "how similar in meaning" two
things are — like matching socks by color even if the labels are missing. This is
**machine learning, but it does NOT make things up** — it only *finds the closest
match*, and it gives the same answer every time.

### Step 4 — Ask the AI (only when stuck)
If the event is **brand new AND looks dangerous** and nothing above matched, *only
then* do we ask Gemma — and even then its answer is just a **suggestion stamped
"please double-check."** It is never the final word.

> **Why this order matters:** most events are handled by Steps 1–2 (cheap and
> exact). The expensive, risky AI is almost never needed. That keeps things fast,
> cheap, and trustworthy.

---

## Part 5 — How do we know it's any good? (Testing)

You can't improve what you don't measure. So we built a **report card**.

We made a list of **30 example events** and wrote down, by hand, the **correct
answer** for each (which boxes it really belongs in). This is the "answer key."
Then the engine takes the test and we grade it.

Two grades matter:

```
   PRECISION  =  "Of the boxes you picked, how many were right?"
                  (too many wrong picks = low precision)

   RECALL     =  "Of the boxes you SHOULD have picked, how many did you find?"
                  (missing boxes = low recall)

   F1         =  one combined score (0.00 = terrible, 1.00 = perfect)
```

Simple example: the answer is "Box 5 and Box 6."
- The engine says "Box 5, Box 6, Box 9."
  - It got 5 and 6 right (good!) but also said 9 (wrong). → precision dinged.
- The engine says "Box 5" only.
  - It missed Box 6. → recall dinged.

We also test **benign** (boring, safe) events. The right answer for those is
**"no boxes at all."** If a boring health-check gets tagged with a security rule,
that's a **false alarm** — and we count those too.

The report card tool is `tests/eval/run_eval.py`. It even tells us **which step**
made each mistake, so we know exactly what to fix.

---

## Part 6 — The journey: how the score went up

When we first measured, the score was **mediocre**: F1 **0.67**. Here's the story
of how we got it to **0.99**, and every problem we found along the way.

### Try #1 — We found a sneaky bug: "words hiding inside words"

The keyword checklist was matching letters **anywhere**, even hidden inside other
words. This caused silly mistakes:

```
   Looking for "rce" (short for Remote Code Execution)
   …but "rce" is hiding inside other words!

      sou R C E IPAddress          ← "source" contains "rce"
      event S ou R C E             ← "eventSource" contains "rce"

   So almost EVERY log wrongly got tagged "Application Security".
```

It's like searching for the word **"cat"** and accidentally grabbing
**"lo*cat*ion," "*cat*erpillar," and "s*cat*ter."**

Other examples of the same bug:
- `c2` (a hacker term) was hiding inside "e**c2**.amazonaws.com" → every Amazon
  cloud event looked like a hacker attack.
- `s3` and `bucket` tagged **every** storage action, even safe ones.
- `ids` (intrusion detection) matched the harmless label "**IDs:**" in scan output.

**The fix:** tell the checklist to only match **whole words**, not letters hiding
inside other words. (In code this is called a "word boundary," written `\b`.)

We also discovered **6 boxes had no checklist at all**, so nothing could ever go in
them. We added checklists for those.

➡️ Score jumped **0.67 → 0.83**.

### Try #2 — We stopped one box from grabbing everything

One box ("Service Provider Management") was matching the word `amazonaws.com`, so
**every** cloud event landed in it — even boring ones. We made it only trigger on
the *real* signals (creating accounts, logging into the console without a password
check, etc.).

We also taught it words it was missing, like "MFA" (a login without the extra
security check) and "conditional access."

➡️ Score jumped **0.83 → 0.97**, and false alarms on boring events dropped to
**zero**.

### Try #3 — One last stubborn word

The intrusion-detection rule still matched the harmless "IDs:" label. We swapped it
for precise terms (the actual names of detection tools).

➡️ Score reached **0.99**.

### The score journey at a glance

```
   F1 score   0.67 ███████████████░░░░░░░░░░  start (sneaky bugs)
              0.83 ███████████████████░░░░░░  try #1: whole-words + missing boxes
              0.97 ███████████████████████░░  try #2: stop over-grabbing + add words
              0.99 ████████████████████████░  try #3: last fix
```

| Try | What we changed | Precision | Recall | F1 | False alarms |
|---|---|---|---|---|---|
| start | letters-anywhere matching, 6 boxes empty | 0.60 | 0.75 | 0.67 | 2 of 4 |
| #1 | whole-word matching + fill the 6 empty boxes | 0.81 | 0.85 | 0.83 | 2 of 4 |
| #2 | stop the greedy box + add missing words | 0.95 | 1.00 | 0.97 | 0 of 4 |
| #3 | fix the "IDs:" word | 0.97 | 1.00 | 0.99 | 0 of 4 |

---

## Part 7 — "But did the REAL machine work?" (the best check)

Here's a grown-up lesson that a 10-year-old can understand: **testing a toy model
of something is not the same as testing the real thing.**

Our report card was testing the mapping **brain by itself** (a toy on the bench).
But the real factory has the brain **plus** the decision desk that can call the AI.
So we ran the **whole real machine** on our 30 events. Surprise — two more bugs:

1. **Boring events were waking up the expensive AI.** Any event the checklist
   didn't recognize got sent to Gemma "just in case" — including totally safe
   health-checks. Wasteful and noisy.
   **Fix:** only wake the AI if there's a *real sign of danger*. A calm, safe event
   simply gets "no rules apply" — and the AI stays asleep.

2. **The same "words-inside-words" bug, in a second place** (the danger-signals
   list). `c2` was again matching "e**c2**.amazonaws," making safe Amazon reads
   look dangerous.
   **Fix:** whole-word matching there too.

After the fixes, on the **real, full machine**:

```
   Before this check:   25 of 30 correct,  5 needless AI calls
   After  the fixes:    29 of 30 correct,  0 needless AI calls
```

(The 1 "miss" is a judgment call we agree with, not a bug — a query to a domain
literally named `malware-c2.ru` also counts as "malware defense.")

We then upgraded the report card so it can test the **real machine** too
(`run_eval.py --pipeline`), so this kind of bug can never sneak back.

> **Moral:** always test the real thing, not just the part you think you changed.

---

## Part 8 — When DO we still use the AI?

We didn't ban the AI. We put it in the **right seat**: only for the rare, brand-new,
suspicious event nothing else recognized — and only as a **suggestion a human
checks**. It never gets to be the official answer. Three good jobs remain:

```
   ✔ read a messy log format we have no parser for (turn mush into tidy data)
   ✔ draft a first-guess mapping for a totally new rulebook (human approves)
   ✔ write a friendly summary for a human to read
   ✘ NEVER: be the official, audited mapping (that's always code)
```

---

## Part 9 — What's where (the file map)

```
   furix_mvp/
     containers/c6_normaliser.py   the SORTING ROOM — keyword checklists + signals
     compliance.py                 the TRANSLATION DICTIONARY (crosswalk tables)
     rag.py                        the SIMILAR-MEANING search (embeddings)
     mapping.py                    the WATERFALL — decides Steps 1-4, the brain
     brain.py                      the DECISION DESK — runs it all, calls AI if stuck
     agents.py                     the AI helpers (Gemma) — fallback only

   tests/
     test_mapping.py               8 safety checks (incl. "same answer every time")
     eval/gold_set.jsonl           the ANSWER KEY (30 hand-labeled events)
     eval/run_eval.py              the REPORT CARD (grades the engine)

   docs/
     COMPLIANCE_MAPPING.md         the technical architecture
     ACCURACY_TUNING.md            the deep-dive on the score bump
     COMPLIANCE_ENGINE_EXPLAINED.md  ← you are here (the simple story)
```

---

## Part 10 — The whole thing in one picture

```
            ┌──────────────────────────────────────────────────────────┐
            │                  FURIX COMPLIANCE ENGINE                   │
            └──────────────────────────────────────────────────────────┘

  raw event                                                       answer
     │                                                              ▲
     ▼                                                              │
 ┌────────┐   ┌─────────────────── the 4-step waterfall ─────────┐ │
 │  C6    │   │                                                   │ │
 │ sort & │──►│ 2) keyword rules ─► 1) crosswalk ─► 3) embeddings │─┘
 │ signal │   │            (each step is CODE, same answer always) │
 └────────┘   │                          │                         │
              │                  nothing matched + looks risky?     │
              │                          ▼                          │
              │             4) ask AI (Gemma) — suggestion only,    │
              │                a human checks it. Rarely used.       │
              └───────────────────────────────────────────────────┘

   Result today:  F1 = 0.99   ·   0 false alarms on safe events
                  almost never needs the AI   ·   same answer every time
```

---

## One-paragraph summary (for grown-ups in a hurry)

Furix maps security events to compliance controls using a deterministic, code-first
waterfall: exact keyword rules, then crosswalk-table lookups, then non-generative
embedding similarity, with a local LLM reserved as a non-authoritative,
human-reviewed fallback for novel-and-suspicious events only. We built a labeled
30-event benchmark that measures precision, recall, F1, false-alarm rate, and
per-tier blame. It exposed that crude substring keyword matching (`rce` inside
"source", `c2` inside "ec2") plus six unmapped controls were wrecking accuracy;
fixing those with word-boundary matching and added coverage took F1 from 0.67 to
0.99 with zero benign false positives. Testing the *full* pipeline (not just the
resolver) then caught two more bugs — benign events needlessly invoking the LLM,
and the same substring bug in the signals list — which we fixed, reaching 29/30
end-to-end exact matches with zero LLM calls on the benchmark.

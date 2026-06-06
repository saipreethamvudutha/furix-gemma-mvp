#!/usr/bin/env python3
# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  TOOL · RAG / GROUNDING EVAL — measure control-mapping accuracy             ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# WHAT : Runs each labeled sample log through the SAME grounding the AI Brain uses
#        (RAG if RAG_ENABLED=1, else the deterministic candidate controls), and
#        scores the controls it surfaces against a hand-labeled ground truth.
# WHY  : "How accurate is the RAG?" deserves a number, not a vibe. This is the
#        quality twin of tools/loadtest.py (which measures speed).
# METRICS (per log, then aggregated):
#   precision = correct ÷ predicted   (how much of what we said was right)
#   recall    = correct ÷ expected    (how much of the truth we found)
#   F1        = harmonic mean of the two
#   coverage  = fraction of logs where we found ≥1 expected control
# NOTE : This evaluates the GROUNDING stage (which controls we surface), not the
#        final Gemma decision (that needs a live model). In lite/static mode it
#        scores C6's candidate controls; flip RAG_ENABLED=1 to score the vector path.
#
#   python tools/eval_rag.py
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from furix_mvp import brain, rag                 # noqa: E402
from furix_mvp.containers import c6_normaliser as c6  # noqa: E402
from furix_mvp.dal import DAL                    # noqa: E402
from furix_mvp.samples import SAMPLE_LOGS        # noqa: E402

# Ground truth: the CIS controls a security analyst would expect for each log.
LABELS: dict[str, list[str]] = {
    "syslog_multistage": ["Control 6", "Control 7", "Control 10"],
    "nmap":              ["Control 7"],
    "windows_evtx":      ["Control 5", "Control 10"],
    "aws_cloudtrail":    ["Control 5", "Control 15"],
    "suricata_ids":      ["Control 10", "Control 13"],
    "crowdstrike_edr":   ["Control 5", "Control 10"],
    "okta_sso":          ["Control 6"],
    "dns_tunneling":     ["Control 9", "Control 13"],
}


def predict(log: str) -> list[str]:
    """Exactly the grounding the Brain would use for this log."""
    finding = c6.normalise(log)
    redacted = DAL().strip(log)
    return brain._ground(redacted, finding).get("controls", [])


def prf(pred: set, exp: set) -> tuple[float, float, float, int]:
    tp = len(pred & exp)
    p = tp / len(pred) if pred else 0.0
    r = tp / len(exp) if exp else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f, tp


def main() -> None:
    st = rag.status()
    mode = "RAG (vector+graph)" if st.get("available") else f"STATIC candidates ({st.get('reason')})"
    print(f"# RAG/grounding eval · mode = {mode}\n")
    print(f"{'log':<20}{'P':>6}{'R':>6}{'F1':>6}  expected → predicted")
    print("-" * 78)

    sum_tp = sum_pred = sum_exp = 0
    macro_f = covered = 0
    for key, expected in LABELS.items():
        if key not in SAMPLE_LOGS:
            continue
        pred = set(predict(SAMPLE_LOGS[key]))
        exp = set(expected)
        p, r, f, tp = prf(pred, exp)
        sum_tp += tp; sum_pred += len(pred); sum_exp += len(exp)
        macro_f += f; covered += 1 if tp else 0
        print(f"{key:<20}{p:>6.2f}{r:>6.2f}{f:>6.2f}  {sorted(exp)} → {sorted(pred)}")

    n = len(LABELS)
    micro_p = sum_tp / sum_pred if sum_pred else 0.0
    micro_r = sum_tp / sum_exp if sum_exp else 0.0
    micro_f = 2 * micro_p * micro_r / (micro_p + micro_r) if (micro_p + micro_r) else 0.0
    print("-" * 78)
    print(f"micro  precision={micro_p:.2f}  recall={micro_r:.2f}  F1={micro_f:.2f}")
    print(f"macro  F1={macro_f / n:.2f}   coverage={covered}/{n} logs found ≥1 expected control")
    print("\nReading it: high recall + low precision = broad/noisy grounding (typical of "
          "the C6 candidates).\nThe agent + catalog validation then narrows it to the precise set.")


if __name__ == "__main__":
    main()

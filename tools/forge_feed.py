#!/usr/bin/env python3
# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  TOOL · FORGE FEED — ship a LogForge bundle into the appliance + score it   ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# WHAT : Reads a LogForge bundle (logs/*.log|*.jsonl + labels.jsonl) and feeds the
#        log lines into the MVP via /api/analyze/batch — i.e. it acts as the
#        dev-mode equivalent of C2/Vector (a log shipper). Because LogForge ships
#        GROUND-TRUTH labels (benign / malicious / benign_suspicious), it then
#        JOINS our verdicts back to the labels by event_id and scores detection.
# WHY  : Turns "can we ingest realistic logs and see?" into a measured answer:
#        does our pipeline flag the malicious events and leave the benign alone?
# HONEST NOTES:
#   • In MOCK_LLM=1 the verdicts are deterministic stubs (no real Gemma reasoning),
#     so the score reflects the DETERMINISTIC funnel (C6 signals + mock agents),
#     not your model. Run with MOCK_LLM=0 for a real Gemma detection score.
#   • Our MVP analyses each log INDEPENDENTLY. LogForge's whole value is cross-log
#     CORRELATION (an attack is a story across many benign-looking lines). Real
#     Furix correlates via the C9 graph; expect us to MISS subtle campaign steps —
#     that miss is itself the lesson (why you need the graph, not just signals).
#
#   # 1) generate a bundle (in logforge's own venv):
#   #    logforge generate --industry healthcare --size 50 --days 1 --incidents 1 --out /tmp/lfbundle
#   # 2) start the MVP (./run.sh), then:
#   python tools/forge_feed.py --bundle /tmp/lfbundle --limit 60
from __future__ import annotations
import argparse
import glob
import json
import os
import re
import urllib.request
from pathlib import Path

_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_HEX32 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_JSON_ID_KEYS = ("event_id", "eventID", "ReportId", "id", "auditID")


def _norm(s: str) -> str:
    return re.sub(r"[^0-9a-f]", "", s.lower())


def extract_event_id(line: str) -> str | None:
    """LogForge stamps event_id into a native slot of each format. Pull it out:
    JSON → a known key (or falco's output_fields.evt.id); text/XML → a GUID
    (Windows ActivityID) or a 32-hex tail (PAN-OS/DHCP). Normalise to 32-hex."""
    s = line.strip()
    if s.startswith("{"):
        try:
            o = json.loads(s)
            for k in _JSON_ID_KEYS:
                if isinstance(o.get(k), str):
                    return _norm(o[k])
            evt = (o.get("output_fields") or {}).get("evt.id")
            if isinstance(evt, str):
                return _norm(evt)
        except json.JSONDecodeError:
            pass
    m = _GUID.search(s) or _HEX32.search(s)
    return _norm(m.group(0)) if m else None


def load_logs(bundle: str) -> list[dict]:
    out = []
    for f in sorted(glob.glob(os.path.join(bundle, "logs", "*"))):
        src = Path(f).stem
        for line in open(f, encoding="utf-8", errors="replace"):
            line = line.rstrip("\n")
            if line.strip():
                out.append({"source": src, "raw": line, "event_id": extract_event_id(line)})
    return out


def load_labels(bundle: str) -> dict[str, dict]:
    labels = {}
    p = os.path.join(bundle, "labels.jsonl")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            try:
                o = json.loads(line)
                labels[_norm(o["event_id"])] = o
            except (json.JSONDecodeError, KeyError):
                pass
    return labels


def label_of(log: dict, labels: dict) -> str:
    return labels.get(log["event_id"] or "", {}).get("label", "unlabeled")


def sample(logs, labels, limit, take_all):
    """Keep ALL malicious + suspicious (they're rare and the point), plus a
    capped sample of benign — so the demo always shows the interesting events."""
    if take_all:
        return logs
    mal = [l for l in logs if label_of(l, labels) == "malicious"]
    sus = [l for l in logs if label_of(l, labels) == "benign_suspicious"]
    ben = [l for l in logs if label_of(l, labels) == "benign"][:limit]
    return mal + sus + ben


def post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=1200) as r:
        return json.loads(r.read().decode())


def main() -> None:
    ap = argparse.ArgumentParser(description="Feed a LogForge bundle into the MVP + score detection")
    ap.add_argument("--bundle", required=True, help="path to a logforge bundle dir")
    ap.add_argument("--url", default="http://localhost:8080")
    ap.add_argument("--limit", type=int, default=60, help="benign logs to sample (malicious always kept)")
    ap.add_argument("--all", action="store_true", help="feed EVERY log (ignores --limit)")
    args = ap.parse_args()

    logs = load_logs(args.bundle)
    labels = load_labels(args.bundle)
    fed = sample(logs, labels, args.limit, args.all)
    counts = {"malicious": 0, "benign_suspicious": 0, "benign": 0, "unlabeled": 0}
    for l in fed:
        counts[label_of(l, labels)] = counts.get(label_of(l, labels), 0) + 1
    print(f"bundle: {args.bundle}")
    print(f"loaded {len(logs)} logs, {len(labels)} labels; feeding {len(fed)} "
          f"({counts['malicious']} malicious, {counts['benign_suspicious']} suspicious, "
          f"{counts['benign']} benign)\n")

    resp = post(f"{args.url}/api/analyze/batch",
                {"logs": [l["raw"] for l in fed], "mode": "direct"})
    results = resp["results"]

    # JOIN: our verdict (in input order) ↔ the ground-truth label
    tp = fp = fn = tn = 0
    sus_alerted = 0
    caught = []
    for log, res in zip(fed, results):
        truth = label_of(log, labels)
        v = res["verdict"]
        alerted = v["severity"] in ("critical", "high") or v.get("is_anomaly")
        if truth == "malicious":
            if alerted: tp += 1; caught.append((log["source"], labels[log["event_id"]].get("mitre_technique"), v["severity"]))
            else:       fn += 1
        elif truth == "benign":
            fp += 1 if alerted else 0
            tn += 0 if alerted else 1
        elif truth == "benign_suspicious":
            sus_alerted += 1 if alerted else 0

    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    mode = resp.get("mode")
    print(f"# Detection score (mode={mode}) — 'alert' = severity≥high OR anomaly")
    print(f"  malicious caught (TP) : {tp}")
    print(f"  malicious missed (FN) : {fn}   ← the subtle campaign steps (correlation gap)")
    print(f"  benign false-alarm(FP): {fp}")
    print(f"  benign clean     (TN) : {tn}")
    print(f"  suspicious alerted    : {sus_alerted}/{counts['benign_suspicious']} (the grey zone)")
    print(f"  precision={prec:.2f}  recall={rec:.2f}")
    if caught:
        print("\n  sample malicious events we caught:")
        for src, tech, sev in caught[:6]:
            print(f"    [{src:<22}] {tech or '-':<12} → {sev}")
    print("\nReminder: MOCK_LLM=1 scores the deterministic funnel, not Gemma. "
          "Run with MOCK_LLM=0 for a real model score.\nMisses are expected — we "
          "analyse each log alone; campaign detection needs cross-log correlation (the C9 graph).")


if __name__ == "__main__":
    main()

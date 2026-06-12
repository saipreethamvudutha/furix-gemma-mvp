#!/usr/bin/env python3
"""
jsonl_to_ecs.py - Convert Coventra-style security JSONL logs to Elastic Common Schema (ECS).

Why this is reliable
---------------------
1. Defensive   : every field access uses .get(); no record shape can abort the run.
2. Lossless    : recognized fields map to first-class ECS fields; ANY unrecognized
                 metadata key is preserved under ``labels.*`` and the verbatim source
                 line is kept in ``event.original``. Nothing is silently dropped, so the
                 converter keeps working even when new/unknown fields appear.
3. Isolated    : a record that fails to convert is still emitted as a minimal ECS doc
                 tagged ``_ecs_conversion_failure`` (with the original line + the error),
                 so input and output line counts always match and failures are auditable.

Targets ECS 8.11. Pure standard library - no dependencies.

Usage
-----
    python3 jsonl_to_ecs.py INPUT.jsonl [-o OUTPUT.ecs.jsonl]
                                        [--report] [--preview N]
                                        [--limit N] [--fail-fast]

If -o is omitted, output is written next to the input as ``<input>.ecs.jsonl``.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter

ECS_VERSION = "8.11.0"

# --------------------------------------------------------------------------- #
# Per-category configuration.
#   role     : "observer" for network appliances that watch traffic between other
#              parties (firewall, email gateway); "host" for systems where the event
#              actually happened (db, app, endpoint, ...).
#   category : default ECS event.category list.
#   type     : default ECS event.type list.
# Unknown categories fall back to DEFAULT_CFG and still convert cleanly.
# --------------------------------------------------------------------------- #
CATEGORY_CONFIG = {
    "firewall":       {"role": "observer", "category": ["network"],        "type": ["connection"]},
    "email":          {"role": "observer", "category": ["email"],          "type": ["info"]},
    "web_server":     {"role": "host",     "category": ["web"],            "type": ["access"]},
    "application":    {"role": "host",     "category": ["web"],            "type": ["access"]},
    "database":       {"role": "host",     "category": ["database"],       "type": ["access"]},
    "endpoint":       {"role": "host",     "category": ["process"],        "type": ["info"]},
    "authentication": {"role": "host",     "category": ["authentication"], "type": ["info"]},
    "cloud":          {"role": "host",     "category": ["api"],            "type": ["info"]},
}
DEFAULT_CFG = {"role": "host", "category": [], "type": ["info"]}

# Numeric severity for log levels (free-form scale; higher = worse).
SEVERITY = {
    "DEBUG": 1, "INFO": 2, "NOTICE": 3, "WARN": 4, "WARNING": 4,
    "ERROR": 6, "ERR": 6, "CRITICAL": 8, "CRIT": 8, "ALERT": 9, "EMERGENCY": 10,
}

SUCCESS_WORDS = {"success", "allow", "allowed", "accept", "accepted",
                 "delivered", "granted", "ok", "pass", "passed"}
FAILURE_WORDS = {"failure", "fail", "failed", "deny", "denied", "blocked",
                 "quarantined", "reject", "rejected", "drop", "dropped", "error"}
TRANSPORTS = {"tcp", "udp", "icmp"}


# --------------------------------------------------------------------------- #
# Small helpers for building a nested ECS document safely.
# --------------------------------------------------------------------------- #
def set_field(doc, path, value):
    """Set doc[a][b][c] = value, creating intermediate dicts. Skips empty values."""
    if value is None:
        return
    if isinstance(value, str) and value == "":
        return
    if isinstance(value, (list, dict)) and len(value) == 0:
        return
    parts = path.split(".")
    node = doc
    for p in parts[:-1]:
        nxt = node.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            node[p] = nxt
        node = nxt
    node[parts[-1]] = value


def append_unique(doc, path, value):
    """Append value (or each item of a list) to a list field, de-duplicated."""
    if value is None or value == "":
        return
    parts = path.split(".")
    node = doc
    for p in parts[:-1]:
        nxt = node.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            node[p] = nxt
        node = nxt
    lst = node.get(parts[-1])
    if not isinstance(lst, list):
        lst = []
        node[parts[-1]] = lst
    for v in (value if isinstance(value, list) else [value]):
        if v not in lst:
            lst.append(v)


def add_tag(doc, tag):
    append_unique(doc, "tags", tag)


_LABEL_KEY = re.compile(r"[.\s]+")


def add_label(doc, key, value):
    """Preserve an arbitrary key/value under labels.* (the ECS-sanctioned catch-all)."""
    if value is None or value == "":
        return
    safe = _LABEL_KEY.sub("_", str(key)).strip("_")
    if not safe:
        return
    if isinstance(value, (dict, list)):
        value = json.dumps(value, separators=(",", ":"), sort_keys=True)
    doc.setdefault("labels", {})[safe] = value


def is_ip(v):
    if not isinstance(v, str):
        return False
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return None


def ms_to_ns(v):
    """ECS event.duration is in nanoseconds; inputs here are milliseconds."""
    try:
        return int(round(float(v) * 1_000_000))
    except (TypeError, ValueError):
        return None


def vendor_of(name):
    if not name:
        return None
    n = str(name).lower()
    if "palo" in n:
        return "Palo Alto Networks"
    if "proofpoint" in n:
        return "Proofpoint"
    if "duo" in n:
        return "Cisco"
    return None


def set_outcome_from_word(doc, word):
    w = str(word).strip().lower()
    if w in SUCCESS_WORDS:
        set_field(doc, "event.outcome", "success")
    elif w in FAILURE_WORDS:
        set_field(doc, "event.outcome", "failure")


def set_outcome_from_status(doc, code):
    if code is None:
        return
    if 100 <= code < 400:
        set_field(doc, "event.outcome", "success")
    elif 400 <= code < 600:
        set_field(doc, "event.outcome", "failure")


def set_action(doc, val):
    s = str(val).strip()
    set_field(doc, "event.action", s.lower().replace(" ", "_"))
    set_outcome_from_word(doc, s)
    low = s.lower()
    if low in ("allow", "allowed", "accept", "accepted", "delivered"):
        append_unique(doc, "event.type", "allowed")
    elif low in ("deny", "denied", "blocked", "drop", "dropped", "quarantined"):
        append_unique(doc, "event.type", "denied")


def set_action_if_absent(doc, val):
    if not doc.get("event", {}).get("action"):
        set_field(doc, "event.action", str(val).strip().lower().replace(" ", "_"))


def map_protocol(doc, val):
    p = str(val).strip().lower()
    if p in TRANSPORTS:
        set_field(doc, "network.transport", p)
    elif p == "https":
        set_field(doc, "network.protocol", "https")
        set_field(doc, "network.transport", "tcp")
    elif p in ("ssh", "rdp", "smb", "http"):
        set_field(doc, "network.protocol", p)
        set_field(doc, "network.transport", "tcp")
    else:  # dns and anything else: record as application protocol, no forced transport
        set_field(doc, "network.protocol", p)


# --------------------------------------------------------------------------- #
# Metadata mapping.  Keys are semantically consistent across categories in this
# feed, so one mapping covers every category.  Anything not handled explicitly
# is preserved under labels.* (and boolean-true flags also become tags).
# --------------------------------------------------------------------------- #
def map_metadata(doc, md, category):
    for key, val in md.items():
        if val is None:
            continue
        k = str(key).lower()

        if k == "log_category":
            continue  # already represented by event.module / event.dataset
        elif k == "anomaly":
            if val:
                add_tag(doc, "anomaly")

        # --- network endpoints ---
        elif k in ("src_ip", "client_ip", "attacker_ip"):
            if is_ip(val):
                set_field(doc, "source.ip", val)
            else:
                add_label(doc, key, val)
            if k == "attacker_ip":
                add_tag(doc, "attacker")
        elif k == "src_port":
            set_field(doc, "source.port", to_int(val))
        elif k == "src_host":
            set_field(doc, "source.domain", val)
        elif k == "dst_ip":
            if is_ip(val):
                set_field(doc, "destination.ip", val)
            else:
                add_label(doc, key, val)
        elif k == "dst_port":
            set_field(doc, "destination.port", to_int(val))
        elif k in ("dst_host", "target_host"):
            set_field(doc, "destination.domain", val)

        # --- bytes / protocol ---
        elif k == "bytes_sent":
            n = to_int(val)
            set_field(doc, "source.bytes", n)
            set_field(doc, "network.bytes", n)
        elif k == "protocol":
            map_protocol(doc, val)

        # --- http / url ---
        elif k == "method":
            # 'method' is an HTTP verb for web/app, but an auth mechanism elsewhere.
            if category in ("web_server", "application"):
                set_field(doc, "http.request.method", str(val).upper())
            else:
                add_label(doc, "auth_method", val)
        elif k == "path":
            set_field(doc, "url.path", val)
        elif k == "status":
            sc = to_int(val)
            set_field(doc, "http.response.status_code", sc)
            set_outcome_from_status(doc, sc)
        elif k in ("response_ms", "duration_ms"):
            set_field(doc, "event.duration", ms_to_ns(val))

        # --- identity ---
        elif k in ("user", "iam_user", "actor"):
            if not doc.get("user", {}).get("name"):
                set_field(doc, "user.name", val)
            elif doc["user"]["name"] != val:
                add_label(doc, key, val)
        elif k == "target_user":
            set_field(doc, "user.target.name", val)

        # --- actions / outcomes ---
        elif k == "action":
            set_action(doc, val)
        elif k == "result":
            set_outcome_from_word(doc, val)
            add_label(doc, "result", val)  # keep the raw verb
        elif k in ("operation", "event_name", "api", "api_operation",
                   "action_type", "pam_action"):
            set_action_if_absent(doc, val)
            if k != "operation":
                add_label(doc, key, val)

        # --- windows-style event id ---
        elif k == "event_id":
            set_field(doc, "event.code", str(val))

        # --- dns ---
        elif k == "query_domain":
            set_field(doc, "dns.question.name", val)
        elif k == "query_type":
            set_field(doc, "dns.question.type", val)

        # --- cloud ---
        elif k == "region":
            set_field(doc, "cloud.region", val)

        # --- firewall rule ---
        elif k == "rule":
            set_field(doc, "rule.name", val)

        # --- email ---
        elif k == "sender":
            set_field(doc, "email.from.address", [val] if "@" in str(val) else val)
        elif k == "recipient":
            set_field(doc, "email.to.address", [val] if "@" in str(val) else val)
        elif k == "attachment":
            set_field(doc, "email.attachments", [{"file": {"name": val}}])

        # --- everything else: preserve losslessly ---
        else:
            add_label(doc, key, val)
            if val is True:
                add_tag(doc, k)


def map_mitre(doc, m):
    set_field(doc, "threat.framework", "MITRE ATT&CK")
    tech = m.get("technique")
    name = m.get("name")
    if tech:
        t = str(tech)
        if "." in t:
            # Sub-technique: mirror Elastic's structure - parent id on technique,
            # full id+name on subtechnique. The feed only gives the leaf name, so
            # the parent technique.name is intentionally left unset.
            append_unique(doc, "threat.technique.id", t.split(".")[0])
            append_unique(doc, "threat.technique.subtechnique.id", t)
            if name:
                append_unique(doc, "threat.technique.subtechnique.name", name)
        else:
            append_unique(doc, "threat.technique.id", t)
            if name:
                append_unique(doc, "threat.technique.name", name)
    tactic = m.get("tactic")
    if tactic:
        for part in str(tactic).split("/"):
            part = part.strip()
            if not part:
                continue
            toks = part.split(None, 1)
            tid, tname = toks[0], (toks[1] if len(toks) > 1 else None)
            if re.fullmatch(r"TA\d+", tid):
                append_unique(doc, "threat.tactic.id", tid)
                if tname:
                    append_unique(doc, "threat.tactic.name", tname)
            else:
                append_unique(doc, "threat.tactic.name", part)
    desc = m.get("description")
    if desc:
        set_field(doc, "event.reason", desc)


# --------------------------------------------------------------------------- #
# Top-level conversion.
# --------------------------------------------------------------------------- #
def convert(record, raw_line):
    """Convert one parsed log record into an ECS document. Returns (doc, category)."""
    doc = {}
    set_field(doc, "ecs.version", ECS_VERSION)

    ts = record.get("timestamp")
    set_field(doc, "@timestamp", ts)
    if not ts:
        add_tag(doc, "_missing_timestamp")

    set_field(doc, "message", record.get("message"))

    level = record.get("level")
    if level:
        set_field(doc, "log.level", str(level).lower())
        set_field(doc, "event.severity", SEVERITY.get(str(level).upper()))

    src = record.get("source") or {}
    md = record.get("metadata") or {}
    category = src.get("type") or (md.get("log_category") if isinstance(md, dict) else None) or "unknown"
    category = str(category).lower()
    cfg = CATEGORY_CONFIG.get(category, DEFAULT_CFG)

    set_field(doc, "organization.name", src.get("org"))

    host, ip, name, zone = src.get("host"), src.get("ip"), src.get("name"), src.get("zone")
    if cfg["role"] == "observer":
        set_field(doc, "observer.name", host)
        set_field(doc, "observer.hostname", host)
        if is_ip(ip):
            set_field(doc, "observer.ip", [ip])
        set_field(doc, "observer.product", name)
        set_field(doc, "observer.type", category)
        set_field(doc, "observer.vendor", vendor_of(name))
        set_field(doc, "observer.ingress.zone", zone)
    else:
        set_field(doc, "host.name", host)
        if is_ip(ip):
            set_field(doc, "host.ip", [ip])
        set_field(doc, "service.name", name)
        set_field(doc, "service.type", category)
        add_label(doc, "source_zone", zone)

    set_field(doc, "event.module", category)
    set_field(doc, "event.dataset", "security." + category)
    for c in cfg["category"]:
        append_unique(doc, "event.category", c)
    for t in cfg["type"]:
        append_unique(doc, "event.type", t)

    log_type = record.get("log_type")
    set_field(doc, "event.kind", "alert" if log_type == "anomaly" else "event")
    add_label(doc, "log_type", log_type)

    if isinstance(md, dict):
        map_metadata(doc, md, category)

    mitre = record.get("mitre")
    if isinstance(mitre, dict):
        map_mitre(doc, mitre)

    set_field(doc, "event.original", raw_line)
    return doc, category


def fallback_doc(raw_line, err, record=None):
    """Minimal, valid ECS doc for a record we could not fully convert."""
    doc = {}
    set_field(doc, "ecs.version", ECS_VERSION)
    set_field(doc, "event.kind", "event")
    set_field(doc, "event.original", raw_line)
    set_field(doc, "error.message", str(err))
    add_tag(doc, "_ecs_conversion_failure")
    if isinstance(record, dict):  # salvage whatever we can
        set_field(doc, "@timestamp", record.get("timestamp"))
        set_field(doc, "message", record.get("message"))
    return doc


# --------------------------------------------------------------------------- #
# CLI / driver.
# --------------------------------------------------------------------------- #
def run(in_path, out_path, limit=None, fail_fast=False, preview=0):
    stats = Counter()
    by_category = Counter()

    with open(in_path, "r", encoding="utf-8", errors="replace") as fin, \
            open(out_path, "w", encoding="utf-8") as fout:
        for lineno, line in enumerate(fin, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            if limit and stats["total"] >= limit:
                break
            stats["total"] += 1

            record = None
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError("line is not a JSON object")
                doc, category = convert(record, line)
                stats["ok"] += 1
                by_category[category] += 1
                if record.get("log_type") == "anomaly":
                    stats["anomalies"] += 1
            except Exception as err:  # never let one bad line stop the run
                if fail_fast:
                    sys.stderr.write(f"[FATAL] line {lineno}: {err}\n")
                    raise
                doc = fallback_doc(line, err, record)
                stats["failed"] += 1
                by_category["_failed"] += 1

            if preview and stats["total"] <= preview:
                sys.stderr.write(json.dumps(doc, ensure_ascii=False, indent=2) + "\n")

            fout.write(json.dumps(doc, ensure_ascii=False) + "\n")

    return stats, by_category


def main(argv=None):
    ap = argparse.ArgumentParser(description="Convert JSONL security logs to ECS.")
    ap.add_argument("input", help="Path to input .jsonl file")
    ap.add_argument("-o", "--output", help="Output path (default: <input>.ecs.jsonl)")
    ap.add_argument("--report", action="store_true", help="Print a conversion summary")
    ap.add_argument("--preview", type=int, default=0, metavar="N",
                    help="Pretty-print the first N converted docs to stderr")
    ap.add_argument("--limit", type=int, default=None, help="Convert only the first N records")
    ap.add_argument("--fail-fast", action="store_true",
                    help="Abort on the first conversion error instead of emitting a fallback doc")
    args = ap.parse_args(argv)

    out_path = args.output
    if not out_path:
        out_path = re.sub(r"\.jsonl$", "", args.input) + ".ecs.jsonl"

    stats, by_category = run(args.input, out_path, args.limit, args.fail_fast, args.preview)

    if args.report:
        sys.stderr.write("\n=== ECS conversion report ===\n")
        sys.stderr.write(f"input          : {args.input}\n")
        sys.stderr.write(f"output         : {out_path}\n")
        sys.stderr.write(f"records total  : {stats['total']}\n")
        sys.stderr.write(f"converted ok   : {stats['ok']}\n")
        sys.stderr.write(f"  - anomalies  : {stats['anomalies']} (event.kind=alert)\n")
        sys.stderr.write(f"failed/fallback: {stats['failed']}\n")
        sys.stderr.write("by category    :\n")
        for cat, n in sorted(by_category.items(), key=lambda kv: -kv[1]):
            sys.stderr.write(f"    {cat:16s} {n}\n")
        rate = (stats["ok"] / stats["total"] * 100) if stats["total"] else 0.0
        sys.stderr.write(f"success rate   : {rate:.2f}%\n")

    return 0 if stats["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

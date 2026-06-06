"""CONTAINER C14 · Data Abstraction Layer (DAL) — strip PII before prompts reach Gemma.

Mirrors furix C14's DAL: deterministic tokenization of identifiers into stable
placeholders, with an in-memory token map for re-hydration after inference.
The LLM only ever sees placeholders ({IPV4_001}, {HOST_001}, ...).

Two redaction strategies (Lesson 4.5):
  1. REGEX redaction (strip)     — pattern-matched identifiers in free text.
  2. FIELD-AWARE redaction (tokenize) — force a placeholder for a value we KNOW
     is sensitive because of the field it came from (e.g. entities.usernames).
     Usernames look like ordinary words ("root"), so no regex can catch them —
     but we know the field, so we redact by field, not by pattern. This is how
     real furix does it (graph node-property markers).
"""
from __future__ import annotations
import re

from . import config

# ── INFRASTRUCTURE rules — always on (this is a SIEM; these live in every log) ─
# Order matters: most specific first so emails aren't shredded into hostnames.
_INFRA_RULES: list[tuple[str, str]] = [
    ("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ("MAC",   r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    # IPv6 must contain a hex letter so HH:MM:SS timestamps are never matched.
    ("IPV6",  r"\b(?=[0-9A-Fa-f:]*[A-Fa-f])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}\b"),
    ("IPV4",  r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ("HOST",  r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|corp|local|internal|onmicrosoft\.com|gserviceaccount\.com)\b"),
    ("SECRET", r"\b(?:sk-[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{12,}|eyJ[A-Za-z0-9_-]{10,})\b"),
]

# ── HIPAA Safe Harbor rules — OPT-IN (config.DAL_HIPAA_MODE) ──────────────────
# WHY opt-in: these patterns (esp. DATE) over-match in security logs — a log
# timestamp would be redacted as a "date of birth". They belong ON only when the
# data being analysed is healthcare/PHI, not network telemetry. Covers the
# regex-detectable subset of HIPAA's 18 identifiers; the non-pattern ones (names,
# MRN, account #) are handled by FIELD-AWARE tokenize() instead.
_HIPAA_PRE: list[tuple[str, str]] = [               # run BEFORE infra (URLs wrap hosts)
    ("URL",   r"\bhttps?://[^\s\"'<>]+"),
]
_HIPAA_POST: list[tuple[str, str]] = [              # run AFTER infra (no conflicts)
    ("SSN",   r"\b\d{3}-\d{2}-\d{4}\b"),
    ("PHONE", r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),   # phone+fax
    ("DATE",  r"\b(?:19|20)\d{2}[-/]\d{1,2}[-/]\d{1,2}\b|\b\d{1,2}[-/]\d{1,2}[-/](?:19|20)\d{2}\b"),
    ("VIN",   r"\b[A-HJ-NPR-Z0-9]{17}\b"),
]


class DAL:
    def __init__(self, hipaa_mode: bool | None = None) -> None:
        self._fwd: dict[str, str] = {}   # original -> placeholder
        self._rev: dict[str, str] = {}   # placeholder -> original
        self._counter: dict[str, int] = {}
        hipaa = config.DAL_HIPAA_MODE if hipaa_mode is None else hipaa_mode
        # Build the active rule set: HIPAA URL → infra → HIPAA numerics.
        self._rules = (_HIPAA_PRE + _INFRA_RULES + _HIPAA_POST) if hipaa else _INFRA_RULES

    def _placeholder(self, kind: str, original: str) -> str:
        if original in self._fwd:                # SAME value → SAME placeholder
            return self._fwd[original]
        self._counter[kind] = self._counter.get(kind, 0) + 1
        ph = "{%s_%03d}" % (kind, self._counter[kind])
        self._fwd[original] = ph
        self._rev[ph] = original
        return ph

    # ── Strategy 1: regex redaction over free text ───────────────────────────
    def strip(self, text: str) -> str:
        out = text
        for kind, pat in self._rules:
            out = re.sub(pat, lambda m, k=kind: self._placeholder(k, m.group(0)), out)
        return out

    # ── Strategy 2: field-aware redaction (no pattern needed) ────────────────
    def tokenize(self, value, kind: str) -> str:
        """Force a placeholder for a value we KNOW is sensitive by its field.
        Used for usernames, names, MRNs — things no regex can reliably spot."""
        value = str(value)
        return self._placeholder(kind, value) if value else value

    def rehydrate(self, text: str) -> str:
        if not text:
            return text
        for ph, original in self._rev.items():
            text = text.replace(ph, original)
        return text

    def rehydrate_obj(self, obj):
        if isinstance(obj, str):
            return self.rehydrate(obj)
        if isinstance(obj, list):
            return [self.rehydrate_obj(x) for x in obj]
        if isinstance(obj, dict):
            return {k: self.rehydrate_obj(v) for k, v in obj.items()}
        return obj

    @property
    def token_map(self) -> dict[str, str]:
        return dict(self._rev)

    def report(self) -> dict:
        by_kind: dict[str, int] = {}
        for ph in self._rev:
            kind = ph.strip("{}").rsplit("_", 1)[0]
            by_kind[kind] = by_kind.get(kind, 0) + 1
        return {"redacted_count": len(self._rev), "by_kind": by_kind}

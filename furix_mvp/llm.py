"""CONTAINER C7 · vLLM/Gemma client (OpenAI-compatible) + resilient JSON parsing.

One thin call surface for every agent. Talks to the in-house Gemma endpoint
(Ollama / vLLM /v1). MOCK_LLM=1 short-circuits to a caller-supplied stub so the
full pipeline runs offline for verification.
"""
from __future__ import annotations
import json
import re
import time
from typing import Any, Optional

from openai import OpenAI

from . import config

_client = OpenAI(base_url=config.GEMMA_BASE_URL, api_key=config.GEMMA_API_KEY,
                 timeout=config.GEMMA_TIMEOUT)


# ── JSON recovery (ported from CIS_NIST_HIPAA reference) ─────────────────────
def _repair_truncated_json(text: str) -> str:
    start = text.find("{")
    if start == -1:
        return text
    text = text[start:]
    in_str = esc = False
    for ch in text:
        if esc:
            esc = False; continue
        if ch == "\\":
            esc = True; continue
        if ch == '"':
            in_str = not in_str
    if in_str:
        text += '"'
    db = dbk = 0
    in_str = esc = False
    for ch in text:
        if esc:
            esc = False; continue
        if ch == "\\":
            esc = True; continue
        if ch == '"':
            in_str = not in_str; continue
        if in_str:
            continue
        db += ch == "{"; db -= ch == "}"
        dbk += ch == "["; dbk -= ch == "]"
    return text + "]" * max(0, dbk) + "}" * max(0, db)


def parse_json(raw: str) -> tuple[dict, Optional[str]]:
    """Best-effort JSON extraction. Returns (obj, error_or_None)."""
    clean = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.MULTILINE)
    clean = re.sub(r"\s*```$", "", clean, flags=re.MULTILINE).strip()
    try:
        return json.loads(clean), None
    except json.JSONDecodeError:
        pass
    m = re.search(r"(\{[\s\S]*\})", clean)
    if m:
        try:
            return json.loads(m.group(1)), None
        except json.JSONDecodeError:
            pass
    try:
        return json.loads(_repair_truncated_json(clean)), None
    except json.JSONDecodeError as e:
        return {}, f"json_parse_failed: {e}"


class LLMResult(dict):
    """A dict subclass carrying parse meta on attributes."""
    latency_ms: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    source: str = "llm"
    error: Optional[str] = None


def complete_json(system: str, user: str, *, max_tokens: Optional[int] = None,
                  mock: Optional[dict] = None) -> LLMResult:
    """Single JSON-returning Gemma call with retry + recovery.

    `mock` is returned verbatim when MOCK_LLM=1 (offline verification path).
    """
    t0 = time.time()
    if config.MOCK_LLM:
        r = LLMResult(mock or {})
        r.source = "mock"; r.latency_ms = int((time.time() - t0) * 1000)
        return r

    last_err = "unknown"
    for attempt in range(3):
        try:
            kwargs = dict(
                model=config.GEMMA_MODEL,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}],
                temperature=config.GEMMA_TEMPERATURE + attempt * 0.05,
                max_tokens=max_tokens or config.GEMMA_MAX_TOKENS,
            )
            # Forced JSON mode makes some Ollama+model combos return an EMPTY
            # completion. Off by default — the prompts mandate JSON and
            # parse_json() recovers it (fences, {...} extraction, repair).
            if config.GEMMA_JSON_MODE:
                kwargs["response_format"] = {"type": "json_object"}
            resp = _client.chat.completions.create(**kwargs)
            text = (resp.choices[0].message.content or "").strip()
            obj, err = parse_json(text)
            if obj:
                r = LLMResult(obj)
                r.latency_ms = int((time.time() - t0) * 1000)
                r.error = err
                u = getattr(resp, "usage", None)
                if u:
                    r.prompt_tokens = u.prompt_tokens or 0
                    r.completion_tokens = u.completion_tokens or 0
                return r
            last_err = err or "empty_response"
        except Exception as e:  # noqa: BLE001 — network/endpoint errors
            last_err = str(e)
            time.sleep(1.0)
    r = LLMResult()
    r.error = last_err; r.source = "fallback"
    r.latency_ms = int((time.time() - t0) * 1000)
    return r


def health() -> dict:
    if config.MOCK_LLM:
        return {"reachable": True, "mode": "mock", "model": config.GEMMA_MODEL}
    info = {"mode": "live", "model": config.GEMMA_MODEL, "endpoint": config.GEMMA_BASE_URL}
    # Probe with a tiny REAL chat completion — the exact capability the agents use.
    # More reliable than /v1/models, which some Ollama/vLLM setups return as null.
    try:
        resp = _client.chat.completions.create(
            model=config.GEMMA_MODEL,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=1, temperature=0)
        info["reachable"] = True
        info["sample"] = (resp.choices[0].message.content or "")[:40]
    except Exception as e:  # noqa: BLE001
        info["reachable"] = False
        info["error"] = str(e)
    return info

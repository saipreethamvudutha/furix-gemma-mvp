# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C13 · VALKEY — Cache / Sessions / Verdict Cache                  ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# ROLE        : Fast key-value memory shared across containers. Its most valuable
#               job here is the VERDICT CACHE: if the AI Brain (C14) has already
#               reasoned about an identical finding, serve the cached verdict in
#               microseconds instead of paying for another Gemma (C7) call.
# REAL-WORLD  : Valkey (a BSD fork of Redis). Also holds sessions, locks, the
#               DAL re-hydration table, and fresh IOCs from Intel Sync (C4).
# IN THIS MVP : redis-py if VALKEY_URL is set and reachable; otherwise an
#               in-process TTL dict. Same get()/set() either way.
# INSIGHT     : Caching is THE lever that makes an on-prem LLM affordable. Every
#               cache hit is one Gemma call you didn't make. Watch the hit-rate
#               counter during a stress test — it explains your throughput.
from __future__ import annotations

import hashlib
import json
import os
import threading
import time

from . import c12_operations as ops


class _MemoryCache:
    def __init__(self) -> None:
        self._d: dict[str, tuple[float, str]] = {}   # key -> (expiry_ts, value)
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            item = self._d.get(key)
            if not item:
                return None
            expiry, val = item
            if expiry and expiry < time.time():
                self._d.pop(key, None)
                return None
            return val

    def set(self, key: str, val: str, ttl: int = 0) -> None:
        with self._lock:
            self._d[key] = (time.time() + ttl if ttl else 0, val)

    def info(self) -> dict:
        with self._lock:
            return {"backend": "memory", "keys": len(self._d)}


class _RedisCache:  # pragma: no cover — used only when a real Valkey is present
    def __init__(self, url: str) -> None:
        import redis  # type: ignore
        self._r = redis.from_url(url, decode_responses=True)
        self._r.ping()

    def get(self, key: str):
        return self._r.get(key)

    def set(self, key: str, val: str, ttl: int = 0) -> None:
        self._r.set(key, val, ex=ttl or None)

    def info(self) -> dict:
        return {"backend": "valkey", "keys": self._r.dbsize()}


def _build():
    url = os.environ.get("VALKEY_URL")
    if url:
        try:
            c = _RedisCache(url)
            print(f"[C13 valkey] backend=valkey url={url}")
            return c
        except Exception as e:  # noqa: BLE001
            print(f"[C13 valkey] valkey unreachable ({e}) → in-memory cache")
    return _MemoryCache()


CACHE = _build()

VERDICT_TTL = 24 * 3600   # docs: verdict cache lives 24h


def verdict_key(finding: dict) -> str:
    """Stable cache key from the SHAPE of a finding (not its PII).

    Two findings that are structurally identical (same log_type + signals +
    candidate controls) hash to the same key → second one is a cache hit and
    skips Gemma entirely."""
    shape = {"log_type": finding.get("log_type"),
             "signals": finding.get("signals"),
             "controls": sorted(finding.get("candidate_controls", []))}
    raw = json.dumps(shape, sort_keys=True)
    return "verdict:" + hashlib.sha256(raw.encode()).hexdigest()[:16]


def get_verdict(finding: dict):
    val = CACHE.get(verdict_key(finding))
    if val:
        ops.incr("verdict_cache_hits_total")
        return json.loads(val)
    ops.incr("verdict_cache_misses_total")
    return None


def put_verdict(finding: dict, verdict: dict) -> None:
    CACHE.set(verdict_key(finding), json.dumps(verdict), ttl=VERDICT_TTL)


def register_health() -> None:
    ops.register_health("C13_valkey", lambda: {"ok": True, **CACHE.info()})

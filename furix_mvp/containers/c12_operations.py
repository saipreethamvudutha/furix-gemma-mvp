# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C12 · OPERATIONS — Observability (metrics + health)              ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# ROLE        : The appliance's nervous system. Every other container reports
#               counters (events processed, LLM calls, errors) and latencies
#               here. C12 aggregates them and exposes /metrics in Prometheus
#               text format + a /health rollup.
# REAL-WORLD  : Prometheus + Grafana + Loki + Alertmanager scraping every box.
# IN THIS MVP : A tiny in-process registry (no external Prometheus needed) that
#               speaks the real Prometheus exposition format, so you can later
#               point a real Prometheus at it unchanged.
# INSIGHT     : Observability is not optional plumbing — when you stress-test
#               Gemma (C7) you READ p95/p99 latency and error-rate from here.
#               That is why this is built first: it is how we SEE everything.
from __future__ import annotations

import threading
import time
from collections import defaultdict

_lock = threading.Lock()

# ── Counters: monotonically increasing totals (events, calls, errors) ────────
_counters: dict[tuple[str, tuple], float] = defaultdict(float)
# ── Histograms: raw latency samples per metric, summarised to percentiles ────
_samples: dict[str, list[float]] = defaultdict(list)
# ── Health probes registered by containers: name -> callable returning dict ──
_health_probes: dict[str, callable] = {}

_START = time.time()


def _key(name: str, labels: dict | None) -> tuple[str, tuple]:
    return (name, tuple(sorted((labels or {}).items())))


def incr(name: str, value: float = 1.0, **labels) -> None:
    """Add to a counter, e.g. incr('events_total', source='C6')."""
    with _lock:
        _counters[_key(name, labels)] += value


def observe(name: str, millis: float) -> None:
    """Record one latency sample (ms). Used for p50/p95/p99 rollups."""
    with _lock:
        s = _samples[name]
        s.append(millis)
        if len(s) > 5000:          # cap memory — keep most recent window
            del s[: len(s) - 5000]


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    v = sorted(values)
    i = min(len(v) - 1, int(round((p / 100.0) * (len(v) - 1))))
    return round(v[i], 1)


def latency_summary(name: str) -> dict:
    with _lock:
        v = list(_samples.get(name, []))
    if not v:
        return {"count": 0}
    return {"count": len(v), "p50": _percentile(v, 50), "p95": _percentile(v, 95),
            "p99": _percentile(v, 99), "max": round(max(v), 1),
            "avg": round(sum(v) / len(v), 1)}


def register_health(name: str, probe) -> None:
    """A container registers a callable that reports its own health dict."""
    _health_probes[name] = probe


def health() -> dict:
    out = {"uptime_s": round(time.time() - _START, 1), "containers": {}}
    for name, probe in _health_probes.items():
        try:
            out["containers"][name] = probe()
        except Exception as e:  # noqa: BLE001 — a sick probe must not crash /health
            out["containers"][name] = {"ok": False, "error": str(e)}
    return out


def snapshot() -> dict:
    """Human/JSON view of all metrics — used by the dashboard Ops panel."""
    with _lock:
        counters = {f"{n}{dict(l) or ''}": v for (n, l), v in _counters.items()}
    lat = {n: latency_summary(n) for n in list(_samples.keys())}
    return {"counters": counters, "latency": lat, "uptime_s": round(time.time() - _START, 1)}


def render_prometheus() -> str:
    """Emit the real Prometheus text exposition format (scrapeable)."""
    lines: list[str] = []
    with _lock:
        for (name, labels), val in _counters.items():
            lbl = ",".join(f'{k}="{v}"' for k, v in labels)
            lines.append(f"furix_{name}{{{lbl}}} {val}" if lbl else f"furix_{name} {val}")
    for name in list(_samples.keys()):
        s = latency_summary(name)
        for q, key in (("0.5", "p50"), ("0.95", "p95"), ("0.99", "p99")):
            lines.append(f'furix_{name}_ms{{quantile="{q}"}} {s.get(key, 0)}')
    return "\n".join(lines) + "\n"


class timer:
    """`with timer('ai_brain_latency'):` records elapsed ms into a histogram."""
    def __init__(self, name: str):
        self.name = name

    def __enter__(self):
        self._t = time.time()
        return self

    def __exit__(self, *exc):
        observe(self.name, (time.time() - self._t) * 1000.0)

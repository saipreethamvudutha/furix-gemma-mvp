# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C5 · KAFKA (KRaft) — The Pipeline Bus                            ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# ROLE        : The spine of the whole appliance. Containers NEVER call each
#               other directly — they publish to a topic and whoever cares
#               subscribes. This decoupling is what lets each box scale, crash,
#               and restart independently.
# REAL-WORLD  : Apache Kafka in KRaft mode (no ZooKeeper). Durable, replicated,
#               at-least-once delivery; consumers commit offsets after a
#               successful write so nothing is lost.
# IN THIS MVP : Two interchangeable backends behind ONE tiny interface:
#                 • "memory" (default) — synchronous in-process pub/sub. Lets the
#                    entire 15-container pipeline run in a single process with
#                    zero infra. Perfect for learning + local stress tests.
#                 • "kafka"  — a thin adapter over kafka-python for the real
#                    docker-compose deployment. Same publish()/subscribe() API.
# INSIGHT     : Because producers and consumers share ONE contract (topic name +
#               JSON message), you can swap memory↔kafka without touching any
#               container's logic. That is the entire point of an event bus.
from __future__ import annotations

import json
import os
import threading
from collections import defaultdict, deque
from typing import Callable

from . import c12_operations as ops

# ── The canonical topic list (mirrors the furix architecture doc) ────────────
# Naming: <stage>.<lane/kind>. A container only needs to know topic NAMES.
class T:
    RAW_HOT          = "raw.HOT"            # C2 → C6   high-priority logs
    RAW_WARM         = "raw.WARM"           # C2 → C6   standard logs
    RAW_COLD         = "raw.COLD"           # C2 → C6   verbose/low-priority
    SCAN_FINDINGS    = "scan.findings"      # C3 → C6,C8 vulnerability findings
    NORMALIZED       = "normalized.events"  # C6 → C8   canonical events
    DETECTION_INPUT  = "detection.input"    # C6 → C8   feed for rule engine
    AI_ENRICHMENT    = "ai.enrichment"      # C6/C8 → C14 "please reason on this"
    AI_VERDICTS      = "ai.verdicts"        # C14 → C8,C11 verdict + provenance
    INTEL_UPDATES    = "intel.updates"      # C4 → C8,C13 new IOCs/CVEs
    KG_FINDINGS      = "kg.findings"        # C8 → C9   graph writes
    TIMELINE_EVENTS  = "timeline.events"    # C8 → C10  columnar timeline writes


ALL_TOPICS = [v for k, v in vars(T).items() if not k.startswith("_") and isinstance(v, str)]


class _MemoryBus:
    """Synchronous in-process bus. publish() immediately fans out to handlers."""

    def __init__(self) -> None:
        self._subs: dict[str, list[Callable[[dict], None]]] = defaultdict(list)
        self._history: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._lock = threading.Lock()

    def subscribe(self, topic: str, handler: Callable[[dict], None]) -> None:
        with self._lock:
            self._subs[topic].append(handler)

    def publish(self, topic: str, message: dict) -> None:
        ops.incr("bus_messages_total", topic=topic)
        with self._lock:
            self._history[topic].append(message)
            handlers = list(self._subs.get(topic, []))
        # Fan out OUTSIDE the lock so a slow handler can't block other publishers.
        for h in handlers:
            try:
                h(message)
            except Exception as e:  # noqa: BLE001 — one bad consumer ≠ dead bus
                ops.incr("bus_handler_errors_total", topic=topic)
                print(f"[C5 bus] handler error on {topic}: {e}")

    def history(self, topic: str, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(self._history.get(topic, []))[-limit:]


class _KafkaBus:  # pragma: no cover — exercised only in the compose deployment
    """Real Kafka adapter (same interface). Lazily imports kafka-python so the
    lite/in-process path never needs the dependency installed."""

    def __init__(self, brokers: str) -> None:
        from kafka import KafkaProducer  # type: ignore
        self._brokers = brokers
        self._producer = KafkaProducer(
            bootstrap_servers=brokers,
            value_serializer=lambda v: json.dumps(v).encode(),
            acks="all",                 # durability: wait for in-sync replicas
        )

    def publish(self, topic: str, message: dict) -> None:
        ops.incr("bus_messages_total", topic=topic)
        self._producer.send(topic, message)

    def subscribe(self, topic: str, handler: Callable[[dict], None]) -> None:
        # Each subscriber gets its own consumer thread (one consumer group per box).
        import threading as _t
        from kafka import KafkaConsumer  # type: ignore

        def _loop():
            consumer = KafkaConsumer(
                topic, bootstrap_servers=self._brokers,
                value_deserializer=lambda b: json.loads(b.decode()),
                auto_offset_reset="latest", enable_auto_commit=True,
                group_id=f"furix-{topic}-{id(handler)}")
            for msg in consumer:
                try:
                    handler(msg.value)
                except Exception as e:  # noqa: BLE001
                    ops.incr("bus_handler_errors_total", topic=topic)
                    print(f"[C5 kafka] handler error on {topic}: {e}")

        _t.Thread(target=_loop, daemon=True).start()

    def history(self, topic: str, limit: int = 50) -> list[dict]:
        return []   # Kafka is the source of truth; replay via furixctl, not here.


# ── Singleton: pick backend from env (memory unless explicitly kafka) ────────
def _build():
    if os.environ.get("BUS_BACKEND", "memory") == "kafka":
        brokers = os.environ.get("KAFKA_BROKERS", "kafka:9092")
        print(f"[C5 bus] backend=kafka brokers={brokers}")
        return _KafkaBus(brokers)
    return _MemoryBus()


BUS = _build()


def register_health() -> None:
    ops.register_health("C5_bus", lambda: {
        "ok": True, "backend": type(BUS).__name__, "topics": len(ALL_TOPICS)})

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER ENTRYPOINT — run ONE Furix box as its own process (compose mode) ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# In LITE mode one Python process runs all 15 containers. In the docker-compose
# deployment each Furix-built container runs THIS file with a role argument and
# talks over the REAL Kafka bus (BUS_BACKEND=kafka). Infra containers (nginx,
# kafka, postgres, ...) are real images and don't use this entrypoint.
#
#   python -m furix_mvp.run_container ai_brain
#
# Roles → which container(s) this process embodies:
#   dashboard   C11  (uvicorn web UI + API; does NOT consume the bus)
#   normaliser  C6   (consumes raw.* → emits normalized/detection/ai.enrichment)
#   storage     C8   (consumes normalized/detection/ai.verdicts → persists)
#   ai_brain    C14  (consumes ai.enrichment → calls Gemma → emits ai.verdicts)
#   intel       C4   (periodically refreshes the IOC feed)
#   scan        C3   (on-demand scanner; idles waiting for API triggers)
#   backup      C15  (periodically snapshots all stores)
from __future__ import annotations
import os
import sys
import time


def main() -> None:
    role = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CONTAINER", "dashboard")
    os.environ.setdefault("BUS_BACKEND", "kafka")   # compose uses the real bus

    if role == "dashboard":
        os.environ["FURIX_BOOTSTRAP"] = "0"          # dedicated containers run the bus
        import uvicorn
        uvicorn.run("furix_mvp.api:app", host="0.0.0.0", port=8080)
        return

    from .containers import (c3_scan_engine, c4_intel_sync, c6_normaliser,
                             c8_storage_detect, c14_ai_brain)

    if role == "normaliser":
        c6_normaliser.start()
    elif role == "storage":
        c8_storage_detect.start()
    elif role == "ai_brain":
        c14_ai_brain.start()
    elif role == "scan":
        c3_scan_engine.register_health()
    elif role == "intel":
        pass   # handled in the loop below
    elif role == "backup":
        pass
    else:
        raise SystemExit(f"unknown role: {role}")

    print(f"[run_container] role={role} bus={os.environ['BUS_BACKEND']} — running")
    # Service loop. Consumer-based roles just keep the process alive (their Kafka
    # consumer threads do the work). Periodic roles act on a schedule.
    last_intel = last_backup = 0.0
    while True:
        now = time.time()
        if role == "intel" and now - last_intel > 4 * 3600:      # every 4h
            c4_intel_sync.refresh(); last_intel = now
        if role == "backup" and now - last_backup > 24 * 3600:   # daily
            from .containers import c15_backup
            c15_backup.snapshot(reason="scheduled"); last_backup = now
        time.sleep(5)


if __name__ == "__main__":
    main()

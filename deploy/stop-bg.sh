#!/usr/bin/env bash
# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  STOP the background Furix process (started by start-bg.sh)                 ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# RUN : bash deploy/stop-bg.sh
set -euo pipefail

if pgrep -f "uvicorn furix_mvp.api:app" > /dev/null; then
  pkill -f "uvicorn furix_mvp.api:app" || true
  # Wait until the process has ACTUALLY exited, so a following start-bg.sh doesn't
  # see it still alive and refuse to start (the restart race). Escalate to -9.
  for _ in $(seq 1 30); do
    pgrep -f "uvicorn furix_mvp.api:app" > /dev/null || break
    sleep 0.3
  done
  if pgrep -f "uvicorn furix_mvp.api:app" > /dev/null; then
    pkill -9 -f "uvicorn furix_mvp.api:app" || true
    sleep 1
  fi
  echo "✓ Furix stopped."
else
  echo "Furix was not running."
fi

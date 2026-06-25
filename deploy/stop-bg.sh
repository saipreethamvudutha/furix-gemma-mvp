#!/usr/bin/env bash
# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  STOP the background Furix process (started by start-bg.sh)                 ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# RUN : bash deploy/stop-bg.sh
set -euo pipefail

if pgrep -f "uvicorn furix_mvp.api:app" > /dev/null; then
  pkill -f "uvicorn furix_mvp.api:app"
  echo "✓ Furix stopped."
else
  echo "Furix was not running."
fi

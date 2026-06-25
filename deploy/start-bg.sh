#!/usr/bin/env bash
# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  START IN BACKGROUND — no sudo, no systemd needed                           ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# WHAT : Starts the Furix MVP (C11 dashboard + all 15 lite containers) detached
#        from the terminal via nohup. Survives closing the terminal and SSH/RDP
#        disconnects. Logs go to furix.log. Use this when you do NOT have sudo
#        (so the systemd installer can't run).
# RUN  : bash deploy/start-bg.sh
# STOP : bash deploy/stop-bg.sh
# NOTE : Does NOT auto-start on reboot (that needs sudo). After a server reboot,
#        just run this script again.
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$APP_DIR"

# venv + deps (idempotent — skips if already there).
if [ ! -d .venv ]; then
  echo "→ Creating virtualenv + installing requirements..."
  python3 -m venv .venv
  ./.venv/bin/pip install -q --upgrade pip
  ./.venv/bin/pip install -q -r requirements.txt
fi
[ -f .env ] || cp .env.example .env

# Already running? Don't double-start.
if pgrep -f "uvicorn furix_mvp.api:app" > /dev/null; then
  echo "Furix is already running (pid: $(pgrep -f 'uvicorn furix_mvp.api:app' | tr '\n' ' '))."
  echo "To apply new code: bash deploy/stop-bg.sh && bash deploy/start-bg.sh"
  exit 0
fi

nohup ./.venv/bin/uvicorn furix_mvp.api:app --host 0.0.0.0 --port 8080 \
  > "$APP_DIR/furix.log" 2>&1 &
PID=$!
sleep 2

if kill -0 "$PID" 2>/dev/null; then
  echo "✓ Furix started in background (pid $PID)."
  echo "  Logs      : tail -f $APP_DIR/furix.log"
  echo "  Dashboard : http://localhost:8080        (or http://<server-ip>:8080)"
  echo "  Demo      : http://localhost:8080/demo"
else
  echo "✗ Furix failed to start. Last log lines:"
  tail -n 20 "$APP_DIR/furix.log"
  exit 1
fi

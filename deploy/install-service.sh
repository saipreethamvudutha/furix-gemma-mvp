#!/usr/bin/env bash
# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  ONE-TIME INSTALLER — run Furix as a background systemd service             ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# WHAT : Installs the Furix MVP (C11 dashboard + all 15 lite containers) as a
#        systemd service so it runs in the BACKGROUND — no terminal to babysit,
#        survives SSH disconnects + reboots, and auto-restarts if it crashes.
# RUN  : bash deploy/install-service.sh          (it will sudo where needed)
# AFTER: sudo systemctl status furix     → is it running?
#        sudo systemctl restart furix    → apply new code after `git pull`
#        journalctl -u furix -f          → live logs (optional)
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_USER="$(whoami)"

echo "→ App dir : $APP_DIR"
echo "→ Run as  : $APP_USER"

# 1. Make sure the venv + deps exist (idempotent).
if [ ! -d "$APP_DIR/.venv" ]; then
  echo "→ Creating virtualenv + installing requirements..."
  python3 -m venv "$APP_DIR/.venv"
  "$APP_DIR/.venv/bin/pip" install -q --upgrade pip
  "$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
fi

# 2. Make sure a .env exists (the app reads it for the Gemma endpoint).
[ -f "$APP_DIR/.env" ] || cp "$APP_DIR/.env.example" "$APP_DIR/.env"

# 3. Write the systemd unit (paths + user filled in dynamically — no hardcoding).
echo "→ Writing /etc/systemd/system/furix.service ..."
sudo tee /etc/systemd/system/furix.service > /dev/null <<EOF
[Unit]
Description=Furix Gemma MVP appliance (C11 dashboard + all 15 lite containers)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/.venv/bin/uvicorn furix_mvp.api:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# 4. Enable (start on boot) + start now.
sudo systemctl daemon-reload
sudo systemctl enable furix
sudo systemctl restart furix

echo ""
echo "✓ Furix is now running in the background on port 8080."
echo "  Dashboard : http://localhost:8080        (or http://<server-ip>:8080)"
echo "  Demo      : http://localhost:8080/demo"
echo ""
echo "  Status    : sudo systemctl status furix"
echo "  Restart   : sudo systemctl restart furix   (after git pull)"
echo "  Logs      : journalctl -u furix -f"

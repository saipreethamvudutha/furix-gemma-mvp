# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C11 · DASHBOARD — the only user-facing box                       ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# ROLE        : What the analyst actually touches. Renders verdicts, the live
#               timeline, alerts, and the Ops view; lets you trigger analyses,
#               batch ingest, scans, and backups.
# REAL-WORLD  : React 18 SPA + FastAPI + WebSocket, behind Nginx (C1).
# IN THIS MVP : FastAPI + a single static page. The actual app object lives in
#               furix_mvp/api.py; this module re-exports it so you can run the
#               dashboard "as container C11":  uvicorn furix_mvp.containers.c11_dashboard:app
# INSIGHT     : Keep ALL user input behind one box. C11 is the only container an
#               analyst can reach; everything else is internal-only. That single
#               choke point is where authz, rate-limiting, and audit live.
from __future__ import annotations

from ..api import app   # noqa: F401  — re-export the FastAPI app as C11

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CONTAINER C9 · POSTGRESQL + AGE + pgvector — The Security Knowledge Graph  ║
# ╚════════════════════════════════════════════════════════════════════════════╝
# ROLE        : One Postgres instance wearing three hats:
#                 • Relational : findings, verdicts, audit log (furix_mvp/db.py)
#                 • Graph (AGE): CISControl ─MAPS_TO→ NISTSubcat etc. (rag.py)
#                 • Vector (pgvector): embedded compliance text for RAG (rag.py)
# REAL-WORLD  : PostgreSQL 16 + Apache AGE + pgvector, LUKS-encrypted. The graph
#               is THE core asset — every capability reads/writes it.
# IN THIS MVP : The real retrieval + persistence code lives in rag.py (vector +
#               graph) and db.py (relational). This module is C9's face + a
#               single health probe. Seed the vector/graph store with
#               scripts/ingest.py; everything degrades to static maps if absent.
# INSIGHT     : Three query shapes, ONE store. "How are these related?" → graph.
#               "What's semantically similar?" → vector. "Give me the rows" →
#               SQL. The AI Brain uses all three to ground a prompt in YOUR
#               environment, which is what stops the model hallucinating.
from __future__ import annotations

from .. import db, rag
from . import c12_operations as ops


def register_health() -> None:
    def _probe():
        st = rag.status()
        return {"ok": True, "relational": db.backend(),
                "vector_graph": "live" if st.get("available") else st.get("reason")}
    ops.register_health("C9_postgres", _probe)

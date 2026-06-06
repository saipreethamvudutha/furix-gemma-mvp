"""CONTAINER C9 · Full RAG grounding: pgvector retrieval + SecureBERT rerank + AGE expand.

Faithful to the furix CIS_NIST_HIPAA pipeline but trimmed to the retrieval path.
Everything is lazy and defensive: if RAG_ENABLED=0, or psycopg2 / the embedding
models / the database are unavailable, retrieve() returns an "unavailable" result
and the AI Brain falls back to the static-map grounding in compliance.py.
"""
from __future__ import annotations
import threading
from typing import Optional

from . import config

_lock = threading.Lock()
_embedder = None
_reranker = None
_status: dict = {"checked": False, "available": False, "reason": "not checked"}


def _load_models():
    global _embedder, _reranker
    if _embedder is None:
        from sentence_transformers import SentenceTransformer, CrossEncoder
        _embedder = SentenceTransformer(config.EMBED_MODEL)
        _reranker = CrossEncoder(config.RERANK_MODEL)


def _connect():
    import psycopg2
    from pgvector.psycopg2 import register_vector
    conn = psycopg2.connect(host=config.PG_HOST, port=config.PG_PORT,
                            dbname=config.PG_DBNAME, user=config.PG_USER,
                            password=config.PG_PASSWORD, connect_timeout=5)
    register_vector(conn)
    return conn


def status() -> dict:
    """Cheap, cached probe of whether the full RAG path is usable."""
    global _status
    if _status["checked"]:
        return _status
    if not config.RAG_ENABLED:
        _status = {"checked": True, "available": False, "reason": "RAG_ENABLED=0"}
        return _status
    try:
        conn = _connect()
        with conn.cursor() as cur:
            cur.execute(f"SELECT count(*) FROM {config.PG_TABLE}")
            n = cur.fetchone()[0]
        conn.close()
        _status = {"checked": True, "available": n > 0, "rows": n,
                   "reason": "ok" if n else "empty table — run scripts/ingest.py"}
    except Exception as e:  # noqa: BLE001
        _status = {"checked": True, "available": False, "reason": f"db: {e}"}
    return _status


def _graph_expand(conn, control_ids: list[str]) -> list[str]:
    """AGE: pull NIST subcategories linked to the matched CIS controls."""
    related: list[str] = []
    try:
        with conn.cursor() as cur:
            cur.execute("LOAD 'age';")
            cur.execute("SET search_path = ag_catalog, public;")
            for cid in control_ids:
                cur.execute(
                    f"SELECT * FROM cypher('{config.AGE_GRAPH_NAME}', $$ "
                    f"MATCH (c:CISControl {{id:'{cid}'}})-[:MAPS_TO]->(n:NISTSubcat) "
                    f"RETURN n.id $$) AS (nid agtype);")
                for (nid,) in cur.fetchall():
                    val = str(nid).strip('"')
                    if val not in related:
                        related.append(val)
    except Exception:  # noqa: BLE001 — AGE optional, never fatal
        pass
    return related


def retrieve(query: str, finding: Optional[dict] = None) -> dict:
    """Return grounded compliance context for the agents.

    {available, controls[], snippets[{control_id,framework,content,score}],
     graph_controls[]}
    """
    st = status()
    if not st["available"]:
        return {"available": False, "reason": st["reason"], "controls": [], "snippets": []}

    with _lock:
        _load_models()
    try:
        vec = _embedder.encode(query, normalize_embeddings=True).tolist()
        conn = _connect()
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT control_id, framework, content, 1-(embedding <=> %s::vector) AS score "
                f"FROM {config.PG_TABLE} ORDER BY embedding <=> %s::vector LIMIT %s",
                (vec, vec, config.TOP_K))
            rows = cur.fetchall()

        # cross-encoder rerank
        pairs = [[query, r[2]] for r in rows]
        scores = _reranker.predict(pairs) if pairs else []
        ranked = sorted(zip(rows, scores), key=lambda x: float(x[1]), reverse=True)
        top = ranked[:config.TOP_K_FINAL]

        # RELEVANCE FLOOR (upgrade A): drop matches whose vector cosine similarity
        # is below the floor — so a novel log isn't grounded in irrelevant controls.
        floor = config.RAG_SCORE_FLOOR
        snippets, controls, dropped = [], [], 0
        for (cid, fw, content, vscore), rscore in top:
            if float(vscore) < floor:
                dropped += 1
                continue
            snippets.append({"control_id": cid, "framework": fw, "content": content[:400],
                             "score": round(float(rscore), 3),
                             "similarity": round(float(vscore), 3)})
            if cid and cid not in controls:
                controls.append(cid)

        graph_controls = _graph_expand(conn, [c for c in controls if c.startswith("Control")])
        conn.close()
        reason = "ok" if controls else f"no_match_above_floor({floor})"
        return {"available": True, "controls": controls, "snippets": snippets,
                "graph_controls": graph_controls, "dropped_below_floor": dropped,
                "floor": floor, "reason": reason}
    except Exception as e:  # noqa: BLE001
        return {"available": False, "reason": f"retrieve: {e}", "controls": [], "snippets": []}

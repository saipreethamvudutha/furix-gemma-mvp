#!/usr/bin/env python3
"""Seed the full RAG grounding store (run once, only when RAG_ENABLED=1).

Creates pgvector + Apache AGE objects and ingests the CIS / NIST / HIPAA
catalogs as an embedded, queryable corpus + a CIS->NIST MAPS_TO graph. This
makes furix_mvp.rag.retrieve() fully functional (embed -> cosine -> rerank ->
AGE expand) without needing the original framework PDFs.

    python scripts/ingest.py
"""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import psycopg2
from pgvector.psycopg2 import register_vector
from sentence_transformers import SentenceTransformer

from furix_mvp import config
from furix_mvp.compliance import (CIS_CONTROLS, CIS_TO_NIST, HIPAA_TITLES,
                                  HIPAA_TO_NIST, NIST_ALLOWED)


def connect():
    c = psycopg2.connect(host=config.PG_HOST, port=config.PG_PORT, dbname=config.PG_DBNAME,
                         user=config.PG_USER, password=config.PG_PASSWORD)
    c.autocommit = True
    return c


def setup_schema(conn):
    with conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
        cur.execute(f"DROP TABLE IF EXISTS {config.PG_TABLE};")
        cur.execute(f"""
            CREATE TABLE {config.PG_TABLE} (
                id serial PRIMARY KEY,
                framework text, control_id text, section text,
                content text, embedding vector({config.EMBED_DIM})
            );""")
    print(f"✅ schema ready: {config.PG_TABLE}")


def build_corpus() -> list[tuple[str, str, str, str]]:
    """(framework, control_id, section, content)"""
    rows = []
    for cid, title in CIS_CONTROLS.items():
        nist = ", ".join(CIS_TO_NIST.get(cid, []))
        rows.append(("cis_v8", cid, title,
                     f"{cid}: {title}. CIS Controls v8.1 safeguard family. "
                     f"Maps to NIST CSF 2.0 subcategories: {nist}."))
    for sec, title in HIPAA_TITLES.items():
        nist = ", ".join(HIPAA_TO_NIST.get(sec, []))
        rows.append(("hipaa", sec, title,
                     f"HIPAA Security Rule 45 CFR §{sec}: {title}. "
                     f"Maps to NIST CSF 2.0: {nist}."))
    for sc in NIST_ALLOWED:
        rows.append(("nist_csf", sc, sc, f"NIST CSF 2.0 subcategory {sc}."))
    return rows


def ingest_vectors(conn, embedder):
    rows = build_corpus()
    texts = [r[3] for r in rows]
    embs = embedder.encode(texts, normalize_embeddings=True, show_progress_bar=True)
    with conn.cursor() as cur:
        for (fw, cid, sec, content), emb in zip(rows, embs):
            cur.execute(
                f"INSERT INTO {config.PG_TABLE} (framework, control_id, section, content, embedding) "
                f"VALUES (%s,%s,%s,%s,%s)", (fw, cid, sec, content, emb.tolist()))
    print(f"✅ embedded {len(rows)} compliance chunks")


def setup_graph(conn):
    g = config.AGE_GRAPH_NAME
    with conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS age;")
        cur.execute("LOAD 'age';")
        cur.execute("SET search_path = ag_catalog, public;")
        cur.execute(f"SELECT drop_graph('{g}', true);" if _graph_exists(cur, g) else "SELECT 1;")
        cur.execute(f"SELECT create_graph('{g}');")
        for cid in CIS_CONTROLS:
            cur.execute(f"SELECT * FROM cypher('{g}', $$ CREATE (:CISControl {{id:'{cid}'}}) $$) AS (v agtype);")
        for sc in NIST_ALLOWED:
            cur.execute(f"SELECT * FROM cypher('{g}', $$ CREATE (:NISTSubcat {{id:'{sc}'}}) $$) AS (v agtype);")
        for cid, scs in CIS_TO_NIST.items():
            for sc in scs:
                cur.execute(
                    f"SELECT * FROM cypher('{g}', $$ MATCH (c:CISControl {{id:'{cid}'}}),(n:NISTSubcat {{id:'{sc}'}}) "
                    f"CREATE (c)-[:MAPS_TO]->(n) $$) AS (v agtype);")
    print(f"✅ AGE graph '{g}': CISControl/NISTSubcat nodes + MAPS_TO edges")


def _graph_exists(cur, g) -> bool:
    cur.execute("SELECT count(*) FROM ag_catalog.ag_graph WHERE name=%s;", (g,))
    return cur.fetchone()[0] > 0


def main():
    if not config.RAG_ENABLED:
        print("RAG_ENABLED=0 — set it to 1 in .env before ingesting.")
        return
    print(f"Connecting to {config.PG_HOST}:{config.PG_PORT}/{config.PG_DBNAME} …")
    conn = connect()
    register_vector(conn)
    setup_schema(conn)
    print(f"Loading embedder {config.EMBED_MODEL} …")
    embedder = SentenceTransformer(config.EMBED_MODEL)
    ingest_vectors(conn, embedder)
    try:
        setup_graph(conn)
    except Exception as e:  # noqa: BLE001
        print(f"⚠️  AGE graph skipped ({e}); vector retrieval still works.")
    conn.close()
    print("✅ ingest complete — set RAG_ENABLED=1 and restart the API.")


if __name__ == "__main__":
    main()

-- CONTAINER C9 · PostgreSQL bootstrap (runs once on first container start).
-- Enables the extensions the AI Brain's grounding needs. pgvector ships in the
-- pgvector/pgvector image. Apache AGE is optional — if the extension isn't
-- present the graph-expand step in rag.py degrades gracefully (vector + static
-- maps still work), so this CREATE is wrapped to never fail the boot.
CREATE EXTENSION IF NOT EXISTS vector;

DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS age;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Apache AGE not available in this image — graph-expand will degrade.';
END $$;

-- The compliance corpus + graph are populated by scripts/ingest.py:
--   docker compose exec c14-ai-brain python scripts/ingest.py

"""Central configuration — all runtime knobs come from env (see .env.example)."""
from __future__ import annotations
import os
from dotenv import load_dotenv

load_dotenv()


def _bool(key: str, default: str = "0") -> bool:
    return os.environ.get(key, default).strip() in ("1", "true", "True", "yes")


# ── Gemma (in-house LLM) ──────────────────────────────────────────────────────
GEMMA_BASE_URL  = os.environ.get("GEMMA_BASE_URL", "http://localhost:11434/v1")
GEMMA_MODEL     = os.environ.get("GEMMA_MODEL", "gemma4:e4b")
GEMMA_API_KEY   = os.environ.get("GEMMA_API_KEY", "ollama")
GEMMA_TIMEOUT   = float(os.environ.get("GEMMA_TIMEOUT", "120"))
GEMMA_MAX_TOKENS    = int(os.environ.get("GEMMA_MAX_TOKENS", "1600"))
GEMMA_TEMPERATURE   = float(os.environ.get("GEMMA_TEMPERATURE", "0.1"))
MOCK_LLM        = _bool("MOCK_LLM")

# DAL: enable HIPAA Safe Harbor redaction (SSN/phone/date/VIN/URL). Default OFF —
# those patterns over-redact security logs; turn ON only for healthcare/PHI data.
DAL_HIPAA_MODE  = _bool("DAL_HIPAA_MODE")

# ── RAG grounding (PostgreSQL + pgvector + Apache AGE + SecureBERT) ────────────
RAG_ENABLED  = _bool("RAG_ENABLED")
PG_HOST      = os.environ.get("PG_HOST", "localhost")
PG_PORT      = int(os.environ.get("PG_PORT", "5433"))
PG_DBNAME    = os.environ.get("PG_DBNAME", "cis_rag")
PG_USER      = os.environ.get("PG_USER", "colab_user")
PG_PASSWORD  = os.environ.get("PG_PASSWORD", "colab_pass")
PG_TABLE     = os.environ.get("PG_TABLE", "compliance_chunks")
AGE_GRAPH_NAME = os.environ.get("AGE_GRAPH_NAME", "compliance_graph")
EMBED_MODEL  = os.environ.get("EMBED_MODEL", "cisco-ai/SecureBERT2.0-biencoder")
RERANK_MODEL = os.environ.get("RERANK_MODEL", "cisco-ai/SecureBERT2.0-cross_encoder")
EMBED_DIM    = int(os.environ.get("EMBED_DIM", "768"))

# RAG retrieval params
TOP_K        = 35
TOP_K_RERANK = 12
TOP_K_FINAL  = 6
# Relevance floor: drop retrieved controls whose vector cosine similarity is below
# this, so a totally-novel log isn't grounded in weak, irrelevant controls.
# 0.0 = keep everything (off); ~0.30 = gentle floor.
RAG_SCORE_FLOOR = float(os.environ.get("RAG_SCORE_FLOOR", "0.30"))

# ── Compliance mapping (code-first) ───────────────────────────────────────────
# Compliance mapping is DETERMINISTIC by default (rules + crosswalk + embeddings).
# The LLM (compliance_mapper agent) is consulted ONLY for the "unknown" case —
# when no deterministic tier could map the event. Set to 0 to disable the LLM
# fallback entirely and have unmapped events flagged needs_review instead.
COMPLIANCE_LLM_FALLBACK = _bool("COMPLIANCE_LLM_FALLBACK", "1")
# Run risk_scorer + anomaly_detector deterministically (no Gemma call) using their
# built-in signal logic. Default ON — this is the load-test lever: it cuts Gemma
# calls/event from ~4 to ~2. Set to 0 to use the LLM for scoring instead.
DETERMINISTIC_SCORING = _bool("DETERMINISTIC_SCORING", "1")
# Narrative agents (remediation_generator, report_generator) are genuinely
# generative — run them ON-DEMAND: only for events at/above this severity, OR when
# the caller explicitly requests them (analyst click). Everything below just gets
# the deterministic verdict + mapping. Set to "informational" to always run them.
NARRATIVE_MIN_SEVERITY = os.environ.get("NARRATIVE_MIN_SEVERITY", "high").strip().lower()
# Narrative reports (remediation + report) are the EXPENSIVE generative Gemma
# calls. By default they run ON-DEMAND ONLY (analyst clicks "generate report"),
# so routine detection stays fully deterministic and LLM-call frequency stays
# low — this is what lets the deterministic engines resolve the majority of
# events. Set NARRATIVE_AUTO=1 to auto-run them for events >= NARRATIVE_MIN_SEVERITY.
NARRATIVE_AUTO = _bool("NARRATIVE_AUTO", "0")
_SEV_ORDER = ["informational", "low", "medium", "high", "critical"]


def severity_meets(sev: str, threshold: str | None = None) -> bool:
    th = (threshold or NARRATIVE_MIN_SEVERITY)
    try:
        return _SEV_ORDER.index((sev or "medium")) >= _SEV_ORDER.index(th)
    except ValueError:
        return True   # unknown threshold → don't gate
# Vector cosine-similarity floor for ACCEPTING an embedding-tier control as a
# confident deterministic mapping (Tier 3). Reuses the RAG floor by default.
MAPPING_EMBED_FLOOR = float(os.environ.get("MAPPING_EMBED_FLOOR",
                                           os.environ.get("RAG_SCORE_FLOOR", "0.30")))
# Phase 1.1 — path to an SCF export (free, machine-readable). Accepts the official
# SCF "JSON_Data" export (.json, the real 1,090-control / 200+-framework data from
# the SCF OSCAL GitHub repo) OR a simple catalog CSV. When set + present, compliance
# mapping uses the authoritative SCF crosswalk instead of the small built-in tables.
# Unset = built-in CIS->NIST/HIPAA tables. Fetch with scripts/fetch_scf.py.
# See docs/SCF_INTEGRATION.md. (SCF_CSV_PATH kept as a back-compat alias.)
SCF_PATH = os.environ.get("SCF_PATH", "") or os.environ.get("SCF_CSV_PATH", "")
SCF_CSV_PATH = SCF_PATH  # back-compat alias

# ── Orchestration ─────────────────────────────────────────────────────────────
ALL_AGENTS = ["risk_scorer", "compliance_mapper", "remediation_generator",
              "anomaly_detector", "report_generator"]


def enabled_agents() -> list[str]:
    raw = os.environ.get("ENABLED_AGENTS", "all").strip()
    if raw in ("", "all"):
        return list(ALL_AGENTS)
    want = [a.strip() for a in raw.split(",") if a.strip()]
    return [a for a in ALL_AGENTS if a in want]


PARALLEL_AGENTS = _bool("PARALLEL_AGENTS", "1")

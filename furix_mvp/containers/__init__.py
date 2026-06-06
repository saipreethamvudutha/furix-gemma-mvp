# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  FURIX — THE 15-CONTAINER APPLIANCE  (teaching map)                         ║
# ╠════════════════════════════════════════════════════════════════════════════╣
# ║  Furix ships as ONE on-prem VM running 15 cooperating containers. This       ║
# ║  package gives every container a Python "process module" so you can read the ║
# ║  system one box at a time. Infra containers (nginx/kafka/postgres/...) are    ║
# ║  REAL open-source images in docker-compose.yml; their module here is a thin  ║
# ║  client/explainer. The 7 Furix-built containers have their real (lite) logic ║
# ║  here.                                                                        ║
# ║                                                                              ║
# ║  Read order to understand a security event's life:                           ║
# ║    C2  Vector      ─ logs arrive                                              ║
# ║    C5  Kafka bus   ─ everything flows over topics                            ║
# ║    C6  Normaliser  ─ parse → standardise → enrich → lane-tag                 ║
# ║    C14 AI Brain    ─ DAL + 5 agents + verdict   (calls C7 Gemma)             ║
# ║    C7  vLLM/Gemma  ─ the model under test                                    ║
# ║    C8  Storage+Det ─ persist + rule detection                                ║
# ║    C9  Postgres    ─ knowledge graph / relational / vector                   ║
# ║    C10 ClickHouse  ─ event timeline                                          ║
# ║    C11 Dashboard   ─ what the analyst sees                                    ║
# ╚════════════════════════════════════════════════════════════════════════════╝
"""Furix container modules. See ARCHITECTURE.md for the full teaching map."""

# (container_id, name, kind, what it does in one line)
CONTAINER_MAP = [
    ("C1",  "Nginx",              "infra (real)",  "TLS edge / reverse proxy / routing"),
    ("C2",  "Vector",             "furix (lite)",  "log ingestion front door"),
    ("C3",  "Scan Engine",        "furix",         "active vulnerability + posture scans"),
    ("C4",  "Intel Sync",         "furix",         "pull threat-intel feeds (only outbound flow)"),
    ("C5",  "Kafka (KRaft)",      "infra (real)",  "pipeline bus — every stage talks via topics"),
    ("C6",  "Normaliser",         "furix",         "parse → standardise → enrich → lane-tag"),
    ("C7",  "vLLM / Gemma",       "model",         "local LLM inference (the model under test)"),
    ("C8",  "Storage + Detection","furix",         "persist events + run detection rules"),
    ("C9",  "PostgreSQL+AGE+pgvector","infra (real)","knowledge graph / relational / vector store"),
    ("C10", "ClickHouse",         "infra (real)",  "columnar event timeline"),
    ("C11", "Dashboard",          "furix",         "FastAPI + single-page analyst UI"),
    ("C12", "Operations",         "furix",         "metrics, health, Prometheus exposition"),
    ("C13", "Valkey",             "infra (real)",  "cache / sessions / verdict cache"),
    ("C14", "AI Brain (Praxis)",  "furix",         "orchestrator: DAL + 5 agents + verdict"),
    ("C15", "Backup Coordinator", "furix",         "consistent encrypted snapshots"),
]

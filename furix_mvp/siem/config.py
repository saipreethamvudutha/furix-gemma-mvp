"""SIEM subsystem configuration — ported from the Anomaly-detection engine's
root ``config.py`` and namespaced under ``furix_mvp.siem`` so it never collides
with furix's env-driven ``furix_mvp.config``.

All numeric thresholds / fusion weights are kept VERBATIM from the source engine
(changing them changes detection behaviour). Only the filesystem paths are
repointed into this subpackage:

    furix_mvp/siem/
        rules/   ← all rule-definition data (rules.json, *_patterns.txt, weights)
        data/    ← mitre_techniques.json
        models/  ← trained ML + UEBA artifacts (written by the offline train step)
        logs/    ← baseline / incoming log staging

Env overrides reuse furix's convention (``SIEM_*`` keys) but every value has a
working default so the subsystem runs with zero configuration.
"""
from __future__ import annotations
import os

# Anchor every path inside this subpackage (furix_mvp/siem/), NOT the repo root —
# this is the key change from the source config.py, which anchored at its own root.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _env_path(key: str, default: str) -> str:
    """Allow a SIEM_* env override, else fall back to the in-package default."""
    return os.environ.get(key, default)


# ── Data paths ────────────────────────────────────────────────────────────────
DATA_DIR      = _env_path("SIEM_DATA_DIR", os.path.join(BASE_DIR, "data"))
BASELINE_LOG  = os.path.join(BASE_DIR, "logs", "baseline")
INCOMING_LOG  = os.path.join(BASE_DIR, "logs", "incoming")

MITRE_TECHNIQUES_PATH = _env_path(
    "SIEM_MITRE_PATH", os.path.join(DATA_DIR, "mitre_techniques.json"))

# ── Model paths (written by the offline training step) ────────────────────────
MODELS_DIR          = _env_path("SIEM_MODELS_DIR", os.path.join(BASE_DIR, "models"))
SCALER_PATH         = os.path.join(MODELS_DIR, "scaler.pkl")
ISO_FOREST_PATH     = os.path.join(MODELS_DIR, "iso_forest.pkl")
ECOD_PATH           = os.path.join(MODELS_DIR, "ecod.pkl")
CALIBRATION_PATH    = os.path.join(MODELS_DIR, "calibration.pkl")
BASELINE_STATS_PATH = os.path.join(MODELS_DIR, "baseline_stats.pkl")

UEBA_DIR           = os.path.join(MODELS_DIR, "ueba")
UEBA_PROFILES_PATH = os.path.join(UEBA_DIR, "ueba_profiles.pkl")
UEBA_REPORT_PATH   = os.path.join(UEBA_DIR, "ueba_build_report.json")

# ── Rule data ─────────────────────────────────────────────────────────────────
# Flattened from the source's config/rules/ to furix_mvp/siem/rules/ (the source
# had an intermediate config/ dir; inside this package "config" is the module
# name, so rule data lives directly under rules/).
RULES_DIR            = _env_path("SIEM_RULES_DIR", os.path.join(BASE_DIR, "rules"))
RULES_JSON_PATH      = os.path.join(RULES_DIR, "rules.json")

PORT_RISK_PATH       = os.path.join(RULES_DIR, "port_risk.json")
RULE_WEIGHTS_PATH    = os.path.join(RULES_DIR, "rule_weights.json")
THREAT_INTEL_PATH    = os.path.join(RULES_DIR, "threat_intel.txt")
SQLI_PATTERNS_PATH   = os.path.join(RULES_DIR, "sqli_patterns.txt")
XSS_PATTERNS_PATH    = os.path.join(RULES_DIR, "xss_patterns.txt")
SHELL_PATTERNS_PATH  = os.path.join(RULES_DIR, "shell_patterns.txt")
RANSOMWARE_PATH      = os.path.join(RULES_DIR, "ransomware_patterns.txt")
JNDI_PATTERNS_PATH   = os.path.join(RULES_DIR, "jndi_patterns.txt")
SENSITIVE_FILES_PATH = os.path.join(RULES_DIR, "sensitive_files.txt")
SCANNER_AGENTS_PATH  = os.path.join(RULES_DIR, "scanner_agents.txt")

# ── Isolation Forest ──────────────────────────────────────────────────────────
IF_CONTAMINATION  = 0.01
IF_N_ESTIMATORS   = 200
IF_RANDOM_STATE   = 42

# ── Score-fusion weights — Layer 3 is pure ML; rules are an independent lane ──
WEIGHT_ISO_FOREST = 0.60
WEIGHT_ECOD       = 0.40
WEIGHT_RULES      = 0.25   # kept defined; consumed by the Risk Accumulator

# ── Severity thresholds (percentile-based fused score) ────────────────────────
SEVERITY_CRITICAL = 90
SEVERITY_HIGH     = 70
SEVERITY_MEDIUM   = 45
SEVERITY_LOW      = 30

# ── Session window settings ───────────────────────────────────────────────────
SESSION_WINDOW_MINUTES  = 10
SESSION_FAILURE_WINDOW  = 5
SESSION_MAX_HISTORY     = 500

# ── Feature defaults for missing fields ───────────────────────────────────────
DEFAULT_PORT_RISK = 0.3
DEFAULT_ENTROPY   = 0.5
OFFHOURS_START    = 18   # 6 PM
OFFHOURS_END      = 8    # 8 AM

# ── Port risk tiers ───────────────────────────────────────────────────────────
HIGH_RISK_PORTS   = {22, 23, 3389, 4444, 5900, 6667}
MEDIUM_RISK_PORTS = {21, 25, 53, 110, 143, 512, 513, 514}
LOW_RISK_PORTS    = {80, 443, 8080, 8443}

# ── Private IP ranges (RFC 1918) ──────────────────────────────────────────────
PRIVATE_IP_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.",
)

"""
dal_scrubber.py
---------------
Block 4 — Data Abstraction Layer (DAL).

Two responsibilities:
  1. scrub()        — replaces all sensitive identifiers with typed
                      placeholders before narratives reach the LLM.
  2. reidentify()   — after the LLM returns its response, substitutes
                      placeholders back to real values so the final
                      report is analyst-readable.

Scrubbing is two-layer:
  Layer 1 — Regex   : structured patterns (IPs, hostnames, ARNs, session IDs,
                       usernames, domains). Fast, deterministic, always runs.
  Layer 2 — Presidio: NER-based detection on free text (narrative_summary).
                       Catches names written in natural language.
                       Gracefully degrades to regex-only if not installed.

Placeholder style — typed with role (Option B):
  ATTACKER_IP_1     external attacker infrastructure
  INTERNAL_IP_1     internal network addresses
  EXEC_USER_1       C-suite / leadership accounts
  DBA_USER_1        database administrator accounts
  SVC_ACCOUNT_1     service accounts (svc_*)
  SOC_USER_1        security operations accounts
  IT_USER_1         IT operations accounts
  USER_1            general user accounts
  INTERNAL_HOST_1   internal hostnames / servers
  PHI_SERVER_1      PHI database servers
  EMAIL_1           email addresses
  ATTACKER_DOMAIN_1 attacker-controlled or lookalike domains
  INTERNAL_DOMAIN_1 internal org domain references
  CLOUD_RESOURCE_1  AWS ARNs, account IDs
  PHI_TABLE_1       PHI database / table names
  SESSION_ID_1      PAM session IDs, DAM event IDs

Consistency: same raw value → same placeholder throughout entire campaign.
Mapping stored in pii_mapping_{campaign_id}.json — never sent to LLM.
"""
from __future__ import annotations

import copy
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import tenant


# =============================================================================
#  Configuration
# =============================================================================

# RFC 1918 + loopback prefixes
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.",
)

# Regex patterns for structured-field scrubbing
_RE_IPV4       = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
_RE_EMAIL      = re.compile(r'\b[\w.+-]+@[\w.-]+\.\w{2,}\b', re.IGNORECASE)
_RE_AWS_ARN    = re.compile(r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s"\']+', re.IGNORECASE)
_RE_AWS_ACCT   = re.compile(r'\b\d{12}\b')          # 12-digit AWS account IDs
_RE_PAM_SID    = re.compile(r'\bPSM-\d+\b')         # CyberArk PAM session IDs
_RE_DAM_EID    = re.compile(r'\bDAM-\d+\b')         # Imperva DAM event IDs
_RE_HOSTNAME   = re.compile(                         # internal hostnames: word-digit(s) pattern
    r'\b[a-z][a-z0-9-]*-(?:db|srv|gw|portal|vault|proc|idx|prod|dev|'
    r'backup|mgmt|pam|phi|web|app|api|mail|log|mon)-?\d{0,3}\b',
    re.IGNORECASE,
)

# Fields in structured_data that contain sensitive values (dot-path notation)
# These are scraped for token inventory before substitution
_STRUCTURED_SENSITIVE_PATHS = [
    ("iocs", "external_ips"),
    ("iocs", "affected_users"),
    ("iocs", "affected_hosts"),
]

# Fields / keys to PRESERVE as-is (never scrub these values)
_PRESERVE_KEYS = {
    "campaign_id", "severity", "confidence", "duration_minutes",
    "first_seen", "last_seen", "kill_chain_coverage", "kill_chain_completeness",
    "stage", "name", "technique", "evidence", "mitre_techniques",
    "affected_assets",   # already abstracted to labels like "phi_database"
    "kill_chain_stage", "mitre_technique_id", "mitre_technique",
    "mitre_tactic", "mitre_tactic_id", "detector", "rule_name",
    "triggered_rules", "confidence", "score", "agent_targets",
}

# Token classification rules (checked in order — first match wins)
_CLASSIFICATION_RULES: List[Tuple[str, Any]] = [
    # Leadership / executive accounts (org-specific prefixes → tenant profile)
    ("EXEC_USER",      lambda t, _: any(
        t.lower().startswith(p) for p in tenant.EXEC_USER_PREFIXES
    )),
    # Service accounts (org-specific prefix → tenant profile)
    ("SVC_ACCOUNT",    lambda t, _: t.lower().startswith(tenant.SVC_ACCOUNT_PREFIX)),
    # DBA accounts
    ("DBA_USER",       lambda t, _: any(
        p in t.lower() for p in ("dba_", "_dba", "oracle_", "mssql_")
    )),
    # SOC / security accounts
    ("SOC_USER",       lambda t, _: any(
        p in t.lower()
        for p in ("soc_analyst", "infosec_lead", "risk_analyst", "audit_mgr", "hipaa_")
    )),
    # IT operations accounts
    ("IT_USER",        lambda t, _: any(
        p in t.lower()
        for p in ("cloud_ops", "sysadmin", "netadmin", "devops_", "it_")
    )),
    # Unknown actor special case
    ("THREAT_ACTOR",   lambda t, _: t.lower() in ("unknown_actor", "attacker")),
    # PAM / session IDs
    ("SESSION_ID",     lambda t, _: bool(re.match(r'^(PSM|DAM|REQ)-\d+$', t, re.I))),
    # AWS ARN
    ("CLOUD_RESOURCE", lambda t, _: t.startswith("arn:aws:") or bool(re.match(r'^\d{12}$', t))),
    # Attacker domains / lookalikes (org-name lookalikes → tenant; generic local)
    ("ATTACKER_DOMAIN", lambda t, _: any(
        x in t.lower()
        for x in (*tenant.ATTACKER_DOMAIN_LOOKALIKES, "malware", ".onion", ".ru/",
                  ".xyz/", "c2.", "beacon", "-c2.")
    )),
    # Internal org domain (org domain → tenant profile)
    ("INTERNAL_DOMAIN", lambda t, _: tenant.ORG_DOMAIN in t.lower() and "@" not in t),
    # Email
    ("EMAIL",           lambda t, _: bool(_RE_EMAIL.match(t))),
    # PHI servers (specific hostnames)
    ("PHI_SERVER",      lambda t, _: any(
        p in t.lower() for p in ("phi-db", "phi_db", "member-db", "claims-dw")
    )),
    # Internal hostnames
    ("INTERNAL_HOST",   lambda t, _: bool(_RE_HOSTNAME.match(t))),
    # IPv4 — split by attacker vs internal vs external
    ("ATTACKER_IP",     lambda t, att: bool(_RE_IPV4.match(t)) and t in att),
    ("INTERNAL_IP",     lambda t, _: bool(_RE_IPV4.match(t)) and any(
        t.startswith(p) for p in _PRIVATE_PREFIXES
    )),
    ("EXTERNAL_IP",     lambda t, _: bool(_RE_IPV4.match(t))),
    # PHI table / database names (generic medical fragments local; org-specific
    # dataset names → tenant profile)
    ("PHI_TABLE",       lambda t, _: any(
        p in t.lower()
        for p in ("phi", "rx_history", "mental_health", "lab_results",
                  "member_health", "claim_diag", "prior_auth",
                  *tenant.PHI_NAME_FRAGMENTS)
    )),
]


def _classify(token: str, attacker_ips: Set[str]) -> str:
    """Return placeholder category for a token."""
    for category, rule in _CLASSIFICATION_RULES:
        try:
            if rule(token, attacker_ips):
                return category
        except Exception:
            continue
    return "USER"   # default


# =============================================================================
#  Presidio loader (graceful degradation)
# =============================================================================

def _try_presidio():
    """Attempt to load Presidio analyzer. Returns analyzer or None."""
    try:
        from presidio_analyzer import AnalyzerEngine
        analyzer = AnalyzerEngine()
        print("[DAL] Presidio available — NER layer active")
        return analyzer
    except Exception:
        print("[DAL] Presidio not available — using regex-only mode")
        return None


# =============================================================================
#  DALScrubber
# =============================================================================

class DALScrubber:
    """
    Scrubs attack narratives before LLM routing and re-attaches
    real identifiers after the LLM returns its response.

    Usage (forward):
        scrubber = DALScrubber()
        scrubbed, mappings = scrubber.scrub(narratives)
        scrubber.save_scrubbed(scrubbed, "results/scrubbed_narratives.json")
        scrubber.save_mappings(mappings, "results/")

    Usage (reverse — after LLM completes):
        mappings = scrubber.load_mappings("results/", campaign_id)
        final_report = scrubber.reidentify(llm_output_text, mappings[campaign_id])
    """

    def __init__(self):
        self._presidio = _try_presidio()
        self._last_mappings: Dict[str, dict] = {}

    # ------------------------------------------------------------------ #
    # Public: forward pass (scrub)
    # ------------------------------------------------------------------ #

    def scrub(
        self,
        narratives: List[dict],
    ) -> Tuple[List[dict], Dict[str, dict]]:
        """
        Scrub all narratives.

        Returns:
            scrubbed_narratives  — deep copy with all sensitive tokens replaced
            mappings             — {campaign_id: {"token": "PLACEHOLDER", ...}}
        """
        scrubbed_list = []
        all_mappings: Dict[str, dict] = {}

        for narrative in narratives:
            campaign_id = narrative.get("campaign_id", "UNKNOWN")
            print(f"[DAL] Scrubbing {campaign_id} ...")

            scrubbed, mapping, stats = self._scrub_one(narrative)
            scrubbed_list.append(scrubbed)
            all_mappings[campaign_id] = {
                "campaign_id":    campaign_id,
                "scrubbed_at":    datetime.now(timezone.utc).isoformat(),
                "presidio_used":  self._presidio is not None,
                "tokens_scrubbed": stats["total"],
                "by_category":    stats["by_category"],
                "mapping":        mapping,          # original → placeholder
                "reverse":        {v: k for k, v in mapping.items()},
            }
            print(f"[DAL]   → {stats['total']} tokens scrubbed "
                  f"({len(mapping)} unique): {stats['by_category']}")

        self._last_mappings = all_mappings
        return scrubbed_list, all_mappings

    # ------------------------------------------------------------------ #
    # Public: reverse pass (re-identify)
    # ------------------------------------------------------------------ #

    def reidentify(self, text: str, mapping_entry: dict) -> str:
        """
        Restore real identifiers in LLM output text.

        Args:
            text          — LLM response containing placeholders
            mapping_entry — one entry from save_mappings output
                            (has "reverse" key: {placeholder: original})

        Returns:
            text with all placeholders replaced by original values.
        """
        reverse = mapping_entry.get("reverse", {})
        if not reverse:
            return text

        result = text
        # Longest placeholders first to avoid partial replacements
        # (EXEC_USER_10 must be replaced before EXEC_USER_1)
        for placeholder in sorted(reverse, key=len, reverse=True):
            original = reverse[placeholder]
            if placeholder in result:
                result = result.replace(placeholder, original)
        return result

    def reidentify_report(self, report: dict, mapping_entry: dict) -> dict:
        """
        Restore real identifiers in a structured LLM report (dict/list).
        Recursively walks all string values.
        """
        return self._deep_reidentify(report, mapping_entry.get("reverse", {}))

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #

    def save_scrubbed(self, scrubbed: List[dict], path: str) -> None:
        """Save scrubbed narratives to JSON (this file goes to Block 5/LLM)."""
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(scrubbed, f, indent=2, ensure_ascii=False)
        size_kb = os.path.getsize(path) / 1024
        print(f"[DAL] Scrubbed narratives → {path}  ({size_kb:.1f} KB)")

    def save_mappings(self, mappings: Dict[str, dict], output_dir: str) -> None:
        """
        Save one pii_mapping_{campaign_id}.json per campaign.
        These files STAY LOCAL — never sent to the LLM or stored in cloud.
        """
        os.makedirs(output_dir, exist_ok=True)
        for campaign_id, entry in mappings.items():
            safe_id = campaign_id.replace("/", "-").replace(":", "-")
            path = os.path.join(output_dir, f"pii_mapping_{safe_id}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(entry, f, indent=2, ensure_ascii=False)
            print(f"[DAL] PII mapping → {path}  "
                  f"({entry['tokens_scrubbed']} tokens)")

    def load_mappings(
        self,
        output_dir: str,
        campaign_id: Optional[str] = None,
    ) -> Dict[str, dict]:
        """
        Load saved PII mappings from output_dir.
        If campaign_id is given, returns only that campaign's mapping.
        Otherwise returns all mappings found in the directory.
        """
        result = {}
        if not os.path.isdir(output_dir):
            print(f"[DAL] WARNING: mappings directory not found: {output_dir}")
            return result

        for fname in os.listdir(output_dir):
            if not fname.startswith("pii_mapping_") or not fname.endswith(".json"):
                continue
            path = os.path.join(output_dir, fname)
            with open(path, "r", encoding="utf-8") as f:
                entry = json.load(f)
            cid = entry.get("campaign_id", fname)
            result[cid] = entry

        if campaign_id:
            return {k: v for k, v in result.items() if k == campaign_id}
        return result

    # ------------------------------------------------------------------ #
    # Core scrub logic
    # ------------------------------------------------------------------ #

    def _scrub_one(
        self,
        narrative: dict,
    ) -> Tuple[dict, Dict[str, str], dict]:
        """
        Scrub one narrative. Returns (scrubbed_copy, mapping, stats).
        mapping: {original_value: PLACEHOLDER_N}
        """
        # Step 1: collect all sensitive tokens from known structured paths
        attacker_ips = set(narrative.get("iocs", {}).get("external_ips", []))
        tokens       = self._collect_tokens(narrative, attacker_ips)

        # Step 2: augment with Presidio hits on free text
        if self._presidio:
            free_text = (
                narrative.get("llm_context", {}).get("narrative_summary", "") + " " +
                narrative.get("llm_context", {}).get("system_prompt", "")
            )
            tokens.update(self._presidio_tokens(free_text))

        # Step 3: assign placeholders (sorted longest-first for safe substitution)
        mapping, stats = self._assign_placeholders(tokens, attacker_ips)

        # Step 4: deep-substitute throughout the narrative copy
        scrubbed = self._deep_substitute(copy.deepcopy(narrative), mapping)

        return scrubbed, mapping, stats

    def _collect_tokens(
        self,
        narrative: dict,
        attacker_ips: Set[str],
    ) -> Set[str]:
        """
        Collect all sensitive raw values from the narrative's structured fields.
        """
        tokens: Set[str] = set()

        def _add(val):
            if val and isinstance(val, str) and len(val) >= 2:
                tokens.add(val.strip())

        # Top-level fields
        _add(narrative.get("entry_point", ""))

        for ent in narrative.get("affected_entities", []):
            _add(ent.get("entity_key", ""))

        iocs = narrative.get("iocs", {})
        for ip  in iocs.get("external_ips",   []): _add(ip)
        for usr in iocs.get("affected_users",  []): _add(usr)
        for hst in iocs.get("affected_hosts",  []): _add(hst)

        # llm_context structured_data
        sd = narrative.get("llm_context", {}).get("structured_data", {})
        _add(sd.get("entry_point", ""))

        for field, sub in _STRUCTURED_SENSITIVE_PATHS:
            for val in sd.get(field, {}).get(sub, []):
                _add(val)

        for ent in sd.get("affected_entities", []):
            _add(ent.get("entity_key", ""))

        for stage_entry in sd.get("attack_timeline", []):
            for ent in stage_entry.get("entities", []):
                _add(ent.get("entity", ""))

        for ev in sd.get("top_evidence", []):
            _add(ev.get("source_ip", ""))
            _add(ev.get("user", ""))

        # Also scan narrative_summary for extra IPs not in the inventory
        summary = narrative.get("llm_context", {}).get("narrative_summary", "")
        for ip_match in _RE_IPV4.findall(summary):
            _add(ip_match)
        for email_match in _RE_EMAIL.findall(summary):
            _add(email_match)

        # Scan top_risk_events in incident_candidate (if present)
        for re_ev in narrative.get("top_risk_events", []):
            _add(re_ev.get("source_ip", ""))
            _add(re_ev.get("user", ""))

        # Remove empty / whitespace-only
        tokens.discard("")
        tokens.discard(" ")

        return tokens

    def _presidio_tokens(self, text: str) -> Set[str]:
        """
        Run Presidio NER on free text, return all detected entity strings.
        Falls back silently if analysis fails.
        """
        if not self._presidio or not text.strip():
            return set()
        try:
            results = self._presidio.analyze(
                text=text,
                entities=["PERSON", "EMAIL_ADDRESS", "IP_ADDRESS",
                          "LOCATION", "URL", "DOMAIN_NAME"],
                language="en",
            )
            return {text[r.start:r.end].strip() for r in results if r.end > r.start}
        except Exception as exc:
            print(f"[DAL] Presidio analysis failed: {exc}")
            return set()

    def _assign_placeholders(
        self,
        tokens: Set[str],
        attacker_ips: Set[str],
    ) -> Tuple[Dict[str, str], dict]:
        """
        Assign a typed, numbered placeholder to each token.
        Returns (mapping, stats).
        """
        counters: Dict[str, int]    = defaultdict(int)
        mapping:  Dict[str, str]    = {}
        cat_tokens: Dict[str, list] = defaultdict(list)

        # Sort by length descending — longer tokens get replaced first
        # to prevent partial-match collisions (e.g. dba_oracle_01 before dba_oracle)
        for token in sorted(tokens, key=len, reverse=True):
            if not token or len(token) < 2:
                continue
            category = _classify(token, attacker_ips)
            counters[category] += 1
            placeholder = f"{category}_{counters[category]}"
            mapping[token] = placeholder
            cat_tokens[category].append(token)

        by_category = {k: len(v) for k, v in cat_tokens.items()}
        stats = {"total": len(mapping), "by_category": by_category}
        return mapping, stats

    def _deep_substitute(self, obj: Any, mapping: Dict[str, str]) -> Any:
        """
        Recursively walk obj and replace all sensitive tokens in string values.
        Skips substitution on dict keys that are in _PRESERVE_KEYS.
        Always substitutes longest tokens first (mapping is pre-sorted by key length).
        """
        if isinstance(obj, str):
            return self._sub_string(obj, mapping)

        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                if k in _PRESERVE_KEYS:
                    result[k] = v          # preserve as-is
                else:
                    result[k] = self._deep_substitute(v, mapping)
            return result

        if isinstance(obj, list):
            return [self._deep_substitute(item, mapping) for item in obj]

        return obj

    @staticmethod
    def _sub_string(text: str, mapping: Dict[str, str]) -> str:
        """Apply all token replacements to a single string."""
        result = text
        # Longest tokens first (guaranteed by how mapping was built)
        for original in sorted(mapping, key=len, reverse=True):
            if original and original in result:
                result = result.replace(original, mapping[original])
        return result

    def _deep_reidentify(self, obj: Any, reverse: Dict[str, str]) -> Any:
        """Recursively restore placeholders in a structured object."""
        if isinstance(obj, str):
            result = obj
            for placeholder in sorted(reverse, key=len, reverse=True):
                if placeholder in result:
                    result = result.replace(placeholder, reverse[placeholder])
            return result
        if isinstance(obj, dict):
            return {k: self._deep_reidentify(v, reverse) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._deep_reidentify(item, reverse) for item in obj]
        return obj
